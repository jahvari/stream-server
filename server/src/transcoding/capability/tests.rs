use super::storage::{
    SeedStorageError, SeedStorageEvent, load_or_create_device_seed,
    load_or_create_device_seed_with_observer,
};
use std::{
    fs,
    sync::{Arc, Barrier, Mutex},
};
use tokio_util::sync::CancellationToken;

fn new_config_directory() -> tempfile::TempDir {
    tempfile::tempdir().expect("isolated config directory")
}

#[test]
fn seed_create_reload_and_fresh_install_namespaces_are_stable_and_distinct() {
    let first_config = new_config_directory();
    let cancellation = CancellationToken::new();
    let first = load_or_create_device_seed(first_config.path(), &cancellation)
        .expect("create protected seed");
    let reloaded = load_or_create_device_seed(first_config.path(), &cancellation)
        .expect("reload protected seed");
    assert_eq!(first.as_test_bytes(), reloaded.as_test_bytes());
    assert_eq!(
        fs::read(first_config.path().join("transcoding/device-id.key"))
            .expect("read seed fixture")
            .len(),
        32
    );

    let second_config = new_config_directory();
    let second = load_or_create_device_seed(second_config.path(), &cancellation)
        .expect("create independent seed");
    assert_ne!(first.as_test_bytes(), second.as_test_bytes());
}

#[test]
fn seed_concurrent_creators_all_reopen_the_same_complete_winner() {
    const WORKERS: usize = 8;
    let config = Arc::new(new_config_directory());
    let barrier = Arc::new(Barrier::new(WORKERS));
    let workers = (0..WORKERS)
        .map(|_| {
            let config = Arc::clone(&config);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                load_or_create_device_seed(config.path(), &CancellationToken::new())
                    .expect("race participant loads winner")
                    .as_test_bytes()
            })
        })
        .collect::<Vec<_>>();
    let seeds = workers
        .into_iter()
        .map(|worker| worker.join().expect("seed worker completes"))
        .collect::<Vec<_>>();

    assert!(seeds.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(
        fs::read(config.path().join("transcoding/device-id.key"))
            .expect("read race winner")
            .len(),
        32
    );
}

#[test]
fn seed_race_losers_wait_for_an_in_progress_winner_instead_of_reading_partial_bytes() {
    let config = Arc::new(new_config_directory());
    let (created_sender, created_receiver) = std::sync::mpsc::sync_channel(1);
    let writer_config = Arc::clone(&config);
    let writer = std::thread::spawn(move || {
        load_or_create_device_seed_with_observer(
            writer_config.path(),
            &CancellationToken::new(),
            |event| {
                if event == SeedStorageEvent::SeedCreatedBeforeWrite {
                    created_sender.send(()).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            },
        )
        .expect("delayed creator completes")
        .as_test_bytes()
    });
    created_receiver
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("writer reached the pre-write checkpoint");

    let readers = (0..4)
        .map(|_| {
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                load_or_create_device_seed(config.path(), &CancellationToken::new())
                    .expect("race loser reopens complete winner")
                    .as_test_bytes()
            })
        })
        .collect::<Vec<_>>();
    let winner = writer.join().unwrap();
    for reader in readers {
        assert_eq!(reader.join().unwrap(), winner);
    }
}

#[test]
fn seed_short_long_and_empty_winners_are_rejected_without_overwrite() {
    for malformed in [Vec::new(), vec![0x41; 31], vec![0x42; 33]] {
        let config = new_config_directory();
        let cancellation = CancellationToken::new();
        load_or_create_device_seed(config.path(), &cancellation).expect("create protected fixture");
        let path = config.path().join("transcoding/device-id.key");
        fs::write(&path, &malformed).expect("replace fixture contents");

        let error = load_or_create_device_seed(config.path(), &cancellation)
            .expect_err("malformed winner must fail closed");
        assert_eq!(error, SeedStorageError::Invalid);
        assert_eq!(fs::read(path).unwrap(), malformed);
    }
}

#[test]
fn seed_requires_a_regular_file_and_never_replaces_the_wrong_type() {
    let config = new_config_directory();
    let cancellation = CancellationToken::new();
    load_or_create_device_seed(config.path(), &cancellation).expect("create protected fixture");
    let path = config.path().join("transcoding/device-id.key");
    fs::remove_file(&path).expect("remove seed fixture");
    fs::create_dir(&path).expect("install wrong-type fixture");

    assert_eq!(
        load_or_create_device_seed(config.path(), &cancellation).unwrap_err(),
        SeedStorageError::Untrusted
    );
    assert!(path.is_dir());
}

#[test]
fn seed_cancellation_before_creation_leaves_no_key() {
    let config = new_config_directory();
    let cancellation = CancellationToken::new();
    cancellation.cancel();

    assert_eq!(
        load_or_create_device_seed(config.path(), &cancellation).unwrap_err(),
        SeedStorageError::Cancelled
    );
    assert!(!config.path().join("transcoding/device-id.key").exists());
}

#[test]
fn seed_cancellation_after_root_validation_leaves_no_key() {
    let config = new_config_directory();
    let cancellation = CancellationToken::new();
    let error = load_or_create_device_seed_with_observer(config.path(), &cancellation, |event| {
        if event == SeedStorageEvent::RootReady {
            cancellation.cancel();
        }
    })
    .unwrap_err();

    assert_eq!(error, SeedStorageError::Cancelled);
    assert!(!config.path().join("transcoding/device-id.key").exists());
}

#[test]
fn seed_creation_reports_file_and_parent_durability_checkpoints() {
    let config = new_config_directory();
    let events = Mutex::new(Vec::new());
    load_or_create_device_seed_with_observer(config.path(), &CancellationToken::new(), |event| {
        events.lock().unwrap().push(event)
    })
    .expect("durable seed creation");

    let events = events.into_inner().unwrap();
    let file_sync = events
        .iter()
        .position(|event| *event == SeedStorageEvent::SeedFileSynced)
        .expect("seed file was flushed");
    let directory_sync = events
        .iter()
        .position(|event| *event == SeedStorageEvent::ParentDirectorySyncAttempted)
        .expect("parent synchronization was attempted");
    assert!(file_sync < directory_sync);
}

#[cfg(unix)]
#[test]
fn seed_unix_objects_use_private_modes_and_reject_symlink_parents() {
    use std::os::unix::fs::{MetadataExt, symlink};

    let config = new_config_directory();
    load_or_create_device_seed(config.path(), &CancellationToken::new()).unwrap();
    let root = config.path().join("transcoding");
    let seed = root.join("device-id.key");
    assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&seed).unwrap().mode() & 0o777, 0o600);

    let namespace = new_config_directory();
    let real = namespace.path().join("real");
    let linked = namespace.path().join("linked");
    fs::create_dir(&real).unwrap();
    symlink(&real, &linked).unwrap();
    assert_eq!(
        load_or_create_device_seed(&linked, &CancellationToken::new()).unwrap_err(),
        SeedStorageError::Untrusted
    );
    assert!(!real.join("transcoding").exists());
}

#[cfg(windows)]
#[test]
fn seed_windows_objects_use_protected_dacls_and_reject_reparse_parents() {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    let config = new_config_directory();
    load_or_create_device_seed(config.path(), &CancellationToken::new()).unwrap();
    let root = config.path().join("transcoding");
    let seed = root.join("device-id.key");
    assert!(super::storage::windows::dacl_is_protected_for_test(&root));
    assert!(super::storage::windows::dacl_is_protected_for_test(&seed));

    let namespace = new_config_directory();
    let real = namespace.path().join("real");
    let linked = namespace.path().join("linked");
    fs::create_dir(&real).unwrap();
    symlink_dir(&real, &linked).expect("create reparse parent fixture");
    assert_eq!(
        load_or_create_device_seed(&linked, &CancellationToken::new()).unwrap_err(),
        SeedStorageError::Untrusted
    );
    assert!(!real.join("transcoding").exists());

    let linked_seed_config = new_config_directory();
    load_or_create_device_seed(linked_seed_config.path(), &CancellationToken::new()).unwrap();
    let linked_seed = linked_seed_config.path().join("transcoding/device-id.key");
    fs::remove_file(&linked_seed).unwrap();
    let outside_seed = linked_seed_config.path().join("outside.key");
    fs::write(&outside_seed, [0x5a; 32]).unwrap();
    symlink_file(&outside_seed, &linked_seed).expect("create seed reparse fixture");
    assert_eq!(
        load_or_create_device_seed(linked_seed_config.path(), &CancellationToken::new())
            .unwrap_err(),
        SeedStorageError::Untrusted
    );
    assert_eq!(fs::read(outside_seed).unwrap(), [0x5a; 32]);

    let linked_object_config = new_config_directory();
    load_or_create_device_seed(linked_object_config.path(), &CancellationToken::new()).unwrap();
    let linked_object = linked_object_config
        .path()
        .join("transcoding/device-id.key");
    fs::remove_file(&linked_object).unwrap();
    let outside_object = linked_object_config.path().join("outside-hardlink.key");
    fs::write(&outside_object, [0x33; 32]).unwrap();
    fs::hard_link(&outside_object, &linked_object).unwrap();
    assert_eq!(
        load_or_create_device_seed(linked_object_config.path(), &CancellationToken::new())
            .unwrap_err(),
        SeedStorageError::Untrusted
    );
    assert_eq!(fs::read(outside_object).unwrap(), [0x33; 32]);
}

#[cfg(windows)]
#[test]
fn seed_windows_rejects_a_preexisting_unprotected_root_without_modifying_it() {
    let config = new_config_directory();
    let root = config.path().join("transcoding");
    fs::create_dir(&root).unwrap();
    assert!(!super::storage::windows::dacl_is_protected_for_test(&root));

    assert_eq!(
        load_or_create_device_seed(config.path(), &CancellationToken::new()).unwrap_err(),
        SeedStorageError::Untrusted
    );
    assert!(!root.join("device-id.key").exists());
    assert!(!super::storage::windows::dacl_is_protected_for_test(&root));
}
