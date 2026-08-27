use enginefs::hls::{HlsEngine, ProbeResult};

fn probe(duration: f64) -> ProbeResult {
    ProbeResult {
        duration,
        container: "test".to_string(),
        streams: Vec::new(),
    }
}

#[test]
fn stream_playlist_bytes_remain_stable_with_selected_audio() {
    let actual = HlsEngine::get_stream_playlist(&probe(8.25), 0, "segments/", Some(17), "token=é");

    let expected = concat!(
        "#EXTM3U\n",
        "#EXT-X-VERSION:3\n",
        "#EXT-X-TARGETDURATION:4\n",
        "#EXT-X-MEDIA-SEQUENCE:0\n",
        "#EXT-X-PLAYLIST-TYPE:VOD\n",
        "#EXTINF:4.000000,\n",
        "segments/audio-17-0.ts?token=é\n",
        "#EXTINF:4.000000,\n",
        "segments/audio-17-1.ts?token=é\n",
        "#EXTINF:0.250000,\n",
        "segments/audio-17-2.ts?token=é\n",
        "#EXT-X-ENDLIST\n",
    );

    assert_eq!(actual, expected);
}

#[test]
fn stream_playlist_bytes_remain_stable_without_selected_audio() {
    let actual = HlsEngine::get_stream_playlist(&probe(4.0), 0, "./", None, "q=x");

    let expected = concat!(
        "#EXTM3U\n",
        "#EXT-X-VERSION:3\n",
        "#EXT-X-TARGETDURATION:4\n",
        "#EXT-X-MEDIA-SEQUENCE:0\n",
        "#EXT-X-PLAYLIST-TYPE:VOD\n",
        "#EXTINF:4.000000,\n",
        "./0.ts?q=x\n",
        "#EXT-X-ENDLIST\n",
    );

    assert_eq!(actual, expected);
}

#[test]
fn empty_stream_playlist_remains_reloadable() {
    let expected = concat!(
        "#EXTM3U\n",
        "#EXT-X-VERSION:3\n",
        "#EXT-X-TARGETDURATION:2\n",
        "#EXT-X-MEDIA-SEQUENCE:0\n",
    );

    for duration in [f64::NAN, -1.0, 0.0] {
        assert_eq!(
            HlsEngine::get_stream_playlist(&probe(duration), 0, "./", None, ""),
            expected,
            "duration={duration:?}",
        );
    }
}
