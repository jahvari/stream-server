use super::identity::{DriverField, DriverRecord, PlatformTag, PrivateDeviceIdentity};
use super::{DeviceAvailability, DeviceError, DeviceLocator, PlatformDeviceRecord, Vendor};
use crate::transcoding::{BackendKind, DeviceClass};
use std::collections::{BTreeMap, HashSet};
use tokio_util::sync::CancellationToken;

const MAX_WINDOWS_ADAPTERS: usize = 32;
const MAX_PRIVATE_INPUT_BYTES: usize = 2_048;
const MAX_DEVICE_ID_UTF16_UNITS: usize = 200;
const LINKED_GROUP_DOMAIN: &[u8] = b"windows-linked-group/v1\0";
pub(super) const D3D12_GENERIC_MEDIA_ATTRIBUTE_U128: u128 = 0x8eb2c848_82f6_4b49_aa87_aecfcf0174c6;

#[derive(Clone, Eq, PartialEq)]
pub(super) struct WindowsPhysicalSnapshot {
    pub(super) physical_index: Option<u32>,
    pub(super) instance_id: Vec<u16>,
    pub(super) repeated_instance_id: Vec<u16>,
    pub(super) driver: WindowsDriverSnapshot,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct WindowsDriverSnapshot {
    package: Option<Vec<u8>>,
    date: Option<Vec<u8>>,
    version: Option<Vec<u8>>,
    provider: Option<Vec<u8>>,
    dxcore_version: Option<Vec<u8>>,
    d3dkmt_version: Option<Vec<u8>>,
}

impl WindowsDriverSnapshot {
    #[cfg(test)]
    pub(super) fn complete_for_test(version: &str) -> Self {
        Self {
            package: Some(b"synthetic-package".to_vec()),
            date: Some(b"2026-01-01".to_vec()),
            version: Some(version.as_bytes().to_vec()),
            provider: Some(b"Synthetic Provider".to_vec()),
            dxcore_version: Some(b"1".to_vec()),
            d3dkmt_version: Some(b"3.2".to_vec()),
        }
    }

    #[cfg(test)]
    pub(super) fn incomplete_for_test() -> Self {
        Self {
            package: None,
            date: None,
            version: None,
            provider: None,
            dxcore_version: None,
            d3dkmt_version: None,
        }
    }

    #[cfg(test)]
    pub(super) fn oversized_incomplete_for_test() -> Self {
        Self {
            package: None,
            date: None,
            version: None,
            provider: None,
            dxcore_version: Some(vec![b'X'; MAX_PRIVATE_INPUT_BYTES + 1]),
            d3dkmt_version: None,
        }
    }

    fn append_fields(
        &self,
        identity: &[u8],
        fields: &mut Vec<DriverField>,
    ) -> Result<bool, DeviceError> {
        for value in [
            self.package.as_deref(),
            self.date.as_deref(),
            self.version.as_deref(),
            self.provider.as_deref(),
            self.dxcore_version.as_deref(),
            self.d3dkmt_version.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.is_empty() {
                return Err(DeviceError::Invalid);
            }
            if value.len() > MAX_PRIVATE_INPUT_BYTES {
                return Err(DeviceError::Overflow);
            }
        }
        let required = [
            (2, self.package.as_deref()),
            (3, self.date.as_deref()),
            (4, self.version.as_deref()),
            (5, self.provider.as_deref()),
        ];
        if required.iter().any(|(_, value)| value.is_none()) {
            return Ok(false);
        }
        push_driver_field(fields, 1, identity)?;
        for (tag, value) in required {
            push_driver_field(fields, tag, value.ok_or(DeviceError::Invalid)?)?;
        }
        if let Some(version) = &self.dxcore_version {
            push_driver_field(fields, 6, version)?;
        }
        if let Some(version) = &self.d3dkmt_version {
            push_driver_field(fields, 7, version)?;
        }
        Ok(true)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct WindowsAdapterSnapshot {
    pub(super) luid: i64,
    pub(super) display_name: Vec<u8>,
    pub(super) vendor_id: Option<u32>,
    pub(super) is_hardware: Option<bool>,
    pub(super) is_integrated: Option<bool>,
    pub(super) has_virtual_or_remote_evidence: bool,
    pub(super) physical_adapters: Vec<WindowsPhysicalSnapshot>,
}

pub(super) enum WindowsCandidateLists {
    DxCore {
        d3d11_graphics: Vec<WindowsAdapterSnapshot>,
        generic_media: Option<Vec<WindowsAdapterSnapshot>>,
    },
    DxgiFallback(Vec<WindowsAdapterSnapshot>),
}

pub(super) fn map_windows_records(
    candidates: WindowsCandidateLists,
    cancellation: &CancellationToken,
) -> Result<Vec<PlatformDeviceRecord>, DeviceError> {
    check_cancelled(cancellation)?;
    let candidates: Vec<WindowsAdapterSnapshot> = match candidates {
        WindowsCandidateLists::DxCore {
            d3d11_graphics,
            generic_media,
        } => {
            let mut union = BTreeMap::new();
            merge_candidate_list(&mut union, d3d11_graphics, cancellation)?;
            if let Some(generic_media) = generic_media {
                merge_candidate_list(&mut union, generic_media, cancellation)?;
            }
            union.into_values().collect()
        }
        WindowsCandidateLists::DxgiFallback(candidates) => {
            let mut deduplicated = BTreeMap::new();
            merge_candidate_list(&mut deduplicated, candidates, cancellation)?;
            deduplicated.into_values().collect()
        }
    };

    let mut records = Vec::new();
    for candidate in candidates {
        check_cancelled(cancellation)?;
        if candidate.is_hardware == Some(false) {
            continue;
        }
        map_adapter(candidate, cancellation, &mut records)?;
        if records.len() > MAX_WINDOWS_ADAPTERS {
            return Err(DeviceError::Overflow);
        }
    }
    Ok(records)
}

fn merge_candidate_list(
    union: &mut BTreeMap<i64, WindowsAdapterSnapshot>,
    candidates: Vec<WindowsAdapterSnapshot>,
    cancellation: &CancellationToken,
) -> Result<(), DeviceError> {
    if candidates.len() > MAX_WINDOWS_ADAPTERS {
        return Err(DeviceError::Overflow);
    }
    for mut candidate in candidates {
        check_cancelled(cancellation)?;
        candidate.physical_adapters.sort_unstable_by(|left, right| {
            (
                left.physical_index,
                &left.instance_id,
                &left.repeated_instance_id,
            )
                .cmp(&(
                    right.physical_index,
                    &right.instance_id,
                    &right.repeated_instance_id,
                ))
        });
        candidate.physical_adapters.dedup();
        match union.entry(candidate.luid) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &candidate => {}
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(DeviceError::Ambiguous);
            }
        }
        if union.len() > MAX_WINDOWS_ADAPTERS {
            return Err(DeviceError::Overflow);
        }
    }
    Ok(())
}

fn map_adapter(
    mut adapter: WindowsAdapterSnapshot,
    cancellation: &CancellationToken,
    records: &mut Vec<PlatformDeviceRecord>,
) -> Result<(), DeviceError> {
    if adapter.display_name.len() > MAX_PRIVATE_INPUT_BYTES
        || adapter.physical_adapters.is_empty()
        || adapter.physical_adapters.len() > MAX_WINDOWS_ADAPTERS
    {
        return Err(if adapter.physical_adapters.is_empty() {
            DeviceError::Invalid
        } else {
            DeviceError::Overflow
        });
    }

    let mut physical = Vec::with_capacity(adapter.physical_adapters.len());
    for snapshot in std::mem::take(&mut adapter.physical_adapters) {
        check_cancelled(cancellation)?;
        physical.push(ValidatedPhysicalSnapshot::new(snapshot)?);
    }

    let all_members_indexed = physical
        .iter()
        .all(|member| member.physical_index.is_some());
    let unique_physical_indices = physical
        .iter()
        .filter_map(|member| member.physical_index)
        .collect::<HashSet<_>>()
        .len();
    if physical.len() > 1 && all_members_indexed && unique_physical_indices != physical.len() {
        return Err(DeviceError::Ambiguous);
    }
    let one_to_one = physical.len() == 1 || all_members_indexed;
    if one_to_one {
        let unique_identities = physical
            .iter()
            .map(|member| member.identity.clone())
            .collect::<HashSet<_>>();
        if unique_identities.len() != physical.len() {
            return Err(DeviceError::Ambiguous);
        }
        for member in physical {
            check_cancelled(cancellation)?;
            let driver = driver_record_for_members(std::slice::from_ref(&member))?;
            records.push(platform_record(
                &adapter,
                member.identity,
                DeviceLocator::Windows {
                    adapter_luid: adapter.luid,
                    physical_index: member.physical_index,
                },
                driver,
                class_for_adapter(&adapter),
            )?);
        }
        return Ok(());
    }

    physical.sort_unstable_by(|left, right| left.utf16.cmp(&right.utf16));
    if physical
        .windows(2)
        .any(|pair| pair[0].utf16 == pair[1].utf16 && pair[0].driver != pair[1].driver)
    {
        return Err(DeviceError::Ambiguous);
    }
    physical.dedup_by(|left, right| left.utf16 == right.utf16);
    let identity = linked_group_identity(&physical)?;
    let driver = driver_record_for_members(&physical)?;
    check_cancelled(cancellation)?;
    records.push(platform_record(
        &adapter,
        identity,
        DeviceLocator::Windows {
            adapter_luid: adapter.luid,
            physical_index: None,
        },
        driver,
        DeviceClass::Unknown,
    )?);
    Ok(())
}

#[derive(Clone)]
struct ValidatedPhysicalSnapshot {
    physical_index: Option<u32>,
    utf16: Vec<u16>,
    identity: Vec<u8>,
    driver: WindowsDriverSnapshot,
}

impl ValidatedPhysicalSnapshot {
    fn new(snapshot: WindowsPhysicalSnapshot) -> Result<Self, DeviceError> {
        if snapshot.instance_id != snapshot.repeated_instance_id {
            return Err(DeviceError::Invalid);
        }
        let identity = canonical_pnp_identity(&snapshot.instance_id)?;
        Ok(Self {
            physical_index: snapshot.physical_index,
            utf16: snapshot.instance_id,
            identity,
            driver: snapshot.driver,
        })
    }
}

fn canonical_pnp_identity(instance_id: &[u16]) -> Result<Vec<u8>, DeviceError> {
    if instance_id.is_empty()
        || instance_id.len() >= MAX_DEVICE_ID_UTF16_UNITS
        || instance_id.contains(&0)
    {
        return Err(DeviceError::Invalid);
    }
    let byte_length = instance_id
        .len()
        .checked_mul(2)
        .ok_or(DeviceError::Overflow)?;
    if byte_length > MAX_PRIVATE_INPUT_BYTES {
        return Err(DeviceError::Overflow);
    }
    let mut bytes = Vec::with_capacity(byte_length);
    for code_unit in instance_id {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
    Ok(bytes)
}

fn linked_group_identity(members: &[ValidatedPhysicalSnapshot]) -> Result<Vec<u8>, DeviceError> {
    let count = u32::try_from(members.len()).map_err(|_| DeviceError::Overflow)?;
    let mut identity = Vec::with_capacity(LINKED_GROUP_DOMAIN.len() + 4);
    identity.extend_from_slice(LINKED_GROUP_DOMAIN);
    identity.extend_from_slice(&count.to_be_bytes());
    for member in members {
        let length = u32::try_from(member.identity.len()).map_err(|_| DeviceError::Overflow)?;
        let next_length = identity
            .len()
            .checked_add(4)
            .and_then(|size| size.checked_add(member.identity.len()))
            .ok_or(DeviceError::Overflow)?;
        if next_length > MAX_PRIVATE_INPUT_BYTES {
            return Err(DeviceError::Overflow);
        }
        identity.extend_from_slice(&length.to_be_bytes());
        identity.extend_from_slice(&member.identity);
    }
    Ok(identity)
}

fn driver_record_for_members(
    members: &[ValidatedPhysicalSnapshot],
) -> Result<DriverRecord, DeviceError> {
    let mut fields = Vec::new();
    for member in members {
        if !member.driver.append_fields(&member.identity, &mut fields)? {
            return Ok(DriverRecord::Incomplete);
        }
    }
    Ok(DriverRecord::Complete(fields))
}

fn push_driver_field(
    fields: &mut Vec<DriverField>,
    tag: u8,
    bytes: &[u8],
) -> Result<(), DeviceError> {
    if bytes.is_empty() {
        return Err(DeviceError::Invalid);
    }
    if bytes.len() > MAX_PRIVATE_INPUT_BYTES {
        return Err(DeviceError::Overflow);
    }
    fields.push(DriverField::new(tag, bytes.to_vec()));
    Ok(())
}

fn platform_record(
    adapter: &WindowsAdapterSnapshot,
    identity: Vec<u8>,
    locator: DeviceLocator,
    driver: DriverRecord,
    class: DeviceClass,
) -> Result<PlatformDeviceRecord, DeviceError> {
    let persistent_identity =
        PrivateDeviceIdentity::new(identity).map_err(|_| DeviceError::Overflow)?;
    Ok(PlatformDeviceRecord {
        platform: PlatformTag::Windows,
        display_name: adapter.display_name.clone(),
        vendor: vendor_from_id(adapter.vendor_id),
        class,
        availability: DeviceAvailability::Available,
        persistent_identity,
        locator,
        driver,
        backends: backends_for_vendor(adapter.vendor_id),
    })
}

fn class_for_adapter(adapter: &WindowsAdapterSnapshot) -> DeviceClass {
    if adapter.has_virtual_or_remote_evidence {
        DeviceClass::Virtual
    } else {
        match (adapter.is_hardware, adapter.is_integrated) {
            (_, Some(true)) => DeviceClass::Integrated,
            (Some(true), Some(false)) => DeviceClass::Discrete,
            _ => DeviceClass::Unknown,
        }
    }
}

fn vendor_from_id(vendor_id: Option<u32>) -> Vendor {
    match vendor_id {
        Some(0x8086) => Vendor::Intel,
        Some(0x10de) => Vendor::Nvidia,
        Some(0x1002) => Vendor::Amd,
        Some(0x106b) => Vendor::Apple,
        Some(0x1414) => Vendor::Microsoft,
        Some(_) => Vendor::Other,
        None => Vendor::Unknown,
    }
}

fn backends_for_vendor(vendor_id: Option<u32>) -> Vec<BackendKind> {
    match vendor_id {
        Some(0x8086) => vec![BackendKind::D3d11va, BackendKind::Qsv],
        Some(0x10de) => vec![BackendKind::Cuda, BackendKind::D3d11va, BackendKind::Nvenc],
        Some(0x1002) => vec![BackendKind::Amf, BackendKind::D3d11va],
        _ => vec![BackendKind::D3d11va],
    }
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), DeviceError> {
    if cancellation.is_cancelled() {
        Err(DeviceError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use crate::transcoding::device::DeviceEnumerator;
    use std::collections::BTreeMap;
    use std::ffi::c_void;
    #[cfg(test)]
    use std::sync::atomic::{AtomicIsize, Ordering};
    use windows::Wdk::Graphics::Direct3D::{
        D3DKMT_CLOSEADAPTER, D3DKMT_DRIVERVERSION, D3DKMT_OPENADAPTERFROMLUID,
        D3DKMT_PHYSICAL_ADAPTER_COUNT, D3DKMT_PNP_KEY_SOFTWARE,
        D3DKMT_QUERY_PHYSICAL_ADAPTER_PNP_KEY, D3DKMT_QUERYADAPTERINFO, D3DKMTCloseAdapter,
        D3DKMTOpenAdapterFromLuid, D3DKMTQueryAdapterInfo, KMTQAITYPE_PHYSICALADAPTERCOUNT,
        KMTQAITYPE_PHYSICALADAPTERPNPKEY,
    };
    use windows::Win32::Devices::DeviceAndDriverInstallation::{
        CM_Get_DevNode_PropertyW, CM_LOCATE_DEVNODE_NORMAL, CM_Locate_DevNodeW, CR_BUFFER_SMALL,
        CR_NO_SUCH_VALUE, CR_SUCCESS, DIGCF_PRESENT, HDEVINFO, SP_DEVINFO_DATA,
        SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    };
    use windows::Win32::Devices::Properties::{
        DEVPKEY_Device_Driver, DEVPKEY_Device_DriverDate, DEVPKEY_Device_DriverProvider,
        DEVPKEY_Device_DriverVersion, DEVPKEY_Device_InstanceId, DEVPROP_TYPE_FILETIME,
        DEVPROP_TYPE_STRING, DEVPROPTYPE,
    };
    use windows::Win32::Foundation::{FreeLibrary, HMODULE, LUID};
    use windows::Win32::Graphics::DXCore::{
        DXCORE_ADAPTER_ATTRIBUTE_D3D11_GRAPHICS, DXCoreHardwareID, DXCoreHardwareIDParts,
        DriverDescription, DriverVersion, HardwareID, HardwareIDParts, IDXCoreAdapter,
        IDXCoreAdapterFactory, IDXCoreAdapterList, InstanceLuid, IsDetachable, IsHardware,
        IsIntegrated, KmdModelVersion,
    };
    use windows::Win32::Graphics::Dxgi::{
        CreateDXGIFactory1, DXGI_ADAPTER_FLAG_REMOTE, DXGI_ADAPTER_FLAG_SOFTWARE,
        DXGI_ERROR_NOT_FOUND, IDXGIFactory1,
    };
    use windows::Win32::System::LibraryLoader::{
        GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    };
    use windows::core::{GUID, HRESULT, Interface, PCWSTR, PWSTR, s, w};

    const D3D12_GENERIC_MEDIA_ATTRIBUTE: GUID = GUID::from_u128(D3D12_GENERIC_MEDIA_ATTRIBUTE_U128);

    #[cfg(test)]
    static OPEN_NATIVE_HANDLES: AtomicIsize = AtomicIsize::new(0);

    pub(crate) struct WindowsDeviceEnumerator;

    #[async_trait::async_trait]
    impl DeviceEnumerator for WindowsDeviceEnumerator {
        async fn enumerate(
            &self,
            cancellation: CancellationToken,
        ) -> Result<Vec<PlatformDeviceRecord>, DeviceError> {
            let worker_cancellation = cancellation.clone();
            tokio::task::spawn_blocking(move || enumerate_native_windows(&worker_cancellation))
                .await
                .map_err(|_| DeviceError::Invalid)?
        }
    }

    #[cfg(test)]
    pub(crate) fn native_open_handle_count_for_test() -> isize {
        OPEN_NATIVE_HANDLES.load(Ordering::SeqCst)
    }

    fn enumerate_native_windows(
        cancellation: &CancellationToken,
    ) -> Result<Vec<PlatformDeviceRecord>, DeviceError> {
        check_cancelled(cancellation)?;
        let candidates = match enumerate_dxcore(cancellation)? {
            Some(candidates) => candidates,
            None => WindowsCandidateLists::DxgiFallback(enumerate_dxgi(cancellation)?),
        };
        map_windows_records(candidates, cancellation)
    }

    struct DynamicDxCoreFactory {
        factory: IDXCoreAdapterFactory,
        _module: OwnedModule,
    }

    struct OwnedModule(HMODULE);

    impl OwnedModule {
        fn new(module: HMODULE) -> Self {
            #[cfg(test)]
            OPEN_NATIVE_HANDLES.fetch_add(1, Ordering::SeqCst);
            Self(module)
        }
    }

    impl Drop for OwnedModule {
        fn drop(&mut self) {
            // SAFETY: this instance exclusively owns the successful LoadLibraryExW reference.
            let _ = unsafe { FreeLibrary(self.0) };
            #[cfg(test)]
            OPEN_NATIVE_HANDLES.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn load_dxcore_factory() -> Result<DynamicDxCoreFactory, DeviceError> {
        // SAFETY: the library name is constant and search is restricted to System32.
        let module = unsafe {
            LoadLibraryExW(w!("dxcore.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32)
                .map_err(|_| DeviceError::Invalid)?
        };
        let module = OwnedModule::new(module);
        // SAFETY: the module is live and the symbol name is a constant NUL-terminated string.
        let procedure = unsafe { GetProcAddress(module.0, s!("DXCoreCreateAdapterFactory")) }
            .ok_or(DeviceError::Invalid)?;
        type CreateFactory = unsafe extern "system" fn(*const GUID, *mut *mut c_void) -> HRESULT;
        // SAFETY: Microsoft defines this exported symbol with the exact signature above.
        let create_factory: CreateFactory = unsafe { std::mem::transmute(procedure) };
        let mut raw = std::ptr::null_mut();
        // SAFETY: raw is a valid output pointer and IID identifies IDXCoreAdapterFactory.
        unsafe { create_factory(&IDXCoreAdapterFactory::IID, &mut raw) }
            .ok()
            .map_err(|_| DeviceError::Invalid)?;
        if raw.is_null() {
            return Err(DeviceError::Invalid);
        }
        // SAFETY: successful DXCoreCreateAdapterFactory transferred one owned COM reference.
        let factory = unsafe { IDXCoreAdapterFactory::from_raw(raw) };
        Ok(DynamicDxCoreFactory {
            factory,
            _module: module,
        })
    }

    fn enumerate_dxcore(
        cancellation: &CancellationToken,
    ) -> Result<Option<WindowsCandidateLists>, DeviceError> {
        let dynamic = match load_dxcore_factory() {
            Ok(dynamic) => dynamic,
            Err(_) => return Ok(None),
        };
        // SAFETY: the factory is live and the attribute is a Microsoft-defined GUID.
        let d3d11: IDXCoreAdapterList = match unsafe {
            dynamic
                .factory
                .CreateAdapterList(&[DXCORE_ADAPTER_ATTRIBUTE_D3D11_GRAPHICS])
        } {
            Ok(list) => list,
            Err(_) => return Ok(None),
        };
        // A missing/newer Generic Media attribute disables only that list.
        // SAFETY: the factory is live and the GUID value is fixed by the public DXCore contract.
        let generic_media: Option<IDXCoreAdapterList> = unsafe {
            dynamic
                .factory
                .CreateAdapterList(&[D3D12_GENERIC_MEDIA_ATTRIBUTE])
                .ok()
        };

        let mut adapters = BTreeMap::new();
        append_dxcore_list(&mut adapters, &d3d11, cancellation)?;
        if let Some(list) = &generic_media {
            append_dxcore_list(&mut adapters, list, cancellation)?;
        }
        let dxgi_flags = enumerate_dxgi_flags(cancellation)?;
        let mut snapshots = Vec::with_capacity(adapters.len());
        for (luid, adapter) in adapters {
            check_cancelled(cancellation)?;
            let snapshot = snapshot_dxcore_adapter(
                luid,
                &adapter,
                dxgi_flags.get(&luid).copied(),
                cancellation,
            )?;
            check_cancelled(cancellation)?;
            snapshots.push(snapshot);
        }
        Ok(Some(WindowsCandidateLists::DxCore {
            d3d11_graphics: snapshots,
            generic_media: None,
        }))
    }

    fn append_dxcore_list(
        union: &mut BTreeMap<i64, IDXCoreAdapter>,
        list: &IDXCoreAdapterList,
        cancellation: &CancellationToken,
    ) -> Result<(), DeviceError> {
        // SAFETY: list is a live COM interface.
        let count = unsafe { list.GetAdapterCount() } as usize;
        if count > MAX_WINDOWS_ADAPTERS {
            return Err(DeviceError::Overflow);
        }
        // SAFETY: list is a live COM interface.
        if unsafe { list.IsStale() } {
            return Err(DeviceError::Invalid);
        }
        for index in 0..count {
            check_cancelled(cancellation)?;
            // SAFETY: index is below GetAdapterCount and the list remains live.
            let adapter: IDXCoreAdapter = unsafe {
                list.GetAdapter(u32::try_from(index).map_err(|_| DeviceError::Overflow)?)
            }
            .map_err(|_| DeviceError::Invalid)?;
            // SAFETY: adapter is a live COM interface.
            if !unsafe { adapter.IsValid() } {
                return Err(DeviceError::Invalid);
            }
            let luid = get_dxcore_copy::<LUID>(&adapter, InstanceLuid, cancellation)?
                .ok_or(DeviceError::Invalid)?;
            union.entry(luid_to_i64(luid)).or_insert(adapter);
            if union.len() > MAX_WINDOWS_ADAPTERS {
                return Err(DeviceError::Overflow);
            }
        }
        // SAFETY: list is a live COM interface.
        if unsafe { list.IsStale() } {
            return Err(DeviceError::Invalid);
        }
        Ok(())
    }

    fn snapshot_dxcore_adapter(
        luid: i64,
        adapter: &IDXCoreAdapter,
        dxgi_flags: Option<u32>,
        cancellation: &CancellationToken,
    ) -> Result<WindowsAdapterSnapshot, DeviceError> {
        check_cancelled(cancellation)?;
        let is_hardware = get_dxcore_bool(adapter, IsHardware, cancellation)?;
        let display_name =
            get_dxcore_bytes(adapter, DriverDescription, cancellation)?.unwrap_or_default();
        let vendor_id =
            match get_dxcore_copy::<DXCoreHardwareIDParts>(adapter, HardwareIDParts, cancellation)?
            {
                Some(parts) => Some(parts.vendorID),
                None => get_dxcore_copy::<DXCoreHardwareID>(adapter, HardwareID, cancellation)?
                    .map(|hardware_id| hardware_id.vendorID),
            };
        let is_integrated = get_dxcore_bool(adapter, IsIntegrated, cancellation)?;
        let _is_detachable = get_dxcore_bool(adapter, IsDetachable, cancellation)?;
        let dxgi_software =
            dxgi_flags.is_some_and(|flags| flags & (DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32) != 0);
        if is_hardware == Some(true) && dxgi_software {
            return Err(DeviceError::Ambiguous);
        }
        let is_hardware = if dxgi_software {
            Some(false)
        } else {
            is_hardware
        };
        let has_virtual_or_remote_evidence =
            dxgi_flags.is_some_and(|flags| flags & (DXGI_ADAPTER_FLAG_REMOTE.0 as u32) != 0);
        let driver_version = get_dxcore_copy::<u64>(adapter, DriverVersion, cancellation)?
            .map(|value| value.to_be_bytes().to_vec());
        let kmd_version =
            get_dxcore_copy::<D3DKMT_DRIVERVERSION>(adapter, KmdModelVersion, cancellation)?
                .map(|value| value.0.to_be_bytes().to_vec());
        let physical_adapters = if is_hardware == Some(false) {
            Vec::new()
        } else {
            enumerate_physical_adapters(luid, driver_version, kmd_version, cancellation)?
        };
        Ok(WindowsAdapterSnapshot {
            luid,
            display_name,
            vendor_id,
            is_hardware,
            is_integrated,
            has_virtual_or_remote_evidence,
            physical_adapters,
        })
    }

    fn get_dxcore_bool(
        adapter: &IDXCoreAdapter,
        property: windows::Win32::Graphics::DXCore::DXCoreAdapterProperty,
        cancellation: &CancellationToken,
    ) -> Result<Option<bool>, DeviceError> {
        match get_dxcore_copy::<u8>(adapter, property, cancellation)? {
            Some(0) => Ok(Some(false)),
            Some(1) => Ok(Some(true)),
            Some(_) => Err(DeviceError::Invalid),
            None => Ok(None),
        }
    }

    fn get_dxcore_copy<T: Copy + Default>(
        adapter: &IDXCoreAdapter,
        property: windows::Win32::Graphics::DXCore::DXCoreAdapterProperty,
        cancellation: &CancellationToken,
    ) -> Result<Option<T>, DeviceError> {
        check_cancelled(cancellation)?;
        // SAFETY: adapter is live; unsupported properties are not queried.
        if !unsafe { adapter.IsPropertySupported(property) } {
            return Ok(None);
        }
        check_cancelled(cancellation)?;
        // SAFETY: adapter is live and property support was checked.
        let size =
            unsafe { adapter.GetPropertySize(property) }.map_err(|_| DeviceError::Invalid)?;
        if size != std::mem::size_of::<T>() {
            return Err(DeviceError::Invalid);
        }
        check_cancelled(cancellation)?;
        let mut value = T::default();
        // SAFETY: value is writable for exactly size_of::<T>() bytes.
        unsafe {
            adapter.GetProperty(
                property,
                size,
                std::ptr::from_mut(&mut value).cast::<c_void>(),
            )
        }
        .map_err(|_| DeviceError::Invalid)?;
        check_cancelled(cancellation)?;
        Ok(Some(value))
    }

    fn get_dxcore_bytes(
        adapter: &IDXCoreAdapter,
        property: windows::Win32::Graphics::DXCore::DXCoreAdapterProperty,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<u8>>, DeviceError> {
        check_cancelled(cancellation)?;
        // SAFETY: adapter is live; unsupported properties are not queried.
        if !unsafe { adapter.IsPropertySupported(property) } {
            return Ok(None);
        }
        check_cancelled(cancellation)?;
        // SAFETY: adapter is live and property support was checked.
        let size =
            unsafe { adapter.GetPropertySize(property) }.map_err(|_| DeviceError::Invalid)?;
        if size == 0 || size > MAX_PRIVATE_INPUT_BYTES + 1 {
            return Err(DeviceError::Overflow);
        }
        check_cancelled(cancellation)?;
        let mut bytes = vec![0_u8; size];
        // SAFETY: the allocation is writable for the size reported by DXCore.
        unsafe { adapter.GetProperty(property, size, bytes.as_mut_ptr().cast::<c_void>()) }
            .map_err(|_| DeviceError::Invalid)?;
        check_cancelled(cancellation)?;
        if bytes.last() == Some(&0) {
            bytes.pop();
        }
        if bytes.len() > MAX_PRIVATE_INPUT_BYTES {
            return Err(DeviceError::Overflow);
        }
        Ok(Some(bytes))
    }

    fn enumerate_dxgi_flags(
        cancellation: &CancellationToken,
    ) -> Result<BTreeMap<i64, u32>, DeviceError> {
        // SAFETY: CreateDXGIFactory1 initializes a COM interface with an owned reference.
        let factory: IDXGIFactory1 = match unsafe { CreateDXGIFactory1() } {
            Ok(factory) => factory,
            Err(_) => return Ok(BTreeMap::new()),
        };
        let mut flags = BTreeMap::new();
        for index in 0..=MAX_WINDOWS_ADAPTERS {
            check_cancelled(cancellation)?;
            // SAFETY: factory is live; EnumAdapters1 defines not-found as the terminator.
            let adapter = match unsafe {
                factory.EnumAdapters1(u32::try_from(index).map_err(|_| DeviceError::Overflow)?)
            } {
                Ok(adapter) => adapter,
                Err(error) if error.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(_) => return Err(DeviceError::Invalid),
            };
            if flags.len() == MAX_WINDOWS_ADAPTERS {
                return Err(DeviceError::Overflow);
            }
            // SAFETY: adapter is a live COM interface.
            let description = unsafe { adapter.GetDesc1() }.map_err(|_| DeviceError::Invalid)?;
            check_cancelled(cancellation)?;
            if flags
                .insert(luid_to_i64(description.AdapterLuid), description.Flags)
                .is_some()
            {
                return Err(DeviceError::Ambiguous);
            }
        }
        Ok(flags)
    }

    fn enumerate_dxgi(
        cancellation: &CancellationToken,
    ) -> Result<Vec<WindowsAdapterSnapshot>, DeviceError> {
        // SAFETY: CreateDXGIFactory1 initializes a COM interface with an owned reference.
        let factory: IDXGIFactory1 = match unsafe { CreateDXGIFactory1() } {
            Ok(factory) => factory,
            Err(_) => return Ok(Vec::new()),
        };
        let mut snapshots = Vec::new();
        for index in 0..=MAX_WINDOWS_ADAPTERS {
            check_cancelled(cancellation)?;
            // SAFETY: factory is live; EnumAdapters1 defines not-found as the terminator.
            let adapter = match unsafe {
                factory.EnumAdapters1(u32::try_from(index).map_err(|_| DeviceError::Overflow)?)
            } {
                Ok(adapter) => adapter,
                Err(error) if error.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(_) => return Err(DeviceError::Invalid),
            };
            if snapshots.len() == MAX_WINDOWS_ADAPTERS {
                return Err(DeviceError::Overflow);
            }
            // SAFETY: adapter is a live COM interface.
            let description = unsafe { adapter.GetDesc1() }.map_err(|_| DeviceError::Invalid)?;
            let description_end = description
                .Description
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(description.Description.len());
            let display_name =
                String::from_utf16_lossy(&description.Description[..description_end]).into_bytes();
            let software = description.Flags & (DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32) != 0;
            let remote = description.Flags & (DXGI_ADAPTER_FLAG_REMOTE.0 as u32) != 0;
            let luid = luid_to_i64(description.AdapterLuid);
            let physical_adapters = if software {
                Vec::new()
            } else {
                enumerate_physical_adapters(luid, None, None, cancellation)?
            };
            check_cancelled(cancellation)?;
            snapshots.push(WindowsAdapterSnapshot {
                luid,
                display_name,
                vendor_id: Some(description.VendorId),
                is_hardware: Some(!software),
                is_integrated: None,
                has_virtual_or_remote_evidence: remote,
                physical_adapters,
            });
        }
        Ok(snapshots)
    }

    struct OwnedD3dkmtAdapter {
        raw: u32,
        close_native: bool,
    }

    impl OwnedD3dkmtAdapter {
        fn open(luid: i64) -> Result<Self, DeviceError> {
            let mut request = D3DKMT_OPENADAPTERFROMLUID {
                AdapterLuid: i64_to_luid(luid),
                hAdapter: 0,
            };
            // SAFETY: request is initialized and writable for the documented structure size.
            let status = unsafe { D3DKMTOpenAdapterFromLuid(&mut request) };
            if status.0 != 0 || request.hAdapter == 0 {
                return Err(DeviceError::Invalid);
            }
            #[cfg(test)]
            OPEN_NATIVE_HANDLES.fetch_add(1, Ordering::SeqCst);
            Ok(Self {
                raw: request.hAdapter,
                close_native: true,
            })
        }

        #[cfg(test)]
        fn fake() -> Self {
            OPEN_NATIVE_HANDLES.fetch_add(1, Ordering::SeqCst);
            Self {
                raw: 1,
                close_native: false,
            }
        }
    }

    impl Drop for OwnedD3dkmtAdapter {
        fn drop(&mut self) {
            if self.close_native {
                let close = D3DKMT_CLOSEADAPTER { hAdapter: self.raw };
                // SAFETY: this owned handle was returned by D3DKMTOpenAdapterFromLuid once.
                let _ = unsafe { D3DKMTCloseAdapter(&close) };
            }
            #[cfg(test)]
            OPEN_NATIVE_HANDLES.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[cfg(test)]
    pub(crate) fn exercise_native_handle_exit_for_test(
        result: Result<(), DeviceError>,
    ) -> Result<(), DeviceError> {
        let _handle = OwnedD3dkmtAdapter::fake();
        result
    }

    fn enumerate_physical_adapters(
        luid: i64,
        dxcore_version: Option<Vec<u8>>,
        d3dkmt_version: Option<Vec<u8>>,
        cancellation: &CancellationToken,
    ) -> Result<Vec<WindowsPhysicalSnapshot>, DeviceError> {
        check_cancelled(cancellation)?;
        let handle = OwnedD3dkmtAdapter::open(luid)?;
        let mut count = D3DKMT_PHYSICAL_ADAPTER_COUNT::default();
        query_adapter_info(&handle, KMTQAITYPE_PHYSICALADAPTERCOUNT, &mut count)?;
        let count = usize::try_from(count.Count).map_err(|_| DeviceError::Overflow)?;
        if count == 0 {
            return Err(DeviceError::Invalid);
        }
        if count > MAX_WINDOWS_ADAPTERS {
            return Err(DeviceError::Overflow);
        }
        let mut physical = Vec::with_capacity(count);
        for index in 0..count {
            check_cancelled(cancellation)?;
            let index = u32::try_from(index).map_err(|_| DeviceError::Overflow)?;
            let pnp_key = query_physical_pnp_key(&handle, index)?;
            check_cancelled(cancellation)?;
            if pnp_key != query_physical_pnp_key(&handle, index)? {
                return Err(DeviceError::Invalid);
            }
            check_cancelled(cancellation)?;
            let device_node = resolve_device_node(&pnp_key, cancellation)?;
            let instance_id = read_instance_id_twice(device_node, cancellation)?;
            let driver = read_driver_snapshot(
                device_node,
                dxcore_version.clone(),
                d3dkmt_version.clone(),
                cancellation,
            )?;
            check_cancelled(cancellation)?;
            physical.push(WindowsPhysicalSnapshot {
                physical_index: Some(index),
                repeated_instance_id: instance_id.clone(),
                instance_id,
                driver,
            });
        }
        Ok(physical)
    }

    fn query_adapter_info<T>(
        handle: &OwnedD3dkmtAdapter,
        kind: windows::Wdk::Graphics::Direct3D::KMTQUERYADAPTERINFOTYPE,
        value: &mut T,
    ) -> Result<(), DeviceError> {
        let size = u32::try_from(std::mem::size_of::<T>()).map_err(|_| DeviceError::Overflow)?;
        let mut query = D3DKMT_QUERYADAPTERINFO {
            hAdapter: handle.raw,
            Type: kind,
            pPrivateDriverData: std::ptr::from_mut(value).cast::<c_void>(),
            PrivateDriverDataSize: size,
        };
        // SAFETY: query points to a live owned handle and a writable value of the declared size.
        let status = unsafe { D3DKMTQueryAdapterInfo(&mut query) };
        if status.0 == 0 {
            Ok(())
        } else {
            Err(DeviceError::Invalid)
        }
    }

    fn query_physical_pnp_key(
        handle: &OwnedD3dkmtAdapter,
        physical_index: u32,
    ) -> Result<Vec<u16>, DeviceError> {
        let mut buffer = [0_u16; MAX_DEVICE_ID_UTF16_UNITS];
        let mut character_count = u32::try_from(buffer.len()).map_err(|_| DeviceError::Overflow)?;
        let mut value = D3DKMT_QUERY_PHYSICAL_ADAPTER_PNP_KEY {
            PhysicalAdapterIndex: physical_index,
            PnPKeyType: D3DKMT_PNP_KEY_SOFTWARE,
            pDest: PWSTR(buffer.as_mut_ptr()),
            pCchDest: &mut character_count,
        };
        query_adapter_info(handle, KMTQAITYPE_PHYSICALADAPTERPNPKEY, &mut value)?;
        let character_count =
            usize::try_from(character_count).map_err(|_| DeviceError::Overflow)?;
        if character_count < 2
            || character_count > buffer.len()
            || buffer[character_count - 1] != 0
            || buffer[..character_count - 1].contains(&0)
        {
            return Err(DeviceError::Invalid);
        }
        Ok(buffer[..character_count - 1].to_vec())
    }

    fn locate_device_node(pnp_key: &[u16]) -> Result<u32, DeviceError> {
        if pnp_key.is_empty() || pnp_key.len() >= MAX_DEVICE_ID_UTF16_UNITS {
            return Err(DeviceError::Invalid);
        }
        let mut nul_terminated = Vec::with_capacity(pnp_key.len() + 1);
        nul_terminated.extend_from_slice(pnp_key);
        nul_terminated.push(0);
        let mut device_node = 0_u32;
        // SAFETY: the input is a bounded NUL-terminated device-instance identifier buffer.
        let result = unsafe {
            CM_Locate_DevNodeW(
                &mut device_node,
                PCWSTR(nul_terminated.as_ptr()),
                CM_LOCATE_DEVNODE_NORMAL,
            )
        };
        if result == CR_SUCCESS {
            Ok(device_node)
        } else {
            Err(DeviceError::Invalid)
        }
    }

    struct OwnedDeviceInfoSet(HDEVINFO);

    impl OwnedDeviceInfoSet {
        fn new(set: HDEVINFO) -> Self {
            #[cfg(test)]
            OPEN_NATIVE_HANDLES.fetch_add(1, Ordering::SeqCst);
            Self(set)
        }
    }

    impl Drop for OwnedDeviceInfoSet {
        fn drop(&mut self) {
            // SAFETY: this instance exclusively owns the successful SetupDiGetClassDevsW result.
            let _ = unsafe { SetupDiDestroyDeviceInfoList(self.0) };
            #[cfg(test)]
            OPEN_NATIVE_HANDLES.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn resolve_device_node(
        pnp_key: &[u16],
        cancellation: &CancellationToken,
    ) -> Result<u32, DeviceError> {
        if let Some(driver_key) = driver_key_suffix(pnp_key)? {
            return find_device_node_by_driver_key(&driver_key, cancellation);
        }
        check_cancelled(cancellation)?;
        locate_device_node(pnp_key)
    }

    fn driver_key_suffix(pnp_key: &[u16]) -> Result<Option<Vec<u16>>, DeviceError> {
        const MARKER: &[u8] = b"\\control\\class\\";
        if pnp_key.is_empty() || pnp_key.len() >= MAX_DEVICE_ID_UTF16_UNITS {
            return Err(DeviceError::Invalid);
        }
        let marker_start = pnp_key.windows(MARKER.len()).position(|candidate| {
            candidate
                .iter()
                .zip(MARKER)
                .all(|(unit, marker)| ascii_lower_u16(*unit) == u16::from(*marker))
        });
        let Some(marker_start) = marker_start else {
            return Ok(None);
        };
        let suffix_start = marker_start
            .checked_add(MARKER.len())
            .ok_or(DeviceError::Overflow)?;
        let suffix = &pnp_key[suffix_start..];
        if suffix.is_empty() || suffix.contains(&0) {
            return Err(DeviceError::Invalid);
        }
        Ok(Some(suffix.to_vec()))
    }

    fn find_device_node_by_driver_key(
        driver_key: &[u16],
        cancellation: &CancellationToken,
    ) -> Result<u32, DeviceError> {
        check_cancelled(cancellation)?;
        let class_guid = driver_class_guid(driver_key)?;
        let expected = driver_key
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        // SAFETY: the class GUID came from the bounded OS driver key and no remote enumerator is used.
        let set =
            unsafe { SetupDiGetClassDevsW(Some(&class_guid), PCWSTR::null(), None, DIGCF_PRESENT) }
                .map_err(|_| DeviceError::Invalid)?;
        let set = OwnedDeviceInfoSet::new(set);
        let mut match_node = None;
        for index in 0..=MAX_WINDOWS_ADAPTERS {
            check_cancelled(cancellation)?;
            let mut info = SP_DEVINFO_DATA {
                cbSize: u32::try_from(std::mem::size_of::<SP_DEVINFO_DATA>())
                    .map_err(|_| DeviceError::Overflow)?,
                ..SP_DEVINFO_DATA::default()
            };
            // SAFETY: set is live and info has the documented cbSize and writable layout.
            match unsafe {
                SetupDiEnumDeviceInfo(
                    set.0,
                    u32::try_from(index).map_err(|_| DeviceError::Overflow)?,
                    &mut info,
                )
            } {
                Ok(()) => {}
                Err(error)
                    if error.code()
                        == HRESULT::from_win32(
                            windows::Win32::Foundation::ERROR_NO_MORE_ITEMS.0,
                        ) =>
                {
                    break;
                }
                Err(_) => return Err(DeviceError::Invalid),
            }
            if index == MAX_WINDOWS_ADAPTERS {
                return Err(DeviceError::Overflow);
            }
            let Some(candidate) =
                read_optional_string_property(info.DevInst, &DEVPKEY_Device_Driver, cancellation)?
            else {
                continue;
            };
            if candidate.eq_ignore_ascii_case(&expected)
                && match_node.replace(info.DevInst).is_some()
            {
                return Err(DeviceError::Ambiguous);
            }
        }
        match_node.ok_or(DeviceError::Invalid)
    }

    fn driver_class_guid(driver_key: &[u16]) -> Result<GUID, DeviceError> {
        if driver_key.len() < 39
            || driver_key[0] != u16::from(b'{')
            || driver_key[37] != u16::from(b'}')
            || driver_key[38] != u16::from(b'\\')
        {
            return Err(DeviceError::Invalid);
        }
        let guid = driver_key[1..37]
            .iter()
            .map(|unit| u8::try_from(*unit).map(char::from))
            .collect::<Result<String, _>>()
            .map_err(|_| DeviceError::Invalid)?;
        GUID::try_from(guid.as_str()).map_err(|_| DeviceError::Invalid)
    }

    fn ascii_lower_u16(unit: u16) -> u16 {
        if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
            unit + u16::from(b'a' - b'A')
        } else {
            unit
        }
    }

    fn read_instance_id_twice(
        device_node: u32,
        cancellation: &CancellationToken,
    ) -> Result<Vec<u16>, DeviceError> {
        let first = read_required_string_property(
            device_node,
            &DEVPKEY_Device_InstanceId,
            MAX_DEVICE_ID_UTF16_UNITS,
            cancellation,
        )?;
        check_cancelled(cancellation)?;
        let second = read_required_string_property(
            device_node,
            &DEVPKEY_Device_InstanceId,
            MAX_DEVICE_ID_UTF16_UNITS,
            cancellation,
        )?;
        if first == second {
            Ok(first)
        } else {
            Err(DeviceError::Invalid)
        }
    }

    fn read_driver_snapshot(
        device_node: u32,
        dxcore_version: Option<Vec<u8>>,
        d3dkmt_version: Option<Vec<u8>>,
        cancellation: &CancellationToken,
    ) -> Result<WindowsDriverSnapshot, DeviceError> {
        Ok(WindowsDriverSnapshot {
            package: read_optional_string_property(
                device_node,
                &DEVPKEY_Device_Driver,
                cancellation,
            )?,
            date: read_optional_fixed_property(
                device_node,
                &DEVPKEY_Device_DriverDate,
                DEVPROP_TYPE_FILETIME,
                8,
                cancellation,
            )?,
            version: read_optional_string_property(
                device_node,
                &DEVPKEY_Device_DriverVersion,
                cancellation,
            )?,
            provider: read_optional_string_property(
                device_node,
                &DEVPKEY_Device_DriverProvider,
                cancellation,
            )?,
            dxcore_version,
            d3dkmt_version,
        })
    }

    fn read_required_string_property(
        device_node: u32,
        key: &windows::Win32::Foundation::DEVPROPKEY,
        maximum_units: usize,
        cancellation: &CancellationToken,
    ) -> Result<Vec<u16>, DeviceError> {
        let (property_type, bytes) =
            read_device_property(device_node, key, cancellation)?.ok_or(DeviceError::Invalid)?;
        if property_type != DEVPROP_TYPE_STRING || bytes.len() % 2 != 0 {
            return Err(DeviceError::Invalid);
        }
        let units = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        if units.len() < 2
            || units.len() > maximum_units
            || units.last() != Some(&0)
            || units[..units.len() - 1].contains(&0)
        {
            return Err(DeviceError::Invalid);
        }
        Ok(units[..units.len() - 1].to_vec())
    }

    fn read_optional_string_property(
        device_node: u32,
        key: &windows::Win32::Foundation::DEVPROPKEY,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<u8>>, DeviceError> {
        let Some((property_type, bytes)) = read_device_property(device_node, key, cancellation)?
        else {
            return Ok(None);
        };
        if property_type != DEVPROP_TYPE_STRING || bytes.len() % 2 != 0 {
            return Err(DeviceError::Invalid);
        }
        let units = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        if units.len() < 2 || units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
            return Err(DeviceError::Invalid);
        }
        let bytes = units[..units.len() - 1]
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        if bytes.is_empty() {
            Ok(None)
        } else if bytes.len() > MAX_PRIVATE_INPUT_BYTES {
            Err(DeviceError::Overflow)
        } else {
            Ok(Some(bytes))
        }
    }

    fn read_optional_fixed_property(
        device_node: u32,
        key: &windows::Win32::Foundation::DEVPROPKEY,
        expected_type: DEVPROPTYPE,
        expected_length: usize,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<u8>>, DeviceError> {
        let Some((property_type, bytes)) = read_device_property(device_node, key, cancellation)?
        else {
            return Ok(None);
        };
        if property_type != expected_type || bytes.len() != expected_length {
            return Err(DeviceError::Invalid);
        }
        Ok(Some(bytes))
    }

    fn read_device_property(
        device_node: u32,
        key: &windows::Win32::Foundation::DEVPROPKEY,
        cancellation: &CancellationToken,
    ) -> Result<Option<(DEVPROPTYPE, Vec<u8>)>, DeviceError> {
        check_cancelled(cancellation)?;
        let mut property_type = DEVPROPTYPE::default();
        let mut required_size = 0_u32;
        // SAFETY: output pointers are initialized; a null buffer with size zero is the documented probe.
        let probe = unsafe {
            CM_Get_DevNode_PropertyW(
                device_node,
                key,
                &mut property_type,
                None,
                &mut required_size,
                0,
            )
        };
        if probe == CR_NO_SUCH_VALUE {
            return Ok(None);
        }
        if probe != CR_BUFFER_SMALL || required_size == 0 {
            return Err(DeviceError::Invalid);
        }
        check_cancelled(cancellation)?;
        let required_size = usize::try_from(required_size).map_err(|_| DeviceError::Overflow)?;
        if required_size > MAX_PRIVATE_INPUT_BYTES {
            return Err(DeviceError::Overflow);
        }
        let mut bytes = vec![0_u8; required_size];
        let mut actual_size = u32::try_from(required_size).map_err(|_| DeviceError::Overflow)?;
        let mut actual_type = DEVPROPTYPE::default();
        // SAFETY: the buffer is writable for actual_size bytes and all output pointers are valid.
        let result = unsafe {
            CM_Get_DevNode_PropertyW(
                device_node,
                key,
                &mut actual_type,
                Some(bytes.as_mut_ptr()),
                &mut actual_size,
                0,
            )
        };
        check_cancelled(cancellation)?;
        if result != CR_SUCCESS
            || actual_type != property_type
            || usize::try_from(actual_size).map_err(|_| DeviceError::Overflow)? != required_size
        {
            return Err(DeviceError::Invalid);
        }
        Ok(Some((actual_type, bytes)))
    }

    fn luid_to_i64(luid: LUID) -> i64 {
        ((luid.HighPart as i64) << 32) | i64::from(luid.LowPart)
    }

    fn i64_to_luid(value: i64) -> LUID {
        LUID {
            LowPart: value as u32,
            HighPart: (value >> 32) as i32,
        }
    }
}

#[cfg(all(windows, test))]
pub(super) use native::{
    WindowsDeviceEnumerator, exercise_native_handle_exit_for_test,
    native_open_handle_count_for_test,
};
