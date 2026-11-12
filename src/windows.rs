//! Windows DMA surface: Kernel DMA Protection state straight from the kernel,
//! the device-enumeration policy, and the ACPI DMAR/IVRS tables.

use serde::Serialize;
use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};
use windows_sys::Win32::System::SystemInformation::GetSystemFirmwareTable;

/// SYSTEM_VSM_PROTECTION_INFORMATION { DmaProtectionsAvailable,
/// DmaProtectionsInUse, HardwareMbecAvailable, ApicVirtualizationAvailable }.
/// This is the IOMMU as used by the hypervisor/VBS — *not* Kernel DMA
/// Protection: it can read 1/1 while external devices are unprotected.
const SYSTEM_VSM_PROTECTION_INFORMATION: i32 = 169;
/// SYSTEM_DMA_GUARD_POLICY_INFORMATION { DmaGuardPolicyEnabled } — what
/// msinfo32 reports as "Kernel DMA Protection". Requires a 1-byte buffer.
const SYSTEM_DMA_GUARD_POLICY_INFORMATION: i32 = 202;

#[derive(Debug, Default, Serialize)]
pub struct WinState {
    /// IOMMU available to / used by the hypervisor (VBS).
    pub iommu_available: Option<bool>,
    pub iommu_in_use_by_vbs: Option<bool>,
    /// Kernel DMA Protection for external devices.
    pub kernel_dma_protection: Option<bool>,
    pub mbec_available: Option<bool>,
    /// HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy
    pub enumeration_policy: Option<u32>,
    #[serde(skip)]
    pub dmar_raw: Option<Vec<u8>>,
    #[serde(skip)]
    pub ivrs_raw: Option<Vec<u8>>,
}

fn query(class: i32, len: usize) -> Option<Vec<u8>> {
    let mut b = vec![0u8; len];
    let mut ret = 0u32;
    // SAFETY: b is writable for `len` bytes.
    let st =
        unsafe { NtQuerySystemInformation(class, b.as_mut_ptr().cast(), len as u32, &mut ret) };
    (st >= 0).then_some(b)
}

fn acpi_table(sig: &[u8; 4]) -> Option<Vec<u8>> {
    let provider = u32::from_be_bytes(*b"ACPI");
    let id = u32::from_le_bytes(*sig);
    // SAFETY: size query with a null buffer, then a fill of exactly that size.
    unsafe {
        let n = GetSystemFirmwareTable(provider, id, std::ptr::null_mut(), 0);
        if n == 0 {
            return None;
        }
        let mut b = vec![0u8; n as usize];
        let got = GetSystemFirmwareTable(provider, id, b.as_mut_ptr().cast(), n);
        (got == n).then_some(b)
    }
}

fn reg_dword(key: &str, value: &str) -> Option<u32> {
    let w = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let (k, v) = (w(key), w(value));
    let mut data = 0u32;
    let mut size = 4u32;
    // SAFETY: 4-byte out buffer; NUL-terminated strings.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            k.as_ptr(),
            v.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    };
    (rc == 0).then_some(data)
}

pub fn collect() -> WinState {
    let vsm = query(SYSTEM_VSM_PROTECTION_INFORMATION, 4);
    WinState {
        iommu_available: vsm.as_ref().map(|b| b[0] != 0),
        iommu_in_use_by_vbs: vsm.as_ref().map(|b| b[1] != 0),
        mbec_available: vsm.as_ref().map(|b| b[2] != 0),
        kernel_dma_protection: query(SYSTEM_DMA_GUARD_POLICY_INFORMATION, 1).map(|b| b[0] != 0),
        enumeration_policy: reg_dword(
            r"SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection",
            "DeviceEnumerationPolicy",
        ),
        dmar_raw: acpi_table(b"DMAR"),
        ivrs_raw: acpi_table(b"IVRS"),
    }
}
