//! DMA attack-surface findings, shared between Linux and Windows.

use serde::Serialize;

use crate::acpi::{Dmar, Ivrs};
use crate::report::{Finding, Severity};

#[derive(Debug, Default, Serialize)]
pub struct Firmware {
    pub dmar: Option<Dmar>,
    pub ivrs: Option<Ivrs>,
    /// Tables could not be read (e.g. not root); absence means nothing then.
    pub unreadable: Option<String>,
}

pub fn firmware(fw: &Firmware, x86: bool) -> Vec<Finding> {
    let mut f = Vec::new();
    if fw.dmar.is_none() && fw.ivrs.is_none() {
        if fw.unreadable.is_none() && x86 {
            f.push(
                Finding::new("DMA-012", Severity::High, "Firmware exposes no IOMMU (no ACPI DMAR / IVRS table)")
                    .detail("VT-d / AMD-Vi is disabled or unsupported, so every PCIe, Thunderbolt and FireWire device can read and write all of physical memory (PCILeech-style attacks, malicious peripherals).")
                    .fix("Enable 'VT-d' / 'Intel Virtualization for Directed I/O' or 'IOMMU' / 'AMD-Vi' in firmware setup.")
                    .source("acpi/DMAR"),
            );
        } else if let Some(e) = &fw.unreadable {
            f.push(
                Finding::new(
                    "DMA-015",
                    Severity::Info,
                    "ACPI DMAR/IVRS tables not readable",
                )
                .detail(e.clone())
                .fix("Re-run as root to include firmware-table checks."),
            );
        }
        return f;
    }
    if let Some(d) = &fw.dmar {
        if !d.dma_ctrl_platform_opt_in {
            f.push(
                Finding::new("DMA-003", Severity::Medium, "Firmware does not opt in to pre-boot DMA protection (DMAR)")
                    .detail("DMA_CTRL_PLATFORM_OPT_IN is clear: firmware does not promise to keep VT-d protecting memory across the boot-to-OS handoff. Windows Kernel DMA Protection and Linux Thunderbolt `iommu_dma_protection` stay off on such platforms, and devices can DMA during early boot.")
                    .fix("Update firmware; enable 'Pre-boot DMA protection' / 'Kernel DMA Protection' / 'Thunderbolt DMA protection' in setup if offered.")
                    .source("acpi/DMAR"),
            );
        }
        if !d.intr_remap {
            f.push(
                Finding::new("DMA-007", Severity::Medium, "Interrupt remapping not supported (DMAR)")
                    .detail("Without interrupt remapping a DMA-capable device can forge MSIs and inject interrupts, a known IOMMU bypass.")
                    .fix("Enable interrupt remapping / x2APIC in firmware or update it.")
                    .source("acpi/DMAR"),
            );
        }
        if d.x2apic_opt_out {
            f.push(
                Finding::new("DMA-014", Severity::Low, "Firmware requests x2APIC opt-out")
                    .detail("X2APIC_OPT_OUT asks the OS to stay in xAPIC mode, which limits interrupt-remapping protection.")
                    .source("acpi/DMAR"),
            );
        }
        let odd: Vec<String> = d
            .rmrrs
            .iter()
            .flat_map(|r| {
                r.devices
                    .iter()
                    .map(move |dev| format!("{dev} [{}..{}]", r.base, r.limit))
            })
            .filter(|dev| {
                !dev.contains("00:02.0")
                    && !dev.contains("00:14.0")
                    && !dev.contains("00:1a.")
                    && !dev.contains("00:1d.")
            })
            .collect();
        if !odd.is_empty() {
            let mut fi = Finding::new("DMA-010", Severity::Info, format!("{} RMRR identity-mapped region(s) on non-legacy devices", odd.len()))
                .detail("Reserved Memory Region Reporting forces identity mappings that the IOMMU cannot fully isolate. Expected for integrated graphics/USB; unusual elsewhere.")
                .source("acpi/DMAR");
            for o in odd.into_iter().take(10) {
                fi = fi.evidence(o);
            }
            f.push(fi);
        }
        if !d.header.checksum_ok {
            f.push(
                Finding::new("DMA-011", Severity::Low, "DMAR table checksum is invalid")
                    .detail("Firmware bug or tampered table.")
                    .source("acpi/DMAR"),
            );
        }
    }
    if let Some(v) = &fw.ivrs {
        if !v.dma_remap_opt_in {
            f.push(
                Finding::new("DMA-003", Severity::Medium, "Firmware does not opt in to pre-boot DMA protection (IVRS)")
                    .detail("IVinfo DMA-remap bit clear: the AMD platform does not request DMA protection through boot, so OS-level Kernel DMA Protection stays off.")
                    .fix("Update firmware; enable 'Kernel DMA Protection' / 'DMA protection' in setup if offered.")
                    .source("acpi/IVRS"),
            );
        }
        if !v.header.checksum_ok {
            f.push(
                Finding::new("DMA-011", Severity::Low, "IVRS table checksum is invalid")
                    .detail("Firmware bug or tampered table.")
                    .source("acpi/IVRS"),
            );
        }
    }
    f
}

#[cfg(not(windows))]
pub fn linux(s: &crate::linux::LinuxState) -> Vec<Finding> {
    use crate::linux::has_arg;
    let mut f = Vec::new();
    let cmd = s.cmdline.as_deref().unwrap_or("");

    for arg in ["intel_iommu=off", "amd_iommu=off", "iommu=off"] {
        if has_arg(cmd, arg) {
            f.push(
                Finding::new("DMA-006", Severity::High, format!("IOMMU disabled on the kernel command line ({arg})"))
                    .detail("The kernel was told not to use the IOMMU; every bus-mastering device has unrestricted access to RAM.")
                    .fix(format!("Remove `{arg}` from the bootloader configuration."))
                    .source("/proc/cmdline"),
            );
        }
    }
    if s.iommu_units.is_empty() && !s.wsl {
        f.push(
            Finding::new("DMA-001", Severity::High, "No IOMMU is active")
                .detail("/sys/class/iommu is empty: devices are not isolated from system memory.")
                .fix("Enable VT-d / AMD-Vi in firmware; on Intel with older kernels add intel_iommu=on.")
                .source("/sys/class/iommu"),
        );
    }
    let identity = s.domain_types.get("identity").copied().unwrap_or(0);
    if identity > 0 || has_arg(cmd, "iommu=pt") || has_arg(cmd, "iommu.passthrough=1") {
        f.push(
            Finding::new("DMA-002", Severity::Medium, format!("IOMMU in passthrough mode ({identity} identity-mapped group(s))"))
                .detail("Identity domains give devices 1:1 access to physical memory — the IOMMU is present but not isolating them. Thunderbolt/untrusted devices are still forced into DMA domains, internal ones are not.")
                .fix("Drop iommu=pt / iommu.passthrough=1 unless required for performance; prefer iommu.strict=1.")
                .source("/sys/kernel/iommu_groups/*/type"),
        );
    }
    if let Some(n) = s.domain_types.get("DMA-FQ").filter(|n| **n > 0) {
        f.push(
            Finding::new("DMA-016", Severity::Low, format!("Lazy IOTLB invalidation on {n} group(s) (DMA-FQ)"))
                .detail("Flush queues defer IOTLB invalidation, leaving a short window where a device can still reach freed buffers.")
                .fix("Boot with iommu.strict=1 on machines exposed to untrusted peripherals.")
                .source("/sys/kernel/iommu_groups/*/type"),
        );
    }
    for d in &s.thunderbolt {
        let src = format!("/sys/bus/thunderbolt/devices/{}/security", d.name);
        match d.security.as_str() {
            "none" if d.iommu_dma_protection != Some(true) => f.push(
                Finding::new("DMA-005", Severity::High, format!("Thunderbolt {} security level 'none' without DMA protection", d.name))
                    .detail("Any Thunderbolt device is connected automatically with PCIe tunnelling and no IOMMU backstop — a plug-in DMA attack needs no user interaction.")
                    .fix("Set the Thunderbolt security level to 'user' or 'secure' in firmware (and use bolt/boltctl to authorise devices), or enable Kernel DMA Protection.")
                    .source(src),
            ),
            "none" => f.push(
                Finding::new("DMA-005", Severity::Low, format!("Thunderbolt {} security level 'none' (IOMMU-protected)", d.name))
                    .detail("Devices auto-connect, but iommu_dma_protection=1 confines them to their own DMA domains.")
                    .source(src),
            ),
            _ => {}
        }
        if d.iommu_dma_protection == Some(false) && d.security != "none" {
            f.push(
                Finding::new("DMA-004", Severity::Medium, format!("Thunderbolt {}: iommu_dma_protection off", d.name))
                    .detail("Authorised Thunderbolt devices are not confined by the IOMMU (requires firmware DMA opt-in + IOMMU).")
                    .fix("Enable the IOMMU and firmware pre-boot DMA protection.")
                    .source(format!("/sys/bus/thunderbolt/devices/{}/iommu_dma_protection", d.name)),
            );
        }
    }
    if !s.removable_pci.is_empty() {
        let mut fi = Finding::new(
            "DMA-013",
            Severity::Info,
            format!(
                "{} external (removable) PCIe device(s) attached",
                s.removable_pci.len()
            ),
        )
        .detail("Devices behind external-facing ports; confirm each one is expected.")
        .source("/sys/bus/pci/devices/*/removable");
        for p in &s.removable_pci {
            fi = fi.evidence(format!(
                "{} {}:{} class {} group {}",
                p.address,
                p.vendor,
                p.device,
                p.class,
                p.iommu_group.as_deref().unwrap_or("-")
            ));
        }
        f.push(fi);
    }
    if s.firewire {
        f.push(
            Finding::new("DMA-009", Severity::Low, "FireWire (IEEE 1394) controller active")
                .detail("FireWire's physical DMA (SBP-2) is the original DMA attack vector; it relies on the IOMMU and firewire-ohci filtering.")
                .fix("Blacklist firewire_ohci / firewire_sbp2 if unused, or disable the controller in firmware.")
                .source("/sys/module/firewire_ohci"),
        );
    }
    f
}

#[cfg(windows)]
pub fn windows(s: &crate::windows::WinState) -> Vec<Finding> {
    let mut f = Vec::new();
    if s.iommu_available == Some(false) {
        f.push(
            Finding::new("DMA-001", Severity::High, "No IOMMU available to Windows")
                .detail("Neither the hypervisor nor the kernel can isolate device DMA: every PCIe/Thunderbolt device can read all of memory.")
                .fix("Enable VT-d / AMD IOMMU (AMD-Vi) in firmware setup.")
                .source("ntdll!NtQuerySystemInformation(SystemVsmProtectionInformation)"),
        );
    }
    if s.kernel_dma_protection == Some(false) {
        let iommu_ok = s.iommu_available == Some(true);
        f.push(
            Finding::new("DMA-004", if iommu_ok { Severity::Medium } else { Severity::High }, "Kernel DMA Protection is off")
                .detail(if iommu_ok {
                    "The IOMMU works (VBS uses it), but Windows does not confine external PCIe / Thunderbolt / USB4 devices. This almost always means firmware lacks the pre-boot DMA opt-in flag (see DMA-003), so a hot-plugged device can DMA into memory — including on the lock screen."
                } else {
                    "External PCIe / Thunderbolt / USB4 devices are not confined by an IOMMU."
                })
                .fix("Update firmware and enable 'Kernel DMA Protection' / 'Pre-boot DMA protection' in setup. Until then: BitLocker with pre-boot PIN, and disable external PCIe tunnelling (Thunderbolt/USB4 PCIe) in firmware when unused.")
                .source("ntdll!NtQuerySystemInformation(SystemDmaGuardPolicyInformation)"),
        );
    }
    let src =
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy";
    match s.enumeration_policy {
        Some(2) => f.push(
            Finding::new("DMA-008", Severity::Medium, "DMA enumeration policy allows all external devices")
                .detail("DeviceEnumerationPolicy=2 lets external devices incompatible with DMA remapping start at any time, even on the lock screen.")
                .fix("Set the Group Policy 'Enumeration policy for external devices incompatible with Kernel DMA Protection' to 'Block all' (0).")
                .source(src),
        ),
        Some(1) | None if s.kernel_dma_protection == Some(true) => f.push(
            Finding::new("DMA-008", Severity::Info, "Incompatible external devices enumerate after user sign-in (default)")
                .detail("Default policy: devices that do not support DMA remapping are blocked only until a user logs in.")
                .fix("Set the policy to 'Block all' (0) for high-risk machines.")
                .source(src),
        ),
        _ => {}
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acpi::{build, parse_dmar};

    #[test]
    fn missing_tables_is_high_unless_unreadable() {
        let f = firmware(&Firmware::default(), true);
        assert_eq!(f[0].id, "DMA-012");
        let f = firmware(
            &Firmware {
                unreadable: Some("root".into()),
                ..Default::default()
            },
            true,
        );
        assert_eq!(f[0].id, "DMA-015");
    }

    #[test]
    fn dmar_without_opt_in_flags() {
        let fw = Firmware {
            dmar: parse_dmar(&build::dmar(0b001, true)),
            ..Default::default()
        };
        let ids: Vec<&str> = firmware(&fw, true).iter().map(|f| f.id).collect();
        assert_eq!(ids, vec!["DMA-003"]); // xHCI RMRR is expected, not reported
        let fw = Firmware {
            dmar: parse_dmar(&build::dmar(0b101, false)),
            ..Default::default()
        };
        assert!(firmware(&fw, true).is_empty());
    }
}
