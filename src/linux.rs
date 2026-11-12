//! Linux DMA surface: IOMMU units and domain types, boot parameters,
//! Thunderbolt security, external-facing PCIe and FireWire.

use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct TbDomain {
    pub name: String,
    pub security: String,
    pub iommu_dma_protection: Option<bool>,
}

#[derive(Debug, Default, Serialize)]
pub struct TbDevice {
    pub id: String,
    pub vendor: String,
    pub name: String,
    pub authorized: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct PciDev {
    pub address: String,
    pub vendor: String,
    pub device: String,
    pub class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iommu_group: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct LinuxState {
    pub iommu_units: Vec<String>,
    pub iommu_groups: usize,
    /// Default domain type per group: DMA, DMA-FQ, identity, unmanaged, blocked.
    pub domain_types: std::collections::BTreeMap<String, usize>,
    pub cmdline: Option<String>,
    pub thunderbolt: Vec<TbDomain>,
    pub tb_devices: Vec<TbDevice>,
    pub removable_pci: Vec<PciDev>,
    pub firewire: bool,
    #[serde(skip)]
    pub dmar_raw: Option<Vec<u8>>,
    #[serde(skip)]
    pub ivrs_raw: Option<Vec<u8>>,
    #[serde(skip)]
    pub acpi_error: Option<String>,
    pub wsl: bool,
}

fn rd(root: &Path, p: &str) -> Option<String> {
    std::fs::read_to_string(root.join(p.trim_start_matches('/')))
        .ok()
        .map(|s| s.trim().to_string())
}

fn entries(dir: PathBuf) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    v.sort();
    v
}

fn name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn read_table(root: &Path, sig: &str, state_err: &mut Option<String>) -> Option<Vec<u8>> {
    let p = root.join("sys/firmware/acpi/tables").join(sig);
    match std::fs::read(&p) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            *state_err = Some(format!("{} needs root", p.display()));
            None
        }
        Err(_) => None,
    }
}

pub fn collect(root: &Path) -> LinuxState {
    let mut s = LinuxState {
        cmdline: rd(root, "/proc/cmdline"),
        wsl: rd(root, "/proc/sys/kernel/osrelease")
            .is_some_and(|r| r.to_ascii_lowercase().contains("microsoft")),
        ..Default::default()
    };
    s.iommu_units = entries(root.join("sys/class/iommu"))
        .iter()
        .map(|p| name(p))
        .collect();
    let groups = entries(root.join("sys/kernel/iommu_groups"));
    s.iommu_groups = groups.len();
    for g in &groups {
        if let Ok(t) = std::fs::read_to_string(g.join("type")) {
            *s.domain_types.entry(t.trim().to_string()).or_default() += 1;
        }
    }

    for d in entries(root.join("sys/bus/thunderbolt/devices")) {
        let n = name(&d);
        if n.starts_with("domain") {
            s.thunderbolt.push(TbDomain {
                security: std::fs::read_to_string(d.join("security"))
                    .map(|v| v.trim().to_string())
                    .unwrap_or_default(),
                iommu_dma_protection: std::fs::read_to_string(d.join("iommu_dma_protection"))
                    .ok()
                    .map(|v| v.trim() == "1"),
                name: n,
            });
        } else if n.contains('-') && !n.contains(':') && !n.ends_with("-0") {
            let r = |f: &str| {
                std::fs::read_to_string(d.join(f))
                    .map(|v| v.trim().to_string())
                    .ok()
            };
            s.tb_devices.push(TbDevice {
                vendor: r("vendor_name").unwrap_or_default(),
                name: r("device_name").unwrap_or_default(),
                authorized: r("authorized"),
                id: n,
            });
        }
    }

    for d in entries(root.join("sys/bus/pci/devices")) {
        let r = |f: &str| {
            std::fs::read_to_string(d.join(f))
                .map(|v| v.trim().to_string())
                .ok()
        };
        if r("removable").as_deref() == Some("removable") {
            s.removable_pci.push(PciDev {
                address: name(&d),
                vendor: r("vendor").unwrap_or_default(),
                device: r("device").unwrap_or_default(),
                class: r("class").unwrap_or_default(),
                iommu_group: std::fs::read_link(d.join("iommu_group"))
                    .ok()
                    .map(|l| name(&l)),
            });
        }
    }

    s.firewire = root.join("sys/module/firewire_ohci").exists()
        || !entries(root.join("sys/bus/firewire/devices")).is_empty();
    let mut err = None;
    s.dmar_raw = read_table(root, "DMAR", &mut err);
    s.ivrs_raw = read_table(root, "IVRS", &mut err);
    s.acpi_error = err;
    s
}

pub fn has_arg(cmdline: &str, arg: &str) -> bool {
    cmdline
        .split_whitespace()
        .any(|a| a == arg || (arg.ends_with('=') && a.starts_with(arg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_fixture() {
        let root = std::env::temp_dir().join(format!("dmaguard-fx-{}", std::process::id()));
        let w = |p: &str, v: &str| {
            let f = root.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, v).unwrap();
        };
        w("proc/cmdline", "root=/dev/nvme0n1p2 iommu=pt\n");
        std::fs::create_dir_all(root.join("sys/class/iommu/dmar0")).unwrap();
        w("sys/kernel/iommu_groups/0/type", "identity\n");
        w("sys/kernel/iommu_groups/1/type", "DMA-FQ\n");
        w("sys/bus/thunderbolt/devices/domain0/security", "none\n");
        w(
            "sys/bus/thunderbolt/devices/domain0/iommu_dma_protection",
            "0\n",
        );
        w("sys/bus/thunderbolt/devices/0-1/vendor_name", "Dock Co\n");
        w("sys/bus/thunderbolt/devices/0-1/authorized", "1\n");
        w("sys/bus/pci/devices/0000:05:00.0/removable", "removable\n");
        w("sys/bus/pci/devices/0000:05:00.0/vendor", "0x8086\n");
        let s = collect(&root);
        assert_eq!(s.iommu_units, vec!["dmar0"]);
        assert_eq!(s.iommu_groups, 2);
        assert_eq!(s.domain_types.get("identity"), Some(&1));
        assert_eq!(s.thunderbolt[0].security, "none");
        assert_eq!(s.thunderbolt[0].iommu_dma_protection, Some(false));
        assert_eq!(s.tb_devices.len(), 1);
        assert_eq!(s.removable_pci[0].address, "0000:05:00.0");
        assert!(has_arg(s.cmdline.as_deref().unwrap(), "iommu=pt"));
        std::fs::remove_dir_all(root).ok();
    }
}
