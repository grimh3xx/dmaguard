<img src="docs/banner.svg" alt="dmaguard" width="100%">

[![build](https://img.shields.io/github/actions/workflow/status/grimh3xx/dmaguard/build.yml?branch=main&style=flat-square&labelColor=111826&label=build)](https://github.com/grimh3xx/dmaguard/actions)
[![license](https://img.shields.io/github/license/grimh3xx/dmaguard?style=flat-square&labelColor=111826&color=22D3EE)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-2021-3B82F6?style=flat-square&labelColor=111826)
![platform](https://img.shields.io/badge/Windows%20%7C%20Linux-x64-22D3EE?style=flat-square&labelColor=111826)
![read-only](https://img.shields.io/badge/read--only-no%20changes-34D399?style=flat-square&labelColor=111826)

**Can a device you plug in read your memory?** dmaguard answers that
question. It parses the firmware's ACPI **DMAR** (Intel VT-d) and **IVRS**
(AMD-Vi) tables directly, then checks how the OS actually uses the IOMMU:
**Kernel DMA Protection** on Windows; IOMMU domains, boot parameters,
**Thunderbolt security levels** and external PCIe devices on Linux.

## Findings

| ID | Severity | Finding |
|---|---|---|
| DMA-001 | high | No IOMMU active / available |
| DMA-002 | medium | IOMMU in passthrough (identity domains, `iommu=pt`) |
| DMA-003 | medium | Firmware does not opt in to pre-boot DMA protection (DMAR `DMA_CTRL_PLATFORM_OPT_IN` / IVRS IVinfo bit 1). This is the root cause behind "Kernel DMA Protection: Off" |
| DMA-004 | high/medium | Kernel DMA Protection off (Windows) / Thunderbolt `iommu_dma_protection=0` (Linux) |
| DMA-005 | high | Thunderbolt security level `none` without an IOMMU backstop |
| DMA-006 | high | IOMMU disabled on the kernel command line |
| DMA-007 | medium | No interrupt remapping (MSI injection bypass) |
| DMA-008 | medium/info | Windows DMA device-enumeration policy |
| DMA-009 | low | FireWire controller active |
| DMA-010 | info | RMRR identity-mapped regions on devices other than legacy GPU/USB |
| DMA-011 | low | Invalid ACPI table checksum |
| DMA-012 | high | No DMAR/IVRS table at all (VT-d / AMD-Vi off in firmware) |
| DMA-013 | info | External (removable) PCIe devices attached |
| DMA-016 | low | Lazy IOTLB invalidation (`DMA-FQ`) |

### A note on Windows

`SystemVsmProtectionInformation` reports whether the **hypervisor** has an
IOMMU. That can read *available / in use* while external devices are
unprotected. Kernel DMA Protection, as msinfo32 shows it, is
`SystemDmaGuardPolicyInformation`. dmaguard reads both and explains the gap.
On real hardware, a set IOMMU flag together with Kernel DMA Protection Off
traced back to the firmware's IVRS opt-in bit being clear.

## Usage

```sh
dmaguard                         # audit this machine (Linux: root for ACPI tables)
dmaguard --dmar DMAR.bin         # parse a dumped table (acpidump -b, GetSystemFirmwareTable)
dmaguard --ivrs IVRS.bin
dmaguard --root /mnt/snapshot    # Linux: offline /proc + /sys tree
dmaguard --json | --sarif
```

ACPI tables are read from `/sys/firmware/acpi/tables` on Linux and through
`GetSystemFirmwareTable('ACPI', ...)` on Windows, then parsed in-tree. Exit
codes follow the worst finding (0–4).

## Build

```sh
cargo build --release
cargo build --release --target x86_64-pc-windows-gnu
```

MIT © grimh3xx
