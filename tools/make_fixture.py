#!/usr/bin/env python3
"""Build tests/fixtures/laptop: /proc + /sys of a Thunderbolt laptop with a
weak DMA posture, used by docs/demo.svg.

  * ACPI DMAR: interrupt remapping yes, DMA_CTRL_PLATFORM_OPT_IN no,
    an RMRR on the onboard NIC (00:1f.6)
  * IOMMU on, but booted with iommu=pt (identity domains, lazy flush)
  * Thunderbolt domain security "none", iommu_dma_protection 0
  * an external dock's PCIe device attached

Usage: python3 tools/make_fixture.py
"""
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "laptop"


def acpi(sig, extra, body):
    t = bytearray(sig + struct.pack("<IBB", 0, 1, 0) + b"CONTSO" + b"LAPTOP14" + struct.pack("<III", 1, 0x4C544E49, 1))
    t += extra + body
    t[4:8] = struct.pack("<I", len(t))
    t[9] = (-sum(t)) & 0xFF
    return bytes(t)


def dmar():
    hdr = bytes([38, 0b001]) + b"\0" * 10  # HAW 39 bits, INTR_REMAP only
    drhd = struct.pack("<HHBBHQ", 0, 16, 1, 0, 0, 0xFED91000)
    scope = bytes([1, 8, 0, 0, 0, 0, 0x1F, 6])  # endpoint 00:1f.6
    rmrr = struct.pack("<HHHHQQ", 1, 24 + len(scope), 0, 0, 0x7B800000, 0x7BFFFFFF) + scope
    return acpi(b"DMAR", hdr, drhd + rmrr)


def w(rel, data):
    p = OUT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())


def main():
    w("proc/sys/kernel/osrelease", "6.8.0-45-generic\n")
    w("proc/cmdline", "BOOT_IMAGE=/vmlinuz-6.8.0-45-generic root=/dev/nvme0n1p2 ro quiet splash iommu=pt\n")
    w("sys/firmware/acpi/tables/DMAR", dmar())
    w("sys/class/iommu/dmar0/.keep", "")
    for i, t in enumerate(["identity"] * 14 + ["DMA-FQ"] * 3):
        w(f"sys/kernel/iommu_groups/{i}/type", t + "\n")
    w("sys/bus/thunderbolt/devices/domain0/security", "none\n")
    w("sys/bus/thunderbolt/devices/domain0/iommu_dma_protection", "0\n")
    w("sys/bus/thunderbolt/devices/0-0/device_name", "Host router\n")
    w("sys/bus/thunderbolt/devices/0-1/vendor_name", "Contoso\n")
    w("sys/bus/thunderbolt/devices/0-1/device_name", "TB4 Dock\n")
    w("sys/bus/thunderbolt/devices/0-1/authorized", "1\n")
    dev = "sys/bus/pci/devices/0000:3c:00.0"
    w(f"{dev}/removable", "removable\n")
    w(f"{dev}/vendor", "0x8086\n")
    w(f"{dev}/device", "0x15f2\n")
    w(f"{dev}/class", "0x020000\n")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
