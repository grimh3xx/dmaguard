//! ACPI DMAR (Intel VT-d) and IVRS (AMD-Vi) table parsing. Both tables are
//! read raw — from sysfs, GetSystemFirmwareTable, or a dump file — so the
//! same code runs everywhere and can be unit-tested with synthetic tables.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub signature: String,
    pub length: u32,
    pub revision: u8,
    pub checksum_ok: bool,
    pub oem_id: String,
    pub oem_table_id: String,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .trim_end_matches(['\0', ' '])
        .to_string()
}

pub fn header(t: &[u8]) -> Option<Header> {
    if t.len() < 36 {
        return None;
    }
    let length = u32_at(t, 4)?;
    let body = t.get(..length as usize)?;
    Some(Header {
        signature: text(&t[0..4]),
        length,
        revision: t[8],
        checksum_ok: body.iter().fold(0u8, |a, b| a.wrapping_add(*b)) == 0,
        oem_id: text(&t[10..16]),
        oem_table_id: text(&t[16..24]),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct Rmrr {
    pub segment: u16,
    pub base: String,
    pub limit: String,
    pub devices: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Dmar {
    pub header: Header,
    pub host_address_width: u8,
    pub intr_remap: bool,
    pub x2apic_opt_out: bool,
    /// DMA_CTRL_PLATFORM_OPT_IN_FLAG: firmware kept DMA protection on through
    /// the boot-to-OS handoff. Windows Kernel DMA Protection and Linux
    /// Thunderbolt `iommu_dma_protection` both require it.
    pub dma_ctrl_platform_opt_in: bool,
    pub drhd_units: usize,
    pub include_pci_all: bool,
    pub rmrrs: Vec<Rmrr>,
    pub atsr: usize,
    pub satc: usize,
}

/// Device scope entries: Type u8, Length u8, Reserved u16, EnumerationID u8,
/// StartBus u8, then (Device u8, Function u8) path pairs.
fn scopes(b: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut p = 0;
    while p + 6 <= b.len() {
        let len = b[p + 1] as usize;
        if len < 6 || p + len > b.len() {
            break;
        }
        let kind = match b[p] {
            1 => "pci-endpoint",
            2 => "pci-bridge",
            3 => "ioapic",
            4 => "hpet",
            5 => "acpi-namespace",
            _ => "other",
        };
        let bus = b[p + 5];
        let path: Vec<String> = b[p + 6..p + len]
            .chunks_exact(2)
            .map(|df| format!("{:02x}.{}", df[0], df[1]))
            .collect();
        out.push(format!("{kind} {bus:02x}:{}", path.join("/")));
        p += len;
    }
    out
}

pub fn parse_dmar(t: &[u8]) -> Option<Dmar> {
    let header = header(t)?;
    if header.signature != "DMAR" || t.len() < 48 {
        return None;
    }
    let flags = t[37];
    let mut d = Dmar {
        host_address_width: t[36].wrapping_add(1),
        intr_remap: flags & 0x1 != 0,
        x2apic_opt_out: flags & 0x2 != 0,
        dma_ctrl_platform_opt_in: flags & 0x4 != 0,
        drhd_units: 0,
        include_pci_all: false,
        rmrrs: Vec::new(),
        atsr: 0,
        satc: 0,
        header,
    };
    let end = (d.header.length as usize).min(t.len());
    let mut p = 48;
    while p + 4 <= end {
        let typ = u16_at(t, p)?;
        let len = u16_at(t, p + 2)? as usize;
        if len < 4 || p + len > end {
            break;
        }
        let s = &t[p..p + len];
        match typ {
            0 => {
                d.drhd_units += 1;
                d.include_pci_all |= s.get(4).is_some_and(|f| f & 1 != 0);
            }
            1 if len >= 24 => d.rmrrs.push(Rmrr {
                segment: u16_at(s, 6)?,
                base: format!("{:#x}", u64_at(s, 8)?),
                limit: format!("{:#x}", u64_at(s, 16)?),
                devices: scopes(&s[24..]),
            }),
            2 => d.atsr += 1,
            5 => d.satc += 1,
            _ => {}
        }
        p += len;
    }
    Some(d)
}

#[derive(Debug, Clone, Serialize)]
pub struct Ivrs {
    pub header: Header,
    /// IVinfo[1]: platform requests DMA remapping be kept on for pre-boot
    /// protection (AMD analogue of DMA_CTRL_PLATFORM_OPT_IN).
    pub dma_remap_opt_in: bool,
    pub efr_supported: bool,
    pub ivhd_blocks: usize,
    pub ivmd_blocks: usize,
}

pub fn parse_ivrs(t: &[u8]) -> Option<Ivrs> {
    let header = header(t)?;
    if header.signature != "IVRS" || t.len() < 48 {
        return None;
    }
    let ivinfo = u32_at(t, 36)?;
    let mut v = Ivrs {
        dma_remap_opt_in: ivinfo & 0x2 != 0,
        efr_supported: ivinfo & 0x1 != 0,
        ivhd_blocks: 0,
        ivmd_blocks: 0,
        header,
    };
    let end = (v.header.length as usize).min(t.len());
    let mut p = 48;
    while p + 4 <= end {
        let typ = t[p];
        let len = u16_at(t, p + 2)? as usize;
        if len < 4 || p + len > end {
            break;
        }
        match typ {
            0x10 | 0x11 | 0x40 => v.ivhd_blocks += 1,
            0x20..=0x22 => v.ivmd_blocks += 1,
            _ => {}
        }
        p += len;
    }
    Some(v)
}

#[cfg(test)]
pub mod build {
    pub fn table(sig: &[u8; 4], extra_hdr: &[u8], body: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(sig);
        t.extend_from_slice(&0u32.to_le_bytes());
        t.push(1); // revision
        t.push(0); // checksum, patched below
        t.extend_from_slice(b"GRIMH3");
        t.extend_from_slice(b"TESTTBL ");
        t.extend_from_slice(&[0u8; 12]);
        t.extend_from_slice(extra_hdr);
        t.extend_from_slice(body);
        let len = t.len() as u32;
        t[4..8].copy_from_slice(&len.to_le_bytes());
        let sum = t.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        t[9] = 0u8.wrapping_sub(sum);
        t
    }

    pub fn dmar(flags: u8, with_rmrr: bool) -> Vec<u8> {
        let mut hdr = vec![38, flags];
        hdr.extend_from_slice(&[0u8; 10]);
        let mut body = Vec::new();
        // DRHD, INCLUDE_PCI_ALL
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&16u16.to_le_bytes());
        body.extend_from_slice(&[1, 0, 0, 0]);
        body.extend_from_slice(&0xfed9_0000u64.to_le_bytes());
        if with_rmrr {
            body.extend_from_slice(&1u16.to_le_bytes());
            body.extend_from_slice(&32u16.to_le_bytes());
            body.extend_from_slice(&[0, 0, 0, 0]);
            body.extend_from_slice(&0x7c00_0000u64.to_le_bytes());
            body.extend_from_slice(&0x7fff_ffffu64.to_le_bytes());
            body.extend_from_slice(&[1, 8, 0, 0, 0, 0, 0x14, 0]); // endpoint 00:14.0 (xHCI)
        }
        table(b"DMAR", &hdr, &body)
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    #[test]
    fn dmar_flags_and_structures() {
        let d = parse_dmar(&dmar(0b101, true)).unwrap();
        assert!(d.header.checksum_ok);
        assert_eq!(d.header.oem_id, "GRIMH3");
        assert_eq!(d.host_address_width, 39);
        assert!(d.intr_remap && d.dma_ctrl_platform_opt_in && !d.x2apic_opt_out);
        assert_eq!(d.drhd_units, 1);
        assert!(d.include_pci_all);
        assert_eq!(d.rmrrs.len(), 1);
        assert_eq!(d.rmrrs[0].devices, vec!["pci-endpoint 00:14.0"]);
    }

    #[test]
    fn dmar_bad_checksum_detected() {
        let mut t = dmar(0, false);
        t[40] ^= 0xff;
        assert!(!parse_dmar(&t).unwrap().header.checksum_ok);
    }

    #[test]
    fn ivrs_opt_in_bit() {
        let mut hdr = 0x2u32.to_le_bytes().to_vec();
        hdr.extend_from_slice(&[0u8; 8]);
        let mut body = vec![0x40, 0, 8, 0];
        body.extend_from_slice(&[0u8; 4]);
        let v = parse_ivrs(&table(b"IVRS", &hdr, &body)).unwrap();
        assert!(v.dma_remap_opt_in);
        assert_eq!(v.ivhd_blocks, 1);
    }

    #[test]
    fn truncated_is_none() {
        assert!(parse_dmar(&[0u8; 20]).is_none());
        assert!(parse_dmar(&table(b"APIC", &[0; 12], &[])).is_none());
    }
}
