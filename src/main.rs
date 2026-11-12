//! dmaguard — read-only DMA attack-surface auditor.
//!
//! Answers "can a device I plug in read my memory?": parses the firmware's
//! ACPI DMAR (Intel VT-d) / IVRS (AMD-Vi) tables, then checks how the OS uses
//! the IOMMU — Kernel DMA Protection on Windows; IOMMU domains, boot
//! parameters, Thunderbolt security and external PCIe on Linux.

mod acpi;
mod checks;
#[cfg(not(windows))]
mod linux;
mod report;
#[cfg(windows)]
mod windows;

use std::path::PathBuf;
use std::process::ExitCode;

use anstream::println;
use clap::Parser;
use owo_colors::OwoColorize;
use serde_json::json;

use checks::Firmware;
use report::{Finding, Severity};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO: &str = "https://github.com/grimh3xx/dmaguard";

#[derive(Parser)]
#[command(
    name = "dmaguard",
    version,
    about = "Read-only DMA / IOMMU attack-surface auditor"
)]
struct Cli {
    /// Parse this raw ACPI DMAR table instead of the system's
    #[arg(long, value_name = "FILE")]
    dmar: Option<PathBuf>,
    /// Parse this raw ACPI IVRS table instead of the system's
    #[arg(long, value_name = "FILE")]
    ivrs: Option<PathBuf>,
    /// Linux: audit a tree rooted here (snapshot of /proc and /sys)
    #[cfg(not(windows))]
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,
    #[arg(long, conflicts_with = "sarif")]
    json: bool,
    #[arg(long)]
    sarif: bool,
    #[arg(long, default_value = "info", value_name = "LVL")]
    min_severity: String,
    #[arg(long)]
    no_color: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.no_color {
        anstream::ColorChoice::Never.write_global();
    }
    let Some(min) = Severity::parse(&cli.min_severity) else {
        eprintln!("invalid --min-severity: {}", cli.min_severity);
        return ExitCode::from(64);
    };
    let x86 = cfg!(any(target_arch = "x86_64", target_arch = "x86"));

    let (os_state, mut dmar_raw, mut ivrs_raw, unreadable, os_findings, not_applicable) =
        gather(&cli);
    if let Some(p) = &cli.dmar {
        dmar_raw = std::fs::read(p).ok();
    }
    if let Some(p) = &cli.ivrs {
        ivrs_raw = std::fs::read(p).ok();
    }
    let fw = Firmware {
        dmar: dmar_raw.as_deref().and_then(acpi::parse_dmar),
        ivrs: ivrs_raw.as_deref().and_then(acpi::parse_ivrs),
        unreadable: if cli.dmar.is_some() || cli.ivrs.is_some() {
            None
        } else {
            unreadable
        },
    };

    let mut findings: Vec<Finding> = Vec::new();
    if not_applicable {
        findings.push(
            Finding::new(
                "DMA-017",
                Severity::Info,
                "Running inside WSL — host DMA protection is not visible",
            )
            .detail("The WSL2 VM has no physical devices; the Windows host owns the IOMMU.")
            .fix("Run dmaguard.exe on the Windows host."),
        );
    } else {
        findings.extend(checks::firmware(&fw, x86));
        findings.extend(os_findings);
    }
    let findings = report::filter_sort(findings, min);

    if cli.json {
        let v = json!({ "tool": "dmaguard", "version": VERSION, "firmware": fw, "os": os_state, "findings": findings });
        println!(
            "{}",
            serde_json::to_string_pretty(&v).expect("serializable")
        );
    } else if cli.sarif {
        let s = report::sarif("dmaguard", VERSION, REPO, "platform/dma", &findings);
        println!(
            "{}",
            serde_json::to_string_pretty(&s).expect("serializable")
        );
    } else {
        banner();
        render_firmware(&fw);
        render_os(&os_state);
        report::print_findings(&findings);
        report::print_summary(&findings);
        println!();
    }
    ExitCode::from(report::worst(&findings))
}

type Gathered = (
    serde_json::Value,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Vec<Finding>,
    bool,
);

#[cfg(not(windows))]
fn gather(cli: &Cli) -> Gathered {
    let root = cli.root.clone().unwrap_or_else(|| PathBuf::from("/"));
    let mut s = linux::collect(&root);
    let f = checks::linux(&s);
    let (d, i) = (s.dmar_raw.take(), s.ivrs_raw.take());
    let wsl = s.wsl && cli.root.is_none() && cli.dmar.is_none() && cli.ivrs.is_none();
    (
        serde_json::to_value(&s).expect("serializable"),
        d,
        i,
        s.acpi_error.clone(),
        f,
        wsl,
    )
}

#[cfg(windows)]
fn gather(_cli: &Cli) -> Gathered {
    let mut s = windows::collect();
    let f = checks::windows(&s);
    let (d, i) = (s.dmar_raw.take(), s.ivrs_raw.take());
    (
        serde_json::to_value(&s).expect("serializable"),
        d,
        i,
        None,
        f,
        false,
    )
}

fn banner() {
    println!();
    println!(
        "  {}{}  {}",
        "dma".bold().cyan(),
        "guard".bold().bright_blue(),
        format!("v{VERSION}").dimmed()
    );
    println!(
        "  {}",
        "DMA / IOMMU attack-surface auditor · read-only".dimmed()
    );
}

fn flag(b: bool) -> String {
    if b {
        "yes".green().to_string()
    } else {
        "no".red().to_string()
    }
}

fn render_firmware(fw: &Firmware) {
    report::section("firmware (ACPI)");
    match &fw.dmar {
        Some(d) => {
            report::kv(
                "DMAR",
                format!(
                    "{} {} rev {}{}",
                    d.header.oem_id,
                    d.header.oem_table_id,
                    d.header.revision,
                    if d.header.checksum_ok {
                        ""
                    } else {
                        " (bad checksum)"
                    }
                ),
            );
            report::kv(
                "  remapping units",
                format!(
                    "{} DRHD{}",
                    d.drhd_units,
                    if d.include_pci_all {
                        " (INCLUDE_PCI_ALL)"
                    } else {
                        ""
                    }
                ),
            );
            report::kv("  address width", format!("{} bits", d.host_address_width));
            report::kv("  DMA opt-in", flag(d.dma_ctrl_platform_opt_in));
            report::kv("  interrupt remap", flag(d.intr_remap));
            report::kv(
                "  RMRR / ATSR / SATC",
                format!("{} / {} / {}", d.rmrrs.len(), d.atsr, d.satc),
            );
        }
        None => report::kv("DMAR", "—".dimmed()),
    }
    match &fw.ivrs {
        Some(v) => {
            report::kv(
                "IVRS",
                format!(
                    "{} {} rev {}",
                    v.header.oem_id, v.header.oem_table_id, v.header.revision
                ),
            );
            report::kv(
                "  IVHD / IVMD",
                format!("{} / {}", v.ivhd_blocks, v.ivmd_blocks),
            );
            report::kv("  DMA remap opt-in", flag(v.dma_remap_opt_in));
        }
        None => report::kv("IVRS", "—".dimmed()),
    }
    if let Some(e) = &fw.unreadable {
        report::kv("note", e.yellow());
    }
}

fn render_os(s: &serde_json::Value) {
    report::section("operating system");
    let Some(obj) = s.as_object() else { return };
    for (k, v) in obj {
        let shown = match v {
            serde_json::Value::Null => continue,
            serde_json::Value::Bool(b) => flag(*b),
            serde_json::Value::Array(a) if a.is_empty() => "none".dimmed().to_string(),
            serde_json::Value::Array(a) => a
                .iter()
                .map(|x| {
                    x.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| x.to_string())
                })
                .collect::<Vec<_>>()
                .join(", "),
            serde_json::Value::Object(o) if o.is_empty() => "—".dimmed().to_string(),
            serde_json::Value::Object(o) => o
                .iter()
                .map(|(a, b)| format!("{a}={b}"))
                .collect::<Vec<_>>()
                .join(" "),
            serde_json::Value::String(t) => t.clone(),
            other => other.to_string(),
        };
        report::kv(&k.replace('_', " "), shown);
    }
}
