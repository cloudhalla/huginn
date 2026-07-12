use crate::error::HuginnError;
use crate::models::system_info::{InstalledSoftware, SoftwareInfo};

use super::registry;

const UNINSTALL_ROOTS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
];

/// Case-insensitive substrings that flag a product as AV/EDR.
const AV_EDR_MARKERS: &[&str] = &[
    "windows defender",
    "microsoft defender",
    "mcafee",
    "symantec",
    "norton",
    "crowdstrike",
    "falcon",
    "sentinelone",
    "sophos",
    "kaspersky",
    "trend micro",
    "eset",
    "bitdefender",
    "cortex xdr",
    "carbon black",
    "cylance",
    "malwarebytes",
    "avast",
    "avg antivirus",
    "webroot",
    "f-secure",
    "elastic agent",
    "elastic endpoint",
    "endgame",
    "tanium",
    "fireeye",
    "trellix",
];

pub fn collect(software: &mut SoftwareInfo) -> Result<(), HuginnError> {
    let mut entries: Vec<InstalledSoftware> = Vec::new();
    for root in UNINSTALL_ROOTS {
        for subkey in registry::enum_subkeys(root) {
            let full = format!("{}\\{}", root, subkey);
            let Some(name) = registry::read_reg_string(&full, "DisplayName") else {
                continue; // Placeholder entries without DisplayName are not real products.
            };
            let version = registry::read_reg_string(&full, "DisplayVersion");
            let vendor = registry::read_reg_string(&full, "Publisher");
            let install_date = registry::read_reg_string(&full, "InstallDate");
            let install_location = registry::read_reg_string(&full, "InstallLocation");
            let is_av_or_edr = is_av_or_edr(&name, vendor.as_deref());

            entries.push(InstalledSoftware {
                name,
                version,
                vendor,
                install_date,
                install_location,
                is_av_or_edr,
            });
        }
    }

    // Dedup by (lowercased name, version). WOW6432 + native + per-user can list the
    // same product multiple times.
    entries.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
            .then_with(|| a.version.cmp(&b.version))
    });
    entries.dedup_by(|a, b| {
        a.name.eq_ignore_ascii_case(&b.name) && a.version == b.version
    });

    software.av_edr_products = entries
        .iter()
        .filter(|e| e.is_av_or_edr)
        .map(|e| e.name.clone())
        .collect();
    software.installed_software = entries;

    Ok(())
}

fn is_av_or_edr(name: &str, vendor: Option<&str>) -> bool {
    let n = name.to_ascii_lowercase();
    if AV_EDR_MARKERS.iter().any(|m| n.contains(m)) {
        return true;
    }
    if let Some(v) = vendor {
        let v = v.to_ascii_lowercase();
        AV_EDR_MARKERS.iter().any(|m| v.contains(m))
    } else {
        false
    }
}
