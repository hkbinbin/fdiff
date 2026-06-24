//! Enumerate fixed NTFS volumes on the machine.
//!
//! Uses FindFirstVolumeW/FindNextVolumeW (not GetLogicalDrives) so we don't miss
//! mount-pointed volumes without drive letters.

use anyhow::{Context, Result};
use windows::core::PWSTR;
use windows::Win32::Storage::FileSystem::{
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetVolumeInformationW,
    GetVolumePathNamesForVolumeNameW,
};

#[derive(Debug, Clone)]
pub struct NtfsVolume {
    /// `\\?\Volume{GUID}\` — actual device path.
    pub guid_path: String,
    /// First mount point if any, e.g. `C:\`.
    pub mount: Option<String>,
    /// File system name, always "NTFS" for items returned here.
    pub fs_name: String,
}

impl NtfsVolume {
    /// Short label used in CLI / DB, e.g. "C:" or "{abcd-...}" if no letter.
    pub fn label(&self) -> String {
        match &self.mount {
            Some(m) => m.trim_end_matches('\\').to_string(),
            None => self.guid_path.clone(),
        }
    }

    /// Path suitable for `Volume::new` — `\\.\C:` form when a drive letter is
    /// present, falling back to the GUID path otherwise.
    pub fn open_path(&self) -> String {
        if let Some(m) = &self.mount {
            // E.g. "C:\" → "\\.\C:"
            let letter = m.trim_end_matches('\\').trim_end_matches(':');
            if letter.len() == 1 {
                return format!("\\\\.\\{}:", letter);
            }
        }
        // Strip trailing backslash for ntfs-reader.
        self.guid_path.trim_end_matches('\\').to_string()
    }
}

pub fn enumerate_ntfs_volumes() -> Result<Vec<NtfsVolume>> {
    unsafe {
        let mut buf = [0u16; 260];
        let mut out = Vec::new();

        let handle = FindFirstVolumeW(&mut buf).context("FindFirstVolumeW")?;
        loop {
            let guid_path = wide_to_string(&buf);
            if let Some(v) = inspect_volume(&guid_path)? {
                out.push(v);
            }

            let mut next = [0u16; 260];
            let r = FindNextVolumeW(handle, &mut next);
            if r.is_err() {
                break;
            }
            buf = next;
        }
        let _ = FindVolumeClose(handle);
        Ok(out)
    }
}

unsafe fn inspect_volume(guid_path: &str) -> Result<Option<NtfsVolume>> {
    let mut wide: Vec<u16> = guid_path.encode_utf16().collect();
    wide.push(0);
    let mut fs_name_buf = [0u16; 32];
    let mut volname_buf = [0u16; 64];
    let mut serial = 0u32;
    let mut max_comp = 0u32;
    let mut fs_flags = 0u32;
    let r = GetVolumeInformationW(
        PWSTR(wide.as_mut_ptr()),
        Some(&mut volname_buf),
        Some(&mut serial),
        Some(&mut max_comp),
        Some(&mut fs_flags),
        Some(&mut fs_name_buf),
    );
    if r.is_err() {
        // Not ready / no media / inaccessible.
        return Ok(None);
    }
    let fs_name = wide_to_string(&fs_name_buf);
    if !fs_name.eq_ignore_ascii_case("NTFS") {
        return Ok(None);
    }

    let mount = mount_point_for(guid_path);

    Ok(Some(NtfsVolume {
        guid_path: guid_path.to_string(),
        mount,
        fs_name,
    }))
}

fn mount_point_for(guid_path: &str) -> Option<String> {
    unsafe {
        let mut wide: Vec<u16> = guid_path.encode_utf16().collect();
        wide.push(0);
        let mut buf = vec![0u16; 1024];
        let mut len = 0u32;
        let r = GetVolumePathNamesForVolumeNameW(
            windows::core::PCWSTR(wide.as_ptr()),
            Some(&mut buf),
            &mut len,
        );
        if r.is_err() {
            return None;
        }
        // The buffer is a sequence of null-terminated wide strings ending with a
        // double-null. We take the first one.
        let mut end = 0;
        while end < buf.len() && buf[end] != 0 {
            end += 1;
        }
        if end == 0 {
            None
        } else {
            Some(String::from_utf16_lossy(&buf[..end]))
        }
    }
}

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
