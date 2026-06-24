//! Privilege management — check admin and enable SeBackupPrivilege so that
//! hashing pass can open files even when normal ACLs would deny read.

use anyhow::{anyhow, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenElevation,
    LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub fn ensure_admin() -> Result<()> {
    if is_elevated()? {
        Ok(())
    } else {
        Err(anyhow!(
            "fdiff needs administrator privileges to open raw volumes. \
             Re-run from an elevated terminal."
        ))
    }
}

fn is_elevated() -> Result<bool> {
    unsafe {
        let mut token: HANDLE = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("OpenProcessToken failed")?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let r = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        r.context("GetTokenInformation failed")?;
        Ok(elevation.TokenIsElevated != 0)
    }
}

/// Best-effort: enable SeBackupPrivilege on the current process token.
/// Logs and continues on failure since raw MFT reads work anyway.
pub fn try_enable_backup_privilege() {
    if let Err(e) = enable_backup_privilege_inner() {
        eprintln!("[warn] could not enable SeBackupPrivilege: {e:#}");
    }
}

fn enable_backup_privilege_inner() -> Result<()> {
    unsafe {
        let mut token: HANDLE = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .context("OpenProcessToken")?;

        let name: Vec<u16> = "SeBackupPrivilege\0".encode_utf16().collect();
        let mut luid = LUID::default();
        let r = LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(name.as_ptr()), &mut luid);
        if r.is_err() {
            let _ = CloseHandle(token);
            return Err(anyhow!("LookupPrivilegeValueW: {:?}", r));
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let r = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
        let _ = CloseHandle(token);
        r.context("AdjustTokenPrivileges")?;
        Ok(())
    }
}
