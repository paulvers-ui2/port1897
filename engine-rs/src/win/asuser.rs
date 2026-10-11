// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The user token (a port of asuser_windows.go). The engine runs as admin,
//! or as SYSTEM when AuroraVPN Service starts it, but most files it opens
//! belong to the app, in the user's own folder: its log, the API token,
//! rules, routes, WireGuard files. Malware running as that user could swap
//! one for a link to a system file and have the engine overwrite or read it
//! with admin rights. So those files are opened as the user would: with a
//! token that has the Administrators group for deny only, no privilege but
//! SeChangeNotify, at medium integrity, as an unelevated program runs.
//!
//! Started by the service, the token is the asking user's (`-user-token`,
//! an inherited handle); otherwise it is the engine's own, lowered.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::windows::fs::OpenOptionsExt;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::{
    ACL, CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE, DuplicateTokenEx, GetLengthSid, GetSecurityDescriptorDacl, GetTokenInformation,
    PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation, TOKEN_ADJUST_DEFAULT,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
    TokenDefaultDacl, TokenImpersonation, TokenIntegrityLevel, TokenOwner, TokenUser, WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinMediumLabelSid,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::SystemServices::{MAXIMUM_ALLOWED, SE_GROUP_INTEGRITY};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, SetThreadToken};

use super::{err_text, last_error, wide};
use crate::golike;

/// A token (or other kernel) handle, closed on drop.
pub(crate) struct Token(pub(crate) HANDLE);

// SAFETY: a kernel handle may be used and closed from any thread
unsafe impl Send for Token {}
// SAFETY: as above; the calls made with it do not change the handle
unsafe impl Sync for Token {}

impl Token {
    /// The handle, no longer closed on drop: someone else owns it now.
    pub(crate) fn into_raw(self) -> HANDLE {
        let h = self.0;
        std::mem::forget(self);
        h
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle is ours and closed once
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// One class of information about t, in a buffer aligned for the structs
/// Windows writes; Err is the Win32 error code.
pub(crate) fn token_info(t: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>, u32> {
    let mut n = 0u32;
    // SAFETY: a size query: no buffer, n receives the size
    unsafe { GetTokenInformation(t, class, null_mut(), 0, &mut n) };
    if n == 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32);
    }
    let mut buf = vec![0u64; (n as usize).div_ceil(8)];
    // SAFETY: buf holds at least n bytes, aligned for any token struct
    if unsafe { GetTokenInformation(t, class, buf.as_mut_ptr().cast(), n, &mut n) } == 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32);
    }
    Ok(buf)
}

/// The user SID of t, in a TOKEN_USER buffer: the SID points into it.
pub(crate) fn token_user(t: HANDLE) -> Result<Vec<u64>, String> {
    token_info(t, TokenUser).map_err(err_text)
}

/// The SID inside a buffer from token_user.
pub(crate) fn user_sid(buf: &[u64]) -> PSID {
    // SAFETY: buf came from token_user, so it starts with a TOKEN_USER
    unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid }
}

/// sid as S-1-5-...
fn sid_string(sid: PSID) -> Result<String, String> {
    let mut s = null_mut();
    // SAFETY: sid is a valid SID; s receives a LocalAlloc'd string
    if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 {
        return Err(last_error());
    }
    // SAFETY: s is NUL-terminated; it is freed once, after the copy
    let out = unsafe {
        let n = (0..).take_while(|&i| *s.add(i) != 0).count();
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
        LocalFree(s.cast());
        text
    };
    Ok(out)
}

/// A well-known SID, such as the Administrators group.
fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Result<Vec<u64>, String> {
    let mut buf = vec![0u64; (SECURITY_MAX_SID_SIZE as usize).div_ceil(8)];
    let mut n = SECURITY_MAX_SID_SIZE;
    // SAFETY: buf holds SECURITY_MAX_SID_SIZE bytes, which n says
    if unsafe { CreateWellKnownSid(kind, null_mut(), buf.as_mut_ptr().cast(), &mut n) } == 0 {
        return Err(last_error());
    }
    Ok(buf)
}

/// A security descriptor from SDDL, freed on drop.
pub(crate) struct SecDesc(pub(crate) PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is only read once made, from any thread
unsafe impl Send for SecDesc {}
// SAFETY: as above
unsafe impl Sync for SecDesc {}

impl SecDesc {
    pub(crate) fn from_sddl(sddl: &str) -> Result<SecDesc, String> {
        let s = wide(sddl);
        let mut sd = null_mut();
        // SAFETY: s is NUL-terminated; sd receives a LocalAlloc'd descriptor
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(s.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) } == 0 {
            return Err(last_error());
        }
        Ok(SecDesc(sd))
    }

    /// Its DACL, which lives as long as the descriptor.
    pub(crate) fn dacl(&self) -> Result<*mut ACL, String> {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl = null_mut();
        // SAFETY: self.0 is a valid descriptor; the out-parameters are writable
        if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) } == 0 {
            return Err(last_error());
        }
        Ok(dacl)
    }
}

impl Drop for SecDesc {
    fn drop(&mut self) {
        // SAFETY: the descriptor was LocalAlloc'd for us and is freed once
        unsafe { LocalFree(self.0) };
    }
}

/// The user's token: one copy for children, one for impersonation.
pub struct UserToken {
    primary: Token,
    imp: Token,
    /// the user's environment for children; None: the engine's
    env: Option<Vec<String>>,
}

impl UserToken {
    /// Go's newUserTokenFrom: the token of the user who asked AuroraVPN
    /// Service for the engine (the inherited handle of `-user-token`),
    /// restricted and lowered as `own`'s, with that user's environment. It
    /// takes the handle over.
    pub fn from_handle(h: u64) -> Result<UserToken, String> {
        let t = Token(h as usize as HANDLE);
        token_user(t.0).map_err(|e| format!("-user-token: {e}"))?;
        let restricted = restrict(&t)?;
        let mut u = user_token_from(&t, restricted)?;
        // a user who never signed in here has no profile yet; children then
        // get the engine's environment
        u.env = environ(&t);
        Ok(u)
    }

    /// Go's newUserToken: the engine's own token, restricted and lowered.
    pub fn own() -> Result<UserToken, String> {
        let mut h = null_mut();
        let access = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT;
        // SAFETY: the pseudo handle of this process; h receives the token
        if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut h) } == 0 {
            return Err(format!("user token: {}", last_error()));
        }
        let me = Token(h);
        let restricted = restrict(&me)?;
        user_token_from(&me, restricted)
    }

    /// The primary token, for starting a child as the user.
    pub fn primary_handle(&self) -> HANDLE {
        self.primary.0
    }

    /// The user's environment for children, if the user has a profile here.
    pub fn env(&self) -> Option<&[String]> {
        self.env.as_deref()
    }

    /// Go's userToken.do: runs f on a thread of its own that acts as the
    /// user, so the files f opens are checked against the user's rights,
    /// not the engine's; what f opens stays usable afterwards. The thread
    /// ends with f, so its impersonation can never leak into other work.
    pub fn act<R: Send>(&self, f: impl FnOnce() -> R + Send) -> Result<R, String> {
        let imp = &self.imp;
        std::thread::scope(|s| {
            let t = s.spawn(move || {
                // SAFETY: null means this thread; imp is an impersonation token
                if unsafe { SetThreadToken(null(), imp.0) } == 0 {
                    return Err(format!("act as the user: {}", last_error()));
                }
                let r = f();
                // SAFETY: no arguments; were it to fail, the thread ends here anyway
                unsafe { RevertToSelf() };
                Ok(r)
            });
            t.join().unwrap_or_else(|p| std::panic::resume_unwind(p))
        })
    }

    /// Opens path for writing as the user, created or emptied, as Go's
    /// redirectOutput (O_CREATE|O_WRONLY|O_TRUNC). A file it creates is
    /// owned by the user, even when the engine runs as SYSTEM.
    pub fn create_file(&self, path: &str) -> Result<File, String> {
        let p = golike::clean(path);
        self.act(|| {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                // as Go's syscall.Open: others may read and write, not delete
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .open(&p)
                .map_err(|e| path_err("open", &p, &e))
        })?
    }

    /// Reads one of the app's files with the user's rights (readUserFile).
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, String> {
        let p = golike::clean(path);
        self.act(|| {
            let mut f = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .open(&p)
                .map_err(|e| path_err("open", &p, &e))?;
            let mut b = Vec::new();
            f.read_to_end(&mut b).map_err(|e| path_err("read", &p, &e))?;
            Ok(b)
        })?
    }
}

/// An error as Go's *PathError prints it: "open C:\x: Access is denied."
fn path_err(op: &str, path: &str, e: &std::io::Error) -> String {
    let why = e.raw_os_error().map_or_else(|| e.to_string(), |c| err_text(c as u32));
    format!("{op} {path}: {why}")
}

/// t with the Administrators group for deny only and no privilege but
/// SeChangeNotify.
fn restrict(t: &Token) -> Result<Token, String> {
    let admins = well_known_sid(WinBuiltinAdministratorsSid).map_err(|e| format!("user token: {e}"))?;
    let deny = SID_AND_ATTRIBUTES { Sid: admins.as_ptr() as PSID, Attributes: 0 };
    let mut r = null_mut();
    // SAFETY: deny points at one valid SID that outlives the call; r
    // receives the new token
    if unsafe { CreateRestrictedToken(t.0, DISABLE_MAX_PRIVILEGE, 1, &deny, 0, null(), 0, null(), &mut r) } == 0 {
        return Err(format!("user token: restrict: {}", last_error()));
    }
    Ok(Token(r))
}

/// Finishes restricted, a restrict of me, as the user token.
fn user_token_from(me: &Token, restricted: Token) -> Result<UserToken, String> {
    lower(me, &restricted)?;
    let mut imp = null_mut();
    // SAFETY: restricted is a valid token; imp receives the copy
    if unsafe { DuplicateTokenEx(restricted.0, MAXIMUM_ALLOWED, null(), SecurityImpersonation, TokenImpersonation, &mut imp) } == 0 {
        return Err(format!("user token: impersonation copy: {}", last_error()));
    }
    Ok(UserToken { primary: restricted, imp: Token(imp), env: None })
}

fn set_info<T>(t: &Token, class: TOKEN_INFORMATION_CLASS, v: &T, size: u32) -> Result<(), String> {
    // SAFETY: v is a struct of the kind class takes, valid for size bytes
    // (with the SIDs it points at, which the caller keeps alive)
    if unsafe { SetTokenInformation(t.0, class, (v as *const T).cast(), size) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Makes the restricted token look like an unelevated program's: medium
/// integrity, owned by the user rather than the Administrators group it can
/// no longer use, and with the user in its default DACL. That DACL guards
/// what the token makes, first a child's own process: an elevated token's
/// lets in only Administrators and SYSTEM, and a child of the restricted
/// token could not open itself (0xC0000142 at start).
fn lower(me: &Token, r: &Token) -> Result<(), String> {
    let medium = well_known_sid(WinMediumLabelSid).map_err(|e| format!("user token: {e}"))?;
    let msid = medium.as_ptr() as PSID;
    let label = TOKEN_MANDATORY_LABEL { Label: SID_AND_ATTRIBUTES { Sid: msid, Attributes: SE_GROUP_INTEGRITY as u32 } };
    // SAFETY: msid is a valid SID
    let size = std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + unsafe { GetLengthSid(msid) };
    set_info(r, TokenIntegrityLevel, &label, size).map_err(|e| format!("user token: medium integrity: {e}"))?;

    let user = token_user(me.0).map_err(|e| format!("user token: {e}"))?;
    let sid = user_sid(&user);
    let owner = TOKEN_OWNER { Owner: sid };
    set_info(r, TokenOwner, &owner, std::mem::size_of::<TOKEN_OWNER>() as u32).map_err(|e| format!("user token: owner: {e}"))?;

    let dacl_err = |e: String| format!("user token: default DACL: {e}");
    let sd = SecDesc::from_sddl(&format!("D:(A;;GA;;;{})(A;;GA;;;BA)(A;;GA;;;SY)", sid_string(sid).map_err(dacl_err)?)).map_err(dacl_err)?;
    let def = TOKEN_DEFAULT_DACL { DefaultDacl: sd.dacl().map_err(dacl_err)? };
    set_info(r, TokenDefaultDacl, &def, std::mem::size_of::<TOKEN_DEFAULT_DACL>() as u32).map_err(dacl_err)
}

/// The environment of t's user (Go's Token.Environ(false)); None when it
/// cannot be made.
fn environ(t: &Token) -> Option<Vec<String>> {
    let mut block = null_mut();
    // SAFETY: t is a valid token; block receives the environment
    if unsafe { CreateEnvironmentBlock(&mut block, t.0, 0) } == 0 {
        return None;
    }
    let mut out = Vec::new();
    // SAFETY: the block is "a=b\0c=d\0\0" in UTF-16, read up to its end and
    // freed once
    unsafe {
        let mut p = block.cast::<u16>().cast_const();
        loop {
            let n = (0..).take_while(|&i| *p.add(i) != 0).count();
            if n == 0 {
                break;
            }
            out.push(String::from_utf16_lossy(std::slice::from_raw_parts(p, n)));
            p = p.add(n + 1);
        }
        DestroyEnvironmentBlock(block);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{EqualSid, TokenPrimary};

    fn temp_dir(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("fswin-rs-asuser-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    // The token the service hands the engine: a primary copy of the asking
    // program's, which the engine turns into its user token. No admin
    // needed: this test program's own token stands in for the app's.
    #[test]
    fn user_token_from_the_service() {
        let mut h = null_mut();
        // SAFETY: as in own
        assert_ne!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut h) }, 0);
        let me = Token(h);
        let mut dup = null_mut();
        // SAFETY: me is valid; dup receives the copy
        assert_ne!(unsafe { DuplicateTokenEx(me.0, MAXIMUM_ALLOWED, null(), SecurityImpersonation, TokenPrimary, &mut dup) }, 0);
        let u = UserToken::from_handle(dup as usize as u64).unwrap();
        let (a, b) = (token_user(me.0).unwrap(), token_user(u.primary_handle()).unwrap());
        // SAFETY: both are valid SIDs
        assert_ne!(unsafe { EqualSid(user_sid(&a), user_sid(&b)) }, 0, "a user token of another user");
        let env = u.env().expect("no user environment");
        assert!(env.iter().any(|e| e.to_uppercase().starts_with("USERPROFILE=")), "{} variables", env.len());

        // the user's own files stay usable, and the file is the user's
        let dir = temp_dir("own");
        let f = crate::usque::join(&dir, "mine.txt");
        {
            use std::io::Write;
            let mut w = u.create_file(&f).unwrap();
            w.write_all(b"ok").unwrap();
        }
        assert_eq!(u.read_file(&f).unwrap(), b"ok");
        // O_TRUNC: a second create empties it
        drop(u.create_file(&f).unwrap());
        assert_eq!(u.read_file(&f).unwrap(), b"");
        let missing = crate::usque::join(&dir, "none.txt");
        assert_eq!(u.read_file(&missing).unwrap_err(), format!("open {missing}: The system cannot find the file specified."));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bad_handle() {
        assert!(UserToken::from_handle(0).err().unwrap().starts_with("-user-token: "));
    }

    // Acting as the user, the engine can neither write nor read what only
    // admins may, such as a system file a planted link points at, and is
    // fully itself again afterwards.
    #[test]
    #[ignore = "admin: needs the engine's admin rights to make an admin-only folder"]
    fn user_token_keeps_admin_files_out() {
        use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
        use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION};
        let u = UserToken::own().unwrap();
        let locked = temp_dir("locked");
        let sd = SecDesc::from_sddl("D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)").unwrap();
        let w = wide(&locked);
        // SAFETY: w is NUL-terminated; the DACL lives in sd through the call
        let r = unsafe {
            SetNamedSecurityInfoW(w.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, null_mut(), null_mut(), sd.dacl().unwrap(), null())
        };
        assert_eq!(r, 0, "{}", err_text(r));
        let secret = crate::usque::join(&locked, "secret.txt");
        std::fs::write(&secret, "admins only").unwrap();

        let planted = crate::usque::join(&locked, "planted.txt");
        assert_eq!(u.create_file(&planted).unwrap_err(), format!("open {planted}: Access is denied."));
        assert_eq!(u.read_file(&secret).unwrap_err(), format!("open {secret}: Access is denied."));
        std::fs::write(crate::usque::join(&locked, "after.txt"), "x").expect("the engine lost its rights after acting as the user");
        let _ = std::fs::remove_dir_all(&locked);
    }
}
