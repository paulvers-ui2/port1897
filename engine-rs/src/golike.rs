// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Go standard library behaviour the engine's contract depends on: string
//! case and space handling, Windows path functions (`path/filepath`) and
//! `strconv` number parsing. The Go engine's rules, flags and service checks
//! are built on these; matching them keeps the Rust engine's answers equal
//! to the Go engine's for the same input.

/// Go's `unicode.ToLower` for one rune: Rust's lowercase mapping, first rune
/// (only U+0130 maps to two runes in Rust; Go maps it to 'i').
fn lower_rune(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

/// `strings.ToLower`.
pub fn to_lower(s: &str) -> String {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    s.chars().map(lower_rune).collect()
}

/// `strings.TrimSpace`: Go's and Rust's white space sets are the same
/// (Unicode White_Space).
pub fn trim_space(s: &str) -> &str {
    s.trim()
}

/// A rune's simple case fold, for `strings.EqualFold`: runes that fold
/// together (k, K and the Kelvin sign; s, S and long s) map to one.
fn fold_rune(c: char) -> char {
    let mut up = c.to_uppercase();
    match (up.next(), up.next()) {
        (Some(u), None) => lower_rune(u),
        _ => lower_rune(c),
    }
}

/// `strings.EqualFold`.
pub fn equal_fold(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        return a.eq_ignore_ascii_case(b);
    }
    a.chars().map(fold_rune).eq(b.chars().map(fold_rune))
}

/// `strings.TrimSuffix`.
pub fn trim_suffix<'a>(s: &'a str, suffix: &str) -> &'a str {
    s.strip_suffix(suffix).unwrap_or(s)
}

/// `strings.TrimPrefix`.
pub fn trim_prefix<'a>(s: &'a str, prefix: &str) -> &'a str {
    s.strip_prefix(prefix).unwrap_or(s)
}

/// `strconv.Quote`, as `%q` prints: control runes escaped, the rest kept.
/// (Go also escapes printable-looking format runes such as U+200B; this
/// only shows in error messages.)
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// strconv

/// Why a number did not parse, as Go's flag package words it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumError {
    Syntax,
    Range,
}

impl NumError {
    pub fn text(self) -> &'static str {
        match self {
            NumError::Syntax => "parse error",
            NumError::Range => "value out of range",
        }
    }
}

/// `strconv.ParseUint(s, 0, 64)`: base from the prefix (0x, 0o, 0b, or a
/// leading 0 for octal), underscores allowed between digits only then.
pub fn parse_uint_base0(s: &str) -> Result<u64, NumError> {
    parse_uint(s, 0, 64)
}

/// `strconv.ParseInt(s, 0, 64)`.
pub fn parse_int_base0(s: &str) -> Result<i64, NumError> {
    parse_int(s, 0, 64)
}

/// `strconv.ParseInt(s, base, bits)`.
pub fn parse_int(s: &str, base: u32, bits: u32) -> Result<i64, NumError> {
    if s.is_empty() {
        return Err(NumError::Syntax);
    }
    let (neg, digits) = match s.as_bytes()[0] {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };
    let un = parse_uint(digits, base, bits)?;
    let cutoff = 1u64 << (bits - 1);
    if !neg && un >= cutoff {
        return Err(NumError::Range);
    }
    if neg && un > cutoff {
        return Err(NumError::Range);
    }
    if neg {
        // un <= cutoff, so this fits
        Ok((un as i128).wrapping_neg() as i64)
    } else {
        Ok(un as i64)
    }
}

/// `strconv.ParseUint(s, base, bits)`, base 0 or 10 (all the engine uses).
pub fn parse_uint(s: &str, base: u32, bits: u32) -> Result<u64, NumError> {
    if s.is_empty() {
        return Err(NumError::Syntax);
    }
    let b = s.as_bytes();
    let mut base = base;
    let mut i = 0;
    let base0 = base == 0;
    if base == 0 {
        base = 10;
        if b[0] == b'0' {
            if b.len() >= 3 {
                match b[1].to_ascii_lowercase() {
                    b'b' => {
                        base = 2;
                        i = 2;
                    }
                    b'o' => {
                        base = 8;
                        i = 2;
                    }
                    b'x' => {
                        base = 16;
                        i = 2;
                    }
                    _ => {
                        base = 8;
                        i = 1;
                    }
                }
            } else {
                base = 8;
                i = 1;
            }
        }
    }
    let max: u64 = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
    let mut n: u64 = 0;
    let mut underscores = false;
    for &c in &b[i..] {
        let d = match c {
            b'_' if base0 => {
                underscores = true;
                continue;
            }
            b'0'..=b'9' => (c - b'0') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 10,
            b'A'..=b'Z' => (c - b'A') as u32 + 10,
            _ => return Err(NumError::Syntax),
        };
        if d >= base {
            return Err(NumError::Syntax);
        }
        // Go stops at the first overflow, before later syntax errors
        match n.checked_mul(base as u64).and_then(|m| m.checked_add(d as u64)) {
            Some(v) if v <= max => n = v,
            _ => return Err(NumError::Range),
        }
    }
    if underscores && !underscore_ok(s) {
        return Err(NumError::Syntax);
    }
    Ok(n)
}

/// Go's `underscoreOK`: underscores only between digits, or right after a
/// base prefix.
fn underscore_ok(s: &str) -> bool {
    // saw: '^' start, '0' digit or prefix, '_' underscore, '!' other
    let b = s.as_bytes();
    let mut saw = b'^';
    let mut i = 0;
    if !b.is_empty() && (b[0] == b'-' || b[0] == b'+') {
        i = 1;
    }
    let mut hex = false;
    if b.len() - i >= 2 && b[i] == b'0' {
        let c = b[i + 1].to_ascii_lowercase();
        if c == b'b' || c == b'o' || c == b'x' {
            hex = c == b'x';
            i += 2;
            saw = b'0';
        }
    }
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_digit() || (hex && c.is_ascii_hexdigit()) {
            saw = b'0';
        } else if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
        } else {
            if saw == b'_' {
                return false;
            }
            saw = b'!';
        }
        i += 1;
    }
    saw != b'_'
}

/// `strconv.ParseBool`.
pub fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

// path/filepath, as on Windows: both slashes separate, volumes are drive
// letters and UNC shares.

fn is_sep(c: u8) -> bool {
    c == b'\\' || c == b'/'
}

/// `pathHasPrefixFold`: s starts with prefix, ignoring case and treating
/// the separators alike; a longer s must go on with a separator.
fn has_prefix_fold(s: &[u8], prefix: &[u8]) -> bool {
    if s.len() < prefix.len() {
        return false;
    }
    for (i, &p) in prefix.iter().enumerate() {
        if is_sep(p) {
            if !is_sep(s[i]) {
                return false;
            }
        } else if !p.eq_ignore_ascii_case(&s[i]) {
            return false;
        }
    }
    !(s.len() > prefix.len() && !is_sep(s[prefix.len()]))
}

fn unc_len(p: &[u8], prefix_len: usize) -> usize {
    let mut count = 0;
    for (i, &c) in p.iter().enumerate().skip(prefix_len) {
        if is_sep(c) {
            count += 1;
            if count == 2 {
                return i;
            }
        }
    }
    p.len()
}

/// `volumeNameLen`: the length of the leading volume name of path.
pub fn volume_name_len(path: &str) -> usize {
    let p = path.as_bytes();
    if p.len() >= 2 && p[1] == b':' {
        return 2;
    }
    if p.is_empty() || !is_sep(p[0]) {
        return 0;
    }
    if has_prefix_fold(p, br"\\.\UNC") {
        return unc_len(p, br"\\.\UNC\".len());
    }
    if has_prefix_fold(p, br"\\.") || has_prefix_fold(p, br"\\?") || has_prefix_fold(p, br"\??") {
        if p.len() == 3 {
            return 3;
        }
        let rest = &p[4..];
        return match rest.iter().position(|&c| is_sep(c)) {
            Some(j) => 4 + j,
            None => p.len(),
        };
    }
    if p.len() >= 2 && is_sep(p[1]) {
        return unc_len(p, 2);
    }
    0
}

/// `filepath.FromSlash`.
fn from_slash(s: &str) -> String {
    s.replace('/', "\\")
}

/// `filepath.Base`.
pub fn base(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let mut p = path;
    while let Some(&last) = p.as_bytes().last() {
        if !is_sep(last) {
            break;
        }
        p = &p[..p.len() - 1];
    }
    p = &p[volume_name_len(p)..];
    if let Some(i) = p.bytes().rposition(is_sep) {
        p = &p[i + 1..];
    }
    if p.is_empty() {
        return "\\".to_string();
    }
    p.to_string()
}

/// `filepath.Dir`.
pub fn dir(path: &str) -> String {
    let vlen = volume_name_len(path);
    let vol = from_slash(&path[..vlen]);
    let b = path.as_bytes();
    let mut i = b.len();
    while i > vlen && !is_sep(b[i - 1]) {
        i -= 1;
    }
    let d = clean(&path[vlen..i]);
    if d == "." && vol.len() > 2 {
        return vol; // must be UNC
    }
    vol + &d
}

/// `filepath.IsAbs`.
pub fn is_abs(path: &str) -> bool {
    let l = volume_name_len(path);
    if l == 0 {
        return false;
    }
    let b = path.as_bytes();
    if is_sep(b[0]) && is_sep(b[1]) {
        return true;
    }
    match b.get(l) {
        Some(&c) => is_sep(c),
        None => false,
    }
}

/// `filepath.Clean`: the shortest equivalent path by lexical processing.
pub fn clean(path: &str) -> String {
    let original = path;
    let vol_len = volume_name_len(path);
    let p = &path.as_bytes()[vol_len..];
    let ob = original.as_bytes();
    if p.is_empty() {
        if vol_len > 1 && is_sep(ob[0]) && is_sep(ob[1]) {
            return from_slash(original); // UNC
        }
        return original.to_string() + ".";
    }
    let rooted = is_sep(p[0]);
    let n = p.len();
    let mut out = LazyBuf { path: p, buf: None, w: 0 };
    let (mut r, mut dotdot) = (0, 0);
    if rooted {
        out.append(b'\\');
        r = 1;
        dotdot = 1;
    }
    while r < n {
        if is_sep(p[r]) || (p[r] == b'.' && (r + 1 == n || is_sep(p[r + 1]))) {
            // an empty element, or "."
            r += 1;
        } else if p[r] == b'.' && r + 1 < n && p[r + 1] == b'.' && (r + 2 == n || is_sep(p[r + 2])) {
            r += 2;
            if out.w > dotdot {
                out.w -= 1;
                while out.w > dotdot && !is_sep(out.index(out.w)) {
                    out.w -= 1;
                }
            } else if !rooted {
                if out.w > 0 {
                    out.append(b'\\');
                }
                out.append(b'.');
                out.append(b'.');
                dotdot = out.w;
            }
        } else {
            if (rooted && out.w != 1) || (!rooted && out.w != 0) {
                out.append(b'\\');
            }
            while r < n && !is_sep(p[r]) {
                out.append(p[r]);
                r += 1;
            }
        }
    }
    if out.w == 0 {
        out.append(b'.');
    }
    // postClean: keep a relative path with a colon in its first element, or
    // one starting \??\, from turning into a volume
    let mut prefix: &[u8] = b"";
    if vol_len == 0 {
        if let Some(buf) = &out.buf {
            let body = &buf[..out.w];
            let first_colon = body.iter().take_while(|&&c| !is_sep(c)).any(|&c| c == b':');
            if first_colon {
                prefix = b".\\";
            } else if body.len() >= 3 && is_sep(body[0]) && body[1] == b'?' && body[2] == b'?' {
                prefix = b"\\.";
            }
        }
    }
    let body: Vec<u8> = match &out.buf {
        Some(buf) => buf[..out.w].to_vec(),
        None => p[..out.w].to_vec(),
    };
    let mut s = Vec::with_capacity(vol_len + prefix.len() + body.len());
    s.extend_from_slice(&ob[..vol_len]);
    s.extend_from_slice(prefix);
    s.extend_from_slice(&body);
    // only ASCII bytes were added or removed between whole runes
    from_slash(&String::from_utf8_lossy(&s))
}

/// Go's lazybuf: allocates only once the output differs from the input.
struct LazyBuf<'a> {
    path: &'a [u8],
    buf: Option<Vec<u8>>,
    w: usize,
}

impl LazyBuf<'_> {
    fn index(&self, i: usize) -> u8 {
        match &self.buf {
            Some(b) => b[i],
            None => self.path[i],
        }
    }

    fn append(&mut self, c: u8) {
        if self.buf.is_none() {
            if self.w < self.path.len() && self.path[self.w] == c {
                self.w += 1;
                return;
            }
            let mut b = Vec::with_capacity(self.path.len() + 2);
            b.extend_from_slice(&self.path[..self.w]);
            self.buf = Some(b);
        }
        if let Some(b) = &mut self.buf {
            b.truncate(self.w);
            b.push(c);
        }
        self.w += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_and_fold() {
        assert_eq!(to_lower("C:\\Program Files\\App.EXE"), "c:\\program files\\app.exe");
        assert_eq!(to_lower("ÄÖÜ"), "äöü");
        assert_eq!(to_lower("\u{130}"), "i"); // Go maps U+0130 to i
        assert!(equal_fold("Chrome.EXE", "chrome.exe"));
        assert!(equal_fold("\u{212a}", "k")); // Kelvin sign
        assert!(equal_fold("\u{17f}", "S")); // long s
        assert!(!equal_fold("a", "b"));
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("1.2.3.x"), "\"1.2.3.x\"");
        assert_eq!(quote("a\"b\\c\n\u{1}"), "\"a\\\"b\\\\c\\n\\x01\"");
        assert_eq!(quote("é"), "\"é\"");
    }

    #[test]
    fn ints_like_strconv() {
        assert_eq!(parse_int_base0("0"), Ok(0));
        assert_eq!(parse_int_base0("1500"), Ok(1500));
        assert_eq!(parse_int_base0("-3"), Ok(-3));
        assert_eq!(parse_int_base0("+3"), Ok(3));
        assert_eq!(parse_int_base0("0x10"), Ok(16));
        assert_eq!(parse_int_base0("010"), Ok(8));
        assert_eq!(parse_int_base0("0o17"), Ok(15));
        assert_eq!(parse_int_base0("0b101"), Ok(5));
        assert_eq!(parse_int_base0("1_000"), Ok(1000));
        assert_eq!(parse_int_base0("0x_1f"), Ok(31));
        assert_eq!(parse_int_base0("1__0"), Err(NumError::Syntax));
        assert_eq!(parse_int_base0("_1"), Err(NumError::Syntax));
        assert_eq!(parse_int_base0("1_"), Err(NumError::Syntax));
        assert_eq!(parse_int_base0("08"), Err(NumError::Syntax));
        assert_eq!(parse_int_base0(""), Err(NumError::Syntax));
        assert_eq!(parse_int_base0("1.5"), Err(NumError::Syntax));
        assert_eq!(parse_int_base0("9223372036854775807"), Ok(i64::MAX));
        assert_eq!(parse_int_base0("-9223372036854775808"), Ok(i64::MIN));
        assert_eq!(parse_int_base0("9223372036854775808"), Err(NumError::Range));
        assert_eq!(parse_uint_base0("18446744073709551615"), Ok(u64::MAX));
        assert_eq!(parse_uint_base0("18446744073709551616"), Err(NumError::Range));
        assert_eq!(parse_uint_base0("-1"), Err(NumError::Syntax));
        assert_eq!(parse_uint("0443", 10, 16), Ok(443));
        assert_eq!(parse_uint("65536", 10, 16), Err(NumError::Range));
        assert_eq!(parse_uint("1_0", 10, 16), Err(NumError::Syntax));
    }

    #[test]
    fn bools_like_strconv() {
        for t in ["1", "t", "T", "TRUE", "true", "True"] {
            assert_eq!(parse_bool(t), Some(true), "{t}");
        }
        for f in ["0", "f", "F", "FALSE", "false", "False"] {
            assert_eq!(parse_bool(f), Some(false), "{f}");
        }
        assert_eq!(parse_bool("yes"), None);
        assert_eq!(parse_bool("tRUE"), None);
    }

    // cases from Go's path/filepath tests (Windows)
    #[test]
    fn filepath_base() {
        for (p, want) in [
            ("", "."),
            (".", "."),
            ("/.", "."),
            ("/", "\\"),
            ("////", "\\"),
            ("x/", "x"),
            ("abc", "abc"),
            ("abc/def", "def"),
            ("a/b/.x", ".x"),
            ("a/b/c.", "c."),
            ("a/b/c.x", "c.x"),
            ("c:\\", "\\"),
            ("c:.", "."),
            ("c:\\a\\b", "b"),
            ("c:a\\b", "b"),
            ("c:a\\b\\c", "c"),
            ("\\\\host\\share\\", "\\"),
            ("\\\\host\\share\\a", "a"),
            ("\\\\host\\share\\a\\b", "b"),
            (r"C:\Program Files\Test\app.exe", "app.exe"),
        ] {
            assert_eq!(base(p), want, "base({p:?})");
        }
    }

    #[test]
    fn filepath_dir() {
        for (p, want) in [
            ("", "."),
            (".", "."),
            ("/.", "\\"),
            ("/", "\\"),
            ("/foo", "\\"),
            ("x/", "x"),
            ("abc", "."),
            ("abc/def", "abc"),
            ("a/b/.x", "a\\b"),
            ("c:\\", "c:\\"),
            ("c:.", "c:."),
            ("c:\\a\\b", "c:\\a"),
            ("c:a\\b", "c:a"),
            ("c:a\\b\\c", "c:a\\b"),
            ("\\\\host\\share", "\\\\host\\share"),
            ("\\\\host\\share\\", "\\\\host\\share\\"),
            ("\\\\host\\share\\a", "\\\\host\\share\\"),
            ("\\\\host\\share\\a\\b", "\\\\host\\share\\a"),
            ("\\\\\\\\", "\\\\\\\\"),
        ] {
            assert_eq!(dir(p), want, "dir({p:?})");
        }
    }

    #[test]
    fn filepath_clean() {
        for (p, want) in [
            ("abc", "abc"),
            ("abc/def", "abc\\def"),
            ("", "."),
            ("..", ".."),
            ("../..", "..\\.."),
            ("/", "\\"),
            ("abc/", "abc"),
            ("abc//def//ghi", "abc\\def\\ghi"),
            ("abc/./def", "abc\\def"),
            ("abc/def/..", "abc"),
            ("abc/def/../..", "."),
            ("/abc/def/../..", "\\"),
            ("abc/def/../../..", ".."),
            ("/abc/def/../../..", "\\"),
            ("abc/./../def", "def"),
            ("c:", "c:."),
            ("c:\\", "c:\\"),
            ("c:\\abc", "c:\\abc"),
            ("c:abc\\..\\..\\.\\.\\..\\def", "c:..\\..\\def"),
            ("c:\\abc\\def\\..\\..", "c:\\"),
            ("c:..\\abc", "c:..\\abc"),
            ("\\", "\\"),
            ("/", "\\"),
            ("\\\\i\\..\\c$", "\\\\i\\..\\c$"),
            ("\\\\i\\..\\i\\c$", "\\\\i\\..\\i\\c$"),
            ("\\\\i\\..\\I\\c$", "\\\\i\\..\\I\\c$"),
            ("\\\\host\\share\\foo\\..\\bar", "\\\\host\\share\\bar"),
            ("//host/share/foo/../baz", "\\\\host\\share\\baz"),
            ("\\\\.\\C:\\a\\..\\..\\b", "\\\\.\\C:\\b"),
            ("a/../c:", ".\\c:"),
            ("a\\..\\c:", ".\\c:"),
            ("a/../c:/a", ".\\c:\\a"),
            ("\\a\\..\\??\\c:\\x", "\\.\\??\\c:\\x"),
            (r"C:\Program Files\AuroraVPN\.\AuroraVPN.exe", r"C:\Program Files\AuroraVPN\AuroraVPN.exe"),
        ] {
            assert_eq!(clean(p), want, "clean({p:?})");
        }
    }

    #[test]
    fn filepath_is_abs() {
        for (p, want) in [
            ("", false),
            ("/", false),
            ("/usr/bin/gcc", false),
            ("..", false),
            ("C:\\", true),
            ("c\\", false),
            ("c::", false),
            ("c:", false),
            ("/", false),
            ("\\", false),
            ("\\Windows", false),
            ("c:a\\b", false),
            ("c:\\a\\b", true),
            ("c:/a/b", true),
            ("\\\\host\\share", true),
            ("\\\\host\\share\\", true),
            ("\\\\host\\share\\foo", true),
            ("//host/share/foo/bar", true),
            ("\\\\?\\a\\b\\c", true),
            ("\\??\\a\\b\\c", true),
        ] {
            assert_eq!(is_abs(p), want, "is_abs({p:?})");
        }
    }
}
