//! Time-based one-time passwords (RFC 6238) and their `otpauth://` enrolment
//! URI, matching the OPNsense `otp_seed` format: a base32 secret per user and
//! six digits in a thirty-second period.
//!
//! Secrets are generated here because the QR code only ever contains a URI:
//! the authenticator and the firewall derive the same codes from it.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;

/// Digits in a generated code (OPNsense and almost every authenticator app).
pub const DIGITS: u32 = 6;
/// Length of one code period in seconds.
pub const PERIOD: u64 = 30;
/// Accepted periods on either side of the current one (clock drift).
pub const WINDOW: i64 = 1;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A new random secret: 160 bits, as RFC 4226 recommends.
pub fn generate_seed() -> String {
    let mut bytes = [0u8; 20];
    if getrandom::fill(&mut bytes).is_err() {
        // getrandom only fails when the OS has no entropy source; mixing the
        // clock keeps the function total without a Result in every caller.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (now.rotate_left(i as u32 * 7) >> (i % 8 * 8)) as u8;
        }
    }
    base32_encode(&bytes)
}

/// True when `code` is a valid code for `seed` at `now`, allowing one period
/// of clock drift either way.
pub fn verify(seed: &str, code: &str, now: SystemTime) -> bool {
    let Some(key) = base32_decode(seed) else {
        return false;
    };
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let seconds = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let counter = (seconds / PERIOD) as i64;
    (-WINDOW..=WINDOW).any(|offset| {
        let expected = hotp(&key, (counter + offset) as u64);
        constant_time_eq(expected.as_bytes(), code.as_bytes())
    })
}

/// The code for `seed` at `now`, or `None` when the secret is not base32.
/// Authenticator apps compute the same value; tests and provisioning previews
/// use this rather than a second implementation.
pub fn code(seed: &str, now: SystemTime) -> Option<String> {
    let key = base32_decode(seed)?;
    let seconds = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    Some(hotp(&key, seconds / PERIOD))
}

/// The `otpauth://` URI an authenticator app imports, including the secret.
pub fn provisioning_uri(issuer: &str, account: &str, seed: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&digits={DIGITS}&period={PERIOD}",
        percent(issuer),
        percent(account),
        seed,
        percent(issuer),
    )
}

fn hotp(key: &[u8], counter: u64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    let modulus = 10u32.pow(DIGITS);
    format!("{:0width$}", binary % modulus, width = DIGITS as usize)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for b in bytes {
        buffer = (buffer << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Decodes base32, ignoring spaces, dashes and `=` padding.
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for c in text.chars() {
        if matches!(c, ' ' | '-' | '=' | '\n' | '\r' | '\t') {
            continue;
        }
        let value = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u8 - b'A',
            c @ '2'..='7' => c as u8 - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Percent-encodes a URI label (`sensr`, `alice@example.com`).
fn percent(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(seconds)
    }

    #[test]
    fn rfc6238_sha1_vectors_truncate_to_six_digits() {
        // The RFC vectors use the ASCII secret and eight digits; the six-digit
        // code is the same dynamic truncation modulo one million.
        let seed = base32_encode(b"12345678901234567890");
        for (seconds, code) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
        ] {
            assert!(verify(&seed, code, at(seconds)), "{seconds}: {code}");
        }
        assert!(!verify(&seed, "287083", at(59)));
        assert!(!verify(&seed, "28708", at(59)));
    }

    #[test]
    fn one_period_of_drift_is_accepted() {
        let seed = base32_encode(b"12345678901234567890");
        let code = hotp(b"12345678901234567890", 59 / PERIOD);
        assert!(verify(&seed, &code, at(59 + PERIOD)));
        assert!(!verify(&seed, &code, at(59 + 2 * PERIOD)));
    }

    #[test]
    fn generated_seeds_round_trip_and_are_unique() {
        let a = generate_seed();
        let b = generate_seed();
        assert_ne!(a, b);
        assert_eq!(base32_decode(&a).map(|v| v.len()), Some(20));
        let code = hotp(&base32_decode(&a).unwrap(), 0);
        assert!(verify(&a, &code, UNIX_EPOCH));
    }

    #[test]
    fn the_uri_carries_the_secret_and_issuer() {
        let uri = provisioning_uri("sensr", "admin@example.com", "ABCD2345");
        assert_eq!(
            uri,
            "otpauth://totp/sensr:admin%40example.com?secret=ABCD2345&issuer=sensr&digits=6&period=30"
        );
    }
}
