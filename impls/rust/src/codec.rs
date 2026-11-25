//! Base58 (Bitcoin alphabet), Base64 (RFC 4648 standard, padded) and number formatting.

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// 58^5 fits in a `u32`, so each limb holds five base-58 digits.
const LIMB: u64 = 58 * 58 * 58 * 58 * 58;

/// Base58-encode `input` (WIRE_FORMATS.md §15.1).
///
/// Big-number conversion with base-58^5 limbs, folding in up to three input bytes per pass:
/// the same result as the textbook digit loop, about 15x fewer inner iterations.
pub fn b58_encode(input: &[u8]) -> String {
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let rest = &input[zeros..];
    let mut limbs: Vec<u32> = Vec::with_capacity(rest.len() * 138 / 500 + 2);
    for chunk in rest.chunks(3) {
        let mut carry: u64 = 0;
        let mut shift: u64 = 1;
        for &b in chunk {
            carry = (carry << 8) | b as u64;
            shift <<= 8;
        }
        for limb in limbs.iter_mut() {
            carry += *limb as u64 * shift;
            *limb = (carry % LIMB) as u32;
            carry /= LIMB;
        }
        while carry > 0 {
            limbs.push((carry % LIMB) as u32);
            carry /= LIMB;
        }
    }
    let mut digits: Vec<u8> = Vec::with_capacity(limbs.len() * 5);
    for &limb in &limbs {
        let mut v = limb;
        for _ in 0..5 {
            digits.push((v % 58) as u8);
            v /= 58;
        }
    }
    while digits.last() == Some(&0) {
        digits.pop();
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(B58[d as usize] as char);
    }
    out
}

/// Base58-decode (not needed by `getBlock`; used by tests and for completeness).
pub fn b58_decode(s: &str) -> Option<Vec<u8>> {
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut out: Vec<u8> = Vec::new();
    for c in s.bytes().skip(zeros) {
        let mut carry = B58.iter().position(|&a| a == c)? as u32;
        for byte in out.iter_mut() {
            carry += *byte as u32 * 58;
            *byte = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    let mut result = vec![0u8; zeros];
    result.extend(out.iter().rev());
    Some(result)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard padded Base64 (WIRE_FORMATS.md §15.2).
pub fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// `real_number_string_trimmed(amount, decimals)` (WIRE_FORMATS.md §15.4).
pub fn real_number_string_trimmed(amount: u64, decimals: u8) -> String {
    let digits = amount.to_string();
    if decimals == 0 {
        return digits;
    }
    let dec = decimals as usize;
    let mut s = if digits.len() <= dec {
        let mut s = String::with_capacity(dec + 2);
        s.push_str("0.");
        for _ in 0..dec - digits.len() {
            s.push('0');
        }
        s.push_str(&digits);
        s
    } else {
        let split = digits.len() - dec;
        format!("{}.{}", &digits[..split], &digits[split..])
    };
    while s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }
    s
}

/// Rust `u64::from_str` semantics: ASCII digits with an optional leading `+`, must fit.
pub fn parse_unsigned(s: &str, max: u64) -> Option<u64> {
    let digits = s.strip_prefix('+').unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut v: u64 = 0;
    for b in digits.bytes() {
        v = v.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    (v <= max).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_vectors() {
        assert_eq!(b58_encode(&[0u8; 32]), "1".repeat(32));
        assert_eq!(b58_encode(&[]), "");
        assert_eq!(b58_encode(&[0x00, 0x01, 0x2a, 0xff]), "1Pki");
        assert_eq!(b58_encode(&[0x00, 0x07, 0xc8]), "1bM");
        assert_eq!(b58_encode(b"hello world"), "StV1DL6CwTryKyV");
        // Cross-check against the textbook algorithm over many lengths and patterns.
        let mut seed = 0x1234_5678_9abc_def0u64;
        for len in 0..200 {
            let bytes: Vec<u8> = (0..len)
                .map(|i| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    if i < len / 7 { 0 } else { seed as u8 }
                })
                .collect();
            let enc = b58_encode(&bytes);
            assert_eq!(b58_decode(&enc).unwrap(), bytes, "len {len}");
            assert_eq!(enc, naive_b58(&bytes));
        }
    }

    fn naive_b58(bytes: &[u8]) -> String {
        let zeros = bytes.iter().take_while(|&&b| b == 0).count();
        let mut digits: Vec<u32> = vec![];
        for &b in &bytes[zeros..] {
            let mut carry = b as u32;
            for d in digits.iter_mut() {
                carry += *d << 8;
                *d = carry % 58;
                carry /= 58;
            }
            while carry > 0 {
                digits.push(carry % 58);
                carry /= 58;
            }
        }
        "1".repeat(zeros) + &digits.iter().rev().map(|&d| B58[d as usize] as char).collect::<String>()
    }

    #[test]
    fn base64_vectors() {
        assert_eq!(b64_encode(&[0x00, 0xff, 0x01, 0x2a]), "AP8BKg==");
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn ui_amount_strings() {
        assert_eq!(real_number_string_trimmed(1_000_000, 6), "1");
        assert_eq!(real_number_string_trimmed(1_250_000, 6), "1.25");
        assert_eq!(real_number_string_trimmed(5, 6), "0.000005");
        assert_eq!(real_number_string_trimmed(0, 6), "0");
        assert_eq!(real_number_string_trimmed(42, 0), "42");
        assert_eq!(real_number_string_trimmed(1, 20), "0.00000000000000000001");
        assert_eq!(real_number_string_trimmed(0, 255), "0");
        assert_eq!(real_number_string_trimmed(u64::MAX, 20), "0.18446744073709551615");
    }

    #[test]
    fn unsigned_parsing() {
        assert_eq!(parse_unsigned("7", 255), Some(7));
        assert_eq!(parse_unsigned("+7", 255), Some(7));
        assert_eq!(parse_unsigned("256", 255), None);
        assert_eq!(parse_unsigned("-1", 255), None);
        assert_eq!(parse_unsigned("", 255), None);
        assert_eq!(parse_unsigned("+", 255), None);
        assert_eq!(parse_unsigned(" 1", 255), None);
        assert_eq!(parse_unsigned("18446744073709551615", u64::MAX), Some(u64::MAX));
        assert_eq!(parse_unsigned("18446744073709551616", u64::MAX), None);
    }
}
