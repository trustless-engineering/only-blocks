//! DataFrame checksums: CRC-64/GO-ISO (slicing-by-8) and FNV-1a 64 (WIRE_FORMATS.md §6).

use std::sync::OnceLock;

const POLY_REFLECTED: u64 = 0xD800_0000_0000_0000;

fn tables() -> &'static [[u64; 256]; 8] {
    static TABLES: OnceLock<Box<[[u64; 256]; 8]>> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut t = Box::new([[0u64; 256]; 8]);
        for i in 0..256 {
            let mut crc = i as u64;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ POLY_REFLECTED } else { crc >> 1 };
            }
            t[0][i] = crc;
        }
        for k in 1..8 {
            for i in 0..256 {
                let prev = t[k - 1][i];
                t[k][i] = (prev >> 8) ^ t[0][(prev & 0xFF) as usize];
            }
        }
        t
    })
}

/// CRC-64/GO-ISO: reflected poly 0x1B, init and xorout all-ones.
pub fn crc64_go_iso(data: &[u8]) -> u64 {
    let t = tables();
    let mut crc = u64::MAX;
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        crc ^= u64::from_le_bytes(word);
        crc = t[7][(crc & 0xFF) as usize]
            ^ t[6][((crc >> 8) & 0xFF) as usize]
            ^ t[5][((crc >> 16) & 0xFF) as usize]
            ^ t[4][((crc >> 24) & 0xFF) as usize]
            ^ t[3][((crc >> 32) & 0xFF) as usize]
            ^ t[2][((crc >> 40) & 0xFF) as usize]
            ^ t[1][((crc >> 48) & 0xFF) as usize]
            ^ t[0][(crc >> 56) as usize];
    }
    for &b in chunks.remainder() {
        crc = (crc >> 8) ^ t[0][((crc ^ b as u64) & 0xFF) as usize];
    }
    crc ^ u64::MAX
}

/// FNV-1a 64-bit (XOR, then multiply), as used by Rust's `fnv::FnvHasher`.
pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for &b in data {
        h = (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// A DataFrame hash matches if either checksum equals it.
pub fn dataframe_hash_matches(data: &[u8], expected: u64) -> bool {
    crc64_go_iso(data) == expected || fnv1a_64(data) == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_values() {
        assert_eq!(crc64_go_iso(b"123456789"), 0xB909_56C7_75A4_1001);
        assert_eq!(crc64_go_iso(b""), 0);
        assert_eq!(fnv1a_64(b""), 0xCBF2_9CE4_8422_2325);
        assert_eq!(fnv1a_64(b"a"), 0xAF63_DC4C_8601_EC8C);
        assert_eq!(fnv1a_64(b"123456789"), 0x06D5_5739_23C6_CDFC);
    }

    #[test]
    fn slicing_matches_bitwise() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 31 + 7) as u8).collect();
        for len in [0, 1, 7, 8, 9, 15, 16, 17, 100, 1000] {
            let mut crc = u64::MAX;
            for &b in &data[..len] {
                crc ^= b as u64;
                for _ in 0..8 {
                    crc = if crc & 1 != 0 { (crc >> 1) ^ POLY_REFLECTED } else { crc >> 1 };
                }
            }
            assert_eq!(crc64_go_iso(&data[..len]), crc ^ u64::MAX, "len {len}");
        }
    }
}
