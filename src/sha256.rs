// sha256 as per https://csrc.nist.gov/files/pubs/fips/180-2/final/docs/fips180-2.pdf

/// A circular left shift operation is defined by the following:
/// (X << n) OR (X >> (32 - n))
pub fn circular_left_shift(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

/// A circular right shift operation is defined by the following:
/// (X >> n) OR (X << (32 - n))
pub fn circular_right_shift(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

/// Following the standard, the message is to be padded as follows:
/// 1. Append a 1 bit to the message
/// 2. Append 0 bits until the length of the message is congruent to 448 mod 512
/// 3. Append the length of the message in bits as a 64 bit number
pub fn message_padding(message: &[u8]) -> Vec<u8> {
    let message_len_bits = (message.len() * 8) as u64;
    let mut message_bytes = Vec::from(message);

    // append 1 bit as per the standard
    message_bytes.push(0x80); 
 
    let padding_len = (64 - (message_bytes.len() + 8) % 64) % 64;
    message_bytes.extend(vec![0; padding_len]);

    message_bytes.extend_from_slice(&message_len_bits.to_be_bytes());

    message_bytes
}

// functions for the hash algorithm 
pub fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

pub fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

pub fn big_sigma_0(x: u32) -> u32 {
    circular_right_shift(x, 2) ^ circular_right_shift(x, 13) ^ circular_right_shift(x, 22)
}

pub fn big_sigma_1(x: u32) -> u32 {
    circular_right_shift(x, 6) ^ circular_right_shift(x, 11) ^ circular_right_shift(x, 25)
}

pub fn small_sigma_0(x: u32) -> u32 {
    circular_right_shift(x, 7) ^ circular_right_shift(x, 18) ^ (x >> 3)
}


pub fn small_sigma_1(x: u32) -> u32 {
    circular_right_shift(x, 17) ^ circular_right_shift(x, 19) ^ (x >> 10)
}

/// Constants K as defined in the standard
pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
     0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
     0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
     0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

/// Initial hash values
pub const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

/// Create a SHA-256 hash of a message
/// 
/// ## Example
/// ```
/// use sha::sha256::hash;
/// 
/// let message = b"hello world";
/// let hash = hash(message);
/// 
/// // print the hash as a hex string
/// for h in hash.iter() {
///     print!("{:x}", h);
/// }
/// println!();
/// ```
pub fn hash(message: &[u8]) -> [u32; 8] {
    let message_bytes = message_padding(message);
    let mut h_const = H;

    for chunk in message_bytes.chunks(64) {
        let mut w = [0u32; 64];
        for t in 0..16 {
            w[t] = u32::from_be_bytes([
                chunk[t * 4],
                chunk[t * 4 + 1],
                chunk[t * 4 + 2],
                chunk[t * 4 + 3],
            ]);
        }
        for t in 16..64 {
            w[t] = small_sigma_1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(small_sigma_0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a = h_const[0];
        let mut b = h_const[1];
        let mut c = h_const[2];
        let mut d = h_const[3];
        let mut e = h_const[4];
        let mut f = h_const[5];
        let mut g = h_const[6];
        let mut h = h_const[7];

        for t in 0..64 {
            let temp1 = h
                .wrapping_add(big_sigma_1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let temp2 = big_sigma_0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h_const[0] = h_const[0].wrapping_add(a);
        h_const[1] = h_const[1].wrapping_add(b);
        h_const[2] = h_const[2].wrapping_add(c);
        h_const[3] = h_const[3].wrapping_add(d);
        h_const[4] = h_const[4].wrapping_add(e);
        h_const[5] = h_const[5].wrapping_add(f);
        h_const[6] = h_const[6].wrapping_add(g);
        h_const[7] = h_const[7].wrapping_add(h);
    }

    h_const
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_test() {
        let message = b"hello world";
        let padded_message = message_padding(message);
        assert_eq!(padded_message.len() % 64, 0); // padded message should be a multiple of 512 bits
    }

    #[test]
    fn circular_left_shift_test() {
        assert_eq!(circular_left_shift(0x80000000, 1), 1);
        assert_eq!(circular_left_shift(0x80000000, 31), 1073741824);
    }

    #[test]
    fn hash_test_sha256() {
        let message = b"hello world";
        let hash = hash(message);
        assert_eq!(hash, [
             0xb94d27b9, 0x934d3e08, 0xa52e52d7, 0xda7dabfa, 0xc484efe3, 0x7a5380ee, 0x9088f7ac, 0xe2efcde9
        ]);
    }

    #[test]
    fn hash_test_sha256_multi_block() {
        let message = b"a".repeat(1000);
        let hash = hash(&message);

        assert_eq!(hash, [
            0x41edece4, 0x2d63e8d9, 0xbf515a9b, 0xa6932e1c, 0x20cbc9f5, 0xa5d13464, 0x5adb5db1, 0xb9737ea3
        ]);
    }
}


