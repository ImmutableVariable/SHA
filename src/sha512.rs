// sha512.rs contains code from https://csrc.nist.gov/files/pubs/fips/180-2/final/docs/fips180-2.pdf

/// Following the standard, the message is to be padded as follows:
/// 1. Append a 1 bit to the message
/// 2. Append 0 bits until the length of the message is congruent to 896 mod 1024
/// 3. Append the length of the message in bits as a 128 bit number
pub fn message_padding(message: &[u8]) -> Vec<u8> {
    let message_len_bits = (message.len() * 8) as u128;
    let mut message_bytes = Vec::from(message);

    message_bytes.push(0x80);

    // Calculate padding length for 1024-bit block size
    // The total length (message + padding + length field) should be a multiple of 1024 bits
    let padding_len = (128 - (message_bytes.len() + 16) % 128) % 128;
    message_bytes.extend(std::iter::repeat(0).take(padding_len));

    message_bytes.extend_from_slice(&message_len_bits.to_be_bytes());

    message_bytes
}

pub const H: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

pub const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

// functions
pub fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ ((!x) & z)
}

pub fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

pub fn big_sigma_0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

pub fn big_sigma_1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

pub fn small_sigma_0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

pub fn small_sigma_1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// The hash function for SHA-512
/// 
/// ```
/// use sha::sha512::hash;
/// 
/// let message = b"hello world";
/// let result = hash(message);
/// 
/// for h in result.iter() {
///     print!("{:x}", h); // see https://emn178.github.io/online-tools/sha512.html?input=hi&input_type=utf-8&output_type=hex&hmac_input_type=utf-8
/// }
/// println!();
/// ```
pub fn hash(message: &[u8]) -> [u64; 8] {
    let message_bytes = message_padding(message);
    let mut h_const = H;

    for chunk in message_bytes.chunks(128) {
        let mut w = [0u64; 80];

        for t in 0..16 {
            w[t] = u64::from_be_bytes([
                chunk[t * 8],
                chunk[t * 8 + 1],
                chunk[t * 8 + 2],
                chunk[t * 8 + 3],
                chunk[t * 8 + 4],
                chunk[t * 8 + 5],
                chunk[t * 8 + 6],
                chunk[t * 8 + 7],
            ]);
        }

        for i in 16..80 {
            let s0 = small_sigma_0(w[i - 15]);
            let s1 = small_sigma_1(w[i - 2]);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h_const[0];
        let mut b = h_const[1];
        let mut c = h_const[2];
        let mut d = h_const[3];
        let mut e = h_const[4];
        let mut f = h_const[5];
        let mut g = h_const[6];
        let mut h = h_const[7];

        for i in 0..80 {
            let s1 = big_sigma_1(e);
            let ch = ch(e, f, g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = big_sigma_0(a);
            let maj = maj(a, b, c);
            let temp2 = s0.wrapping_add(maj);

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
    fn test_message_padding() {
        let message = b"hello world";
        let padded_message = message_padding(message);

        // Check if the message is padded correctly
        assert_eq!(padded_message.len() % 128, 0);
    }

    #[test]
    fn test_hash_sha512() {
        let message = b"hello world";
        let result = hash(message);

        // Expected hash value from https://emn178.github.io/online-tools/sha512.html
        let expected = [
            0x309ecc489c12d6eb, 0x4cc40f50c902f2b4, 0xd0ed77ee511a7c7a, 0x9bcd3ca86d4cd86f, 0x989dd35bc5ff4996, 0x70da34255b45b0cf, 0xd830e81f605dcf7d, 0xc5542e93ae9cd76f
        ];

        assert_eq!(result, expected);
    }

    #[test]
    fn test_hash_sha512_multi_block() {
        let message = b"a".repeat(1000000); // fips-180-2.pdf
        let result = hash(&message);

        let expected = [
            0xe718483d0ce76964, 0x4e2e42c7bc15b463, 0x8e1f98b13b204428, 0x5632a803afa973eb,
            0xde0ff244877ea60a, 0x4cb0432ce577c31b, 0xeb009c5c2c49aa2e, 0x4eadb217ad8cc09b
        ];

        assert_eq!(result, expected);
    }

}