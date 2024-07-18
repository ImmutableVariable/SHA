// SHA 1 - https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub180-1.pdf
/// K constants for SHA-1
pub const K: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];

/// Initial hash values for SHA-1
pub const H: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// A circular left shift operation is defined by the following:
/// (X << n) OR (X >> (32 - n))
pub fn circular_left_shift(x: u32, n: u32) -> u32 {
    (x << n) | (x >> (32 - n))
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
 
    // message must be a multiple of 512 bits, so add padding to the message until it is
    let padding_len = (64 - (message_bytes.len() + 8) % 64) % 64;
    message_bytes.extend(vec![0; padding_len]);

    // now just append the length of the message (as stated in the standard)
    message_bytes.extend_from_slice(&message_len_bits.to_be_bytes());

    message_bytes
}

/// The function f(t;B,C,D) is defined as follows:
/// f(t;B,C,D) = (B AND C) OR ((NOT B) AND D) when 0 ≤ t ≤ 19
/// f(t;B,C,D) = B XOR C XOR D when 20 ≤ t ≤ 39
/// f(t;B,C,D) = (B AND C) OR (B AND D) OR (C AND D) when 40 ≤ t ≤ 59
/// f(t;B,C,D) = B XOR C XOR D when 60 ≤ t ≤ 79
/// This one will panic if the value of t is not in the range of 0 to 79
pub fn func_f(t: u32, b: u32, c: u32, d: u32) -> u32 {
    match t {
        0..=19 => (b & c) | ((!b) & d),
        20..=39 => b ^ c ^ d,
        40..=59 => (b & c) | (b & d) | (c & d),
        60..=79 => b ^ c ^ d,
        _ => panic!("Invalid value of t"),
    }
}

/// The Kt values are defined as follows:
/// Kt = 0x5A827999 when 0 ≤ t ≤ 19
/// Kt = 0x6ED9EBA1 when 20 ≤ t ≤ 39
/// Kt = 0x8F1BBCDC when 40 ≤ t ≤ 59
/// Kt = 0xCA62C1D6 when 60 ≤ t ≤ 79
/// If it is not in the range of 0 to 79, it will panic
pub fn get_k(t: u32) -> u32 {
    match t {
        0..=19 => K[0],
        20..=39 => K[1],
        40..=59 => K[2],
        60..=79 => K[3],
        _ => panic!("Invalid value of t"),
    }
}

/// The main hashing function of the SHA-1 algorithm
/// It expects a message as a byte slice and returns the hash as an array of 5 u32 values
/// ```rust
/// use sha1::hash;
/// 
/// let message = b"hello world";
/// let hash = hash(message);    
/// println!("{:?}", hash);
/// 
/// // print the hash as a hex string
/// for h in hash.iter() {
///     print!("{:x}", h);
/// }
/// println!();
/// 
/// ```
pub fn hash(message: &[u8]) -> [u32; 5] {
    let message_bytes = message_padding(message);
    let mut h = H;

    // this is all basically just the sha1 algorithm from the pdf file
    for chunk in message_bytes.chunks(64) {
        let chunk_len = chunk.len();
        let mut padded_chunk = Vec::from(chunk);
        if chunk_len < 64 {
            padded_chunk.resize(64, 0); // pad with zeros so it doesn't panic, maybe im dumb
        }

        let mut w = [0u32; 80];
        for t in 0..16 {
            w[t] = u32::from_be_bytes([
                padded_chunk[t * 4],
                padded_chunk[t * 4 + 1],
                padded_chunk[t * 4 + 2],
                padded_chunk[t * 4 + 3],
            ]);
        }
        for t in 16..80 {
            w[t] = circular_left_shift(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        for t in 0..80 {
            let temp = 
                circular_left_shift(a, 5)
                .wrapping_add(func_f(t, b, c, d))
                .wrapping_add(e)
                .wrapping_add(w[t as usize])
                .wrapping_add(get_k(t));
            e = d;
            d = c;
            c = circular_left_shift(b, 30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    h
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
    fn hash_test() {
        let message = b"hello world";
        let hash = hash(message);
        assert_eq!(hash, [0x2aae6c35, 0xc94fcfb4, 0x15dbe95f, 0x408b9ce9, 0x1ee846ed]);
    }

    #[test]
    fn hash_multiple_chunks_test() {
        let message = "abc".repeat(5000);
        let hash = hash(&message.as_bytes());
        assert_eq!(hash, [0x2ed315e2, 0x3eb0067f, 0xca759bce, 0x85eae2dc, 0xf180ac79]);
    }
}
