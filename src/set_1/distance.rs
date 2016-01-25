extern crate bit_vec;
use self::bit_vec::BitVec;

pub fn bits_from_str(input: &str) -> BitVec {
    BitVec::from_bytes(&input.chars()
        .map(|c| c as u8)
        .collect::<Vec<_>>()[..])
}

pub fn hamming_distance(left: &str, right: &str) -> u32 {
    bits_from_str(left).iter()
        .zip(bits_from_str(right).iter())
        .fold(0, |acc, (a, b)| if a == b { acc } else { acc + 1 })
}
