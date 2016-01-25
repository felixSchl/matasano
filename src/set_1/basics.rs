extern crate rustc_serialize as serialize;
use self::serialize::base64::{ ToBase64, STANDARD };
use self::serialize::hex::{ FromHex, FromHexError };
use std::cmp::Ordering::{ Equal };
use super::{ Ngram };

pub fn hex_to_base64(str: &str) -> Result<String, FromHexError> {
    return str.from_hex().map(|s| s.to_base64(STANDARD))
}

pub fn xor(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
    v1.iter().zip(v2).map(|(&x, &y)| x ^ y).collect::<Vec<u8>>()
}

pub fn single_byte_xor(bytes: Vec<u8>, ngram: &Ngram) -> Option<Vec<String>> {
    let mut chars = (0u8..255u8).collect::<Vec<u8>>();
    chars.push(255u8); // ... because the range end is exclusive, and `0..256` does not work.

    let mut results = chars.iter()
        .map(|c| {
            bytes.iter()
                .fold(vec![], |mut acc, x| {
                    acc.push((x ^ c) as char);
                    acc
                })
                .into_iter()
                .collect::<String>()
        })
        .map(|s| (s.clone(), ngram.score(&s)))
        .collect::<Vec<_>>();

    results.sort_by(|&(_, score_a), &(_, score_b)| {
        score_b.partial_cmp(&score_a).unwrap_or(Equal)
    });

    Some(results.iter()
        .map(|&(ref x, _)| x.clone())
        .collect::<Vec<String>>())
}
