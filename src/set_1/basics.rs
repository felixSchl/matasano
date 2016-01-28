extern crate rustc_serialize as serialize;
use self::serialize::base64::{ ToBase64, STANDARD };
use self::serialize::hex::{ FromHex, FromHexError, ToHex };
use std::cmp::Ordering::{ Equal };
use std::thread;
use super::{ Ngram };
use std::sync::{ Arc };

pub fn hex_to_base64(str: &str) -> Result<String, FromHexError> {
    return str.from_hex().map(|s| s.to_base64(STANDARD))
}

pub fn xor(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
    v1.iter().zip(v2).map(|(&x, &y)| x ^ y).collect::<Vec<u8>>()
}

pub fn detect_single_byte_xor(bytes: &Vec<u8>, ngram: &Ngram) -> Option<Vec<String>> {
    let mut chars = (0u8..255u8).collect::<Vec<u8>>();
    chars.push(255u8); // ... because the range end is exclusive, and `0..256` does not work.

    let mut results = {
        let ngram = Arc::new(ngram);
        let bytes = bytes.to_vec();
        let bytes = Arc::new(bytes);
        let mut work_handles = Vec::<thread::JoinHandle<(String, f32)>>::new();
        for c in chars {
            let bytes = bytes.clone();
            let ngram = ngram.clone();
            work_handles.push(thread::spawn(move || {
                let input = bytes.iter()
                    .map(|x| (x ^ c) as char)
                    .collect::<String>();
                // XXX: THIS DOES NOT COMPILE:
                let score = ngram.score(&input.to_string());
                (input, score)
            }))
        }

        work_handles.into_iter()
            .map(|h| h.join())
            .map(|r| r.unwrap())
            .collect::<Vec<_>>()
    };

    results.sort_by(|&(_, score_a), &(_, score_b)| {
        score_b.partial_cmp(&score_a).unwrap_or(Equal)
    });

    Some(results.iter()
        .map(|&(ref x, _)| x.clone())
        .collect::<Vec<String>>())
}

pub fn repeating_key_xor(key: &str, input: &str) -> String {
    let hash = input.chars().zip(key.chars().cycle())
        .map(|(char, byte)| (char as u8) ^ (byte as u8))
        .collect::<Vec<_>>();
    hash.to_hex()
}
