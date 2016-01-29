extern crate crossbeam;
extern crate rustc_serialize as serialize;
extern crate simple_parallel;
use self::simple_parallel::Pool;
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

pub fn detect_single_byte_xor(
    bytes: &Vec<u8>,
    ngram: &Ngram,
    pool:  Option<&mut Pool>
    ) -> Vec<(char, String)>
{
    let mut chars = (0u8..255u8).collect::<Vec<u8>>();
    chars.push(255u8); // ... because the range end is exclusive, and `0..256` does not work.

    let mut results = {
        let mut default_pool = Pool::new(1);
        let mut pool = pool.unwrap_or(&mut default_pool);
        let results: Vec<_> = crossbeam::scope(|scope| {
            pool.map(scope, chars.iter(), |c| {
                let input = bytes.iter()
                    .map(|x| (x ^ c) as char)
                    .collect::<String>();
                let score = ngram.score(&input);
                (c.to_owned() as char, input, score)
            }).collect()
        });
        results
    };

    results.sort_by(|&(_, _, score_a), &(_, _, score_b)| {
        score_b.partial_cmp(&score_a).unwrap_or(Equal)
    });

    results.iter()
        .map(|&(c, ref x, _)| (c, x.clone()))
        .collect::<Vec<(char, String)>>()
}

pub fn repeating_key_xor(key: &str, input: &str) -> String {
    input.chars().zip(key.chars().cycle())
        .map(|(char, byte)| (char as u8) ^ (byte as u8))
        .map(|c| c as char)
        .collect::<String>()
}
