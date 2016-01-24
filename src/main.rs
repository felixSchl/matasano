extern crate regex;
extern crate rustc_serialize as serialize;

use std::fs::File;
use std::cmp;
use std::cmp::Ordering;
use std::ascii::{ AsciiExt };
use std::io::{ self, BufReader };
use std::io::prelude::*;
use serialize::base64::{ ToBase64, STANDARD };
use serialize::hex::{ FromHex, ToHex };
use std::collections::HashMap;
use regex::Regex;

fn hex_to_base64(str: &str) -> String {
    return str.from_hex()
        .unwrap()
        .to_base64(STANDARD);
}

#[test]
fn challenge_1() {
    let input="49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected="SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(
        hex_to_base64(input),
        expected
    )
}

fn xor(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
    v1.iter().zip(v2).map(|(&x, &y)| x ^ y).collect::<Vec<u8>>()
}

#[test]
fn challenge_2() {
    let input_1="1c0111001f010100061a024b53535009181c";
    let input_2="686974207468652062756c6c277320657965";
    let expected="746865206b696420646f6e277420706c6179";
    assert_eq!(
        xor(&input_1.from_hex().unwrap(),
            &input_2.from_hex().unwrap())[..].to_hex(),
        expected
    )
}

macro_rules! hashmap {
    ($( $key: expr => $val: expr ),*) => {{
        let mut map = ::std::collections::HashMap::new();
        $( map.insert($key, $val); )*
        map
    }}
}

#[derive(Debug)]
struct Ngram {
    L: u32,
    N: u32,
    floor: f32,
    table: HashMap<String, f32>,
}

impl Ngram {
    fn score(&self, input: &str) -> f32 {

        let mut score = 0f32;

        let plaintext = {
            let re=Regex::new(r"[^A-Z] ").unwrap();
            re.replace_all(&input.to_ascii_uppercase(), "")
        };

        for word in plaintext.split(" ") {
            for i in 0..cmp::max(0, (word.len() as i32) - (self.L as i32)) {
                let gram = word.chars()
                    .skip(i as usize)
                    .take(self.L as usize)
                    .collect::<String>();
                score += *self.table
                    .get(&gram)
                    .unwrap_or(&self.floor);
            }
        }

        return score
    }
}

fn load_training_set(path: &str) -> Ngram {
    let f = File::open(path).unwrap() /* XXX */;
    let f = BufReader::new(f);

    // populate the count-table
    let mut sum = 0;
    let mut table = HashMap::<String, f32>::new();
    let mut keylen = None;
    for line in f.lines() {
        let line = line.unwrap() /* XXX */;
        let xs = line.split(' ').collect::<Vec<_>>();
        if let Some((key, val)) = xs.get(0).and_then(|key| {
            let key = key.to_string();
            xs.get(1)
                .and_then(|val| val.parse::<u32>().ok())
                .map(|val| (key, val))
        }) {

            let new_keylen = match keylen {
                None         => Ok(key.len() as u32),
                Some(keylen) => {
                    if keylen == key.len() as u32 {
                        Ok(keylen as u32)
                    } else {
                        Err("key-lengths are not homogenous")
                    }
                }
            };

            sum += val;
            keylen = Some(new_keylen.unwrap() /* XXX */);
            table.insert(key, (val as f32));
        }
    }

    // convert the counts to probabilities
    for (_, val) in table.iter_mut() {
        *val = (*val / (sum as f32)).log10();
    }

    // calculate the base value
    let floor = (0.01f32 / (sum as f32)).log10();

    return Ngram {
        L:     keylen.unwrap() /* XXX */,
        N:     sum,
        floor: floor,
        table: table,
    }
}

fn calc_score(input: &str) -> f32 {
    let ngram = load_training_set("./resources/english_trigrams.txt");
    ngram.score(&input)
}

fn single_byte_xor(bytes: Vec<u8>) -> Option<Vec<String>> {
    let chars=32u8..128u8;
    let mut results = chars.clone()
        .filter_map(|c| {
            bytes.iter()
                .fold(Some(vec![]), |acc, x| acc.and_then(|mut data| {
                    let xor = x ^ c;
                    if xor >= 32u8 /* skip control characters */ {
                        data.push(xor);
                        Some(data)
                    } else {
                        None
                    }
                }))
        })
        .map(|b| String::from_utf8(b).unwrap())
        .map(|s| (s.clone(), calc_score(&s)))
        .collect::<Vec<_>>();

    // XXX: No compare instance for f32?
    results.sort_by(|&(_, scoreA), &(_, scoreB)| {
        scoreB.partial_cmp(&scoreA).unwrap_or(Ordering::Equal)
    });

    Some(
        results.iter()
            .map(|&(ref x, _)| x.clone())
            .collect::<Vec<String>>()
    )
}

#[test]
fn challenge_3() {
    let input="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    assert_eq!(
        input.from_hex().ok()
            .and_then(single_byte_xor).unwrap()
            .first().unwrap(),
        "Cooking MC's like a pound of bacon"
    );
}

// #[test]
// fn challenge_4() {
//     let f = File::open("./fixtures/set1_challenge4.txt").unwrap();
//     let f = BufReader::new(f);
//
//     let mut results = f.lines()
//         .map(|l| l.unwrap())
//         .filter(|l| l.len() == 60)
//         .filter_map(|l| l.from_hex().ok())
//         .filter_map(|l| single_byte_xor(l))
//         .filter_map(|xs| xs.first().map(|x| x.clone()))
//         .map(|str| {
//             let bytes = str.chars();
//             (
//                 str.clone(),
//                 bytes.fold(0, |acc, x| acc + calc_score(x))
//             )
//         })
//         .collect::<Vec<_>>();
//     results.sort_by(|&(_, scoreA), &(_, scoreB)| scoreB.cmp(&scoreA));
//     let results = results.iter()
//         .map(|&(ref x, _)| x.clone())
//         .collect::<Vec<String>>();
//
//     println!("{}", results.first().unwrap());
// }


fn main() {
}
