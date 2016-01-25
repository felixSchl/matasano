extern crate regex;
extern crate rustc_serialize as serialize;

use std::fs::File;
use std::cmp;
use std::cmp::Ordering;
use std::ascii::{ AsciiExt };
use std::io::{ BufReader };
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
    size: u32,
    total: u32,
    floor: f32,
    table: HashMap<String, f32>,
}

/// N-gram based crypto frequency analysis based on the
/// "practicalcryptography.com" articles on the topic.
///
/// Reference implementation:
/// http://practicalcryptography.com/media/cryptanalysis/files/ngram_score_1.py
impl Ngram {
    fn score(&self, input: &str) -> f32 {
        let mut score = 0f32;

        let plaintext = {
            let re=Regex::new(r"[^A-Z] ").unwrap();
            re.replace_all(&input.to_ascii_uppercase(), "")
        };

        for word in plaintext.split(" ") {
            for i in 0..cmp::max(0, (word.len() as i32) - (self.size as i32)) {
                let gram = word.chars()
                    .skip(i as usize)
                    .take(self.size as usize)
                    .collect::<String>();
                score += *self.table
                    .get(&gram)
                    .unwrap_or(&self.floor);
            }
        }

        return score
    }

    fn from_file(path: &str) -> Ngram {
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
            size:  keylen.unwrap() /* XXX */,
            total: sum,
            floor: floor,
            table: table,
        }
    }
}

fn single_byte_xor(bytes: Vec<u8>, ngram: &Ngram) -> Option<Vec<String>> {

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
        score_b.partial_cmp(&score_a).unwrap_or(Ordering::Equal)
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

    let ngram = Ngram::from_file("./resources/english_trigrams.txt");

    assert_eq!(
        input.from_hex().ok()
            .and_then(|x| single_byte_xor(x, &ngram)).unwrap()
            .first().unwrap(),
        "Cooking MC's like a pound of bacon"
    );
}

#[test]
fn challenge_4() {
    let ngram = Ngram::from_file("./resources/english_trigrams.txt");

    let f = File::open("./fixtures/set1_challenge4.txt").unwrap();
    let f = BufReader::new(f);

    // select the best single-byte-xor for each input
    let mut candidates = f.lines()
        .filter_map(|l| l.ok())
        .filter(|l| l.len() == 60)
        .filter_map(|l| l.from_hex().ok())
        .filter_map(|l| single_byte_xor(l, &ngram))
        .filter_map(|xs| xs.first().map(|x| x.clone()))
        .map(|ref x| (x.clone(), ngram.score(&x)))
        .collect::<Vec<_>>();

    // sort each candidate by it's english-ness
    candidates.sort_by(|&(_, score_a), &(_, score_b)| {
        score_b.partial_cmp(&score_a).unwrap_or(Ordering::Equal)
    });

    // select the winner
    let results = candidates.iter()
        .map(|&(ref x, _)| x.clone())
        .collect::<Vec<String>>();

    assert_eq!(results.first().unwrap(), "Now that the party is jumping\n");
}

fn main() {
}
