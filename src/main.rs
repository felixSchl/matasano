extern crate rustc_serialize as serialize;

use std::fs::File;
use std::ascii::{ AsciiExt };
use std::io::{ self, BufReader };
use std::io::prelude::*;
use serialize::base64::{ ToBase64, STANDARD };
use serialize::hex::{ FromHex, ToHex };
use std::collections::HashMap;

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

fn calc_score(input: &str) -> u32 {
    let common_words = hashmap![
      "THE" => 6.42,   "ON" => 0.78,  "ARE" => 0.47,
       "OF" => 2.76, "WITH" => 0.75, "THIS" => 0.42,
      "AND" => 2.75,   "HE" => 0.75,    "I" => 0.41,
       "TO" => 2.67,   "IT" => 0.74,  "BUT" => 0.40,
        "A" => 2.43,   "AS" => 0.71, "HAVE" => 0.39,
       "IN" => 2.31,   "AT" => 0.58,   "AN" => 0.37,
       "IS" => 1.12,  "HIS" => 0.55,  "HAS" => 0.35,
      "FOR" => 1.01,   "BY" => 0.51,  "NOT" => 0.34,
     "THAT" => 0.92,   "BE" => 0.48, "THEY" => 0.33,
      "WAS" => 0.88, "FROM" => 0.47,   "OR" => 0.30
    ];

    let monogram_freqs = hashmap![
        'A' =>  8.55, 'K' =>  0.81, 'U' =>  2.68,
        'B' =>  1.60, 'L' =>  4.21, 'V' =>  1.06,
        'C' =>  3.16, 'M' =>  2.53, 'W' =>  1.83,
        'D' =>  3.87, 'N' =>  7.17, 'X' =>  0.19,
        'E' => 12.10, 'O' =>  7.47, 'Y' =>  1.72,
        'F' =>  2.18, 'P' =>  2.07, 'Z' =>  0.11,
        'G' =>  2.09, 'Q' =>  0.10,
        'H' =>  4.96, 'R' =>  6.33,
        'I' =>  7.33, 'S' =>  6.73,
        'J' =>  0.22, 'T' =>  8.94
    ];

    let bigram_freqs = hashmap![
        "TH" => 2.71, "EN" => 1.13, "NG" => 0.89,
        "HE" => 2.33, "AT" => 1.12, "AL" => 0.88,
        "IN" => 2.03, "ED" => 1.08, "IT" => 0.88,
        "ER" => 1.78, "ND" => 1.07, "AS" => 0.87,
        "AN" => 1.61, "TO" => 1.07, "IS" => 0.86,
        "RE" => 1.41, "OR" => 1.06, "HA" => 0.83,
        "ES" => 1.32, "EA" => 1.00, "ET" => 0.76,
        "ON" => 1.32, "TI" => 0.99, "SE" => 0.73,
        "ST" => 1.25, "AR" => 0.98, "OU" => 0.72,
        "NT" => 1.17, "TE" => 0.98, "OF" => 0.71
    ];

    let trigram_freqs = hashmap![
        "THE" => 1.81, "ERE" => 0.31, "HES" => 0.24,
        "AND" => 0.73, "TIO" => 0.31, "VER" => 0.24,
        "ING" => 0.72, "TER" => 0.30, "HIS" => 0.24,
        "ENT" => 0.42, "EST" => 0.28, "OFT" => 0.22,
        "ION" => 0.42, "ERS" => 0.28, "ITH" => 0.21,
        "HER" => 0.36, "ATI" => 0.26, "FTH" => 0.21,
        "FOR" => 0.34, "HAT" => 0.26, "STH" => 0.21,
        "THA" => 0.33, "ATE" => 0.25, "OTH" => 0.21,
        "NTH" => 0.33, "ALL" => 0.25, "RES" => 0.21,
        "INT" => 0.32, "ETH" => 0.24, "ONT" => 0.20
    ];

    let quad_freqs = hashmap![
        "TION" => 0.31, "OTHE" => 0.16, "THEM" => 0.12,
        "NTHE" => 0.27, "TTHE" => 0.16, "RTHE" => 0.12,
        "THER" => 0.24, "DTHE" => 0.15, "THEP" => 0.11,
        "THAT" => 0.21, "INGT" => 0.15, "FROM" => 0.10,
        "OFTH" => 0.19, "ETHE" => 0.15, "THIS" => 0.10,
        "FTHE" => 0.19, "SAND" => 0.14, "TING" => 0.10,
        "THES" => 0.18, "STHE" => 0.14, "THEI" => 0.10,
        "WITH" => 0.18, "HERE" => 0.13, "NGTH" => 0.10,
        "INTH" => 0.17, "THEC" => 0.13, "IONS" => 0.10,
        "ATIO" => 0.17, "MENT" => 0.12, "ANDT" => 0.10
    ];

    let quint_freqs = hashmap![
        "OFTHE" => 0.18, "ANDTH" => 0.07, "CTION" => 0.05,
        "ATION" => 0.17, "NDTHE" => 0.07, "WHICH" => 0.05,
        "INTHE" => 0.16, "ONTHE" => 0.07, "THESE" => 0.05,
        "THERE" => 0.09, "EDTHE" => 0.06, "AFTER" => 0.05,
        "INGTH" => 0.09, "THEIR" => 0.06, "EOFTH" => 0.05,
        "TOTHE" => 0.08, "TIONA" => 0.06, "ABOUT" => 0.04,
        "NGTHE" => 0.08, "ORTHE" => 0.06, "ERTHE" => 0.04,
        "OTHER" => 0.07, "FORTH" => 0.06, "IONAL" => 0.04,
        "ATTHE" => 0.07, "INGTO" => 0.06, "FIRST" => 0.04,
        "TIONS" => 0.07, "THECO" => 0.05, "WOULD" => 0.04
    ];

    0
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

    results.sort_by(|&(_, scoreA), &(_, scoreB)| scoreB.cmp(&scoreA));

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
