extern crate rustc_serialize as serialize;

use serialize::base64::{ ToBase64, STANDARD };
use serialize::hex::{ FromHex, ToHex };

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

fn calc_score(c: char) -> i32 {

    let lower_alpha = 97u8..123u8;
    let upper_alpha = 65u8..91u8;
    let punctuation = [' ', '\'', '"', ',', '.', ':'];

    let byte = c as u8;
    if (byte >= lower_alpha.start && byte < lower_alpha.end)
    || (byte >= upper_alpha.start && byte < upper_alpha.end) {
        100
    } else if punctuation.contains(&c) {
        50
    } else {
        0
    }
}

fn single_byte_xor(bytes: Vec<u8>) -> Option<String> {
    let chars=32u8..127u8;
    let mut results = chars.clone()
        .filter_map(|c| {
            bytes.iter()
                .fold(Some(vec![]), |acc, x| acc.and_then(|mut data| {
                    let xor = x ^ c;
                    if xor >= chars.start && xor < chars.end {
                        data.push(xor as char);
                        Some(data)
                    } else {
                        None
                    }
                }))
        })
        .map(|bytes| {
            (
                bytes.iter().cloned().collect::<String>(),
                bytes.iter().fold(0, |acc, x| acc + calc_score(*x))
            )
        })
        .collect::<Vec<_>>();
    results.sort_by(|&(_, scoreA), &(_, scoreB)| scoreB.cmp(&scoreA));
    results.first().map(|&(ref x, _)| x.clone())
}

#[test]
fn challenge_3() {
    let input="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    assert_eq!(
        input.from_hex().ok().and_then(single_byte_xor).unwrap(),
        "Cooking MC's like a pound of bacon"
    );
}

fn main() {
}
