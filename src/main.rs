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

#[test]
fn challenge_3() {
    let input="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let chars=('a' as u8)..('z' as u8);
    let bytes=input.from_hex().unwrap();

    let results=chars
        .map(|c| {
            bytes.iter()
                .map(|b| (b ^ c) as char)
                .collect::<String>()

        })
        .collect::<Vec<_>>();

    for result in results {
        println!("{}", result);
    }
}

fn main() {
}
