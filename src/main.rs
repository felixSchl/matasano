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
    assert_eq!(
        hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )
}

fn xor(v1: &Vec<u8>, v2: &Vec<u8>) -> Vec<u8> {
    v1.iter().zip(v2).map(|(&x, &y)| x ^ y).collect::<Vec<u8>>()
}

#[test]
fn challenge_2() {
    assert_eq!(
        xor(&"1c0111001f010100061a024b53535009181c".from_hex().unwrap(),
            &"686974207468652062756c6c277320657965".from_hex().unwrap())[..].to_hex(),
        "746865206b696420646f6e277420706c6179"
    )
}

fn main() {
}
