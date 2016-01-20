extern crate rustc_serialize as serialize;

use serialize::base64::{ ToBase64, STANDARD };
use serialize::hex::{ FromHex };

fn hex_to_base64(str: &str) -> String {
    return str.from_hex()
        .unwrap()
        .to_base64(STANDARD);
}

fn main() {
    println!("{}", hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
}
