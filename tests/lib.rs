extern crate matasano;
extern crate rustc_serialize as serialize;
use self::matasano::set_1;
use self::serialize::hex::{ FromHex, ToHex };
use std::cmp::Ordering::{ Equal };
use std::fs::File;
use std::io::{ BufReader };
use std::io::prelude::*;
use matasano::set_1::{ Ngram, detect_single_byte_xor };

#[test]
fn challenge_1() {
    let input="49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected="SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    assert_eq!(
        set_1::hex_to_base64(input).unwrap(),
        expected
    )
}

#[test]
fn challenge_2() {
    let input_1="1c0111001f010100061a024b53535009181c";
    let input_2="686974207468652062756c6c277320657965";
    let expected="746865206b696420646f6e277420706c6179";

    assert_eq!(
        set_1::xor(
            &input_1.from_hex().unwrap(),
            &input_2.from_hex().unwrap()
        )[..].to_hex(),
        expected
    )
}

#[test]
fn challenge_3() {
    let input="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ngram = Ngram::from_file("./resources/english_trigrams.txt");

    assert_eq!(
        input.from_hex().ok()
            .and_then(|x| detect_single_byte_xor(x, &ngram)).unwrap()
            .first().unwrap(),
        "Cooking MC's like a pound of bacon"
    );
}

#[test]
#[ignore]
fn challenge_4() {
    let ngram = Ngram::from_file("./resources/english_trigrams.txt");

    let f = File::open("./fixtures/set1_challenge4.txt").unwrap();
    let f = BufReader::new(f);

    // select the best single-byte-xor for each input
    let mut candidates = f.lines()
        .filter_map(|l| l.ok())
        .filter(|l| l.len() == 60)
        .filter_map(|l| l.from_hex().ok())
        .filter_map(|l| detect_single_byte_xor(l, &ngram))
        .filter_map(|xs| xs.first().map(|x| x.clone()))
        .map(|ref x| (x.clone(), ngram.score(&x)))
        .collect::<Vec<_>>();

    // sort each candidate by it's english-ness
    candidates.sort_by(|&(_, score_a), &(_, score_b)| {
        score_b.partial_cmp(&score_a).unwrap_or(Equal)
    });

    // select the winner
    let results = candidates.iter()
        .map(|&(ref x, _)| x.clone())
        .collect::<Vec<String>>();

    assert_eq!(results.first().unwrap(), "Now that the party is jumping\n");
}

#[test]
fn challenge_5() {
    let key = "ICE";
    let input =
       "Burning 'em, if you ain't quick and nimble\n\
        I go crazy when I hear a cymbal";
    assert_eq!(
        set_1::repeating_key_xor(key, input),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
            a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )
}
