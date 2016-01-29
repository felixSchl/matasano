extern crate matasano;
extern crate crossbeam;
extern crate rustc_serialize as serialize;
extern crate simple_parallel;
use self::matasano::set_1;
use self::serialize::hex::{ FromHex, ToHex };
use self::serialize::base64::{ FromBase64 };
use std::cmp::Ordering::{ Equal };
use std::fs::File;
use std::io::{ BufReader };
use std::io::prelude::*;
use matasano::set_1::{ Ngram, detect_single_byte_xor, repeating_key_xor };
use std::thread;
use std::sync::mpsc;
use std::sync::{ Arc };
use self::simple_parallel::Pool;

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
            .and_then(|x| detect_single_byte_xor(&x, &ngram, None).first().cloned())
            .unwrap(),
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
        .map(|l| detect_single_byte_xor(&l, &ngram, None))
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

#[test]
fn challenge_6() {
    assert_eq!(
        set_1::hamming_distance(
            "this is a test",
            "wokka wokka!!!"
        ),
        37
    );

    let ngram = Ngram::from_file("./resources/english_trigrams.txt");
    let mut file = File::open("./fixtures/set1_challenge6.txt").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();

    // XXX: Should avoid making this a string first, just operate on u8s!
    let contents = contents.from_base64().unwrap()
        .into_iter()
        .map(|b| b as char)
        .collect::<String>();

    // calculate the scores for various key lengths
    let mut keysize_scores = (2..41).map(|keysize| {
        let block_1 = contents.chars()
            .take(keysize)
            .collect::<String>();
        let block_2 = contents.chars()
            .skip(keysize)
            .take(keysize)
            .collect::<String>();
        let dist = set_1::hamming_distance(&block_1, &block_2);
        let norm_dist = (dist as f32) / (keysize as f32);
        (keysize, norm_dist)
    }).collect::<Vec<_>>();

    keysize_scores.sort_by(|&(_, a), &(_, b)| {
        a.partial_cmp(&b).unwrap_or(Equal)
    });

    // select the most likely key size
    let mut keysizes = keysize_scores.iter()
        .map(|&(a, _)| a)
        .take(3 /* arbitrary */)
        .collect::<Vec<_>>();

    keysizes.dedup();

    // break the ciphertext into blocks of `keysize`
    let blocks = keysizes.iter()
        .map(|keysize| {
            println!("chunking up contents into chunks of keysize {}", keysize);
            let chunks = contents
                .chars()
                .collect::<Vec<_>>()
                .chunks(*keysize)
                .fold(Vec::new() as Vec<Vec<char>>, |mut acc, cs| {
                    let mut block = Vec::new();
                    block.extend_from_slice(cs);
                    acc.push(block);
                    acc
                });
            println!("got {} chunks for keysize {}", chunks.len(), keysize);
            (keysize, chunks)
        })
        .collect::<Vec<_>>();

    // transpose the blocks
    let blocks = blocks.iter()
        .map(|&(keysize, ref chunks)| {
            (0..*keysize).map(move |i| {
                chunks.iter()
                    .filter_map(move |ref block| block.get(i))
                    .map(|c| c.to_owned() as u8)
                    .collect::<Vec<u8>>()
            }).collect::<Vec<_>>()
        }).collect::<Vec<_>>();

    // solve the single-byte-xor for each block
    let mut pool = Pool::new(4);
    let blocks = blocks.iter()
        .map(|chunks| {
            chunks.into_iter()
                .filter_map(|bytes| {
                    detect_single_byte_xor(
                        &bytes.iter().map(|c| *c as u8).collect::<Vec<_>>(),
                        &ngram,
                        Some(&mut pool)
                    ).first().cloned()
                })
                .collect::<Vec<_>>()
                [..].concat()
        })
        .collect::<Vec<_>>();

    for key in blocks {
        println!("keysize: {}", key.len());
        println!(
            "solved: {}",
            repeating_key_xor(&key, &contents)
                .from_hex()
                .unwrap()
                .into_iter()
                .map(|b| b as char)
                .collect::<String>()
        );
    }
}
