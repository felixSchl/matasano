extern crate openssl;
extern crate matasano;
extern crate crossbeam;
extern crate rustc_serialize as serialize;
extern crate simple_parallel;
use self::matasano::set_1;
use self::serialize::hex::{ FromHex, ToHex };
use self::serialize::base64::{ FromBase64 };
use self::simple_parallel::Pool;
use self::openssl::crypto::symm as crypto;
use std::cmp::Ordering::{ Equal };
use std::fs::File;
use std::io::{ BufReader };
use std::io::prelude::*;
use std::str;
use matasano::set_1::{ Ngram, detect_single_byte_xor, repeating_key_xor };

fn str_to_u8_vec(input: &str) -> Vec<u8> {
    input.chars().map(|c| c as u8).collect::<Vec<u8>>()
}

fn u8_vec_to_str(input: &Vec<u8>) -> String {
    input.into_iter().map(|b| *b as char).collect::<String>()
}

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
    let input = input.from_hex().unwrap();
    let result = detect_single_byte_xor(&input, &ngram, None);
    let result = result.first().cloned().unwrap().1;
    let result = str::from_utf8(&result).unwrap();

    assert_eq!(
        result,
        "Cooking MC's like a pound of bacon"
    );
}

#[test]
fn challenge_4() {
    let ngram = Ngram::from_file("./resources/english_trigrams.txt");
    let mut pool = Pool::new(8);

    let f = File::open("./fixtures/set_1_challenge_4.txt").unwrap();
    let f = BufReader::new(f);

    // select the best single-byte-xor for each input
    // XXX: Consider doing this in parallel (!)
    let mut candidates = f.lines()
        .filter_map(|l| l.ok())
        .filter(|l| l.len() == 60)
        .filter_map(|l| l.from_hex().ok())
        .map(|l| detect_single_byte_xor(&l, &ngram, Some(&mut pool)))
        .filter_map(|xs| xs.first().cloned())
        .map(|x| x.1)
        .map(|ref x| (x.clone(), ngram.score(&x)))
        .collect::<Vec<_>>();

    // sort each candidate by it's english-ness
    candidates.sort_by(|&(_, score_a), &(_, score_b)| {
        score_b.partial_cmp(&score_a).unwrap_or(Equal)
    });

    // select the winner
    let results = candidates.iter()
        .map(|&(ref x, _)| x.clone())
        .collect::<Vec<Vec<u8>>>();

    let result = results.first().unwrap();
    let result = str::from_utf8(&result).unwrap();

    assert_eq!(result, "Now that the party is jumping\n");
}

#[test]
fn challenge_5() {
    let key = "ICE";
    let input =
       "Burning 'em, if you ain't quick and nimble\n\
        I go crazy when I hear a cymbal";
    assert_eq!(
        set_1::repeating_key_xor(
            &str_to_u8_vec(key),
            &str_to_u8_vec(input)
        ).to_hex(),
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
        a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )
}

fn unsafe_read_file(path: &str) -> String {
    let mut file = File::open(path).unwrap();
    let mut contents =  String::new();
    file.read_to_string(&mut contents).unwrap();
    contents
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
    let cipher_text = unsafe_read_file("./fixtures/set_1_challenge_6.txt");
    let solution = unsafe_read_file("./fixtures/set_1_challenge_6_solution.txt");

    // XXX: Should avoid making this a string first, just operate on u8s!
    let cipher_text = cipher_text.from_base64().unwrap();

    // calculate the scores for various key lengths
    let mut keysize_scores = (2..41).map(|keysize| {

        let chunks = cipher_text.chunks(keysize*2);
        let num_chunks = chunks.len();

        let dist = chunks.map(|chunk| {
            let block_1 = chunk.iter()
                .map(|c| *c as char)
                .take(keysize)
                .collect::<String>();
            let block_2 = chunk.iter()
                .map(|c| *c as char)
                .skip(keysize)
                .take(keysize)
                .collect::<String>();
            set_1::hamming_distance(&block_1, &block_2)
        }).fold(0, |sum, i| sum + i);

        let norm_dist = (dist as f32) / ((keysize * num_chunks) as f32);

        (keysize, norm_dist)
    }).collect::<Vec<_>>();

    keysize_scores.sort_by(|&(_, a), &(_, b)| {
        a.partial_cmp(&b).unwrap_or(Equal)
    });

    // select the most likely key size
    let keysizes = keysize_scores.iter()
        .map(|&(a, _)| a)
        .skip(0)
        .take(3)
        .collect::<Vec<_>>();

    // break the ciphertext into blocks of `keysize`
    let blocks = keysizes.iter()
        .map(|keysize| {
            let chunks = cipher_text.chunks(*keysize)
                .fold(Vec::new() as Vec<Vec<u8>>, |mut acc, cs| {
                    let mut block = Vec::new();
                    block.extend_from_slice(cs);
                    acc.push(block);
                    acc
                });
            (keysize, chunks)
        })
        .collect::<Vec<_>>();

    // transpose the blocks
    let blocks = blocks.iter()
        .map(|&(keysize, ref chunks)| {
            (0..*keysize).map(|i| {
                chunks.iter()
                    .filter_map(|block| block.get(i))
                    .map(|c| c.to_owned() as u8)
                    .collect::<Vec<u8>>()
            }).collect::<Vec<_>>()
        }).collect::<Vec<_>>();

    // solve the single-byte-xor for each block
    let mut pool = Pool::new(8);
    let keys = blocks.iter()
        .map(|chunks| {
            chunks.into_iter()
                .filter_map(|bytes| {
                    let keys = detect_single_byte_xor(
                        &bytes,
                        &ngram,
                        Some(&mut pool)
                    );

                    let keys = keys.iter()
                        .map(|&(c, _)| c)
                        .collect::<Vec<_>>();

                    keys.first().cloned()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let mut answers = keys.iter()
        .map(|key| repeating_key_xor(&key, &cipher_text))
        .map(|x| (x.clone(), ngram.score(&x)))
        .collect::<Vec<_>>();

    answers.sort_by(|&(_, score_a), &(_, score_b)| {
        score_b.partial_cmp(&score_a).unwrap_or(Equal)
    });

    let answers = answers.into_iter().map(|(x, _)| x).collect::<Vec<_>>();
    let answer = answers.first().unwrap();

    assert_eq!(
        &u8_vec_to_str(answer),
        &solution
    );
}

#[test]
fn challenge_7() {
    let key = "YELLOW SUBMARINE";
    let solution = unsafe_read_file("./fixtures/set_1_challenge_7_solution.txt");
    let cipher_text = unsafe_read_file("./fixtures/set_1_challenge_7.txt");
    let cipher_text = cipher_text.from_base64().unwrap();
    let cr = crypto::Crypter::new(crypto::Type::AES_128_ECB);

    cr.init(
        crypto::Mode::Decrypt,
        &str_to_u8_vec(&key)[..],
        &[]
    );

    let mut p1 = cr.update(&cipher_text[..]);
    p1.extend(cr.finalize().into_iter());

    assert_eq!(
        &u8_vec_to_str(&p1.to_vec()),
        &solution
    );
}
