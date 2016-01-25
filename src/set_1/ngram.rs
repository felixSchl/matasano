extern crate regex;

use std::cmp;
use std::fs::File;
use std::io::{ BufReader };
use std::collections::HashMap;
use std::ascii::{ AsciiExt };
use std::io::prelude::*;
use self::regex::Regex;

#[derive(Debug)]
pub struct Ngram {
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
    pub fn score(&self, input: &str) -> f32 {
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

    pub fn from_file(path: &str) -> Ngram {
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
