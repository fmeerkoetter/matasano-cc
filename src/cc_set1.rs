fn to_base64(bin : Vec<u8>) -> String {
    assert!(bin.len() % 3 == 0); // padding not implemented

    let pack24 = | index : uint | {
        bin[index] as uint << 16 | bin[index+1] as uint << 8 | bin[index+2] as uint
    };

    let unpack6 = | c: uint, shift: uint | {
        let mask6bits = 0x3f;
        let conversion_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs\
                                tuvwxyz0123456789+/".as_bytes();
        conversion_table[((c >> shift) & mask6bits)] as char
    };

    let mut index = 0;
    let mut encoded = "".to_string();
    while index < bin.len() {
        let p = pack24(index);
        encoded.push(unpack6(p, 18));
        encoded.push(unpack6(p, 12));
        encoded.push(unpack6(p,  6));
        encoded.push(unpack6(p,  0));
        index += 3;
    }
    encoded
}

fn hex2bin(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!("Invalid input length: {}", hex.len()));
    }

    let mut bin: Vec<u8> = Vec::with_capacity(hex.len()/2);
    let map_hex = | c | {
        match c {
            b'0'...b'9' => Ok(c - b'0'),
            b'a'...b'f' => Ok(c - b'a' + 10),
            b'A'...b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("Invalid input: '{}'", c)),
        }
    };
 
    let mut accumulator : u8 = 0;
    let mut even = true;
    for c in hex.bytes() {
        let b = try!(map_hex(c));
        if even {
            accumulator = b << 4;
        }
        else {
            accumulator |= b;
            bin.push(accumulator);
            accumulator = 0;
        }
        even = !even;
    }
    Ok(bin)
}

fn set1_exercise1() -> Result<(), String> {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120\
                 706f69736f6e6f7573206d757368726f6f6d";
    let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3\
                           VzIG11c2hyb29t";

    let bin = try!(hex2bin(input));
    assert_eq!(to_base64(bin).as_slice(), expected_output);
    Ok(())
}

fn xor(lhs : Vec<u8>, rhs : Vec<u8>) -> Vec<u8> {
    assert_eq!(lhs.len(), rhs.len()); 
    let mut it = lhs.iter().zip(rhs.iter());
    let mut result = Vec::with_capacity(lhs.len());
    for p in it {
        let (l, r) = p;
        result.push(*l ^ *r);
    }
    result
}

fn bin2hex(bin: Vec<u8>) -> String {
    let mut result = String::with_capacity(bin.len() * 2);
    for b in bin.iter() {
        let hex = format!("{:x}", *b);
        result.push(hex.as_bytes()[0] as char);
        result.push(hex.as_bytes()[1] as char);
    }
    result
}

fn set1_exercise2() -> Result<(), String> {
    let lhs = try!(hex2bin("1c0111001f010100061a024b53535009181c"));
    let rhs = try!(hex2bin("686974207468652062756c6c277320657965"));

    assert_eq!(bin2hex(xor(lhs, rhs)).as_slice(), "746865206b696420646f6e277420706c6179");
    Ok(())
}

fn get_letter_freq_table_en() -> [uint, ..256] {
    let mut freq_table = [0u, ..256];
    // the chars in 'letters' are sorted by their relative frequency
    // in english text
    let letters = "etaoinshrdlcumwfgypbvkjxqz".as_bytes();
    let mut score = letters.len();
    for x in letters.iter() {
        freq_table[*x as uint] = score;
        //freq_table[std::char::to_uppercase(*x as char) as uint] = score;
        score -= 1;
    }
    freq_table
}

fn brute_force_single_byte_xor(cipher_text: Vec<u8>) -> (uint, Vec<u8>, u8) {
    let freq_table = get_letter_freq_table_en();
    // tuple contains 'score, potential cleartext, key'
    let mut candidates : Vec<(uint, Vec<u8>, u8)> = Vec::with_capacity(255);
    for candidate_key in range(0u8, 255) {
        let mut tmp : Vec<u8> = Vec::with_capacity(cipher_text.len());
        let mut score = 0u;
        for c in cipher_text.iter() {
            let d = *c ^ candidate_key;
            score += freq_table[d as uint];
            tmp.push(d);
        }
        candidates.push((score, tmp, candidate_key));
    }
    candidates.sort_by(| a, b | a.ref0().cmp(b.ref0()));
    candidates.pop().unwrap()
}

fn set1_exercise3() -> Result<(), String> {
    let cipher_text = try!(hex2bin("1b37373331363f78151b7f2b783431333d783978\
                           28372d363c78373e783a393b3736"));
    let result = brute_force_single_byte_xor(cipher_text);

    match std::str::from_utf8(result.ref1().as_slice()) {
        Some(c) => println!("Key: {}, Cleartext: {}", result.ref2(), c),
        None => return Err(String::from_str("from_utf8() failed")),
    }
    Ok(())
}

fn set1_exercise4() -> Result<(), String> {
    use std::io::BufferedReader;
    use std::io::File;

    let path = Path::new("4.txt");
    let mut file = BufferedReader::new(File::open(&path));
    let mut candidates : Vec<(uint, Vec<u8>, u8)> = Vec::new();
    for line in file.lines() {
        let cipher_text = try!(hex2bin(line.unwrap().as_slice().trim_right_chars('\n')));
        candidates.push(brute_force_single_byte_xor(cipher_text));
    }
    candidates.sort_by(| a, b | a.ref0().cmp(b.ref0()));
    let result = candidates.pop().unwrap();
    match std::str::from_utf8(result.ref1().as_slice()) {
        Some(c) => println!("Key: {}, Cleartext: {}", result.ref2(), c),
        None => return Err(String::from_str("from_utf8() failed")),
    }
    Ok(())
}

fn main() {
    match set1_exercise1() {
        Ok(_)  => (),
        Err(e) => println!("{}", e),
    }

    match set1_exercise2() {
        Ok(_)  => (),
        Err(e) => println!("{}", e),
    }

    match set1_exercise3() {
        Ok(_)  => (),
        Err(e) => println!("{}", e),
    }
    
    match set1_exercise4() {
        Ok(_)  => (),
        Err(e) => println!("{}", e),
    }
}
