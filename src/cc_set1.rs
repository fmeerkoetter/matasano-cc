fn to_base64(bin : Vec<u8>) -> String {
    assert!(bin.len() % 3 == 0); // padding not implemented

    let pack24 = | index : uint | {
        bin[index] as uint << 16 | bin[index+1] as uint << 8 | bin[index+2] as uint
    };

    let unpack6 = | c: uint, shift: uint | {
        let mask6bits = 0x3f;
        let conversion_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes();
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
        let b = map_hex(c);
        match b {
            Ok(x)  => if even {
                          accumulator = x << 4;
                      }
                      else {
                          accumulator |= x;
                          bin.push(accumulator);
                          accumulator = 0;
                      },
            Err(e) => return Err(e),
        }
        even = !even;
    }
    Ok(bin)
}

fn set1_exercise1() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    
    let bin = hex2bin(input);
    match bin {
        Ok(bin) => assert!(to_base64(bin).as_slice() == expected_output),
        Err(e) => println!("{}", e),
    }
}

fn main() {
    set1_exercise1();
}
