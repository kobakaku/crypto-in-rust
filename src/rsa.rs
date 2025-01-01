//!
//! Reference from
//! - <https://www.geeksforgeeks.org/rsa-algorithm-cryptography/>
//!

pub fn encrypt(input: u128) {
    let p: u128 = 11;
    let q: u128 = 13;
    let n = p * q;
    let l = lcm(p - 1, q - 1);
    let e = 7;
    assert!(gcd(l, e) == 1);

    println!("original message: {}", input);
    println!("public key: {{ {} {} }}", e, n);

    let d = (1..).find(|&d| (e * d) % l == 1).unwrap();

    println!("private key: {{ {} {} }}", d, n);
    let encrypted = modpow(input, e, n);
    println!("encrypted message: {}", encrypted);
    let decrepted = modpow(encrypted, d, n);
    println!("decrepted message: {}", decrepted);
}

fn modpow(a: u128, mut b: u128, m: u128) -> u128 {
    let mut result = 1;
    let mut a = a % m;

    while b > 0 {
        if b & 1 != 0 {
            result = (result * a) % m;
        }
        a = (a * a) % m;
        b >>= 1;
    }

    result
}

// least common multiple
fn lcm(a: u128, b: u128) -> u128 {
    a * b / gcd(a, b)
}

// greater common divisor
fn gcd(a: u128, b: u128) -> u128 {
    if b == 0 {
        return a;
    }
    gcd(b, a % b)
}
