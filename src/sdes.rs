//!
//! Reference from
//! - <https://www.geeksforgeeks.org/simplified-data-encryption-standard-key-generation/>
//! - <https://www.geeksforgeeks.org/simplified-data-encryption-standard-set-2/>
//!

pub fn encrypt(key1: u8, key2: u8, plain_text: u8) -> u8 {
    let ip = initial_permutation(plain_text);
    let fk_first = fk(key1, ip);
    let switch = switch(fk_first, 8);
    let fk_second = fk(key2, switch);
    final_permutation(fk_second)
}

fn switch(input: u8, bit_length: u8) -> u8 {
    input << (bit_length / 2) | input >> (bit_length / 2)
}

fn fk(key: u8, ip: u8) -> u8 {
    let (ip_left, ip_right) = split_8bit(ip);
    let ep = expanded_permutation(ip_right);

    let xor_with_key = key ^ ep;
    let (xor_with_key_left, xor_with_key_right) = split_8bit(xor_with_key);
    let sbox = sbox(xor_with_key_left, xor_with_key_right);
    let p4 = p4_permutation(sbox);
    let xor_with_ip_left = ip_left ^ p4;
    combine_two_key(xor_with_ip_left, ip_right, 4) as u8
}

fn sbox(left: u8, right: u8) -> u8 {
    let sbox0: [[u8; 4]; 4] = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]];
    let sbox1: [[u8; 4]; 4] = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]];

    let s0 = apply_sbox(left, sbox0);
    let s1 = apply_sbox(right, sbox1);

    is_4bit(s0 << 2 | s1)
}

fn apply_sbox(input: u8, sbox: [[u8; 4]; 4]) -> u8 {
    let row = ((input >> 2) & 0b10) | input & 1;
    let column = (input >> 1) & (0b011);
    sbox[row as usize][column as usize]
}

fn is_bit_length<T>(input: T, bit_length: u8) -> T
where
    T: Into<u16> + Copy,
{
    let input_value: u16 = input.into();
    assert!(
        input_value < (1 << bit_length),
        "input is not {}-bit length.",
        bit_length
    );
    input
}

fn is_10bit(input: u16) -> u16 {
    is_bit_length(input, 10)
}

fn is_8bit(input: u8) -> u8 {
    is_bit_length(input, 8)
}

fn is_5bit(input: u8) -> u8 {
    is_bit_length(input, 5)
}

fn is_4bit(input: u8) -> u8 {
    is_bit_length(input, 4)
}

pub fn generate_key(key: u16) -> (u8, u8) {
    let after_p10 = p10_permutation(is_10bit(key));
    let (k1, k2) = split_10bit(after_p10);

    let k1 = is_5bit(left_shift_1bit(k1));
    let k2 = is_5bit(left_shift_1bit(k2));
    let key1 = p8_permutation(is_10bit(combine_two_key(k1, k2, 5)));

    let k1 = left_shift_2bit(k1);
    let k2 = left_shift_2bit(k2);
    let key2 = p8_permutation(is_10bit(combine_two_key(k1, k2, 5)));

    (key1, key2)
}

fn initial_permutation(key: u8) -> u8 {
    let k1 = (key >> 7) & 1;
    let k2 = (key >> 6) & 1;
    let k3 = (key >> 5) & 1;
    let k4 = (key >> 4) & 1;
    let k5 = (key >> 3) & 1;
    let k6 = (key >> 2) & 1;
    let k7 = (key >> 1) & 1;
    let k8 = key & 1;

    is_8bit(k2 << 7 | k6 << 6 | k3 << 5 | k1 << 4 | k4 << 3 | k8 << 2 | k5 << 1 | k7)
}

fn final_permutation(key: u8) -> u8 {
    let k1 = (key >> 7) & 1;
    let k2 = (key >> 6) & 1;
    let k3 = (key >> 5) & 1;
    let k4 = (key >> 4) & 1;
    let k5 = (key >> 3) & 1;
    let k6 = (key >> 2) & 1;
    let k7 = (key >> 1) & 1;
    let k8 = key & 1;

    is_8bit(k4 << 7 | k1 << 6 | k3 << 5 | k5 << 4 | k7 << 3 | k2 << 2 | k8 << 1 | k6)
}

fn expanded_permutation(key: u8) -> u8 {
    let k1 = (key >> 3) & 1;
    let k2 = (key >> 2) & 1;
    let k3 = (key >> 1) & 1;
    let k4 = key & 1;

    is_8bit(k4 << 7 | k1 << 6 | k2 << 5 | k3 << 4 | k2 << 3 | k3 << 2 | k4 << 1 | k1)
}

fn p4_permutation(key: u8) -> u8 {
    let k1 = (key >> 3) & 1;
    let k2 = (key >> 2) & 1;
    let k3 = (key >> 1) & 1;
    let k4 = key & 1;

    is_4bit(k2 << 3 | k4 << 2 | k3 << 1 | k1)
}

fn p8_permutation(key: u16) -> u8 {
    let k3 = (key >> 7) & 1;
    let k4 = (key >> 6) & 1;
    let k5 = (key >> 5) & 1;
    let k6 = (key >> 4) & 1;
    let k7 = (key >> 3) & 1;
    let k8 = (key >> 2) & 1;
    let k9 = (key >> 1) & 1;
    let k10 = key & 1;

    is_8bit((k6 << 7 | k3 << 6 | k7 << 5 | k4 << 4 | k8 << 3 | k5 << 2 | k10 << 1 | k9) as u8)
}

fn p10_permutation(key: u16) -> u16 {
    let k1 = (key >> 9) & 1;
    let k2 = (key >> 8) & 1;
    let k3 = (key >> 7) & 1;
    let k4 = (key >> 6) & 1;
    let k5 = (key >> 5) & 1;
    let k6 = (key >> 4) & 1;
    let k7 = (key >> 3) & 1;
    let k8 = (key >> 2) & 1;
    let k9 = (key >> 1) & 1;
    let k10 = key & 1;

    is_10bit(
        k3 << 9
            | k5 << 8
            | k2 << 7
            | k7 << 6
            | k4 << 5
            | k10 << 4
            | k1 << 3
            | k9 << 2
            | k8 << 1
            | k6,
    )
}

fn split_8bit(key: u8) -> (u8, u8) {
    let left = is_4bit(key >> 4);
    let right = is_4bit(key & 0b1111);
    (left, right)
}

fn split_10bit(key: u16) -> (u8, u8) {
    let left = is_5bit((key >> 5) as u8);
    let right = is_5bit((key & 0b11111) as u8);
    (left, right)
}

fn left_shift_1bit(key: u8) -> u8 {
    (key << 1) & 0b11111 | (key & 0b10000) >> 4
}

fn left_shift_2bit(key: u8) -> u8 {
    (key << 2) & 0b11111 | (key & 0b11000) >> 3
}

fn combine_two_key(key1: u8, key2: u8, key_bit_length: u8) -> u16 {
    (key1 << key_bit_length | key2) as u16
}
