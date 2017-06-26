use super::key::*;
use super::{encrypt, decrypt};

#[test]
fn encrypt_128() {
    let key: [u8; 16] = [0xff; 16];
    let pt: [u8; 16] = [0x00; 16];
    let ct: [u8; 16] = [
        0xa1, 0xf6, 0x25, 0x8c,
        0x87, 0x7d, 0x5f, 0xcd,
        0x89, 0x64, 0x48, 0x45,
        0x38, 0xbf, 0xc9, 0x2c
    ];

    let aes_key = AESKey128::new(key);

    assert_eq!(encrypt(pt, &aes_key), ct);
}

#[test]
fn decrypt_128() {
    let key: [u8; 16] = [0xff; 16];
    let pt: [u8; 16] = [0x00; 16];
    let ct: [u8; 16] = [
        0xa1, 0xf6, 0x25, 0x8c,
        0x87, 0x7d, 0x5f, 0xcd,
        0x89, 0x64, 0x48, 0x45,
        0x38, 0xbf, 0xc9, 0x2c
    ];

    let aes_key = AESKey128::new(key);

    assert_eq!(decrypt(ct, &aes_key), pt);
}

#[test]
fn encrypt_decrypt_128() {
    let key: [u8; 16] = [0xaf; 16];
    let ct1: [u8; 16] = [0xbe; 16];
    let ct2: [u8; 16] = [0xbe; 16];

    let aes_key = AESKey128::new(key);

    assert_eq!(decrypt(encrypt(ct1, &aes_key), &aes_key), ct2);
}


#[test]
fn encrypt_192() {
    let key: [u8; 24] = [0xff; 24];
    let pt: [u8; 16] = [0x00; 16];
    let ct: [u8; 16] = [
        0xdd, 0x8a, 0x49, 0x35,
        0x14, 0x23, 0x1c, 0xbf,
        0x56, 0xec, 0xce, 0xe4,
        0xc4, 0x08, 0x89, 0xfb
    ];

    let aes_key = AESKey192::new(key);

    assert_eq!(encrypt(pt, &aes_key), ct);
}

#[test]
fn decrypt_192() {
    let key: [u8; 24] = [0xff; 24];
    let pt: [u8; 16] = [0x00; 16];
    let ct: [u8; 16] = [
        0xdd, 0x8a, 0x49, 0x35,
        0x14, 0x23, 0x1c, 0xbf,
        0x56, 0xec, 0xce, 0xe4,
        0xc4, 0x08, 0x89, 0xfb
    ];

    let aes_key = AESKey192::new(key);

    assert_eq!(decrypt(ct, &aes_key), pt);
}

#[test]
fn encrypt_decrypt_192() {
    let key: [u8; 24] = [0xda; 24];
    let ct1: [u8; 16] = [0xae; 16];
    let ct2: [u8; 16] = [0xae; 16];

    let aes_key = AESKey192::new(key);

    assert_eq!(decrypt(encrypt(ct1, &aes_key), &aes_key), ct2);
}


#[test]
fn encrypt_256() {
    let key: [u8; 32] = [0xff; 32];
    let pt: [u8; 16] = [0x00; 16];
    let ct: [u8; 16] = [
        0x4b, 0xf8, 0x5f, 0x1b,
        0x5d, 0x54, 0xad, 0xbc,
        0x30, 0x7b, 0x0a, 0x04,
        0x83, 0x89, 0xad, 0xcb
    ];

    let aes_key = AESKey256::new(key);

    assert_eq!(encrypt(pt, &aes_key), ct);
}

#[test]
fn decrypt_256() {
    let key: [u8; 32] = [0xff; 32];
    let pt: [u8; 16] = [0x00; 16];
    let ct: [u8; 16] = [
        0x4b, 0xf8, 0x5f, 0x1b,
        0x5d, 0x54, 0xad, 0xbc,
        0x30, 0x7b, 0x0a, 0x04,
        0x83, 0x89, 0xad, 0xcb
    ];

    let aes_key = AESKey256::new(key);

    assert_eq!(decrypt(ct, &aes_key), pt);
}

#[test]
fn encrypt_decrypt_256() {
    let key: [u8; 32] = [0x1f; 32];
    let ct1: [u8; 16] = [0xa2; 16];
    let ct2: [u8; 16] = [0xa2; 16];

    let aes_key = AESKey256::new(key);

    assert_eq!(decrypt(encrypt(ct1, &aes_key), &aes_key), ct2);
}
