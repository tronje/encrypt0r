use super::AESKey;
use super::misc::{SBOX, INV_SBOX, SHIFTS, INV_SHIFTS};

/* public methods (encrypt and decrypt) */

/// Encrypt a 16-byte block using an `AESKey`, which can contain
/// a key of 16-, 24-, or 32-byte size.
///
/// # Panics
/// `encrypt` panics when `key` doesn't have a valid size.
/// It must have a size of one of 16, 24, or 32 bytes.
pub fn encrypt<T: AESKey>(plaintext: [u8; 16], key: &T) -> [u8; 16] {
    let mut state = plaintext;

    let rounds = match key.size() {
        16 => 11,
        24 => 13,
        32 => 15,
         _ => panic!("Invalid key length!"),
    };

    let key_schedule = expand_key(key);
    let mut round_key = &key_schedule[0..16];

    // round 0: one add_roundkey step
    state = add_roundkey(state, round_key);

    // rounds 1 through (n-1)
    for i in 1..(rounds - 1) {
        state = sub_bytes(state);
        state = shift_rows(state);
        state = mix_columns(state);

        round_key = &key_schedule[(i * 16)..((i + 1) * 16)];

        state = add_roundkey(state, round_key);
    }

    // round key for final round
    round_key = &key_schedule[(16 * (rounds - 1))..(16 * rounds)];

    // final round
    state = sub_bytes(state);
    state = shift_rows(state);
    state = add_roundkey(state, round_key);

    state
}

/// Decrypt a 16-byte block using an `AESKey`, which can contain
/// a key of 16-, 24-, or 32-byte size.
///
/// # Panics
/// `decrypt` panics when `key` doesn't have a valid size.
/// It must have a size of one of 16, 24, or 32 bytes.
pub fn decrypt<T: AESKey>(ciphertext: [u8; 16], key: &T) -> [u8; 16] {
    let mut state = ciphertext;

    let rounds = match key.size() {
        16 => 11,
        24 => 13,
        32 => 15,
         _ => panic!("Invalid key length!"),
    };

    let key_schedule = expand_key(key);
    let mut round_key = &key_schedule[(16 * (rounds - 1))..(16 * rounds)];

    // round 0: one add_roundkey step
    state = add_roundkey(state, round_key);

    // rounds 1 through (n-1)
    for i in 1..(rounds - 1) {
        state = inv_shift_rows(state);
        state = inv_sub_bytes(state);

        round_key = &key_schedule[(16 * (rounds - (i+1)))..(16 * (rounds - i))];

        state = add_roundkey(state, round_key);
        state = inv_mix_columns(state);
    }

    // round key for final round
    round_key = &key_schedule[0..16];

    // final round
    state = inv_shift_rows(state);
    state = inv_sub_bytes(state);
    state = add_roundkey(state, round_key);

    state
}

/* State manipulation functions */

/// Add the round key to the state. There's not inverse function
/// for this one, because it's its own inverse.
fn add_roundkey(state: [u8; 16], rkey: &[u8]) -> [u8; 16] {
    let mut result = [0u8; 16];

    for i in 0..16 {
        result[i] = state[i] ^ rkey[i];
    }

    result
}

/// Substitute the state's bytes using Rijndael's substitution box.
fn sub_bytes(state: [u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];

    for i in 0..16 {
        result[i] = SBOX[state[i] as usize];
    }

    result
}

/// Inverse of `sub_bytes`, using Rijndael's inverse substitution box.
fn inv_sub_bytes(state: [u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];

    for i in 0..16 {
        result[i] = INV_SBOX[state[i] as usize];
    }

    result
}

/// Shift the rows of the state around (see the SHIFTS array).
fn shift_rows(state: [u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];

    for i in 0..16 {
        result[i] = state[SHIFTS[i] as usize];
    }

    result
}

/// Inverse of `shift_rows`, performing shifts of the rows in the state
/// in order to reverse any shifts done in `shift_rows`.
fn inv_shift_rows(state: [u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];

    for i in 0..16 {
        result[i] = state[INV_SHIFTS[i] as usize];
    }

    result
}

/// Each column is treated as a four-term polynomial in Rijndael's
/// Galois field. Each polynomial is multiplied with another, fixed
/// polynomial.
/// This method is slightly optimized, and thus the operation described
/// above might not be immediately recognizable.
fn mix_columns(state: [u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let mut a = [0u8; 4];
    let mut b = [0u8; 4];
    let mut h: u8 = 0;

    for i in 0..4 {
        for j in 0..4 {
            a[j] = state[j + 4 * i];
            b[j] = state[j + 4 * i] << 1;
            h = state[j + 4 * i] & 0x80;

            if h == 0x80 {
                b[j] ^= 0x1b;
            }
        }

        result[4 * i]     = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
        result[1 + 4 * i] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
        result[2 + 4 * i] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
        result[3 + 4 * i] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    }

    result
}

/// Multiplication in Rijndael's Galois field.
fn gmul(mul_a: u8, mul_b: u8) -> u8 {
    let mut a = mul_a;
    let mut b = mul_b;
    let mut product = 0u8;
    let mut hi_bit_set = 0;

    for _ in 0..8 {
        if (b & 1) == 1 {
            product ^= a;
        }

        hi_bit_set = a & 0x80;
        a <<= 1;

        if hi_bit_set == 0x80 {
            a ^= 0x1b;
        }

        b >>= 1;
    }

    product
}

/// Inverse of `mix_columns`, multiplying each column with
/// the inverse of the fixed polynomial used in `mix_columns`.
/// This is more easily recognizable in this method, as there are no
/// simple replacement-optimizations, so we have to use
/// the helper function `gmul`.
fn inv_mix_columns(state: [u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let mut a = [0u8; 4];

    for i in 0..4 {
        for j in 0..4 {
            a[j] = state[j + 4 * i];
        }

        result[4 * i] =
              gmul(a[0], 14)
            ^ gmul(a[3],  9)
            ^ gmul(a[2], 13)
            ^ gmul(a[1], 11);

        result[1 + 4 * i] =
              gmul(a[1], 14)
            ^ gmul(a[0],  9)
            ^ gmul(a[3], 13)
            ^ gmul(a[2], 11);

        result[2 + 4 * i] =
              gmul(a[2], 14)
            ^ gmul(a[1],  9)
            ^ gmul(a[0], 13)
            ^ gmul(a[3], 11);

        result[3 + 4 * i] =
              gmul(a[3], 14)
            ^ gmul(a[2],  9)
            ^ gmul(a[1], 13)
            ^ gmul(a[0], 11);
    }

    result
}


/* Key schedule functions */

/// Compute the round constant
fn rcon(i: u8) -> u8 {
    let mut round_constant: u8 = 1;
    let mut counter = i;

    if i == 0 {
        return 0;
    }

    while counter != 1 {
        let b = round_constant & 0x80;
        round_constant <<= 1;

        if b == 0x80 {
            round_constant ^= 0x1b;
        }

        counter -= 1;
    }

    round_constant
}

/// The so-called 'core' operation of the key schedule.
/// We rotate four key-bytes, apply Rijndael's substitution box,
/// and add the round constant to the first byte.
fn schedule_core(arr: [u8; 4], n: u8) -> [u8; 4] {
    let mut result = [0u8; 4];

    result[0] = arr[1];
    result[1] = arr[2];
    result[2] = arr[3];
    result[3] = arr[0];

    for i in 0..4 {
        result[i] = SBOX[result[i] as usize];
    }

    result[0] ^= rcon(n);

    result
}

/// Expand 16, 24, or 32 bytes of key into 176, 208, or 240 bytes
/// of key schedule, respectively.
fn expand_key<T: AESKey>(key: &T) -> Vec<u8> {
    let schedule_size = match key.size() {
        16 => 176,
        24 => 208,
        32 => 240,
         _ => panic!("Invalid keysize!"),
    };

    let mut schedule = Vec::with_capacity(schedule_size);

    // populate the schedule; the first {16, 24, 32} bytes are simply the key
    for elem in key.borrow() {
        schedule.push(elem.clone());
    }

    let mut t = [0u8; 4];
    let mut n = 1;

    // repeat the following until we have 176, 208, or 240 bytes
    // of key schedule, respectively
    while schedule.len() < schedule_size {
        // grab 4 bytes from the schedule so far
        for i in 0..4 {
            t[i] = schedule[i + schedule.len() - 4];
        }

        // every so often, perform a 'special' mutation, the schedule core
        if (schedule.len() % key.size()) == 0 {
            t = schedule_core(t, n);
            n += 1;
        }

        // AES256's key schedule contains an extra SBOX-application
        if key.size() * 8 == 256 {
            if schedule.len() % key.size() == 16 {
                for i in 0..4 {
                    t[i] = SBOX[t[i] as usize];
                }
            }
        }

        // xor the last four bytes with the t array and push into the schedule
        for i in 0..4 {
            let to_push = schedule[schedule.len() - key.size()] ^ t[i];
            schedule.push(to_push);
        }
    }

    schedule
}
