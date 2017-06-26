mod key;
mod misc;
mod aes;

#[cfg(test)]
mod test;

pub use self::aes::{encrypt, decrypt};

/// To allow the aes module to only expose one function each for
/// encryption and decryption, rather than one for each key-size, for
/// both encryption and decryption, we declare the `AESKey` trait.
/// Something that implements this trait can be used as the `key` parameter
/// in the `encrypt` and `decrypt` methods.
/// Since the aes module already implements all three possible `AESKey`s,
/// you are advised not to implement your own.
///
/// # Methods
///
/// An `AESKey` has the method `borrow`, which allows borrowing the
/// contained key array as a slice. It also provides the method `size`,
/// which can be used to determine wether it's a 128-, 192- or 256-bit key.
pub trait AESKey {
    fn borrow(&self) -> &[u8];

    fn size(&self) -> usize {
        self.borrow().len()
    }
}
