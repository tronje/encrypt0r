/// # Block-cipher mode of operation
///
/// A block-cipher such as AES is only effective if used in a certain
/// mode of operation. The supported modes are represented by this enum.
pub enum Mode {

    /// # CBC - Cipher Block Chaining
    ///
    /// Each block of plaintext is XORed with the previous block of ciphertext.
    /// An initialization vector is used.
    CBC,

    /// # CFB - Cipher Feedback
    ///
    /// Turns a block cipher into a self-synchronizing stream cipher. Otherwise
    /// similar to CBC.
    CFB,

    /// # OFB - Output Feedback
    ///
    /// Turns a block cipher into a synchronous stream cipher. Generates
    /// keystream blocks which are XORed with the plaintext to get the ciphertext.
    /// Interestingly, OFB encryption and decryption are identical.
    OFB,

    /// # CTR - Counter
    ///
    /// Also known as Integer Count Mode (ICM) and Segmented Integer Counter (SIC).
    /// Similar to OFB; generates the next keystream by encrypting successive
    /// values of a 'counter'.
    CTR,
}
