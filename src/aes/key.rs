use super::AESKey;


pub struct AESKey128 {
    key: [u8; 16],
}

impl AESKey128 {
    pub fn new(key: [u8; 16]) -> AESKey128 {
        AESKey128 {
            key: key,
        }
    }
}

impl AESKey for AESKey128 {
    fn borrow(&self) -> &[u8] {
        &self.key
    }
}


pub struct AESKey192 {
    key: [u8; 24],
}

impl AESKey192 {
    pub fn new(key: [u8; 24]) -> AESKey192 {
        AESKey192 {
            key: key,
        }
    }
}

impl AESKey for AESKey192 {
    fn borrow(&self) -> &[u8] {
        &self.key
    }
}


pub struct AESKey256 {
    key: [u8; 32],
}

impl AESKey256 {
    pub fn new(key: [u8; 32]) -> AESKey256 {
        AESKey256 {
            key: key,
        }
    }
}

impl AESKey for AESKey256 {
    fn borrow(&self) -> &[u8] {
        &self.key
    }
}
