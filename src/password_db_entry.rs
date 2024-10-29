use core::str;

use anyhow::anyhow;
use chacha20poly1305::{aead::AeadMut, XChaCha20Poly1305};

pub struct PasswordDbEntry {
    encrypted_password: Vec<u8>,
    nonce: [u8; 24],
}

impl PasswordDbEntry  {
    pub fn new(encrypted_password: Vec<u8>, nonce: [u8; 24]) -> Self {
        PasswordDbEntry {
            encrypted_password,
            nonce
        }
    }

    pub fn decrypt_password_using_mastercypher(&self, masterpass: &mut XChaCha20Poly1305) -> anyhow::Result<String> {
        let decrypted = masterpass.decrypt(&self.nonce.into(), self.encrypted_password.as_ref());
        let decrypted = match decrypted {
            Ok(r) => r,
            Err(e) => return Err(anyhow!(e))
        }; 
        let decrypted_data = str::from_utf8(&decrypted)?;
        Ok(decrypted_data.to_string())
    }
}
