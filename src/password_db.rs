use std::collections::HashMap;
use anyhow::anyhow;
use chacha20poly1305::{aead::Aead, XChaCha20Poly1305};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::password_db_entry::PasswordDbEntry;

pub struct PasswordDb {
    db: HashMap<String, PasswordDbEntry>,
    hasher: Sha256
}

impl PasswordDb {
    pub fn new() -> Self {
        PasswordDb {
            db: HashMap::new(),
            hasher: Sha256::new()
        }
    }
    pub fn insert(&mut self, name: &str, password: &str, masterpass: &mut XChaCha20Poly1305) -> anyhow::Result<()>{
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        let encrypted_password = masterpass.encrypt(
            &nonce.into(), 
            password.as_ref()
        );

        let encrypted_password = match encrypted_password {
            Ok(r) => r,
            Err(e) => return Err(anyhow!(e))
        };
        
        let db_entry = PasswordDbEntry::new(encrypted_password, nonce);
        self.db.insert(String::from(name), db_entry);
        
        Ok(())
    }
    pub fn get(&self, name: &str, masterpass: &mut XChaCha20Poly1305) -> anyhow::Result<String> {
        let entry = match self.db.get(name) {
            Some(r) => r,
            None => return Err(anyhow!("This password entry does not exist"))
        };
        let decrypted_password = entry.decrypt_password_using_mastercypher(masterpass).map_err(|_e| anyhow!("Invalid Password"))?;
        return Ok(decrypted_password);
    }
}
