pub mod password_db_entry;
pub mod password_db;

use core::str;

use chacha20poly1305::{aead::{Aead, NewAead}, XChaCha20Poly1305};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

fn main() {
    let pwd = "hello world";
    let mut hasher = Sha256::new();
    hasher.update(pwd.as_bytes());
    let hashed = hasher.finalize();
    let key = hashed.as_slice();

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new(key.into());
    let data = "goodbye world";

    let encrypted_data = cipher.encrypt(
        &nonce.into(), 
        data.as_ref()
    ).unwrap();
    println!("{:?}", encrypted_data);

    let decrypted_data = cipher.decrypt(
        &nonce.into(),
        encrypted_data.as_ref()
    ).unwrap();

    let decrypted_data = str::from_utf8(&decrypted_data).unwrap();
    println!("{}", decrypted_data)
}
