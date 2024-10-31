mod password_db;
pub mod password_db_entry;

use chacha20poly1305::{aead::NewAead, XChaCha20Poly1305};
use sha2::{Digest, Sha256};


fn main() -> anyhow::Result<()> {
    //create master_password
    let pwd = "hello world";
    let mut hasher = Sha256::new();
    hasher.update(pwd.as_bytes());
    let hashed = hasher.finalize();
    let key = hashed.as_slice();
    let mut master_password = XChaCha20Poly1305::new(key.into());

    //insert a new password into db using master_password
    let mut password_db =  password_db::PasswordDb::new();
    password_db.insert("test", "test123", &mut master_password)?;

    //attempt to retrieve saved password using right master_password
    let retrieved_pass = password_db.get("test", &mut master_password);
    match retrieved_pass {
        Ok(r) => println!("Password: {r}"),
        Err(e) => println!("Could not retrieve password, for reason: {e}")
    }

    Ok(())
}
