mod password_db;
pub mod password_db_entry;

use chacha20poly1305::{aead::NewAead, XChaCha20Poly1305};
use password_db::PasswordDb;
use sha2::{Digest, Sha256};


fn main() -> anyhow::Result<()> {
    let mut password_db =  password_db::PasswordDb::new();

    tui_homepage(&mut password_db)?;
    Ok(())
}

fn tui_homepage(password_db: &mut PasswordDb) -> anyhow::Result<()> {
    println!("Please enter the master password: ");
    let mut input_buffer = String::new();
    let stdin = std::io::stdin();
    stdin.read_line(&mut input_buffer)?;
    input_buffer.pop();

    let mut master_pass = conv_string_to_key(&input_buffer);
    input_buffer = String::new();
    
    loop {
        input_buffer.clear();
        println!("What would you like to do?:\n{}\n{}\n{}",
            "1. Retrieve a password",
            "2. Insert a new password",
            "3. Quit"
        );

        match stdin.read_line(&mut input_buffer) {
            Ok(_) => {},
            Err(e) => {
                println!("An Error occured: {e}, please try again");
                continue;
            }
        }
        input_buffer.pop();
        let chosen_option = input_buffer.parse::<usize>();
        let chosen_option = match chosen_option {
            Ok(r) => r,
            Err(e) => {
                println!("An Error occured: {e}, please try again");
                continue;
            }
        };

        match chosen_option {
            1 => {
                tui_retrieve_page(password_db, &mut master_pass)
                    .unwrap_or_else(|e| println!("Failed to retrieve password, error: \n{e}"));
                continue;
            },
            2 => {
                tui_insert_page(password_db, &mut master_pass)
                    .unwrap_or_else(|e| println!("Failed to insert password, error: \n{e}"));
                continue;
            },
            3 => break,
            _ => {
                println!("An Error occured: {}, please try again", "Input outside of bounds");
                continue;
            },
        }
    }
    Ok(())
}

fn tui_retrieve_page(password_db: &PasswordDb, master_pass: &mut XChaCha20Poly1305) -> anyhow::Result<()> {
    println!("Enter the name of the password entry you would like to retrieve:");
    let mut input_buff = String::new();
    let stdin = std::io::stdin();

    stdin.read_line(&mut input_buff)?;
    input_buff.pop();

    let entry = password_db.get(&input_buff, master_pass)?;
    println!("Password retrieved successfully: {entry}");

    Ok(())
}

fn tui_insert_page(password_db: &mut PasswordDb, master_pass: &mut XChaCha20Poly1305) -> anyhow::Result<()> {
    println!("Enter the name of the password entry you would like to insert:");
    let mut input_buff = String::new();
    let stdin = std::io::stdin();

    stdin.read_line(&mut input_buff)?;
    input_buff.pop();
    let key = input_buff.clone();

    println!("Enter the password you would like to insert:");
    let mut input_buff = String::new();
    let stdin = std::io::stdin();

    stdin.read_line(&mut input_buff)?;
    input_buff.pop();
    let password = input_buff.clone();
    input_buff.clear();

    password_db.insert(&key, &password, master_pass)?;
    Ok(())
}

fn conv_string_to_key(input: &String) -> XChaCha20Poly1305 {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hashed = hasher.finalize();
    let key = hashed.as_slice();
    return XChaCha20Poly1305::new(key.into());
}
