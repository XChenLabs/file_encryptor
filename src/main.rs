use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes128Gcm, Key, Nonce,
};
use argon2::{Argon2, RECOMMENDED_SALT_LEN};
use rand::prelude::*;
use rpassword;
use std::env;
use std::fs;
use std::io::prelude::*;

const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 || (args[1] != "enc" && args[1] != "dec") {
        println!("usage: file_encryptor enc/dec input_file output_file");
        return Ok(());
    }
    let mut enc = true;
    if args[1] == "dec" {
        enc = false;
    }
    let in_fname = &args[2];
    let out_fname = &args[3];

    //0. check input file's existance and size; check output file does not exist
    let filemeta = fs::metadata(in_fname)?;
    if filemeta.len() > MAX_FILE_SIZE {
        println!("error: input file size exceeds {MAX_FILE_SIZE}");
        return Ok(());
    }
    if fs::metadata(out_fname).is_ok() {
        println!("error: output file already exists");
        return Ok(());
    }

    //1. read password from cmd
    let password = rpassword::prompt_password("Your password: ").unwrap();

    if enc {
        //2. generate master key from password using argon2id
        let mut salt = [0u8; RECOMMENDED_SALT_LEN];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut salt);
        let mut master_key = [0u8; 16];
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut master_key)
            .expect("argon2 error");

        //3. generate cryptographic random data key
        let data_key = Aes128Gcm::generate_key(OsRng);

        //4. encrypt data key with master key using aes-gcm
        let mkey = Key::<Aes128Gcm>::from_slice(&master_key);
        let dk_cipher = Aes128Gcm::new(&mkey);
        let dk_nonce = Aes128Gcm::generate_nonce(&mut OsRng);
        let enc_data_key = dk_cipher
            .encrypt(&dk_nonce, data_key.as_slice())
            .expect("error: encryption of data key fails");

        //5. output argon2id parameters (salt, time/memory/parallel)
        let mut out_file = fs::File::create(out_fname)?;
        out_file.write_all(&salt)?;

        //6. output encrypted data key (nonce, ciphertext)
        out_file.write_all(&dk_nonce)?;
        out_file.write_all(&enc_data_key)?;

        //7. output encrypted file data (nonce, ciphertext)
        let cipher = Aes128Gcm::new(&data_key);
        let nonce = Aes128Gcm::generate_nonce(&mut OsRng);
        out_file.write_all(&nonce)?;
        let plaintext = fs::read(in_fname)?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_slice())
            .expect("error: encryption of file fails");
        out_file.write_all(&ciphertext)?;
    } else {
        //2. read salt; generate master key from password using argon2id
        let mut in_file = fs::File::open(in_fname)?;
        let mut salt = [0u8; RECOMMENDED_SALT_LEN];
        in_file.read_exact(&mut salt)?;
        let mut master_key = [0u8; 16];
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut master_key)
            .expect("argon2 error");

        //3. read nonce, encrypted_data_key; decrypt data key using master key
        let mkey = Key::<Aes128Gcm>::from_slice(&master_key);
        let dk_cipher = Aes128Gcm::new(&mkey);
        let mut dk_nonce = [0u8; 12];
        in_file.read_exact(&mut dk_nonce)?;
        let dk_nonce = Nonce::from_slice(&dk_nonce);
        let mut enc_data_key = [0u8; 32];
        in_file.read_exact(&mut enc_data_key)?;
        let data_key = dk_cipher
            .decrypt(&dk_nonce, enc_data_key.as_ref())
            .expect("error: incorrect password or file is corrupted/modified");

        //4. read nonce, ciphertext; decrypt ciphertext using data key
        let data_key = Key::<Aes128Gcm>::from_slice(&data_key);
        let cipher = Aes128Gcm::new(&data_key);
        let mut nonce = [0u8; 12];
        in_file.read_exact(&mut nonce)?;
        let nonce = Nonce::from_slice(&nonce);
        let mut ciphertext = vec![];
        in_file.read_to_end(&mut ciphertext)?;
        let plaintext = cipher
            .decrypt(&nonce, ciphertext.as_ref())
            .expect("error: file is corrupted or modified");
        let mut out_file = fs::File::create(out_fname)?;
        out_file.write_all(&plaintext)?;
    }

    println!("Done!");
    Ok(())
}
