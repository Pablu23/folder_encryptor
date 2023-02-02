use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::XChaCha20;
use rand::RngCore;
use rand_core::OsRng;
use std::path::Path;
use std::{
    env,
    fs,
    fs::File,
    io,
    io::{Read, Write},
    // time::SystemTime,
};

extern crate rpassword;

use rpassword::read_password;

const BUFFER_LEN: usize = 50 * 1024 * 1024; // 50 MiB

fn encrypt_file(
    source_path: String,
    dest_path: String,
    nonce: &[u8; 24],
    key: &Vec<u8>,
) -> io::Result<()> {
    let mut cipher = XChaCha20::new(key[..32].as_ref().into(), nonce.into());

    let source_file = Path::new(&source_path);

    if !source_file.try_exists()? {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }

    let file_name = source_file.file_name().unwrap_or_default();
    let path = dest_path + "/" + file_name.to_str().unwrap_or_default() + ".cha";

    if Path::new(&path).try_exists()? {
        fs::remove_file(&path)?;
    }

    let mut source_file = File::open(source_path)?;
    let mut dest_file = File::create(path)?;

    // Stack allocated buffer
    // let mut buffer = [0u8; BUFFER_LEN];

    // Heap allocated buffer (Allows larger sized buffer, up to 50 % max ram)
    let mut buffer = vec![0u8; BUFFER_LEN].into_boxed_slice();

    dest_file.write(nonce)?;

    loop {
        let read_count = source_file.read(&mut buffer).unwrap();

        if read_count == BUFFER_LEN {
            cipher.apply_keystream(&mut buffer);
            dest_file.write(&buffer).unwrap();
        } else {
            cipher.apply_keystream(&mut buffer[..read_count]);
            dest_file.write(&buffer[..read_count]).unwrap();
            break;
        }
    }

    return Ok(());
}

fn decrypt_file(source_path: String, pwd: &String, config: &argon2::Config) -> io::Result<()> {
    let mut nonce = [0u8; 24];

    let path_info = Path::new(&source_path);

    if !path_info.try_exists()? {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }

    let path = &source_path[..&source_path.len() - 4];

    if Path::new(&path).exists() {
        fs::remove_file(&path)?;
    }

    let mut source_file = File::open(&source_path)?;
    let mut dest_file = File::create(path)?;

    source_file.read(&mut nonce)?;

    let key = argon2::hash_raw(pwd.as_bytes(), &nonce, &config).unwrap();

    let mut cipher = XChaCha20::new(key[..32].as_ref().into(), &nonce.into());

    // Stack allocated buffer
    // let mut buffer = [0u8; BUFFER_LEN];

    // Heap allocated buffer (Allows larger sized buffer, up to 50 % max ram)
    let mut buffer = vec![0u8; BUFFER_LEN].into_boxed_slice();

    loop {
        let read_count = source_file.read(&mut buffer).unwrap();

        if read_count == BUFFER_LEN {
            cipher.apply_keystream(&mut buffer);
            dest_file.write(&buffer).unwrap();
        } else {
            cipher.apply_keystream(&mut buffer[..read_count]);
            dest_file.write(&buffer[..read_count]).unwrap();
            break;
        }
    }

    return Ok(());
}

fn main() -> io::Result<()> {
    let config = argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    };

    let exe = env::current_exe().unwrap();
    let cwd = env::current_dir().unwrap();
    let private = cwd.join("private");

    if private.exists() {
        let paths = fs::read_dir(&private).unwrap();

        print!("Type password for encrypted files: ");
        std::io::stdout().flush().unwrap();
        let pwd = read_password().unwrap();

        for path_result in paths {
            let path = path_result.unwrap().path();

            if path.is_file() {
                decrypt_file(String::from(path.to_str().unwrap()), &pwd, &config)?;
                fs::remove_file(String::from(path.to_str().unwrap()))?;
            }
        }

        //fs::remove_dir_all(private).unwrap();
    } else {
        let paths = fs::read_dir(&cwd).unwrap();

        for path_result in paths {
            let path = path_result.unwrap().path();

            if path.is_file() && path != exe {
                println!("{path:?}");
            }
        }

        println!("Encrypt files? [y]es / [n]o");

        let input: u8 = std::io::stdin().bytes().next().unwrap().unwrap();

        match input {
            b'n' => return Ok(()),
            b'y' => (),
            _ => panic!("Input was not correct!"),
        }

        fs::create_dir(&private).unwrap();

        print!("Type password to encrypt files: ");
        std::io::stdout().flush().unwrap();
        let pwd = read_password().unwrap();

        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        let key = argon2::hash_raw(pwd.as_bytes(), &nonce, &config).unwrap();

        let paths = fs::read_dir(cwd).unwrap();

        for path_result in paths {
            let path = path_result.unwrap().path();

            if path.is_file() && path != exe {
                encrypt_file(
                    String::from(path.to_str().unwrap()),
                    String::from(private.to_str().unwrap()),
                    &nonce,
                    &key,
                )
                .unwrap();
            }
        }
    }

    // let start = SystemTime::now();

    // let source_path = String::from("E:\\Programieren\\Rust\\folder_encryptor\\1gb.test.bin.cha");
    // // let plaintext: String = String::from("Das ist ein Test string");
    // let pwd: String = String::from("TestPassword!");

    // // let mut nonce = [0u8; 24];
    // // OsRng.fill_bytes(&mut nonce);

    // // let key = argon2::hash_raw(pwd.as_bytes(), &nonce, &config).unwrap();

    // decrypt_file(source_path, &pwd, &config)?;

    // let encrypt_time = start.elapsed().unwrap();

    // println!("Encrypt took {encrypt_time:?}");

    Ok(())

    // let start = SystemTime::now();

    // Decrypt Part
    //dist_file.seek(SeekFrom::Start(0)).unwrap();
    // drop(dist_file);

    // cipher.seek(0u32);

    // let mut dist_file = File::open(dist_path).unwrap();
    // let decrypted_path = source_path.clone() + ".decrypted.bin";
    // let mut decrypted_file = File::create(decrypted_path).unwrap();

    // let mut read_nonce = [0u8; 24];

    // let nonce_size = dist_file.read(&mut read_nonce).unwrap();

    // assert_eq!(24, nonce_size);
    // assert_eq!(read_nonce, nonce);

    // let t = dist_file.stream_position().unwrap();

    // println!("{t}");

    // let mut decrypt_buffer = [0u8; BUFFER_LEN];

    // loop {
    //     let read_count = dist_file.read(&mut decrypt_buffer).unwrap();

    //     println!("Decrypt Read: {read_count}");

    //     if read_count == BUFFER_LEN {
    //         cipher.apply_keystream(&mut decrypt_buffer);
    //         decrypted_file.write(&decrypt_buffer).unwrap();
    //     } else {
    //         cipher.apply_keystream(&mut decrypt_buffer[..read_count]);
    //         decrypted_file.write(&decrypt_buffer[..read_count]).unwrap();
    //         break;
    //     }
    // }

    // let decrypt_time = start.elapsed().unwrap();

    // println!("Encrypt took {encrypt_time:?}");
    // println!("Decrypt took {decrypt_time:?}");
}
