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
use uuid::Uuid;

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

    let source_file_path = Path::new(&source_path);

    if !source_file_path.try_exists()? {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }

    let file_name = source_file_path.file_name().unwrap_or_default();

    let uuid = Uuid::new_v4();
    let path = dest_path + "/" + &uuid.to_string() + ".cha";

    if Path::new(&path).try_exists()? {
        fs::remove_file(&path)?;
    }

    let mut source_file = File::open(&source_path)?;
    let mut dest_file = File::create(path)?;

    // Stack allocated buffer
    // let mut buffer = [0u8; BUFFER_LEN];

    // Heap allocated buffer (Allows larger sized buffer, up to 50 % max ram)
    let mut buffer = vec![0u8; BUFFER_LEN].into_boxed_slice();

    dest_file.write(nonce)?;

    let mut f_name_bytes = file_name.to_str().unwrap_or_default().as_bytes().to_owned();

    cipher.apply_keystream(&mut f_name_bytes);

    if f_name_bytes.len() > u16::MAX.into() {
        // TODO: Return a better Error, this doesnt make any sense at all
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }

    let size: u16 = f_name_bytes.len() as u16;

    let f_name_len: [u8; 2] = size.to_le_bytes();
    dest_file.write(&f_name_len)?;
    dest_file.write(&f_name_bytes)?;

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

    fs::remove_file(source_file_path)?;

    return Ok(());
}

fn decrypt_file(source_path: String, pwd: &String, config: &argon2::Config) -> io::Result<()> {
    let mut nonce = [0u8; 24];

    let path_info = Path::new(&source_path);

    if !path_info.try_exists()? {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }

    //let path = &source_path[..&source_path.len() - 4];

    // if Path::new(&path).exists() {
    //     fs::remove_file(&path)?;
    // }

    let mut source_file = File::open(&source_path)?;

    source_file.read(&mut nonce)?;

    let key = argon2::hash_raw(pwd.as_bytes(), &nonce, &config).unwrap();

    let mut cipher = XChaCha20::new(key[..32].as_ref().into(), &nonce.into());

    // Stack allocated buffer
    // let mut buffer = [0u8; BUFFER_LEN];

    let mut file_name_size_buffer: [u8; 2] = [0u8, 2];
    source_file.read(&mut file_name_size_buffer)?;
    let file_name_size = u16::from_le_bytes(file_name_size_buffer);

    println!("File Name Size: {file_name_size}");

    let mut file_name_bytes = vec![0u8; file_name_size.into()];
    source_file.read_exact(&mut file_name_bytes)?;

    cipher.apply_keystream(&mut file_name_bytes);

    let private_dir_path = match path_info.parent() {
        Some(p) => Ok(p),
        None => Err(io::Error::from(io::ErrorKind::AddrNotAvailable)),
    }?;

    let root_dir_path = match private_dir_path.parent() {
        Some(p) => Ok(p),
        None => Err(io::Error::from(io::ErrorKind::AddrNotAvailable)),
    }?;

    let file_name = String::from_utf8(file_name_bytes).unwrap_or_default();
    let path = root_dir_path.join(&file_name); //to_str().unwrap_or_default().to_owned() + &file_name;

    println!("File Name: {file_name}\n Path: {path:?}");

    let mut dest_file = File::create(path)?;

    println!("Worked!");

    // Heap allocated buffer (Allows larger sized buffer, up to 50 % max ram)
    let mut buffer = vec![0u8; BUFFER_LEN].into_boxed_slice();

    loop {
        let read_count = source_file.read(&mut buffer)?;

        println!("Read Bytes {read_count}");

        if read_count == BUFFER_LEN {
            cipher.apply_keystream(&mut buffer);
            dest_file.write(&buffer)?;
        } else {
            cipher.apply_keystream(&mut buffer[..read_count]);
            dest_file.write(&buffer[..read_count])?;
            break;
        }
    }

    println!("Fully written");
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

        fs::remove_dir(private)?;

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

    Ok(())
}
