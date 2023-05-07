use anyhow::{bail, Result};
use argon2::Config;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::XChaCha20;
use rand::RngCore;
use rand_core::OsRng;
use std::fs::ReadDir;
use std::path::{Path, PathBuf};
use std::{
    env,
    fs,
    fs::File,
    io,
    io::{Read, Write},
    sync::Arc, // time::SystemTime,
    thread,
    thread::{available_parallelism, JoinHandle},
};
use uuid::Uuid;

extern crate rpassword;

use rpassword::read_password;

const BUFFER_LEN: usize = 50 * 1024 * 1024; // 50 MiB

pub fn encrypt_file(
    source_path: String,
    root_path: &String,
    pwd: &String,
    config: &Config,
) -> Result<()> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let key = argon2::hash_raw(pwd.as_bytes(), &nonce, &config)?;
    let mut cipher = XChaCha20::new(key[..32].as_ref().into(), &nonce.into());

    let uuid = Uuid::new_v4();
    let dest_path = root_path.to_owned() + "/private/" + &uuid.to_string() + ".cha";

    let origin_path = Path::new(&source_path).strip_prefix(root_path)?;

    let mut source_file = File::open(&source_path)?;
    let mut dest_file = File::create(dest_path)?;

    let mut buffer = vec![0u8; BUFFER_LEN].into_boxed_slice();

    println!("Now encrypting {source_path}");

    dest_file.write(&nonce)?;
    let mut origin_path_bytes = origin_path
        .to_str()
        .expect("Origin Path can convert to string")
        .as_bytes()
        .to_owned();
    cipher.apply_keystream(&mut origin_path_bytes);

    if origin_path_bytes.len() > u32::MAX.try_into()? {
        bail!("Origin String too long");
    }

    let size: u32 = origin_path_bytes.len() as u32;
    let size_bytes: [u8; 4] = size.to_le_bytes();
    dest_file.write(&size_bytes)?;
    dest_file.write(&origin_path_bytes)?;

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

    println!("Finished encrypthing {source_path}");

    fs::remove_file(source_path)?;

    Ok(())
}

pub fn decrypt_file(source_path: &Path, pwd: &String, config: &Config) -> Result<()> {
    let mut nonce = [0u8; 24];
    if !source_path.try_exists()? {
        bail!("File not found");
    }

    println!("Start decrypting File {source_path:?}");

    let mut source_file = File::open(&source_path)?;

    source_file.read(&mut nonce)?;

    let key = argon2::hash_raw(pwd.as_bytes(), &nonce, &config)?;

    let mut cipher = XChaCha20::new(key[..32].as_ref().into(), &nonce.into());
    let mut file_name_size_buffer: [u8; 4] = [0u8; 4];
    source_file.read(&mut file_name_size_buffer)?;

    let file_name_size = u32::from_le_bytes(file_name_size_buffer);
    let mut file_name_buffer = vec![0u8; file_name_size.try_into()?];
    source_file.read(&mut file_name_buffer)?;

    cipher.apply_keystream(&mut file_name_buffer);

    let private_dir_path = match source_path.parent() {
        Some(p) => Ok::<&Path, anyhow::Error>(p),
        None => bail!("Private dir could not be extracted"),
    }?;

    let root_dir_path = match private_dir_path.parent() {
        Some(p) => Ok::<&Path, anyhow::Error>(p),
        None => bail!("Root dir could not be extracted"),
    }?;

    let file_name = String::from_utf8(file_name_buffer)?;
    let path = root_dir_path.join(&file_name);

    let prefix = path.parent().expect("No parent Directory");
    std::fs::create_dir_all(prefix)?;

    let mut dest_file = File::create(path)?;

    let mut buffer = vec![0u8; BUFFER_LEN].into_boxed_slice();

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            cipher.apply_keystream(&mut buffer);
            dest_file.write(&buffer)?;
        } else {
            cipher.apply_keystream(&mut buffer[..read_count]);
            dest_file.write(&buffer[..read_count])?;
            break;
        }
    }

    println!("Finished decrpyting File {file_name}");

    Ok(())
}

fn populate_file_list(
    root_dir: fs::ReadDir,
    file_list: &mut Vec<PathBuf>,
    dir_list: &mut Vec<PathBuf>,
) -> io::Result<()> {
    for path in root_dir {
        let path = path.unwrap().path();
        if path.is_file() {
            file_list.push(path);
        } else if path.is_dir() {
            let dir = fs::read_dir(&path).unwrap();
            dir_list.push(path);
            populate_file_list(dir, file_list, dir_list)?;
        }
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let config = Arc::new(argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    });

    let exe = env::current_exe().unwrap();
    let cwd = env::current_dir().unwrap();
    let private = cwd.join("private");

    let mut max_threads: usize = available_parallelism().unwrap().into();

    let percent = max_threads as f32 * 0.7;
    max_threads = percent.floor() as usize;

    if max_threads < 1 {
        max_threads = 1;
    }

    println!("Parallelism: {max_threads}");

    if private.exists() {
        let paths = fs::read_dir(&private).unwrap();

        print!("Type password for encrypted files: ");
        std::io::stdout().flush().unwrap();
        let pwd = Arc::new(read_password().unwrap());

        let config = Arc::new(config);

        let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(max_threads);

        let mut current_threads = 0;

        for path_result in paths {
            let path = path_result.unwrap().path();
            let pwd = pwd.clone();
            let config = config.clone();

            handles.push(thread::spawn(move || {
                if path.is_file() {
                    decrypt_file(path.as_path(), &pwd, &config).unwrap();
                    fs::remove_file(String::from(path.to_str().unwrap())).unwrap();
                }
            }));
            current_threads += 1;

            if current_threads >= max_threads {
                while let Some(handle) = handles.pop() {
                    handle.join().unwrap();
                    current_threads -= 1;
                }
            }
        }

        if current_threads > 0 {
            while let Some(handle) = handles.pop() {
                handle.join().unwrap();
                current_threads -= 1;
            }
        }

        fs::remove_dir(private)?;
    } else {
        let root_dir = fs::read_dir(&cwd).unwrap();
        let mut paths = vec![];
        let mut dir_list = vec![];

        populate_file_list(root_dir, &mut paths, &mut dir_list).unwrap();

        for path in &paths {
            println!("{path:?}");
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
        let pwd = Arc::new(read_password().unwrap());

        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        let exe = Arc::new(exe);
        // let private = Arc::new(private);

        let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(max_threads);
        let mut current_threads = 0;
        let cwd: Arc<String> = Arc::from(String::from(cwd.to_str().unwrap()));

        for path in paths {
            let pwd = pwd.clone();
            let exe = exe.clone();
            let config = config.clone();
            let cwd = cwd.clone();

            handles.push(thread::spawn(move || {
                if path.is_file() && path.as_os_str() != exe.as_os_str() {
                    encrypt_file(
                        String::from(path.to_str().unwrap()),
                        &cwd.to_string(),
                        &pwd.to_string(),
                        &config,
                    )
                    .unwrap();
                }
            }));
            current_threads += 1;

            if current_threads >= max_threads {
                while let Some(handle) = handles.pop() {
                    handle.join().unwrap();
                    current_threads -= 1;
                }
            }
        }

        if current_threads > 0 {
            while let Some(handle) = handles.pop() {
                handle.join().unwrap();
                current_threads -= 1;
            }
        }

        for dir in dir_list {
            fs::remove_dir_all(dir)?;
        }
    }

    Ok(())
}
