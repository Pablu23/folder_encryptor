use anyhow::Result;
use std::{
    hint,
    path::PathBuf,
    sync::{
        atomic::AtomicBool,
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    thread::{self, JoinHandle},
};

use argon2::Config;

use crate::decrypt_file;

#[derive(Debug)]
pub struct DecryptJob<'a> {
    source_path: PathBuf,
    pwd: String,
    config: Config<'a>,
}

#[derive(Debug)]
pub struct ThreadPool<'a> {
    workers: Vec<Worker<'a>>,
    last_assigned_to: usize,
    max_workers: usize,
}

#[derive(Debug)]
struct Worker<'a> {
    id: usize,
    handle: JoinHandle<()>,
    sender: Sender<DecryptJob<'a>>,
    active: Arc<AtomicBool>,
}

impl<'a> DecryptJob<'a> {
    pub fn new(source_path: PathBuf, pwd: String, config: Config<'a>) -> Self {
        DecryptJob {
            source_path,
            pwd,
            config,
        }
    }
}

impl<'a> Worker<'a>
where
    'a: 'static,
{
    pub fn new(id: usize) -> Self {
        let active = Arc::new(AtomicBool::new(false));
        let active_thread = active.clone();
        let (tx, rx): (Sender<DecryptJob>, Receiver<DecryptJob>) = mpsc::channel();
        let handle = thread::spawn(move || loop {
            let res = rx.recv();
            let job = match res {
                Ok(job) => job,
                Err(e) => {
                    println!("{e} occured in thread {id}");
                    return;
                }
            };

            active_thread.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = decrypt_file(job.source_path, job.pwd, job.config);
            active_thread.store(false, std::sync::atomic::Ordering::SeqCst);
        });

        return Worker {
            id,
            handle,
            sender: tx,
            active,
        };
    }
}

impl<'a> ThreadPool<'a>
where
    'a: 'static,
{
    pub fn new(size: usize) -> ThreadPool<'a> {
        assert!(size > 0);

        let mut workers = Vec::with_capacity(size);
        for i in 0..size {
            workers.push(Worker::new(i));
        }

        let th_pool = ThreadPool {
            workers,
            last_assigned_to: 0,
            max_workers: size,
        };

        return th_pool;
    }

    pub fn queue(&mut self, job: DecryptJob<'a>) -> Result<()> {
        let mut chosen_worker: Option<&Worker> = None;
        for worker in self.workers.iter() {
            if !worker.active.load(std::sync::atomic::Ordering::SeqCst) {
                chosen_worker = Some(worker);
                break;
            }
        }

        let w = match chosen_worker {
            Some(w) => w,
            None => {
                if self.last_assigned_to + 1 >= self.max_workers {
                    &self.workers[0]
                } else {
                    &self.workers[self.last_assigned_to + 1]
                }
            }
        };

        self.last_assigned_to = w.id;
        w.sender.send(job)?;
        Ok(())
    }

    pub fn wait(self) {
        for worker in self.workers {
            while worker.active.load(std::sync::atomic::Ordering::SeqCst) {
                hint::spin_loop();
            }
            drop(worker.sender);
            let _ = worker.handle.join();
        }
    }
}
