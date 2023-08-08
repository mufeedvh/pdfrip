const BUFFER_SIZE: usize = 200;

use std::{fs, path::Path, sync::Arc, thread};

use crossbeam::channel::{Receiver, Sender};
use indicatif::ProgressBar;
use pdf::file::File;

use crate::core::production::Producer;

pub fn decrypt_pdf(pdf_bytes: &[u8], password: &[u8]) -> bool {
    match File::from_data_password(pdf_bytes, password) {
        Ok(_) => true,
        Err(_) => false,
    }
}

enum Message {
    Password(Arc<Vec<u8>>),
    Die,
}

pub fn crack_file(
    target_path: &Path,
    no_workers: usize,
    mut producer: Box<dyn Producer>,
) -> anyhow::Result<()> {
    // Spin up workers
    let (s, r): (Sender<Message>, Receiver<Message>) = crossbeam::channel::bounded(BUFFER_SIZE);
    let pdf_file = fs::read(target_path)?;

    let (success_sender, success_reader): (Sender<Arc<Vec<u8>>>, Receiver<Arc<Vec<u8>>>) =
        crossbeam::channel::unbounded();

    let mut worker_handles = vec![];
    for _ in 0..no_workers {
        let reader = r.clone();
        // let each thread have their own copy of the file, this uses RAM but whatever
        let filecontent = pdf_file.clone();
        let success_target = success_sender.clone();

        let handle = thread::spawn(move || {
            while let Ok(message) = reader.recv() {
                match message {
                    Message::Password(password) => {
                        if decrypt_pdf(&filecontent, &password) {
                            // inform main thread we found a good password then die
                            let _ = success_target.send(password);
                            return;
                        }
                    }
                    Message::Die => return,
                }
            }
        });
        worker_handles.push(handle);
    }

    info!("Starting crack...");
    let mut success: Option<Arc<Vec<u8>>> = None;
    let progress_bar = ProgressBar::new(producer.size() as u64);
    progress_bar.set_draw_delta(1000);
    loop {
        // Check if any thread succeeded..
        match success_reader.try_recv() {
            Ok(password) => {
                success = Some(password);
                break;
            }
            Err(_) => {
                // They have not finished yet. Send some passwords
                if let Some(password) = producer.next() {
                    // Ignore any errors incase the reading threads have exited
                    let _ = s.send(Message::Password(password));
                    progress_bar.inc(1);
                } else {
                    // Out of passwords, exit loop
                    break;
                }
            }
        };
    }

    progress_bar.finish();
    // Kill any threads that are still running
    for _ in 0..worker_handles.len() {
        // Ignore any errors incase the threads have exited
        let _ = s.send(Message::Die);
    }

    for handle in worker_handles {
        let result = handle.join();
        match result {
            Ok(_) => {}
            Err(err) => {
                error!("Error waiting for thread: {:?}", err)
            }
        }
    }

    match success {
        Some(password) => {
            info!(
                "Success! Found password: {}",
                String::from_utf8_lossy(&password)
            )
        }
        None => {
            info!("Failed to crack file...")
        }
    }

    Ok(())
}
