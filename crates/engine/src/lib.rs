#[macro_use]
extern crate log;

/// Exposes our available Producers
pub mod producers {
    pub use producer::*;
}

/// Expose our available crackers
pub mod crackers {
    pub use cracker::{PDFCracker, PDFCrackerState};
}

// We will run a SPMC layout where a single producer produces passwords
// consumed by multiple workers. This ensures there is a buffer
// so the queue won't be consumed before the producer has time to wake up
const BUFFER_SIZE: usize = 200;

use std::sync::Arc;

use crossbeam::channel::{Receiver, Sender, TryRecvError};

use producer::Producer;

use cracker::{PDFCracker, PDFCrackerState};

/// Returns Ok(Some(<Password in bytes>)) if it successfully cracked the file.
/// Returns Ok(None) if it did not find the password.
/// Returns Err if something went wrong.
/// Callback is called once very time it consumes a password from producer
pub fn crack_file(
    no_workers: usize,
    cracker: PDFCracker,
    mut producer: Box<dyn Producer>,
    callback: Box<dyn Fn()>,
) -> anyhow::Result<Option<Vec<u8>>> {
    // Spin up workers
    let (sender, r): (Sender<Vec<u8>>, Receiver<_>) = crossbeam::channel::bounded(BUFFER_SIZE);

    let (success_sender, success_reader) = crossbeam::channel::unbounded::<Vec<u8>>();
    let mut handles = vec![];
    let cracker_handle = Arc::from(cracker);

    for _ in 0..no_workers {
        let success = success_sender.clone();
        let r2 = r.clone();
        let c2 = cracker_handle.clone();
        let id: std::thread::JoinHandle<()> = std::thread::spawn(move || {
            let Ok(mut cracker) = PDFCrackerState::from_cracker(&c2) else {
                return
            };

            while let Ok(passwd) = r2.recv() {
                if cracker.attempt(&passwd) {
                    // inform main thread we found a good password then die
                    success.send(passwd).unwrap_or_default();
                    return;
                }
            }
        });
        handles.push(id);
    }
    // Drop our ends
    drop(r);
    drop(success_sender);

    info!("Starting password cracking job...");

    let mut success = None;

    loop {
        match success_reader.try_recv() {
            Ok(password) => {
                success = Some(password);
                break;
            }
            Err(e) => {
                match e {
                    TryRecvError::Empty => {
                        // This is fine *lit*
                    }
                    TryRecvError::Disconnected => {
                        // All threads have died. Wtf?
                        // let's just report an error and break
                        error!("All workers have exited prematurely, cannot continue operations");
                        break;
                    }
                }
            }
        }

        match producer.next() {
            Ok(Some(password)) => {
                if sender.send(password).is_err() {
                    // This should only happen if their reciever is closed.
                    error!("unable to send next password since channel is closed");
                }
                callback()
            }
            Ok(None) => {
                trace!("out of passwords, exiting loop");
                break;
            }
            Err(error_msg) => {
                error!("error occured while sending: {error_msg}");
                break;
            }
        }
    }

    // Ensure any threads that are still running will eventually exit
    drop(sender);

    let found_password = match success {
        Some(result) => Some(result),
        None => {
            match success_reader.recv() {
                Ok(result) => Some(result),
                Err(e) => {
                    // Channel is empty and disconnected, i.e. all threads have exited
                    // and none found the password
                    debug!("{}", e);
                    None
                }
            }
        }
    };

    Ok(found_password)
}
