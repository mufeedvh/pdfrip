// We will run a SPMC layout where a single producer produces passwords
// consumed by multiple workers. This ensures there is a buffer
// so the queue won't be consumed before the producer has time to wake up
const BUFFER_SIZE: usize = 200;

use crossbeam::channel::{Receiver, Sender, TryRecvError};
use indicatif::ProgressBar;

use crate::core::production::Producer;

use super::cracker::{pdf::PDFCracker, Cracker};

enum Message {
    Password(Vec<u8>),
    Die,
}

pub fn crack_file(
    no_workers: usize,
    cracker: PDFCracker,
    mut producer: Box<dyn Producer>,
) -> anyhow::Result<()> {
    // Spin up workers
    let (sender, r): (Sender<Message>, Receiver<_>) = crossbeam::channel::bounded(BUFFER_SIZE);

    let (success_sender, success_reader) = crossbeam::channel::unbounded::<Vec<u8>>();
    let mut handles = vec![];

    for _ in 0..no_workers {
        let success = success_sender.clone();
        let r2 = r.clone();
        let c2 = cracker.clone();
        let id = std::thread::spawn(move || {
            while let Ok(message) = r2.recv() {
                match message {
                    Message::Password(passwd) => {
                        if c2.attempt(&passwd) {
                            // inform main thread we found a good password then die
                            success.send(passwd).unwrap_or_default();
                            return;
                        }
                    }
                    Message::Die => {
                        return;
                    }
                }
            }
        });
        handles.push(id);
    }
    // Drop our ends
    drop(r);
    drop(success_sender);

    info!("Starting crack...");

    let mut success = None;

    let progress_bar = ProgressBar::new(producer.size() as u64);
    progress_bar.set_draw_delta(1000);

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
                if let Err(_) = sender.send(Message::Password(password)) {
                    // This should only happen if their reciever is closed.
                    error!("unable to send next password since channel is closed");
                }
                progress_bar.inc(1);
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
    for _ in 0..no_workers {
        sender.send(Message::Die).unwrap_or_default();
    }

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

    progress_bar.finish();

    match found_password {
        Some(password) => match std::str::from_utf8(&password) {
            Ok(password) => {
                info!("Success! Found password: {}", password)
            }
            Err(_) => {
                let hex_string: String = password
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<String>>()
                    .join(" ");
                info!(
                            "Success! Found password, but it contains invalid UTF-8 characters. Displaying as hex: {}",
                            hex_string
                        )
            }
        },
        None => {
            info!("Failed to crack file...")
        }
    }

    Ok(())
}
