// We will run a SPMC layout where a single producer produces passwords
// consumed by multiple workers. This ensures there is a buffer
// so the queue won't be consumed before the producer has time to wake up
const BUFFER_SIZE: usize = 200;

use crossbeam::{
    channel::{Receiver, Sender, TryRecvError},
    thread,
};
use indicatif::ProgressBar;

use crate::core::production::Producer;

use super::cracker::Cracker;


pub fn crack_file(
    no_workers: usize,
    cracker: Box<dyn Cracker>,
    mut producer: Box<dyn Producer>,
) -> anyhow::Result<()> {
    // Spin up workers
    let (sender, r): (Sender<Vec<u8>>, Receiver<Vec<u8>>) =
        crossbeam::channel::bounded(BUFFER_SIZE);

    let (success_sender, success_reader) = crossbeam::channel::unbounded::<Vec<u8>>();

    thread::scope(|s| {
        for _ in 0..no_workers {
            s.builder()
                .spawn(|_| {
                    while let Ok(password) = r.recv() {
                        if cracker.attempt(&password) {
                            // inform main thread we found a good password then die
                            success_sender.send(password).unwrap_or_default();
                            return;
                        }
                    }
                })
                .unwrap();
        }

        info!("Starting crack...");

        let mut success = None;

        let progress_bar = ProgressBar::new(producer.size() as u64);
        progress_bar.set_draw_delta(1000);

        loop {
            match success_reader.try_recv() {
                Ok(password) => {
                    success = Some(password);
                    break;
                },
                Err(e) => {
                    match e {
                        TryRecvError::Empty => {
                            // This is fine *lit*
                        },
                        TryRecvError::Disconnected => {
                            // All threads have died. Wtf?
                            // let's just report an error and break
                            error!("All workers have exited prematurely, cannot continue operations");
                            break;
                        },
                    }
                },
            }

                match producer.next() {
                    Ok(Some(password)) => {
                        if let Err(e) = sender.send(password) {
                            // This should only happen if their reciever is closed.
                            error!("unable to send next password: {}", String::from_utf8_lossy(&e.0));
                        }
                        progress_bar.inc(1);
                    }
                    Ok(None) => {
                        // Out of passwords, stop loop
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
                match success_reader.recv(){
                    Ok(result) => Some(result),
                    Err(e) => {
                        // Channel is empty and disconnected, i.e. all threads have exited
                        // and none found the password
                        debug!("{}", e);
                        None
                    },
                }
            },
        };

        progress_bar.finish();

        match found_password {
            Some(password) => {
                match std::str::from_utf8(&password) {
                    Ok(password) => {
                        info!(
                            "Success! Found password: {}",
                            password
                        )
                    }
                    Err(_) => {
                        let hex_string: String = password.iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<String>>()
                            .join(" ");
                        info!(
                            "Success! Found password, but it contains invalid UTF-8 characters. Displaying as hex: {}",
                            hex_string
                        )
                    }
                }
            }
            None => {
                info!("Failed to crack file...")
            }
        }
        // We cannot use the ? operator here due to size constraints
    })
        .expect("Something went wrong when cracking file");

    Ok(())
}
