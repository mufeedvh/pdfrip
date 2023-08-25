// We will run a SPMC layout where a single producer produces passwords
// consumed by multiple workers. This ensures there is a buffer
// so the queue won't be consumed before the producer has time to wake up
const BUFFER_SIZE: usize = 200;

use crossbeam::{
    channel::{Receiver, Sender},
    thread,
};
use indicatif::ProgressBar;

use crate::core::production::Producer;

use super::cracker::Cracker;

enum Message {
    Password(Vec<u8>),
    Die,
}

pub fn crack_file(
    no_workers: usize,
    cracker: Box<dyn Cracker>,
    mut producer: Box<dyn Producer>,
) -> anyhow::Result<()> {
    // Spin up workers
    let (sender, r): (Sender<Message>, Receiver<Message>) =
        crossbeam::channel::bounded(BUFFER_SIZE);

    let (success_sender, success_reader) = crossbeam::channel::unbounded::<Vec<u8>>();

    thread::scope(|s| {
        for _ in 0..no_workers {
            s.builder()
                .spawn(|_| {
                    while let Ok(message) = r.recv() {
                        match message {
                            Message::Password(password) => {
                                if cracker.attempt(&password) {
                                    // inform main thread we found a good password then die
                                    let _ = success_sender.send(password);
                                    return;
                                }
                            }
                            Message::Die => return,
                        }
                    }
                })
                .unwrap();
        }

        info!("Starting crack...");
        let mut success = None;
        let mut error_message = None;

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
                    match producer.next() {
                        Ok(Some(password)) => {
                            // Ignore any errors in case the reading threads have exited
                            let _ = sender.send(Message::Password(password));
                            progress_bar.inc(1);
                        }
                        Ok(None) => {
                            // Out of passwords, exit loop
                            break;
                        }
                        Err(error_msg) => {
                            // Error occurred
                            error_message = Some(error_msg);
                            break;
                        }
                    }
                }
            };
        }
        progress_bar.finish();
        // Kill any threads that are still running
        for _ in 0..no_workers {
            // Ignore any errors in case the threads have exited
            let _ = sender.send(Message::Die);
        }

        if let Some(msg) = error_message {
            println!("Error Occurred: {msg}");
        }

        if let Some(msg) = producer.error_msg() {
            info!("{}", msg);
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
        // We cannot use the ? operator here due to size constraints
    })
    .expect("Something went wrong when cracking file");

    Ok(())
}
