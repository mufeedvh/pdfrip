//! Job coordination and worker orchestration for PDF password cracking.
//!
//! The engine accepts a deterministic [`producer::Producer`] and chooses one of two execution
//! strategies:
//!
//! - worker-local lease sharding when the producer supports [`Producer::boxed_clone`]
//! - coordinator-driven batching as a backwards-compatible fallback for sequential-only producers
//!
//! Both modes preserve the same user-facing guarantees introduced in this release cycle:
//!
//! - exact progress bars that count only verified work
//! - checkpoint/resume support based on a verified-attempt prefix
//! - deterministic cancellation semantics that drain already-assigned work before returning a
//!   resumable offset
//! - graceful worker-failure reporting instead of silent premature exits
//!
//! The current hot path still relies on `crates/cracker` for PDF verification, but the
//! coordination layer is now explicit enough to support cancellation, draining, structured result
//! reporting, and worker-local keyspace generation on multi-core systems.

#[macro_use]
extern crate log;

/// Exposes the available producers.
pub mod producers {
    pub use producer::*;
}

/// Exposes the available crackers.
pub mod crackers {
    pub use cracker::{PDFCracker, PDFCrackerState, PasswordKind, VerificationMode};
}

use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use anyhow::{anyhow, Context};
use crossbeam::channel::{Receiver, RecvTimeoutError, Sender};

use cracker::{PDFCracker, PDFCrackerState};
use producer::Producer;

/// Default number of candidates grouped into a single worker message or range lease.
///
/// In the batching fallback this controls channel amortization. In sharded mode it controls how
/// much contiguous keyspace a worker leases before it checks whether cancellation should stop new
/// work from being assigned.
pub const DEFAULT_BATCH_SIZE: usize = 256;
const QUEUED_BATCHES_PER_WORKER: usize = 2;
const WORKER_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A clonable cancellation primitive shared between the CLI and the engine.
///
/// The token is intentionally tiny: the CLI flips it from a Ctrl-C handler, and the engine then
/// stops assigning new work while allowing already assigned ranges to drain so any resulting
/// checkpoint reflects a verified-attempt prefix with no gaps.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates a new token in the non-cancelled state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns `true` once cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Runtime configuration for a cracking job.
///
/// `initial_attempts` is used for checkpoint resume. It represents a verified-attempt prefix from
/// a previous run and is therefore applied either by asking the producer to skip exactly that many
/// candidates or by seeding the sharded lease cursor to the same offset.
#[derive(Debug, Clone)]
pub struct JobOptions {
    pub no_workers: usize,
    pub batch_size: usize,
    pub initial_attempts: usize,
    pub cancellation_token: CancellationToken,
}

impl JobOptions {
    /// Builds a job configuration with sensible defaults for a fresh run.
    pub fn new(no_workers: usize) -> Self {
        Self {
            no_workers,
            batch_size: DEFAULT_BATCH_SIZE,
            initial_attempts: 0,
            cancellation_token: CancellationToken::new(),
        }
    }
}

/// Terminal state returned by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Success,
    Exhausted,
    Cancelled,
}

/// Progress data emitted after workers verify real candidates.
///
/// `delta` reports how many additional candidates were verified since the previous callback.
/// Callers should prefer this value over per-candidate callbacks to keep UI/reporting overhead low.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressUpdate {
    pub attempts: usize,
    pub delta: usize,
    pub total_candidates: usize,
}

/// Final engine result.
///
/// `attempts` is always the exact number of password candidates that reached the verifier, not the
/// number of candidates produced or queued. When `status` is [`JobStatus::Cancelled`], `attempts`
/// can be persisted as a checkpoint resume offset because cancellation drains all already assigned
/// work before returning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobResult {
    pub status: JobStatus,
    pub password: Option<Vec<u8>>,
    pub attempts: usize,
    pub total_candidates: usize,
    pub resumed_from: usize,
}

struct PasswordBatch {
    candidates: Vec<Vec<u8>>,
}

struct EventDrainState<'a> {
    attempts: &'a mut usize,
    active_workers: &'a mut usize,
    total_candidates: usize,
    found_password: &'a mut Option<Vec<u8>>,
    fatal_error: &'a mut Option<anyhow::Error>,
    stop_immediately: &'a AtomicBool,
    progress_callback: Option<&'a dyn Fn(ProgressUpdate)>,
}

enum WorkerEvent {
    BatchComplete {
        worker_id: usize,
        attempts: usize,
    },
    PasswordFound {
        worker_id: usize,
        password: Vec<u8>,
        attempts: usize,
    },
    WorkerInitFailed {
        worker_id: usize,
        error: String,
    },
    WorkerRuntimeFailed {
        worker_id: usize,
        error: String,
    },
    WorkerStopped {
        worker_id: usize,
    },
}

struct WorkerExitNotifier {
    worker_id: usize,
    sender: Sender<WorkerEvent>,
}

impl Drop for WorkerExitNotifier {
    fn drop(&mut self) {
        let _ = self.sender.send(WorkerEvent::WorkerStopped {
            worker_id: self.worker_id,
        });
    }
}

#[derive(Clone)]
struct ShardedWorkerShared {
    cracker: Arc<PDFCracker>,
    total_candidates: usize,
    lease_size: usize,
    next_range_start: Arc<AtomicUsize>,
    sender: Sender<WorkerEvent>,
    stop_fetching: Arc<AtomicBool>,
    stop_immediately: Arc<AtomicBool>,
}

struct JobCompletionState {
    attempts: usize,
    total_candidates: usize,
    resumed_from: usize,
    found_password: Option<Vec<u8>>,
    cancellation_requested: bool,
    fatal_error: Option<anyhow::Error>,
}

/// Returns a worker-count default based on the current machine.
///
/// The heuristic deliberately matches the number of logical CPUs reported by the standard library.
/// This keeps the CLI default adaptive without adding extra dependencies.
pub fn recommended_worker_count() -> usize {
    thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1)
}

/// Returns the engine's default work batch size.
pub fn default_batch_size() -> usize {
    DEFAULT_BATCH_SIZE
}

/// Backwards-compatible wrapper around [`crack_file_with_options`].
///
/// This compatibility API preserves the old `Option<Vec<u8>>` return type and replays batch-level
/// progress as repeated callback invocations. New callers should prefer [`crack_file_with_options`]
/// because it exposes exact attempt counts, cancellation, and lower-overhead progress updates.
pub fn crack_file(
    no_workers: usize,
    cracker: PDFCracker,
    producer: Box<dyn Producer>,
    callback: Box<dyn Fn()>,
) -> anyhow::Result<Option<Vec<u8>>> {
    let progress = move |update: ProgressUpdate| {
        for _ in 0..update.delta {
            callback();
        }
    };

    let result = crack_file_with_options(
        cracker,
        producer,
        JobOptions::new(no_workers),
        Some(&progress),
    )?;

    Ok(result.password)
}

/// Runs a cracking job with exact progress accounting and optional cancellation support.
///
/// # Parameters
/// - `cracker`: immutable PDF data shared across worker-local verifier states.
/// - `producer`: deterministic candidate source.
/// - `options`: worker count, batch size, cancellation token, and optional resume offset.
/// - `progress_callback`: optional low-frequency callback invoked after workers verify real work.
///
/// # Returns
/// A [`JobResult`] describing success, exhaustion, or cancellation. The `attempts` field always
/// reflects actual verification work rather than queued work.
///
/// # Errors
/// Returns an error when the producer cannot be resumed to the requested offset, when workers fail
/// to initialize, when progress accounting would overflow, or when worker threads panic before a
/// successful result is established.
pub fn crack_file_with_options(
    cracker: PDFCracker,
    producer: Box<dyn Producer>,
    options: JobOptions,
    progress_callback: Option<&dyn Fn(ProgressUpdate)>,
) -> anyhow::Result<JobResult> {
    validate_job_options(&options)?;

    let total_candidates = producer.size();
    if options.initial_attempts > total_candidates {
        return Err(anyhow!(
            "resume offset {} exceeds total candidate count {}",
            options.initial_attempts,
            total_candidates
        ));
    }

    if options.initial_attempts == total_candidates {
        return Ok(JobResult {
            status: JobStatus::Exhausted,
            password: None,
            attempts: total_candidates,
            total_candidates,
            resumed_from: options.initial_attempts,
        });
    }

    if let Some(worker_producers) =
        clone_worker_producers(producer.as_ref(), options.no_workers.saturating_sub(1))
    {
        return crack_file_with_sharded_dispatch(
            cracker,
            producer,
            worker_producers,
            total_candidates,
            options,
            progress_callback,
        );
    }

    info!(
        "event=job_dispatch_mode mode=batched workers={} batch_size={} total_candidates={} initial_attempts={}",
        options.no_workers,
        options.batch_size,
        total_candidates,
        options.initial_attempts
    );

    crack_file_with_batched_dispatch(
        cracker,
        producer,
        total_candidates,
        options,
        progress_callback,
    )
}

fn validate_job_options(options: &JobOptions) -> anyhow::Result<()> {
    if options.no_workers == 0 {
        return Err(anyhow!("worker count must be at least 1"));
    }
    if options.batch_size == 0 {
        return Err(anyhow!("batch size must be at least 1"));
    }

    Ok(())
}

fn clone_worker_producers(
    producer: &dyn Producer,
    clone_count: usize,
) -> Option<Vec<Box<dyn Producer>>> {
    if clone_count == 0 {
        producer.boxed_clone().map(|_| Vec::new())
    } else {
        let mut clones = Vec::with_capacity(clone_count);
        for _ in 0..clone_count {
            clones.push(producer.boxed_clone()?);
        }
        Some(clones)
    }
}

fn crack_file_with_sharded_dispatch(
    cracker: PDFCracker,
    primary_producer: Box<dyn Producer>,
    additional_producers: Vec<Box<dyn Producer>>,
    total_candidates: usize,
    options: JobOptions,
    progress_callback: Option<&dyn Fn(ProgressUpdate)>,
) -> anyhow::Result<JobResult> {
    let (event_sender, event_receiver) = crossbeam::channel::unbounded::<WorkerEvent>();
    let stop_fetching = Arc::new(AtomicBool::new(false));
    let stop_immediately = Arc::new(AtomicBool::new(false));
    let worker_shared = ShardedWorkerShared {
        cracker: Arc::new(cracker),
        total_candidates,
        lease_size: options.batch_size,
        next_range_start: Arc::new(AtomicUsize::new(options.initial_attempts)),
        sender: event_sender.clone(),
        stop_fetching: stop_fetching.clone(),
        stop_immediately: stop_immediately.clone(),
    };

    let mut handles = Vec::with_capacity(options.no_workers);
    handles.push(spawn_sharded_worker(
        0,
        primary_producer,
        worker_shared.clone(),
    ));
    for (worker_id, producer) in additional_producers.into_iter().enumerate() {
        handles.push(spawn_sharded_worker(
            worker_id + 1,
            producer,
            worker_shared.clone(),
        ));
    }
    drop(event_sender);

    info!(
        "event=job_start mode=sharded workers={} lease_size={} total_candidates={} initial_attempts={}",
        options.no_workers,
        options.batch_size,
        total_candidates,
        options.initial_attempts
    );

    let mut attempts = options.initial_attempts;
    let mut active_workers = options.no_workers;
    let mut found_password = None;
    let mut cancellation_requested = false;
    let mut fatal_error: Option<anyhow::Error> = None;

    while active_workers > 0 {
        if !cancellation_requested
            && found_password.is_none()
            && fatal_error.is_none()
            && options.cancellation_token.is_cancelled()
        {
            cancellation_requested = true;
            stop_fetching.store(true, Ordering::Release);
            info!(
                "event=job_cancel_requested attempts={} total_candidates={} mode=sharded",
                attempts, total_candidates
            );
        }

        match event_receiver.recv_timeout(WORKER_EVENT_POLL_INTERVAL) {
            Ok(event) => {
                let mut event_state = EventDrainState {
                    attempts: &mut attempts,
                    active_workers: &mut active_workers,
                    total_candidates,
                    found_password: &mut found_password,
                    fatal_error: &mut fatal_error,
                    stop_immediately: &stop_immediately,
                    progress_callback,
                };
                handle_worker_event(event, &mut event_state)?;
                drain_worker_events(&event_receiver, &mut event_state)?;
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                if active_workers == 0 {
                    break;
                }
                return Err(anyhow!(
                    "worker event channel closed unexpectedly while sharded workers were still active"
                ));
            }
        }

        if found_password.is_some() || fatal_error.is_some() {
            stop_fetching.store(true, Ordering::Release);
            stop_immediately.store(true, Ordering::Release);
        }
    }

    finalize_worker_handles(
        handles,
        JobCompletionState {
            attempts,
            total_candidates,
            resumed_from: options.initial_attempts,
            found_password,
            cancellation_requested,
            fatal_error,
        },
        &stop_immediately,
    )
}

fn crack_file_with_batched_dispatch(
    cracker: PDFCracker,
    mut producer: Box<dyn Producer>,
    total_candidates: usize,
    options: JobOptions,
    progress_callback: Option<&dyn Fn(ProgressUpdate)>,
) -> anyhow::Result<JobResult> {
    resume_producer_to_offset(&mut *producer, options.initial_attempts)?;

    let queue_capacity = options
        .no_workers
        .saturating_mul(QUEUED_BATCHES_PER_WORKER)
        .max(1);
    let (work_sender, work_receiver) = crossbeam::channel::bounded::<PasswordBatch>(queue_capacity);
    let (event_sender, event_receiver) = crossbeam::channel::unbounded::<WorkerEvent>();
    let stop_immediately = Arc::new(AtomicBool::new(false));
    let cracker_handle = Arc::new(cracker);

    let mut handles = Vec::with_capacity(options.no_workers);
    for worker_id in 0..options.no_workers {
        handles.push(spawn_batched_worker(
            worker_id,
            cracker_handle.clone(),
            work_receiver.clone(),
            event_sender.clone(),
            stop_immediately.clone(),
        ));
    }
    drop(work_receiver);
    drop(event_sender);

    info!(
        "event=job_start mode=batched workers={} batch_size={} total_candidates={} initial_attempts={} queue_capacity={}",
        options.no_workers,
        options.batch_size,
        total_candidates,
        options.initial_attempts,
        queue_capacity
    );

    let mut attempts = options.initial_attempts;
    let mut active_workers = options.no_workers;
    let mut found_password = None;
    let mut producer_finished = false;
    let mut cancellation_requested = false;
    let mut fatal_error: Option<anyhow::Error> = None;

    loop {
        {
            let mut event_state = EventDrainState {
                attempts: &mut attempts,
                active_workers: &mut active_workers,
                total_candidates,
                found_password: &mut found_password,
                fatal_error: &mut fatal_error,
                stop_immediately: &stop_immediately,
                progress_callback,
            };
            drain_worker_events(&event_receiver, &mut event_state)?;
        }

        if found_password.is_some() || fatal_error.is_some() {
            break;
        }

        if options.cancellation_token.is_cancelled() {
            cancellation_requested = true;
            info!(
                "event=job_cancel_requested attempts={} total_candidates={} mode=batched",
                attempts, total_candidates
            );
            break;
        }

        if producer_finished {
            break;
        }

        match collect_batch(&mut *producer, options.batch_size)? {
            Some(batch) => {
                if work_sender.send(batch).is_err() {
                    {
                        let mut event_state = EventDrainState {
                            attempts: &mut attempts,
                            active_workers: &mut active_workers,
                            total_candidates,
                            found_password: &mut found_password,
                            fatal_error: &mut fatal_error,
                            stop_immediately: &stop_immediately,
                            progress_callback,
                        };
                        drain_worker_events(&event_receiver, &mut event_state)?;
                    }

                    if found_password.is_none() && fatal_error.is_none() {
                        stop_immediately.store(true, Ordering::Release);
                        fatal_error = Some(anyhow!(
                            "all workers exited before additional work could be dispatched"
                        ));
                    }
                }
            }
            None => {
                producer_finished = true;
                debug!(
                    "event=producer_exhausted attempts={} total_candidates={} mode=batched",
                    attempts, total_candidates
                );
            }
        }
    }

    drop(work_sender);

    while active_workers > 0 {
        let event = event_receiver
            .recv()
            .context("worker event channel closed unexpectedly while draining")?;
        let mut event_state = EventDrainState {
            attempts: &mut attempts,
            active_workers: &mut active_workers,
            total_candidates,
            found_password: &mut found_password,
            fatal_error: &mut fatal_error,
            stop_immediately: &stop_immediately,
            progress_callback,
        };
        handle_worker_event(event, &mut event_state)?;
    }

    finalize_worker_handles(
        handles,
        JobCompletionState {
            attempts,
            total_candidates,
            resumed_from: options.initial_attempts,
            found_password,
            cancellation_requested,
            fatal_error,
        },
        &stop_immediately,
    )
}

fn finalize_worker_handles(
    handles: Vec<thread::JoinHandle<()>>,
    mut completion: JobCompletionState,
    stop_immediately: &AtomicBool,
) -> anyhow::Result<JobResult> {
    for (worker_id, handle) in handles.into_iter().enumerate() {
        if handle.join().is_err()
            && completion.found_password.is_none()
            && completion.fatal_error.is_none()
        {
            stop_immediately.store(true, Ordering::Release);
            completion.fatal_error = Some(anyhow!("worker thread {worker_id} panicked"));
        }
    }

    if let Some(error) = completion.fatal_error {
        error!(
            "event=job_failed attempts={} total_candidates={} error={error:#}",
            completion.attempts, completion.total_candidates
        );
        return Err(error);
    }

    let status = if completion.found_password.is_some() {
        JobStatus::Success
    } else if completion.cancellation_requested {
        JobStatus::Cancelled
    } else {
        JobStatus::Exhausted
    };

    info!(
        "event=job_complete status={:?} attempts={} total_candidates={} resumed_from={}",
        status, completion.attempts, completion.total_candidates, completion.resumed_from
    );

    Ok(JobResult {
        status,
        password: completion.found_password.take(),
        attempts: completion.attempts,
        total_candidates: completion.total_candidates,
        resumed_from: completion.resumed_from,
    })
}

fn spawn_sharded_worker(
    worker_id: usize,
    mut producer: Box<dyn Producer>,
    shared: ShardedWorkerShared,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let _exit_notifier = WorkerExitNotifier {
            worker_id,
            sender: shared.sender.clone(),
        };

        let mut cracker_state = match PDFCrackerState::from_cracker(&shared.cracker) {
            Ok(state) => state,
            Err(error) => {
                let _ = shared.sender.send(WorkerEvent::WorkerInitFailed {
                    worker_id,
                    error: format!("{error:#}"),
                });
                return;
            }
        };

        let mut producer_cursor = 0usize;
        let mut candidate = Vec::new();
        debug!("event=worker_started worker={} mode=sharded", worker_id);

        loop {
            if shared.stop_immediately.load(Ordering::Acquire)
                || shared.stop_fetching.load(Ordering::Acquire)
            {
                return;
            }

            let lease_start = shared
                .next_range_start
                .fetch_add(shared.lease_size, Ordering::AcqRel);
            if lease_start >= shared.total_candidates {
                debug!(
                    "event=worker_exhausted worker={} mode=sharded lease_start={} total_candidates={}",
                    worker_id, lease_start, shared.total_candidates
                );
                return;
            }
            let lease_end = lease_start
                .saturating_add(shared.lease_size)
                .min(shared.total_candidates);
            debug!(
                "event=worker_lease_acquired worker={} lease_start={} lease_end={} mode=sharded",
                worker_id, lease_start, lease_end
            );

            if let Err(error) =
                advance_producer_cursor(&mut *producer, &mut producer_cursor, lease_start)
            {
                shared.stop_fetching.store(true, Ordering::Release);
                shared.stop_immediately.store(true, Ordering::Release);
                let _ = shared
                    .sender
                    .send(WorkerEvent::WorkerRuntimeFailed { worker_id, error });
                return;
            }

            let mut attempts = 0usize;
            while producer_cursor < lease_end {
                if shared.stop_immediately.load(Ordering::Acquire) {
                    if attempts > 0 {
                        let _ = shared.sender.send(WorkerEvent::BatchComplete {
                            worker_id,
                            attempts,
                        });
                    }
                    return;
                }

                match producer.next_into(&mut candidate) {
                    Ok(true) => {}
                    Ok(false) => {
                        if attempts > 0 {
                            let _ = shared.sender.send(WorkerEvent::BatchComplete {
                                worker_id,
                                attempts,
                            });
                        }
                        shared.stop_fetching.store(true, Ordering::Release);
                        shared.stop_immediately.store(true, Ordering::Release);
                        let _ = shared.sender.send(WorkerEvent::WorkerRuntimeFailed {
                            worker_id,
                            error: format!(
                                "worker {worker_id} expected candidate at offset {producer_cursor} but producer ended early"
                            ),
                        });
                        return;
                    }
                    Err(error) => {
                        if attempts > 0 {
                            let _ = shared.sender.send(WorkerEvent::BatchComplete {
                                worker_id,
                                attempts,
                            });
                        }
                        shared.stop_fetching.store(true, Ordering::Release);
                        shared.stop_immediately.store(true, Ordering::Release);
                        let _ = shared.sender.send(WorkerEvent::WorkerRuntimeFailed {
                            worker_id,
                            error: format!(
                                "worker {worker_id} failed to generate candidate at offset {producer_cursor}: {error}"
                            ),
                        });
                        return;
                    }
                }
                producer_cursor += 1;
                attempts += 1;

                if cracker_state.attempt(&candidate) {
                    shared.stop_fetching.store(true, Ordering::Release);
                    shared.stop_immediately.store(true, Ordering::Release);
                    let _ = shared.sender.send(WorkerEvent::PasswordFound {
                        worker_id,
                        password: std::mem::take(&mut candidate),
                        attempts,
                    });
                    return;
                }
            }

            if attempts > 0 {
                let _ = shared.sender.send(WorkerEvent::BatchComplete {
                    worker_id,
                    attempts,
                });
            }

            if shared.stop_fetching.load(Ordering::Acquire) {
                return;
            }
        }
    })
}

fn advance_producer_cursor(
    producer: &mut dyn Producer,
    producer_cursor: &mut usize,
    target_offset: usize,
) -> Result<(), String> {
    if target_offset < *producer_cursor {
        return Err(format!(
            "worker shard attempted to rewind producer from {} back to {}",
            producer_cursor, target_offset
        ));
    }

    let delta = target_offset - *producer_cursor;
    if delta == 0 {
        return Ok(());
    }

    let skipped = producer.skip(delta)?;
    if skipped != delta {
        return Err(format!(
            "worker shard skipped only {skipped} candidates out of requested seek distance {delta}"
        ));
    }

    *producer_cursor += skipped;
    Ok(())
}

fn resume_producer_to_offset(producer: &mut dyn Producer, offset: usize) -> anyhow::Result<()> {
    if offset == 0 {
        return Ok(());
    }

    let skipped = producer
        .skip(offset)
        .map_err(anyhow::Error::msg)
        .context("failed to resume producer at requested attempt offset")?;
    if skipped != offset {
        return Err(anyhow!(
            "producer skipped only {skipped} candidates out of requested resume offset {offset}"
        ));
    }

    Ok(())
}

fn spawn_batched_worker(
    worker_id: usize,
    cracker: Arc<PDFCracker>,
    receiver: Receiver<PasswordBatch>,
    sender: Sender<WorkerEvent>,
    stop_immediately: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let _exit_notifier = WorkerExitNotifier {
            worker_id,
            sender: sender.clone(),
        };

        let mut cracker_state = match PDFCrackerState::from_cracker(&cracker) {
            Ok(state) => state,
            Err(error) => {
                let _ = sender.send(WorkerEvent::WorkerInitFailed {
                    worker_id,
                    error: format!("{error:#}"),
                });
                return;
            }
        };

        debug!("event=worker_started worker={} mode=batched", worker_id);

        while !stop_immediately.load(Ordering::Acquire) {
            let batch = match receiver.recv() {
                Ok(batch) => batch,
                Err(_) => return,
            };

            let mut attempts = 0usize;
            for candidate in batch.candidates {
                if stop_immediately.load(Ordering::Acquire) {
                    if attempts > 0 {
                        let _ = sender.send(WorkerEvent::BatchComplete {
                            worker_id,
                            attempts,
                        });
                    }
                    return;
                }

                attempts += 1;
                if cracker_state.attempt(&candidate) {
                    stop_immediately.store(true, Ordering::Release);
                    let _ = sender.send(WorkerEvent::PasswordFound {
                        worker_id,
                        password: candidate,
                        attempts,
                    });
                    return;
                }
            }

            if attempts > 0 {
                let _ = sender.send(WorkerEvent::BatchComplete {
                    worker_id,
                    attempts,
                });
            }
        }
    })
}

fn collect_batch(
    producer: &mut dyn Producer,
    batch_size: usize,
) -> anyhow::Result<Option<PasswordBatch>> {
    let mut candidates = Vec::with_capacity(batch_size);

    while candidates.len() < batch_size {
        match producer.next().map_err(anyhow::Error::msg)? {
            Some(candidate) => candidates.push(candidate),
            None => break,
        }
    }

    if candidates.is_empty() {
        Ok(None)
    } else {
        Ok(Some(PasswordBatch { candidates }))
    }
}

fn drain_worker_events(
    receiver: &Receiver<WorkerEvent>,
    state: &mut EventDrainState<'_>,
) -> anyhow::Result<()> {
    while let Ok(event) = receiver.try_recv() {
        handle_worker_event(event, state)?;
    }

    Ok(())
}

fn handle_worker_event(event: WorkerEvent, state: &mut EventDrainState<'_>) -> anyhow::Result<()> {
    match event {
        WorkerEvent::BatchComplete {
            worker_id,
            attempts: delta,
        } => {
            record_attempts(
                state.attempts,
                delta,
                state.total_candidates,
                state.progress_callback,
            )?;
            trace!(
                "event=batch_complete worker={} delta={} attempts={} total_candidates={}",
                worker_id,
                delta,
                *state.attempts,
                state.total_candidates
            );
        }
        WorkerEvent::PasswordFound {
            worker_id,
            password,
            attempts: delta,
        } => {
            state.stop_immediately.store(true, Ordering::Release);
            record_attempts(
                state.attempts,
                delta,
                state.total_candidates,
                state.progress_callback,
            )?;
            if state.found_password.is_none() {
                info!(
                    "event=password_found worker={} attempts={} total_candidates={}",
                    worker_id, *state.attempts, state.total_candidates
                );
                *state.found_password = Some(password);
            }
        }
        WorkerEvent::WorkerInitFailed { worker_id, error } => {
            state.stop_immediately.store(true, Ordering::Release);
            error!(
                "event=worker_init_failed worker={} error={}",
                worker_id, error
            );
            if state.fatal_error.is_none() {
                *state.fatal_error = Some(anyhow!(
                    "worker {worker_id} failed to initialize cracker state: {error}"
                ));
            }
        }
        WorkerEvent::WorkerRuntimeFailed { worker_id, error } => {
            state.stop_immediately.store(true, Ordering::Release);
            error!(
                "event=worker_runtime_failed worker={} error={}",
                worker_id, error
            );
            if state.fatal_error.is_none() {
                *state.fatal_error = Some(anyhow!(
                    "worker {worker_id} failed during execution: {error}"
                ));
            }
        }
        WorkerEvent::WorkerStopped { worker_id } => {
            *state.active_workers = state.active_workers.saturating_sub(1);
            debug!(
                "event=worker_stopped worker={} remaining_workers={}",
                worker_id, *state.active_workers
            );
        }
    }

    Ok(())
}

fn record_attempts(
    attempts: &mut usize,
    delta: usize,
    total_candidates: usize,
    progress_callback: Option<&dyn Fn(ProgressUpdate)>,
) -> anyhow::Result<()> {
    if delta == 0 {
        return Ok(());
    }

    let next_attempts = attempts
        .checked_add(delta)
        .ok_or_else(|| anyhow!("attempt counter overflowed"))?;
    if next_attempts > total_candidates {
        return Err(anyhow!(
            "attempt counter exceeded total candidate count: {} > {}",
            next_attempts,
            total_candidates
        ));
    }

    *attempts = next_attempts;

    if let Some(callback) = progress_callback {
        callback(ProgressUpdate {
            attempts: *attempts,
            delta,
            total_candidates,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use crate::{
        crack_file_with_options, crackers::PDFCracker, handle_worker_event, CancellationToken,
        EventDrainState, JobOptions, JobStatus, ProgressUpdate, WorkerEvent,
    };
    use producer::Producer;

    #[derive(Clone)]
    struct StaticProducer {
        values: Vec<Vec<u8>>,
        position: usize,
    }

    impl StaticProducer {
        fn new(values: Vec<Vec<u8>>) -> Self {
            Self {
                values,
                position: 0,
            }
        }
    }

    impl Producer for StaticProducer {
        fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
            let Some(value) = self.values.get(self.position).cloned() else {
                return Ok(None);
            };
            self.position += 1;
            Ok(Some(value))
        }

        fn size(&self) -> usize {
            self.values.len()
        }

        fn skip(&mut self, count: usize) -> Result<usize, String> {
            let remaining = self.values.len().saturating_sub(self.position);
            let skipped = count.min(remaining);
            self.position += skipped;
            Ok(skipped)
        }

        fn boxed_clone(&self) -> Option<Box<dyn Producer>> {
            Some(Box::new(self.clone()))
        }
    }

    struct SequentialOnlyProducer {
        inner: StaticProducer,
    }

    impl SequentialOnlyProducer {
        fn new(values: Vec<Vec<u8>>) -> Self {
            Self {
                inner: StaticProducer::new(values),
            }
        }
    }

    impl Producer for SequentialOnlyProducer {
        fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
            self.inner.next()
        }

        fn size(&self) -> usize {
            self.inner.size()
        }

        fn skip(&mut self, count: usize) -> Result<usize, String> {
            self.inner.skip(count)
        }
    }

    #[derive(Clone, Default)]
    struct ProducerCallCounters {
        next_calls: Arc<AtomicUsize>,
        next_into_calls: Arc<AtomicUsize>,
    }

    #[derive(Clone)]
    struct InstrumentedCloneableProducer {
        inner: StaticProducer,
        counters: ProducerCallCounters,
    }

    impl InstrumentedCloneableProducer {
        fn new(values: Vec<Vec<u8>>, counters: ProducerCallCounters) -> Self {
            Self {
                inner: StaticProducer::new(values),
                counters,
            }
        }
    }

    impl Producer for InstrumentedCloneableProducer {
        fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
            self.counters.next_calls.fetch_add(1, Ordering::AcqRel);
            self.inner.next()
        }

        fn next_into(&mut self, output: &mut Vec<u8>) -> Result<bool, String> {
            self.counters.next_into_calls.fetch_add(1, Ordering::AcqRel);
            match self.inner.next() {
                Ok(Some(candidate)) => {
                    output.clear();
                    output.extend_from_slice(&candidate);
                    Ok(true)
                }
                Ok(None) => {
                    output.clear();
                    Ok(false)
                }
                Err(error) => Err(error),
            }
        }

        fn size(&self) -> usize {
            self.inner.size()
        }

        fn skip(&mut self, count: usize) -> Result<usize, String> {
            self.inner.skip(count)
        }

        fn boxed_clone(&self) -> Option<Box<dyn Producer>> {
            Some(Box::new(self.clone()))
        }
    }

    fn example_pdf(name: &str) -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
            .join(name)
            .display()
            .to_string()
    }

    #[test]
    fn counts_only_verified_attempts_when_success_stops_prefilled_work() {
        let candidates = vec![
            b"wrong-1".to_vec(),
            b"wrong-2".to_vec(),
            b"15012000".to_vec(),
            b"wrong-3".to_vec(),
            b"wrong-4".to_vec(),
            b"wrong-5".to_vec(),
        ];
        let mut options = JobOptions::new(1);
        options.batch_size = 4;

        let progress_points = Mutex::new(Vec::new());
        let progress = |update: ProgressUpdate| {
            progress_points
                .lock()
                .expect("progress lock should not poison")
                .push(update.attempts);
        };

        let result = crack_file_with_options(
            PDFCracker::from_file(&example_pdf("datetime-15012000.pdf"))
                .expect("example pdf should load"),
            Box::new(StaticProducer::new(candidates)),
            options,
            Some(&progress),
        )
        .expect("engine run should succeed");

        assert_eq!(result.status, JobStatus::Success);
        assert_eq!(result.password, Some(b"15012000".to_vec()));
        assert_eq!(result.attempts, 3);
        assert_eq!(
            progress_points
                .lock()
                .expect("progress lock should not poison")
                .last()
                .copied(),
            Some(3)
        );
    }

    #[test]
    fn cancelled_job_resumes_from_the_exact_verified_prefix() {
        let mut candidates = (0..500)
            .map(|value| format!("wrong-{value:03}").into_bytes())
            .collect::<Vec<_>>();
        candidates[400] = b"15012000".to_vec();

        let cancellation = CancellationToken::new();
        let mut first_options = JobOptions::new(4);
        first_options.batch_size = 7;
        first_options.cancellation_token = cancellation.clone();

        let cancel_on_progress = |update: ProgressUpdate| {
            if update.attempts >= 14 {
                cancellation.cancel();
            }
        };

        let cancelled = crack_file_with_options(
            PDFCracker::from_file(&example_pdf("datetime-15012000.pdf"))
                .expect("example pdf should load"),
            Box::new(StaticProducer::new(candidates.clone())),
            first_options,
            Some(&cancel_on_progress),
        )
        .expect("cancelled run should finish cleanly");

        assert_eq!(cancelled.status, JobStatus::Cancelled);
        assert!(cancelled.attempts > 0);
        assert!(cancelled.attempts < 401);

        let mut resumed_options = JobOptions::new(1);
        resumed_options.batch_size = 7;
        resumed_options.initial_attempts = cancelled.attempts;

        let resumed = crack_file_with_options(
            PDFCracker::from_file(&example_pdf("datetime-15012000.pdf"))
                .expect("example pdf should load"),
            Box::new(StaticProducer::new(candidates)),
            resumed_options,
            None,
        )
        .expect("resumed run should finish cleanly");

        assert_eq!(resumed.status, JobStatus::Success);
        assert_eq!(resumed.password, Some(b"15012000".to_vec()));
        assert_eq!(resumed.attempts, 401);
        assert_eq!(resumed.resumed_from, cancelled.attempts);
    }

    #[test]
    fn exhausted_job_stops_exactly_at_total_candidate_count() {
        let candidates = vec![
            b"wrong-1".to_vec(),
            b"wrong-2".to_vec(),
            b"wrong-3".to_vec(),
        ];
        let mut options = JobOptions::new(2);
        options.batch_size = 16;

        let progress_points = Mutex::new(Vec::new());
        let progress = |update: ProgressUpdate| {
            progress_points
                .lock()
                .expect("progress lock should not poison")
                .push(update.attempts);
        };

        let result = crack_file_with_options(
            PDFCracker::from_file(&example_pdf("datetime-15012000.pdf"))
                .expect("example pdf should load"),
            Box::new(StaticProducer::new(candidates)),
            options,
            Some(&progress),
        )
        .expect("exhausted run should finish cleanly");

        assert_eq!(result.status, JobStatus::Exhausted);
        assert_eq!(result.attempts, result.total_candidates);
        assert_eq!(result.total_candidates, 3);
        assert_eq!(
            progress_points
                .lock()
                .expect("progress lock should not poison")
                .last()
                .copied(),
            Some(3)
        );
    }

    #[test]
    fn non_cloneable_producers_fall_back_to_batched_dispatch() {
        let candidates = vec![b"wrong-1".to_vec(), b"15012000".to_vec()];
        let mut options = JobOptions::new(3);
        options.batch_size = 1;

        let result = crack_file_with_options(
            PDFCracker::from_file(&example_pdf("datetime-15012000.pdf"))
                .expect("example pdf should load"),
            Box::new(SequentialOnlyProducer::new(candidates)),
            options,
            None,
        )
        .expect("fallback batched run should succeed");

        assert_eq!(result.status, JobStatus::Success);
        assert_eq!(result.password, Some(b"15012000".to_vec()));
        assert_eq!(result.attempts, 2);
    }

    #[test]
    fn single_worker_cloneable_runs_use_sharded_next_into_path() {
        let counters = ProducerCallCounters::default();
        let candidates = vec![b"wrong-1".to_vec(), b"15012000".to_vec()];
        let mut options = JobOptions::new(1);
        options.batch_size = 1;

        let result = crack_file_with_options(
            PDFCracker::from_file(&example_pdf("datetime-15012000.pdf"))
                .expect("example pdf should load"),
            Box::new(InstrumentedCloneableProducer::new(
                candidates,
                counters.clone(),
            )),
            options,
            None,
        )
        .expect("single-worker sharded run should succeed");

        assert_eq!(result.status, JobStatus::Success);
        assert_eq!(result.password, Some(b"15012000".to_vec()));
        assert_eq!(result.attempts, 2);
        assert_eq!(counters.next_calls.load(Ordering::Acquire), 0);
        assert!(counters.next_into_calls.load(Ordering::Acquire) >= 2);
    }

    #[test]
    fn worker_init_failure_sets_fatal_error_and_stop_flag() {
        let mut attempts = 0usize;
        let mut active_workers = 1usize;
        let total_candidates = 4usize;
        let mut found_password = None;
        let mut fatal_error = None;
        let stop_immediately = AtomicBool::new(false);

        let mut state = EventDrainState {
            attempts: &mut attempts,
            active_workers: &mut active_workers,
            total_candidates,
            found_password: &mut found_password,
            fatal_error: &mut fatal_error,
            stop_immediately: &stop_immediately,
            progress_callback: None,
        };

        handle_worker_event(
            WorkerEvent::WorkerInitFailed {
                worker_id: 7,
                error: String::from("synthetic init failure"),
            },
            &mut state,
        )
        .expect("worker-init failure handling should not error");

        assert!(stop_immediately.load(Ordering::Acquire));
        let error = fatal_error.expect("fatal error should be recorded");
        assert!(error
            .to_string()
            .contains("worker 7 failed to initialize cracker state"));
        assert_eq!(attempts, 0);
        assert_eq!(active_workers, 1);
        assert!(found_password.is_none());
    }
}
