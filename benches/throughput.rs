use std::{cell::RefCell, collections::HashMap, path::PathBuf};

use cracker::{PDFCracker, PDFCrackerState};
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use engine::{
    crack_file_with_options, producers::number_ranges::RangeProducer, JobOptions, JobStatus,
};
use pdf::file::{Cache, NoLog, Storage};
use pdf::object::{ParseOptions, PlainRef};

struct SimpleCache<T>(RefCell<HashMap<PlainRef, T>>);

impl<T: Clone> SimpleCache<T> {
    fn new() -> Self {
        Self(RefCell::new(HashMap::new()))
    }
}

impl<T: Clone> Cache<T> for SimpleCache<T> {
    fn get_or_compute(&self, key: PlainRef, compute: impl FnOnce() -> T) -> T {
        let mut hash = self.0.borrow_mut();
        match hash.get(&key) {
            Some(value) => value.clone(),
            None => {
                let value = compute();
                hash.insert(key, value.clone());
                value
            }
        }
    }
}

fn workspace_path(relative: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(relative)
        .display()
        .to_string()
}

fn fixture_path(name: &str) -> String {
    workspace_path(&format!("crates/cracker/tests/fixtures/{name}"))
}

fn example_path(name: &str) -> String {
    workspace_path(&format!("examples/{name}"))
}

fn legacy_attempt(pdf_bytes: &[u8], password: &[u8]) -> bool {
    let mut storage = Storage::with_cache(
        pdf_bytes.to_vec(),
        ParseOptions::strict(),
        SimpleCache::new(),
        SimpleCache::new(),
        NoLog,
    )
    .expect("legacy storage should initialize for benchmark fixtures");
    storage.load_storage_and_trailer_password(password).is_ok()
}

fn bench_case(
    group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>,
    label: &str,
    path: &str,
) {
    let wrong = b"definitely-wrong-password";
    let prepared = PDFCracker::from_file(path).expect("prepared benchmark fixture should load");
    let mut prepared_state =
        PDFCrackerState::from_cracker(&prepared).expect("prepared benchmark state should build");
    let legacy_bytes = std::fs::read(path).expect("legacy benchmark fixture should be readable");

    group.bench_function(format!("prepared-{label}"), |b| {
        b.iter(|| prepared_state.attempt(wrong))
    });
    group.bench_function(format!("legacy-{label}"), |b| {
        b.iter(|| legacy_attempt(&legacy_bytes, wrong))
    });
}

fn bench_prepared_vs_legacy(c: &mut Criterion) {
    let mut synthetic_group = c.benchmark_group("prepared-verifier-vs-legacy-synthetic");
    bench_case(
        &mut synthetic_group,
        "r4-aes128-wrong-password",
        &fixture_path("r4-aes128.pdf"),
    );
    bench_case(
        &mut synthetic_group,
        "r5-aes256-wrong-password",
        &fixture_path("r5-aes256.pdf"),
    );
    bench_case(
        &mut synthetic_group,
        "r6-aes256-wrong-password",
        &fixture_path("r6-aes256.pdf"),
    );
    synthetic_group.finish();

    let mut parser_heavy_group = c.benchmark_group("prepared-verifier-vs-legacy-parser-heavy");
    bench_case(
        &mut parser_heavy_group,
        "default-query-r3-large-wrong-password",
        &example_path("default-query-1.pdf"),
    );
    bench_case(
        &mut parser_heavy_group,
        "datetime-r4-large-wrong-password",
        &example_path("datetime-15012000.pdf"),
    );
    parser_heavy_group.finish();
}

fn benchmark_engine_worker_scaling(c: &mut Criterion) {
    let cracker = PDFCracker::from_file(&fixture_path("mask-upper-digit.pdf"))
        .expect("engine scaling benchmark fixture should load");

    let mut group = c.benchmark_group("engine-worker-scaling");
    for workers in [1usize, 4usize] {
        group.bench_function(format!("mask-digit-exhaustion-workers-{workers}"), |b| {
            b.iter(|| {
                let mut options = JobOptions::new(workers);
                options.batch_size = 512;

                let result = crack_file_with_options(
                    cracker.clone(),
                    Box::new(
                        RangeProducer::try_new(4, 0, 9_999)
                            .expect("engine scaling producer should build"),
                    ),
                    options,
                    None,
                )
                .expect("engine scaling benchmark run should succeed");
                assert_eq!(result.status, JobStatus::Exhausted);
                assert_eq!(result.attempts, 10_000);
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_prepared_vs_legacy,
    benchmark_engine_worker_scaling
);
criterion_main!(benches);
