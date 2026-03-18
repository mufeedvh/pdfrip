<div align="center">
  <h1><code>PDFRip</code></h1>
  <p><strong>A multithreaded PDF password cracker with prepared-verifier performance, structured search builders, and exact resume-aware progress.</strong></p>
</div>

## 📖 Table of Contents

- [Introduction](#%E2%84%B9%EF%B8%8F-introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contribution](#contribution)
- [License](#license)

## ℹ️ Introduction


**pdfrip** is a multithreaded PDF password cracking utility written in Rust with support for wordlist attacks, bounded masks, contains-word workflows, date and number generators, printable-ASCII brute-forcing, checkpoint/resume, and structured JSON output.

<div align="center">
  <table>
    <tr>
      <td><img height="300" width="400" src="screenshots/pdfrip-usage.gif"></td>
    </tr>
  </table>
</div>

## Features

- **Prepared verifier hot path:** Password attempts reuse a prepared security envelope instead of rebuilding general PDF parsing state on every try.
- **Exact progress accounting:** Progress is based on verified password attempts, not merely queued work.
- **Checkpoint + resume:** Cancel with <kbd>Ctrl</kbd>+<kbd>C</kbd>, save a checkpoint, and resume the same job later without replaying verified attempts.
- **Opt-in user-password-only fast mode:** Skip owner-password acceptance checks with `--user-password-only` when you only care about the document-opening password path.
- **JSON output:** Emit machine-readable results for automation with `--json`.
- **Custom Query Builder:** You can write your own queries like `STRING{69-420}` which would generate and use a wordlist with the full number range.
- **Mask Bruteforce:** Use bounded masks like `?u{4}?d{4}` or `DOC-?d{2,4}` to target structured passwords directly.
- **Contains-Word Bruteforce:** Require one of a set of known words while brute-forcing the remaining positions.
- **Date Bruteforce:** You can pass in a year range and an output format such as `DDMMYYYY`, `DD.MM.YYYY`, or `YYYY-MM-DD` to brute-force common date-shaped passwords.
- **Number Bruteforce:** Give an inclusive number range like `5000-100000` and PDFRip will try every value in that range.
- **Default Bruteforce:** Specify a maximum and optionally a minimum length for the password search and PDFRip will try every printable ASCII password in that span, including spaces, digits, letters, and punctuation.

## Installation

### Download

If you don't have cargo or rust installed, you can download a binary from the [release section](https://github.com/mufeedvh/pdfrip/releases/) and execute it.

### Install with `cargo`:

    $ cargo install --git https://github.com/mufeedvh/pdfrip.git

[Install Rust/Cargo](https://rust-lang.org/tools/install)

## Build From Source

**Prerequisites:**

* [Git](https://git-scm.org/downloads)
* [Rust](https://rust-lang.org/tools/install)
* Cargo (Automatically installed when installing Rust)
* A C linker (Only for Linux, generally comes pre-installed)

```
$ git clone https://github.com/mufeedvh/pdfrip.git
$ cd pdfrip/
$ cargo build --release
```

The first command clones this repository into your local machine and the last two commands enters the directory and builds the source in release mode.

## Usage

Get a list of all the arguments:

    $ pdfrip --help

Start a dictionary attack with a wordlist:

    $ pdfrip --file encrypted.pdf wordlist rockyou.txt

Bruteforce number ranges for the password:

    $ pdfrip --file encrypted.pdf range 1000 9999

Bruteforce all dates in an inclusive year span for passwords in `DDMMYYYY` format:

    $ pdfrip --file encrypted.pdf date 1900 2000

Bruteforce all dates in a custom format such as `DD.MM.YYYY`:

    $ pdfrip --file encrypted.pdf date --format DD.MM.YYYY 1900 2000

Bruteforce arbitrary strings of length 4-8:

    $ pdfrip --file encrypted.pdf default-query --max-length 8

Bruteforce arbitrary strings of length 3:

    $ pdfrip --file encrypted.pdf default-query --max-length 3 --min-length 3

Test an explicit blank password:

    $ pdfrip --file encrypted.pdf default-query --min-length 0 --max-length 0

Build a custom query to generate a wordlist: (useful when you know the password format)

    $ pdfrip --file encrypted.pdf custom-query ALICE{1000-9999}

    $ pdfrip --file encrypted.pdf custom-query DOC-ID{0-99}-FILE

Enable preceding zeros for custom queries: (which would make `{10-5000}` to `{0010-5000}` matching the end range's digits)

    $ pdfrip --file encrypted.pdf custom-query ALICE{10-9999} --add-preceding-zeros

Use a bounded mask for mixed uppercase/digit formats:

    $ pdfrip --file encrypted.pdf mask ?u{4}?d{4}

Require one of a set of known words while brute-forcing the remaining positions:

    $ pdfrip --file encrypted.pdf contains-word known-words.txt --min-length 8 --max-length 10 --fill-charset ascii

Tune workers and batching explicitly:

    $ pdfrip --threads 8 --batch-size 512 --file encrypted.pdf wordlist rockyou.txt

Emit machine-readable JSON:

    $ pdfrip --json --file encrypted.pdf custom-query ALICE{1-9999} --add-preceding-zeros

Only test the user/open password path when you do not want owner-password matches and want a faster R5/R6 search:

    $ pdfrip --user-password-only --file encrypted.pdf wordlist rockyou.txt

Save a checkpoint on cancellation and resume it later with the same cracking arguments:

    $ pdfrip --checkpoint alice.checkpoint.json --file encrypted.pdf custom-query ALICE{1-9999} --add-preceding-zeros
    $ pdfrip --resume alice.checkpoint.json --checkpoint alice.checkpoint.json --file encrypted.pdf custom-query ALICE{1-9999} --add-preceding-zeros

## Password Semantics

PDFRip targets the PDF Standard Security Handler's password-based user and owner passwords.

- Success output now distinguishes **user** and **owner** passwords when the encryption revision allows that classification.
- `--user-password-only` is an explicit opt-in fast mode that skips owner-password acceptance checks. It can be materially faster on R5/R6 workloads, but it will intentionally miss owner-only passwords.
- Blank passwords are rendered explicitly as `""` instead of looking like missing output.
- Wordlist attacks preserve blank lines, so a file containing an empty line can intentionally test an empty password.
- Permissions-password workflows are not a separate cracking mode in PDFRip; if a document uses the Standard Security Handler, PDFRip focuses on the document-opening passwords that actually gate access.
- Certificate/public-key encrypted PDFs are out of scope for pdfrip because they are not password-cracking workflows.

## Testing and Fixture Regeneration

The repository includes deterministic encrypted fixtures under `crates/cracker/tests/fixtures`.
They are generated with `qpdf` and validated with qpdf itself as the oracle.

To regenerate them on macOS:

    $ brew install qpdf
    $ bash crates/cracker/tests/fixtures/generate-verifier-fixtures.sh

The generated set currently covers:

- Standard Security Handler revisions R2 through R6
- blank user-password behavior
- Unicode R5/R6 passwords
- object-stream + xref-stream structure
- linearized files
- `EncryptMetadata=false` variants

## Performance Notes

The hot path no longer rebuilds `pdf::file::Storage` for each password attempt. Instead, PDFRip now:

- extracts the security envelope once
- prepares a direct password verifier once
- reuses worker-local candidate buffers for cloneable hot producers
- shards cloneable deterministic keyspaces across workers via contiguous range leasing
- batches work when a producer cannot be safely cloned for worker-local generation
- counts progress only after real verification work
- can optionally skip owner-password acceptance checks with `--user-password-only`

A reproducible benchmark harness lives at `benches/throughput.rs` and compares the prepared verifier
against the legacy per-attempt storage-loading path on both tiny synthetic fixtures and parser-heavier
bundled examples.

Representative local measurements on the current macOS development machine (`Apple M3 Pro`, `18 GB RAM`) showed:

| Workload | Prepared verifier | Legacy path | Relative result |
|---|---:|---:|---:|
| Synthetic R4 AES-128 wrong password | 49.495 µs | 54.012 µs | 1.1x lower latency |
| Synthetic R5 AES-256 wrong password | 563.22 ns | 8.7321 µs | 15.5x lower latency |
| Large bundled R3 `examples/default-query-1.pdf` wrong password | 47.802 µs | 215.590 µs | 4.5x lower latency |
| Bundled R4 `examples/datetime-15012000.pdf` wrong password | 53.684 µs | 92.326 µs | 1.7x lower latency |
| 10,000-candidate mask exhaustion, 1 worker | 500.33 ms | — | baseline |
| 10,000-candidate mask exhaustion, 4 workers | 145.13 ms | — | 3.4x faster than 1 worker |
| Tiny synthetic R6 AES-256 wrong password | 16.396 ms | 15.323 ms | KDF-bound / near parity in this run |

The recent CPU-side allocation reductions were most visible on R5-class workloads. Default-mode R6
remains mostly KDF-bound, which is why the new opt-in `--user-password-only` mode matters.

On wrong-password-heavy CLI runs whose correct answer is the **user** password, `--user-password-only`
can materially reduce end-to-end wall-clock time by skipping owner-password acceptance checks:

| Workload | Default mode | `--user-password-only` | Relative result |
|---|---:|---:|---:|
| R5 AES-256 fixture, 50,001-candidate wordlist ending in the user password | 18.01 ms | 13.76 ms | 1.31x faster |
| R6 AES-256 fixture, 129-candidate wordlist ending in the user password | 2.038 s | 0.735 s | 2.77x faster |
| R6 AES-256 Unicode fixture, 129-candidate wordlist ending in the user password | 2.102 s | 0.934 s | 2.25x faster |

Memory behavior also improved materially. On `examples/default-query-1.pdf` (`1,300,085` bytes), a 12-worker
prepared-state harness measured about `4.8 MB` maximum RSS, while an equivalent legacy harness that held
12 independent `pdf::file::Storage` instances measured about `18.7 MB` maximum RSS.

Profiling confirmed that the hot path no longer routes through general PDF storage loading. A macOS `sample`
trace of a tight wrong-password loop on `examples/default-query-1.pdf` still showed
`pdf::file::Storage::load_storage_and_trailer_password` in the legacy path, but not in the prepared path.

## Contribution

Ways to contribute:

- Suggest a feature
- Report a bug
- Fix something and open a pull request
- Help me document the code
- Spread the word

## License

Licensed under the MIT License, see <a href="https://github.com/mufeedvh/pdfrip/blob/master/LICENSE">LICENSE</a> for more information.
