<div align="center">
  <h1><code>PDFRip</code></h1>
  <p><strong>A multi-threaded PDF password cracking utility equipped with commonly encountered password format builders and dictionary attacks.</strong></p>
</div>

## 📖 Table of Contents

- [Introduction](#%E2%84%B9%EF%B8%8F-introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contribution](#contribution)
- [License](#license)

## ℹ️ Introduction


**pdfrip** is a fast multithreaded PDF password cracking utility written in Rust with support for wordlist-based dictionary attacks, date, number range, and alphanumeric brute-forcing, and a custom query builder for password formats.

<div align="center">
  <table>
    <tr>
      <td><img height="300" width="400" src="screenshots/pdfrip-usage.gif"></td>
    </tr>
  </table>
</div>

## Features

- **Fast:** Performs about 50k-100k+ passwords per second utilizing full CPU cores.
- **Custom Query Builder:** You can write your own queries like `STRING{69-420}` which would generate and use a wordlist with the full number range.
- **Date Bruteforce:** You can pass in a year which would bruteforce all 365 days of the year in `DDMMYYYY` format which is a pretty commonly used password format for PDFs.
- **Number Bruteforce:** Just give a number range like `5000-100000` and it would bruteforce with the whole range.
- **Default Bruteforce:** Specify a maximum and optionally a minimum length for the password search and all passwords of length 4 up to the specified maximum consisting of letters and numbers (`a-zA-Z0-9`) will be tried

## Installation

Install with `cargo`:

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

    $ pdfrip -f encrypted.pdf wordlist rockyou.txt
    
Bruteforce number ranges for the password:

    $ pdfrip -f encrypted.pdf range 1000 9999
    
Bruteforce all dates in a span (inclusive in both ends) of years for the password in `DDMMYYYY` format:

    $ pdfrip -f encrypted.pdf date 1900 2000

Bruteforce arbitrary strings of length 4-8:

    $ pdfrip -f encrypted.pdf default-query --max-length 8

Bruteforce arbitrary strings of length 3:

    $ pdfrip -f encrypted.pdf default-query --max-length 3 --min-length 3

Build a custom query to generate a wordlist: (useful when you know the password format)

    $ pdfrip -f encrypted.pdf custom-query ALICE{1000-9999}

    $ pdfrip -f encrypted.pdf custom-query DOC-ID{0-99}-FILE

Enable preceding zeros for custom queries: (which would make `{10-5000}` to `{0010-5000}` matching the end range's digits)

    $ pdfrip -f encrypted.pdf custom-query ALICE{10-9999} --add-preceding-zeros

## Contribution

Ways to contribute:

- Suggest a feature
- Report a bug
- Fix something and open a pull request
- Help me document the code
- Spread the word

## License

Licensed under the MIT License, see <a href="https://github.com/mufeedvh/pdfrip/blob/master/LICENSE">LICENSE</a> for more information.
