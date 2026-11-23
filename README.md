# ncfuzzer

Fast async TCP line-oracle fuzzer with persistent connections, auto-calibration, and a SQL-injection scan mode.

## Quickstart

    cargo install --git https://github.com/26wv/ncfuzzer

    ncfuzzer -h target -p 9000 -w words.txt

## Usage

Wordlist fuzzing with auto-calibrated oracle (startup probes learn the miss signature):

    ncfuzzer -h target -p 9000 -w words.txt

Explicit oracle, 128 workers, 500 attempts/sec, 10 s timeout, hits report:

    ncfuzzer -h 192.168.1.1 -p 4444 -w words.txt \
             -c 128 -r 500 -t 10 \
             -m 'login failed' -o hits.txt

Positive matcher (regex), CRLF, banner skip, prompt-bounded responses:

    ncfuzzer -h target -p 9000 -w words.txt \
             -M 're:^ok: \S+$' -e '\r\n' -b 2 -P '> '

Custom payload template; `FUZZ` is replaced per line, force-miss filters drop noise:

    ncfuzzer -h target -p 9000 -w words.txt \
             -d 'LOGIN admin FUZZ' -F 'rate limit' -F 're:^WARN'

SQLi scan — wordlist lines are fired as raw payloads after built-in probes:

    ncfuzzer -h target -p 9000 -w payloads.txt -s -S 5 -C 2

Zero-knowledge mode — baseline is a reply-shape fingerprint, no matcher given:

    ncfuzzer -h target -p 9000 -w words.txt -z

JSON Lines on stdout, verbose repro commands on stderr:

    ncfuzzer -h target -p 9000 -w words.txt -j -v

Flags: `-h/--host -p/--port -w/--wordlist -c/--concurrency -r/--rate -t/--timeout
-o/--output -j/--json -v/--verbose -m/--miss -M/--match -F/--filter -G/--no-calibrate
-g/--calibrate-samples -d/--send -e/--eol -P/--prompt -b/--banner
-s/--sqli -S/--sqli-sleep -C/--sqli-confirm -z/--zero-knowledge`. `--help` for details.

Patterns: `-M`, `-F`, `-P` take a literal substring by default; prefix `re:` for a
regex or `lit:` to force literal. `-b` takes an integer (line count to skip) or a
regex (consumed until matched).

## Features

- Persistent connection pool, N workers reuse their socket across attempts
- Auto-calibration learns the miss signature from random probes at startup
- Zero-knowledge mode detects hits as reply-shape deltas from a baseline
- SQLi scan: error / union / boolean / time channels, engine fingerprinting
- Rate limiting (`-r`), banner sync, prompt-bounded response framing
- Memory-mapped wordlist, streamed line reader
- Reproducible per-hit `printf ... | nc HOST PORT` command in the `-o` report
- Response sanitisation (control bytes → `\xNN`) so a hostile server can't inject terminal escapes

## Output

Stdout streams hits as `word<TAB>response` (or one JSON object per line with `-j`).
At end of run on stderr:

    Total hits: 42

The `-o` report starts with a `HITS:` header and one reproducible command per hit:

    HITS:
    admin - printf 'admin\n' | nc target 9000
    root  - printf 'root\n'  | nc target 9000

SQLi mode prints a grouped verdict block instead (empty case: `No injection points detected.`):

    HITS:
      [error]    engine: MySQL/MariaDB
                 wrapper: '<payload>
                 proof:   '                 (matched "SQL syntax" error)
                 appears to allow: mixed-case keywords, inline comments
      [boolean]  wrapper: ' OR <payload>-- -
                 proof:   ' AND 1=1 vs ' AND 1=2   (replies differed, 2/2)

## Version & dependencies

ncfuzzer 0.1.0. Rust 2021.

tokio, clap, anyhow, regex, governor, indicatif, memmap2, serde_json.
