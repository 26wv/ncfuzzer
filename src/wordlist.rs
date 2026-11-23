use anyhow::Result;
use memmap2::Mmap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Memory-mapped wordlist with an atomic cursor. `next()` is lock-free.
pub struct Wordlist {
    pub(crate) mmap: Mmap,
    pub(crate) total: u64,
    pub(crate) cursor: AtomicUsize,
    pub(crate) skipped: AtomicU64,
}

impl Wordlist {
    pub fn open(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        // SAFETY: the mapped file must not be truncated or concurrently mutated by another
        // process while this mapping is live; the caller owns the wordlist path and keeps it stable.
        let mmap = unsafe { Mmap::map(&file)? };
        let newlines = mmap.iter().filter(|&&b| b == b'\n').count() as u64;
        let trailing = u64::from(mmap.last().is_some_and(|&b| b != b'\n'));
        let total = newlines + trailing;
        Ok(Wordlist {
            mmap,
            total,
            cursor: AtomicUsize::new(0),
            skipped: AtomicU64::new(0),
        })
    }

    /// Raw line count of the file. The true number of yielded entries is
    /// `total() - skipped()`; the caller should use that when sizing the progress bar.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Count of lines `next()` discarded (empty or non-UTF-8).
    pub fn skipped(&self) -> u64 {
        self.skipped.load(Ordering::Relaxed)
    }

    /// Atomically advance to the next line. Returns the next entry (trimmed of `\r\n`)
    /// or `None` at EOF; skips empty and non-UTF-8 lines and counts them under `skipped()`.
    pub fn next(&self) -> Option<String> {
        loop {
            let start = self.cursor.load(Ordering::Relaxed);
            if start >= self.mmap.len() {
                return None;
            }
            let (end, next_start) = self.mmap[start..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or((self.mmap.len(), self.mmap.len()), |p| {
                    (start + p, start + p + 1)
                });
            if self
                .cursor
                .compare_exchange(start, next_start, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }
            let mut bytes = &self.mmap[start..end];
            if bytes.ends_with(b"\r") {
                bytes = &bytes[..bytes.len() - 1];
            }
            if bytes.is_empty() {
                self.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if let Ok(s) = std::str::from_utf8(bytes) {
                return Some(s.to_string());
            }
            self.skipped.fetch_add(1, Ordering::Relaxed);
        }
    }
}
