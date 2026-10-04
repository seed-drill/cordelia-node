//! Local history: the text of a memory file as it was just before sync
//! replaced or removed it (decision 2026-09-30-agent-memory-sync §4.5b).
//!
//! One file a record, in `history/` under the node's data directory,
//! readable by the user alone: a line of JSON about the record, then the
//! text as it was. There is no index and no database: a record that cannot
//! be read is reported and the rest stand.
//!
//! A record's name is its id: the second it was written (8 hex digits),
//! the millisecond within it (3) and 3 random hex digits. So names sort
//! by age, a record that cannot be read still has an age, and an id from
//! the command line is checked for its shape before any path is made from
//! it. The store makes no other path from what a person or another device
//! supplies: agent and file names are inside the JSON.
//!
//! A record is written before the change it is for, as pending, and made
//! final once the change is made. A change that is not made takes its
//! pending record with it. Its text is flushed to the disk before the
//! change, as far as the volume can, and is read back only while it is
//! still the text that was kept.
//!
//! Texts are kept, and the store is swept or cleared, only by whoever
//! holds the turn (`History` in the API's state): a sync cycle, a restore,
//! a drop, the sweep. So a pending record that a sweep finds belongs to
//! no change in hand.

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use cordelia_core::protocol::HISTORY_SWEEP_SHARE;
use serde::{Deserialize, Serialize};

/// The directory, under the node's data directory.
const DIR: &str = "history";
/// A record whose change has not been made yet.
const PENDING: &str = ".pending";
/// A pending record found when the node started: its change may or may
/// not have been made.
const INTERRUPTED: &str = ".interrupted";

/// A record's id: 14 lower-case hex digits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id(String);

impl Id {
    /// An id as it was typed, if it has the shape of one. Anything else
    /// (a path, a longer or shorter word, another case) is no id, and is
    /// refused before a path is made from it.
    pub fn parse(text: &str) -> Option<Self> {
        let hex = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
        (text.len() == 14 && text.bytes().all(hex)).then(|| Self(text.to_string()))
    }

    fn new(now: DateTime<Utc>) -> Self {
        let seconds = now.timestamp().clamp(0, u32::MAX as i64) as u32;
        // To the millisecond: two records of one file made in one second
        // are listed in the order they were made.
        let millis = now.timestamp_subsec_millis().min(999);
        let random = uuid::Uuid::new_v4();
        let random = u16::from_be_bytes([random.as_bytes()[0], random.as_bytes()[1]]) & 0xfff;
        Self(format!("{seconds:08x}{millis:03x}{random:03x}"))
    }

    /// The second the record was written, by this device's clock.
    fn written(&self) -> i64 {
        i64::from_str_radix(&self.0[..8], 16).unwrap_or(0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What changed a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// A version from another device replaced the file here.
    Pulled,
    /// A delete from another device removed the file here.
    Removed,
    /// Two index files were merged.
    Merged,
    /// An edit made here replaced the channel's version.
    EditedHere,
    /// A delete made here removed it from the channel.
    DeletedHere,
    /// A restore replaced the file here.
    Restored,
    /// A file arrived that was not here. No text is kept.
    Arrived,
}

/// A device's entry for a file: who wrote it, and at which revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The device's public key, as it is shown.
    pub device: String,
    pub rev: u64,
}

/// Whose text a record keeps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Whose {
    /// This device's file, with the revision it had last agreed with the
    /// channel. `None`: it had agreed none, or the record is of what a
    /// restore replaced, which does not look.
    Here { agreed: Option<u64> },
    /// The channel's version.
    Channel(Entry),
}

/// What took the kept text's place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Replacement {
    /// An entry: another device's, or the one this device published.
    Entry(Entry),
    /// The text of another record, put back by a restore.
    Record(String),
    /// Nothing: the file was removed.
    Nothing,
}

/// The text a record keeps, without the text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kept {
    pub whose: Whose,
    /// SHA-256 of the text, in hex: records with one text are found by it.
    pub sha256: String,
}

/// What a record says about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct About {
    /// When it was written, by this device's clock (RFC 3339). Set when
    /// the record is kept.
    #[serde(default)]
    pub at: String,
    /// The name the folder syncs under.
    pub agent: String,
    /// The memory folder the file is in.
    pub folder: String,
    pub file: String,
    pub change: Change,
    /// The text that is kept, or `None` where there was none to keep.
    pub kept: Option<Kept>,
    pub replaced_by: Replacement,
    /// This device's file was behind what replaced it: the kept text is
    /// the version this device had agreed, and the one that took its place
    /// was written after it. Another device may hold a newer copy.
    #[serde(default)]
    pub behind: bool,
}

/// A record as it is listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: Id,
    pub about: About,
    /// It was pending when the node started: its change may or may not
    /// have been made.
    pub interrupted: bool,
    /// The size of the record's file.
    pub bytes: u64,
}

/// What the store holds.
#[derive(Debug, Default)]
pub struct Listing {
    /// Newest first.
    pub records: Vec<Record>,
    /// Records that cannot be read, by id. They count towards the size,
    /// and go when they are old, like the rest.
    pub unreadable: Vec<Id>,
    /// The size of every record's file, readable or not.
    pub bytes: u64,
}

/// What a sweep removed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// Records older than the age kept.
    pub aged: usize,
    /// Records removed, oldest first, to bring the store under its size.
    pub over: usize,
    /// What was to go and could not be removed. It is passed over, and
    /// the sweep goes on.
    pub failed: usize,
}

/// What starting history did ([`Store::start`]).
#[derive(Debug)]
pub enum Start {
    /// History is off, and what was kept was removed, or could not be.
    Off(std::io::Result<()>),
    /// History is on.
    On {
        store: Store,
        /// How many records were pending when the node last stopped, and
        /// are now marked; or why the directory cannot be used.
        interrupted: std::io::Result<usize>,
        /// What was too old or over the size, and went.
        swept: std::io::Result<Swept>,
    },
}

/// A record written ahead of its change. It is removed again when this is
/// dropped, unless the change was made and [`Store::settle`] called.
#[derive(Debug)]
pub struct Pending {
    id: Id,
    path: PathBuf,
    settled: bool,
}

impl Pending {
    pub fn id(&self) -> &Id {
        &self.id
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if !self.settled {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// The history kept on this device.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
    keep_secs: i64,
    max_bytes: u64,
    /// The bytes kept since the store was last swept, in every copy of
    /// this store.
    grown: Arc<AtomicU64>,
}

/// A record's file name, taken apart: its id, and whether it is pending or
/// was interrupted. `None` for a file that is not a record's.
fn record_name(name: &str) -> Option<(Id, &str)> {
    let (id, state) = match name.len() {
        14 => (name, ""),
        _ => name.split_at_checked(14)?,
    };
    matches!(state, "" | PENDING | INTERRUPTED).then_some(())?;
    Some((Id::parse(id)?, state))
}

impl Store {
    /// The history under `home`, kept for `days` and up to `max_bytes`.
    /// With `days` at 0 history is off, and there is no store.
    ///
    /// Nothing is touched on disk. A store whose directory cannot be made
    /// is still a store: it keeps nothing, so no change that needs a text
    /// kept is made, and each says why.
    pub fn new(home: &Path, days: u32, max_bytes: u64) -> Option<Self> {
        (days > 0).then(|| Self {
            dir: home.join(DIR),
            keep_secs: i64::from(days) * 24 * 60 * 60,
            max_bytes,
            grown: Arc::default(),
        })
    }

    /// Set history up as the node starts, before anything else uses it.
    /// Turned off, what was kept is removed. Otherwise the records that
    /// were pending when the node last stopped are marked, and what is
    /// too old or over the size is dropped.
    ///
    /// A store whose directory cannot be prepared is still a store: it
    /// keeps nothing, so no change that needs a text kept is made.
    pub fn start(home: &Path, days: u32, max_bytes: u64, now: DateTime<Utc>) -> Start {
        let Some(store) = Self::new(home, days, max_bytes) else {
            return Start::Off(Self::turn_off(home));
        };
        let interrupted = store.prepare().and_then(|()| store.recover());
        let swept = store.sweep(now);
        Start::On {
            store,
            interrupted,
            swept,
        }
    }

    /// How many days a record is kept.
    pub fn days(&self) -> u32 {
        (self.keep_secs / (24 * 60 * 60)) as u32
    }

    /// The most the store holds, in bytes.
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// History is turned off: remove what was kept under `home`.
    pub fn turn_off(home: &Path) -> std::io::Result<()> {
        match std::fs::remove_dir_all(home.join(DIR)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// Make the directory, readable by the user alone.
    pub fn prepare(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    /// Keep `text` (or the fact that there was none) with what is said
    /// `about` it, as a pending record. An error means nothing was kept,
    /// and the change it was for is then not to be made.
    pub fn keep(
        &self,
        about: About,
        text: Option<&str>,
        now: DateTime<Utc>,
    ) -> std::io::Result<Pending> {
        self.keep_as(about, text, now, &mut || Id::new(now))
    }

    /// [`Store::keep`], with where a record's id comes from: [`Id::new`],
    /// except in a test.
    fn keep_as(
        &self,
        mut about: About,
        text: Option<&str>,
        now: DateTime<Utc>,
        draw: &mut dyn FnMut() -> Id,
    ) -> std::io::Result<Pending> {
        // Made when the node starts; made here if it has gone since.
        if !self.dir.is_dir() {
            self.prepare()?;
        }
        about.at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        // The hash a record carries is of the text it holds: it is read
        // back by it.
        if let (Some(kept), Some(text)) = (about.kept.as_mut(), text) {
            kept.sha256 = hash_of(text.as_bytes());
        }
        let mut line = serde_json::to_vec(&about).map_err(std::io::Error::other)?;
        line.push(b'\n');
        // A name that is taken (two records in one millisecond with the
        // same random digits) is drawn again.
        for _ in 0..16 {
            let id = draw();
            let path = self.dir.join(format!("{id}{PENDING}"));
            let taken = self.dir.join(id.as_str()).exists()
                || self.dir.join(format!("{id}{INTERRUPTED}")).exists();
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = match options.open(&path) {
                Ok(file) if !taken => file,
                Ok(_) => {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            };
            // From here the record is removed again unless it is settled.
            let pending = Pending {
                id,
                path,
                settled: false,
            };
            file.write_all(&line)?;
            file.write_all(text.unwrap_or_default().as_bytes())?;
            // On the disk before the change it is for is made: the change
            // flushes the new text, and if the power went between the two
            // the old one would otherwise be the copy that is lost.
            crate::atomic::flush(&file)?;
            let bytes = line.len() + text.map_or(0, str::len);
            self.grown.fetch_add(bytes as u64, Ordering::Relaxed);
            return Ok(pending);
        }
        Err(std::io::Error::other("no free name for a history record"))
    }

    /// The change a pending record was written for has been made: the
    /// record stands.
    pub fn settle(&self, mut pending: Pending) -> std::io::Result<Id> {
        // The change was made, so the text stays whatever becomes of the
        // rename: left pending, it is found and marked at the next start.
        pending.settled = true;
        std::fs::rename(&pending.path, self.dir.join(pending.id.as_str()))?;
        Ok(pending.id.clone())
    }

    /// Mark the pending records that belong to no change in hand: the
    /// node stopped between keeping the text and finishing the change, or
    /// a record could not be made final, so the change may or may not
    /// have been made. Returns how many were marked. One that cannot be
    /// marked is left, and the rest are.
    pub fn recover(&self) -> std::io::Result<usize> {
        let mut found = 0;
        for name in self.names()? {
            if let Some((id, PENDING)) = record_name(&name) {
                let marked = self.dir.join(format!("{id}{INTERRUPTED}"));
                match std::fs::rename(self.dir.join(&name), marked) {
                    Ok(()) => found += 1,
                    Err(error) => {
                        tracing::warn!(record = %id, %error, "a pending history record could not be marked")
                    }
                }
            }
        }
        Ok(found)
    }

    /// The names in the directory, sorted: oldest record first. A
    /// directory that is not there holds none.
    fn names(&self) -> std::io::Result<Vec<String>> {
        let mut names = Vec::new();
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(names),
            Err(e) => return Err(e),
        };
        for entry in entries {
            names.push(entry?.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        Ok(names)
    }

    /// Where a record that stands is: final, or interrupted. A pending
    /// record is not yet one.
    fn path_of(&self, id: &Id) -> Option<(PathBuf, bool)> {
        let done = self.dir.join(id.as_str());
        let interrupted = self.dir.join(format!("{id}{INTERRUPTED}"));
        if done.is_file() {
            Some((done, false))
        } else {
            interrupted.is_file().then_some((interrupted, true))
        }
    }

    /// Every record, newest first, with those that cannot be read and the
    /// size of all of them.
    pub fn list(&self) -> std::io::Result<Listing> {
        let mut listing = Listing::default();
        for name in self.names()?.into_iter().rev() {
            let Some((id, state)) = record_name(&name) else {
                continue;
            };
            let path = self.dir.join(&name);
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            listing.bytes += meta.len();
            if state == PENDING {
                continue;
            }
            match read_about(&path) {
                Some(about) => listing.records.push(Record {
                    id,
                    about,
                    interrupted: state == INTERRUPTED,
                    bytes: meta.len(),
                }),
                None => listing.unreadable.push(id),
            }
        }
        Ok(listing)
    }

    /// One record with its text (`None` where it keeps none), or `None`
    /// if there is no such record. A record that cannot be read is an
    /// error, and so is one whose text is not the text that was kept (it
    /// was cut short, or changed on the disk): it is not shown or
    /// restored as that text.
    pub fn read(&self, id: &Id) -> std::io::Result<Option<(Record, Option<String>)>> {
        let Some((path, interrupted)) = self.path_of(id) else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        std::fs::File::open(&path)?.read_to_end(&mut bytes)?;
        let damaged = |why: &str| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("record {id} {why}"),
            )
        };
        let unreadable = || damaged("cannot be read");
        let end = bytes
            .iter()
            .position(|b| *b == b'\n')
            .ok_or_else(unreadable)?;
        let about: About = serde_json::from_slice(&bytes[..end]).map_err(|_| unreadable())?;
        let text = match &about.kept {
            Some(kept) => {
                let text = &bytes[end + 1..];
                if hash_of(text) != kept.sha256 {
                    return Err(damaged("no longer holds the text that was kept"));
                }
                Some(String::from_utf8(text.to_vec()).map_err(|_| unreadable())?)
            }
            None => None,
        };
        let record = Record {
            id: id.clone(),
            about,
            interrupted,
            bytes: bytes.len() as u64,
        };
        Ok(Some((record, text)))
    }

    /// Remove records from this device. Returns how many there were.
    pub fn remove(&self, ids: &[Id]) -> std::io::Result<usize> {
        let mut removed = 0;
        for id in ids {
            if let Some((path, _)) = self.path_of(id) {
                std::fs::remove_file(path)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Remove what is older than the age kept, then, while the store is
    /// over its size, the oldest records, whatever file they are of.
    /// Records that cannot be read go by the same rules: their age is in
    /// their name. What cannot be removed is counted and passed over.
    ///
    /// Whoever sweeps holds the turn, or runs before anything else does,
    /// so no change is in hand: a pending record was left behind, and is
    /// marked first.
    pub fn sweep(&self, now: DateTime<Utc>) -> std::io::Result<Swept> {
        self.grown.store(0, Ordering::Relaxed);
        self.recover()?;
        let mut swept = Swept::default();
        // Oldest first: its size, and whether it was to go and could not.
        let mut held: Vec<(PathBuf, u64, bool)> = Vec::new();
        for name in self.names()? {
            let Some((id, _)) = record_name(&name) else {
                continue;
            };
            let path = self.dir.join(&name);
            let aged = id.written() + self.keep_secs <= now.timestamp();
            if aged && std::fs::remove_file(&path).is_ok() {
                swept.aged += 1;
                continue;
            }
            if aged {
                swept.failed += 1;
            }
            let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            held.push((path, bytes, aged));
        }
        let mut total: u64 = held.iter().map(|(_, bytes, _)| bytes).sum();
        for (path, bytes, stuck) in held {
            if total <= self.max_bytes {
                break;
            }
            if stuck {
                continue;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    total -= bytes;
                    swept.over += 1;
                }
                Err(_) => swept.failed += 1,
            }
        }
        Ok(swept)
    }

    /// Whether enough has been kept since the store was last swept that
    /// it is swept again before its hour is up: more than one part in
    /// [`HISTORY_SWEEP_SHARE`] of the most it holds. So what the store
    /// holds passes its size by that much and by what one cycle keeps,
    /// and by no more.
    pub fn has_grown(&self) -> bool {
        self.grown.load(Ordering::Relaxed) > self.max_bytes / HISTORY_SWEEP_SHARE
    }

    /// Remove every record: `history drop --all`. Whoever clears holds
    /// the turn, so a pending record is one left behind, and goes too.
    pub fn clear(&self) -> std::io::Result<usize> {
        let mut removed = 0;
        for name in self.names()? {
            if record_name(&name).is_some() {
                std::fs::remove_file(self.dir.join(&name))?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// The hash a record carries of its text, in hex.
fn hash_of(text: &[u8]) -> String {
    hex::encode(cordelia_crypto::sha256(text))
}

/// The line of JSON a record starts with, if it can be read.
fn read_about(path: &Path) -> Option<About> {
    let file = std::fs::File::open(path).ok()?;
    let mut line = Vec::new();
    std::io::BufReader::new(file)
        .read_until(b'\n', &mut line)
        .ok()?;
    serde_json::from_slice(&line).ok()
}

/// What is said of a text that is about to be kept: whose it is, and the
/// hash it is found by.
pub fn kept(whose: Whose, text: &str) -> Kept {
    Kept {
        whose,
        sha256: hash_of(text.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + seconds, 0).unwrap()
    }

    const DAY: i64 = 24 * 60 * 60;

    fn about(file: &str, text: Option<&str>) -> About {
        About {
            at: String::new(),
            agent: "team".into(),
            folder: "/home/sam/.claude/projects/-home-sam/memory".into(),
            file: file.into(),
            change: if text.is_some() {
                Change::Pulled
            } else {
                Change::Arrived
            },
            kept: text.map(|t| kept(Whose::Here { agreed: Some(4) }, t)),
            replaced_by: Replacement::Entry(Entry {
                device: "cordelia_pk1other".into(),
                rev: 5,
            }),
            behind: text.is_some(),
        }
    }

    fn store(dir: &Path) -> Store {
        Store::new(dir, 30, 1 << 20).unwrap()
    }

    /// Keep a text and make its record final.
    fn keep(s: &Store, file: &str, text: Option<&str>, when: DateTime<Utc>) -> Id {
        let pending = s.keep(about(file, text), text, when).unwrap();
        s.settle(pending).unwrap()
    }

    fn aged(aged: usize) -> Swept {
        Swept {
            aged,
            ..Default::default()
        }
    }

    fn over(over: usize) -> Swept {
        Swept {
            over,
            ..Default::default()
        }
    }

    fn is_damaged<T: std::fmt::Debug>(read: std::io::Result<T>) -> bool {
        read.is_err_and(|e| e.kind() == std::io::ErrorKind::InvalidData)
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir.join(DIR))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn test_a_text_is_kept_and_read_back_as_it_was() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        // Several lines, no line at all, an empty file, and no text.
        let texts = [
            Some("one\ntwo\n\nthree"),
            Some("{\"not\": \"the header\"}\n"),
            Some(""),
            None,
        ];
        for (n, text) in texts.into_iter().enumerate() {
            let id = keep(&s, "notes.md", text, at(n as i64));
            let (record, read) = s.read(&id).unwrap().unwrap();
            assert_eq!(read.as_deref(), text, "{n}");
            assert_eq!(record.about.file, "notes.md");
            assert_eq!(
                record.about.at,
                at(n as i64).to_rfc3339().replace("+00:00", "Z")
            );
            assert_eq!(record.about.kept.is_some(), text.is_some());
            assert!(!record.interrupted);
        }
        // Listed newest first, with what each says, and their size.
        let listing = s.list().unwrap();
        let kept: Vec<bool> = listing
            .records
            .iter()
            .map(|r| r.about.kept.is_some())
            .collect();
        assert_eq!(kept, [false, true, true, true]);
        assert!(listing.unreadable.is_empty());
        let on_disk: u64 = files(tmp.path())
            .iter()
            .map(|n| {
                std::fs::metadata(tmp.path().join(DIR).join(n))
                    .unwrap()
                    .len()
            })
            .sum();
        assert_eq!(listing.bytes, on_disk);
        assert_eq!(
            listing.records.iter().map(|r| r.bytes).sum::<u64>(),
            on_disk
        );
    }

    /// The directory and every record are for the user alone.
    #[cfg(unix)]
    #[test]
    fn test_history_is_readable_by_the_user_alone() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        // A directory that is already there, and open, is closed.
        std::fs::create_dir(tmp.path().join(DIR)).unwrap();
        std::fs::set_permissions(tmp.path().join(DIR), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let s = store(tmp.path());
        s.prepare().unwrap();
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(tmp.path().join(DIR)), 0o700);
        let pending = s.keep(about("a.md", Some("x")), Some("x"), at(0)).unwrap();
        assert_eq!(mode(pending.path.clone()), 0o600);
        let id = s.settle(pending).unwrap();
        assert_eq!(mode(tmp.path().join(DIR).join(id.as_str())), 0o600);
    }

    /// A record is written before its change and stands only if the change
    /// is made. One whose change is not made goes, however that comes
    /// about; one found at start is kept and marked.
    #[test]
    fn test_a_record_stands_only_if_its_change_was_made() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());

        // Pending: on disk, and not yet a record.
        let pending = s.keep(about("a.md", Some("x")), Some("x"), at(0)).unwrap();
        let id = pending.id().clone();
        assert_eq!(files(tmp.path()), [format!("{id}.pending")]);
        assert!(s.list().unwrap().records.is_empty());
        assert!(s.read(&id).unwrap().is_none());
        assert_eq!(s.remove(std::slice::from_ref(&id)).unwrap(), 0);

        // The change is not made: the record goes with it.
        drop(pending);
        assert!(files(tmp.path()).is_empty());

        // The change is made: it stands.
        let id = keep(&s, "a.md", Some("x"), at(1));
        assert_eq!(files(tmp.path()), [id.to_string()]);

        // The node stops between the two: at its next start the record is
        // kept, and says so.
        let pending = s.keep(about("b.md", Some("y")), Some("y"), at(2)).unwrap();
        let stopped = pending.id().clone();
        std::mem::forget(pending);
        assert_eq!(s.recover().unwrap(), 1);
        assert_eq!(s.recover().unwrap(), 0);
        let (record, text) = s.read(&stopped).unwrap().unwrap();
        assert!(record.interrupted);
        assert_eq!(text.as_deref(), Some("y"));
        let listed: Vec<(Id, bool)> = s
            .list()
            .unwrap()
            .records
            .into_iter()
            .map(|r| (r.id, r.interrupted))
            .collect();
        assert_eq!(listed, [(stopped.clone(), true), (id.clone(), false)]);
        assert_eq!(s.remove(&[stopped, id]).unwrap(), 2);
        assert!(files(tmp.path()).is_empty());
    }

    /// An id is 14 hex digits and nothing else: what a person types never
    /// becomes a path unless it has that shape.
    #[test]
    fn test_only_an_id_is_looked_up() {
        assert!(Id::parse("6b49d2000a1b2c").is_some());
        for not in [
            "",
            "6b49d2000a1b2",
            "6b49d2000a1b2c0",
            "6B49D2000A1B2C",
            "../../etc/pass",
            "6b49d200/a1b2c",
            "6b49d2000a1b2g",
            "6b49d2000a1b2c.pending",
        ] {
            assert!(Id::parse(not).is_none(), "{not}");
        }
        // The names the store reads as records, and those it leaves.
        assert!(record_name("6b49d2000a1b2c").is_some());
        assert!(record_name("6b49d2000a1b2c.pending").is_some());
        assert!(record_name("6b49d2000a1b2c.interrupted").is_some());
        for not in [
            "6b49d2000a1b2c.bak",
            "notes.md",
            ".6b49d2000a1b2c",
            "é6b49d2000a1b2",
        ] {
            assert!(record_name(not).is_none(), "{not}");
        }
    }

    /// A record goes 30 days after it was written, and not before.
    #[test]
    fn test_a_record_is_dropped_when_it_is_old() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let old = keep(&s, "a.md", Some("old"), at(0));
        let newer = keep(&s, "a.md", Some("newer"), at(DAY));

        assert_eq!(s.sweep(at(30 * DAY - 1)).unwrap(), Swept::default());
        assert_eq!(s.list().unwrap().records.len(), 2);
        assert_eq!(s.sweep(at(30 * DAY)).unwrap(), aged(1));
        assert!(s.read(&old).unwrap().is_none());
        assert!(s.read(&newer).unwrap().is_some());
        assert_eq!(s.sweep(at(31 * DAY)).unwrap(), aged(1));
        assert!(files(tmp.path()).is_empty());
    }

    /// Over its size the store drops the oldest records first, whatever
    /// file they are of, until it is within it.
    #[test]
    fn test_the_oldest_records_go_when_the_store_is_over_its_size() {
        let tmp = tempfile::tempdir().unwrap();
        let text = "x".repeat(1000);
        let s = Store::new(tmp.path(), 30, 4000).unwrap();
        let ids: Vec<Id> = ["a.md", "b.md", "a.md"]
            .iter()
            .enumerate()
            .map(|(n, file)| keep(&s, file, Some(&text), at(n as i64)))
            .collect();
        assert_eq!(s.sweep(at(10)).unwrap(), Swept::default());

        // Two more take it over: the two oldest go, of two different files.
        let more: Vec<Id> = (3..5)
            .map(|n| keep(&s, "c.md", Some(&text), at(n)))
            .collect();
        assert!(s.list().unwrap().bytes > 4000);
        assert_eq!(s.sweep(at(10)).unwrap(), over(2));
        let left: Vec<Id> = s
            .list()
            .unwrap()
            .records
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(left, [more[1].clone(), more[0].clone(), ids[2].clone()]);
        assert!(s.list().unwrap().bytes <= 4000);
    }

    /// A record that cannot be read is reported, and the rest stand. It
    /// counts towards the size, and it goes when it is old.
    #[test]
    fn test_a_record_that_cannot_be_read_is_counted_and_aged() {
        let tmp = tempfile::tempdir().unwrap();
        let s = Store::new(tmp.path(), 30, 3000).unwrap();
        let good = keep(&s, "a.md", Some("kept"), at(5));
        let damaged = Id::new(at(0));
        let junk = vec![0xffu8; 2500];
        std::fs::write(tmp.path().join(DIR).join(damaged.as_str()), &junk).unwrap();
        // Something that is no record's is left alone throughout.
        std::fs::write(tmp.path().join(DIR).join("README"), "not a record").unwrap();

        let listing = s.list().unwrap();
        assert_eq!(listing.unreadable, std::slice::from_ref(&damaged));
        assert_eq!(listing.records.len(), 1);
        assert!(listing.bytes > 2500);
        assert!(is_damaged(s.read(&damaged)));
        assert_eq!(s.read(&good).unwrap().unwrap().1.as_deref(), Some("kept"));

        // Its size counts: a record that takes the store over sends the
        // oldest out, and that is the damaged one.
        let text = "x".repeat(600);
        keep(&s, "b.md", Some(&text), at(6));
        assert_eq!(s.sweep(at(10)).unwrap(), over(1));
        assert!(s.list().unwrap().unreadable.is_empty());

        // And its age: another, a day older than the rest, goes first.
        std::fs::write(
            tmp.path().join(DIR).join(Id::new(at(-DAY)).as_str()),
            &junk[..10],
        )
        .unwrap();
        assert_eq!(s.sweep(at(29 * DAY)).unwrap(), aged(1));
        assert_eq!(s.list().unwrap().records.len(), 2);
        assert_eq!(files(tmp.path()).len(), 3, "the two records and the README");
    }

    /// Whoever sweeps or clears holds the turn, so a pending record that
    /// is found then belongs to no change in hand: it could not be made
    /// final, or could not be taken back. A sweep marks it, and it is
    /// then listed, aged and counted like any other; clearing removes it.
    #[test]
    fn test_a_record_left_pending_is_marked_by_a_sweep_and_cleared() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let left = |when: DateTime<Utc>| {
            let pending = s.keep(about("a.md", Some("left")), Some("left"), when);
            let pending = pending.unwrap();
            let id = pending.id().clone();
            std::mem::forget(pending);
            id
        };
        let id = left(at(0));
        assert!(s.list().unwrap().records.is_empty());
        assert_eq!(s.sweep(at(1)).unwrap(), Swept::default());
        let listed = s.list().unwrap().records;
        assert_eq!(listed.len(), 1);
        assert!(listed[0].interrupted);
        assert_eq!(s.read(&id).unwrap().unwrap().1.as_deref(), Some("left"));
        // It ages with the rest.
        assert_eq!(s.sweep(at(30 * DAY)).unwrap(), aged(1));
        assert!(files(tmp.path()).is_empty());

        // Clearing takes one that no sweep has marked yet.
        left(at(31 * DAY));
        keep(&s, "b.md", Some("x"), at(31 * DAY));
        assert_eq!(s.clear().unwrap(), 2);
        assert!(files(tmp.path()).is_empty());
    }

    /// Two records made in one second are listed in the order they were
    /// made: an id says when to the millisecond.
    #[test]
    fn test_records_made_in_one_second_keep_their_order() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let when = |millis: i64| at(0) + chrono::Duration::milliseconds(millis);
        // Enough of them, in one second, that chance would not order them.
        let ids: Vec<Id> = [
            1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 999, 1000,
        ]
        .iter()
        .map(|millis| keep(&s, "a.md", Some("x"), when(*millis)))
        .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(sorted, ids);
        let listed: Vec<Id> = s
            .list()
            .unwrap()
            .records
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(listed, ids.into_iter().rev().collect::<Vec<Id>>());
        // The age is still read from the first eight digits.
        assert_eq!(Id::new(when(999)).written(), at(0).timestamp());
        assert_eq!(Id::new(when(1000)).written(), at(1).timestamp());
    }

    /// A record whose name is taken is given another: no record is
    /// written over, whether it stands, was interrupted or is pending.
    #[test]
    fn test_a_name_that_is_taken_is_drawn_again() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let stands = keep(&s, "a.md", Some("stands"), at(0));
        let pending = s
            .keep(about("b.md", Some("in hand")), Some("in hand"), at(0))
            .unwrap();
        let marked = s
            .keep(about("c.md", Some("marked")), Some("marked"), at(0))
            .unwrap();
        let (in_hand, interrupted) = (pending.id().clone(), marked.id().clone());
        std::fs::rename(
            &marked.path,
            tmp.path()
                .join(DIR)
                .join(format!("{interrupted}{INTERRUPTED}")),
        )
        .unwrap();
        std::mem::forget(marked);

        let free = Id::parse("6b49d200000abc").unwrap();
        let mut drawn = vec![
            free.clone(),
            interrupted.clone(),
            in_hand.clone(),
            stands.clone(),
        ];
        let new = s
            .keep_as(about("d.md", Some("new")), Some("new"), at(0), &mut || {
                drawn.pop().unwrap()
            })
            .unwrap();
        assert_eq!(new.id(), &free);
        assert!(drawn.is_empty());
        let id = s.settle(new).unwrap();
        let text = |id: &Id| s.read(id).unwrap().unwrap().1;
        assert_eq!(text(&id).as_deref(), Some("new"));
        assert_eq!(text(&stands).as_deref(), Some("stands"));
        assert_eq!(text(&interrupted).as_deref(), Some("marked"));
        let in_hand = s.settle(pending).unwrap();
        assert_eq!(text(&in_hand).as_deref(), Some("in hand"));

        // With no free name in sixteen draws, nothing is kept.
        let none = s.keep_as(about("e.md", Some("x")), Some("x"), at(0), &mut || {
            stands.clone()
        });
        assert!(none.is_err());
        assert_eq!(files(tmp.path()).len(), 4);
    }

    /// A record is read back only while it holds the text that was kept.
    /// One that was cut short, or changed on the disk, is not shown or
    /// restored as that text. It is still listed, and goes when it is old.
    #[test]
    fn test_a_record_whose_text_is_not_the_one_kept_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let id = keep(
            &s,
            "a.md",
            Some(
                "the text as it was
",
            ),
            at(0),
        );
        let path = tmp.path().join(DIR).join(id.as_str());
        let whole = std::fs::read(&path).unwrap();

        std::fs::write(&path, &whole[..whole.len() - 4]).unwrap();
        assert!(is_damaged(s.read(&id)));
        let mut changed = whole.clone();
        *changed.last_mut().unwrap() = b'!';
        std::fs::write(&path, &changed).unwrap();
        assert!(is_damaged(s.read(&id)));
        // With no line about it at all.
        std::fs::write(&path, "no newline").unwrap();
        assert!(is_damaged(s.read(&id)));

        std::fs::write(&path, &changed).unwrap();
        assert_eq!(s.list().unwrap().records.len(), 1);
        std::fs::write(&path, &whole).unwrap();
        let text = s.read(&id).unwrap().unwrap().1;
        assert_eq!(
            text.as_deref(),
            Some(
                "the text as it was
"
            )
        );

        // The hash is the store's own, whatever it was handed.
        let mut said = about("b.md", Some("x"));
        said.kept.as_mut().unwrap().sha256 = "00".repeat(32);
        let pending = s.keep(said, Some("x"), at(1)).unwrap();
        let id = s.settle(pending).unwrap();
        let (record, text) = s.read(&id).unwrap().unwrap();
        assert_eq!(text.as_deref(), Some("x"));
        assert_eq!(
            record.about.kept.unwrap().sha256,
            kept(Whose::Here { agreed: None }, "x").sha256
        );
    }

    /// What a sweep cannot remove does not stop it: the rest still go.
    #[test]
    fn test_a_sweep_goes_on_past_what_it_cannot_remove() {
        let tmp = tempfile::tempdir().unwrap();
        // Large beside whatever size a directory is said to have.
        let text = "x".repeat(100_000);
        let s = Store::new(tmp.path(), 30, 250_000).unwrap();
        s.prepare().unwrap();
        // A directory under a record's name, older than every record:
        // it cannot be removed as a file.
        let stuck = tmp.path().join(DIR).join(Id::new(at(-DAY)).as_str());
        std::fs::create_dir(&stuck).unwrap();
        let old = keep(&s, "a.md", Some(&text), at(0));
        let newer: Vec<Id> = (1..4)
            .map(|n| keep(&s, "b.md", Some(&text), at(DAY + n)))
            .collect();

        // By age: the directory is to go and cannot, and the record after
        // it goes.
        let swept = s.sweep(at(30 * DAY)).unwrap();
        assert_eq!((swept.aged, swept.failed), (1, 1));
        assert!(s.read(&old).unwrap().is_none());
        assert!(stuck.is_dir());
        // By size: one of the three goes, the oldest.
        assert_eq!(swept.over, 1);
        let left: Vec<Id> = s
            .list()
            .unwrap()
            .records
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(left, [newer[2].clone(), newer[1].clone()]);
    }

    /// The store says when enough has been kept since it was last swept
    /// that it should be swept again: more than an eighth of what it may
    /// hold. Every copy of the store counts as one.
    #[test]
    fn test_a_store_that_has_grown_says_so_until_it_is_swept() {
        let tmp = tempfile::tempdir().unwrap();
        let s = Store::new(tmp.path(), 30, 16_000).unwrap();
        let text = "x".repeat(400);
        assert_eq!(HISTORY_SWEEP_SHARE, 8);
        assert!(!s.has_grown());
        // A record is its text and the line about it: under 1,000 bytes
        // here, and over 667.
        keep(&s, "a.md", Some(&text), at(0));
        assert!(!s.has_grown());
        let copy = s.clone();
        keep(&copy, "a.md", Some(&text), at(1));
        assert!(!s.has_grown());
        // One that is not made final counts as well: it was written.
        drop(copy.keep(about("a.md", Some(&text)), Some(&text), at(2)));
        assert!(s.has_grown() && copy.has_grown());
        s.sweep(at(3)).unwrap();
        assert!(!s.has_grown() && !copy.has_grown());

        // A store that may hold nothing has grown with anything kept.
        let none = Store::new(tmp.path(), 30, 0).unwrap();
        assert!(!none.has_grown());
        keep(&none, "a.md", Some("x"), at(4));
        assert!(none.has_grown());
    }

    /// As the node starts: turned off, what was kept is removed; turned
    /// on, the records that were pending are marked and what is too old
    /// goes. A directory that cannot be used still gives a store, which
    /// keeps nothing.
    #[test]
    fn test_what_starting_does() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let old = keep(&s, "a.md", Some("old"), at(0));
        let recent = keep(&s, "a.md", Some("recent"), at(20 * DAY));
        let pending = s
            .keep(about("b.md", Some("y")), Some("y"), at(20 * DAY + 1))
            .unwrap();
        let stopped = pending.id().clone();
        std::mem::forget(pending);

        let Start::On {
            store,
            interrupted,
            swept,
        } = Store::start(tmp.path(), 30, 1 << 20, at(31 * DAY))
        else {
            panic!("history is on");
        };
        assert_eq!(interrupted.unwrap(), 1);
        assert_eq!(swept.unwrap(), aged(1));
        assert!(store.read(&old).unwrap().is_none());
        assert!(store.read(&recent).unwrap().is_some());
        assert!(store.read(&stopped).unwrap().unwrap().0.interrupted);
        assert_eq!((store.days(), store.max_bytes()), (30, 1 << 20));

        // Turned off: nothing is left.
        let Start::Off(removed) = Store::start(tmp.path(), 0, 1 << 20, at(31 * DAY)) else {
            panic!("history is off");
        };
        removed.unwrap();
        assert!(!tmp.path().join(DIR).exists());

        // A file where the directory would go.
        std::fs::write(tmp.path().join(DIR), "in the way").unwrap();
        let Start::On {
            store,
            interrupted,
            swept,
        } = Store::start(tmp.path(), 30, 1 << 20, at(0))
        else {
            panic!("history is on");
        };
        assert!(interrupted.is_err() && swept.is_err());
        assert!(
            store
                .keep(about("a.md", Some("x")), Some("x"), at(0))
                .is_err()
        );
    }

    /// With the days at 0 history is off, and what was kept is removed.
    #[test]
    fn test_history_turned_off_removes_what_was_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        keep(&s, "a.md", Some("x"), at(0));
        keep(&s, "b.md", Some("y"), at(1));
        assert_eq!(s.clear().unwrap(), 2);
        keep(&s, "a.md", Some("x"), at(2));

        assert!(Store::new(tmp.path(), 0, 1 << 20).is_none());
        Store::turn_off(tmp.path()).unwrap();
        assert!(!tmp.path().join(DIR).exists());
        // Off where there was never any is not an error.
        Store::turn_off(tmp.path()).unwrap();
    }

    /// A store whose directory cannot be made keeps nothing and says so,
    /// each time: the change that needed the text kept is then not made.
    /// Nothing is listed, and nothing is an error until a text is to be
    /// kept.
    #[test]
    fn test_a_store_that_cannot_be_written_keeps_nothing_and_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        // A file where the directory would go.
        std::fs::write(tmp.path().join(DIR), "in the way").unwrap();
        let s = store(tmp.path());
        for _ in 0..2 {
            assert!(s.keep(about("a.md", Some("x")), Some("x"), at(0)).is_err());
        }
        assert!(s.sweep(at(0)).is_err());

        // Once it can be made, it is, and the text is kept.
        std::fs::remove_file(tmp.path().join(DIR)).unwrap();
        assert!(s.list().unwrap().records.is_empty());
        assert_eq!(s.sweep(at(0)).unwrap(), Swept::default());
        let id = keep(&s, "a.md", Some("x"), at(0));
        assert_eq!(s.read(&id).unwrap().unwrap().1.as_deref(), Some("x"));
    }

    /// Records of one text carry one hash, which is how `drop` finds every
    /// record that holds a text.
    #[test]
    fn test_records_of_one_text_are_found_by_its_hash() {
        let same = kept(Whose::Here { agreed: None }, "a token\n");
        let again = kept(
            Whose::Channel(Entry {
                device: "cordelia_pk1other".into(),
                rev: 2,
            }),
            "a token\n",
        );
        assert_eq!(same.sha256, again.sha256);
        assert_ne!(
            same.sha256,
            kept(Whose::Here { agreed: None }, "a token").sha256
        );
    }
}
