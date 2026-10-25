//! What the harness wrote, and where each edit arrived (decision
//! 2026-10-22 §1.3; §4.2, step 6; bar 3). An edit's file begins with a
//! line of its own, `<!-- scale N -->`; the observer reads, every 250 ms,
//! each file it waits for on each other device of the person and the
//! copies the adapter keeps beside it, and an edit counts as arrived only
//! where its own line is found.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The line an edit's file begins with.
pub fn line_of(edit: u64) -> String {
    format!("<!-- scale {edit} -->")
}

/// The edit whose line `first` is, where it is one.
pub fn edit_of(first: &str) -> Option<u64> {
    first
        .trim()
        .strip_prefix("<!-- scale ")?
        .strip_suffix(" -->")?
        .parse()
        .ok()
}

/// The text of edit `edit`: its line, and text to `size` bytes, from
/// `fill`, a number that differs for each edit.
pub fn text_of(edit: u64, size: usize, fill: u64) -> String {
    let mut text = line_of(edit);
    text.push('\n');
    let words = [
        "memory", "note", "the", "of", "a", "project", "build", "test", "relay", "device",
        "person", "edit", "file", "name", "sync", "and", "is", "to", "kept", "said",
    ];
    let mut x = fill | 1;
    while text.len() < size {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        text.push_str(words[(x % words.len() as u64) as usize]);
        text.push(if x.is_multiple_of(11) { '\n' } else { ' ' });
    }
    text.truncate(size.max(line_of(edit).len() + 1));
    text
}

/// The first line of the file at `path`, read from its first bytes.
pub fn first_line(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut head = [0u8; 64];
    let mut got = 0;
    while got < head.len() {
        match file.read(&mut head[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => return None,
        }
    }
    let head = String::from_utf8_lossy(&head[..got]).into_owned();
    Some(head.split('\n').next().unwrap_or_default().to_string())
}

/// Whether `name` is a copy that the adapter keeps beside `file`
/// (`stem.conflict-xxxx.ext`).
pub fn is_copy_of(name: &str, file: &str) -> bool {
    let (stem, ext) = file.rsplit_once('.').unwrap_or((file, ""));
    name.starts_with(&format!("{stem}.conflict-")) && name.ends_with(&format!(".{ext}"))
}

/// An edit the harness wrote.
#[derive(Debug, Clone, PartialEq)]
pub struct Written {
    pub number: u64,
    pub person: usize,
    /// The device it was written on, within its person.
    pub writer: usize,
    pub name: usize,
    pub file: String,
    pub size: usize,
    /// When it was written, in seconds of the run.
    pub at: f64,
    pub burst: bool,
    pub new: bool,
    /// The edit whose line the file began with on the writer when this
    /// one was written: the edit this one replaced, which its writer held.
    pub replaced: Option<u64>,
}

/// Where an edit arrived on a device, and when.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Arrival {
    pub at: f64,
    /// Found in a copy kept beside the file, and not in the file.
    pub in_copy: bool,
}

/// An edit the observer waits for on one device.
#[derive(Debug, Clone)]
struct Watch {
    edit: u64,
    device: usize,
    folder: PathBuf,
    file: String,
}

/// What the observer keeps.
#[derive(Debug, Default)]
pub struct Observer {
    pub edits: Vec<Written>,
    /// By edit number, its place in `edits`.
    at: HashMap<u64, usize>,
    pending: Vec<Watch>,
    /// Every (edit, device) that was waited for, and where it arrived.
    pub waited: Vec<(u64, usize)>,
    pub arrivals: HashMap<(u64, usize), Arrival>,
    /// Waits ended because the device was removed from its person.
    pub gone: Vec<(u64, usize)>,
    /// The time between one read of the files waited for and the next.
    pub gaps: Vec<f64>,
    last_tick: Option<f64>,
}

impl Observer {
    /// The harness wrote `edit`; it is waited for on each of `others`:
    /// each other device of the person, and the folder of the edit's name
    /// there.
    pub fn wrote(&mut self, edit: Written, others: Vec<(usize, PathBuf)>) {
        for (device, folder) in others {
            self.waited.push((edit.number, device));
            self.pending.push(Watch {
                edit: edit.number,
                device,
                folder,
                file: edit.file.clone(),
            });
        }
        self.at.insert(edit.number, self.edits.len());
        self.edits.push(edit);
    }

    pub fn edit(&self, number: u64) -> Option<&Written> {
        self.at.get(&number).map(|at| &self.edits[*at])
    }

    /// The edits waited for on `device` of `person` that have not arrived.
    pub fn pending_on(&self, person: usize, device: usize) -> usize {
        self.pending
            .iter()
            .filter(|w| w.device == device && self.edit(w.edit).is_some_and(|e| e.person == person))
            .count()
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Device `device` of `person` is removed: what was written from
    /// `since` on, which it had no chance at ([`no_chance_from`]), is
    /// waited for on it no more. An older edit it still lacks is a miss,
    /// and stays waited for, so that it counts as not arrived.
    pub fn gone(&mut self, person: usize, device: usize, since: f64) {
        let edits = &self.edits;
        let at = &self.at;
        let mut gone = Vec::new();
        self.pending.retain(|w| {
            let Some(edit) = at.get(&w.edit).map(|i| &edits[*i]) else {
                return true;
            };
            let goes = edit.person == person && w.device == device && edit.at >= since;
            if goes {
                gone.push((w.edit, w.device));
            }
            !goes
        });
        self.gone.extend(gone);
    }

    /// Read every file waited for, at `now`.
    pub fn tick(&mut self, now: f64) {
        if let Some(last) = self.last_tick {
            self.gaps.push(now - last);
        }
        self.last_tick = Some(now);
        let mut listed: HashMap<PathBuf, Vec<String>> = HashMap::new();
        let mut found = Vec::new();
        for (i, watch) in self.pending.iter().enumerate() {
            let line = line_of(watch.edit);
            let path = watch.folder.join(&watch.file);
            if first_line(&path).as_deref() == Some(line.as_str()) {
                found.push((i, false));
                continue;
            }
            let names = listed.entry(watch.folder.clone()).or_insert_with(|| {
                std::fs::read_dir(&watch.folder)
                    .into_iter()
                    .flatten()
                    .filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|name| name.contains(".conflict-"))
                    .collect()
            });
            let in_copy = names.iter().any(|name| {
                is_copy_of(name, &watch.file)
                    && first_line(&watch.folder.join(name)).as_deref() == Some(line.as_str())
            });
            if in_copy {
                found.push((i, true));
            }
        }
        for (i, in_copy) in found.iter().rev() {
            let watch = self.pending.remove(*i);
            self.arrivals.insert(
                (watch.edit, watch.device),
                Arrival {
                    at: now,
                    in_copy: *in_copy,
                },
            );
        }
    }
}

/// From when a device removed at `line` had no chance at an edit, given
/// whether it ran after each change of its life, in their order
/// (`history`): the 120 s before the line; where it was down at the line,
/// the 120 s before it went down; and for each run before that too short
/// for its catch-up (under a minute, bar 3), the 120 s before it went down
/// the time before. An older edit it ran through and lacks is a miss.
pub fn no_chance_from(history: &[(f64, bool)], line: f64) -> f64 {
    // Its runs up to the line: from a start to when it went down, if it did.
    let mut runs: Vec<(f64, Option<f64>)> = Vec::new();
    for (t, runs_now) in history.iter().filter(|(t, _)| *t <= line) {
        match (runs_now, runs.last_mut()) {
            (true, Some((_, None))) => {}
            (true, _) => runs.push((*t, None)),
            (false, Some((_, end @ None))) => *end = Some(*t),
            (false, _) => {}
        }
    }
    let mut since = line - 120.0;
    if let Some((_, Some(down))) = runs.last() {
        since = since.min(down - 120.0);
    }
    let mut rest = runs.as_slice();
    while let Some(((start, end), before)) = rest.split_last() {
        if end.unwrap_or(line) - start >= 60.0 {
            break;
        }
        if let Some((_, Some(down))) = before.last() {
            since = since.min(down - 120.0);
        }
        rest = before;
    }
    since
}
