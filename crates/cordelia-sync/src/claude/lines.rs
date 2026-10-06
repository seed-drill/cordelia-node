//! The index line of a memory that comes back (decision
//! 2026-09-30-agent-memory-sync §4.5).
//!
//! One device deletes a memory and its line in the index while another
//! edits the memory. An edit beats a delete, so the file comes back on
//! both. Its line does not: the device that deleted the memory also
//! removed the line, and that index is the one the other takes. The
//! memory is then in a file that the index does not point to.
//!
//! **The device that deleted a memory puts its line back if the file comes
//! back and nobody else does.** It writes down each of its two acts when it
//! publishes it ([`published`]). Later, in each cycle that dealt with every
//! file of the folder, it looks ([`look`]): where the file is there again
//! as a text that the channel and the folder agree, the index has no line
//! for it, and that has been so at every look for a minute, it adds the
//! line, as an edit of the index that it publishes as its own.
//!
//! Nothing is asked about how the file came back, in which order things
//! arrived, or what another device did: only about this device's own two
//! publishes, and what is there now.

use std::collections::{HashMap, HashSet};

use rusqlite::Connection;

use cordelia_api::publish::{self, PlannedAgainst};
use cordelia_api::state::{LineFound, Look};
use cordelia_core::CordeliaError;
use cordelia_core::protocol::{INDEX_LINE_LOOK_GAP_SECS, INDEX_LINE_LOOK_SECS};
use cordelia_crypto::entry::Value;
use cordelia_crypto::version::Slot;
use cordelia_storage::atomic::write_atomic;
use cordelia_storage::{history, index_lines};

use super::{
    Ctx, Failure, FolderReport, as_seen, current_hash, entry_of, forget_kept, keep_here, lock,
    of_a_publish, of_person, publish_over, record_agreed, revision_ahead, settle,
};
use crate::memory_md::{self, INDEX_FILE};
use crate::names;
use crate::plan::{Agreed, Content, Remote};

/// The file that `line` of an index is a line for, if it is one: its first
/// link is the name of a memory file and nothing more, and that name is
/// neither the index's own nor a conflict file's. A link written any other
/// way (`./notes.md`) is a line for no file.
pub(super) fn line_for(line: &str) -> Option<&str> {
    let file = memory_md::linked_file(line)?;
    (names::is_safe_file_name(file) && file != INDEX_FILE && !names::is_conflict_name(file))
        .then_some(file)
}

/// Whether `index` has a line for `file`.
fn has_line_for(index: &str, file: &str) -> bool {
    index.lines().any(|line| line_for(line) == Some(file))
}

/// A version of the index that stands beside the channel's: another
/// version at the same revision, which lost the tie.
pub(super) struct Beside {
    /// What the version is known by: each entry that the device holds of
    /// it, by what the entry is named by, in the order of their signers'
    /// keys.
    pub id: String,
    /// The lowest key that signed an entry of it.
    pub author: [u8; 32],
    pub text: String,
}

/// What a cycle read of the index's slot, beyond the channel's version.
#[derive(Default)]
pub(super) struct IndexRead {
    /// The versions that stand beside the channel's, in the order of
    /// their writers' keys.
    pub beside: Vec<Beside>,
    /// How many entries there, at the revision read or above it, this
    /// device cannot read ([`publish::not_read`]).
    pub unread: usize,
}

/// The texts that stand beside the current version of `slot`, in the
/// order of their writers' keys. A delete beside it, or what is no text,
/// has no lines.
pub(super) fn beside(slot: &Slot) -> Vec<Beside> {
    let mut beside: Vec<Beside> = slot
        .lost
        .iter()
        .filter_map(|version| {
            let Value::Text(text) = &version.value else {
                return None;
            };
            let ids: Vec<String> = version
                .entries
                .iter()
                .map(|entry| hex::encode(entry.id))
                .collect();
            Some(Beside {
                id: ids.join("+"),
                // A version's entries are in order of their signers' keys.
                author: version.entries.first()?.author,
                text: text.clone(),
            })
        })
        .collect();
    beside.sort_by_key(|version| version.author);
    beside
}

/// What a cycle reads of the index's slot beyond its current version:
/// what stands `beside` that version, and how many entries this device
/// holds there and cannot read. Called under the hold of the lock that
/// the cycle reads the channel under. `name` is the name the folder
/// syncs.
pub(super) fn read_index(
    db: &Connection,
    name: &str,
    beside: Vec<Beside>,
) -> Result<IndexRead, CordeliaError> {
    let unread = publish::not_read(db, name, INDEX_FILE).map_err(of_person)?;
    Ok(IndexRead { beside, unread })
}

/// Write down what this device has just published for `key`: `text`, or a
/// delete. Called under the hold of the database lock that the publish was
/// made under, straight after it, so that no command that makes the
/// folder forget can fall between the two. (They are still two writes: a
/// stop of the process between them leaves the entry published and
/// nothing written down, and the memory is then not covered.)
///
/// - **An edit of the index** (not a merge): for each file that has a line
///   in the entry published over, as the cycle read it, and none in the
///   text published, the first of its lines there.
/// - **A delete of a memory:** that it was published. None is written for
///   a name that can have no line: the index's own, and a conflict
///   file's.
/// - **A text for a memory where the folder had no text agreed for it:**
///   a file of this device's own making under that name, which is the
///   person's or the agent's to list. Its record goes.
pub(super) fn published(
    ctx: &Ctx,
    db: &Connection,
    key: &str,
    text: Option<&str>,
) -> Result<(), CordeliaError> {
    let (folder, channel) = (ctx.folder, ctx.channel);
    let now = ctx.state.sync_control.now();
    if key == INDEX_FILE {
        let (Some(text), Some(over)) = (text, ctx.over.and_then(|r| r.content.as_ref())) else {
            return Ok(());
        };
        let mut seen = HashSet::new();
        let mut removed = Vec::new();
        for line in over.text.lines() {
            let Some(file) = line_for(line) else {
                continue;
            };
            // The first of its lines there.
            if seen.insert(file) && !has_line_for(text, file) {
                removed.push((file, line.trim_end()));
            }
        }
        // One write for the edit, however many lines it dropped.
        return index_lines::lines_removed(db, folder, channel, &removed, now);
    }
    if names::is_conflict_name(key) {
        return Ok(());
    }
    match text {
        None => index_lines::delete_published(db, folder, channel, key, now),
        Some(_) if ctx.agreed.get(key).is_none_or(|a| a.hash.is_none()) => {
            index_lines::drop_record(db, folder, channel, key)
        }
        Some(_) => Ok(()),
    }
}

/// What a cycle that dealt with every file of the folder knows of it.
pub(super) struct Cycle<'a> {
    /// The folder as it was listed.
    pub local: &'a HashMap<String, Content>,
    /// The channel as it was read.
    pub remote: &'a HashMap<String, Remote>,
    /// What the folder had agreed when the cycle began.
    pub agreed: &'a HashMap<String, Agreed>,
    /// What each file was planned against.
    pub taken: &'a HashMap<String, PlannedAgainst>,
    /// The files for which nothing was planned.
    pub quiet: &'a HashSet<String>,
    pub index: &'a IndexRead,
    /// Run just before the hold under which a put-back is published. A
    /// cycle does nothing there. A test does what can arrive in that gap.
    pub before_hold: &'a dyn Fn(),
}

impl Cycle<'_> {
    /// The text of `key`, if it is at rest as a text: the file, the
    /// channel's version as the cycle read it and the folder's record are
    /// one text, with nothing planned for it.
    ///
    /// Nothing planned is not enough by itself. The plan also has nothing
    /// to do for a file that is as the folder agreed while the channel has
    /// no version of it: what is under its name there is neither a text
    /// nor a delete (something written through the API). Such a file is
    /// not at rest.
    fn at_rest(&self, key: &str) -> Option<&Content> {
        if !self.quiet.contains(key) {
            return None;
        }
        let here = self.local.get(key)?;
        let there = self.remote.get(key)?.content.as_ref()?;
        let agreed = self.agreed.get(key)?;
        (here.hash == there.hash && agreed.hash == Some(here.hash)).then_some(here)
    }
}

/// One look, at the end of a cycle that dealt with every file of the
/// folder; `ctx` is the index's. None is made once the settings have
/// changed since the cycle read them: the minute starts again at a
/// settings command, with the next cycle's look and not with this one.
/// For each whole record it finds the line due, the line back, or
/// neither, and writes that down with the time. A
/// record whose line has been back at every look for a minute is dropped:
/// the line has stayed. The lines that have been due at every look for a
/// minute are put back, in one publish.
///
/// The minute starts again where a look finds another of the three than
/// the look before; where the look before was more than 30 seconds ago
/// (the machine slept, the clock was moved, the cycle did not run); where
/// what stands beside the index's entry is not what the look before
/// found; and, by what is kept in the node's state, when the node starts,
/// when it takes a settings command, and when a cycle applies any action
/// to the index or to the file (`sync_folder_with`).
pub(super) fn look(ctx: &Ctx, cycle: &Cycle, report: &mut FolderReport) -> Result<(), Failure> {
    let Ctx {
        state,
        folder,
        channel,
        generation,
        ..
    } = *ctx;
    let control = &state.sync_control;
    let now = control.now();
    let records = {
        let db = lock(state)?;
        if control.generation_under(&db) != generation {
            return Ok(());
        }
        index_lines::whole(&db, folder, channel, now)?
    };
    // What stands beside the index's entry: a version that has just
    // arrived has had no minute.
    let stands: Vec<String> = cycle
        .index
        .beside
        .iter()
        .map(|version| version.id.clone())
        .collect();
    let stood = control.stood_beside(folder, channel);
    let same_beside = stood.as_ref() == Some(&stands);
    control.stands_beside(folder, channel, stands);
    if records.is_empty() {
        return Ok(());
    }

    let index = cycle.at_rest(INDEX_FILE);
    // An entry of the index that this device cannot read is passed over
    // when the channel's version is worked out, and may be above it. A
    // put-back published now would go above it too.
    let unread = cycle.index.unread > 0;

    let mut due = Vec::new();
    let mut stayed = Vec::new();
    for record in &records {
        let file = record.file.as_str();
        let found = match (index, cycle.at_rest(file)) {
            (Some(index), Some(_)) if !unread => match has_line_for(&index.text, file) {
                true => LineFound::Back,
                false => LineFound::Due,
            },
            _ => LineFound::Neither,
        };
        // A time later than now is read as now.
        let since = match control.look(folder, channel, file) {
            Some(before)
                if before.found == found
                    && same_beside
                    && now - before.at <= INDEX_LINE_LOOK_GAP_SECS =>
            {
                before.since.min(now)
            }
            _ => now,
        };
        let at = now;
        control.looked(folder, channel, file, Look { found, since, at });
        if now - since >= INDEX_LINE_LOOK_SECS {
            match found {
                LineFound::Due => due.push(record),
                LineFound::Back => stayed.push(file),
                LineFound::Neither => {}
            }
        }
    }
    if !stayed.is_empty() {
        let db = lock(state)?;
        for file in stayed {
            index_lines::drop_record(&db, folder, channel, file)?;
        }
    }
    match (index, due.is_empty()) {
        (Some(index), false) => put_back(ctx, cycle, index, &due, report),
        _ => Ok(()),
    }
}

/// The index with lines after it: the channel's text as it is, then each
/// line of `beside` that the text so far lacks (a blank line is none, and
/// the space at a line's end is not compared), except a line that
/// `is_deleted` says links to a file deleted in the channel; then the line
/// of each record in `due` whose file has no line in the text so far (as
/// it was written down, which is without the space at its end).
/// Each added line is on a line of its own that ends in a line break,
/// with one before the first if the index does not end in one.
fn with_lines(
    index: &str,
    beside: &[Beside],
    due: &[&index_lines::Record],
    is_deleted: &mut dyn FnMut(&str) -> Result<bool, CordeliaError>,
) -> Result<String, CordeliaError> {
    let mut text = index.to_string();
    let mut present: HashSet<String> = index.lines().map(|l| l.trim_end().to_string()).collect();
    let mut listed: HashSet<String> = index
        .lines()
        .filter_map(line_for)
        .map(String::from)
        .collect();
    let add = |text: &mut String, line: &str| {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(line);
        text.push('\n');
    };
    for version in beside {
        for line in version.text.lines() {
            let line = line.trim_end();
            if line.trim().is_empty() || present.contains(line) {
                continue;
            }
            if let Some(file) = memory_md::linked_file(line)
                && is_deleted(file)?
            {
                continue;
            }
            add(&mut text, line);
            present.insert(line.to_string());
            if let Some(file) = line_for(line) {
                listed.insert(file.to_string());
            }
        }
    }
    for record in due {
        if listed.insert(record.file.clone()) {
            add(&mut text, &record.line);
        }
    }
    Ok(text)
}

/// Put back the lines of `due`, in one publish over the index's entry.
/// It is done as a merged index is: the index as it was is kept in local
/// history, the new text is published, and then the file is written.
///
/// Nothing is published where the index's file or a due file is no longer
/// as the cycle listed it; or, under the hold the publish is made under,
/// where the settings have changed, the index's entry or a due file's
/// is no longer the one the cycle read, what stands beside the index's
/// entry is no longer what the look found, or the index's slot holds an
/// entry that this device cannot read at the revision read or above it.
/// The next looks decide again.
///
/// The entry is published through the path every entry of the folder's
/// is ([`publish_over`]), as an edit of the index's version. If the text
/// does not fit beside its name, nothing is published and the records
/// that were due are dropped.
fn put_back(
    ctx: &Ctx,
    cycle: &Cycle,
    index: &Content,
    due: &[&index_lines::Record],
    report: &mut FolderReport,
) -> Result<(), Failure> {
    let Ctx {
        state,
        dir,
        channel,
        folder,
        agent,
        generation,
        planned,
        ..
    } = *ctx;
    let control = &state.sync_control;
    let not_now = |why: &str| {
        tracing::debug!(
            folder,
            channel,
            why,
            "index lines not put back in this cycle"
        );
        Ok(())
    };
    // Each file is looked at again: it is as the cycle listed it.
    let as_listed = |key: &str| {
        let listed = cycle.local.get(key).map(|c| c.hash);
        listed.is_some() && current_hash(dir, key) == listed
    };
    if !as_listed(INDEX_FILE) || !due.iter().all(|record| as_listed(&record.file)) {
        return not_now("a file changed here");
    }

    // The index as it is here is kept in history first, in a record that
    // names the revision the new entry is to have.
    let me = state.identity.public_key();
    let at = revision_ahead(ctx, INDEX_FILE)?;
    let ahead = match at {
        Some(rev) => {
            let replaced_by = history::Replacement::Entry(entry_of(&me, rev));
            let change = history::Change::Merged;
            match keep_here(ctx, INDEX_FILE, Some(index.hash), change, replaced_by)? {
                super::KeptHere::Ahead(ahead) => ahead,
                super::KeptHere::Changed => return not_now("the index changed here"),
            }
        }
        None => None,
    };

    (cycle.before_hold)();

    let files: Vec<&str> = due.iter().map(|record| record.file.as_str()).collect();
    let (text, made) = {
        let db = lock(state)?;
        if control.generation_under(&db) != generation {
            return not_now("the settings changed");
        }
        let read = |file: &str| publish::read(&db, agent, file).map_err(of_a_publish);
        let now = read(INDEX_FILE)?.slot;
        if PlannedAgainst::what_is_in(&now) != *planned {
            return not_now("the index's entry changed");
        }
        let Some(Value::Text(there)) = now.current.as_ref().map(|version| &version.value) else {
            return not_now("the index's entry is no text");
        };
        // The lines taken are those of the versions that are overtaken.
        let stands = beside(&now);
        let same = stands.len() == cycle.index.beside.len()
            && stands
                .iter()
                .zip(&cycle.index.beside)
                .all(|(now, read)| now.id == read.id);
        if !same {
            return not_now("what stands beside the index's entry changed");
        }
        let no_version = PlannedAgainst::NoVersion;
        for file in &files {
            let now = PlannedAgainst::what_is_in(&read(file)?.slot);
            if now != *cycle.taken.get(*file).unwrap_or(&no_version) {
                return not_now("a file's entry changed");
            }
        }
        if publish::not_read(&db, agent, INDEX_FILE).map_err(of_a_publish)? > 0 {
            return not_now("the index's slot holds an entry that cannot be read");
        }
        // A line from a version beside is left out where its file's
        // version is a delete now.
        let mut asked: HashMap<String, bool> = HashMap::new();
        let mut is_deleted = |file: &str| -> Result<bool, CordeliaError> {
            if let Some(known) = asked.get(file) {
                return Ok(*known);
            }
            let slot = publish::read(&db, agent, file).map_err(of_person)?.slot;
            let deleted = slot
                .current
                .is_some_and(|version| version.value == Value::Delete);
            asked.insert(file.to_string(), deleted);
            Ok(deleted)
        };
        let text = with_lines(there, &stands, due, &mut is_deleted)?;
        if !publish::fits(INDEX_FILE, &Value::Text(text.clone())) {
            for file in &files {
                index_lines::drop_record(&db, folder, channel, file)?;
            }
            tracing::warn!(
                folder,
                channel,
                ?files,
                "the index is too large to take back the lines of memories that came back; \
                 they are not listed"
            );
            return Ok(());
        }
        // An edit of the index's version, as the cycle read it: where
        // the slot holds another by now, or its next revision is not the
        // one that the kept text names, nothing is published.
        let Some(made) = publish_over(ctx, &db, INDEX_FILE, Some(&text), at, None)? else {
            return not_now("the index's entry changed, or an entry arrived under its name");
        };
        // The count goes up of each record that was due in it, whether
        // its own line went in or a version beside had one for its file.
        // The entry is published by now: a count that cannot be written
        // is said, and the file is still written and the publish still
        // reported.
        if let Err(error) = index_lines::put_back(&db, folder, channel, &files) {
            tracing::warn!(
                folder,
                channel,
                %error,
                "lines were put back, and that could not be counted"
            );
        }
        (text, made)
    };
    // A minute of looking starts again for every record of the folder: an
    // action was applied to the index.
    control.look_again(folder, channel, None);
    report.published += 1;
    tracing::info!(
        folder,
        channel,
        ?files,
        "put back the index lines of memories that came back"
    );

    // Published before the file is written, as a merged index is: an
    // agent's write to the index in that moment is merged with it at the
    // next cycle.
    let flushed = || (ctx.flushed)(INDEX_FILE);
    let unchanged = || as_seen(dir, INDEX_FILE, Some(index.hash));
    let written = write_atomic(dir, INDEX_FILE, &text, &flushed, &unchanged)
        .map_err(|e| Failure::File(e.to_string()))?;
    if !written {
        tracing::debug!(file = %dir.join(INDEX_FILE).display(), "the index changed while its lines were put back; the next cycle merges it");
        return Ok(());
    }
    settle(ctx, ahead);
    forget_kept(ctx, INDEX_FILE);
    let agreed = made.agreed(Some(Content::new(text).hash), me);
    record_agreed(state, generation, folder, channel, INDEX_FILE, &agreed)?;
    Ok(())
}
