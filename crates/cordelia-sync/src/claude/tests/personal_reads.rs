//! A cycle's reads of a large personal channel (decision 2026-10-04 §2.2,
//! §16): each device says in it which names it syncs, and a cycle reads
//! what this device says and what the channel lists. At a few thousand
//! words they must not hold the store for long: `cordelia status` asks
//! its node with a second's wait, and `msg summary` tries the store's
//! lock for 100 ms.
//!
//! Timed, and slow in a build that is not optimised, so they are left out
//! of `cargo test`. To run them:
//!
//! ```text
//! cargo test -p cordelia-sync --release --lib personal_reads -- --ignored --nocapture
//! ```

use super::*;
use actix_web::web::Data;
use cordelia_core::protocol::{AGENT_MESSAGE_SUMMARY_WAIT_MS, PERSONAL_NAME_PREFIX};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The size a reviewer measured: four devices of one person, each saying
/// that it syncs about 2,460 names, 9,847 entries of the personal channel
/// in all.
const DEVICES: usize = 4;
const NAMES_EACH: usize = 2_460;

/// How long `cordelia status` waits for `/api/v1/sync/status`.
const STATUS_WAIT: Duration = Duration::from_secs(1);

/// The tests of this file one at a time: what a node keeps of its
/// personal channel between reads is the process's, and two large
/// channels read at once would each find the other's.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// The name that device `d` says as its `i`th: half of each device's
/// names are also the next device's.
fn name_of(d: usize, i: usize) -> String {
    format!("name-{:05}", d * NAMES_EACH / 2 + i)
}

/// A device of four, whose store holds the words of all four.
struct Large {
    st: Data<AppState>,
    /// The other three.
    others: Vec<AppState>,
    /// The names this device syncs.
    wanted: BTreeSet<String>,
    personal: [u8; 32],
    channel: [u8; 32],
}

impl Large {
    /// Store in this device's store, as the door would have stored it,
    /// the word of device `d` (0 is this one) of `name` at `rev`: a text,
    /// or a delete.
    fn word(&self, d: usize, name: &str, rev: u64, value: Value) {
        let by = match d {
            0 => &self.st.identity,
            d => &self.others[d - 1].identity,
        };
        let inside = Inside {
            name: format!("{PERSONAL_NAME_PREFIX}{name}"),
            value,
            chain: Some(Vec::new()),
        };
        let entry = Entry::seal(&self.personal, by, rev, &inside)
            .unwrap()
            .check()
            .unwrap();
        let db = self.st.db.lock().unwrap();
        stored::store(&db, &entry, now()).unwrap();
    }
}

/// A device of four, whose store holds the words of all four: each
/// stored as the door would have stored it.
fn large(tmp: &Path) -> Large {
    let st = state(tmp);
    with_phrase(&st, NAME);
    let others: Vec<AppState> = (1..DEVICES)
        .map(|n| another_device(&st, &tmp.join(format!("device-{n}")), NAME))
        .collect();
    let personal = {
        let db = st.db.lock().unwrap();
        let person = held_rows::applied_secret(&db).unwrap().unwrap();
        derive::personal_secret(&person.secret).unwrap()
    };
    let channel = derive::channel_id(&personal).unwrap();
    let devices: Vec<&AppState> = std::iter::once(&st).chain(&others).collect();
    {
        let db = st.db.lock().unwrap();
        let counting = person::who_counts(&db).unwrap();
        for device in &devices {
            assert!(counting.counts(&device.identity.public_key()));
        }
        db.execute_batch("BEGIN").unwrap();
        for (d, device) in devices.iter().enumerate() {
            for i in 0..NAMES_EACH {
                let inside = Inside {
                    name: format!("{PERSONAL_NAME_PREFIX}{}", name_of(d, i)),
                    value: text(""),
                    chain: Some(Vec::new()),
                };
                let entry = Entry::seal(&personal, &device.identity, 1, &inside)
                    .unwrap()
                    .check()
                    .unwrap();
                stored::store(&db, &entry, now()).unwrap();
            }
        }
        db.execute_batch("COMMIT").unwrap();
    }
    let wanted = (0..NAMES_EACH).map(|i| name_of(0, i)).collect();
    Large {
        st: Data::new(st),
        others,
        wanted,
        personal,
        channel,
    }
}

/// How many entries the store holds of `channel`.
fn entries_of(st: &AppState, channel: &[u8; 32]) -> i64 {
    st.db
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM entries WHERE channel_id = ?1",
            [&channel[..]],
            |row| row.get(0),
        )
        .unwrap()
}

/// One cycle's reads of the personal channel, as a cycle makes them:
/// how long they took, and the names the other devices sync.
fn cycle(st: &AppState, wanted: &BTreeSet<String>) -> (Duration, Vec<String>) {
    let generation = st.sync_control.generation();
    let started = Instant::now();
    let others = exchange_names(st, wanted, generation).unwrap();
    (started.elapsed(), others)
}

/// How long checking and opening every entry of the personal channel
/// takes, once: what reading it through once costs.
fn once_through(st: &AppState, channel: &[u8; 32]) -> Duration {
    let personal = {
        let db = st.db.lock().unwrap();
        let person = held_rows::applied_secret(&db).unwrap().unwrap();
        derive::personal_secret(&person.secret).unwrap()
    };
    let rows = stored::channel_entries_after(&st.db.lock().unwrap(), channel, 0, 100_000).unwrap();
    let started = Instant::now();
    for held in rows {
        if let Ok(entry) = held.entry.check() {
            let _ = entry.open(&personal);
        }
    }
    started.elapsed()
}

/// A thread that takes the store's lock as often as it can, as a status
/// and a summary do, until it is stopped: it gives the longest it waited.
struct Probe {
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<Duration>,
}

impl Probe {
    fn start(st: &Data<AppState>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let (st, stops) = (st.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            let mut longest = Duration::ZERO;
            while !stops.load(Ordering::SeqCst) {
                let asked = Instant::now();
                drop(st.db.lock().unwrap());
                longest = longest.max(asked.elapsed());
                std::thread::sleep(Duration::from_millis(1));
            }
            longest
        });
        Probe { stop, thread }
    }

    fn longest(self) -> Duration {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.join().unwrap()
    }
}

/// A cycle in which the personal channel did not change reads it for
/// almost nothing; the first, and one in which it changed, for no more
/// than once through it. None holds the store's lock for longer than
/// `msg summary` tries it, and each finds what a read of the whole
/// channel finds.
#[test]
#[ignore = "timed: run with --release, as the file says"]
fn a_cycle_reads_a_large_personal_channel_and_holds_the_store_briefly() {
    let _alone = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let large = large(tmp.path());
    let (st, wanted, channel) = (&large.st, &large.wanted, &large.channel);
    let held = entries_of(st, channel);
    assert!(held >= (DEVICES * NAMES_EACH) as i64, "{held}");
    let once = once_through(st, channel);
    // What the other devices sync, and this one does not.
    let mut expected: BTreeSet<String> = (1..DEVICES)
        .flat_map(|d| (0..NAMES_EACH).map(move |i| name_of(d, i)))
        .filter(|name| !wanted.contains(name))
        .collect();
    let listed = |expected: &BTreeSet<String>| expected.iter().cloned().collect::<Vec<_>>();

    let probe = Probe::start(st);
    let (first, others) = cycle(st, wanted);
    assert_eq!(others, listed(&expected));
    let mut unchanged = Vec::new();
    for _ in 0..5 {
        let (took, others) = cycle(st, wanted);
        assert_eq!(others, listed(&expected));
        unchanged.push(took);
    }
    // Device 1 says that it syncs one name more, and device 3 that it
    // syncs no longer the last of its own, which no other device lists.
    large.word(1, "one-more", 1, text(""));
    let last = name_of(3, NAMES_EACH - 1);
    large.word(3, &last, 2, Value::Delete);
    expected.insert("one-more".into());
    expected.remove(&last);
    let (changed, others) = cycle(st, wanted);
    assert_eq!(others, listed(&expected));
    let longest = probe.longest();
    let typical = *unchanged.iter().max().unwrap();
    eprintln!(
        "entries of the personal channel: {held}; checking and opening each once: {once:?}; \
         the first cycle's reads: {first:?}; a cycle's in which nothing changed, at most: \
         {typical:?}; one's in which two words changed: {changed:?}; the longest the store's \
         lock was waited for: {longest:?}"
    );
    assert!(
        first < once * 3 / 2 + Duration::from_millis(200),
        "{first:?}"
    );
    assert!(typical < once / 20, "{typical:?} against {once:?}");
    assert!(changed < once / 20, "{changed:?} against {once:?}");
    assert!(
        longest < Duration::from_millis(AGENT_MESSAGE_SUMMARY_WAIT_MS),
        "{longest:?}"
    );
}

/// The facts of sync that `cordelia status` shows arrive within its
/// second while cycles read a large personal channel, and `msg summary`
/// finds the store's lock within the time it tries it.
#[test]
#[ignore = "timed: run with --release, as the file says"]
fn the_status_answers_within_its_second_while_cycles_read_a_large_personal_channel() {
    let _alone = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let Large {
        st,
        wanted,
        channel,
        others: _others,
        ..
    } = large(tmp.path());
    let held = entries_of(&st, &channel);
    assert!(held >= (DEVICES * NAMES_EACH) as i64, "{held}");

    let stop = Arc::new(AtomicBool::new(false));
    let cycles = Arc::new(AtomicUsize::new(0));
    let cycling = {
        let (st, stop, cycles) = (st.clone(), stop.clone(), cycles.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                cycle(&st, &wanted);
                cycles.fetch_add(1, Ordering::SeqCst);
            }
        })
    };
    let probe = Probe::start(&st);
    let mut slowest = Duration::ZERO;
    // The first cycle, which reads every entry afresh, and five after it;
    // and twenty statuses at least.
    let mut asked = 0;
    while asked < 20 || cycles.load(Ordering::SeqCst) < 6 {
        asked += 1;
        let asked = Instant::now();
        let request = actix_web::test::TestRequest::default()
            .insert_header(("authorization", "Bearer t"))
            .to_http_request();
        let answer = actix_web::rt::System::new()
            .block_on(cordelia_api::sync::sync_status(request, st.clone()))
            .unwrap();
        let took = asked.elapsed();
        slowest = slowest.max(took);
        assert!(answer.status().is_success());
        let body = actix_web::rt::System::new()
            .block_on(actix_web::body::to_bytes(answer.into_body()))
            .unwrap();
        let facts: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(facts["stands"], "applied", "{facts}");
        assert!(took < STATUS_WAIT, "the status took {took:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
    let longest = probe.longest();
    stop.store(true, Ordering::SeqCst);
    cycling.join().unwrap();
    let cycles = cycles.load(Ordering::SeqCst);
    eprintln!(
        "entries of the personal channel: {held}; cycles: {cycles}; statuses: {asked}; the \
         slowest status: {slowest:?}; the longest the store's lock was waited for: {longest:?}"
    );
    assert!(
        longest < Duration::from_millis(AGENT_MESSAGE_SUMMARY_WAIT_MS),
        "{longest:?}"
    );
}
