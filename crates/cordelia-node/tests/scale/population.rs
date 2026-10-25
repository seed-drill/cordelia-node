//! The population of a stage, and what each person does in the window
//! (decision 2026-10-22 §2.1, §2.2): the profiles, the stages, the people
//! and their addresses, and each person's plan of sessions, edits and
//! times off, all drawn from the run's seed (§4.3, rule 3).

use std::collections::HashMap;
use std::net::Ipv4Addr;

// ── Numbers from a seed ──────────────────────────────────────────────

/// Numbers drawn from a seed: xoshiro256**, seeded through splitmix64.
/// Each use of the seed takes a stream of its own, named by what it is
/// for, so that what one part of the plan draws does not move another.
#[derive(Debug, Clone)]
pub struct Rng([u64; 4]);

impl Rng {
    /// The stream named `what` of the seed `seed`.
    pub fn of(seed: u64, what: &str) -> Self {
        // FNV-1a of the name, mixed into the seed.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in what.bytes() {
            h ^= u64::from(byte);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        let mut x = seed ^ h.rotate_left(17);
        let mut next = || {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        Rng([next(), next(), next(), next()])
    }

    pub fn u64(&mut self) -> u64 {
        let s = &mut self.0;
        let out = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        out
    }

    /// A number in [0, 1).
    pub fn f64(&mut self) -> f64 {
        (self.u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// A number in [0, n).
    pub fn below(&mut self, n: usize) -> usize {
        assert!(n > 0);
        (self.f64() * n as f64) as usize % n
    }

    /// A number drawn evenly from [lo, hi).
    pub fn between(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.f64()
    }

    pub fn chance(&mut self, p: f64) -> bool {
        self.f64() < p
    }

    /// The wait to the next event of a Poisson process of `rate` an
    /// hour, in seconds.
    pub fn wait_at(&mut self, rate_an_hour: f64) -> f64 {
        -(1.0 - self.f64()).ln() * 3600.0 / rate_an_hour
    }

    /// A size drawn evenly on a log scale within [lo, hi] (§2.1, item 5).
    pub fn log_between(&mut self, lo: usize, hi: usize) -> usize {
        let (lo, hi) = ((lo as f64).ln(), (hi as f64).ln());
        self.between(lo, hi).exp().round() as usize
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

// ── The profiles (§2.1) ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Profile {
    Casual,
    Developer,
    Heavy,
}

impl Profile {
    pub const ALL: [Profile; 3] = [Profile::Casual, Profile::Developer, Profile::Heavy];

    pub fn name(self) -> &'static str {
        match self {
            Profile::Casual => "casual",
            Profile::Developer => "developer",
            Profile::Heavy => "heavy",
        }
    }

    /// A person's devices (item 1: chosen).
    pub fn devices(self) -> usize {
        match self {
            Profile::Casual => 2,
            Profile::Developer | Profile::Heavy => 3,
        }
    }

    /// A person's names (item 2).
    pub fn names(self) -> usize {
        match self {
            Profile::Casual => 4,
            Profile::Developer => 12,
            Profile::Heavy => 30,
        }
    }

    /// The person's steady edits an hour (item 3), beside the bursts.
    pub fn edits_an_hour(self) -> f64 {
        match self {
            Profile::Casual => 10.0,
            Profile::Developer => 20.0,
            Profile::Heavy => 30.0,
        }
    }

    /// The size of a memory file, in bytes, at the least and the most
    /// (item 5).
    pub fn sizes(self) -> (usize, usize) {
        match self {
            Profile::Casual => (512, 5 * 1024),
            Profile::Developer => (1024, 10 * 1024),
            Profile::Heavy => (2 * 1024, 20 * 1024),
        }
    }

    /// The burst: its edits, and the seconds they are written over, once
    /// every 30 minutes (item 6).
    pub fn burst(self) -> (usize, f64) {
        match self {
            Profile::Casual => (5, 10.0),
            Profile::Developer => (10, 30.0),
            Profile::Heavy => (20, 60.0),
        }
    }

    /// The chance, in each 30 minutes, that a device that is not the
    /// active one is off (item 4: chosen).
    pub fn off_chance(self) -> f64 {
        match self {
            Profile::Casual => 0.5,
            Profile::Developer => 0.2,
            Profile::Heavy => 0.0,
        }
    }

    /// The share of time that a device that is not the active one is off,
    /// as item 4 gives it: its chance in each 30 minutes, times the mean
    /// of 5 to 25 minutes.
    pub fn share_off(self) -> f64 {
        self.off_chance() * 15.0 / 30.0
    }

    /// The edits an hour of the model, the steady ones and the bursts
    /// (bar 12).
    pub fn model_edits_an_hour(self) -> f64 {
        self.edits_an_hour() + 2.0 * self.burst().0 as f64
    }

    /// The channels a device pulls: its names, the personal channel and
    /// the messages channel (§2.3).
    pub fn pulled(self) -> usize {
        self.names() + 2
    }

    /// The person's channels at a relay: the names, the personal channel,
    /// the messages channel and the phrase's channel (§2.2).
    pub fn channels(self) -> usize {
        self.names() + 3
    }
}

/// Seconds in each block of time that a burst and a time off are drawn
/// in (§2.1, items 4 and 6).
pub const BLOCK_SECS: f64 = 1800.0;

/// A file is never written again on the same device within this many
/// seconds of its last write there: three of the adapter's cycles (§2.1,
/// item 8).
pub const REWRITE_GAP_SECS: f64 = 15.0;

/// A session lasts this long, drawn evenly (§2.1, item 7).
pub const SESSION_SECS: (f64, f64) = (600.0, 1800.0);

/// A time off lasts this long, drawn evenly (§2.1, item 4).
pub const OFF_SECS: (f64, f64) = (300.0, 1500.0);

// ── The stages (§2.2) ────────────────────────────────────────────────

/// A stage. Stages 100 and 190 are gate 10 for R1; 250 and 500 come
/// after change B (rule 7 of §2.2) and are not built here. The small
/// stage is section 6's test 4: two relays and seven devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Small,
    Hundred,
    OneNinety,
}

impl Stage {
    pub const ALL: [Stage; 3] = [Stage::Small, Stage::Hundred, Stage::OneNinety];

    /// The stage that `CORDELIA_SCALE_STAGE` names.
    pub fn parse(said: &str) -> Result<Stage, String> {
        match said.trim() {
            "small" => Ok(Stage::Small),
            "100" => Ok(Stage::Hundred),
            "190" => Ok(Stage::OneNinety),
            "250" | "500" => Err(format!(
                "stage {said} runs only after change B, with the relays given a bound of 576 \
                 (decision 2026-10-22 §2.2, rule 7): it is after R1, and not built"
            )),
            other => Err(format!(
                "CORDELIA_SCALE_STAGE is {other:?}: this harness runs small, 100 and 190"
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Stage::Small => "small",
            Stage::Hundred => "100",
            Stage::OneNinety => "190",
        }
    }

    /// The people of each profile (§2.2's table). The small stage is
    /// test 4's: one casual person, one developer, and one person split
    /// between the relays, a casual one.
    pub fn mix(self) -> [(Profile, usize); 3] {
        match self {
            Stage::Small => [
                (Profile::Casual, 2),
                (Profile::Developer, 1),
                (Profile::Heavy, 0),
            ],
            Stage::Hundred => [
                (Profile::Casual, 20),
                (Profile::Developer, 14),
                (Profile::Heavy, 6),
            ],
            Stage::OneNinety => [
                (Profile::Casual, 38),
                (Profile::Developer, 27),
                (Profile::Heavy, 11),
            ],
        }
    }

    pub fn devices(self) -> usize {
        self.mix().iter().map(|(p, n)| p.devices() * n).sum()
    }

    pub fn people(self) -> usize {
        self.mix().iter().map(|(_, n)| n).sum()
    }

    /// Whether the stage has the office of rule 6: every stage of §2.2
    /// does; the small run of test 4 does not.
    pub fn has_office(self) -> bool {
        self != Stage::Small
    }
}

// ── The people ───────────────────────────────────────────────────────

/// The office's people: three heavy people (rule 6 of §2.2).
pub const OFFICE_PEOPLE: usize = 3;

/// The one address the office's devices share in the window: a /24 of
/// its own in 127.0.0.0/8, which no person's address is in.
pub const OFFICE_ADDRESS: Ipv4Addr = Ipv4Addr::new(127, 10, 0, 1);

/// The address of person `k` at setup: a /24 of their own (rule 5 of
/// §2.2).
pub fn person_address(k: usize) -> Ipv4Addr {
    Ipv4Addr::new(127, 20 + (k / 256) as u8, (k % 256) as u8, 1)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub index: usize,
    pub profile: Profile,
    pub devices: usize,
    /// One of the office's people (rule 6).
    pub office: bool,
    /// Their devices split between the relays (rule 4): the first is set
    /// up with the first relay only, and the others with the second.
    pub split: bool,
    /// Their address at setup.
    pub address: Ipv4Addr,
}

impl Person {
    /// The relays (0 and 1) that device `device` is set up with.
    pub fn relays_of(&self, device: usize, relays: usize) -> Vec<usize> {
        match (self.split, device) {
            (true, 0) => vec![0],
            (true, _) => vec![1],
            (false, _) => (0..relays).collect(),
        }
    }

    /// The address its devices have in the window.
    pub fn address_in_window(&self) -> Ipv4Addr {
        match self.office {
            true => OFFICE_ADDRESS,
            false => self.address,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Population {
    pub people: Vec<Person>,
    /// The order the office's devices start in at step 4: (person,
    /// device), fixed by the seed.
    pub office_order: Vec<(usize, usize)>,
}

impl Population {
    /// The population of `stage` with `relays` relays, from `seed`.
    pub fn of(stage: Stage, seed: u64, relays: usize) -> Population {
        let mut profiles: Vec<Profile> = stage
            .mix()
            .iter()
            .flat_map(|(p, n)| std::iter::repeat_n(*p, *n))
            .collect();
        if stage == Stage::Small {
            // Test 4's three people, in a fixed order: one casual, one
            // developer, and the casual person split between the relays.
            profiles = vec![Profile::Casual, Profile::Developer, Profile::Casual];
        } else {
            Rng::of(seed, "population/profiles").shuffle(&mut profiles);
        }
        let mut people: Vec<Person> = profiles
            .iter()
            .enumerate()
            .map(|(index, profile)| Person {
                index,
                profile: *profile,
                devices: profile.devices(),
                office: false,
                split: false,
                address: person_address(index),
            })
            .collect();
        let mut office_order = Vec::new();
        if stage.has_office() {
            // The first three heavy people of the shuffled order.
            let office: Vec<usize> = people
                .iter()
                .filter(|p| p.profile == Profile::Heavy)
                .take(OFFICE_PEOPLE)
                .map(|p| p.index)
                .collect();
            for k in &office {
                people[*k].office = true;
                office_order.extend((0..people[*k].devices).map(|d| (*k, d)));
            }
            Rng::of(seed, "population/office order").shuffle(&mut office_order);
        }
        if relays == 2 {
            match stage {
                Stage::Small => people[2].split = true,
                _ => {
                    // A tenth of the people, among those not in the office.
                    let split = ((people.len() as f64) / 10.0).round() as usize;
                    let mut out: Vec<usize> = people
                        .iter()
                        .filter(|p| !p.office)
                        .map(|p| p.index)
                        .collect();
                    Rng::of(seed, "population/split").shuffle(&mut out);
                    for k in out.into_iter().take(split) {
                        people[k].split = true;
                    }
                }
            }
        }
        Population {
            people,
            office_order,
        }
    }

    pub fn devices(&self) -> usize {
        self.people.iter().map(|p| p.devices).sum()
    }

    /// Each device, as (person, device), in the people's order.
    pub fn each_device(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.people
            .iter()
            .flat_map(|p| (0..p.devices).map(move |d| (p.index, d)))
    }
}

// ── What a person does ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum How {
    /// SIGTERM, and a start again on the same data directory.
    Stop,
    /// SIGSTOP, then SIGCONT.
    Freeze,
}

/// A device off for a time, in seconds from the window's start.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Off {
    pub person: usize,
    pub device: usize,
    pub start: f64,
    pub end: f64,
    pub how: How,
}

/// An edit the plan places: on which device, in which name and file, its
/// size, and when, in seconds from the window's start.
#[derive(Debug, Clone, PartialEq)]
pub struct Planned {
    pub person: usize,
    pub device: usize,
    pub name: usize,
    pub file: String,
    pub new: bool,
    pub size: usize,
    pub at: f64,
    pub burst: bool,
}

/// One session: the person's active device from `start` to `end`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Session {
    pub person: usize,
    pub device: usize,
    pub start: f64,
    pub end: f64,
}

/// What one session brings: the session, its edits, and the times off
/// that begin in it.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionPlan {
    pub session: Session,
    pub edits: Vec<Planned>,
    pub offs: Vec<Off>,
}

/// The name of the folder and the name of name `k`.
pub fn name_of(k: usize) -> String {
    format!("n{:02}", k + 1)
}

/// The name of the first files, written at setup: 10 in each name.
pub fn first_file(k: usize) -> String {
    format!("f{:03}.md", k + 1)
}

/// The times off are given: drawn as item 4 of §2.1 says, or fixed (test
/// 4's one device off and on).
#[derive(Debug, Clone, PartialEq)]
pub enum Offs {
    Drawn,
    Fixed(Vec<Off>),
}

/// A person's plan, drawn a session at a time, so that a device that is
/// removed in the window leaves the plan from then on.
#[derive(Debug, Clone)]
pub struct PersonPlan {
    pub person: usize,
    pub profile: Profile,
    /// The devices still the person's, in their order.
    devices: Vec<usize>,
    sessions: Rng,
    edits: Rng,
    bursts: Rng,
    offs_drawn: Vec<Rng>,
    /// The files of each name.
    files: Vec<Vec<String>>,
    /// When each file was last written on each device: (device, name,
    /// file).
    written: HashMap<(usize, usize, String), f64>,
    next_file: usize,
    next_steady: f64,
    next_start: f64,
    /// Times off that are taken: a device is not chosen while in one.
    taken_offs: Vec<Off>,
    /// The next block whose times off and burst are not drawn yet.
    next_block: usize,
    /// Times off drawn and not yet taken or dropped, and bursts.
    drawn_offs: Vec<Off>,
    burst_starts: Vec<f64>,
    fixed: Option<Vec<Off>>,
    /// The active device of the session under way.
    active: Option<usize>,
}

impl PersonPlan {
    /// The plan of `person` from the window's start, whose first files
    /// are `first_files` in each name, from `seed`.
    pub fn new(person: &Person, seed: u64, first_files: usize, offs: &Offs) -> PersonPlan {
        let k = person.index;
        let files = (0..person.profile.names())
            .map(|_| (0..first_files).map(first_file).collect())
            .collect();
        let mut edits = Rng::of(seed, &format!("person {k}/edits"));
        let next_steady = edits.wait_at(person.profile.edits_an_hour());
        PersonPlan {
            person: k,
            profile: person.profile,
            devices: (0..person.devices).collect(),
            sessions: Rng::of(seed, &format!("person {k}/sessions")),
            edits,
            bursts: Rng::of(seed, &format!("person {k}/bursts")),
            offs_drawn: (0..person.devices)
                .map(|d| Rng::of(seed, &format!("person {k}/device {d}/offs")))
                .collect(),
            files,
            written: HashMap::new(),
            next_file: 0,
            next_steady,
            next_start: 0.0,
            taken_offs: Vec::new(),
            next_block: 0,
            drawn_offs: Vec::new(),
            burst_starts: Vec::new(),
            fixed: match offs {
                Offs::Drawn => None,
                Offs::Fixed(all) => Some(all.iter().filter(|o| o.person == k).copied().collect()),
            },
            active: None,
        }
    }

    /// The device that is active now, if a session has begun.
    pub fn active(&self) -> Option<usize> {
        self.active
    }

    /// When the session under way ends.
    pub fn session_end(&self) -> f64 {
        self.next_start
    }

    /// The device `device` is the person's no longer, from `at`: it is not
    /// chosen again, and its times off from then on are dropped. Where it is
    /// the active device, its session ends at `at`.
    pub fn remove(&mut self, device: usize, at: f64) {
        // Its session is cut at `at`: the next begins there, with the steady
        // edits drawn again from it (those drawn past it were the cut
        // session's, and are dropped where they wait to be written).
        if self.active == Some(device) && at < self.next_start {
            self.next_start = at;
            self.active = None;
            self.next_steady = at + self.edits.wait_at(self.profile.edits_an_hour());
        }
        self.devices.retain(|d| *d != device);
        self.drawn_offs.retain(|o| o.device != device);
        self.taken_offs
            .retain(|o| o.device != device || o.start < at);
        if let Some(fixed) = &mut self.fixed {
            fixed.retain(|o| o.device != device);
        }
    }

    /// Draw the times off and the bursts of each block up to `until`.
    fn draw_blocks(&mut self, until: f64) {
        while (self.next_block as f64) * BLOCK_SECS < until {
            let block = self.next_block as f64 * BLOCK_SECS;
            let (_, secs) = self.profile.burst();
            self.burst_starts
                .push(block + self.bursts.between(0.0, BLOCK_SECS - secs));
            if self.fixed.is_none() {
                for (d, rng) in self.offs_drawn.iter_mut().enumerate() {
                    if !rng.chance(self.profile.off_chance()) {
                        continue;
                    }
                    // Within its block, so that two times off of a device
                    // do not overlap.
                    let long = rng.between(OFF_SECS.0, OFF_SECS.1);
                    let start = block + rng.between(0.0, BLOCK_SECS - long);
                    let how = match rng.chance(0.5) {
                        true => How::Stop,
                        false => How::Freeze,
                    };
                    self.drawn_offs.push(Off {
                        person: self.person,
                        device: d,
                        start,
                        end: start + long,
                        how,
                    });
                }
            }
            self.next_block += 1;
        }
    }

    /// Whether device `d` is in a time off that is taken at `t`.
    fn is_off(&self, d: usize, t: f64) -> bool {
        self.taken_offs
            .iter()
            .any(|o| o.device == d && o.start <= t && t < o.end)
    }

    /// The next session, its edits, and the times off that begin in it.
    pub fn next_session(&mut self) -> SessionPlan {
        let start = self.next_start;
        let end = start + self.sessions.between(SESSION_SECS.0, SESSION_SECS.1);
        self.next_start = end;
        self.draw_blocks(end + BLOCK_SECS);
        // The active device: drawn among those that are on (item 7).
        let on: Vec<usize> = self
            .devices
            .iter()
            .copied()
            .filter(|d| !self.is_off(*d, start))
            .collect();
        let on = match on.is_empty() {
            // Never so where a device is off only while another is
            // active; kept so that a plan cannot stop.
            true => self.devices.clone(),
            false => on,
        };
        let device = on[self.sessions.below(on.len())];
        self.active = Some(device);
        // The times off that begin in the session: none of the active
        // device's (it is never turned off in its session).
        let mut offs = Vec::new();
        let candidates: Vec<Off> = match &mut self.fixed {
            Some(fixed) => {
                let (now, later): (Vec<Off>, Vec<Off>) = fixed.iter().partition(|o| o.start < end);
                *fixed = later;
                now
            }
            None => {
                let (now, later): (Vec<Off>, Vec<Off>) =
                    self.drawn_offs.iter().partition(|o| o.start < end);
                self.drawn_offs = later;
                now
            }
        };
        for mut off in candidates {
            if off.start < start || !self.devices.contains(&off.device) {
                continue;
            }
            if off.device == device {
                match self.fixed.is_some() {
                    // A fixed time off is of a device that is not active.
                    true => match self.devices.iter().find(|d| **d != device) {
                        Some(other) => off.device = *other,
                        None => continue,
                    },
                    false => continue,
                }
            }
            self.taken_offs.push(off);
            offs.push(off);
        }
        // The edits: the steady ones, and the bursts that begin in it.
        let mut times: Vec<(f64, bool)> = Vec::new();
        while self.next_steady < end {
            times.push((self.next_steady, false));
            self.next_steady += self.edits.wait_at(self.profile.edits_an_hour());
        }
        let (n, secs) = self.profile.burst();
        // A burst that would run past the session's end is begun earlier,
        // so that it is written on the session's device (item 7).
        let bursts: Vec<f64> = self
            .burst_starts
            .iter()
            .copied()
            .filter(|b| *b >= start && *b < end)
            .map(|b| b.min(end - secs))
            .collect();
        for b in bursts {
            for i in 0..n {
                times.push((b + secs * i as f64 / n as f64, true));
            }
        }
        times.sort_by(|a, b| a.0.total_cmp(&b.0));
        let mut edits = Vec::new();
        let mut in_burst: Vec<(usize, String)> = Vec::new();
        for (at, burst) in times {
            if !burst {
                in_burst.clear();
            }
            let planned = self.edit_at(device, at, burst, &in_burst);
            if burst {
                in_burst.push((planned.name, planned.file.clone()));
            }
            edits.push(planned);
        }
        SessionPlan {
            session: Session {
                person: self.person,
                device,
                start,
                end,
            },
            edits,
            offs,
        }
    }

    /// One edit on `device` at `at`: two in three rewrite a file of a
    /// name, one in three makes a new one; never a file written on this
    /// device within REWRITE_GAP_SECS, nor one of the burst under way.
    fn edit_at(
        &mut self,
        device: usize,
        at: f64,
        burst: bool,
        in_burst: &[(usize, String)],
    ) -> Planned {
        let names = self.files.len();
        let name = self.edits.below(names);
        let rewrite = self.edits.chance(2.0 / 3.0);
        let (lo, hi) = self.profile.sizes();
        let size = self.edits.log_between(lo, hi);
        let may: Vec<String> = match rewrite {
            false => Vec::new(),
            true => self.files[name]
                .iter()
                .filter(|file| {
                    let last = self.written.get(&(device, name, (*file).clone()));
                    last.is_none_or(|t| at - t >= REWRITE_GAP_SECS)
                        && !in_burst.iter().any(|(n, f)| *n == name && f == *file)
                })
                .cloned()
                .collect(),
        };
        let (file, new) = match may.is_empty() {
            true => {
                self.next_file += 1;
                let file = format!("w{:05}.md", self.next_file);
                self.files[name].push(file.clone());
                (file, true)
            }
            false => (may[self.edits.below(may.len())].clone(), false),
        };
        self.written.insert((device, name, file.clone()), at);
        Planned {
            person: self.person,
            device,
            name,
            file,
            new,
            size,
            at,
            burst,
        }
    }
}
