//! The node's one lock on its database, timed (decision 2026-10-22 §1.1,
//! rule 4; §1.2).
//!
//! [`TimedLock`] is a `Mutex` whose [`TimedLock::lock`] and
//! [`TimedLock::try_lock`] have the form of the `Mutex`'s own, so that the
//! places that take the lock are not changed. Each take is timed: its
//! wait, from asking for the lock to holding it, and its hold, until its
//! guard is dropped. Each is recorded in a histogram of its kind
//! ([`Kind`]): the kind of the request or task it is in.
//!
//! **A take's kind is said where the request or task begins,** not where
//! the lock is taken: [`taking`] says it for what a thread does until its
//! guard is dropped, and [`take_as`] for a future, each time it is polled,
//! on whatever thread. A take that nothing said a kind for is `Other`.
//!
//! **The two mutexes taken while the lock is held at a relay,** its rates
//! and its room, are taken through the guard ([`TimedGuard::nested`]):
//! the time spent waiting for them is recorded apart, so that a wait on
//! them is not read as a long hold of the store. It is in the hold all the
//! same: a hold is how long the store was held.
//!
//! **What timing costs** is a read of the monotonic clock and an addition
//! as the lock is taken where nothing holds it (two reads where it waits),
//! and one read and a few additions as it is let go (§1.1, rule 5). It is measured against LOCK_TIMING_COST_MAX_NANOS by a
//! test here, and is under it: every take is timed.

use std::cell::Cell;
use std::future::Future;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::{LockResult, Mutex, MutexGuard, PoisonError, TryLockError, TryLockResult};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use crate::load::{Histogram, HistogramRead, Kind};

thread_local! {
    /// The kind of take that what runs on this thread now is.
    static KIND: Cell<Kind> = const { Cell::new(Kind::Other) };
}

/// The kind of take that what runs on this thread now is.
fn kind_now() -> Kind {
    KIND.with(Cell::get)
}

/// While this lives, each take of a timed lock on this thread is of its
/// kind. It puts back the kind before it as it is dropped, so that one may
/// be said within another.
#[must_use = "the kind holds only while this lives"]
pub struct Taking {
    before: Kind,
    /// It is undone on the thread it was made on.
    _here: PhantomData<*const ()>,
}

impl Drop for Taking {
    fn drop(&mut self) {
        KIND.with(|kind| kind.set(self.before));
    }
}

/// Each take of a timed lock on this thread, until what this returns is
/// dropped, is of `kind`.
pub fn taking(kind: Kind) -> Taking {
    Taking {
        before: KIND.with(|now| now.replace(kind)),
        _here: PhantomData,
    }
}

/// A future whose takes of a timed lock are of one kind, on whatever
/// thread it is polled ([`take_as`]).
pub struct TakenAs<F> {
    kind: Kind,
    future: Pin<Box<F>>,
}

impl<F: Future> Future for TakenAs<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let _kind = taking(self.kind);
        self.future.as_mut().poll(cx)
    }
}

/// `future`, whose takes of a timed lock are of `kind`: it is said each
/// time the future is polled, and undone after, so that a task polled on
/// a thread between the polls of another keeps its own.
pub fn take_as<F: Future>(kind: Kind, future: F) -> TakenAs<F> {
    TakenAs {
        kind,
        future: Box::pin(future),
    }
}

/// A mutex taken while the lock is held, whose waits are timed apart
/// (decision 2026-10-22 §1.1, rule 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nested {
    /// A relay's counts of what each peer and address pushed and was
    /// handed.
    Rates,
    /// A relay's room for entries.
    Room,
}

impl Nested {
    /// Each of them, in the order they are served.
    pub const ALL: [Nested; 2] = [Nested::Rates, Nested::Room];

    /// Its name, as the route serves it.
    pub fn name(self) -> &'static str {
        match self {
            Nested::Rates => "rates",
            Nested::Room => "room",
        }
    }
}

/// The waits and holds of a timed lock, by kind of take, and the waits
/// for the mutexes taken under it.
#[derive(Debug, Default)]
pub struct LockTimes {
    wait: [Histogram; Kind::ALL.len()],
    hold: [Histogram; Kind::ALL.len()],
    nested: [Histogram; Nested::ALL.len()],
}

impl LockTimes {
    /// The waits of the takes of `kind`.
    pub fn wait(&self, kind: Kind) -> HistogramRead {
        self.wait[kind as usize].read()
    }

    /// The holds of the takes of `kind`.
    pub fn hold(&self, kind: Kind) -> HistogramRead {
        self.hold[kind as usize].read()
    }

    /// The waits for `nested` while the lock was held.
    pub fn nested(&self, nested: Nested) -> HistogramRead {
        self.nested[nested as usize].read()
    }
}

/// A lock that is taken also where a holder panicked, for what is whole
/// after any one step. A `Mutex` is one and a [`TimedLock`] is one, so a
/// helper that takes either is not changed by which it is given.
pub trait LockWhole {
    type Guard<'a>
    where
        Self: 'a;

    /// Take it, also where a holder panicked.
    fn lock_whole(&self) -> Self::Guard<'_>;
}

impl<T> LockWhole for Mutex<T> {
    type Guard<'a>
        = MutexGuard<'a, T>
    where
        T: 'a;

    fn lock_whole(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<T> LockWhole for TimedLock<T> {
    type Guard<'a>
        = TimedGuard<'a, T>
    where
        T: 'a;

    fn lock_whole(&self) -> TimedGuard<'_, T> {
        self.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A mutex whose every take is timed (see the module's documentation).
#[derive(Debug, Default)]
pub struct TimedLock<T> {
    inner: Mutex<T>,
    times: LockTimes,
}

/// A take of a [`TimedLock`]: the lock is held until this is dropped, and
/// its hold is recorded then.
pub struct TimedGuard<'a, T> {
    /// Taken out as this is dropped, so that the lock is let go before
    /// the hold is recorded.
    guard: Option<MutexGuard<'a, T>>,
    times: &'a LockTimes,
    kind: Kind,
    since: Instant,
}

impl<T> TimedLock<T> {
    /// A lock of `value`, which nothing has taken.
    pub fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            times: LockTimes::default(),
        }
    }

    /// The waits and holds of its takes so far.
    pub fn times(&self) -> &LockTimes {
        &self.times
    }

    /// Take it, waiting for as long as it is held, as `Mutex::lock` does:
    /// poisoned where a holder panicked, with the guard in the error.
    pub fn lock(&self) -> LockResult<TimedGuard<'_, T>> {
        let kind = kind_now();
        // A lock that nothing holds is taken at once, and its wait is
        // none: the clock is read once, as the hold begins. Only a take
        // that waits reads it as it asks (decision 2026-10-22 §1.1, rule
        // 5).
        let (taken, since) = match self.inner.try_lock() {
            Ok(guard) => {
                let since = Instant::now();
                self.times.wait[kind as usize].record(Duration::ZERO);
                (Ok(guard), since)
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                let since = Instant::now();
                self.times.wait[kind as usize].record(Duration::ZERO);
                (Err(poisoned), since)
            }
            Err(TryLockError::WouldBlock) => {
                let asked = Instant::now();
                let taken = self.inner.lock();
                let since = Instant::now();
                self.times.wait[kind as usize].record(since - asked);
                (taken, since)
            }
        };
        match taken {
            Ok(guard) => Ok(self.guard(guard, kind, since)),
            Err(poisoned) => Err(PoisonError::new(self.guard(
                poisoned.into_inner(),
                kind,
                since,
            ))),
        }
    }

    /// Take it where nothing holds it, as `Mutex::try_lock` does. A take
    /// that finds it held is no take, and nothing is recorded of it.
    pub fn try_lock(&self) -> TryLockResult<TimedGuard<'_, T>> {
        let kind = kind_now();
        let asked = Instant::now();
        let taken = self.inner.try_lock();
        let since = Instant::now();
        let guard = match taken {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(TryLockError::WouldBlock),
            Err(TryLockError::Poisoned(poisoned)) => {
                self.times.wait[kind as usize].record(since - asked);
                let guard = self.guard(poisoned.into_inner(), kind, since);
                return Err(TryLockError::Poisoned(PoisonError::new(guard)));
            }
        };
        self.times.wait[kind as usize].record(since - asked);
        Ok(self.guard(guard, kind, since))
    }

    /// What it holds, where nothing can hold the lock: it is borrowed
    /// mutably.
    pub fn get_mut(&mut self) -> LockResult<&mut T> {
        self.inner.get_mut()
    }

    /// What it holds, given up.
    pub fn into_inner(self) -> LockResult<T> {
        self.inner.into_inner()
    }

    fn guard<'a>(
        &'a self,
        guard: MutexGuard<'a, T>,
        kind: Kind,
        since: Instant,
    ) -> TimedGuard<'a, T> {
        TimedGuard {
            guard: Some(guard),
            times: &self.times,
            kind,
            since,
        }
    }
}

impl<'a, T> TimedGuard<'a, T> {
    /// Take `mutex` while this lock is held, and record the wait for it
    /// apart as one for `which` (decision 2026-10-22 §1.1, rule 4). A
    /// holder of `mutex` that panicked left what it guards whole, as each
    /// of the relay's counts is after any one step, so it is taken all the
    /// same.
    pub fn nested<'b, U>(&self, which: Nested, mutex: &'b Mutex<U>) -> MutexGuard<'b, U> {
        let asked = Instant::now();
        let guard = mutex.lock().unwrap_or_else(PoisonError::into_inner);
        self.times.nested[which as usize].record(asked.elapsed());
        guard
    }
}

impl<T> Deref for TimedGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        match &self.guard {
            Some(guard) => guard,
            None => unreachable!("a guard is taken out only as it is dropped"),
        }
    }
}

impl<T> DerefMut for TimedGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        match &mut self.guard {
            Some(guard) => guard,
            None => unreachable!("a guard is taken out only as it is dropped"),
        }
    }
}

impl<T> Drop for TimedGuard<'_, T> {
    fn drop(&mut self) {
        drop(self.guard.take());
        self.times.hold[self.kind as usize].record(self.since.elapsed());
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for TimedGuard<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::LOCK_TIMING_COST_MAX_NANOS;
    use std::sync::Arc;

    /// The kinds whose takes moved, and how many each.
    fn moved(times: &LockTimes, of: fn(&LockTimes, Kind) -> HistogramRead) -> Vec<(Kind, u64)> {
        Kind::ALL
            .into_iter()
            .map(|kind| (kind, of(times, kind).count))
            .filter(|(_, count)| *count > 0)
            .collect()
    }

    /// A take is recorded in its kind's histograms, its wait and its
    /// hold, and in no other kind's: the kind said for the thread, the one
    /// said within it while that lives, and `Other` where none is said.
    #[test]
    fn a_take_is_recorded_as_the_kind_said_for_it_and_as_no_other() {
        let lock = TimedLock::new(0u32);
        {
            let _pull = taking(Kind::Pull);
            *lock.lock().unwrap() += 1;
            {
                let _sweep = taking(Kind::Sweep);
                drop(lock.lock().unwrap());
            }
            drop(lock.lock().unwrap());
        }
        drop(lock.lock().unwrap());
        let times = lock.times();
        let want = vec![(Kind::Pull, 2), (Kind::Sweep, 1), (Kind::Other, 1)];
        assert_eq!(moved(times, LockTimes::wait), want);
        assert_eq!(moved(times, LockTimes::hold), want);
        assert_eq!(*lock.lock().unwrap(), 1);
    }

    /// A hold is recorded as long as the guard lived, and a wait as long
    /// as the lock was held by another.
    #[test]
    fn a_hold_is_as_long_as_its_guard_lives_and_a_wait_as_long_as_another_holds_it() {
        let lock = Arc::new(TimedLock::new(()));
        let held = lock.lock().unwrap();
        let waiting = {
            let lock = lock.clone();
            std::thread::spawn(move || {
                let _push = taking(Kind::Push);
                drop(lock.lock().unwrap());
            })
        };
        std::thread::sleep(Duration::from_millis(30));
        drop(held);
        waiting.join().unwrap();
        let times = lock.times();
        assert!(times.hold(Kind::Other).max_micros >= 30_000);
        assert!(times.wait(Kind::Push).max_micros >= 20_000);
        assert!(times.hold(Kind::Push).max_micros < 20_000);
        assert_eq!(times.wait(Kind::Other).count, 1);
    }

    /// A future's takes are of the kind it was given, on whatever thread
    /// it is polled, and the kind is undone between its polls: a take on
    /// the same thread between them is of its own kind.
    #[test]
    fn a_futures_takes_are_of_its_kind_and_not_of_what_runs_between_its_polls() {
        let lock = Arc::new(TimedLock::new(()));
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let rx = Arc::new(Mutex::new(rx));
        // A future that takes the lock, waits to be woken, and takes it
        // again: polled twice.
        let future = {
            let lock = lock.clone();
            let mut first = true;
            take_as(
                Kind::Pass,
                std::future::poll_fn(move |cx| {
                    drop(lock.lock().unwrap());
                    if std::mem::take(&mut first) {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    let _ = rx.lock().unwrap().try_recv();
                    Poll::Ready(())
                }),
            )
        };
        let mut future = Box::pin(future);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(future.as_mut().poll(&mut cx).is_pending());
        // Between its polls, on this thread, a take of its own kind.
        drop(lock.lock().unwrap());
        // Polled again on another thread.
        let polled = std::thread::spawn(move || {
            let mut cx = Context::from_waker(std::task::Waker::noop());
            future.as_mut().poll(&mut cx).is_ready()
        });
        assert!(polled.join().unwrap());
        let _ = tx.send(());
        assert_eq!(
            moved(lock.times(), LockTimes::hold),
            [(Kind::Pass, 2), (Kind::Other, 1)]
        );
    }

    /// A mutex taken through the guard is timed apart, as the one it is,
    /// and as no other; the take of the lock is recorded as its own.
    #[test]
    fn a_wait_for_a_mutex_taken_under_the_lock_is_recorded_apart() {
        let lock = TimedLock::new(());
        let rates = Arc::new(Mutex::new(0u32));
        let room = Mutex::new(0u32);
        // Another thread holds the rates for 30 ms.
        let (tx, rx) = std::sync::mpsc::channel();
        let release = {
            let rates = rates.clone();
            std::thread::spawn(move || {
                let held = rates.lock().unwrap();
                tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(30));
                drop(held);
            })
        };
        rx.recv().unwrap();
        {
            let _pull = taking(Kind::Pull);
            let db = lock.lock().unwrap();
            *db.nested(Nested::Rates, &rates) += 1;
            *db.nested(Nested::Room, &room) += 1;
        }
        release.join().unwrap();
        let times = lock.times();
        assert_eq!(times.nested(Nested::Rates).count, 1);
        assert!(times.nested(Nested::Rates).max_micros >= 20_000);
        assert_eq!(times.nested(Nested::Room).count, 1);
        assert!(times.nested(Nested::Room).max_micros < 20_000);
        // The wait for the rates is in the hold of the store, and not in
        // its wait.
        assert!(times.hold(Kind::Pull).max_micros >= 20_000);
        assert!(times.wait(Kind::Pull).max_micros < 20_000);
        assert_eq!(*rates.lock().unwrap(), 1);
    }

    /// A take that finds the lock held is no take, and records nothing;
    /// one that finds it free is recorded as any take is.
    #[test]
    fn a_try_that_finds_the_lock_held_records_nothing() {
        let lock = TimedLock::new(());
        let held = lock.lock().unwrap();
        let _proof = taking(Kind::Proof);
        assert!(matches!(lock.try_lock(), Err(TryLockError::WouldBlock)));
        drop(held);
        drop(lock.try_lock().unwrap());
        let times = lock.times();
        assert_eq!(
            moved(times, LockTimes::wait),
            [(Kind::Proof, 1), (Kind::Other, 1)]
        );
        assert_eq!(
            moved(times, LockTimes::hold),
            [(Kind::Proof, 1), (Kind::Other, 1)]
        );
    }

    /// A lock whose holder panicked is poisoned as a `Mutex` is, and its
    /// guard is in the error; the panicked hold is recorded.
    #[test]
    fn a_lock_whose_holder_panicked_is_poisoned_as_a_mutex_is() {
        let lock = Arc::new(TimedLock::new(5u32));
        let panicked = {
            let lock = lock.clone();
            std::thread::spawn(move || {
                let _held = lock.lock().unwrap();
                panic!("a holder that panics");
            })
        };
        assert!(panicked.join().is_err());
        let guard = lock.lock().unwrap_err().into_inner();
        assert_eq!(*guard, 5);
        drop(guard);
        assert_eq!(lock.times().hold(Kind::Other).count, 2);
    }

    /// The nanoseconds that `takes` takes of a lock cost each, the least
    /// of several rounds: the least is the cost, and the rest is what
    /// else the machine was doing.
    fn cost_of_a_take(take: impl Fn()) -> f64 {
        const TAKES: u32 = 1_000_000;
        const ROUNDS: usize = 11;
        (0..ROUNDS)
            .map(|_| {
                let begun = Instant::now();
                for _ in 0..TAKES {
                    take();
                }
                begun.elapsed().as_nanos() as f64 / f64::from(TAKES)
            })
            .fold(f64::INFINITY, f64::min)
    }

    /// What timing a take costs (decision 2026-10-22 §1.1, rule 5): a
    /// million takes of a timed lock, and a million of the `Mutex` it
    /// wraps, each the least of several rounds. The difference is under
    /// 1% of the median hold that §1.4 measured
    /// (LOCK_TIMING_COST_MAX_NANOS), so every take is timed and none is
    /// sampled. It prints both, for the record.
    #[test]
    fn timing_a_take_costs_under_one_hundredth_of_the_median_hold() {
        let timed = TimedLock::new(0u64);
        let plain = Mutex::new(0u64);
        let _pull = taking(Kind::Pull);
        let untimed = cost_of_a_take(|| *std::hint::black_box(&plain).lock().unwrap() += 1);
        let with_timing = cost_of_a_take(|| *std::hint::black_box(&timed).lock().unwrap() += 1);
        let cost = with_timing - untimed;
        println!(
            "a take: {untimed:.1} ns untimed, {with_timing:.1} ns timed; timing costs {cost:.1} ns, \
             against a bar of {LOCK_TIMING_COST_MAX_NANOS} ns"
        );
        assert!(
            cost < LOCK_TIMING_COST_MAX_NANOS as f64,
            "timing a take costs {cost:.1} ns, over {LOCK_TIMING_COST_MAX_NANOS} ns"
        );
        assert!(timed.times().hold(Kind::Pull).count >= 11_000_000);
    }
}
