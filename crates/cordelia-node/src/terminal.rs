//! The terminal that a command asks at (decision 2026-10-04 §5).
//!
//! Every yes is asked by the command, at a terminal. A yes stops a
//! command that is run by mistake, or by a script that has no terminal:
//! so a command that asks refuses when its input is not one, before it
//! asks or does anything. [`Terminal::at`] is that refusal, and the one
//! way to a [`Terminal`]: nothing is asked, and no phrase is read, but
//! through one.
//!
//! The recovery phrase is typed here and nowhere else: never as an
//! argument, never over the local API. Its twelve words are asked for by
//! number, one at a time, with echo off ([`Terminal::phrase`]). Nothing
//! that is typed is shown: no letter, no star, no count of letters. Each
//! word is read into memory that is overwritten as soon as the word has
//! been looked up in the list.
//!
//! **After a word, a command says whether it is a word of the list: and
//! where a phrase is proved, it says nothing more** (decision 2026-10-04
//! §16). A tick beside a word's number means "a word of the list". A
//! wrong word of the list is given it as the right one is: nothing here
//! knows which it is, the same code runs for both, and the phrase is
//! judged only once the twelfth word is typed. (That is no proof against
//! timing: no step here is measured.) A word that is not in the list gets a cross, and its number is
//! asked again: that is no guess at a word, and has no bound. Only where
//! the words were shown a moment ago and are typed back
//! ([`Terminal::phrase_back`]) is a word held against the word shown at
//! its number: a miss is said there after a pause, and the third stops
//! the command.
//!
//! Whatever is typed is read from the terminal a byte at a time, and not
//! through the buffer that the program's standard input otherwise has:
//! what a person types at one prompt is not read ahead into memory that
//! nothing overwrites, where the next prompt is for the phrase.
//!
//! **Ctrl-C at a prompt that hides what is typed, or that has the other
//! screen up, is read as a key** (decision 2026-10-04 §16): the
//! terminal's own signals are off for that read, so that the terminal is
//! always put back as it was, and the command then ends. And what was
//! typed ahead of a prompt is dropped before the prompt is shown: an
//! Enter pressed twice does not answer what is asked next.
//!
//! **A process that is to hold a recovery phrase cannot be dumped or
//! traced** (decision 2026-10-04 §16): a command that makes or reads one
//! asks for its terminal through [`Terminal::for_a_phrase`], which sees
//! to that first, before anything is read ([`cannot_be_dumped`]). And a
//! phrase that is shown is written straight to the terminal, never
//! through the buffer that the program's standard output has, which
//! nothing overwrites.
//!
//! **A phrase is shown only on a terminal that lets go of it** (decision
//! 2026-10-04 §16). What is shown once is taken away by the terminal's
//! other screen and by the clearing of the lines that scrolled off
//! ([`Terminal::once`]). A terminal that is known to honour neither
//! keeps what was shown, and nothing is shown there
//! ([`Terminal::keeps_what_is_shown`]).

use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

use cordelia_core::protocol::{
    PHRASE_MISS_PAUSE_SECS, PHRASE_QUIET_AFTER_CROSS_SECS, PHRASE_TYPED_BACK_MISSES, PHRASE_WORDS,
};
use cordelia_crypto::phrase::{PhraseError, place_in_list};
use zeroize::{Zeroize, Zeroizing};

/// What a command that asks says where its input is no terminal.
pub const NOT_A_TERMINAL: &str = "this command asks before it does anything, and it asks at a \
                                  terminal: its input is not one. Nothing was done.";

/// What a command that shows or reads a recovery phrase says where what
/// it writes to is no terminal.
pub const NOT_TO_A_TERMINAL: &str = "this command shows or reads a recovery phrase, and what it \
                                     writes to is not a terminal: a phrase is shown on a \
                                     terminal and nowhere else. Nothing was done.";

/// Take everything off the screen: the cursor home, the screen cleared,
/// and the lines that have scrolled off it cleared too.
const CLEAR_SCREEN: &str = "\x1b[H\x1b[2J\x1b[3J";

/// The most that one line may hold, and one word of a recovery phrase as
/// it is typed: more than twelve of the longest words of the list and the
/// space between them, several times over.
const MAX_LINE: usize = 1024;

/// The terminal that a command was run at. There is one only where the
/// command's input is a terminal ([`Terminal::at`]).
pub struct Terminal(());

/// What a command says where Ctrl-C was pressed at a prompt that reads it
/// as a key: the terminal was put back as it was, and the command ends.
pub const INTERRUPTED: &str = "Interrupted: the terminal is as it was, and nothing was made.";

/// Drop what was typed and not yet read: before a prompt is shown, so
/// that nothing typed ahead of it answers it.
#[cfg(unix)]
fn drop_what_was_typed_ahead() {
    use rustix::termios::{QueueSelector, tcflush};
    let _ = tcflush(rustix::stdio::stdin(), QueueSelector::IFlush);
}

#[cfg(not(unix))]
fn drop_what_was_typed_ahead() {}

/// The terminal set so that each key is read as it is pressed, Ctrl-C
/// among them, and so that what is typed is not shown: its own signals
/// are off, it hands on no whole lines, and it echoes nothing. It is put
/// back as it was when this is dropped, whatever became of the reading.
/// What was typed before is dropped as it is set.
///
/// **And what was typed and not read is dropped before the terminal is
/// put back,** on every way out (decision 2026-10-04 §16): after the
/// last word, after Ctrl-C, where a word is too long, where a write
/// fails, where the input ends. The rest of a line that was pasted is
/// words of a phrase: it is not handed to whatever reads the terminal
/// next, which is the shell.
#[cfg(unix)]
struct ReadsKeys(rustix::termios::Termios);

#[cfg(unix)]
impl ReadsKeys {
    fn set() -> anyhow::Result<Self> {
        use rustix::termios::{
            LocalModes, OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr,
        };
        let stdin = rustix::stdio::stdin();
        let was = tcgetattr(stdin)
            .map_err(|e| anyhow::anyhow!("could not read how the terminal is set: {e}"))?;
        let mut reads = was.clone();
        // Ctrl-C, and the other keys that the terminal makes signals of,
        // are read as keys: and each as it is pressed, which a terminal
        // that hands on whole lines would not do. What is typed is not
        // shown.
        reads
            .local_modes
            .remove(LocalModes::ISIG | LocalModes::ICANON | LocalModes::ECHO | LocalModes::ECHONL);
        reads.special_codes[SpecialCodeIndex::VMIN] = 1;
        reads.special_codes[SpecialCodeIndex::VTIME] = 0;
        tcsetattr(stdin, OptionalActions::Flush, &reads).map_err(|e| {
            anyhow::anyhow!("could not set the terminal for what is typed: {e}. Nothing was read.")
        })?;
        Ok(Self(was))
    }

    /// Wait out `long`, with nothing said and nothing taken. A key that
    /// is pressed meanwhile is read at once, so that Ctrl-C ends the wait
    /// then, with [`INTERRUPTED`], and not when the wait is over. Any
    /// other key is dropped as it is read: it is no part of what is
    /// typed next.
    fn waits(&self, long: Duration) -> anyhow::Result<()> {
        self.drops_keys(long, false)
    }

    /// Wait until nothing has been typed for `quiet`, with nothing said:
    /// what is typed until then is dropped as it is read, and each key
    /// begins the wait again. So what a person goes on typing after a
    /// cross is no answer to the number that is asked again (decision
    /// 2026-10-04 §16). Ctrl-C ends it at once, with [`INTERRUPTED`].
    fn waits_for_quiet(&self, quiet: Duration) -> anyhow::Result<()> {
        self.drops_keys(quiet, true)
    }

    /// [`Self::waits`], or, where `a_key_begins_it_again`,
    /// [`Self::waits_for_quiet`].
    fn drops_keys(&self, long: Duration, a_key_begins_it_again: bool) -> anyhow::Result<()> {
        use rustix::termios::{OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr};
        // How long one read waits for a key: a tenth of a second, which
        // is the terminal's own unit for it.
        let a_read = Duration::from_millis(100);
        let stdin = rustix::stdio::stdin();
        let reads = tcgetattr(stdin)
            .map_err(|e| anyhow::anyhow!("could not read how the terminal is set: {e}"))?;
        let mut waits = reads.clone();
        waits.special_codes[SpecialCodeIndex::VMIN] = 0;
        waits.special_codes[SpecialCodeIndex::VTIME] = 1;
        tcsetattr(stdin, OptionalActions::Now, &waits)
            .map_err(|e| anyhow::anyhow!("could not set the terminal for a wait: {e}"))?;
        let mut until = Instant::now() + long;
        let mut key = Zeroizing::new([0u8; 1]);
        let mut interrupted = false;
        while !interrupted {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let asked = Instant::now();
            if matches!(rustix::io::read(stdin, &mut *key), Ok(1..)) {
                interrupted = INTERRUPT_KEYS.contains(&key[0]);
                if a_key_begins_it_again {
                    until = Instant::now() + long;
                }
            } else if asked.elapsed() < a_read / 2 {
                // A read that comes back with no key sooner than it
                // waits for one is of a terminal that is gone: the wait
                // is waited out all the same, and not by asking it over
                // and over.
                std::thread::sleep(left.min(a_read));
            }
        }
        // Each key is waited for again, as before the wait. Where this
        // fails, the terminal is put back as it was when this is dropped.
        tcsetattr(stdin, OptionalActions::Now, &reads)
            .map_err(|e| anyhow::anyhow!("could not set the terminal for what is typed: {e}"))?;
        if interrupted {
            anyhow::bail!(INTERRUPTED);
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for ReadsKeys {
    fn drop(&mut self) {
        use rustix::termios::{OptionalActions, tcsetattr};
        // While what is typed is still hidden.
        drop_what_was_typed_ahead();
        let _ = tcsetattr(rustix::stdio::stdin(), OptionalActions::Now, &self.0);
    }
}

/// The terminal's other screen, up and cleared: what is shown once is
/// shown there. **It is cleared, with the lines that scrolled off it, and
/// put away when this is dropped,** whatever became of the showing: as
/// [`ReadsKeys`] puts the terminal back. So a write that fails in the
/// middle leaves no word on a screen that stays up.
struct OtherScreen(());

impl OtherScreen {
    fn up() -> anyhow::Result<Self> {
        // Held from before the first write: where one of the two fails,
        // the screen is cleared and put away all the same.
        let screen = Self(());
        say("\x1b[?1049h")?;
        say(CLEAR_SCREEN)?;
        Ok(screen)
    }
}

impl Drop for OtherScreen {
    fn drop(&mut self) {
        // Cleared before the other screen is left, and so before anything
        // more is asked: on a terminal that has no other screen this is
        // what takes the words away.
        let _ = say(CLEAR_SCREEN);
        let _ = say("\x1b[?1049l");
    }
}

/// Say `asks`, with no line's end, and have it shown at once.
fn say(asks: &str) -> anyhow::Result<()> {
    let mut out = std::io::stdout();
    write!(out, "{asks}")?;
    out.flush()?;
    Ok(())
}

/// Write `shown` straight to where the command writes, and through no
/// buffer of the program's own: what is written this way is in no memory
/// here but the caller's, which the caller overwrites.
#[cfg(unix)]
fn say_unbuffered(shown: &str) -> anyhow::Result<()> {
    // What was said before it comes first.
    std::io::stdout().flush()?;
    let mut left = shown.as_bytes();
    while !left.is_empty() {
        match rustix::io::write(rustix::stdio::stdout(), left) {
            Ok(written) => left = &left[written..],
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => anyhow::bail!("could not write to the terminal: {e}"),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn say_unbuffered(_shown: &str) -> anyhow::Result<()> {
    anyhow::bail!("this command asks at the terminal of a Unix system");
}

/// Make this process one that cannot be dumped or traced (decision
/// 2026-10-04 §16), for as long as it runs this program: it is to hold a
/// recovery phrase, and what comes from one.
///
/// - On Linux its dumpable flag is cleared: it leaves no core file, and
///   no other process of the same user can attach to it or read its
///   memory.
/// - On macOS it denies that it be attached to.
/// - On both, the size of a core file it may leave is set to nothing.
///
/// A process that could not be made so reads no phrase: this fails, and
/// the command ends before anything is read.
#[cfg(unix)]
pub fn cannot_be_dumped() -> anyhow::Result<()> {
    let not = |what: &str, e: std::io::Error| {
        anyhow::anyhow!(
            "could not {what} ({e}), and a recovery phrase is read only by a process that \
             cannot be dumped or traced. Nothing was read."
        )
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| not("stop this process being dumped or traced", e.into()))?;
    #[cfg(target_os = "macos")]
    {
        // SAFETY: the request takes no address and no data, and is about
        // this process alone.
        let denied = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if denied == -1 {
            return Err(not(
                "stop this process being attached to",
                std::io::Error::last_os_error(),
            ));
        }
    }
    use rustix::process::{Resource, Rlimit, setrlimit};
    let none = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    setrlimit(Resource::Core, none)
        .map_err(|e| not("set the size of a core file to nothing", e.into()))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn cannot_be_dumped() -> anyhow::Result<()> {
    anyhow::bail!("a recovery phrase is read at the terminal of a Unix system");
}

/// The key that Ctrl-C is, and the one that Ctrl-\ is, where the
/// terminal makes no signal of them.
const INTERRUPT_KEYS: [u8; 2] = [0x03, 0x1c];

/// Read one line from the terminal, without its end, into memory that is
/// overwritten when it is dropped. The memory is never moved as the line
/// grows. `None` where the input ended before a line did.
///
/// The terminal hands on whole lines here, and acts itself on the keys
/// that take back what was typed.
#[cfg(unix)]
fn line() -> anyhow::Result<Option<Zeroizing<String>>> {
    let stdin = rustix::stdio::stdin();
    let mut line = Zeroizing::new(String::with_capacity(MAX_LINE));
    let mut byte = [0u8; 1];
    let mut ended = false;
    loop {
        match rustix::io::read(stdin, &mut byte) {
            Ok(0) => break,
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => {
                byte.zeroize();
                anyhow::bail!("could not read from the terminal: {e}");
            }
        }
        if byte[0] == b'\n' {
            ended = true;
            break;
        }
        // A byte that is no letter of a word, a digit or a mark of a key
        // is kept as a mark that nothing is: what is asked for here is
        // plain text.
        let read = match byte[0] {
            b'\r' => continue,
            plain @ 0x20..=0x7e => char::from(plain),
            b'\t' => ' ',
            _ => '?',
        };
        if line.len() + 1 >= MAX_LINE {
            byte.zeroize();
            anyhow::bail!("that line is longer than anything this command asks for");
        }
        line.push(read);
    }
    byte.zeroize();
    Ok((ended || !line.is_empty()).then_some(line))
}

#[cfg(not(unix))]
fn line() -> anyhow::Result<Option<Zeroizing<String>>> {
    anyhow::bail!("this command asks at the terminal of a Unix system");
}

/// Wait for Enter, where the terminal hands on each key as it is pressed
/// ([`ReadsKeys`]). Nothing that is typed meanwhile is kept. The end of
/// the input ends the wait as Enter does. And Ctrl-C is read as a key:
/// this fails with [`INTERRUPTED`], and whoever set the terminal puts it
/// back on the way out.
#[cfg(unix)]
fn enter() -> anyhow::Result<()> {
    let stdin = rustix::stdio::stdin();
    let mut key = Zeroizing::new([0u8; 1]);
    loop {
        match rustix::io::read(stdin, &mut *key) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => anyhow::bail!("could not read from the terminal: {e}"),
        }
        match key[0] {
            interrupt if INTERRUPT_KEYS.contains(&interrupt) => anyhow::bail!(INTERRUPTED),
            // Enter, and Ctrl-D, which ends the input.
            b'\n' | b'\r' | 0x04 => return Ok(()),
            _ => {}
        }
    }
}

#[cfg(not(unix))]
fn enter() -> anyhow::Result<()> {
    anyhow::bail!("this command asks at the terminal of a Unix system");
}

/// How the typing of a word ended.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ended {
    /// At a space: the line it is on goes on.
    Space,
    /// At Enter, which ends its line too.
    Line,
    /// The input ended before the word did.
    Input,
}

/// **A prompt for the phrase ends with the line that its last word was
/// typed on** (decision 2026-10-04 §16). Where that word ended at a
/// space, this reads on, with what is typed still hidden, to the Enter:
/// whatever else is on the line is dropped. So a thirteenth word (a word
/// typed twice, or one that was split into two words of the list) is
/// never shown, and is never handed to whatever reads the terminal next.
/// The end of the input ends it as Enter does, and Ctrl-C is read as a
/// key ([`enter`]).
#[cfg(unix)]
fn to_the_end_of_its_line(last: Ended) -> anyhow::Result<()> {
    match last {
        Ended::Space => enter(),
        Ended::Line | Ended::Input => Ok(()),
    }
}

/// Read one word from the terminal into `word`, which is empty: what is
/// typed up to a space or Enter, with upper case taken as lower. A space
/// or an Enter with nothing typed before it is passed over. How it
/// ended: at a space, at Enter, or with the input before a word was
/// typed.
///
/// The terminal hands on each key as it is pressed ([`ReadsKeys`]), and
/// what is typed is not shown. The keys that a terminal would have acted
/// on are acted on here, for the word that is being typed: the one that
/// takes back a letter, and the ones that take back a word or a line,
/// which here is the word. The key that ends the input ends it where
/// `nothing_yet` says that nothing was typed at this prompt so far, as at
/// the start of a line, and is passed over otherwise. And Ctrl-C is read
/// as a key: this fails with [`INTERRUPTED`].
///
/// `word` is never moved as it grows: it has room for a line, and a word
/// that is longer is refused, as a word. Whoever gave it overwrites it.
#[cfg(unix)]
fn word_typed(word: &mut Zeroizing<String>, nothing_yet: bool) -> anyhow::Result<Ended> {
    let stdin = rustix::stdio::stdin();
    // Overwritten however this returns.
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match rustix::io::read(stdin, &mut *byte) {
            Ok(0) => return Ok(Ended::Input),
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => anyhow::bail!("could not read from the terminal: {e}"),
        }
        match byte[0] {
            interrupt if INTERRUPT_KEYS.contains(&interrupt) => anyhow::bail!(INTERRUPTED),
            // A space or Enter ends a word, and is passed over where
            // nothing was typed before it.
            b' ' | b'\t' | b'\n' | b'\r' => {
                if !word.is_empty() {
                    return Ok(match byte[0] {
                        b'\n' | b'\r' => Ended::Line,
                        _ => Ended::Space,
                    });
                }
            }
            // Backspace, in either of its codes: a letter.
            0x7f | 0x08 => {
                word.pop();
            }
            // Ctrl-W and Ctrl-U: the word that is being typed.
            0x17 | 0x15 => word.zeroize(),
            // Ctrl-D: the end of the input, before anything is typed.
            0x04 if nothing_yet && word.is_empty() => return Ok(Ended::Input),
            0x04 => {}
            typed => {
                if word.len() + 1 >= MAX_LINE {
                    anyhow::bail!("that word is longer than anything this command asks for");
                }
                // A byte that is no letter of a word, a digit or a mark
                // of a key is kept as a mark that nothing is.
                word.push(match typed {
                    plain @ 0x20..=0x7e => char::from(plain.to_ascii_lowercase()),
                    _ => '?',
                });
            }
        }
    }
}

/// What became of the typing back of the words that were shown
/// ([`Terminal::phrase_back`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedBack {
    /// Each of the twelve was the word shown at its number.
    All,
    /// The last miss that a typing back may have: it stopped there.
    Missed,
    /// The input ended before the twelfth word: with what a command says
    /// of that wherever a phrase is typed ([`input_ended_says`]).
    Ended(String),
}

/// What a command says where the input ended before the twelve words
/// were typed, `words` of them having been typed.
fn input_ended_says(words: usize) -> String {
    match words {
        0 => "nothing was typed".to_string(),
        words => PhraseError::WordCount(words).to_string(),
    }
}

/// Ask for word `number` of a recovery phrase until a word of the list is
/// typed: its place in the list and how its typing ended, with the word
/// itself left in `word`, which whoever gave it overwrites. `None` where
/// the input ended first.
///
/// The number is said, right-aligned, and nothing that is typed after
/// it is shown. **A word that is not in the list gets a cross and a few
/// words, at once, and the same number is asked again**, with no bound:
/// it is no guess at a word (decision 2026-10-04 §16). It is asked again
/// once nothing has been typed for a second: the rest of a line that
/// was pasted, and what a person goes on typing, are dropped, and not
/// taken for the word that is asked again ([`ReadsKeys::waits_for_quiet`]).
#[cfg(unix)]
fn word_of_the_list(
    hidden: &ReadsKeys,
    number: usize,
    word: &mut Zeroizing<String>,
) -> anyhow::Result<Option<(Zeroizing<u16>, Ended)>> {
    loop {
        word.zeroize();
        say(&format!("  {number:>2}. "))?;
        let typed = word_typed(word, number == 1);
        if !matches!(typed, Ok(Ended::Space | Ended::Line)) {
            // No mark follows the number: what is said next starts on a
            // line of its own.
            say("\n")?;
        }
        let ended = typed?;
        if ended == Ended::Input {
            return Ok(None);
        }
        // The whole list is gone through, whatever the word.
        if let Some(place) = place_in_list(word) {
            return Ok(Some((Zeroizing::new(place), ended)));
        }
        word.zeroize();
        say(&format!(
            "✗  That is not a word from the list. Type word {number} again.\n"
        ))?;
        hidden.waits_for_quiet(Duration::from_secs(PHRASE_QUIET_AFTER_CROSS_SECS))?;
    }
}

/// Whether `sty`, the value of the variable `STY`, says that the command
/// runs inside GNU `screen`: it is set, to something.
fn inside_screen(sty: Option<&std::ffi::OsStr>) -> bool {
    sty.is_some_and(|sty| !sty.is_empty())
}

impl Terminal {
    /// The terminal that the command was run at. Refused where the
    /// command's input is not a terminal: nothing was asked, and nothing
    /// was done.
    pub fn at() -> anyhow::Result<Self> {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(NOT_A_TERMINAL);
        }
        Ok(Self(()))
    }

    /// The terminal of a command that makes or reads a recovery phrase
    /// (decision 2026-10-04 §16): [`Terminal::at`], in a process that
    /// cannot be dumped or traced from here on ([`cannot_be_dumped`]).
    /// It is asked for before anything is read, the node's answers
    /// included.
    ///
    /// Refused too where what the command writes to is not a terminal:
    /// a phrase that is shown would go wherever that leads (a file, or
    /// another program), and stay there.
    pub fn for_a_phrase() -> anyhow::Result<Self> {
        let at = Self::at()?;
        if !std::io::stdout().is_terminal() {
            anyhow::bail!(NOT_TO_A_TERMINAL);
        }
        cannot_be_dumped()?;
        Ok(at)
    }

    /// Whether this terminal is known to keep what is shown on it once
    /// ([`Self::once`]), so that nothing is to be shown there (decision
    /// 2026-10-04 §16).
    ///
    /// GNU `screen`, as it is set up by itself, has no other screen and
    /// does not clear the lines that scrolled off, as far as is known:
    /// the clear then pushes what was shown into its scrollback, where
    /// it stays. A command that runs inside it is told so by the
    /// variable `STY`.
    pub fn keeps_what_is_shown(&self) -> bool {
        inside_screen(std::env::var_os("STY").as_deref())
    }

    /// How many columns and lines the terminal that the command writes to
    /// says it has: `None` where that cannot be read, or where it says
    /// nothing of its size.
    #[cfg(unix)]
    pub fn size(&self) -> Option<(usize, usize)> {
        let size = rustix::termios::tcgetwinsize(rustix::stdio::stdout()).ok()?;
        (size.ws_col > 0 && size.ws_row > 0)
            .then(|| (usize::from(size.ws_col), usize::from(size.ws_row)))
    }

    #[cfg(not(unix))]
    pub fn size(&self) -> Option<(usize, usize)> {
        None
    }

    /// Ask a yes: `says` is what will happen. Only the word `yes` is one.
    pub fn yes(&self, says: &str) -> anyhow::Result<bool> {
        drop_what_was_typed_ahead();
        say(&format!(
            "{says}\nType yes to go on, or anything else to stop: "
        ))?;
        let typed = line()?;
        Ok(typed.is_some_and(|typed| typed.trim() == "yes"))
    }

    /// Ask for one answer on a line: what a person typed, without the space
    /// around it. Empty where a line was ended with nothing typed, and
    /// `None` where the input ended before a line did.
    pub fn answer(&self, asks: &str) -> anyhow::Result<Option<String>> {
        drop_what_was_typed_ahead();
        say(asks)?;
        Ok(line()?.map(|typed| typed.trim().to_string()))
    }

    /// Show `shown` once, under the line `says`, until a person presses
    /// Enter at `asks`: and then take it off the screen. `shown` is one
    /// row or several, each with its own space before it. Whoever asks
    /// sees to it that the terminal has room for all of it
    /// ([`Self::size`]): what scrolls off the top of the other screen is
    /// not seen, and a row that is broken over two lines is misread. It
    /// is shown on
    /// the terminal's other screen, which is cleared and then put away
    /// when the person is done, and keeps no lines above what is typed
    /// next. A terminal that has no other screen shows it where it is,
    /// and it is cleared from there, with the lines that scrolled off.
    ///
    /// `shown` is written straight to the terminal: the buffer of the
    /// program's standard output never holds it.
    ///
    /// What was typed ahead is dropped first: an Enter that was pressed
    /// twice at the prompt before does not take the screen away. And
    /// Ctrl-C is read as a key while it is up: this fails with
    /// [`INTERRUPTED`].
    ///
    /// **On every way out the screen is cleared and put away, and then
    /// the terminal is put back** ([`OtherScreen`], [`ReadsKeys`]): after
    /// Enter, after Ctrl-C, and where a write fails in the middle.
    pub fn once(&self, says: &str, shown: &str, asks: &str) -> anyhow::Result<()> {
        // Dropped in the order they are not made in: the screen first.
        #[cfg(unix)]
        let _reads = ReadsKeys::set()?;
        let _screen = OtherScreen::up()?;
        say(says)?;
        say("\n\n")?;
        say_unbuffered(shown)?;
        say("\n\n")?;
        say(asks)?;
        enter()
    }

    /// Ask for the recovery phrase where it is to be proved: `asks` is
    /// the line above the twelve numbers. Each word is asked for by its
    /// number, and what is typed is not shown. A word ends at a space or
    /// at Enter, so twelve words typed or pasted on one line are taken
    /// in their order, each to the next number. The prompt ends with the
    /// line that the twelfth word is on: whatever else is on it is
    /// dropped ([`to_the_end_of_its_line`]). What is given back is
    /// the twelve words with one space between them, in memory that is
    /// overwritten when it is dropped and was never moved as it grew.
    ///
    /// **A tick here says that a word is a word of the list, and nothing
    /// more** (decision 2026-10-04 §16). This is given nothing to hold a
    /// word against, and judges none: a wrong word of the list gets the
    /// tick that the right one gets, by the same code and with no wait,
    /// and all twelve are asked for whatever was typed. Whoever asked
    /// judges the phrase, once it is whole.
    ///
    /// Ctrl-C is read as a key while what is typed is hidden: the terminal
    /// is put back as it was, and this fails with [`INTERRUPTED`].
    #[cfg(unix)]
    pub fn phrase(&self, asks: &str) -> anyhow::Result<Zeroizing<String>> {
        // Echo goes off before anything is asked: nothing typed here is
        // ever shown. What was typed before it is dropped.
        let hidden = ReadsKeys::set()?;
        say(&format!("{asks}\n\n"))?;
        // Room for twelve of the longest words, which are eight letters,
        // and the spaces between them; and for a word as it is typed,
        // room for a line. Neither is moved as it grows, so that no copy
        // of what was typed is left behind.
        let mut words = Zeroizing::new(String::with_capacity(PHRASE_WORDS * 9));
        let mut word = Zeroizing::new(String::with_capacity(MAX_LINE));
        let mut last = Ended::Line;
        for number in 1..=PHRASE_WORDS {
            let Some((_, ended)) = word_of_the_list(&hidden, number, &mut word)? else {
                anyhow::bail!(input_ended_says(number - 1));
            };
            last = ended;
            // A word of the list: that is all the tick says, and all
            // that is known of the word here.
            say("✓\n")?;
            if number > 1 {
                words.push(' ');
            }
            words.push_str(&word);
            word.zeroize();
        }
        // The rest of the twelfth word's line is dropped here, unseen.
        // What was typed after that is dropped as the terminal is put
        // back ([`ReadsKeys`]).
        to_the_end_of_its_line(last)?;
        Ok(words)
    }

    #[cfg(not(unix))]
    pub fn phrase(&self, _asks: &str) -> anyhow::Result<Zeroizing<String>> {
        anyhow::bail!("the recovery phrase is typed at the terminal of a Unix system");
    }

    /// Ask for the twelve words that were shown a moment ago to be typed
    /// back, as [`Self::phrase`] asks: `shown` is the place in the list
    /// of each word that was shown. What became of it: all twelve typed
    /// back, the last miss, or the input ended first ([`TypedBack`]).
    ///
    /// **Here, and nowhere else, a word is held against the word that
    /// was shown at its number** (decision 2026-10-04 §16), by its place
    /// in the list: the words that were typed and the words that were
    /// shown are not set beside each other as text, and a word is
    /// overwritten as soon as its place is known.
    ///
    /// - The word that was shown gets a tick, at once.
    /// - A word of the list that is another is a miss. It is said after
    ///   a pause, and the same number is asked again: the pause is
    ///   `PHRASE_MISS_PAUSE_SECS`, and twice as long at each miss after
    ///   the first. Nothing is said during it, and what is typed during
    ///   it is dropped: it is not taken for the word that is asked
    ///   again. So each answer costs time, and neither a key held down
    ///   nor a line that was pasted spends every miss at once.
    /// - After a miss is said, what is typed goes on being dropped until
    ///   nothing has been typed for `PHRASE_QUIET_AFTER_CROSS_SECS`: a
    ///   person who types on without looking spends one miss on a slip,
    ///   and not one for each word that follows it.
    /// - At the miss numbered `PHRASE_TYPED_BACK_MISSES`, counted over
    ///   the whole typing back and not for each word, this stops, at
    ///   once.
    /// - A word that is not in the list is no miss: it is said at once,
    ///   and asked again as after any cross ([`word_of_the_list`]).
    #[cfg(unix)]
    pub fn phrase_back(
        &self,
        asks: &str,
        shown: &[u16; PHRASE_WORDS],
    ) -> anyhow::Result<TypedBack> {
        let hidden = ReadsKeys::set()?;
        say(&format!("{asks}\n\n"))?;
        let mut word = Zeroizing::new(String::with_capacity(MAX_LINE));
        let mut misses = 0;
        let mut number = 1;
        while number <= PHRASE_WORDS {
            // What is kept of the word is its place in the list.
            let Some((place, ended)) = word_of_the_list(&hidden, number, &mut word)? else {
                return Ok(TypedBack::Ended(input_ended_says(number - 1)));
            };
            word.zeroize();
            if *place == shown[number - 1] {
                say("✓\n")?;
                if number == PHRASE_WORDS {
                    to_the_end_of_its_line(ended)?;
                }
                number += 1;
                continue;
            }
            // A miss. The last is said at once, and ends the typing
            // back; one before it is said after its pause.
            misses += 1;
            if misses == PHRASE_TYPED_BACK_MISSES {
                say("✗\n")?;
                return Ok(TypedBack::Missed);
            }
            let waited = hidden.waits(Duration::from_secs(PHRASE_MISS_PAUSE_SECS << (misses - 1)));
            if waited.is_err() {
                // No mark follows the number: what is said next starts
                // on a line of its own.
                say("\n")?;
            }
            waited?;
            say(&format!(
                "✗  That does not match word {number}. Check what you wrote, and type it \
                 again.\n"
            ))?;
            // What was typed while it waited, and what is typed on,
            // answers nothing: the number is asked again once a person
            // has stopped typing.
            hidden.waits_for_quiet(Duration::from_secs(PHRASE_QUIET_AFTER_CROSS_SECS))?;
        }
        Ok(TypedBack::All)
    }

    #[cfg(not(unix))]
    pub fn phrase_back(
        &self,
        _asks: &str,
        _shown: &[u16; PHRASE_WORDS],
    ) -> anyhow::Result<TypedBack> {
        anyhow::bail!("the recovery phrase is typed at the terminal of a Unix system");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    /// GNU `screen` says that a command runs inside it by the variable
    /// `STY`: set to something, and not where it is unset or empty.
    #[test]
    fn a_command_is_inside_screen_where_sty_is_set_to_something() {
        assert!(inside_screen(Some(OsStr::new("4242.pts-1.laptop"))));
        assert!(inside_screen(Some(OsStr::new("x"))));
        assert!(!inside_screen(Some(OsStr::new(""))));
        assert!(!inside_screen(None));
    }

    /// Where the input ends before the twelve words are typed, a command
    /// says how many there were: or, with none, that nothing was typed.
    #[test]
    fn where_the_input_ends_a_command_says_how_many_words_there_were() {
        assert_eq!(input_ended_says(0), "nothing was typed");
        assert_eq!(
            input_ended_says(5),
            "a recovery phrase is twelve words, and this is 5"
        );
        assert_eq!(
            input_ended_says(11),
            "a recovery phrase is twelve words, and this is 11"
        );
    }
}
