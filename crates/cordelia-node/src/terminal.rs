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
//! argument, never over the local API. It is read with echo off
//! ([`Terminal::phrase`]), into memory that is overwritten when it is
//! dropped.
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

use std::io::{IsTerminal, Write};

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

/// The most that one line may hold: more than twelve of the longest words
/// of a recovery phrase and the space between them, several times over.
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
}

#[cfg(unix)]
impl Drop for ReadsKeys {
    fn drop(&mut self) {
        use rustix::termios::{OptionalActions, tcsetattr};
        let _ = tcsetattr(rustix::stdio::stdin(), OptionalActions::Now, &self.0);
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
/// `keys` says that the terminal hands on each key as it is pressed
/// ([`ReadsKeys`]). The keys that a terminal would have acted on are then
/// acted on here: the ones that take back a letter, a word or the line,
/// and the one that ends the input at the start of a line. And Ctrl-C is
/// read as a key: this fails with [`INTERRUPTED`], and whoever set the
/// terminal puts it back on the way out.
#[cfg(unix)]
fn line(keys: bool) -> anyhow::Result<Option<Zeroizing<String>>> {
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
        if keys {
            match byte[0] {
                interrupt if INTERRUPT_KEYS.contains(&interrupt) => {
                    byte.zeroize();
                    anyhow::bail!(INTERRUPTED);
                }
                // Backspace, in either of its codes.
                0x7f | 0x08 => {
                    line.pop();
                    continue;
                }
                // Ctrl-W: the word before, and the space after it.
                0x17 => {
                    while line.ends_with(' ') {
                        line.pop();
                    }
                    while line.chars().next_back().is_some_and(|c| c != ' ') {
                        line.pop();
                    }
                    continue;
                }
                // Ctrl-U: the whole line.
                0x15 => {
                    line.zeroize();
                    continue;
                }
                // Ctrl-D: the end of the input, at the start of a line.
                0x04 if line.is_empty() => break,
                0x04 => continue,
                _ => {}
            }
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
fn line(_keys: bool) -> anyhow::Result<Option<Zeroizing<String>>> {
    anyhow::bail!("this command asks at the terminal of a Unix system");
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

    /// Ask a yes: `says` is what will happen. Only the word `yes` is one.
    pub fn yes(&self, says: &str) -> anyhow::Result<bool> {
        drop_what_was_typed_ahead();
        say(&format!(
            "{says}\nType yes to go on, or anything else to stop: "
        ))?;
        let typed = line(false)?;
        Ok(typed.is_some_and(|typed| typed.trim() == "yes"))
    }

    /// Ask for one answer on a line: what a person typed, without the space
    /// around it. Empty where a line was ended with nothing typed, and
    /// `None` where the input ended before a line did.
    pub fn answer(&self, asks: &str) -> anyhow::Result<Option<String>> {
        drop_what_was_typed_ahead();
        say(asks)?;
        Ok(line(false)?.map(|typed| typed.trim().to_string()))
    }

    /// Show `shown` once, under the line `says`, until a person presses
    /// Enter at `asks`: and then take it off the screen. It is shown on
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
    /// Ctrl-C is read as a key while it is up: the screen is cleared and
    /// put away, the terminal is put back, and this fails with
    /// [`INTERRUPTED`].
    pub fn once(&self, says: &str, shown: &str, asks: &str) -> anyhow::Result<()> {
        #[cfg(unix)]
        let _reads = ReadsKeys::set()?;
        say("\x1b[?1049h")?;
        say(CLEAR_SCREEN)?;
        say(says)?;
        say("\n\n    ")?;
        say_unbuffered(shown)?;
        say("\n\n")?;
        say(asks)?;
        let read = line(true);
        // Cleared before the other screen is left, and so before anything
        // more is asked: on a terminal that has no other screen this is
        // what takes the words away.
        say(CLEAR_SCREEN)?;
        say("\x1b[?1049l")?;
        read?;
        Ok(())
    }

    /// Ask for the recovery phrase: `asks` is the prompt. What is typed is
    /// not shown, and is in memory that is overwritten when it is dropped.
    ///
    /// Ctrl-C is read as a key while what is typed is hidden: the terminal
    /// is put back as it was, and this fails with [`INTERRUPTED`].
    #[cfg(unix)]
    pub fn phrase(&self, asks: &str) -> anyhow::Result<Zeroizing<String>> {
        // Echo goes off before the prompt is shown: nothing typed at the
        // prompt is ever shown. What was typed before it is dropped.
        let _hidden = ReadsKeys::set()?;
        say(asks)?;
        let typed = line(true);
        // The line's end is not shown by the terminal: what is said next
        // starts on a line of its own.
        say("\n")?;
        typed?.ok_or_else(|| anyhow::anyhow!("nothing was typed"))
    }

    #[cfg(not(unix))]
    pub fn phrase(&self, _asks: &str) -> anyhow::Result<Zeroizing<String>> {
        anyhow::bail!("the recovery phrase is typed at the terminal of a Unix system");
    }
}
