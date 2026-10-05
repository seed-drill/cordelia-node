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

use std::io::{IsTerminal, Write};

use zeroize::{Zeroize, Zeroizing};

/// What a command that asks says where its input is no terminal.
pub const NOT_A_TERMINAL: &str = "this command asks before it does anything, and it asks at a \
                                  terminal: its input is not one. Nothing was done.";

/// The most that one line may hold: more than twelve of the longest words
/// of a recovery phrase and the space between them, several times over.
const MAX_LINE: usize = 1024;

/// The terminal that a command was run at. There is one only where the
/// command's input is a terminal ([`Terminal::at`]).
pub struct Terminal(());

/// Say `asks`, with no line's end, and have it shown at once.
fn say(asks: &str) -> anyhow::Result<()> {
    let mut out = std::io::stdout();
    write!(out, "{asks}")?;
    out.flush()?;
    Ok(())
}

/// Read one line from the terminal, without its end, into memory that is
/// overwritten when it is dropped. The memory is never moved as the line
/// grows. `None` where the input ended before a line did.
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

    /// Ask a yes: `says` is what will happen. Only the word `yes` is one.
    pub fn yes(&self, says: &str) -> anyhow::Result<bool> {
        say(&format!(
            "{says}\nType yes to go on, or anything else to stop: "
        ))?;
        let typed = line()?;
        Ok(typed.is_some_and(|typed| typed.trim() == "yes"))
    }

    /// Ask for one answer on a line: what a person typed, without the space
    /// around it. Empty where nothing was typed.
    pub fn answer(&self, asks: &str) -> anyhow::Result<String> {
        say(asks)?;
        Ok(line()?
            .map(|typed| typed.trim().to_string())
            .unwrap_or_default())
    }

    /// Show `shown` once, under the line `says`, until a person presses
    /// Enter at `asks`: and then take it off the screen, where the terminal
    /// knows how. It is shown on the terminal's other screen, which is put
    /// away when the person is done, and keeps no lines above what is typed
    /// next. A terminal that has no other screen shows it where it is.
    pub fn once(&self, says: &str, shown: &str, asks: &str) -> anyhow::Result<()> {
        say("\x1b[?1049h\x1b[H\x1b[2J")?;
        say(says)?;
        say("\n\n    ")?;
        say(shown)?;
        say("\n\n")?;
        say(asks)?;
        let read = line();
        say("\x1b[?1049l")?;
        read?;
        Ok(())
    }

    /// Ask for the recovery phrase: `asks` is the prompt. What is typed is
    /// not shown, and is in memory that is overwritten when it is dropped.
    #[cfg(unix)]
    pub fn phrase(&self, asks: &str) -> anyhow::Result<Zeroizing<String>> {
        use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

        /// The terminal as it was, put back when this is dropped: whatever
        /// became of the reading.
        struct Shown(rustix::termios::Termios);
        impl Drop for Shown {
            fn drop(&mut self) {
                let _ = tcsetattr(rustix::stdio::stdin(), OptionalActions::Now, &self.0);
            }
        }

        let stdin = rustix::stdio::stdin();
        let was = tcgetattr(stdin)
            .map_err(|e| anyhow::anyhow!("could not read how the terminal is set: {e}"))?;
        let mut hidden = was.clone();
        // What is typed is not shown. The line's end is, so that what is said
        // next starts on a line of its own.
        hidden.local_modes.remove(LocalModes::ECHO);
        hidden.local_modes.insert(LocalModes::ECHONL);
        // Echo goes off before the prompt is shown: nothing typed at the
        // prompt is ever shown. What was typed before it is dropped.
        tcsetattr(stdin, OptionalActions::Flush, &hidden).map_err(|e| {
            anyhow::anyhow!(
                "could not stop the terminal showing what is typed: {e}. Nothing was read."
            )
        })?;
        let _shown = Shown(was);
        say(asks)?;
        line()?.ok_or_else(|| anyhow::anyhow!("nothing was typed"))
    }

    #[cfg(not(unix))]
    pub fn phrase(&self, _asks: &str) -> anyhow::Result<Zeroizing<String>> {
        anyhow::bail!("the recovery phrase is typed at the terminal of a Unix system");
    }
}
