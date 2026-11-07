//! A repository's list, read with git (decision 2026-11-06 (joining),
//! rules 2 and 3): which repository a clone is, the node's own fetch of a
//! public repository's list, a read of a clone's copy of it, and whether a
//! clone's commit comes after the last one read.
//!
//! - **The identity** ([`Identity`], rule 2.1) is `host/owner/name` in
//!   lower case, from a remote's address in one of four forms:
//!   `https://<host>/<owner>/<name>`, `ssh://git@<host>/<owner>/<name>`,
//!   `ssh://<host>/<owner>/<name>` and `git@<host>:<owner>/<name>`, each
//!   with or without `.git`. Nothing else: no port, no other user. A host
//!   that HTTPS cannot reach, as an SSH alias, is refused, with why.
//! - **Which remote** ([`choose_remote`]): one that names a repository is
//!   the one; several that name different repositories need the person to
//!   choose (`--remote`).
//! - **The fetch** ([`Git::fetch_list`], rule 3): `HEAD` of the
//!   repository's address over HTTPS, at a depth of one, with no tags and
//!   no file larger than the list may be, into `refs/cordelia/list` of a
//!   bare repository of the node's own, `<repos>/<host>/<owner>/<name>.git`;
//!   then the one file, read from that commit. A redirect is not followed:
//!   the repository has moved. A repository of the node's own that has
//!   grown past [`MEMBERS_REPO_MAX_BYTES`] is made afresh.
//! - **The read of a clone** ([`Git::read_clone`], rule 3): the default
//!   branch as the person's own git last fetched it,
//!   `refs/remotes/<remote>/<branch>`, where `refs/remotes/<remote>/HEAD`
//!   names the branch and the remote still names the repository. Never
//!   the working tree, a local branch or `HEAD`, and nothing is written.
//! - **Never back** ([`Git::comes_after`]): whether a clone's commit is
//!   the last commit read or comes after it.
//!
//! **Nothing of the person's reaches git, so nothing can ask.** Every git
//! command here runs in a cleared environment ([`Git`]): only `PATH` and
//! the variables of a proxy and of a certificate authority are kept;
//! `HOME` and `XDG_CONFIG_HOME` are an empty folder of the node's, so no
//! global setting and no `.netrc` is read; no system setting is read; no
//! credential helper, no askpass, no terminal prompt; only `https` as a
//! transport, so nothing goes over SSH; no lazy fetch; no redirect; no
//! hooks, no `gc` and no maintenance; and git's own messages in the C
//! locale, so that why it failed is read from them. No replace ref and
//! no graft is heeded, so a commit is read as the host made it. A local
//! clone's own
//! objects, and those it borrows from another repository on the disk
//! (`objects/info/alternates`), are read with `https` alone: a read of a
//! clone fetches nothing, so it needs no `file` transport.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use cordelia_core::protocol::{
    AGENT_MESSAGE_LINK_REPO_MAX_BYTES, MEMBERS_FETCH_MAX_SECS, MEMBERS_FILE_MAX_BYTES,
    MEMBERS_GIT_TERM_SECS, MEMBERS_REPO_MAX_BYTES, STREAM_TIMEOUT_SECS,
};

use crate::found::{GitBounds, GitRan, git_run_by};

#[cfg(test)]
mod tests;

/// Where the list is in a repository (rule 1).
pub const MEMBERS_PATH: &str = ".cordelia/members";

/// The ref of the node's own repository that a fetch writes (rule 3).
pub const LIST_REF: &str = "refs/cordelia/list";

/// The first git that heeds `GIT_NO_LAZY_FETCH`: an older one may fetch
/// from a partial clone's promisor while it reads it.
pub const NO_LAZY_FETCH_SINCE: GitVersion = GitVersion {
    major: 2,
    minor: 44,
};

// ── The identity (rule 2.1) ──────────────────────────────────────────

/// A repository, as `host/owner/name` in lower case (rule 2.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identity {
    host: String,
    owner: String,
    name: String,
}

/// Why an address names no repository that the node can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotAnIdentity {
    /// It is not in one of the four forms.
    Form,
    /// It names a port.
    Port,
    /// It names a user other than `git`, or a password.
    User,
    /// Its host is not one that HTTPS can reach, as an SSH alias is not.
    Alias(String),
    /// Its owner or name is not one the node reads.
    Part,
}

impl NotAnIdentity {
    /// A word for each, as a status's JSON carries it.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Form => "form",
            Self::Port => "port",
            Self::User => "user",
            Self::Alias(_) => "alias",
            Self::Part => "part",
        }
    }

    /// Why, said plainly, of an address.
    pub fn says(&self) -> String {
        match self {
            Self::Form => "is not https://<host>/<owner>/<name>, \
                 ssh://git@<host>/<owner>/<name>, ssh://<host>/<owner>/<name> \
                 or git@<host>:<owner>/<name>"
                .to_string(),
            Self::Port => "names a port: use the host's address with no port".to_string(),
            Self::User => "names a user other than git".to_string(),
            Self::Alias(host) => format!(
                "has the host {host}, which HTTPS cannot reach: if it is an SSH alias, \
                 set the remote to the host's own name"
            ),
            Self::Part => "has an owner or a name of other than letters, digits, \
                 '.', '_' and '-'"
                .to_string(),
        }
    }
}

impl Identity {
    /// The repository a remote's address names, in one of the four forms
    /// (rule 2.1), or why it names none.
    pub fn from_address(address: &str) -> Result<Self, NotAnIdentity> {
        let (host, path) = if let Some(rest) = address.strip_prefix("https://") {
            let (authority, path) = rest.split_once('/').ok_or(NotAnIdentity::Form)?;
            if authority.contains('@') {
                return Err(NotAnIdentity::User);
            }
            (authority, path)
        } else if let Some(rest) = address.strip_prefix("ssh://") {
            let (authority, path) = rest.split_once('/').ok_or(NotAnIdentity::Form)?;
            let host = match authority.split_once('@') {
                Some(("git", host)) => host,
                Some(_) => return Err(NotAnIdentity::User),
                None => authority,
            };
            (host, path)
        } else if address.contains("://") {
            return Err(NotAnIdentity::Form);
        } else if let Some((user, rest)) = address.split_once('@') {
            // The form of scp: `git@<host>:<owner>/<name>`.
            if user.contains('/') || user.contains(':') {
                return Err(NotAnIdentity::Form);
            }
            if user != "git" {
                return Err(NotAnIdentity::User);
            }
            rest.split_once(':').ok_or(NotAnIdentity::Form)?
        } else {
            return Err(NotAnIdentity::Form);
        };
        // An address of IPv6 is no host name; any other colon is a port's.
        if host.contains(':') && !host.starts_with('[') {
            return Err(NotAnIdentity::Port);
        }
        let host = host_named(host)?;
        let path = path.to_ascii_lowercase();
        let path = path.strip_suffix(".git").unwrap_or(&path);
        let (owner, name) = path.split_once('/').ok_or(NotAnIdentity::Form)?;
        if name.contains('/') || owner.is_empty() || name.is_empty() {
            return Err(NotAnIdentity::Form);
        }
        Ok(Self {
            host,
            owner: part_named(owner)?,
            name: part_named(name)?,
        })
    }

    /// An identity as [`Identity`]'s `Display` writes it, `host/owner/name`,
    /// as a row keeps it: `None` where it is not one.
    pub fn from_text(text: &str) -> Option<Self> {
        let (host, path) = text.split_once('/')?;
        let (owner, name) = path.split_once('/')?;
        let identity = Self {
            host: host_named(host).ok()?,
            owner: part_named(owner).ok()?,
            name: part_named(name).ok()?,
        };
        (identity.to_string() == text).then_some(identity)
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The address the node fetches the list from: the repository over
    /// HTTPS, with `.git`. A host may redirect an address without it to
    /// one with it, and a redirect is not followed.
    pub fn https_url(&self) -> String {
        format!("https://{}/{}/{}.git", self.host, self.owner, self.name)
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.host, self.owner, self.name)
    }
}

/// A host name that HTTPS can reach, in lower case: labels of letters,
/// digits and `-`, parted by dots, at least two of them, the last a name
/// of letters (or an international one, `xn--`). A host with no dot, or
/// one such as `github.com-work`, is an alias that only SSH's own
/// settings know.
fn host_named(host: &str) -> Result<String, NotAnIdentity> {
    let host = host.to_ascii_lowercase();
    let alias = || NotAnIdentity::Alias(shown(&host));
    if host.is_empty() || host.len() > 253 {
        return Err(alias());
    }
    let labels: Vec<&str> = host.split('.').collect();
    let label_is_good = |label: &&str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let last = labels.last().copied().unwrap_or("");
    let last_is_a_name = (last.len() >= 2 && last.bytes().all(|b| b.is_ascii_lowercase()))
        || last.strip_prefix("xn--").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
    if labels.len() < 2 || !labels.iter().all(label_is_good) || !last_is_a_name {
        return Err(alias());
    }
    Ok(host)
}

/// An owner or a name, in lower case: 1 to
/// [`AGENT_MESSAGE_LINK_REPO_MAX_BYTES`] of letters, digits, `.`, `_` and
/// `-`, not starting with `-`, and not `.` or `..`, so that it is one
/// folder of the node's own repositories.
fn part_named(part: &str) -> Result<String, NotAnIdentity> {
    let part = part.to_ascii_lowercase();
    let good = !part.is_empty()
        && part.len() <= AGENT_MESSAGE_LINK_REPO_MAX_BYTES
        && !part.starts_with('-')
        && part != "."
        && part != ".."
        && part.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
        });
    if good {
        Ok(part)
    } else {
        Err(NotAnIdentity::Part)
    }
}

/// Text that another program gave, as a line may show it: printable ASCII
/// only, and at most 120 characters.
fn shown(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(120)
        .collect()
}

// ── Which remote (rule 2.1) ──────────────────────────────────────────

/// A remote of a clone, and its addresses (`remote.<name>.url`), in the
/// order of the clone's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub name: String,
    pub addresses: Vec<String>,
}

impl Remote {
    /// The repository this remote names: every address of it must name
    /// the same one.
    pub fn identity(&self) -> Result<Identity, RemoteRefused> {
        let mut named: Option<Identity> = None;
        for address in &self.addresses {
            let identity = Identity::from_address(address)
                .map_err(|why| RemoteRefused::NotARepository(self.name.clone(), why))?;
            match &named {
                Some(earlier) if *earlier != identity => {
                    return Err(RemoteRefused::TwoRepositories(self.name.clone()));
                }
                _ => named = Some(identity),
            }
        }
        named.ok_or_else(|| RemoteRefused::NotARepository(self.name.clone(), NotAnIdentity::Form))
    }
}

/// Why no remote of a clone is the one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteRefused {
    /// The clone has no remote.
    NoRemote,
    /// No remote names a repository that the node can read: each, and why.
    NoneNamesARepository(Vec<(String, NotAnIdentity)>),
    /// Remotes name different repositories, and none was chosen: each,
    /// and what it names.
    Several(Vec<(String, Identity)>),
    /// The remote that was chosen is not one of the clone's.
    NoSuchRemote(String),
    /// The remote that was chosen names no repository that the node can
    /// read.
    NotARepository(String, NotAnIdentity),
    /// The remote's addresses name different repositories.
    TwoRepositories(String),
    /// Git could not say.
    Git(ListFailed),
}

impl RemoteRefused {
    /// A word for each, as a status's JSON carries it.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoRemote => "no_remote",
            Self::NoneNamesARepository(_) => "no_repository",
            Self::Several(_) => "several",
            Self::NoSuchRemote(_) => "no_such_remote",
            Self::NotARepository(..) => "not_a_repository",
            Self::TwoRepositories(_) => "two_repositories",
            Self::Git(failed) => failed.code(),
        }
    }

    /// Why, said plainly.
    pub fn says(&self) -> String {
        match self {
            Self::NoRemote => "This clone has no remote.".to_string(),
            Self::NoneNamesARepository(each) if each.is_empty() => {
                "No remote of this clone names one repository that can be read.".to_string()
            }
            Self::NoneNamesARepository(each) => {
                let each: Vec<String> = each
                    .iter()
                    .map(|(remote, why)| format!("{} {}", shown(remote), why.says()))
                    .collect();
                format!(
                    "No remote of this clone names a repository that can be read: {}.",
                    each.join("; ")
                )
            }
            Self::Several(each) => {
                let each: Vec<String> = each
                    .iter()
                    .map(|(remote, identity)| format!("{} is {identity}", shown(remote)))
                    .collect();
                format!(
                    "The remotes of this clone name different repositories ({}): \
                     choose one with --remote <name>.",
                    each.join(", ")
                )
            }
            Self::NoSuchRemote(remote) => {
                format!("This clone has no remote named {}.", shown(remote))
            }
            Self::NotARepository(remote, why) => {
                format!("The address of {} {}.", shown(remote), why.says())
            }
            Self::TwoRepositories(remote) => format!(
                "{} has addresses that name different repositories.",
                shown(remote)
            ),
            Self::Git(failed) => failed.says(),
        }
    }
}

/// The remote whose repository a clone is (rule 2.1), and that
/// repository: the one `chosen` names, where one is; otherwise the one
/// repository that the remotes name, read through `origin` where it is
/// one of those that name it, or else through the first. Remotes that
/// name no repository the node can read are passed over, unless none
/// does.
pub fn choose_remote(
    remotes: &[Remote],
    chosen: Option<&str>,
) -> Result<(String, Identity), RemoteRefused> {
    if let Some(chosen) = chosen {
        let remote = remotes
            .iter()
            .find(|remote| remote.name == chosen)
            .ok_or_else(|| RemoteRefused::NoSuchRemote(chosen.to_string()))?;
        return Ok((remote.name.clone(), remote.identity()?));
    }
    if remotes.is_empty() {
        return Err(RemoteRefused::NoRemote);
    }
    let mut named = Vec::new();
    let mut refused = Vec::new();
    for remote in remotes {
        match remote.identity() {
            Ok(identity) => named.push((remote.name.clone(), identity)),
            Err(RemoteRefused::NotARepository(name, why)) => refused.push((name, why)),
            Err(_) => {}
        }
    }
    let repositories: BTreeSet<&Identity> = named.iter().map(|(_, identity)| identity).collect();
    match repositories.len() {
        0 => Err(RemoteRefused::NoneNamesARepository(refused)),
        1 => {
            let at = named
                .iter()
                .position(|(remote, _)| remote == "origin")
                .unwrap_or(0);
            Ok(named.swap_remove(at))
        }
        _ => {
            named.sort();
            Err(RemoteRefused::Several(named))
        }
    }
}

// ── What a read gives, and why it fails ──────────────────────────────

/// A list as git gave it: the commit it was read at, and the bytes of
/// `.cordelia/members` there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListAt {
    /// The commit, in hex, as git names it.
    pub commit: String,
    /// The file, of at most [`MEMBERS_FILE_MAX_BYTES`]: `None` where the
    /// commit has no `.cordelia/members`.
    pub file: Option<Vec<u8>>,
}

/// A list read from a clone (rule 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClonedList {
    /// The list, at the commit of the remote's default branch.
    pub at: ListAt,
    /// The default branch, as `refs/remotes/<remote>/HEAD` names it.
    pub branch: String,
    /// When the person's git last fetched this branch of this repository
    /// into the clone, as `FETCH_HEAD` says: for "fetched 2 hours ago".
    /// `None` where it does not say so, as after the host renamed its
    /// default branch, and the clone still reads the old one: the list is
    /// then not known to be fresh.
    pub fetched: Option<SystemTime>,
}

/// Why the list was not read: each said plainly, for a status line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListFailed {
    /// Git could not be run.
    GitNotRun(String),
    /// Git had not ended within this many seconds, and was stopped.
    Late { secs: u64 },
    /// A fetch of this repository is already running in this node.
    Busy,
    /// The host answered with a redirect: the repository was renamed or
    /// moved.
    Moved,
    /// The host asked for a password: the repository is private, or not
    /// there.
    AsksForPassword,
    /// The host says there is no such repository.
    NotFound,
    /// The repository has no commit yet.
    NoCommits,
    /// The host could not be reached: git's words.
    NotReached(String),
    /// The host's certificate is not trusted: git's words.
    Certificate(String),
    /// The address is not one over HTTPS, and nothing else is used.
    NotHttps,
    /// The folder is not in a git repository.
    NotARepository,
    /// The clone has no remote of this name.
    NoSuchRemote(String),
    /// The remote's address no longer names the repository followed.
    RemoteMoved { remote: String },
    /// The clone does not say which branch is its remote's default.
    NoRemoteHead { remote: String },
    /// The clone has no copy of the remote's default branch.
    NoBranch { remote: String, branch: String },
    /// The clone is partial, and this git, older than 2.44, would fetch
    /// from its promisor while it reads it.
    PartialOnOldGit { version: Option<GitVersion> },
    /// The clone is partial, and does not hold the list.
    NotInClone { remote: String, branch: String },
    /// `.cordelia/members` is not a plain file.
    NotAFile,
    /// `.cordelia/members` is larger than [`MEMBERS_FILE_MAX_BYTES`]: in
    /// the node's own repository, a fetch leaves it out.
    TooLarge,
    /// Anything else: the last thing git said.
    Git(String),
}

impl ListFailed {
    /// A word for each, as a status's JSON carries it.
    pub fn code(&self) -> &'static str {
        match self {
            Self::GitNotRun(_) => "git_not_run",
            Self::Late { .. } => "late",
            Self::Busy => "busy",
            Self::Moved => "moved",
            Self::AsksForPassword => "asks_for_password",
            Self::NotFound => "not_found",
            Self::NoCommits => "no_commits",
            Self::NotReached(_) => "not_reached",
            Self::Certificate(_) => "certificate",
            Self::NotHttps => "not_https",
            Self::NotARepository => "not_a_repository",
            Self::NoSuchRemote(_) => "no_such_remote",
            Self::RemoteMoved { .. } => "remote_moved",
            Self::NoRemoteHead { .. } => "no_remote_head",
            Self::NoBranch { .. } => "no_branch",
            Self::PartialOnOldGit { .. } => "partial_on_old_git",
            Self::NotInClone { .. } => "not_in_clone",
            Self::NotAFile => "not_a_file",
            Self::TooLarge => "too_large",
            Self::Git(_) => "git",
        }
    }

    /// Why, said plainly, short enough for a status line.
    pub fn says(&self) -> String {
        match self {
            Self::GitNotRun(why) => format!("git could not be run: {}", shown(why)),
            Self::Late { secs } => format!("git did not finish within {secs} seconds"),
            Self::Busy => "it is being fetched already".to_string(),
            Self::Moved => {
                "it has moved: run cordelia subscribe in a clone of it again".to_string()
            }
            Self::AsksForPassword => "it asks for a password, so it is private or not there: \
                 its list is read from your clone"
                .to_string(),
            Self::NotFound => "the host says it is not there".to_string(),
            Self::NoCommits => "it has no commit yet".to_string(),
            Self::NotReached(why) => format!("its host was not reached: {why}"),
            Self::Certificate(why) => format!("its host's certificate is not trusted: {why}"),
            Self::NotHttps => "only an address over https is fetched".to_string(),
            Self::NotARepository => "that folder is not in a git repository".to_string(),
            Self::NoSuchRemote(remote) => {
                format!("your clone has no remote named {}", shown(remote))
            }
            Self::RemoteMoved { remote } => format!(
                "the address of {} in your clone no longer names this repository",
                shown(remote)
            ),
            Self::NoRemoteHead { remote } => {
                let remote = shown(remote);
                format!(
                    "your clone does not say which branch of {remote} is its default: \
                     run git remote set-head {remote} --auto"
                )
            }
            Self::NoBranch { remote, branch } => {
                let (remote, branch) = (shown(remote), shown(branch));
                format!(
                    "your clone has no copy of {remote}/{branch}: run git fetch {remote}, \
                     then git remote set-head {remote} --auto"
                )
            }
            Self::PartialOnOldGit { version } => {
                let version = version.map_or_else(|| "this git".to_string(), |v| v.to_string());
                format!(
                    "your clone is a partial clone, and git {version} is older than 2.44, \
                     so a read of it could fetch: upgrade git"
                )
            }
            Self::NotInClone { remote, branch } => {
                let (remote, branch) = (shown(remote), shown(branch));
                format!(
                    "your partial clone does not hold the list: run \
                     git show {remote}/{branch}:{MEMBERS_PATH} in it once"
                )
            }
            Self::NotAFile => format!("{MEMBERS_PATH} is not a plain file"),
            Self::TooLarge => format!(
                "{MEMBERS_PATH} is larger than {} KiB",
                MEMBERS_FILE_MAX_BYTES / 1024
            ),
            Self::Git(said) => format!("git said: {said}"),
        }
    }
}

/// A version of git, as `git version` gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GitVersion {
    pub major: u32,
    pub minor: u32,
}

impl GitVersion {
    /// The version in what `git version` printed: `git version 2.44.0`,
    /// and the like with more after it (`(Apple Git-146)`,
    /// `.windows.1`).
    pub fn from_output(output: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(output).ok()?;
        let number = text.trim().strip_prefix("git version ")?;
        let mut parts = number.split(|c: char| !c.is_ascii_digit());
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        Some(Self { major, minor })
    }
}

impl std::fmt::Display for GitVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ── The node's git (rule 3) ──────────────────────────────────────────

/// The variables of the node's own environment that git is given: `PATH`,
/// to find git, and those of a proxy and of a company's own certificate
/// authority, which never ask. Nothing else of the person's reaches git.
pub const KEPT_VARIABLES: [&str; 8] = [
    "PATH",
    "HTTPS_PROXY",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "GIT_SSL_CAINFO",
];

/// The settings every git command here is given, after every setting of
/// a clone's own, so that each stands over a clone's: no credential
/// helper (an empty value empties the list a clone's configuration may
/// set), no redirect followed, no empty password tried (which would hand
/// a ticket of the person's to a host that asks for one), no hooks, no
/// file-system monitor (a program that a clone's configuration may name;
/// no command here reads the index, which is where git would run it), no
/// `gc` and no maintenance; and no hint that the graft file the node sets
/// aside is one git no longer wants.
const SETTINGS: [&str; 8] = [
    "credential.helper=",
    "http.followRedirects=false",
    "http.emptyAuth=false",
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "gc.auto=0",
    "maintenance.auto=false",
    "advice.graftFileDeprecated=false",
];

/// The filter of the node's fetch: no file larger than the list may be.
/// Git leaves out a blob of at least the limit's size, so the limit is
/// one byte more than [`MEMBERS_FILE_MAX_BYTES`].
fn list_filter() -> String {
    format!("blob:limit={}", MEMBERS_FILE_MAX_BYTES + 1)
}

/// The most of what git says on stderr that is kept: its last 8 KiB.
const STDERR_KEPT_BYTES: usize = 8192;

/// The most of git's output that is kept where it is a few short lines.
const SHORT_OUTPUT_BYTES: usize = 4096;

/// The most of a clone's configuration that is read.
const CONFIG_OUTPUT_BYTES: usize = 256 * 1024;

/// The node's git: the program, an empty folder that is its `HOME`, the
/// folder of the node's own repositories, what it keeps of the node's
/// environment, and its version, read once.
#[derive(Debug)]
pub struct Git {
    program: PathBuf,
    home: PathBuf,
    repos: PathBuf,
    kept: Vec<(OsString, OsString)>,
    version: Option<GitVersion>,
    repo_max_bytes: u64,
}

/// One git command's end, where it ended in time.
struct Ran {
    success: bool,
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

/// Where a command runs: in no repository, in the node's own, or in a
/// clone.
#[derive(Clone, Copy)]
enum At<'a> {
    Nowhere,
    Own(&'a Path),
    Clone(&'a Path),
}

/// The repositories being fetched in this process: a second fetch of one
/// waits for the next read, so that the locks the first holds are not
/// taken for stale.
static FETCHING: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

/// A repository being fetched, while this lives.
struct Fetching(PathBuf);

impl Fetching {
    fn of(repo: &Path) -> Result<Self, ListFailed> {
        let mut fetching = FETCHING.lock().unwrap_or_else(|e| e.into_inner());
        if fetching.insert(repo.to_path_buf()) {
            Ok(Self(repo.to_path_buf()))
        } else {
            Err(ListFailed::Busy)
        }
    }
}

impl Drop for Fetching {
    fn drop(&mut self) {
        FETCHING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

impl Git {
    /// The node's git under its data directory, `git` from the node's
    /// `PATH`: `git-home/`, kept empty, is its `HOME`, and `repos/` holds
    /// the node's own repositories.
    pub fn under(data_dir: &Path) -> std::io::Result<Self> {
        Self::given(data_dir, "git", std::env::vars_os())
    }

    /// [`Git::under`], with the program to run and the environment the
    /// node inherited given: for a node that names its git, and for tests.
    /// Only [`KEPT_VARIABLES`] are taken from `inherited`.
    pub fn given(
        data_dir: &Path,
        program: impl Into<PathBuf>,
        inherited: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> std::io::Result<Self> {
        let home = data_dir.join("git-home");
        let repos = data_dir.join("repos");
        keep_empty(&home)?;
        std::fs::create_dir_all(&repos)?;
        let kept = inherited
            .into_iter()
            .filter(|(name, _)| KEPT_VARIABLES.iter().any(|kept| OsStr::new(kept) == name))
            .collect();
        let mut git = Self {
            program: program.into(),
            home,
            repos,
            kept,
            version: None,
            repo_max_bytes: MEMBERS_REPO_MAX_BYTES,
        };
        git.version = git.read_version();
        Ok(git)
    }

    /// This git, with another bound than [`MEMBERS_REPO_MAX_BYTES`] on what
    /// the node's own repository may hold before it is made afresh: for
    /// tests.
    pub fn with_repo_max_bytes(mut self, bytes: u64) -> Self {
        self.repo_max_bytes = bytes;
        self
    }

    /// Git's version, read once, when this was made: `None` where git
    /// could not be run or said no version.
    pub fn version(&self) -> Option<GitVersion> {
        self.version
    }

    /// The folder that is git's `HOME`.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The node's own repository for `identity`:
    /// `<repos>/<host>/<owner>/<name>.git`.
    pub fn repo_of(&self, identity: &Identity) -> PathBuf {
        self.repos
            .join(&identity.host)
            .join(&identity.owner)
            .join(format!("{}.git", identity.name))
    }

    /// A git command in the cleared environment (rule 3), at `at`.
    fn command(&self, at: At<'_>) -> Command {
        let mut git = Command::new(&self.program);
        git.env_clear()
            .envs(self.kept.iter().map(|(name, value)| (name, value)))
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "")
            .env("GIT_ALLOW_PROTOCOL", "https")
            .env("GIT_NO_LAZY_FETCH", "1")
            // A replace ref or a graft would make a commit read as another,
            // or one seem to come after another that it does not.
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_GRAFT_FILE", "/dev/null")
            .env("LC_ALL", "C")
            .current_dir(&self.home);
        for setting in SETTINGS {
            git.arg("-c").arg(setting);
        }
        match at {
            At::Nowhere => {}
            At::Own(repo) => {
                git.arg("--git-dir").arg(repo);
            }
            At::Clone(clone) => {
                let mut safe = OsString::from("safe.directory=");
                safe.push(clone);
                git.arg("-c").arg(safe).arg("-C").arg(clone);
            }
        }
        git
    }

    /// Run `git`, given until `deadline`, keeping at most `stdout_max` of
    /// its output: `Late` (said as `secs`) where it did not end by then.
    fn run(
        &self,
        mut git: Command,
        deadline: Instant,
        secs: u64,
        stdout_max: usize,
    ) -> Result<Ran, Outcome> {
        // A file that something put in git's HOME is a setting it would
        // read: it is taken out before git runs.
        let _ = keep_empty(&self.home);
        let bounds = GitBounds {
            stdout_max,
            stderr_max: STDERR_KEPT_BYTES,
            term_grace: Duration::from_secs(MEMBERS_GIT_TERM_SECS),
        };
        match git_run_by(&mut git, deadline, bounds) {
            GitRan::Ended {
                status,
                stdout,
                stderr,
            } => Ok(Ran {
                success: status.success(),
                code: status.code(),
                stdout,
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
            }),
            GitRan::TooMuch => Err(Outcome::TooMuch),
            GitRan::Late => Err(Outcome::Failed(ListFailed::Late { secs })),
            GitRan::NotRun(e) => Err(Outcome::Failed(ListFailed::GitNotRun(e.to_string()))),
        }
    }

    /// `git version`, in the cleared environment.
    fn read_version(&self) -> Option<GitVersion> {
        let mut git = self.command(At::Nowhere);
        git.arg("version");
        let deadline = Instant::now() + Duration::from_secs(STREAM_TIMEOUT_SECS);
        let ran = self
            .run(git, deadline, STREAM_TIMEOUT_SECS, SHORT_OUTPUT_BYTES)
            .ok()?;
        ran.success
            .then(|| GitVersion::from_output(&ran.stdout))
            .flatten()
    }

    // ── The fetch (rule 3) ───────────────────────────────────────────

    /// Fetch the list of a public repository (rule 3) from `url`, its
    /// address over HTTPS ([`Identity::https_url`], or another that a test
    /// or a node's setting maps it to), into the node's own repository,
    /// within [`MEMBERS_FETCH_MAX_SECS`].
    pub fn fetch_list(&self, identity: &Identity, url: &str) -> Result<ListAt, ListFailed> {
        let deadline = Instant::now() + Duration::from_secs(MEMBERS_FETCH_MAX_SECS);
        self.fetch_list_by(identity, url, deadline)
    }

    /// [`Git::fetch_list`], with the fetch given until `deadline`: where
    /// it has not ended by then, git is stopped, by TERM and then KILL,
    /// and the node's repository's stale locks are cleared.
    pub fn fetch_list_by(
        &self,
        identity: &Identity,
        url: &str,
        deadline: Instant,
    ) -> Result<ListAt, ListFailed> {
        let secs = secs_until(deadline);
        let repo = self.repo_of(identity);
        let _fetching = Fetching::of(&repo)?;
        // Each fetch adds what a commit changed, and nothing is pruned: a
        // repository past its bound is made afresh, and fetched whole.
        if repo.exists() && bytes_under(&repo) > self.repo_max_bytes {
            std::fs::remove_dir_all(&repo).map_err(|e| ListFailed::Git(shown(&e.to_string())))?;
        }
        // What a fetch that was stopped, or a node that was, left behind:
        // no other fetch of this repository runs.
        clear_locks(&repo);
        self.make_own(&repo, url, deadline, secs)?;
        let mut git = self.command(At::Own(&repo));
        git.args([
            "fetch",
            "--quiet",
            "--depth",
            "1",
            "--no-tags",
            "--no-recurse-submodules",
        ])
        .arg(format!("--filter={}", list_filter()))
        .arg("origin")
        .arg(format!("+HEAD:{LIST_REF}"));
        let ran = match self.run(git, deadline, secs, SHORT_OUTPUT_BYTES) {
            Ok(ran) => ran,
            Err(outcome) => {
                clear_locks(&repo);
                return Err(outcome.failed());
            }
        };
        if !ran.success {
            clear_locks(&repo);
            return Err(fetch_failed(&ran.stderr));
        }
        let commit = self.commit_of(At::Own(&repo), LIST_REF, deadline, secs)?;
        let file = self.file_at(At::Own(&repo), &commit, deadline, secs, Lacks::Filtered)?;
        Ok(ListAt { commit, file })
    }

    /// Make the node's own repository, where it is not there, and set it
    /// up: `url` as its remote, and that remote as the promisor of a
    /// partial clone, as git needs for a fetch with a filter. Each setting
    /// is written only where it is not so already.
    fn make_own(
        &self,
        repo: &Path,
        url: &str,
        deadline: Instant,
        secs: u64,
    ) -> Result<(), ListFailed> {
        if !repo.join("HEAD").is_file() {
            std::fs::create_dir_all(repo).map_err(|e| ListFailed::Git(shown(&e.to_string())))?;
            let mut git = self.command(At::Own(repo));
            git.args(["init", "--bare", "--quiet", "--template="]);
            self.succeeds(git, deadline, secs)?;
        }
        let mut git = self.command(At::Own(repo));
        git.args(["config", "--null", "--list"]);
        let listed = self
            .run(git, deadline, secs, CONFIG_OUTPUT_BYTES)
            .map_err(Outcome::failed)?;
        let filter = list_filter();
        // The format's version first: git reads an extension only in a
        // repository of version 1.
        let wanted = [
            ("core.repositoryformatversion", "1"),
            ("extensions.partialclone", "origin"),
            ("remote.origin.url", url),
            ("remote.origin.promisor", "true"),
            ("remote.origin.partialclonefilter", filter.as_str()),
        ];
        for (key, value) in wanted {
            let entry = format!("{key}\n{value}");
            let set = listed
                .stdout
                .split(|b| *b == 0)
                .any(|e| e == entry.as_bytes());
            if !set {
                let mut git = self.command(At::Own(repo));
                git.args(["config", key, value]);
                self.succeeds(git, deadline, secs)?;
            }
        }
        Ok(())
    }

    /// Run `git`, which must succeed.
    fn succeeds(&self, git: Command, deadline: Instant, secs: u64) -> Result<(), ListFailed> {
        let ran = self
            .run(git, deadline, secs, SHORT_OUTPUT_BYTES)
            .map_err(Outcome::failed)?;
        if ran.success {
            Ok(())
        } else {
            Err(ListFailed::Git(last_said(&ran.stderr)))
        }
    }

    /// The commit that the ref named `reference`, by its whole name, holds
    /// at `at`: `None` where there is no such ref, where it is a symbolic
    /// ref, or where it holds no commit. The ref is looked up as named,
    /// and not as `rev-parse` would guess at a name.
    fn commit_at(
        &self,
        at: At<'_>,
        reference: &str,
        deadline: Instant,
        secs: u64,
    ) -> Result<Option<String>, ListFailed> {
        let mut git = self.command(at);
        git.args([
            "for-each-ref",
            "--format=%(refname)%00%(objectname)%00%(objecttype)%00%(symref)",
            reference,
        ]);
        let ran = match self.run(git, deadline, secs, CONFIG_OUTPUT_BYTES) {
            Ok(ran) => ran,
            Err(Outcome::TooMuch) => return Ok(None),
            Err(outcome) => return Err(outcome.failed()),
        };
        if !ran.success {
            return Err(ListFailed::Git(last_said(&ran.stderr)));
        }
        let listed = String::from_utf8_lossy(&ran.stdout);
        let held = listed.lines().find_map(|line| {
            let mut fields = line.split('\0');
            let (name, object, kind, symref) = (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
            );
            (name == reference).then_some((object, kind, symref))
        });
        Ok(match held {
            Some((object, "commit", "")) if is_a_commit(object) => Some(object.to_string()),
            _ => None,
        })
    }

    /// The commit of the node's own `reference`, which a fetch has just
    /// written.
    fn commit_of(
        &self,
        at: At<'_>,
        reference: &str,
        deadline: Instant,
        secs: u64,
    ) -> Result<String, ListFailed> {
        self.commit_at(at, reference, deadline, secs)?
            .ok_or_else(|| ListFailed::Git(format!("{reference} names no commit")))
    }

    /// `.cordelia/members` at `commit`: `None` where the commit has none.
    /// Where it is there, it must be a plain file of at most
    /// [`MEMBERS_FILE_MAX_BYTES`], read with `git cat-file blob`. What a
    /// file that git does not hold means is `lacks`.
    fn file_at(
        &self,
        at: At<'_>,
        commit: &str,
        deadline: Instant,
        secs: u64,
        lacks: Lacks<'_>,
    ) -> Result<Option<Vec<u8>>, ListFailed> {
        let not_held = |said: &str| match lacks {
            Lacks::Partial { remote, branch } => ListFailed::NotInClone {
                remote: remote.to_string(),
                branch: branch.to_string(),
            },
            Lacks::Whole | Lacks::Filtered => ListFailed::Git(last_said(said)),
        };
        let mut git = self.command(at);
        git.args(["ls-tree", "-z", "--full-tree", commit, "--", MEMBERS_PATH]);
        let ran = self
            .run(git, deadline, secs, SHORT_OUTPUT_BYTES)
            .map_err(Outcome::failed)?;
        if !ran.success {
            return Err(not_held(&ran.stderr));
        }
        let Some(entry) = ran.stdout.split(|b| *b == 0).find(|e| !e.is_empty()) else {
            return Ok(None);
        };
        // `<mode> <type> <object>\t<path>`
        let entry = String::from_utf8_lossy(entry);
        let mut words = entry.split([' ', '\t']);
        let (mode, kind, object) = (words.next(), words.next(), words.next());
        if !matches!(mode, Some("100644" | "100755")) || kind != Some("blob") {
            return Err(ListFailed::NotAFile);
        }
        let mut git = self.command(at);
        git.args(["cat-file", "blob"])
            .arg(format!("{commit}:{MEMBERS_PATH}"));
        let ran = match self.run(git, deadline, secs, MEMBERS_FILE_MAX_BYTES) {
            Ok(ran) if ran.success => return Ok(Some(ran.stdout)),
            Ok(ran) => ran,
            Err(Outcome::TooMuch) => return Err(ListFailed::TooLarge),
            Err(outcome) => return Err(outcome.failed()),
        };
        // In the node's own repository, the one file a fetch leaves out is
        // one larger than the list may be.
        if let (Lacks::Filtered, Some(object)) = (lacks, object.filter(|o| is_a_commit(o))) {
            let mut git = self.command(at);
            git.args(["cat-file", "-e", object]);
            let held = self
                .run(git, deadline, secs, SHORT_OUTPUT_BYTES)
                .map_err(Outcome::failed)?;
            if !held.success {
                return Err(ListFailed::TooLarge);
            }
        }
        Err(not_held(&ran.stderr))
    }

    // ── A clone (rules 2 and 3) ──────────────────────────────────────

    /// The remotes of the clone at `clone`, the top of its work tree, as
    /// its own configuration names them.
    pub fn remotes_of(&self, clone: &Path) -> Result<Vec<Remote>, ListFailed> {
        let deadline = Instant::now() + Duration::from_secs(STREAM_TIMEOUT_SECS);
        let clone = self.clone_at(clone, deadline)?;
        Ok(self.config_of(&clone, deadline)?.remotes)
    }

    /// The remote whose repository the clone at `clone` is, and that
    /// repository (rule 2.1): [`choose_remote`] over its remotes.
    pub fn identity_of_clone(
        &self,
        clone: &Path,
        chosen: Option<&str>,
    ) -> Result<(String, Identity), RemoteRefused> {
        let remotes = self.remotes_of(clone).map_err(RemoteRefused::Git)?;
        choose_remote(&remotes, chosen)
    }

    /// Read the list from the clone at `clone`, the top of its work tree
    /// (rule 3): at `refs/remotes/<remote>/<branch>`, the branch that
    /// `refs/remotes/<remote>/HEAD` names, where the remote's address still
    /// names `identity`. Nothing of the clone is written, and neither its
    /// working tree, a local branch nor `HEAD` is read.
    pub fn read_clone(
        &self,
        clone: &Path,
        remote: &str,
        identity: &Identity,
    ) -> Result<ClonedList, ListFailed> {
        let deadline = Instant::now() + Duration::from_secs(STREAM_TIMEOUT_SECS);
        let secs = STREAM_TIMEOUT_SECS;
        let (clone, config) = self.clone_to_read(clone, deadline)?;
        let named = config
            .remotes
            .iter()
            .find(|named| named.name == remote)
            .ok_or_else(|| ListFailed::NoSuchRemote(remote.to_string()))?;
        if named.identity().ok().as_ref() != Some(identity) {
            return Err(ListFailed::RemoteMoved {
                remote: remote.to_string(),
            });
        }
        let at = At::Clone(&clone.top);
        let branch = self.default_branch(at, remote, deadline, secs)?;
        let reference = format!("refs/remotes/{remote}/{branch}");
        let commit = self
            .commit_at(at, &reference, deadline, secs)?
            .ok_or_else(|| ListFailed::NoBranch {
                remote: remote.to_string(),
                branch: branch.clone(),
            })?;
        let lacks = match config.partial {
            true => Lacks::Partial {
                remote,
                branch: &branch,
            },
            false => Lacks::Whole,
        };
        let file = self.file_at(at, &commit, deadline, secs, lacks)?;
        let fetched = clone.fetched(&branch, identity);
        Ok(ClonedList {
            at: ListAt { commit, file },
            branch,
            fetched,
        })
    }

    /// Whether `commit` is `last`, the last commit read, or comes after it
    /// (rule 3), as the clone at `clone` knows them: `git merge-base
    /// --is-ancestor`, run in the clone. A `last` that the clone does not
    /// hold is one its commit cannot come after: the clone is behind.
    pub fn comes_after(&self, clone: &Path, last: &str, commit: &str) -> Result<bool, ListFailed> {
        if !is_a_commit(last) || !is_a_commit(commit) {
            return Err(ListFailed::Git("that is not a commit".to_string()));
        }
        if last == commit {
            return Ok(true);
        }
        let deadline = Instant::now() + Duration::from_secs(STREAM_TIMEOUT_SECS);
        let (clone, _) = self.clone_to_read(clone, deadline)?;
        let mut git = self.command(At::Clone(&clone.top));
        git.args(["merge-base", "--is-ancestor", last, commit]);
        let ran = self
            .run(git, deadline, STREAM_TIMEOUT_SECS, SHORT_OUTPUT_BYTES)
            .map_err(Outcome::failed)?;
        match ran.code {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ if ran.stderr.contains("Not a valid commit name")
                || ran.stderr.contains("Not a valid object name") =>
            {
                Ok(false)
            }
            _ => Err(ListFailed::Git(last_said(&ran.stderr))),
        }
    }

    /// The clone at `clone`, and its configuration, where its objects may
    /// be read: a partial clone is refused to a git older than 2.44, which
    /// would fetch from its promisor while it read it. Every read of a
    /// clone's objects comes through here.
    fn clone_to_read(
        &self,
        clone: &Path,
        deadline: Instant,
    ) -> Result<(CloneAt, CloneConfig), ListFailed> {
        let clone = self.clone_at(clone, deadline)?;
        let config = self.config_of(&clone, deadline)?;
        if config.partial && self.version.is_none_or(|v| v < NO_LAZY_FETCH_SINCE) {
            return Err(ListFailed::PartialOnOldGit {
                version: self.version,
            });
        }
        Ok((clone, config))
    }

    /// The clone at `clone`: where its git directories are. Git is run in
    /// `clone` as it is given, and `safe.directory` names it, which git
    /// heeds for the top of a work tree; callers give that.
    fn clone_at(&self, clone: &Path, deadline: Instant) -> Result<CloneAt, ListFailed> {
        let top = clone
            .canonicalize()
            .map_err(|_| ListFailed::NotARepository)?;
        let mut git = self.command(At::Clone(&top));
        git.args(["rev-parse", "--absolute-git-dir", "--git-common-dir"]);
        let ran = self
            .run(git, deadline, STREAM_TIMEOUT_SECS, SHORT_OUTPUT_BYTES)
            .map_err(Outcome::failed)?;
        if !ran.success {
            return Err(ListFailed::NotARepository);
        }
        let said = String::from_utf8_lossy(&ran.stdout);
        let mut lines = said.lines();
        let (Some(own), Some(common)) = (lines.next(), lines.next()) else {
            return Err(ListFailed::NotARepository);
        };
        // The common directory is given relative to where git ran.
        let own = PathBuf::from(own);
        let common = top.join(common);
        Ok(CloneAt { top, own, common })
    }

    /// What the node reads of a clone's configuration: its remotes, and
    /// whether it is partial.
    fn config_of(&self, clone: &CloneAt, deadline: Instant) -> Result<CloneConfig, ListFailed> {
        let mut git = self.command(At::Clone(&clone.top));
        git.args(["config", "--null", "--list"]);
        let ran = match self.run(git, deadline, STREAM_TIMEOUT_SECS, CONFIG_OUTPUT_BYTES) {
            Ok(ran) => ran,
            Err(Outcome::TooMuch) => {
                return Err(ListFailed::Git(
                    "your clone's configuration is too large to read".to_string(),
                ));
            }
            Err(outcome) => return Err(outcome.failed()),
        };
        if !ran.success {
            return Err(ListFailed::Git(last_said(&ran.stderr)));
        }
        Ok(CloneConfig::from_list(&ran.stdout))
    }

    /// The branch that `refs/remotes/<remote>/HEAD` names.
    fn default_branch(
        &self,
        at: At<'_>,
        remote: &str,
        deadline: Instant,
        secs: u64,
    ) -> Result<String, ListFailed> {
        let no_head = || ListFailed::NoRemoteHead {
            remote: remote.to_string(),
        };
        let head = format!("refs/remotes/{remote}/HEAD");
        let mut git = self.command(at);
        git.args(["symbolic-ref", "--quiet", &head]);
        let ran = self
            .run(git, deadline, secs, SHORT_OUTPUT_BYTES)
            .map_err(Outcome::failed)?;
        if !ran.success {
            return Err(no_head());
        }
        let target = String::from_utf8_lossy(&ran.stdout).trim().to_string();
        let branch = target
            .strip_prefix(&format!("refs/remotes/{remote}/"))
            .filter(|branch| is_a_branch(branch))
            .ok_or_else(no_head)?;
        Ok(branch.to_string())
    }

    /// The top of the work tree that `folder` is in, as a real path: the
    /// clone that `cordelia subscribe` follows, run in any folder of it
    /// (decision 2026-11-06 (joining), rule 2), with git given until
    /// `deadline`, and no longer than [`STREAM_TIMEOUT_SECS`].
    /// `NotARepository` where it is in no repository, or in one with no
    /// work tree.
    pub fn top_of(&self, folder: &Path, deadline: Instant) -> Result<PathBuf, ListFailed> {
        let deadline = deadline.min(Instant::now() + Duration::from_secs(STREAM_TIMEOUT_SECS));
        let folder = folder
            .canonicalize()
            .map_err(|_| ListFailed::NotARepository)?;
        let mut git = self.command(At::Clone(&folder));
        git.args(["rev-parse", "--show-toplevel"]);
        let ran = self
            .run(git, deadline, secs_until(deadline), SHORT_OUTPUT_BYTES)
            .map_err(Outcome::failed)?;
        let said = String::from_utf8_lossy(&ran.stdout);
        let top = said.strip_suffix('\n').unwrap_or(&said);
        if !ran.success || top.is_empty() {
            return Err(ListFailed::NotARepository);
        }
        // A path that is not text is not kept: it does not read back.
        PathBuf::from(top)
            .canonicalize()
            .map_err(|_| ListFailed::NotARepository)
    }
}

/// Why a run gave nothing to read: git wrote more than was asked for, or
/// a failure as it is said.
enum Outcome {
    TooMuch,
    Failed(ListFailed),
}

impl Outcome {
    fn failed(self) -> ListFailed {
        match self {
            Self::TooMuch => ListFailed::Git("git said more than was asked for".to_string()),
            Self::Failed(failed) => failed,
        }
    }
}

/// What a file of the list that git does not hold means.
#[derive(Clone, Copy)]
enum Lacks<'a> {
    /// In a whole clone: a fault, said as git says it.
    Whole,
    /// In a partial clone: the person's git has not brought it yet.
    Partial { remote: &'a str, branch: &'a str },
    /// In the node's own repository, fetched with a filter: it is too
    /// large to read.
    Filtered,
}

/// A clone, as git places it.
struct CloneAt {
    /// The folder git runs in, as a real path: the top of its work tree.
    top: PathBuf,
    /// Its own git directory (a linked worktree's, in one).
    own: PathBuf,
    /// The directory its worktrees share.
    common: PathBuf,
}

/// The most of a `FETCH_HEAD` that is read: 1 MiB, a line for each of
/// thousands of branches.
const FETCH_HEAD_READ_BYTES: u64 = 1024 * 1024;

impl CloneAt {
    /// When the person's git last fetched `branch` of `identity`, by the
    /// `FETCH_HEAD` that each fetch writes, in either of its git
    /// directories: only one that has a line for that branch of that
    /// repository counts. A fetch after the host renamed its default branch
    /// writes no line for the branch the clone still reads, so the list is
    /// then not known to be fresh.
    fn fetched(&self, branch: &str, identity: &Identity) -> Option<SystemTime> {
        use std::io::Read;
        [&self.own, &self.common]
            .iter()
            .filter_map(|dir| {
                let path = dir.join("FETCH_HEAD");
                let mut text = Vec::new();
                std::fs::File::open(&path)
                    .ok()?
                    .take(FETCH_HEAD_READ_BYTES)
                    .read_to_end(&mut text)
                    .ok()?;
                if !fetch_head_names(&String::from_utf8_lossy(&text), branch, identity) {
                    return None;
                }
                std::fs::metadata(&path).ok()?.modified().ok()
            })
            .max()
    }
}

/// Whether a `FETCH_HEAD` has a line for `branch` of `identity`:
/// `<commit>\t<not-for-merge, or nothing>\tbranch '<branch>' of <url>`.
fn fetch_head_names(text: &str, branch: &str, identity: &Identity) -> bool {
    let named = format!("branch '{branch}' of ");
    text.lines().any(|line| {
        let mut fields = line.splitn(3, '\t');
        let (Some(commit), Some(_), Some(note)) = (fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        is_a_commit(commit)
            && note
                .strip_prefix(&named)
                .and_then(fetched_from)
                .is_some_and(|fetched| fetched == *identity)
    })
}

/// The repository an address in a `FETCH_HEAD` names. Git takes the user
/// out of an address it writes there, so `git@<host>:<owner>/<name>` is
/// written `<host>:<owner>/<name>`.
fn fetched_from(url: &str) -> Option<Identity> {
    if let Ok(identity) = Identity::from_address(url) {
        return Some(identity);
    }
    if url.contains("://") || url.contains('@') {
        return None;
    }
    Identity::from_address(&format!("git@{url}")).ok()
}

/// What the node reads of a clone's configuration.
struct CloneConfig {
    remotes: Vec<Remote>,
    /// A remote is a promisor, or `extensions.partialClone` is set.
    partial: bool,
}

impl CloneConfig {
    /// From `git config --null --list`: each entry its key, a line feed
    /// and its value (none, for a key with no `=`), ended by a NUL.
    fn from_list(list: &[u8]) -> Self {
        let mut remotes: Vec<Remote> = Vec::new();
        let mut partial = false;
        for entry in list.split(|b| *b == 0).filter(|e| !e.is_empty()) {
            let entry = String::from_utf8_lossy(entry);
            let (key, value) = match entry.split_once('\n') {
                Some((key, value)) => (key, Some(value)),
                None => (&*entry, None),
            };
            // The section and the variable are in lower case; a remote's
            // name is as it was written.
            if key == "extensions.partialclone" {
                partial = true;
            }
            let Some(middle) = key.strip_prefix("remote.") else {
                continue;
            };
            if let Some(name) = middle.strip_suffix(".promisor") {
                let off = matches!(
                    value.map(|v| v.to_ascii_lowercase()).as_deref(),
                    Some("false" | "no" | "off" | "0")
                );
                if !name.is_empty() && !off {
                    partial = true;
                }
            } else if let Some(name) = middle.strip_suffix(".url") {
                let Some(address) = value else { continue };
                match remotes.iter_mut().find(|remote| remote.name == name) {
                    Some(remote) => remote.addresses.push(address.to_string()),
                    None => remotes.push(Remote {
                        name: name.to_string(),
                        addresses: vec![address.to_string()],
                    }),
                }
            }
        }
        // A remote whose name could be read as more than a ref's part is
        // left out: it is never put in a ref's name.
        remotes.retain(|remote| is_a_remote_name(&remote.name));
        Self { remotes, partial }
    }
}

/// Why a fetch failed, from what git said in the C locale. What the host
/// said, on lines that git begins with `remote:`, is not read: a host
/// could say anything there.
fn fetch_failed(said: &str) -> ListFailed {
    let own: String = said
        .lines()
        .filter(|line| !line.starts_with("remote:"))
        .map(|line| format!("{line}\n"))
        .collect();
    let said = own.as_str();
    let line = last_line(said);
    let has = |words: &str| said.contains(words);
    if has("The requested URL returned error: 3") {
        ListFailed::Moved
    } else if has("could not read Username")
        || has("could not read Password")
        || has("Authentication failed")
        || has("The requested URL returned error: 401")
        || has("The requested URL returned error: 403")
    {
        ListFailed::AsksForPassword
    } else if has("The requested URL returned error: 404")
        || (has("repository '") && has("' not found"))
    {
        ListFailed::NotFound
    } else if has("couldn't find remote ref HEAD") {
        ListFailed::NoCommits
    } else if has("transport '") && has("' not allowed") {
        ListFailed::NotHttps
    } else if has("certificate") {
        ListFailed::Certificate(shown(after_the_address(line)))
    } else if has("unable to access '") {
        // Any other failure to reach the host: its name, a connection,
        // TLS, or a proxy.
        ListFailed::NotReached(shown(after_the_address(line)))
    } else {
        ListFailed::Git(shown(line))
    }
}

/// The last thing git said itself (`fatal:` or `error:`), shown.
fn last_said(said: &str) -> String {
    shown(last_line(said))
}

/// The last line in which git said something itself (`fatal:` or
/// `error:`), after that word; or else its last line.
fn last_line(said: &str) -> &str {
    said.lines()
        .rev()
        .find_map(|line| {
            line.strip_prefix("fatal: ")
                .or_else(|| line.strip_prefix("error: "))
        })
        .or_else(|| said.lines().rev().find(|line| !line.trim().is_empty()))
        .unwrap_or("nothing")
        .trim()
}

/// What git said of an address, after it: `unable to access '<url>':
/// <why>` gives `<why>`.
fn after_the_address(line: &str) -> &str {
    line.rsplit_once("': ").map_or(line, |(_, why)| why)
}

/// The seconds from now until `deadline`, rounded up, to say a late git.
fn secs_until(deadline: Instant) -> u64 {
    let left = deadline.saturating_duration_since(Instant::now());
    left.as_secs() + u64::from(left.subsec_nanos() > 0)
}

/// An object's name as git gives it, a commit's or another's: 40 hex
/// digits, or 64 in a repository of SHA-256.
fn is_a_commit(name: &str) -> bool {
    matches!(name.len(), 40 | 64) && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A remote's name that the node puts in a ref's name: letters, digits,
/// `.`, `_` and `-`, not starting with `.` or `-`.
fn is_a_remote_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= AGENT_MESSAGE_LINK_REPO_MAX_BYTES
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A branch's name, as `refs/remotes/<remote>/HEAD` names it: printable,
/// with no space, no `..`, and no part that is empty or `.` or starts
/// with `-`.
fn is_a_branch(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.bytes().all(|b| b.is_ascii_graphic())
        && !name.contains(['~', '^', ':', '?', '*', '[', '\\'])
        && !name.contains("..")
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.starts_with('-'))
}

/// Make `dir` an empty folder that only this user reads: what is in it
/// is taken out. A link in its place is refused: it could lead anywhere.
fn keep_empty(dir: &Path) -> std::io::Result<()> {
    if std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(std::io::Error::other(format!(
            "{} is a link, and not a folder",
            dir.display()
        )));
    }
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&path)?,
            Ok(_) => std::fs::remove_file(&path)?,
            Err(_) => {}
        }
    }
    Ok(())
}

/// What the files under `dir` hold, together, links not followed.
fn bytes_under(dir: &Path) -> u64 {
    let mut bytes = 0u64;
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.is_dir() {
                dirs.push(entry.path());
            } else if meta.is_file() {
                bytes = bytes.saturating_add(meta.len());
            }
        }
    }
    bytes
}

/// Take out of the node's own repository what a git that was stopped
/// left: every `*.lock` at its top, under `refs/`, in `objects/info/` and
/// in `objects/pack/`, and a pack's temporary files. Only while no git of
/// this node runs in it.
fn clear_locks(repo: &Path) {
    let remove_if = |dir: &Path, stale: &dyn Fn(&str) -> bool| {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let is_file = entry.file_type().is_ok_and(|t| t.is_file());
            if is_file && name.to_str().is_some_and(stale) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    };
    let is_lock = |name: &str| name.ends_with(".lock");
    remove_if(repo, &is_lock);
    remove_if(&repo.join("objects/info"), &is_lock);
    remove_if(&repo.join("objects/pack"), &|name: &str| {
        name.ends_with(".lock") || name.starts_with("tmp_")
    });
    // The refs, to a depth that a ref of the node's own never passes.
    let mut dirs = vec![(repo.join("refs"), 0)];
    while let Some((dir, depth)) = dirs.pop() {
        remove_if(&dir, &is_lock);
        if depth >= 8 {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    dirs.push((entry.path(), depth + 1));
                }
            }
        }
    }
}
