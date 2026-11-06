//! What the tests of a repository's list read with git share (decision
//! 2026-11-06 (joining), rule 3): a server of git over HTTPS on loopback,
//! which serves bare repositories through `git http-backend` as CGI, its
//! certificate authority in a file for `GIT_SSL_CAINFO`; and the test's
//! own git, which makes repositories, commits and clones in an
//! environment of the test's own.
//!
//! The server answers each request with `Connection: close`, and keeps
//! what it was asked, so that a test can say what reached it. It can
//! answer instead with a redirect, with a demand for a password, or never.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// How a server answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answers {
    /// As git's own server does, through `git http-backend`.
    Git,
    /// `301 Moved Permanently`, to the same path under `/moved`.
    Redirect,
    /// `401 Unauthorized`, asking for a password.
    Password,
    /// Never: the request is read, and the connection held open.
    Never,
}

/// A request as the server saw it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
}

impl Seen {
    /// The value of a header, by its name in any case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A server of git over HTTPS on 127.0.0.1, with a folder of its own: its
/// repositories under `root/`, served as `/<owner>/<name>.git`.
pub struct GitServer {
    pub port: u16,
    dir: tempfile::TempDir,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    accepting: Option<std::thread::JoinHandle<()>>,
}

/// The certificate authority and the server's certificate, made once.
struct Tls {
    ca_pem: String,
    config: Arc<rustls::ServerConfig>,
}

fn tls() -> &'static Tls {
    static TLS: OnceLock<Tls> = OnceLock::new();
    TLS.get_or_init(|| {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
            KeyUsagePurpose,
        };
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(DnType::CommonName, "The tests' certificate authority");
        ca.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca = ca.self_signed(&ca_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut leaf =
            CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
        leaf.distinguished_name
            .push(DnType::CommonName, "127.0.0.1");
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        let leaf = leaf.signed_by(&key, &ca, &ca_key).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        Tls {
            ca_pem: ca.pem(),
            config: Arc::new(config),
        }
    })
}

impl GitServer {
    /// A server that answers as `answers` says.
    pub fn start(answers: Answers) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("root")).unwrap();
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        std::fs::write(dir.path().join("ca.pem"), &tls().ca_pem).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let root = dir.path().join("root");
        let home = dir.path().join("home");
        let accepting = {
            let (seen, stop) = (seen.clone(), stop.clone());
            std::thread::spawn(move || {
                for tcp in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(tcp) = tcp else { continue };
                    let served = Served {
                        answers,
                        port,
                        root: root.clone(),
                        home: home.clone(),
                        seen: seen.clone(),
                        stop: stop.clone(),
                    };
                    std::thread::spawn(move || served.serve(tcp));
                }
            })
        };
        Self {
            port,
            dir,
            seen,
            stop,
            accepting: Some(accepting),
        }
    }

    /// The folder its repositories are in: `GIT_PROJECT_ROOT`.
    pub fn root(&self) -> PathBuf {
        self.dir.path().join("root")
    }

    /// The file of its certificate authority, for `GIT_SSL_CAINFO`.
    pub fn ca_file(&self) -> PathBuf {
        self.dir.path().join("ca.pem")
    }

    /// The address of a repository it serves.
    pub fn url(&self, owner: &str, name: &str) -> String {
        format!("https://127.0.0.1:{}/{owner}/{name}.git", self.port)
    }

    /// A bare repository that it serves, made where it is not there yet,
    /// with `main` as its default branch.
    pub fn bare(&self, owner: &str, name: &str) -> PathBuf {
        let bare = self.root().join(owner).join(format!("{name}.git"));
        if !bare.join("HEAD").exists() {
            std::fs::create_dir_all(&bare).unwrap();
            let home = self.dir.path().join("home");
            git(&home, &bare, &["init", "--quiet", "--bare", "-b", "main"]);
            // What a partial clone's fetch of one object asks for.
            git(&home, &bare, &["config", "uploadpack.allowFilter", "true"]);
            git(
                &home,
                &bare,
                &["config", "uploadpack.allowAnySHA1InWant", "true"],
            );
        }
        bare
    }

    /// What it was asked, in order.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for GitServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(accepting) = self.accepting.take() {
            let _ = accepting.join();
        }
    }
}

/// One connection, and what it needs to be answered.
struct Served {
    answers: Answers,
    port: u16,
    root: PathBuf,
    home: PathBuf,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
}

/// A request: its line, its headers and its body.
struct Request {
    seen: Seen,
    body: Vec<u8>,
}

impl Served {
    fn serve(self, tcp: TcpStream) {
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(30)));
        let Ok(conn) = rustls::ServerConnection::new(tls().config.clone()) else {
            return;
        };
        let mut stream = rustls::StreamOwned::new(conn, tcp);
        let Some(request) = read_request(&mut stream) else {
            return;
        };
        self.seen.lock().unwrap().push(request.seen.clone());
        let answer = match self.answers {
            Answers::Never => {
                while !self.stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(20));
                }
                return;
            }
            Answers::Password => response(
                "401 Unauthorized",
                &[("WWW-Authenticate", "Basic realm=\"tests\"")],
                b"",
            ),
            Answers::Redirect => {
                let to = format!(
                    "https://127.0.0.1:{}/moved{}",
                    self.port, request.seen.target
                );
                response("301 Moved Permanently", &[("Location", &to)], b"")
            }
            Answers::Git => self.through_http_backend(&request),
        };
        let _ = stream.write_all(&answer);
        stream.conn.send_close_notify();
        let _ = stream.flush();
    }

    /// The answer of `git http-backend` to `request`, as CGI.
    fn through_http_backend(&self, request: &Request) -> Vec<u8> {
        let seen = &request.seen;
        let (path, query) = seen
            .target
            .split_once('?')
            .unwrap_or((seen.target.as_str(), ""));
        let mut cgi = Command::new("git");
        cgi.arg("http-backend")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_PROJECT_ROOT", &self.root)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("REQUEST_METHOD", &seen.method)
            .env("PATH_INFO", path)
            .env("QUERY_STRING", query)
            .env("CONTENT_TYPE", seen.header("content-type").unwrap_or(""))
            .env("CONTENT_LENGTH", request.body.len().to_string())
            .env("REMOTE_ADDR", "127.0.0.1")
            .env("SERVER_PROTOCOL", "HTTP/1.1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(encoding) = seen.header("content-encoding") {
            cgi.env("HTTP_CONTENT_ENCODING", encoding)
                .env("CONTENT_ENCODING", encoding);
        }
        if let Some(protocol) = seen.header("git-protocol") {
            cgi.env("HTTP_GIT_PROTOCOL", protocol)
                .env("GIT_PROTOCOL", protocol);
        }
        let mut child = cgi.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let body = request.body.clone();
        let writing = std::thread::spawn(move || {
            let _ = stdin.write_all(&body);
        });
        let output = child.wait_with_output().unwrap();
        let _ = writing.join();
        let out = output.stdout;
        let (head, body) = match find(&out, b"\r\n\r\n") {
            Some(at) => (&out[..at], &out[at + 4..]),
            None => match find(&out, b"\n\n") {
                Some(at) => (&out[..at], &out[at + 2..]),
                None => (&out[..], &[][..]),
            },
        };
        let head = String::from_utf8_lossy(head);
        let mut status = "200 OK".to_string();
        let mut headers = Vec::new();
        for line in head.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("status") {
                status = value.trim().to_string();
            } else {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }
        let headers: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        response(&status, &headers, body)
    }
}

/// An answer, with its length, that closes the connection.
fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read one request: its line and headers, then its body by its length,
/// or in chunks.
fn read_request(stream: &mut impl Read) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let end = loop {
        if let Some(at) = find(&buf, b"\r\n\r\n") {
            break at;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut rest = buf[end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target) = (first.next()?.to_string(), first.next()?.to_string());
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    let seen = Seen {
        method,
        target,
        headers,
    };
    let mut more = |rest: &mut Vec<u8>| -> Option<()> {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        rest.extend_from_slice(&chunk[..n]);
        Some(())
    };
    let body = if let Some(length) = seen.header("content-length") {
        let length: usize = length.parse().ok()?;
        while rest.len() < length {
            more(&mut rest)?;
        }
        rest.truncate(length);
        rest
    } else if seen
        .header("transfer-encoding")
        .is_some_and(|e| e.eq_ignore_ascii_case("chunked"))
    {
        let mut body = Vec::new();
        loop {
            let line_end = loop {
                if let Some(at) = find(&rest, b"\r\n") {
                    break at;
                }
                more(&mut rest)?;
            };
            let size_text = String::from_utf8_lossy(&rest[..line_end]).into_owned();
            let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
            rest.drain(..line_end + 2);
            if size == 0 {
                break;
            }
            while rest.len() < size + 2 {
                more(&mut rest)?;
            }
            body.extend_from_slice(&rest[..size]);
            rest.drain(..size + 2);
        }
        body
    } else {
        Vec::new()
    };
    Some(Request { seen, body })
}

// ── The test's own git ───────────────────────────────────────────────

/// Run the test's own git in `dir`, with `home` as its HOME and nothing
/// else of the machine's settings, and say what it wrote: it must
/// succeed.
pub fn git(home: &Path, dir: &Path, args: &[&str]) -> String {
    let output = test_git(home, dir, args).output().unwrap();
    assert!(
        output.status.success(),
        "git {args:?} in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// The test's own git, as a command.
pub fn test_git(home: &Path, dir: &Path, args: &[&str]) -> Command {
    let mut git = Command::new("git");
    git.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("LC_ALL", "C")
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.org",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "protocol.file.allow=always",
            "-c",
            "commit.gpgSign=false",
        ])
        .arg("-C")
        .arg(dir)
        .args(args);
    git
}

/// Write the list in the work tree `work` (or take it out, with `None`),
/// commit, push `main` to `bare`, and give the commit.
pub fn commit_list(home: &Path, work: &Path, bare: &Path, list: Option<&[u8]>) -> String {
    if !work.join(".git").exists() {
        std::fs::create_dir_all(work).unwrap();
        git(home, work, &["init", "--quiet", "-b", "main"]);
    }
    let file = work.join(".cordelia/members");
    match list {
        Some(list) => {
            std::fs::create_dir_all(work.join(".cordelia")).unwrap();
            std::fs::write(&file, list).unwrap();
        }
        None => {
            let _ = std::fs::remove_file(&file);
        }
    }
    commit_work(home, work, bare)
}

/// Commit what the work tree `work` holds, with a change of its own, push
/// `main` to `bare`, and give the commit.
pub fn commit_work(home: &Path, work: &Path, bare: &Path) -> String {
    std::fs::write(
        work.join("README"),
        format!("{:?}\n", std::time::Instant::now()),
    )
    .unwrap();
    git(home, work, &["add", "-A"]);
    git(home, work, &["commit", "--quiet", "-m", "a change"]);
    git(
        home,
        work,
        &["push", "--quiet", "--force", bare.to_str().unwrap(), "main"],
    );
    git(home, work, &["rev-parse", "HEAD"])
}

/// Write a program that a test's git may run: a shell script that writes
/// its name in `marks`, and then does `then`. It is written by another
/// process, so that no fork in another of the tests' threads holds it
/// open for writing when it is run.
pub fn marker(bin: &Path, name: &str, marks: &Path, then: &str) -> PathBuf {
    std::fs::create_dir_all(bin).unwrap();
    let path = bin.join(name);
    let body = format!(
        "#!/bin/sh\necho \"$0 $*\" >> '{}/{name}'\n{then}\n",
        marks.display()
    );
    let mut write = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(&path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    write
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    assert!(write.wait().unwrap().success());
    path
}

/// The marks that programs wrote in `marks`: none, where nothing ran.
pub fn marks_in(marks: &Path) -> Vec<String> {
    let mut found: Vec<String> = std::fs::read_dir(marks)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| {
                    let said = std::fs::read_to_string(e.path()).unwrap_or_default();
                    format!("{}: {}", e.file_name().to_string_lossy(), said.trim())
                })
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

/// Every file under `dir`, with its bytes and when it was changed: what
/// a test compares before and after, to say that nothing in it changed.
pub fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>, Option<std::time::SystemTime>)> {
    let mut files = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                dirs.push(path.clone());
                files.push((path, Vec::new(), meta.modified().ok()));
            } else if meta.is_file() {
                files.push((
                    path.clone(),
                    std::fs::read(&path).unwrap(),
                    meta.modified().ok(),
                ));
            } else {
                files.push((path, Vec::new(), None));
            }
        }
    }
    files.sort();
    files
}
