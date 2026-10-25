//! The machine a run is on: the checks before it starts (decision
//! 2026-10-22 §2.4; §4.2, step 1; §4.3, rule 6), and what is read of each
//! process and of the machine from outside them (§1.1, rule 2; §1.3).

use std::path::Path;

// ── Threads (§2.4) ───────────────────────────────────────────────────

/// The limits on threads, and what is used of each where it is known.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Limits {
    /// `kernel.pid_max`.
    pub pid_max: u64,
    /// `kernel.threads-max`.
    pub threads_max: u64,
    /// The user's `ulimit -u`, where it is not unlimited.
    pub nproc: Option<u64>,
    /// The `pids.max` of the harness's cgroup, the least of it and its
    /// parents', where any is set; and its `pids.current`.
    pub pids_max: Option<u64>,
    pub pids_current: Option<u64>,
    /// The threads the machine runs already.
    pub threads_now: u64,
}

/// Threads of a node not under a mask: a tokio worker and an HTTP worker
/// for each core, and some more (§1.4: about 34 on 16 cores; §2.4 counts
/// 36).
pub fn threads_of_a_node(cores: u64) -> u64 {
    2 * cores + 4
}

/// The cores a device's mask gives it (§2.4).
pub const MASK_CORES: u64 = 4;

/// How the run starts its devices, by the limits on threads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadPlan {
    /// No mask is needed.
    Unmasked,
    /// Each device under a mask of four cores.
    Masked,
    /// A limit is short even with the mask: the run does not start.
    Refused(String),
}

/// The plan for `relays` and `devices` on `cores`, given `limits`: the
/// mask where any limit is under one and a half times what the run needs
/// without it, and a refusal only where a limit is short with it too.
pub fn plan_threads(
    limits: &Limits,
    relays: u64,
    devices: u64,
    cores: u64,
) -> (ThreadPlan, String) {
    let unmasked = (relays + devices) * threads_of_a_node(cores);
    let masked =
        relays * threads_of_a_node(cores) + devices * threads_of_a_node(cores.min(MASK_CORES));
    let mut room: Vec<(&str, u64)> = vec![
        (
            "kernel.pid_max",
            limits.pid_max.saturating_sub(limits.threads_now),
        ),
        (
            "kernel.threads-max",
            limits.threads_max.saturating_sub(limits.threads_now),
        ),
    ];
    if let Some(n) = limits.nproc {
        room.push(("ulimit -u", n.saturating_sub(limits.threads_now)));
    }
    if let Some(n) = limits.pids_max {
        room.push((
            "the cgroup's pids.max",
            n.saturating_sub(limits.pids_current.unwrap_or(limits.threads_now)),
        ));
    }
    let short = |need: u64| -> Vec<String> {
        room.iter()
            .filter(|(_, left)| (*left as f64) < 1.5 * need as f64)
            .map(|(what, left)| format!("{what} leaves {left}"))
            .collect()
    };
    let said = format!(
        "{} nodes need about {unmasked} threads on {cores} cores, {masked} with each device \
         masked to {MASK_CORES} cores; the machine runs {} already",
        relays + devices,
        limits.threads_now
    );
    let short_unmasked = short(unmasked);
    if short_unmasked.is_empty() {
        return (ThreadPlan::Unmasked, format!("{said}: no mask"));
    }
    let short_masked = short(masked);
    if short_masked.is_empty() {
        return (
            ThreadPlan::Masked,
            format!(
                "{said}: each device under a mask of {MASK_CORES} cores ({})",
                short_unmasked.join(", ")
            ),
        );
    }
    (
        ThreadPlan::Refused(format!(
            "{said}: short even with the mask ({})",
            short_masked.join(", ")
        )),
        said,
    )
}

fn read_number(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// The `pids.max` and `pids.current` of the cgroup named in
/// `proc_self_cgroup` (the text of `/proc/self/cgroup`) under `root`
/// (`/sys/fs/cgroup`): the least `pids.max` of it and its parents, where
/// any is set, and its own `pids.current`.
pub fn cgroup_pids(proc_self_cgroup: &str, root: &Path) -> (Option<u64>, Option<u64>) {
    let Some(path) = proc_self_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
    else {
        return (None, None);
    };
    let mut dir = root.join(path.trim().trim_start_matches('/'));
    let current = read_number(&dir.join("pids.current"));
    let mut least: Option<u64> = None;
    loop {
        if let Ok(text) = std::fs::read_to_string(dir.join("pids.max"))
            && let Ok(n) = text.trim().parse::<u64>()
        {
            least = Some(least.map_or(n, |l| l.min(n)));
        }
        if dir == root || !dir.pop() || !dir.starts_with(root) {
            break;
        }
    }
    (least, current)
}

/// The limits on this machine.
pub fn read_limits() -> Limits {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let (pids_max, pids_current) = cgroup_pids(&cgroup, Path::new("/sys/fs/cgroup"));
    let nproc = rustix::process::getrlimit(rustix::process::Resource::Nproc).current;
    // The fourth field of /proc/loadavg: running and all threads.
    let threads_now = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|text| {
            let all = text
                .split_whitespace()
                .nth(3)?
                .split('/')
                .nth(1)?
                .to_string();
            all.parse().ok()
        })
        .unwrap_or(0);
    Limits {
        pid_max: read_number(Path::new("/proc/sys/kernel/pid_max")).unwrap_or(0),
        threads_max: read_number(Path::new("/proc/sys/kernel/threads-max")).unwrap_or(0),
        nproc,
        pids_max,
        pids_current,
        threads_now,
    }
}

/// The cores of this machine.
pub fn cores() -> u64 {
    std::thread::available_parallelism().map_or(1, |n| n.get() as u64)
}

/// The machine as the summary says it: "16 vCPU, 32 GB", from /proc.
pub fn machine_words() -> String {
    let cpus = std::fs::read_to_string("/proc/cpuinfo")
        .map(|t| t.lines().filter(|l| l.starts_with("processor")).count())
        .unwrap_or(0);
    let kib = meminfo("MemTotal").unwrap_or(0);
    format!(
        "{cpus} vCPU, {:.0} GB",
        kib as f64 * 1024.0 / 1_000_000_000.0
    )
}

/// A line of /proc/meminfo, in KiB.
pub fn meminfo(what: &str) -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    text.lines().find_map(|line| {
        let rest = line.strip_prefix(what)?.strip_prefix(':')?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

/// The bytes free on the volume of `path`.
pub fn disk_free(path: &Path) -> Option<u64> {
    let stat = rustix::fs::statvfs(path).ok()?;
    Some(stat.f_bavail * stat.f_frsize)
}

// ── The pids of an earlier run (§4.3, rule 6) ───────────────────────

/// A line of the pid file: a node's pid, and the configuration it runs
/// with, by which its command line is known.
pub fn pid_line(pid: u32, config: &Path) -> String {
    format!("{pid} {}\n", config.display())
}

/// Refused where the pid file `path`, of an earlier run, names a process
/// that lives and whose command line is a node of that run: one that runs
/// with the configuration the file names beside its pid.
pub fn check_earlier_pids(path: &Path) -> Result<(), String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Ok(());
    };
    for line in text.lines() {
        let Some((pid, config)) = line.split_once(' ') else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let args: Vec<String> = cmdline
            .split(|b| *b == 0)
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let runs_it = args
            .windows(2)
            .any(|two| two[0] == "--config" && two[1] == config);
        if runs_it {
            return Err(format!(
                "a node of an earlier run is still running: pid {pid}, with {config} (named in \
                 {}); stop it first",
                path.display()
            ));
        }
    }
    Ok(())
}

// ── What is read from outside a process ─────────────────────────────

/// What /proc says of one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcRead {
    pub rss_kib: u64,
    pub hwm_kib: u64,
    pub threads: u64,
    pub fds: u64,
    /// User and system ticks.
    pub ticks: u64,
}

/// What /proc says of `pid`, where it lives.
pub fn read_proc(pid: u32) -> Option<ProcRead> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let field = |name: &str| -> u64 {
        status
            .lines()
            .find_map(|l| {
                l.strip_prefix(name)?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            })
            .unwrap_or(0)
    };
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Past the command's name, which is in parentheses and may hold spaces.
    let after = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after.split_whitespace().collect();
    // utime and stime are the 14th and 15th fields of the whole line.
    let ticks = fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?;
    let fds = std::fs::read_dir(format!("/proc/{pid}/fd")).map_or(0, |d| d.count() as u64);
    Some(ProcRead {
        rss_kib: field("VmRSS:"),
        hwm_kib: field("VmHWM:"),
        threads: field("Threads:"),
        fds,
        ticks,
    })
}

/// The clock's ticks a second, as /proc counts CPU.
pub fn ticks_a_second() -> u64 {
    std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(100)
}

/// What is read of the machine once a minute (§1.3).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct MachineRead {
    /// /proc/stat's first line: all ticks, idle and iowait.
    pub cpu_all: u64,
    pub cpu_idle: u64,
    pub cpu_iowait: u64,
    pub mem_available_kib: u64,
    pub disk_free: u64,
    /// /proc/diskstats, over the whole disks: writes completed and the
    /// milliseconds spent writing.
    pub writes: u64,
    pub write_ms: u64,
    /// The harness's own CPU ticks.
    pub harness_ticks: u64,
}

pub fn read_machine(out: &Path) -> MachineRead {
    let mut read = MachineRead::default();
    if let Ok(stat) = std::fs::read_to_string("/proc/stat")
        && let Some(cpu) = stat.lines().next()
    {
        let n: Vec<u64> = cpu
            .split_whitespace()
            .skip(1)
            .filter_map(|v| v.parse().ok())
            .collect();
        read.cpu_all = n.iter().take(8).sum();
        read.cpu_idle = n.get(3).copied().unwrap_or(0);
        read.cpu_iowait = n.get(4).copied().unwrap_or(0);
    }
    read.mem_available_kib = meminfo("MemAvailable").unwrap_or(0);
    read.disk_free = disk_free(out).unwrap_or(0);
    if let Ok(disks) = std::fs::read_to_string("/proc/diskstats") {
        for line in disks.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            let Some(name) = f.get(2) else { continue };
            // Whole disks only: not partitions, loops or RAM disks.
            let whole = std::path::Path::new(&format!("/sys/block/{name}/device")).exists();
            if !whole {
                continue;
            }
            read.writes += f.get(7).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
            read.write_ms += f.get(10).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        }
    }
    read.harness_ticks = read_proc(std::process::id()).map_or(0, |p| p.ticks);
    read
}
