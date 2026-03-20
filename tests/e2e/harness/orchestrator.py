#!/usr/bin/env python3
"""
Cordelia E2E test orchestrator.

Replaces bash run-s2.sh / run-s3.sh with a parameterized, observable harness.
Reads TOML scenario specs, drives Docker Compose topologies, polls node metrics
into SQLite, and runs assertions as queries.

Usage:
    python3 orchestrator.py scenarios/s2-r20.toml [--no-teardown] [--db results.db]
    python3 orchestrator.py --batch scenarios/s2-r20.toml scenarios/s3-n4.toml
"""

import argparse
import hashlib
import json
import os
import shlex
import sqlite3
import subprocess
import sys
import time
import tomllib
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# -- Constants ----------------------------------------------------------------

DB_PATH_IN_CONTAINER = "/data/cordelia/cordelia.db"
TOKEN_PATH_IN_CONTAINER = "/data/cordelia/node-token"
API_PORT = 9473

SCRIPT_DIR = Path(__file__).parent.resolve()
E2E_DIR = SCRIPT_DIR.parent
SCALE_DIR = E2E_DIR / "scale"
SCHEMA_PATH = SCRIPT_DIR / "schema.sql"

MAX_WORKERS = int(os.environ.get("CORDELIA_E2E_WORKERS", "64"))

# -- Token cache --------------------------------------------------------------

_token_cache: dict[str, str] = {}


def _get_token(container: str) -> str:
    if container not in _token_cache:
        token = docker_exec(container, f"cat {TOKEN_PATH_IN_CONTAINER}")
        if token:
            _token_cache[container] = token
    return _token_cache.get(container, "")


# -- Helpers ------------------------------------------------------------------

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def channel_id_for(name: str) -> str:
    """Derive channel_id from name (channels-api.md S3.1)."""
    payload = f"cordelia:channel:{name.lower()}"
    return hashlib.sha256(payload.encode()).hexdigest()


def run(cmd: str, check=True, capture=True, timeout=60, env=None) -> subprocess.CompletedProcess:
    """Run a shell command, return CompletedProcess."""
    return subprocess.run(
        cmd, shell=True, check=check, timeout=timeout,
        capture_output=capture, text=True, env=env,
    )


def docker_exec(container: str, cmd: str, timeout=10) -> str:
    """Run a command inside a Docker container, return stdout."""
    full = f"docker exec {shlex.quote(container)} {cmd}"
    try:
        result = run(full, check=False, timeout=timeout)
        return result.stdout.strip() if result.returncode == 0 else ""
    except subprocess.TimeoutExpired:
        return ""


def api_get(container: str, endpoint: str) -> dict:
    """GET a node's REST API endpoint, return parsed JSON."""
    token = _get_token(container)
    if not token:
        return {}
    raw = docker_exec(
        container,
        f'curl -sf -H "Authorization: Bearer {token}" '
        f"http://localhost:{API_PORT}/api/v1/{endpoint}",
    )
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def api_post(container: str, endpoint: str, body: dict) -> dict:
    """POST to a node's REST API endpoint."""
    token = _get_token(container)
    if not token:
        return {}
    body_json = json.dumps(body)
    raw = docker_exec(
        container,
        f'curl -sf -H "Authorization: Bearer {token}" '
        f'-H "Content-Type: application/json" '
        f"-d '{body_json}' "
        f"http://localhost:{API_PORT}/api/v1/{endpoint}",
        timeout=15,
    )
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}


def db_query(container: str, sql: str) -> str:
    """Run a SQLite query inside a container, return result."""
    return docker_exec(
        container,
        f'sqlite3 {DB_PATH_IN_CONTAINER} "{sql}"',
    )


def docker_cleanup():
    """Full Docker cleanup: remove containers, prune networks/volumes, rm test artifacts."""
    print("Cleaning Docker state...")
    run("docker rm -f $(docker ps -aq) 2>/dev/null", check=False, timeout=120)
    run("docker network prune -f 2>/dev/null", check=False, timeout=60)
    run("docker volume prune -af 2>/dev/null", check=False, timeout=60)
    run(f"sudo rm -rf {SCALE_DIR}/s2-* {SCALE_DIR}/s3-* {SCALE_DIR}/keys "
        f"{E2E_DIR}/logs 2>/dev/null", check=False, timeout=15)


# -- Database -----------------------------------------------------------------

class MetricsDB:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        schema = SCHEMA_PATH.read_text()
        self.conn.executescript(schema)

    def init_run(self, run_id: str, scenario: str, params: dict):
        self.conn.execute(
            "INSERT INTO run (run_id, scenario, started_at, params) VALUES (?, ?, ?, ?)",
            (run_id, scenario, now_iso(), json.dumps(params)),
        )
        self.conn.commit()

    def finish_run(self, run_id: str, result: str):
        self.conn.execute(
            "UPDATE run SET finished_at = ?, result = ? WHERE run_id = ?",
            (now_iso(), result, run_id),
        )
        self.conn.commit()

    def observe(self, phase: str, node_id: str, node_role: str, metric: str, value: float):
        self.conn.execute(
            "INSERT INTO observations (ts, phase, node_id, node_role, metric, value) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (now_iso(), phase, node_id, node_role, metric, value),
        )

    def event(self, phase: str, event_type: str, node_id: str = None, detail: str = None):
        self.conn.execute(
            "INSERT INTO events (ts, phase, event_type, node_id, detail) VALUES (?, ?, ?, ?, ?)",
            (now_iso(), phase, event_type, node_id, detail),
        )
        self.conn.commit()

    def assertion(self, name: str, passed: bool, expected=None, actual=None, detail=None):
        self.conn.execute(
            "INSERT INTO assertions (ts, name, passed, expected, actual, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (now_iso(), name, 1 if passed else 0, str(expected), str(actual), detail),
        )
        self.conn.commit()

    def flush(self):
        self.conn.commit()

    def close(self):
        self.conn.commit()
        self.conn.close()


# -- Topology -----------------------------------------------------------------

class S2Topology:
    """S2 relay mesh topology: 2B + R relays + R*PPZ personal."""
    topo_type = "s2"

    def __init__(self, cfg: dict):
        topo = cfg["topology"]
        self.name = topo["name"]
        self.relays = topo["relays"]
        self.ppz = topo.get("personal_per_zone", 1)
        self.bootnodes = topo.get("bootnodes", 2)
        self.personal = self.relays * self.ppz
        self.container_count = self.bootnodes + self.relays + self.personal
        # Container prefix matches generate-s2.sh: "s2-{R}" (e.g. s2-20)
        self.prefix = f"s2-{self.relays}"

    def relay_containers(self) -> list[str]:
        return [f"{self.prefix}-r{i}" for i in range(1, self.relays + 1)]

    def personal_containers(self) -> list[str]:
        return [f"{self.prefix}-p{i}" for i in range(1, self.personal + 1)]

    def bootnode_containers(self) -> list[str]:
        return [f"{self.prefix}-b{i}" for i in range(1, self.bootnodes + 1)]

    def all_containers(self) -> list[str]:
        return self.bootnode_containers() + self.relay_containers() + self.personal_containers()

    def data_containers(self) -> list[str]:
        """Containers that participate in data exchange (not bootnodes)."""
        return self.relay_containers() + self.personal_containers()

    def role_of(self, container: str) -> str:
        suffix = container.split("-")[-1]
        if suffix.startswith("r"):
            return "relay"
        elif suffix.startswith("b"):
            return "bootnode"
        return "personal"

    def compose_file(self) -> Path:
        return SCALE_DIR / f"s2-{self.relays}" / f"s2-{self.relays}.yml"

    def compose_project(self) -> str:
        return f"{self.prefix}-mesh"

    def generate_cmd(self, cfg: dict) -> str:
        return f"bash {SCALE_DIR}/generate-s2.sh {self.relays} {self.ppz}"

    def generate_env(self, cfg: dict) -> dict:
        env = os.environ.copy()
        gov = cfg.get("governor", {})
        relay_hot_max = gov.get("relay_hot_max", self.relays + 5)
        env["RELAY_HOT_MAX_OVERRIDE"] = str(relay_hot_max)
        return env

    def patch_configs(self, cfg: dict):
        """Patch generated configs if governor params differ from defaults."""
        config_dir = SCALE_DIR / f"s2-{self.relays}" / "configs"

        gov = cfg.get("governor", {})
        relay_hot_max = gov.get("relay_hot_max", self.relays + 5)
        if relay_hot_max != self.relays + 5:
            for cfg_file in config_dir.glob("*.toml"):
                text = cfg_file.read_text()
                default = f"hot_max = {self.relays + 5}"
                if default in text:
                    text = text.replace(default, f"hot_max = {relay_hot_max}")
                    cfg_file.write_text(text)
            print(f"  Patched relay hot_max to {relay_hot_max}")

        # Patch log level if scenario overrides it (default: debug from generator)
        log_level = cfg.get("logging", {}).get("level")
        if log_level and log_level != "debug":
            for cfg_file in config_dir.glob("*.toml"):
                text = cfg_file.read_text()
                text = text.replace('level = "debug"', f'level = "{log_level}"')
                cfg_file.write_text(text)
            print(f"  Patched log level to {log_level}")


class S3Topology:
    """S3 PAN swarm topology: 1B + 2R + 2 leads + N*2 swarm nodes."""
    topo_type = "s3"

    def __init__(self, cfg: dict):
        topo = cfg["topology"]
        self.name = topo["name"]
        self.leads = topo.get("leads", 2)
        self.swarm_per_lead = topo.get("swarm_per_lead", 4)
        self.relays = topo.get("relays", 2)
        self.bootnodes = topo.get("bootnodes", 1)
        self.swarm_total = self.leads * self.swarm_per_lead
        self.container_count = (self.bootnodes + self.relays +
                                self.leads + self.swarm_total)
        # Docker Compose project name: s3-{N}-pan
        self.project_name = f"s3-{self.swarm_per_lead}-pan"
        self.prefix = self.project_name

    def relay_containers(self) -> list[str]:
        return [f"{self.prefix}-r{i}-1" for i in range(1, self.relays + 1)]

    def lead_containers(self) -> list[str]:
        return [f"{self.prefix}-lead-{i}-1" for i in range(self.leads)]

    def swarm_containers(self) -> list[str]:
        result = []
        for lead_idx in range(self.leads):
            for swarm_idx in range(self.swarm_per_lead):
                result.append(f"{self.prefix}-swarm-{lead_idx}-{swarm_idx}-1")
        return result

    def swarm_containers_for_lead(self, lead_idx: int) -> list[str]:
        return [f"{self.prefix}-swarm-{lead_idx}-{i}-1"
                for i in range(self.swarm_per_lead)]

    def personal_containers(self) -> list[str]:
        """All personal nodes: leads + swarm."""
        return self.lead_containers() + self.swarm_containers()

    def bootnode_containers(self) -> list[str]:
        return [f"{self.prefix}-b1-1"]

    def all_containers(self) -> list[str]:
        return (self.bootnode_containers() + self.relay_containers() +
                self.lead_containers() + self.swarm_containers())

    def data_containers(self) -> list[str]:
        return self.relay_containers() + self.personal_containers()

    def role_of(self, container: str) -> str:
        # Remove -1 suffix added by Docker Compose
        name = container.replace(f"{self.prefix}-", "")
        if name.startswith("r"):
            return "relay"
        elif name.startswith("b"):
            return "bootnode"
        elif name.startswith("lead"):
            return "lead"
        elif name.startswith("swarm"):
            return "swarm"
        return "personal"

    def compose_file(self) -> Path:
        return SCALE_DIR / f"s3-{self.swarm_per_lead}" / f"s3-{self.swarm_per_lead}.yml"

    def compose_project(self) -> str:
        return self.project_name

    def generate_cmd(self, cfg: dict) -> str:
        return f"bash {SCALE_DIR}/generate-s3.sh {self.swarm_per_lead}"

    def generate_env(self, cfg: dict) -> dict:
        return os.environ.copy()

    def patch_configs(self, cfg: dict):
        pass  # S3 configs are simpler, no patching needed yet


def make_topology(cfg: dict):
    """Factory: create the right topology type from config."""
    topo_type = cfg["topology"].get("type", "s2")
    if topo_type == "s3":
        return S3Topology(cfg)
    return S2Topology(cfg)


# -- Phases -------------------------------------------------------------------

def poll_metrics(db: MetricsDB, topo, phase: str, metrics: list[str]):
    """Poll all data nodes once, write observations."""
    containers = topo.data_containers()

    def _fetch_one(container):
        """Worker: fetch status + item count via docker exec. No DB writes."""
        status = api_get(container, "status")
        item_count = None
        if "items_stored" in metrics:
            val = db_query(container, "SELECT COUNT(*) FROM items WHERE is_tombstone=0")
            try:
                item_count = float(val)
            except (ValueError, TypeError):
                item_count = None
        return container, status, item_count

    workers = min(MAX_WORKERS, len(containers))
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_fetch_one, c): c for c in containers}
        for f in as_completed(futures):
            container = futures[f]
            results[container] = f.result()

    # Write to DB on main thread (SQLite not thread-safe)
    for container, (_, status, item_count) in results.items():
        role = topo.role_of(container)
        for metric in metrics:
            if metric == "items_stored" and item_count is not None:
                db.observe(phase, container, role, metric, item_count)
            elif metric in status:
                try:
                    db.observe(phase, container, role, metric, float(status[metric]))
                except (ValueError, TypeError):
                    pass
    db.flush()


def phase_startup(topo, cfg: dict, db: MetricsDB):
    """Generate topology, compose up, wait for healthy."""
    db.event("startup", "phase_start")
    print(f"\nPhase 0: Starting {topo.container_count} containers...")

    compose_file = topo.compose_file()

    if not compose_file.exists():
        env = topo.generate_env(cfg)
        subprocess.run(
            topo.generate_cmd(cfg),
            shell=True, check=True, env=env, capture_output=True, timeout=30,
        )

    topo.patch_configs(cfg)

    # Compose up
    project = topo.compose_project()
    compose_timeout = max(120, topo.container_count)
    run(f"docker compose -p {project} -f {compose_file} up -d", timeout=compose_timeout)

    # Wait healthy -- concurrent checking with thread pool
    health_timeout = max(120, topo.container_count)
    all_containers = topo.all_containers()
    pending = set(all_containers)
    start = time.time()
    workers = min(MAX_WORKERS, len(all_containers))

    def check_one(container):
        status = api_get(container, "status")
        return container, status.get("status") == "running"

    while pending and time.time() - start < health_timeout:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(check_one, c): c for c in pending}
            still_pending = set()
            for f in as_completed(futures):
                container, healthy = f.result()
                if not healthy:
                    still_pending.add(container)
        pending = still_pending
        if pending:
            elapsed = int(time.time() - start)
            print(f"    {len(all_containers) - len(pending)}/{len(all_containers)} healthy ({elapsed}s)...")
            time.sleep(3)

    if pending:
        elapsed = int(time.time() - start)
        print(f"  TIMEOUT: {len(pending)} containers not healthy after {elapsed}s: {sorted(pending)[:5]}...")
        db.event("startup", "timeout", detail=json.dumps({"pending": len(pending)}))
        return False

    elapsed = int(time.time() - start)
    print(f"  All {topo.container_count} containers healthy ({elapsed}s)")
    db.event("startup", "phase_end", detail=json.dumps({"elapsed_secs": elapsed}))
    return True


def phase_connectivity(topo, cfg: dict, db: MetricsDB, collection: dict):
    """Wait for basic connectivity (S3: each node has min hot peers)."""
    phases = cfg["experiment"]["phases"]
    conn_cfg = next((p for p in phases if p["type"] == "wait_connectivity"), None)
    if not conn_cfg:
        return True

    min_hot = conn_cfg.get("min_hot_per_node", 1)
    timeout = conn_cfg.get("timeout_secs", 30)
    poll_interval = collection.get("poll_interval_secs", 2)
    metrics = collection.get("metrics", ["peers_hot", "peers_warm"])

    db.event("connectivity", "phase_start", detail=json.dumps({
        "min_hot": min_hot, "timeout": timeout,
    }))
    print(f"\nPhase 1: Verifying connectivity (min {min_hot} hot peer/node)...")

    start = time.time()
    # Wait for timeout, polling
    time.sleep(min(timeout, 15))
    poll_metrics(db, topo, "connectivity", metrics)

    containers = topo.data_containers()
    workers = min(MAX_WORKERS, len(containers))

    # Fetch status concurrently
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(api_get, c, "status"): c for c in containers}
        status_results = {}
        for f in as_completed(futures):
            container = futures[f]
            status_results[container] = f.result()

    # Assertions on main thread
    passed = 0
    failed = 0
    for container in containers:
        status = status_results.get(container, {})
        hot = int(status.get("peers_hot", 0))
        ok = hot >= min_hot
        if ok:
            print(f"  PASS: {container} has {hot} hot peers (>= {min_hot})")
            passed += 1
        else:
            print(f"  FAIL: {container} has {hot} hot peers (< {min_hot})")
            failed += 1
        db.assertion(f"{container}_connectivity", ok, min_hot, hot)

    db.event("connectivity", "phase_end", detail=json.dumps({
        "passed": passed, "failed": failed,
    }))
    return failed == 0


def phase_mesh(topo, cfg: dict, db: MetricsDB, collection: dict):
    """Wait for relay mesh formation, polling metrics."""
    phases = cfg["experiment"]["phases"]
    mesh_cfg = next((p for p in phases if p["type"] == "wait_mesh"), None)
    if not mesh_cfg:
        return True

    target = mesh_cfg.get("target", topo.relays - 1)
    target_frac = mesh_cfg.get("target_fraction", 1.0)
    timeout = mesh_cfg.get("timeout_secs", 180)
    poll_interval = collection.get("poll_interval_secs", 2)
    metrics = collection.get("metrics", ["peers_hot", "peers_warm"])

    db.event("mesh", "phase_start", detail=json.dumps({"target": target, "timeout": timeout}))
    print(f"\nPhase 1: Relay mesh formation (target: {target} hot peers/relay)...")

    start = time.time()
    required = int(topo.relays * target_frac)
    relay_containers = topo.relay_containers()

    while time.time() - start < timeout:
        poll_metrics(db, topo, "mesh", metrics)

        # Fetch relay status concurrently
        workers = min(MAX_WORKERS, len(relay_containers))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(api_get, c, "status"): c for c in relay_containers}
            status_results = {}
            for f in as_completed(futures):
                container = futures[f]
                status_results[container] = f.result()

        meshed = 0
        for container in relay_containers:
            status = status_results.get(container, {})
            hot = int(status.get("peers_hot", 0))
            if hot >= target:
                meshed += 1

        elapsed = int(time.time() - start)
        print(f"  tick {elapsed}s: {meshed}/{topo.relays} relays at target")

        if meshed >= required:
            print(f"  Mesh formed in {elapsed}s")
            db.event("mesh", "phase_end", detail=json.dumps({
                "elapsed_secs": elapsed, "meshed": meshed,
            }))
            return True

        time.sleep(poll_interval)

    elapsed = int(time.time() - start)
    print(f"  WARN: Mesh incomplete after {elapsed}s ({meshed}/{topo.relays})")
    db.event("mesh", "phase_end", detail=json.dumps({
        "elapsed_secs": elapsed, "meshed": meshed, "timeout": True,
    }))
    return meshed >= required


def phase_subscribe(topo, cfg: dict, db: MetricsDB):
    """Subscribe personal nodes to the test channel."""
    channel_name = cfg["experiment"]["channel_name"]
    channel_id = channel_id_for(channel_name)

    targets = topo.personal_containers()
    db.event("subscribe", "phase_start")
    print(f"\nPhase 2: Subscribing {len(targets)} nodes...")

    # Generate PSK key material (use harness logs dir, not scale/keys which is root-owned)
    log_dir = E2E_DIR / "logs" / "keys"
    log_dir.mkdir(parents=True, exist_ok=True)
    psk_file = log_dir / f"{channel_id}.psk"
    if not psk_file.exists():
        psk = os.urandom(32).hex()
        psk_file.write_text(psk)
    psk = psk_file.read_text().strip()

    # Subscribe concurrently
    workers = min(MAX_WORKERS, len(targets))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(api_post, c, "channels/subscribe", {"channel": channel_name}): c
            for c in targets
        }
        for f in as_completed(futures):
            container = futures[f]
            f.result()  # consume result / propagate exceptions
            db.event("subscribe", "subscribe", container)

    wait = 10 if isinstance(topo, S3Topology) else 5
    time.sleep(wait)
    db.event("subscribe", "phase_end")
    print(f"  Subscribed, waited {wait}s for propagation")
    return channel_id, psk


def phase_publish(topo, cfg: dict, db: MetricsDB, channel_id: str, psk: str):
    """Publish items from designated publishers."""
    phases = cfg["experiment"]["phases"]
    pub_cfg = next((p for p in phases if p["type"] == "publish"), None)
    if not pub_cfg:
        return 0

    publishers = pub_cfg["publishers"]
    items_per = pub_cfg.get("items_per_publisher", 3)
    item_size = pub_cfg.get("item_size_bytes", 256)
    rate_per_sec = pub_cfg.get("rate_per_sec", 0)  # 0 = no rate limit

    db.event("publish", "phase_start", detail=json.dumps({
        "publishers": publishers, "items_per": items_per,
        "item_size": item_size, "rate_per_sec": rate_per_sec,
    }))
    print(f"\nPhase 3: Publishing {items_per} items from {len(publishers)} publishers"
          f"{f' at {rate_per_sec}/s' if rate_per_sec else ''}...")

    # Resolve publisher names to container names
    channel_name = cfg["experiment"]["channel_name"]
    prefix = topo.prefix

    def _publish_serial(pub_name):
        """Publish all items for one publisher serially (preserves ordering)."""
        if isinstance(topo, S3Topology):
            container = f"{prefix}-{pub_name}-1"
        else:
            container = f"{prefix}-{pub_name}"

        pub_results = []
        for i in range(items_per):
            content = f"{pub_name} item {i+1} " + os.urandom(item_size).hex()
            result = api_post(container, "channels/publish", {
                "channel": channel_name,
                "item_type": "message",
                "content": content,
            })
            pub_results.append((container, i, result))
            if rate_per_sec > 0:
                time.sleep(1.0 / rate_per_sec)
        return pub_results

    # Different publishers run concurrently; items within each are serial
    total = 0
    workers = min(MAX_WORKERS, len(publishers))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_publish_serial, p): p for p in publishers}
        for f in as_completed(futures):
            pub_results = f.result()
            for container, seq, result in pub_results:
                if result:
                    total += 1
                    db.event("publish", "publish", container, json.dumps({
                        "item_id": result.get("item_id", ""),
                        "seq": seq,
                    }))

    db.event("publish", "phase_end", detail=json.dumps({"total_published": total}))
    print(f"  Published {total} items")
    return total


def phase_stress_publish(topo, cfg: dict, db: MetricsDB,
                         channel_id: str, psk: str, collection: dict):
    """Stress testing: publish at controlled rate with metrics collection."""
    phases = cfg["experiment"]["phases"]
    stress_cfg = next((p for p in phases if p["type"] == "stress_publish"), None)
    if not stress_cfg:
        return 0

    publishers = stress_cfg["publishers"]
    total_items = stress_cfg.get("total_items", 100)
    item_size = stress_cfg.get("item_size_bytes", 256)
    rate_per_sec = stress_cfg.get("rate_per_sec", 5)
    metrics = collection.get("metrics", ["peers_hot", "items_stored"])
    poll_every = stress_cfg.get("poll_every_items", 10)

    db.event("stress", "phase_start", detail=json.dumps({
        "publishers": publishers, "total_items": total_items,
        "item_size": item_size, "rate_per_sec": rate_per_sec,
    }))
    print(f"\nStress publish: {total_items} items at {rate_per_sec}/s "
          f"({item_size}B each) from {len(publishers)} publishers...")

    prefix = topo.prefix
    published = 0
    pub_idx = 0
    interval = 1.0 / rate_per_sec if rate_per_sec > 0 else 0

    while published < total_items:
        pub_name = publishers[pub_idx % len(publishers)]
        if isinstance(topo, S3Topology):
            container = f"{prefix}-{pub_name}-1"
        else:
            container = f"{prefix}-{pub_name}"

        channel_name = cfg["experiment"]["channel_name"]
        content = f"stress {pub_name} item {published} " + os.urandom(item_size).hex()
        result = api_post(container, "channels/publish", {
            "channel": channel_name,
            "item_type": "message",
            "content": content,
        })
        if result:
            published += 1
            db.event("stress", "publish", container)

        if published % poll_every == 0:
            poll_metrics(db, topo, "stress", metrics)
            print(f"  {published}/{total_items} published")

        pub_idx += 1
        if interval > 0:
            time.sleep(interval)

    db.event("stress", "phase_end", detail=json.dumps({"published": published}))
    print(f"  Stress complete: {published} items published")
    return published


def phase_delivery(topo, cfg: dict, db: MetricsDB,
                   expected_items: int, channel_id: str, collection: dict):
    """Wait for items to reach target nodes."""
    phases = cfg["experiment"]["phases"]
    del_cfg = next((p for p in phases if p["type"] == "wait_delivery"), None)
    if not del_cfg:
        return True

    target_items = del_cfg.get("target_items", expected_items)
    target_nodes = del_cfg.get("target_nodes", "personal")
    target_frac = del_cfg.get("target_fraction", 1.0)
    timeout = del_cfg.get("timeout_secs", 120)
    poll_interval = collection.get("poll_interval_secs", 2)
    metrics = collection.get("metrics", ["peers_hot", "peers_warm", "items_stored"])

    if target_nodes == "personal":
        targets = topo.personal_containers()
    elif target_nodes == "relay":
        targets = topo.relay_containers()
    else:
        targets = topo.data_containers()

    required = int(len(targets) * target_frac)

    db.event("delivery", "phase_start", detail=json.dumps({
        "target_items": target_items, "target_count": len(targets),
        "required": required, "timeout": timeout,
    }))
    print(f"\nPhase 4: Waiting for delivery ({target_items} items to {len(targets)} nodes)...")

    relay_containers = topo.relay_containers()

    start = time.time()
    done = 0
    while time.time() - start < timeout:
        poll_metrics(db, topo, "delivery", metrics)

        # Query target + relay containers concurrently in one batch
        all_query_containers = list(set(targets) | set(relay_containers))
        workers = min(MAX_WORKERS, len(all_query_containers))

        def _query_container(container):
            """Worker: query channel items and total items counts."""
            channel_count_str = db_query(
                container,
                f"SELECT COUNT(*) FROM items WHERE channel_id='{channel_id}' AND is_tombstone=0",
            )
            total_count_str = db_query(
                container,
                "SELECT COUNT(*) FROM items WHERE is_tombstone=0",
            )
            try:
                channel_count = int(channel_count_str)
            except (ValueError, TypeError):
                channel_count = 0
            try:
                total_count = int(total_count_str)
            except (ValueError, TypeError):
                total_count = 0
            return container, channel_count, total_count

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_query_container, c): c for c in all_query_containers}
            query_results = {}
            for f in as_completed(futures):
                container = futures[f]
                query_results[container] = f.result()

        # Compute delivery progress from results
        done = 0
        personal_counts = []
        for container in targets:
            _, channel_count, _ = query_results.get(container, (container, 0, 0))
            personal_counts.append(channel_count)
            if channel_count >= target_items:
                done += 1

        relay_counts = []
        for container in relay_containers:
            _, _, total_count = query_results.get(container, (container, 0, 0))
            relay_counts.append(total_count)

        relay_full = sum(1 for c in relay_counts if c >= target_items)
        elapsed = int(time.time() - start)

        # Build distribution of relay item counts
        dist = Counter(relay_counts)
        dist_str = " ".join(f"{v}:{c}" for v, c in sorted(dist.items()))

        pdist = Counter(personal_counts)
        pdist_str = " ".join(f"{v}:{c}" for v, c in sorted(pdist.items()))

        print(
            f"  tick {elapsed}s: {done}/{len(targets)} done"
            f" | relays: {relay_full}/{topo.relays} full,"
            f" min={min(relay_counts, default=0)}"
            f" avg={sum(relay_counts) // max(len(relay_counts), 1)}"
            f" max={max(relay_counts, default=0)} of {target_items}"
        )
        print(f"    relay dist: [{dist_str}] | personal dist: [{pdist_str}]")

        if done >= required:
            db.event("delivery", "phase_end", detail=json.dumps({
                "elapsed_secs": elapsed, "done": done,
            }))
            return True

        time.sleep(poll_interval)

    elapsed = int(time.time() - start)
    print(f"  WARN: Delivery incomplete after {elapsed}s ({done}/{len(targets)})")
    db.event("delivery", "phase_end", detail=json.dumps({
        "elapsed_secs": elapsed, "done": done, "timeout": True,
    }))
    return done >= required


def phase_assertions(topo, cfg: dict, db: MetricsDB,
                     expected_items: int, channel_id: str):
    """Run final assertions and record results."""
    db.event("assertions", "phase_start")
    print(f"\nAssertions")

    passed = 0
    failed = 0

    def assert_check(name, ok, expected, actual):
        nonlocal passed, failed
        if ok:
            print(f"  PASS: {name}")
            passed += 1
        else:
            print(f"  FAIL: {name} (expected={expected}, actual={actual})")
            failed += 1
        db.assertion(name, ok, expected, actual)

    # ---- Gather ALL queries concurrently ----
    personal_containers = topo.personal_containers()
    relay_containers = topo.relay_containers()
    bootnode_containers = topo.bootnode_containers()

    # Build a list of (container, query_name, sql) tuples
    queries = []
    for c in personal_containers:
        queries.append((c, "personal_count",
                        f"SELECT COUNT(*) FROM items WHERE channel_id='{channel_id}' AND is_tombstone=0"))
        queries.append((c, "personal_total",
                        f"SELECT COUNT(*) FROM items WHERE channel_id='{channel_id}'"))
        queries.append((c, "personal_unique",
                        f"SELECT COUNT(DISTINCT item_id) FROM items WHERE channel_id='{channel_id}'"))
    for c in relay_containers:
        queries.append((c, "relay_count",
                        "SELECT COUNT(*) FROM items WHERE is_tombstone=0"))
    for c in bootnode_containers:
        queries.append((c, "bootnode_count",
                        "SELECT COUNT(*) FROM items"))

    def _run_query(item):
        container, query_name, sql = item
        result_str = db_query(container, sql)
        try:
            val = int(result_str)
        except (ValueError, TypeError):
            val = 0
        return container, query_name, val

    workers = min(MAX_WORKERS, len(queries))
    query_results = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_run_query, q): q for q in queries}
        for f in as_completed(futures):
            container, query_name, val = f.result()
            query_results[(container, query_name)] = val

    # ---- Run assertions on main thread ----

    # Personal nodes: item count
    for container in personal_containers:
        count = query_results.get((container, "personal_count"), 0)
        assert_check(f"{container} has {expected_items} items",
                     count == expected_items, expected_items, count)

    # Personal nodes: no duplicates
    for container in personal_containers:
        total = query_results.get((container, "personal_total"), 0)
        unique = query_results.get((container, "personal_unique"), 0)
        assert_check(f"{container} no duplicates", total == unique, 0, total - unique)

    # Relay nodes: should have all items
    for container in relay_containers:
        count = query_results.get((container, "relay_count"), 0)
        assert_check(f"{container} has >= {expected_items} stored items",
                     count >= expected_items, expected_items, count)

    # Bootnodes: zero items
    for container in bootnode_containers:
        count = query_results.get((container, "bootnode_count"), 0)
        assert_check(f"{container} stores zero items", count == 0, 0, count)

    # S3-specific: local channel isolation + HKDF verification
    if isinstance(topo, S3Topology):
        # Check HKDF verification in lead logs
        for i in range(topo.leads):
            container = topo.lead_containers()[i]
            result = run(f"docker logs {container} 2>&1", check=False, timeout=15)
            logs = result.stdout if result.returncode == 0 else ""
            hkdf_count = logs.count("verified swarm child via HKDF")
            assert_check(
                f"lead-{i} verified {topo.swarm_per_lead} swarm children via HKDF",
                hkdf_count >= topo.swarm_per_lead,
                topo.swarm_per_lead, hkdf_count,
            )

        # Relay isolation: relays should not have local-scope items
        for container in relay_containers:
            count_str = db_query(
                container,
                "SELECT COUNT(*) FROM items WHERE channel_id LIKE 'cordelia:local:%'",
            )
            try:
                count = int(count_str) if count_str else 0
            except ValueError:
                count = 0
            assert_check(f"{container} has no local-scope items", count == 0, 0, count)

    total = passed + failed
    db.event("assertions", "phase_end", detail=json.dumps({
        "passed": passed, "failed": failed, "total": total,
    }))

    print(f"\n{'=' * 40}")
    print(f"Results: {passed} passed, {failed} failed, {total} total")
    print(f"{'=' * 40}")

    return failed == 0


def teardown(topo, db: MetricsDB, log_dir: Path):
    """Collect logs and tear down containers."""
    db.event("teardown", "phase_start")

    log_dir.mkdir(parents=True, exist_ok=True)
    compose_file = topo.compose_file()
    project = topo.compose_project()

    # Collect logs concurrently
    all_containers = topo.all_containers()

    def _collect_log(container):
        log_file = log_dir / f"{container}.log"
        run(f"docker logs {container} > {log_file} 2>&1", check=False, timeout=60)
        return container

    workers = min(MAX_WORKERS, len(all_containers))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_collect_log, c): c for c in all_containers}
        for f in as_completed(futures):
            f.result()  # propagate exceptions

    print("\nTearing down...")
    teardown_timeout = max(120, topo.container_count)
    run(f"docker compose -p {project} -f {compose_file} down -v --remove-orphans",
        check=False, timeout=teardown_timeout)
    db.event("teardown", "phase_end")


# -- Run a single scenario ----------------------------------------------------

def run_scenario(scenario_path: Path, db_path: str = None,
                 no_teardown: bool = False, clean: bool = False) -> bool:
    """Run a single scenario. Returns True if all assertions pass."""
    with open(scenario_path, "rb") as f:
        cfg = tomllib.load(f)

    _token_cache.clear()

    topo = make_topology(cfg)
    collection = cfg.get("collection", {})

    # Clean BEFORE creating db (cleanup deletes logs dir)
    if clean:
        docker_cleanup()

    run_id = str(uuid.uuid4())[:8]
    if not db_path:
        log_dir = E2E_DIR / "logs" / topo.name
        log_dir.mkdir(parents=True, exist_ok=True)
        db_path = str(log_dir / f"{topo.name}-{run_id}.db")

    db = MetricsDB(db_path)
    db.init_run(run_id, str(scenario_path), cfg)

    print(f"\nRun: {run_id}")
    print(f"Scenario: {scenario_path.name}")
    print(f"Database: {db_path}")
    print(f"Topology: {topo.topo_type} | {topo.container_count} containers")

    if False:  # cleanup already done above
        docker_cleanup()

    ok = True
    try:
        if not phase_startup(topo, cfg, db):
            ok = False

        if ok:
            # Mesh or connectivity phase
            ok = phase_mesh(topo, cfg, db, collection)
            if ok:
                ok = phase_connectivity(topo, cfg, db, collection)

        if ok:
            channel_id, psk = phase_subscribe(topo, cfg, db)

            # Regular publish
            expected = phase_publish(topo, cfg, db, channel_id, psk)

            # Stress publish (additive)
            stress_count = phase_stress_publish(topo, cfg, db, channel_id, psk, collection)
            expected += stress_count

            ok = phase_delivery(topo, cfg, db, expected, channel_id, collection)
            all_passed = phase_assertions(topo, cfg, db, expected, channel_id)
            ok = ok and all_passed

    except KeyboardInterrupt:
        print("\nInterrupted")
        ok = False
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        db.event("error", "exception", detail=str(e))
        ok = False

    db.finish_run(run_id, "pass" if ok else "fail")

    if not no_teardown:
        log_dir = E2E_DIR / "logs" / topo.name
        teardown(topo, db, log_dir)

    db.close()
    print(f"\nResults database: {db_path}")
    return ok


# -- Main ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Cordelia E2E test orchestrator")
    parser.add_argument("scenarios", nargs="+", help="TOML scenario file(s)")
    parser.add_argument("--no-teardown", action="store_true", help="Keep containers running")
    parser.add_argument("--db", help="SQLite database path (single scenario only)")
    parser.add_argument("--clean", action="store_true",
                        help="Docker cleanup before each scenario")
    args = parser.parse_args()

    results = {}
    for scenario_arg in args.scenarios:
        scenario_path = Path(scenario_arg)
        if not scenario_path.is_absolute() and not scenario_path.exists():
            # Try relative to harness dir (e.g. "scenarios/s2-r20.toml")
            scenario_path = SCRIPT_DIR / scenario_path

        if not scenario_path.exists():
            print(f"Scenario not found: {scenario_path}")
            results[scenario_arg] = False
            continue

        print(f"\n{'=' * 60}")
        print(f"SCENARIO: {scenario_path.name}")
        print(f"{'=' * 60}")

        ok = run_scenario(
            scenario_path,
            db_path=args.db if len(args.scenarios) == 1 else None,
            no_teardown=args.no_teardown,
            clean=args.clean or len(args.scenarios) > 1,
        )
        results[scenario_path.name] = ok

    # Batch summary
    if len(results) > 1:
        print(f"\n{'=' * 60}")
        print("BATCH SUMMARY")
        print(f"{'=' * 60}")
        for name, ok in results.items():
            status = "PASS" if ok else "FAIL"
            print(f"  {status}: {name}")
        total_pass = sum(1 for ok in results.values() if ok)
        total = len(results)
        print(f"\n  {total_pass}/{total} scenarios passed")

    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
