#!/usr/bin/env python3
"""
Cordelia E2E test orchestrator.

Replaces bash run-s2.sh / run-s3.sh with a parameterized, observable harness.
Reads TOML scenario specs, drives Docker Compose topologies, polls node metrics
into SQLite, and runs assertions as queries.

Usage:
    python3 orchestrator.py scenarios/s2-r20.toml [--no-teardown] [--db results.db]
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
from datetime import datetime, timezone
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────

DB_PATH_IN_CONTAINER = "/data/cordelia/cordelia.db"
TOKEN_PATH_IN_CONTAINER = "/data/cordelia/node-token"
API_PORT = 9473

SCRIPT_DIR = Path(__file__).parent.resolve()
E2E_DIR = SCRIPT_DIR.parent
SCALE_DIR = E2E_DIR / "scale"
SCHEMA_PATH = SCRIPT_DIR / "schema.sql"


# ── Helpers ──────────────────────────────────────────────────────────

def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def channel_id_for(name: str) -> str:
    """Derive channel_id from name (channels-api.md §3.1)."""
    payload = f"cordelia:channel:{name.lower()}"
    return hashlib.sha256(payload.encode()).hexdigest()


def run(cmd: str, check=True, capture=True, timeout=60) -> subprocess.CompletedProcess:
    """Run a shell command, return CompletedProcess."""
    return subprocess.run(
        cmd, shell=True, check=check, timeout=timeout,
        capture_output=capture, text=True,
    )


def docker_exec(container: str, cmd: str, timeout=10) -> str:
    """Run a command inside a Docker container, return stdout."""
    full = f"docker exec {shlex.quote(container)} {cmd}"
    result = run(full, check=False, timeout=timeout)
    return result.stdout.strip() if result.returncode == 0 else ""


def api_get(container: str, endpoint: str) -> dict:
    """GET a node's REST API endpoint, return parsed JSON."""
    token = docker_exec(container, f"cat {TOKEN_PATH_IN_CONTAINER}")
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
    token = docker_exec(container, f"cat {TOKEN_PATH_IN_CONTAINER}")
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


# ── Database ─────────────────────────────────────────────────────────

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


# ── Topology ─────────────────────────────────────────────────────────

class Topology:
    """Knows the node names, roles, and container prefixes for a scenario."""

    def __init__(self, cfg: dict):
        topo = cfg["topology"]
        self.name = topo["name"]
        self.relays = topo["relays"]
        self.ppz = topo.get("personal_per_zone", 1)
        self.bootnodes = topo.get("bootnodes", 2)
        self.personal = self.relays * self.ppz
        self.container_count = self.bootnodes + self.relays + self.personal
        self.prefix = self.name

    def relay_containers(self) -> list[str]:
        return [f"{self.prefix}-r{i}" for i in range(1, self.relays + 1)]

    def personal_containers(self) -> list[str]:
        return [f"{self.prefix}-p{i}" for i in range(1, self.personal + 1)]

    def bootnode_containers(self) -> list[str]:
        return [f"{self.prefix}-b{i}" for i in range(1, self.bootnodes + 1)]

    def all_containers(self) -> list[str]:
        return self.bootnode_containers() + self.relay_containers() + self.personal_containers()

    def role_of(self, container: str) -> str:
        if "-r" in container.split("-")[-1][0:1] or container.endswith(tuple(f"-r{i}" for i in range(1, 200))):
            return "relay"
        if "-b" in container:
            return "bootnode"
        return "personal"

    def role_of_container(self, container: str) -> str:
        """Determine role from container name suffix."""
        # e.g. s2-20-r1 -> relay, s2-20-p3 -> personal, s2-20-b1 -> bootnode
        suffix = container.split("-")[-1]
        if suffix.startswith("r"):
            return "relay"
        elif suffix.startswith("b"):
            return "bootnode"
        else:
            return "personal"


# ── Phases ───────────────────────────────────────────────────────────

def poll_metrics(db: MetricsDB, topo: Topology, phase: str, metrics: list[str]):
    """Poll all nodes once, write observations."""
    for container in topo.relay_containers() + topo.personal_containers():
        role = topo.role_of_container(container)
        status = api_get(container, "status")

        for metric in metrics:
            if metric == "items_stored":
                val = db_query(container, "SELECT COUNT(*) FROM items WHERE is_tombstone=0")
                try:
                    db.observe(phase, container, role, metric, float(val))
                except (ValueError, TypeError):
                    pass
            elif metric in status:
                try:
                    db.observe(phase, container, role, metric, float(status[metric]))
                except (ValueError, TypeError):
                    pass
    db.flush()


def phase_startup(topo: Topology, cfg: dict, db: MetricsDB):
    """Generate topology, compose up, wait for healthy."""
    db.event("startup", "phase_start")
    print(f"\nPhase 0: Starting {topo.container_count} containers...")

    gov = cfg.get("governor", {})
    relay_hot_max = gov.get("relay_hot_max", topo.relays + 5)

    # Generate topology using existing script
    compose_dir = SCALE_DIR / f"s2-{topo.relays}"
    compose_file = compose_dir / f"s2-{topo.relays}.yml"

    if not compose_file.exists():
        env = os.environ.copy()
        env["RELAY_HOT_MAX_OVERRIDE"] = str(relay_hot_max)
        subprocess.run(
            f"bash {SCALE_DIR}/generate-s2.sh {topo.relays} {topo.ppz}",
            shell=True, check=True, env=env, capture_output=True,
            timeout=30,
        )

    # If hot_max override is needed, patch the generated configs
    if relay_hot_max != topo.relays + 5:
        config_dir = compose_dir / "configs"
        for cfg_file in config_dir.glob("*.toml"):
            text = cfg_file.read_text()
            default = f"hot_max = {topo.relays + 5}"
            if default in text:
                text = text.replace(default, f"hot_max = {relay_hot_max}")
                cfg_file.write_text(text)
        print(f"  Patched relay hot_max to {relay_hot_max}")

    # Compose up
    project = f"{topo.prefix}-mesh"
    run(f"docker compose -p {project} -f {compose_file} up -d",
        timeout=120)

    # Wait healthy
    start = time.time()
    for container in topo.all_containers():
        while time.time() - start < 120:
            status = api_get(container, "status")
            if status.get("status") == "running":
                break
            time.sleep(1)
        else:
            print(f"  TIMEOUT: {container} not healthy after 120s")
            db.event("startup", "timeout", container)
            return False

    elapsed = int(time.time() - start)
    print(f"  All {topo.container_count} containers healthy ({elapsed}s)")
    db.event("startup", "phase_end", detail=json.dumps({"elapsed_secs": elapsed}))
    return True


def phase_mesh(topo: Topology, cfg: dict, db: MetricsDB, collection: dict):
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

    while time.time() - start < timeout:
        poll_metrics(db, topo, "mesh", metrics)

        meshed = 0
        for container in topo.relay_containers():
            status = api_get(container, "status")
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


def phase_subscribe(topo: Topology, cfg: dict, db: MetricsDB):
    """Subscribe all personal nodes to the test channel."""
    channel_name = cfg["experiment"]["channel_name"]
    channel_id = channel_id_for(channel_name)

    db.event("subscribe", "phase_start")
    print(f"\nPhase 2: Subscribing {topo.personal} personal nodes...")

    # Generate PSK key material
    key_dir = SCALE_DIR / "keys"
    key_dir.mkdir(exist_ok=True)
    psk_file = key_dir / f"{channel_id}.psk"
    if not psk_file.exists():
        psk = os.urandom(32).hex()
        psk_file.write_text(psk)
    psk = psk_file.read_text().strip()

    for container in topo.personal_containers():
        # Subscribe
        api_post(container, "channels/subscribe", {
            "channel_name": channel_name,
            "channel_id": channel_id,
            "psk": psk,
            "delivery_mode": "realtime",
            "scope": "network",
        })
        db.event("subscribe", "subscribe", container)

    time.sleep(5)  # Propagation time
    db.event("subscribe", "phase_end")
    print(f"  Subscribed, waited 5s for propagation")
    return channel_id, psk


def phase_publish(topo: Topology, cfg: dict, db: MetricsDB,
                  channel_id: str, psk: str):
    """Publish items from designated publishers."""
    phases = cfg["experiment"]["phases"]
    pub_cfg = next((p for p in phases if p["type"] == "publish"), None)
    if not pub_cfg:
        return 0

    publishers = pub_cfg["publishers"]
    items_per = pub_cfg.get("items_per_publisher", 3)
    item_size = pub_cfg.get("item_size_bytes", 256)

    db.event("publish", "phase_start", detail=json.dumps({
        "publishers": publishers, "items_per": items_per,
    }))
    print(f"\nPhase 3: Publishing {items_per} items from {len(publishers)} publishers...")

    prefix = topo.prefix
    total = 0
    for pub_name in publishers:
        container = f"{prefix}-{pub_name}"
        for i in range(items_per):
            # Create deterministic item content
            content = os.urandom(item_size).hex()
            result = api_post(container, "channels/publish", {
                "channel_id": channel_id,
                "item_type": "message",
                "content": content,
            })
            if result:
                total += 1
                db.event("publish", "publish", container, json.dumps({
                    "item_id": result.get("item_id", ""),
                    "seq": i,
                }))

    db.event("publish", "phase_end", detail=json.dumps({"total_published": total}))
    print(f"  Published {total} items")
    return total


def phase_delivery(topo: Topology, cfg: dict, db: MetricsDB,
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
        targets = topo.all_containers()

    required = int(len(targets) * target_frac)

    db.event("delivery", "phase_start", detail=json.dumps({
        "target_items": target_items, "target_count": len(targets),
        "required": required, "timeout": timeout,
    }))
    print(f"\nPhase 4: Waiting for delivery ({target_items} items to {len(targets)} nodes)...")

    start = time.time()
    while time.time() - start < timeout:
        poll_metrics(db, topo, "delivery", metrics)

        done = 0
        relay_counts = []
        for container in targets:
            count_str = db_query(
                container,
                f"SELECT COUNT(*) FROM items WHERE channel_id='{channel_id}' AND is_tombstone=0",
            )
            try:
                count = int(count_str)
            except (ValueError, TypeError):
                count = 0
            if count >= target_items:
                done += 1

        # Also check relays
        for container in topo.relay_containers():
            count_str = db_query(
                container,
                "SELECT COUNT(*) FROM items WHERE is_tombstone=0",
            )
            try:
                relay_counts.append(int(count_str))
            except (ValueError, TypeError):
                relay_counts.append(0)

        relay_full = sum(1 for c in relay_counts if c >= target_items)
        elapsed = int(time.time() - start)
        print(
            f"  tick {elapsed}s: {done}/{len(targets)} personal done"
            f" | relays: {relay_full}/{topo.relays} full,"
            f" min={min(relay_counts, default=0)}"
            f" avg={sum(relay_counts) // max(len(relay_counts), 1)}"
            f" max={max(relay_counts, default=0)} of {target_items}"
        )

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


def phase_assertions(topo: Topology, cfg: dict, db: MetricsDB,
                     expected_items: int, channel_id: str):
    """Run final assertions and record results."""
    db.event("assertions", "phase_start")
    print(f"\nPhase 5: Assertions")

    passed = 0
    failed = 0

    # Personal nodes: exact item count
    for container in topo.personal_containers():
        count_str = db_query(
            container,
            f"SELECT COUNT(*) FROM items WHERE channel_id='{channel_id}' AND is_tombstone=0",
        )
        try:
            count = int(count_str)
        except (ValueError, TypeError):
            count = 0

        ok = count == expected_items
        label = container.split("-")[-1]  # e.g. p1
        if ok:
            print(f"  PASS: {container} has {count} items")
            passed += 1
        else:
            print(f"  FAIL: {container} has {count} items (expected {expected_items})")
            failed += 1
        db.assertion(f"{label}_item_count", ok, expected_items, count)

    # Personal nodes: no duplicates
    for container in topo.personal_containers():
        total_str = db_query(
            container,
            f"SELECT COUNT(*) FROM items WHERE channel_id='{channel_id}'",
        )
        unique_str = db_query(
            container,
            f"SELECT COUNT(DISTINCT item_id) FROM items WHERE channel_id='{channel_id}'",
        )
        try:
            total, unique = int(total_str), int(unique_str)
        except (ValueError, TypeError):
            total, unique = 0, 0

        ok = total == unique
        label = container.split("-")[-1]
        if ok:
            print(f"  PASS: {label} has no duplicate items")
            passed += 1
        else:
            print(f"  FAIL: {label} has {total - unique} duplicate items")
            failed += 1
        db.assertion(f"{label}_no_duplicates", ok, 0, total - unique)

    # Relay nodes: should have all items
    for container in topo.relay_containers():
        count_str = db_query(
            container,
            "SELECT COUNT(*) FROM items WHERE is_tombstone=0",
        )
        try:
            count = int(count_str)
        except (ValueError, TypeError):
            count = 0

        ok = count >= expected_items
        label = container.split("-")[-1]
        if ok:
            print(f"  PASS: {container} has {count} stored items (>= {expected_items})")
            passed += 1
        else:
            print(f"  FAIL: {container} has {count} stored items (expected >= {expected_items})")
            failed += 1
        db.assertion(f"{label}_relay_items", ok, expected_items, count)

    # Bootnodes: zero items
    for container in topo.bootnode_containers():
        count_str = db_query(container, "SELECT COUNT(*) FROM items")
        try:
            count = int(count_str)
        except (ValueError, TypeError):
            count = 0

        ok = count == 0
        label = container.split("-")[-1]
        if ok:
            print(f"  PASS: {container} stores zero items")
            passed += 1
        else:
            print(f"  FAIL: {container} has {count} items (expected 0)")
            failed += 1
        db.assertion(f"{label}_zero_items", ok, 0, count)

    total = passed + failed
    db.event("assertions", "phase_end", detail=json.dumps({
        "passed": passed, "failed": failed, "total": total,
    }))

    print(f"\n{'=' * 40}")
    print(f"Results: {passed} passed, {failed} failed, {total} total")
    print(f"{'=' * 40}")

    return failed == 0


def teardown(topo: Topology, db: MetricsDB, log_dir: Path):
    """Collect logs and tear down containers."""
    db.event("teardown", "phase_start")

    # Collect logs
    log_dir.mkdir(parents=True, exist_ok=True)
    compose_dir = SCALE_DIR / f"s2-{topo.relays}"
    compose_file = compose_dir / f"s2-{topo.relays}.yml"
    project = f"{topo.prefix}-mesh"

    for container in topo.all_containers():
        log_file = log_dir / f"{container}.log"
        run(f"docker logs {container} > {log_file} 2>&1", check=False, timeout=30)

    print("\nTearing down...")
    run(f"docker compose -p {project} -f {compose_file} down -v --remove-orphans",
        check=False, timeout=60)
    db.event("teardown", "phase_end")


# ── Main ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Cordelia E2E test orchestrator")
    parser.add_argument("scenario", help="Path to TOML scenario file")
    parser.add_argument("--no-teardown", action="store_true", help="Keep containers running")
    parser.add_argument("--db", help="SQLite database path (default: auto-named)")
    args = parser.parse_args()

    # Load scenario
    scenario_path = Path(args.scenario)
    if not scenario_path.is_absolute():
        scenario_path = SCRIPT_DIR / scenario_path
    with open(scenario_path, "rb") as f:
        cfg = tomllib.load(f)

    topo = Topology(cfg)
    collection = cfg.get("collection", {})

    # Database
    run_id = str(uuid.uuid4())[:8]
    if args.db:
        db_path = args.db
    else:
        log_dir = E2E_DIR / "logs" / topo.name
        log_dir.mkdir(parents=True, exist_ok=True)
        db_path = str(log_dir / f"{topo.name}-{run_id}.db")

    db = MetricsDB(db_path)
    db.init_run(run_id, str(scenario_path), cfg)

    print(f"Run: {run_id}")
    print(f"Scenario: {scenario_path.name}")
    print(f"Database: {db_path}")
    print(f"Topology: {topo.bootnodes}B + {topo.relays}R + {topo.personal}P = {topo.container_count}")

    # Run phases
    ok = True
    try:
        if not phase_startup(topo, cfg, db):
            ok = False

        if ok:
            ok = phase_mesh(topo, cfg, db, collection)

        if ok:
            channel_id, psk = phase_subscribe(topo, cfg, db)
            expected = phase_publish(topo, cfg, db, channel_id, psk)
            ok = phase_delivery(topo, cfg, db, expected, channel_id, collection)
            phase_assertions(topo, cfg, db, expected, channel_id)

    except KeyboardInterrupt:
        print("\nInterrupted")
        ok = False
    except Exception as e:
        print(f"\nError: {e}")
        db.event("error", "exception", detail=str(e))
        ok = False

    db.finish_run(run_id, "pass" if ok else "fail")

    if not args.no_teardown:
        log_dir = E2E_DIR / "logs" / topo.name
        teardown(topo, db, log_dir)

    db.close()

    print(f"\nResults database: {db_path}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
