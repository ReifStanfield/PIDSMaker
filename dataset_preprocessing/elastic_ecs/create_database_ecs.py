"""Elastic Defend (ECS) NDJSON -> PIDSMaker Postgres database.

Converts Elastic Defend endpoint events into the 4-table schema that every
PIDSMaker dataset uses (event_table, subject_node_table, file_node_table,
netflow_node_table), following the conventions of
dataset_preprocessing/darpa_tc/create_database_e3.py:

- hash_id   = sha256 hex digest of node_uuid (the DARPA script's `stringtomd5`
              actually uses sha256; we match the code, not the function name).
- index_id  = one integer space shared by all node tables, assigned netflow
              first, then subjects, then files (same order as the DARPA script).
- operation = DARPA TC event names (EVENT_READ, EVENT_WRITE, ...) restricted to
              the 10 types of `rel2id_darpa_tc`, so num_edge_types stays 10.
- direction = subject -> object, except operations in `edge_reversed`
              (EVENT_READ, EVENT_OPEN, EVENT_EXECUTE, EVENT_RECVFROM, ...), which
              are stored object -> subject.
- timestamp_rec = nanoseconds since the Unix epoch (UTC), like timestampNanos.

Usage:
    python create_database_ecs.py --input <dir> --database ortsoc_dev \
        [--host 127.0.0.1 --port 8888 --user postgres --password postgres] [--reset]

This module has no PIDSMaker imports so it runs in a small venv
(psycopg2-binary only).
"""

import argparse
import calendar
import hashlib
import json
import os
import re
import sys
from collections import Counter, OrderedDict

# ---------------------------------------------------------------------------
# PIDSMaker conventions (copied from pidsmaker/utils/dataset_utils.py so this
# script does not need torch / the pidsmaker package).
# ---------------------------------------------------------------------------

# rel2id_darpa_tc: the only operations PIDSMaker keeps when building graphs
# for DARPA-TC-schema datasets (build_default_graphs filters on it).
DARPA_TC_OPERATIONS = (
    "EVENT_CONNECT",
    "EVENT_EXECUTE",
    "EVENT_OPEN",
    "EVENT_READ",
    "EVENT_RECVFROM",
    "EVENT_RECVMSG",
    "EVENT_SENDMSG",
    "EVENT_SENDTO",
    "EVENT_WRITE",
    "EVENT_CLONE",
)

# edge_reversed: stored object -> subject.
EDGE_REVERSED = {
    "EVENT_EXECUTE",
    "EVENT_LSEEK",
    "EVENT_MMAP",
    "EVENT_OPEN",
    "EVENT_ACCEPT",
    "EVENT_READ",
    "EVENT_RECVFROM",
    "EVENT_RECVMSG",
    "EVENT_READ_SOCKET_PARAMS",
    "EVENT_CHECK_FILE_ATTRIBUTES",
    "READ",
}

# Databases created by postgres/init-create-databases.sh. The converter refuses
# to write to any of them.
PROTECTED_DATABASES = {
    "postgres",
    "template0",
    "template1",
    "clearscope_e3",
    "cadets_e3",
    "theia_e3",
    "clearscope_e5",
    "cadets_e5",
    "theia_e5",
    "optc_051",
    "optc_501",
    "optc_201",
    "fivedirections_e3",
    "fivedirections_e5",
    "trace_e3",
    "trace_e5",
    "atlasv2_edr",
    "carbanakv2_edr",
}

# Same DDL as postgres/init-create-databases.sh (with IF NOT EXISTS).
DDL = """
CREATE TABLE IF NOT EXISTS event_table (
    src_node VARCHAR,
    src_index_id VARCHAR,
    operation VARCHAR,
    dst_node VARCHAR,
    dst_index_id VARCHAR,
    event_uuid VARCHAR NOT NULL,
    timestamp_rec BIGINT,
    _id SERIAL PRIMARY KEY
);
ALTER TABLE event_table OWNER TO postgres;
CREATE UNIQUE INDEX IF NOT EXISTS event_table__id_uindex ON event_table (_id);
GRANT DELETE, INSERT, REFERENCES, SELECT, TRIGGER, TRUNCATE, UPDATE ON event_table TO postgres;

CREATE TABLE IF NOT EXISTS file_node_table (
    node_uuid VARCHAR NOT NULL,
    hash_id VARCHAR NOT NULL,
    path VARCHAR,
    index_id BIGINT,
    PRIMARY KEY (node_uuid, hash_id)
);
ALTER TABLE file_node_table OWNER TO postgres;

CREATE TABLE IF NOT EXISTS netflow_node_table (
    node_uuid VARCHAR NOT NULL,
    hash_id VARCHAR NOT NULL,
    src_addr VARCHAR,
    src_port VARCHAR,
    dst_addr VARCHAR,
    dst_port VARCHAR,
    index_id BIGINT,
    PRIMARY KEY (node_uuid, hash_id)
);
ALTER TABLE netflow_node_table OWNER TO postgres;

CREATE TABLE IF NOT EXISTS subject_node_table (
    node_uuid VARCHAR,
    hash_id VARCHAR,
    path VARCHAR,
    cmd VARCHAR,
    index_id BIGINT,
    PRIMARY KEY (node_uuid, hash_id)
);
ALTER TABLE subject_node_table OWNER TO postgres;
"""

TABLES = ("event_table", "subject_node_table", "file_node_table", "netflow_node_table")

# ---------------------------------------------------------------------------
# Operation mapping. Key: (event.category, event.action). Value: DARPA TC
# operation, or None to drop. See README.md for the rationale per row.
# ---------------------------------------------------------------------------

FILE_ACTION_MAP = {
    "creation": "EVENT_WRITE",  # approximate: TC EVENT_CREATE_OBJECT is not in rel2id
    "modification": "EVENT_WRITE",
    "overwrite": "EVENT_WRITE",
    "write": "EVENT_WRITE",
    "open": "EVENT_OPEN",
    "read": "EVENT_READ",
    "access": "EVENT_READ",
    "deletion": None,  # TC EVENT_UNLINK not in rel2id
    "rename": None,  # TC EVENT_RENAME not in rel2id
    "attributes_modified": None,  # TC EVENT_MODIFY_FILE_ATTRIBUTES not in rel2id
    "extended_attributes_delete": None,
    "mount": None,
}

NETWORK_ACTION_MAP = {
    "connection_attempted": "EVENT_CONNECT",
    "connection_accepted": "EVENT_RECVFROM",  # approximate: TC EVENT_ACCEPT not in rel2id
    "disconnect_received": None,
    "connection_closed": None,
    "lookup_requested": None,  # DNS: no socket-level match
    "lookup_result": None,
    "http_request": None,
}

PROCESS_START_ACTIONS = {"exec", "fork", "start", "process_started", "executed"}
PROCESS_DROP_ACTIONS = {"end", "exit", "process_stopped", "already_running"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sha256_hex(s):
    """hash_id convention of create_database_e3.py (its `stringtomd5` uses sha256)."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def get_field(doc, dotted, default=None):
    """Read an ECS field from a document that may use nested objects, dotted
    keys ("process.entity_id": ...), or a mix of both."""
    if not isinstance(doc, dict):
        return default
    if dotted in doc:
        return doc[dotted]
    parts = dotted.split(".")
    for i in range(1, len(parts)):
        head = ".".join(parts[:i])
        if head in doc and isinstance(doc[head], dict):
            val = get_field(doc[head], ".".join(parts[i:]), None)
            if val is not None:
                return val
    return default


def first_str(value):
    """ECS allows some fields to be arrays; take the first element."""
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    value = str(value)
    return value if value != "" else None


_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$"
)


def parse_timestamp_ns(value):
    """ISO 8601 / RFC 3339 -> integer nanoseconds since the Unix epoch (UTC).

    Keeps up to 9 fractional digits (Elastic `date_nanos`), and does not rely on
    Python 3.11+ datetime.fromisoformat. A timestamp without an offset is treated
    as UTC (Elasticsearch stores @timestamp in UTC). Numeric values are treated as
    epoch milliseconds (Elasticsearch `date` default). Returns None if unparseable.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(round(value * 1_000_000))
    m = _TS_RE.match(str(value).strip())
    if not m:
        return None
    year, month, day, hh, mm, ss, frac, tz = m.groups()
    try:
        secs = calendar.timegm(
            (int(year), int(month), int(day), int(hh), int(mm), int(ss), 0, 0, 0)
        )
        # timegm normalises out-of-range values silently; reject them instead.
        if not (1 <= int(month) <= 12 and 1 <= int(day) <= 31 and int(hh) < 24 and int(mm) < 60 and int(ss) < 61):
            return None
    except (ValueError, OverflowError):
        return None
    frac_ns = int((frac or "0")[:9].ljust(9, "0"))
    offset = 0
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        offset = sign * (int(digits[:2]) * 3600 + int(digits[2:4]) * 60)
    return (secs - offset) * 1_000_000_000 + frac_ns


def host_key(doc):
    for f in ("host.id", "host.hostname", "host.name", "agent.id"):
        v = first_str(get_field(doc, f))
        if v:
            return v
    return None


def process_identity(doc, prefix, host):
    """Return (node_uuid, source) for `process` or `process.parent`, or (None, None).

    source is "entity_id" or "fallback".
    """
    entity_id = first_str(get_field(doc, f"{prefix}.entity_id"))
    if entity_id:
        return entity_id, "entity_id"
    pid = first_str(get_field(doc, f"{prefix}.pid"))
    if pid is None:
        return None, None
    exe = first_str(get_field(doc, f"{prefix}.executable")) or first_str(
        get_field(doc, f"{prefix}.name")
    )
    start = first_str(get_field(doc, f"{prefix}.start"))
    return f"{host}|{exe or ''}|{pid}|{start or ''}", "fallback"


def process_attrs(doc, prefix):
    path = first_str(get_field(doc, f"{prefix}.executable"))
    cmd = first_str(get_field(doc, f"{prefix}.command_line")) or first_str(
        get_field(doc, f"{prefix}.name")
    )
    return path, cmd


def iter_documents(input_dir):
    """Yield (source_doc, hit_id) or (None, None) for malformed lines.

    Accepts bare ECS documents and Elasticsearch search hits ({"_id", "_source"}).
    Reads every *.ndjson / *.json / *.jsonl file in `input_dir`, sorted by name.
    """
    names = sorted(
        n for n in os.listdir(input_dir) if n.endswith((".ndjson", ".json", ".jsonl"))
    )
    for name in names:
        with open(os.path.join(input_dir, name), "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    yield None, None
                    continue
                if not isinstance(obj, dict):
                    yield None, None
                    continue
                if isinstance(obj.get("_source"), dict):
                    yield obj["_source"], first_str(obj.get("_id"))
                else:
                    yield obj, None


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------


class Converter:
    """Accumulates nodes and edges in memory, then assigns index_ids."""

    def __init__(self):
        # node_uuid -> attributes; insertion order = first appearance.
        self.subjects = OrderedDict()  # uuid -> [path, cmd]
        self.files = OrderedDict()  # uuid -> path
        self.netflows = OrderedDict()  # uuid -> [src_addr, src_port, dst_addr, dst_port]
        # edges: (src_kind, src_uuid, operation, dst_kind, dst_uuid, event_uuid, ts)
        self.edges = []
        self.stats = Counter()
        self.skipped = Counter()
        self.dropped_actions = Counter()
        self.process_id_source = Counter()
        self.seen_event_uuids = set()
        self._synthetic_counter = 0

    # -- node registration -------------------------------------------------
    def _add_subject(self, uuid, path, cmd):
        cur = self.subjects.get(uuid)
        if cur is None:
            self.subjects[uuid] = [path, cmd]
        else:  # fill fields that earlier events did not carry
            if cur[0] is None and path is not None:
                cur[0] = path
            if cur[1] is None and cmd is not None:
                cur[1] = cmd

    def _add_file(self, host, path):
        uuid = f"{host}|{path}"
        self.files.setdefault(uuid, path)
        return uuid

    def _add_netflow(self, host, transport, src_ip, src_port, dst_ip, dst_port):
        uuid = f"{host}|{transport or ''}|{dst_ip}:{dst_port or ''}"
        if uuid not in self.netflows:
            self.netflows[uuid] = [src_ip, src_port, dst_ip, dst_port]
        return uuid

    def _edge(self, operation, subj_uuid, obj_kind, obj_uuid, event_uuid, ts):
        """Add a subject/object edge using the DARPA direction convention."""
        assert operation in DARPA_TC_OPERATIONS, operation
        if operation in EDGE_REVERSED:
            self.edges.append((obj_kind, obj_uuid, operation, "subject", subj_uuid, event_uuid, ts))
        else:
            self.edges.append(("subject", subj_uuid, operation, obj_kind, obj_uuid, event_uuid, ts))
        self.stats[f"edges_{operation}"] += 1

    # -- per-document ------------------------------------------------------
    def add_document(self, doc, hit_id=None):
        self.stats["events_read"] += 1
        if doc is None:
            self.skipped["malformed_json"] += 1
            return

        ts = parse_timestamp_ns(get_field(doc, "@timestamp"))
        if ts is None:
            self.skipped["bad_timestamp"] += 1
            return

        category_raw = get_field(doc, "event.category")
        categories = category_raw if isinstance(category_raw, list) else [category_raw]
        categories = [c for c in categories if c]
        action = first_str(get_field(doc, "event.action"))
        types_raw = get_field(doc, "event.type")
        types = types_raw if isinstance(types_raw, list) else [types_raw]

        if "process" in categories:
            kind = "process"
        elif "file" in categories:
            kind = "file"
        elif "network" in categories:
            kind = "network"
        else:
            self.dropped_actions[(",".join(map(str, categories)) or "none", action)] += 1
            self.skipped["unmapped_category"] += 1
            return

        # Decide the operation(s) before resolving identities, so dropped
        # actions are counted as such and not as identity failures.
        if kind == "process":
            is_start = (action in PROCESS_START_ACTIONS) or ("start" in types and action not in PROCESS_DROP_ACTIONS)
            if not is_start:
                self.dropped_actions[("process", action)] += 1
                self.skipped["unmapped_action"] += 1
                return
        elif kind == "file":
            op = FILE_ACTION_MAP.get(action, "unknown")
            if op == "unknown":  # fall back on event.type
                if "creation" in types or "change" in types:
                    op = "EVENT_WRITE"
                elif "access" in types:
                    op = "EVENT_READ"
                else:
                    op = None
            if op is None:
                self.dropped_actions[("file", action)] += 1
                self.skipped["unmapped_action"] += 1
                return
        else:
            op = NETWORK_ACTION_MAP.get(action, "unknown")
            if op == "unknown":
                op = "EVENT_CONNECT" if ("connection" in types and "start" in types) else None
            if op is None:
                self.dropped_actions[("network", action)] += 1
                self.skipped["unmapped_action"] += 1
                return

        host = host_key(doc)
        if host is None:
            self.skipped["no_host"] += 1
            return

        subj_uuid, source = process_identity(doc, "process", host)
        if subj_uuid is None:
            self.skipped["no_process_identity"] += 1
            return

        # Validate the object before registering anything.
        if kind == "file":
            path = first_str(get_field(doc, "file.path"))
            if path is None:
                self.skipped["no_file_path"] += 1
                return
        elif kind == "network":
            dst_ip = first_str(get_field(doc, "destination.ip"))
            if dst_ip is None:
                self.skipped["no_destination_ip"] += 1
                return

        event_uuid = first_str(get_field(doc, "event.id")) or hit_id
        if event_uuid is None:
            self._synthetic_counter += 1
            event_uuid = f"synthetic-{self._synthetic_counter:012d}"
            self.stats["synthetic_event_uuid"] += 1
        elif event_uuid in self.seen_event_uuids:
            self.skipped["duplicate_event_uuid"] += 1
            return
        self.seen_event_uuids.add(event_uuid)

        self.process_id_source[source] += 1
        self._add_subject(subj_uuid, *process_attrs(doc, "process"))

        if kind == "process":
            parent_uuid, parent_source = process_identity(doc, "process.parent", host)
            if parent_uuid is None:
                self.stats["parent_edge_skipped_missing_parent"] += 1
            else:
                self.process_id_source[f"parent_{parent_source}"] += 1
                self._add_subject(parent_uuid, *process_attrs(doc, "process.parent"))
                # EVENT_CLONE is not reversed: parent -> child.
                self._edge("EVENT_CLONE", parent_uuid, "subject", subj_uuid, event_uuid, ts)
            exe = first_str(get_field(doc, "process.executable"))
            if exe and action != "fork":
                # exec: the image file is executed by the new process (file -> process).
                file_uuid = self._add_file(host, exe)
                self._edge("EVENT_EXECUTE", subj_uuid, "file", file_uuid, event_uuid, ts)
        elif kind == "file":
            file_uuid = self._add_file(host, path)
            self._edge(op, subj_uuid, "file", file_uuid, event_uuid, ts)
        else:
            net_uuid = self._add_netflow(
                host,
                first_str(get_field(doc, "network.transport")),
                first_str(get_field(doc, "source.ip")),
                first_str(get_field(doc, "source.port")),
                dst_ip,
                first_str(get_field(doc, "destination.port")),
            )
            self._edge(op, subj_uuid, "netflow", net_uuid, event_uuid, ts)
        self.stats["events_converted"] += 1

    # -- output ------------------------------------------------------------
    def build_rows(self):
        """Assign index_ids (netflow, subject, file; one shared space) and return
        rows ready for the 4 tables."""
        index = 0
        uuid_to_index = {}
        netflow_rows, subject_rows, file_rows = [], [], []
        for uuid, (sa, sp, da, dp) in self.netflows.items():
            netflow_rows.append([uuid, sha256_hex(uuid), sa, sp, da, dp, index])
            uuid_to_index[("netflow", uuid)] = index
            index += 1
        for uuid, (path, cmd) in self.subjects.items():
            subject_rows.append([uuid, sha256_hex(uuid), path, cmd, index])
            uuid_to_index[("subject", uuid)] = index
            index += 1
        for uuid, path in self.files.items():
            file_rows.append([uuid, sha256_hex(uuid), path, index])
            uuid_to_index[("file", uuid)] = index
            index += 1

        event_rows = []
        for src_kind, src_uuid, op, dst_kind, dst_uuid, event_uuid, ts in self.edges:
            event_rows.append(
                [
                    sha256_hex(src_uuid),
                    str(uuid_to_index[(src_kind, src_uuid)]),
                    op,
                    sha256_hex(dst_uuid),
                    str(uuid_to_index[(dst_kind, dst_uuid)]),
                    event_uuid,
                    ts,
                ]
            )
        return {
            "netflow_node_table": netflow_rows,
            "subject_node_table": subject_rows,
            "file_node_table": file_rows,
            "event_table": event_rows,
        }

    def summary(self):
        lines = []
        s = self.stats
        lines.append(f"events read:            {s['events_read']}")
        lines.append(f"events converted:       {s['events_converted']}")
        lines.append(f"edge rows written:      {len(self.edges)}")
        for k in sorted(k for k in s if k.startswith("edges_")):
            lines.append(f"  {k[6:]:<22}{s[k]}")
        lines.append(f"events skipped:         {sum(self.skipped.values())}")
        for k, v in sorted(self.skipped.items()):
            lines.append(f"  {k:<22}{v}")
        if self.dropped_actions:
            lines.append("dropped (category, action):")
            for (c, a), v in sorted(self.dropped_actions.items(), key=lambda kv: -kv[1]):
                lines.append(f"  {c}/{a}: {v}")
        lines.append(f"parent edges skipped (missing parent): {s['parent_edge_skipped_missing_parent']}")
        lines.append(f"synthetic event_uuids:  {s['synthetic_event_uuid']}")
        lines.append(
            f"nodes: subject={len(self.subjects)} file={len(self.files)} netflow={len(self.netflows)}"
        )
        ent, fb = self.process_id_source["entity_id"], self.process_id_source["fallback"]
        tot = ent + fb
        if tot:
            lines.append(
                f"process ids (event actor): entity_id={ent} ({100 * ent / tot:.1f}%) "
                f"fallback={fb} ({100 * fb / tot:.1f}%)"
            )
        return "\n".join(lines)


def convert_directory(input_dir):
    conv = Converter()
    for doc, hit_id in iter_documents(input_dir):
        conv.add_document(doc, hit_id)
    return conv


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


def check_database_name(database):
    if database.lower() in PROTECTED_DATABASES:
        raise SystemExit(f"Refusing to write to protected database '{database}'.")
    if not re.fullmatch(r"[a-z_][a-z0-9_]*", database):
        raise SystemExit(f"Invalid database name '{database}' (use lowercase letters, digits, _).")


def connect(database, host, port, user, password):
    import psycopg2

    return psycopg2.connect(database=database, host=host, port=port, user=user, password=password)


def ensure_database(database, host, port, user, password):
    check_database_name(database)
    conn = connect("postgres", host, port, user, password)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (database,))
        if cur.fetchone() is None:
            cur.execute(f'CREATE DATABASE "{database}"')
    conn.close()
    conn = connect(database, host, port, user, password)
    with conn.cursor() as cur:
        cur.execute(DDL)
    conn.commit()
    return conn


def table_counts(conn):
    with conn.cursor() as cur:
        out = {}
        for t in TABLES:
            cur.execute(f"SELECT count(*) FROM {t}")
            out[t] = cur.fetchone()[0]
        return out


def write_rows(conn, rows, reset=False):
    from psycopg2 import extras as ex

    counts = table_counts(conn)
    if any(counts.values()):
        if not reset:
            raise SystemExit(
                f"Database already contains data {counts}; re-run with --reset to replace it."
            )
        with conn.cursor() as cur:
            cur.execute("TRUNCATE " + ", ".join(TABLES) + " RESTART IDENTITY")
    with conn.cursor() as cur:
        ex.execute_values(cur, "INSERT INTO netflow_node_table VALUES %s", rows["netflow_node_table"], page_size=10000)
        ex.execute_values(cur, "INSERT INTO subject_node_table VALUES %s", rows["subject_node_table"], page_size=10000)
        ex.execute_values(cur, "INSERT INTO file_node_table VALUES %s", rows["file_node_table"], page_size=10000)
        ex.execute_values(
            cur,
            "INSERT INTO event_table (src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid, timestamp_rec) VALUES %s",
            rows["event_table"],
            page_size=50000,
        )
    conn.commit()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--input", required=True, help="Directory of .ndjson/.json files")
    p.add_argument("--database", required=True, help="Target database (created if absent)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default="8888")
    p.add_argument("--user", default="postgres")
    p.add_argument("--password", default="postgres")
    p.add_argument("--reset", action="store_true", help="Truncate the 4 tables first if they hold data")
    args = p.parse_args(argv)

    check_database_name(args.database)
    conv = convert_directory(args.input)
    rows = conv.build_rows()
    conn = ensure_database(args.database, args.host, args.port, args.user, args.password)
    write_rows(conn, rows, reset=args.reset)
    print(conv.summary())
    print("table rows:", table_counts(conn))
    conn.close()
    return conv


if __name__ == "__main__":
    main()
