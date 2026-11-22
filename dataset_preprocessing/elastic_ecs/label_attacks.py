"""Turn a planted-attack answer key into PIDSMaker node ground-truth files.

Answer key CSV columns:
    attack_name,host,start,end,root_process_entity_id
`start`/`end` are ISO 8601 timestamps with a timezone offset.

For each attack, the malicious node set is:
  1. the root process (subject_node_table.node_uuid == root_process_entity_id);
  2. every descendant process created within [start, end], following
     EVENT_CLONE parent -> child edges in event_table;
  3. every file and netflow node that any of those processes touched within
     [start, end] (any event between the process and the object, either direction).

Output: one CSV per attack at <out_dir>/node_<attack_name>.csv, in the format of
Ground_Truth/orthrus/E3-CADETS/node_*.csv:
    <node_uuid>,{'<type>': '<label>'},<index_id>
Label strings follow the DARPA ground truth files:
    subject: f"{path} {cmd}"          (CADETS: 'None nginx')
    file:    path                      (CADETS: '/tmp/main')
    netflow: f"{src_addr}:{src_port}->{dst_addr}:{dst_port}"

Also prints the `ground_truth_relative_path` and `attack_to_time_window`
entries for pidsmaker/config/config.py (times rendered in --timezone).

Usage:
    python label_attacks.py --answer-key attacks.csv --database ortsoc_dev \
        [--out-dir ../../Ground_Truth/orthrus/ORTSOC-DEV] [--timezone US/Pacific]
"""

import argparse
import csv
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from create_database_ecs import (  # noqa: E402
    check_database_name,
    connect,
    parse_timestamp_ns,
)

DEFAULT_OUT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "Ground_Truth", "orthrus", "ORTSOC-DEV"
)
GT_SUBDIR = "ORTSOC-DEV"


def read_answer_key(path):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    required = {"attack_name", "host", "start", "end", "root_process_entity_id"}
    for r in rows:
        missing = required - set(k for k, v in r.items() if v)
        if missing:
            raise SystemExit(f"Answer key row {r} is missing {sorted(missing)}")
    return rows


def load_nodes(cur):
    """index_id -> (type, node_uuid, label)."""
    nodes = {}
    cur.execute("SELECT index_id, node_uuid, path, cmd FROM subject_node_table")
    for idx, uuid, path, cmd in cur.fetchall():
        nodes[int(idx)] = ("subject", uuid, f"{path} {cmd}")
    cur.execute("SELECT index_id, node_uuid, path FROM file_node_table")
    for idx, uuid, path in cur.fetchall():
        nodes[int(idx)] = ("file", uuid, str(path))
    cur.execute("SELECT index_id, node_uuid, src_addr, src_port, dst_addr, dst_port FROM netflow_node_table")
    for idx, uuid, sa, sp, da, dp in cur.fetchall():
        nodes[int(idx)] = ("netflow", uuid, f"{sa}:{sp}->{da}:{dp}")
    return nodes


def label_attack(cur, nodes, root_uuid, start_ns, end_ns):
    """Return the sorted list of malicious index_ids for one attack."""
    cur.execute("SELECT index_id FROM subject_node_table WHERE node_uuid = %s", (root_uuid,))
    row = cur.fetchone()
    if row is None:
        raise SystemExit(f"Root process '{root_uuid}' not found in subject_node_table")
    root = int(row[0])

    cur.execute(
        "SELECT src_index_id, operation, dst_index_id FROM event_table "
        "WHERE timestamp_rec >= %s AND timestamp_rec <= %s",
        (start_ns, end_ns),
    )
    children = defaultdict(set)
    touched = defaultdict(set)  # process index -> object indexes
    for src, op, dst in cur.fetchall():
        src, dst = int(src), int(dst)
        if op == "EVENT_CLONE":
            children[src].add(dst)
            continue
        # Either direction (reads/opens/executes are stored object -> subject).
        if nodes.get(src, ("",))[0] == "subject" and nodes.get(dst, ("",))[0] in ("file", "netflow"):
            touched[src].add(dst)
        elif nodes.get(dst, ("",))[0] == "subject" and nodes.get(src, ("",))[0] in ("file", "netflow"):
            touched[dst].add(src)

    processes, stack = {root}, [root]
    while stack:
        for child in children[stack.pop()]:
            if child not in processes:
                processes.add(child)
                stack.append(child)

    malicious = set(processes)
    for p in processes:
        malicious |= touched[p]
    return sorted(malicious)


def write_ground_truth(path, nodes, index_ids):
    """Same layout as Ground_Truth/orthrus/E3-CADETS/node_*.csv: no header, '\\n' line
    endings, fields quoted only when a label contains a comma or quote."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        for idx in index_ids:
            ntype, uuid, label = nodes[idx]
            w.writerow([uuid, str({ntype: label}), idx])


def ns_to_local(ns, tz_name):
    """ns since epoch -> 'YYYY-MM-DD HH:MM:SS' wall-clock time in tz_name."""
    try:
        from zoneinfo import ZoneInfo  # Python 3.9+
    except ImportError:  # pragma: no cover
        raise SystemExit("Python 3.9+ is required for --timezone handling")
    dt = datetime(1970, 1, 1, tzinfo=ZoneInfo("UTC")) + timedelta(microseconds=ns // 1000)
    return dt.astimezone(ZoneInfo(tz_name)).strftime("%Y-%m-%d %H:%M:%S")


def run(answer_key, database, out_dir, timezone, host, port, user, password):
    check_database_name(database)
    conn = connect(database, host, port, user, password)
    cur = conn.cursor()
    nodes = load_nodes(cur)
    results = []
    for row in read_answer_key(answer_key):
        start_ns = parse_timestamp_ns(row["start"])
        end_ns = parse_timestamp_ns(row["end"])
        if start_ns is None or end_ns is None or end_ns < start_ns:
            raise SystemExit(f"Bad time window in answer key row {row}")
        ids = label_attack(cur, nodes, row["root_process_entity_id"], start_ns, end_ns)
        name = row["attack_name"]
        out_path = os.path.join(out_dir, f"node_{name}.csv")
        write_ground_truth(out_path, nodes, ids)
        by_type = defaultdict(int)
        for i in ids:
            by_type[nodes[i][0]] += 1
        results.append(
            {
                "attack_name": name,
                "path": out_path,
                "relative_path": f"{GT_SUBDIR}/node_{name}.csv",
                "index_ids": ids,
                "by_type": dict(by_type),
                # Minute-aligned window in the dataset timezone, widened to cover [start, end].
                "window": [
                    ns_to_local(start_ns - start_ns % 60_000_000_000, timezone),
                    ns_to_local(end_ns + (-end_ns) % 60_000_000_000, timezone),
                ],
            }
        )
    conn.close()
    return results


def main(argv=None):
    p = argparse.ArgumentParser(description="Label planted attacks for PIDSMaker.")
    p.add_argument("--answer-key", required=True)
    p.add_argument("--database", default="ortsoc_dev")
    p.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    p.add_argument("--timezone", default="US/Pacific", help="Dataset timezone in config.py")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default="8888")
    p.add_argument("--user", default="postgres")
    p.add_argument("--password", default="postgres")
    args = p.parse_args(argv)

    results = run(
        args.answer_key, args.database, os.path.abspath(args.out_dir), args.timezone,
        args.host, args.port, args.user, args.password,
    )
    for r in results:
        print(f"{r['attack_name']}: {len(r['index_ids'])} nodes {r['by_type']} -> {r['path']}")
    print("\n# pidsmaker/config/config.py entries:")
    print('"ground_truth_relative_path": [')
    for r in results:
        print(f'    "{r["relative_path"]}",')
    print("],")
    print('"attack_to_time_window": [')
    for r in results:
        print(f'    ["{r["relative_path"]}", "{r["window"][0]}", "{r["window"][1]}"],')
    print("],")
    return results


if __name__ == "__main__":
    main()
