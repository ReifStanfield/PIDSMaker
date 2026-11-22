"""Tests for dataset_preprocessing/elastic_ecs (Elastic Defend -> PIDSMaker).

Run on the host in the converter venv:
    .venv-converter/bin/python -m pytest tests/test_ecs_converter.py -v

The round-trip and labeler tests write to the `ortsoc_dev` database on
127.0.0.1:8888 (override with ORTSOC_PG_HOST / ORTSOC_PG_PORT); they are skipped
if it is unreachable. They never touch any other database.
"""

import ast
import csv
import json
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "dataset_preprocessing", "elastic_ecs"))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))

import create_database_ecs as conv_mod  # noqa: E402
import label_attacks  # noqa: E402
import make_synthetic_ecs  # noqa: E402
from create_database_ecs import (  # noqa: E402
    DARPA_TC_OPERATIONS,
    EDGE_REVERSED,
    Converter,
    parse_timestamp_ns,
    sha256_hex,
)

PG = {
    "host": os.environ.get("ORTSOC_PG_HOST", "127.0.0.1"),
    "port": os.environ.get("ORTSOC_PG_PORT", "8888"),
    "user": "postgres",
    "password": "postgres",
}
DB = "ortsoc_dev"
HOST = {"id": "host-a", "name": "a"}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def proc(eid="P1", pid=100, exe="/usr/bin/x", cmd="x --y", name="x", start="2026-11-02T15:00:00.000Z", parent=None):
    p = {"pid": pid, "executable": exe, "command_line": cmd, "name": name, "start": start}
    if eid:
        p["entity_id"] = eid
    if parent is not None:
        p["parent"] = parent
    return p


def doc(category, action, process, ts="2026-11-02T15:00:00.123456789Z", host=HOST, **extra):
    d = {"@timestamp": ts, "host": dict(host), "event": {"category": [category], "action": action, "id": extra.pop("event_id", "E1")}, "process": process}
    if d["event"]["id"] is None:
        del d["event"]["id"]
    d.update(extra)
    return d


def one(conv, d, hit_id=None):
    conv.add_document(d, hit_id)
    return conv


def rows_of(conv):
    return conv.build_rows()


def index_of(rows, table, uuid):
    for r in rows[table]:
        if r[0] == uuid:
            return str(r[-1])
    raise KeyError(uuid)


# ---------------------------------------------------------------------------
# timestamps
# ---------------------------------------------------------------------------


class TestTimestamps:
    def test_nanoseconds_kept(self):
        assert parse_timestamp_ns("2026-11-02T15:00:00.123456789Z") == 1793631600_123456789

    def test_millis_and_micros(self):
        assert parse_timestamp_ns("2026-11-02T15:00:00.5Z") == 1793631600_500000000
        assert parse_timestamp_ns("2026-11-02T15:00:00.000001Z") == 1793631600_000001000

    def test_offsets(self):
        z = parse_timestamp_ns("2026-11-02T15:00:00Z")
        assert parse_timestamp_ns("2026-11-02T07:00:00-08:00") == z
        assert parse_timestamp_ns("2026-11-02T15:00:00+00:00") == z
        assert parse_timestamp_ns("2026-11-02T16:30:00+0130") == z

    def test_no_offset_is_utc(self):
        assert parse_timestamp_ns("2026-11-02T15:00:00") == parse_timestamp_ns("2026-11-02T15:00:00Z")

    def test_epoch_millis_number(self):
        assert parse_timestamp_ns(1793631600123) == 1793631600_123000000

    @pytest.mark.parametrize("bad", ["not-a-date", "", None, "2026-13-02T15:00:00Z", "2026-11-02T25:00:00Z", True])
    def test_unparseable(self, bad):
        assert parse_timestamp_ns(bad) is None

    def test_more_than_nine_digits_truncated(self):
        assert parse_timestamp_ns("2026-11-02T15:00:00.1234567891Z") == 1793631600_123456789


# ---------------------------------------------------------------------------
# entity resolution
# ---------------------------------------------------------------------------


class TestEntityResolution:
    def test_process_entity_id_used(self):
        c = one(Converter(), doc("file", "modification", proc(eid="ENT-1"), file={"path": "/tmp/a"}))
        assert "ENT-1" in c.subjects
        assert c.process_id_source["entity_id"] == 1

    def test_process_fallback_identity(self):
        p = proc(eid=None, pid=42, exe="/usr/bin/tar", start="2026-11-02T15:00:00.000Z")
        c = one(Converter(), doc("file", "modification", p, file={"path": "/tmp/a"}))
        assert list(c.subjects) == ["host-a|/usr/bin/tar|42|2026-11-02T15:00:00.000Z"]
        assert c.process_id_source["fallback"] == 1

    def test_fallback_uses_name_when_no_executable(self):
        p = proc(eid=None, pid=42, exe=None, name="tar")
        del p["executable"]
        c = one(Converter(), doc("file", "modification", p, file={"path": "/tmp/a"}))
        assert list(c.subjects) == ["host-a|tar|42|2026-11-02T15:00:00.000Z"]

    def test_no_entity_id_no_pid_skipped(self):
        p = {"executable": "/usr/bin/ghost", "name": "ghost"}
        c = one(Converter(), doc("file", "modification", p, file={"path": "/tmp/a"}))
        assert c.skipped["no_process_identity"] == 1 and not c.edges and not c.subjects

    @pytest.mark.parametrize(
        "host,expected",
        [
            ({"id": "I", "hostname": "H", "name": "N"}, "I"),
            ({"hostname": "H", "name": "N"}, "H"),
            ({"name": "N"}, "N"),
        ],
    )
    def test_host_key_precedence(self, host, expected):
        c = one(Converter(), doc("file", "modification", proc(), host=host, file={"path": "/f"}))
        assert list(c.files) == [f"{expected}|/f"]

    def test_host_key_agent_id(self):
        d = doc("file", "modification", proc(), file={"path": "/f"})
        del d["host"]
        d["agent"] = {"id": "AGENT"}
        c = one(Converter(), d)
        assert list(c.files) == ["AGENT|/f"]

    def test_subject_path_and_cmd(self):
        c = one(Converter(), doc("file", "modification", proc(exe="/bin/ls", cmd="ls -la"), file={"path": "/f"}))
        assert c.subjects["P1"] == ["/bin/ls", "ls -la"]

    def test_subject_cmd_falls_back_to_name(self):
        p = proc(name="ls")
        del p["command_line"]
        c = one(Converter(), doc("file", "modification", p, file={"path": "/f"}))
        assert c.subjects["P1"][1] == "ls"

    def test_missing_attributes_filled_from_later_events(self):
        c = Converter()
        p = proc()
        del p["executable"]
        one(c, doc("file", "modification", p, file={"path": "/f"}, event_id="E1"))
        one(c, doc("file", "modification", proc(exe="/usr/bin/x"), file={"path": "/f"}, event_id="E2"))
        assert c.subjects["P1"][0] == "/usr/bin/x"

    def test_file_paths_are_host_scoped(self):
        c = Converter()
        one(c, doc("file", "read", proc(eid="A"), host={"id": "h1"}, file={"path": "/etc/hosts"}, event_id="1"))
        one(c, doc("file", "read", proc(eid="B"), host={"id": "h2"}, file={"path": "/etc/hosts"}, event_id="2"))
        assert set(c.files) == {"h1|/etc/hosts", "h2|/etc/hosts"}

    def test_netflow_key_and_fields(self):
        d = doc("network", "connection_attempted", proc(), network={"transport": "tcp"},
                source={"ip": "10.0.0.1", "port": 5000}, destination={"ip": "1.2.3.4", "port": 443})
        c = one(Converter(), d)
        assert c.netflows == {"host-a|tcp|1.2.3.4:443": ["10.0.0.1", "5000", "1.2.3.4", "443"]}

    def test_netflows_are_host_scoped(self):
        c = Converter()
        for h, e in (("h1", "1"), ("h2", "2")):
            one(c, doc("network", "connection_attempted", proc(eid=h), host={"id": h}, event_id=e,
                       network={"transport": "tcp"}, destination={"ip": "1.2.3.4", "port": 443}))
        assert set(c.netflows) == {"h1|tcp|1.2.3.4:443", "h2|tcp|1.2.3.4:443"}

    def test_missing_file_path_skipped(self):
        c = one(Converter(), doc("file", "modification", proc()))
        assert c.skipped["no_file_path"] == 1 and not c.edges and not c.subjects

    def test_missing_destination_ip_skipped(self):
        c = one(Converter(), doc("network", "connection_attempted", proc(), destination={"port": 80}))
        assert c.skipped["no_destination_ip"] == 1 and not c.edges

    def test_dotted_keys(self):
        d = {"@timestamp": "2026-11-02T15:00:00Z", "host.id": "H", "event.category": "file",
             "event.action": "modification", "event.id": "E9", "process.entity_id": "P",
             "process.pid": 1, "file.path": "/x"}
        c = one(Converter(), d)
        assert list(c.files) == ["H|/x"] and c.edges[0][5] == "E9"


# ---------------------------------------------------------------------------
# event_uuid
# ---------------------------------------------------------------------------


class TestEventUuid:
    def test_event_id_preserved(self):
        c = one(Converter(), doc("file", "modification", proc(), file={"path": "/f"}, event_id="evt-abc"))
        assert rows_of(c)["event_table"][0][5] == "evt-abc"

    def test_hit_id_used_when_no_event_id(self):
        c = one(Converter(), doc("file", "modification", proc(), file={"path": "/f"}, event_id=None), hit_id="HIT-1")
        assert c.edges[0][5] == "HIT-1"

    def test_event_id_wins_over_hit_id(self):
        c = one(Converter(), doc("file", "modification", proc(), file={"path": "/f"}, event_id="E"), hit_id="HIT")
        assert c.edges[0][5] == "E"

    def test_synthetic_uuid_when_neither(self):
        c = Converter()
        one(c, doc("file", "modification", proc(), file={"path": "/f"}, event_id=None))
        one(c, doc("file", "modification", proc(), file={"path": "/g"}, event_id=None))
        uuids = [e[5] for e in c.edges]
        assert len(set(uuids)) == 2 and all(u.startswith("synthetic-") for u in uuids)
        assert c.stats["synthetic_event_uuid"] == 2

    def test_duplicate_event_id_skipped(self):
        c = Converter()
        one(c, doc("file", "modification", proc(), file={"path": "/f"}, event_id="dup"))
        one(c, doc("file", "modification", proc(), file={"path": "/f"}, event_id="dup"))
        assert len(c.edges) == 1 and c.skipped["duplicate_event_uuid"] == 1

    def test_search_hit_unwrapped(self, tmp_path):
        d = doc("file", "modification", proc(), file={"path": "/f"}, event_id=None)
        (tmp_path / "a.ndjson").write_text(json.dumps({"_index": "i", "_id": "H1", "_source": d}) + "\n")
        c = conv_mod.convert_directory(str(tmp_path))
        assert c.edges[0][5] == "H1" and list(c.files) == ["host-a|/f"]


# ---------------------------------------------------------------------------
# operations and edge direction (DARPA conventions)
# ---------------------------------------------------------------------------


class TestOperations:
    def test_constants_match_pidsmaker(self):
        """The copied constants must match pidsmaker/utils/dataset_utils.py."""
        src = open(os.path.join(ROOT, "pidsmaker", "utils", "dataset_utils.py")).read()
        rel = re.search(r"rel2id_darpa_tc = \{(.*?)\n\}", src, re.S).group(1)
        assert set(re.findall(r'"(EVENT_\w+)"', rel)) == set(DARPA_TC_OPERATIONS)
        rev = re.search(r"edge_reversed = \[(.*?)\]", src, re.S).group(1)
        assert set(re.findall(r'"(\w+)"', rev)) == EDGE_REVERSED

    def test_process_start_parent_to_child_clone_and_execute(self):
        parent = proc(eid="PARENT", exe="/usr/bin/bash", cmd="bash")
        child = proc(eid="CHILD", exe="/usr/bin/curl", cmd="curl x", parent=parent)
        c = one(Converter(), doc("process", "exec", child))
        r = rows_of(c)
        clone = [e for e in r["event_table"] if e[2] == "EVENT_CLONE"][0]
        assert clone[0] == sha256_hex("PARENT") and clone[3] == sha256_hex("CHILD")
        assert clone[1] == index_of(r, "subject_node_table", "PARENT")
        assert clone[4] == index_of(r, "subject_node_table", "CHILD")
        execute = [e for e in r["event_table"] if e[2] == "EVENT_EXECUTE"][0]
        # EVENT_EXECUTE is in edge_reversed: file -> process.
        assert execute[0] == sha256_hex("host-a|/usr/bin/curl") and execute[3] == sha256_hex("CHILD")

    def test_fork_has_no_execute_edge(self):
        child = proc(eid="C", parent=proc(eid="P"))
        c = one(Converter(), doc("process", "fork", child))
        assert [e[2] for e in c.edges] == ["EVENT_CLONE"]

    def test_missing_parent_skips_clone_only(self):
        c = one(Converter(), doc("process", "exec", proc(eid="C")))
        assert [e[2] for e in c.edges] == ["EVENT_EXECUTE"]
        assert c.stats["parent_edge_skipped_missing_parent"] == 1
        assert set(c.subjects) == {"C"}  # no shared placeholder parent

    def test_parent_fallback_identity(self):
        parent = proc(eid=None, pid=7, exe="/usr/sbin/cron", start="2026-10-01T00:00:00Z")
        c = one(Converter(), doc("process", "exec", proc(eid="C", parent=parent)))
        assert "host-a|/usr/sbin/cron|7|2026-10-01T00:00:00Z" in c.subjects

    @pytest.mark.parametrize(
        "action,op",
        [("creation", "EVENT_WRITE"), ("modification", "EVENT_WRITE"), ("overwrite", "EVENT_WRITE"),
         ("open", "EVENT_OPEN"), ("read", "EVENT_READ"), ("access", "EVENT_READ")],
    )
    def test_file_mapping_and_direction(self, action, op):
        c = one(Converter(), doc("file", action, proc(eid="P"), file={"path": "/f"}))
        r = rows_of(c)["event_table"][0]
        assert r[2] == op
        if op in EDGE_REVERSED:  # READ/OPEN: file -> process
            assert (r[0], r[3]) == (sha256_hex("host-a|/f"), sha256_hex("P"))
        else:  # WRITE: process -> file
            assert (r[0], r[3]) == (sha256_hex("P"), sha256_hex("host-a|/f"))

    @pytest.mark.parametrize("action,op", [("connection_attempted", "EVENT_CONNECT"), ("connection_accepted", "EVENT_RECVFROM")])
    def test_network_mapping_and_direction(self, action, op):
        d = doc("network", action, proc(eid="P"), network={"transport": "tcp"}, destination={"ip": "1.2.3.4", "port": 80})
        r = rows_of(one(Converter(), d))["event_table"][0]
        net = sha256_hex("host-a|tcp|1.2.3.4:80")
        assert r[2] == op
        assert (r[0], r[3]) == ((net, sha256_hex("P")) if op in EDGE_REVERSED else (sha256_hex("P"), net))

    @pytest.mark.parametrize(
        "category,action",
        [("process", "end"), ("file", "deletion"), ("file", "rename"), ("file", "attributes_modified"),
         ("network", "lookup_requested"), ("network", "disconnect_received")],
    )
    def test_dropped_actions(self, category, action):
        c = one(Converter(), doc(category, action, proc(), file={"path": "/f"}, destination={"ip": "1.1.1.1", "port": 53}))
        assert not c.edges and c.skipped["unmapped_action"] == 1
        assert c.dropped_actions[(category, action)] == 1

    def test_unmapped_category(self):
        c = one(Converter(), doc("authentication", "log_on", proc()))
        assert c.skipped["unmapped_category"] == 1 and not c.edges

    def test_only_rel2id_operations_emitted(self, synthetic):
        c = conv_mod.convert_directory(os.path.join(synthetic["dir"], "ecs"))
        assert {e[2] for e in c.edges} <= set(DARPA_TC_OPERATIONS)

    def test_shared_index_space_order(self):
        c = Converter()
        one(c, doc("network", "connection_attempted", proc(eid="P"), destination={"ip": "1.1.1.1", "port": 1}, event_id="1"))
        one(c, doc("file", "read", proc(eid="P"), file={"path": "/f"}, event_id="2"))
        r = rows_of(c)
        # netflow, then subject, then file (create_database_e3.py order), no gaps.
        assert [r["netflow_node_table"][0][-1], r["subject_node_table"][0][-1], r["file_node_table"][0][-1]] == [0, 1, 2]
        assert r["subject_node_table"][0][1] == sha256_hex("P")


# ---------------------------------------------------------------------------
# synthetic data: skipped-event counts
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def synthetic(tmp_path_factory):
    out = tmp_path_factory.mktemp("synthetic")
    expected = make_synthetic_ecs.generate(str(out))
    return {"dir": str(out), "expected": expected}


class TestSyntheticCounts:
    def test_skip_counts_match_planted_edge_cases(self, synthetic):
        c = conv_mod.convert_directory(os.path.join(synthetic["dir"], "ecs"))
        e = synthetic["expected"]["edge_cases"]
        assert c.stats["events_read"] == synthetic["expected"]["documents"]
        for reason in ("no_file_path", "no_destination_ip", "no_process_identity", "bad_timestamp",
                       "malformed_json", "unmapped_category"):
            assert c.skipped[reason] == e[reason], reason
        assert c.stats["parent_edge_skipped_missing_parent"] == e["parent_edge_skipped_missing_parent"]
        assert c.stats["synthetic_event_uuid"] == e["synthetic_event_uuid"]
        assert c.skipped["duplicate_event_uuid"] == 0
        assert c.process_id_source["fallback"] > 0

    def test_hit_ids_used(self, synthetic):
        c = conv_mod.convert_directory(os.path.join(synthetic["dir"], "ecs"))
        hit_uuids = {e[5] for e in c.edges if e[5].startswith("hit-")}
        # Hits without event.id fall back to _id. Some of those hits are dropped
        # actions (process end, DNS, deletion), so only an upper bound is known.
        assert 0 < len(hit_uuids) <= synthetic["expected"]["hits_without_event_id"]

    def test_nanosecond_timestamps_survive(self, synthetic):
        c = conv_mod.convert_directory(os.path.join(synthetic["dir"], "ecs"))
        assert any(e[6] % 1000 != 0 for e in c.edges)


# ---------------------------------------------------------------------------
# database round trip and labeler (real ortsoc_dev database)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def loaded_db(synthetic):
    try:
        conn = conv_mod.ensure_database(DB, PG["host"], PG["port"], PG["user"], PG["password"])
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"Postgres not reachable: {exc}")
    conv = conv_mod.convert_directory(os.path.join(synthetic["dir"], "ecs"))
    rows = conv.build_rows()
    conv_mod.write_rows(conn, rows, reset=True)
    yield {"conn": conn, "conv": conv, "rows": rows}
    conn.close()


class TestRoundTrip:
    def test_protected_database_refused(self):
        with pytest.raises(SystemExit):
            conv_mod.check_database_name("cadets_e3")

    def test_counts(self, loaded_db):
        counts = conv_mod.table_counts(loaded_db["conn"])
        conv = loaded_db["conv"]
        assert counts == {
            "event_table": len(conv.edges),
            "subject_node_table": len(conv.subjects),
            "file_node_table": len(conv.files),
            "netflow_node_table": len(conv.netflows),
        }

    def test_every_event_references_existing_nodes(self, loaded_db):
        cur = loaded_db["conn"].cursor()
        cur.execute(
            """
            WITH nodes AS (
                SELECT index_id::text AS idx, hash_id FROM subject_node_table
                UNION ALL SELECT index_id::text, hash_id FROM file_node_table
                UNION ALL SELECT index_id::text, hash_id FROM netflow_node_table)
            SELECT count(*) FROM event_table e
            WHERE NOT EXISTS (SELECT 1 FROM nodes n WHERE n.idx = e.src_index_id AND n.hash_id = e.src_node)
               OR NOT EXISTS (SELECT 1 FROM nodes n WHERE n.idx = e.dst_index_id AND n.hash_id = e.dst_node)
            """
        )
        assert cur.fetchone()[0] == 0

    def test_index_ids_unique_across_tables(self, loaded_db):
        cur = loaded_db["conn"].cursor()
        cur.execute(
            "SELECT count(*), count(DISTINCT index_id) FROM (SELECT index_id FROM subject_node_table "
            "UNION ALL SELECT index_id FROM file_node_table UNION ALL SELECT index_id FROM netflow_node_table) t"
        )
        total, distinct = cur.fetchone()
        assert total == distinct

    def test_hash_id_is_sha256_of_uuid(self, loaded_db):
        cur = loaded_db["conn"].cursor()
        cur.execute("SELECT node_uuid, hash_id FROM file_node_table LIMIT 20")
        for uuid, h in cur.fetchall():
            assert h == sha256_hex(uuid)

    def test_event_uuid_and_timestamps_stored(self, loaded_db):
        cur = loaded_db["conn"].cursor()
        cur.execute("SELECT count(*) FROM event_table WHERE event_uuid LIKE 'evt-%'")
        assert cur.fetchone()[0] > 0
        cur.execute("SELECT count(*) FROM event_table WHERE timestamp_rec % 1000 <> 0")
        assert cur.fetchone()[0] > 0


@pytest.fixture(scope="session")
def labeled(loaded_db, synthetic, tmp_path_factory):
    out = tmp_path_factory.mktemp("gt")
    res = label_attacks.run(
        os.path.join(synthetic["dir"], "answer_key.csv"), DB, str(out), "US/Pacific",
        PG["host"], PG["port"], PG["user"], PG["password"],
    )
    return {"results": res, "dir": str(out)}


class TestLabeler:

    def _rows(self, labeled):
        with open(labeled["results"][0]["path"], newline="") as f:
            return list(csv.reader(f))

    def test_labels_exactly_the_attack(self, labeled, synthetic):
        exp = synthetic["expected"]["malicious"]
        got = {"subject": set(), "file": set(), "netflow": set()}
        for uuid, label, _ in self._rows(labeled):
            got[next(iter(ast.literal_eval(label)))].add(uuid)  # label is a dict literal, as in CADETS
        assert got == {k: set(v) for k, v in exp.items()}

    def test_root_and_descendants(self, labeled, synthetic):
        uuids = {r[0] for r in self._rows(labeled)}
        assert synthetic["expected"]["attack_root"] in uuids
        assert len([u for u in uuids if u.startswith("EID-")]) == 5  # bash, curl, chmod, x.sh, nc

    def test_no_benign_day5_node_labeled(self, labeled, synthetic, loaded_db):
        """Nodes active on day 5 that the attack never touched must not be labeled."""
        exp = set().union(*map(set, synthetic["expected"]["malicious"].values()))
        cur = loaded_db["conn"].cursor()
        lo = parse_timestamp_ns("2026-11-06T00:00:00-08:00")
        hi = parse_timestamp_ns("2026-11-07T00:00:00-08:00")
        cur.execute("SELECT DISTINCT src_index_id FROM event_table WHERE timestamp_rec BETWEEN %s AND %s "
                    "UNION SELECT DISTINCT dst_index_id FROM event_table WHERE timestamp_rec BETWEEN %s AND %s",
                    (lo, hi, lo, hi))
        day5 = {int(r[0]) for r in cur.fetchall()}
        labeled_ids = {int(r[2]) for r in self._rows(labeled)}
        nodes = label_attacks.load_nodes(cur)
        benign_day5 = {i for i in day5 if nodes[i][1] not in exp}
        assert len(benign_day5) > 50  # sanity: day 5 has plenty of benign activity
        assert not (benign_day5 & labeled_ids)
        # The parent of the root (sshd) is active in the window but not a descendant.
        assert not any(nodes[i][1].endswith("sshd") for i in labeled_ids)

    def test_csv_format_matches_cadets(self, labeled):
        cadets = os.path.join(ROOT, "Ground_Truth", "orthrus", "E3-CADETS", "node_Nginx_Backdoor_06.csv")
        pattern = re.compile(r"^[^,\n]+,\{'(subject|file|netflow)': '[^'\n]*'\},\d+$")
        for path in (cadets, labeled["results"][0]["path"]):
            raw = open(path, "rb").read()
            assert b"\r" not in raw and raw.endswith(b"\n")
            lines = raw.decode().splitlines()
            assert lines and all(pattern.match(l) for l in lines), path

    def test_label_strings(self, labeled):
        rows = {r[0]: ast.literal_eval(r[1]) for r in self._rows(labeled)}
        h = make_synthetic_ecs.HOSTS["ws01"]["id"]
        assert rows[f"{h}|/tmp/x.sh"] == {"file": "/tmp/x.sh"}
        root = [v for k, v in rows.items() if k.startswith("EID-") and "bash -i" in str(v)][0]
        assert root == {"subject": "/usr/bin/bash bash -i"}
        net = rows[f"{h}|tcp|198.51.100.23:4444"]["netflow"]
        assert re.fullmatch(r"10\.20\.0\.11:\d+->198\.51\.100\.23:4444", net)

    def test_index_ids_match_db(self, labeled, loaded_db):
        cur = loaded_db["conn"].cursor()
        nodes = label_attacks.load_nodes(cur)
        for uuid, _, idx in self._rows(labeled):
            assert nodes[int(idx)][1] == uuid

    def test_time_window_entry(self, labeled):
        assert labeled["results"][0]["window"] == ["2026-11-06 14:05:00", "2026-11-06 14:20:00"]
        assert labeled["results"][0]["relative_path"] == "ORTSOC-DEV/node_curl_dropper.csv"

    def test_committed_config_matches_labeler(self, labeled):
        import importlib.util

        spec = importlib.util.spec_from_file_location("pm_config", os.path.join(ROOT, "pidsmaker", "config", "config.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        cfg = m.DATASET_DEFAULT_CONFIG["ORTSOC_DEV"]
        r = labeled["results"][0]
        assert cfg["database"] == DB and cfg["timezone"] == "US/Pacific"
        assert cfg["ground_truth_relative_path"] == [r["relative_path"]]
        assert cfg["attack_to_time_window"] == [[r["relative_path"], *r["window"]]]
        assert set(cfg) == set(m.DATASET_DEFAULT_CONFIG["CADETS_E3"])

    def test_committed_ground_truth_matches_labeler(self, labeled):
        committed = os.path.join(ROOT, "Ground_Truth", "orthrus", "ORTSOC-DEV", "node_curl_dropper.csv")
        assert open(committed).read() == open(labeled["results"][0]["path"]).read()
