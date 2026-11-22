# Elastic Defend (ECS) to PIDSMaker

Converts Elastic Defend endpoint telemetry (ECS, NDJSON) from ORTSOC, Oregon State's student SOC, into the 4-table Postgres schema that every PIDSMaker dataset uses. It also turns a planted-attack answer key into PIDSMaker ground-truth files. With the `ORTSOC_DEV` dataset registered, `python pidsmaker/main.py orthrus_non_snooped ORTSOC_DEV` reads the converted data like any DARPA TC dataset.

No real ORTSOC data exists yet. Everything here is developed and tested against synthetic data from `tests/fixtures/make_synthetic_ecs.py`.

| File | Purpose |
|---|---|
| `create_database_ecs.py` | NDJSON to `event_table`, `subject_node_table`, `file_node_table`, `netflow_node_table` |
| `label_attacks.py` | Answer key to `Ground_Truth/orthrus/ORTSOC-DEV/node_<attack>.csv`, plus config entries |
| `../../tests/fixtures/make_synthetic_ecs.py` | 5 days, 2 hosts, 1 planted attack, edge cases |
| `../../tests/test_ecs_converter.py` | 75 pytest tests (unit, DB round trip, labeler) |

## Usage

Run on the host in a small venv. Neither script imports `pidsmaker`, torch or the conda env.

```bash
cd ~/PIDSMaker-dev
python3 -m venv .venv-converter
.venv-converter/bin/pip install psycopg2-binary pytest

# 1. Convert (creates the database and tables if absent; --reset replaces existing rows)
.venv-converter/bin/python dataset_preprocessing/elastic_ecs/create_database_ecs.py \
    --input /path/to/ndjson_dir --database ortsoc_dev --host 127.0.0.1 --port 8888 --reset

# 2. Label planted attacks (writes Ground_Truth/orthrus/ORTSOC-DEV/ and prints config entries)
.venv-converter/bin/python dataset_preprocessing/elastic_ecs/label_attacks.py \
    --answer-key /path/to/answer_key.csv --database ortsoc_dev --timezone US/Pacific
```

Input is every `*.ndjson`, `*.jsonl` and `*.json` file in `--input`, read line by line. Each line is either a bare ECS document or an Elasticsearch search hit (`{"_id", "_index", "_source"}`). Nested objects, dotted keys (`"process.entity_id": ...`) and mixes of the two are all accepted. The converter refuses to write to `cadets_e3` and every other database that `postgres/init-create-databases.sh` creates. It also refuses a non-empty target unless `--reset` is given.

Answer key format (times ISO 8601 with offset):

```
attack_name,host,start,end,root_process_entity_id
curl_dropper,ortsoc-ws01,2026-11-06T14:05:00-08:00,2026-11-06T14:20:00-08:00,EID-ws01-000740
```

## PIDSMaker conventions followed (Step 1 findings)

Taken from `dataset_preprocessing/darpa_tc/create_database_e3.py`, `dataset_preprocessing/optc/create_database_optc.py`, `pidsmaker/utils/dataset_utils.py`, `pidsmaker/utils/labelling.py` and `pidsmaker/preprocessing/build_graph_methods/build_default_graphs.py`.

| Convention | PIDSMaker (DARPA E3 script) | This converter |
|---|---|---|
| `hash_id` | `stringtomd5(uuid)`, which actually computes **sha256** | sha256 hex of `node_uuid` (follows the code, not the spec's "md5") |
| `index_id` | One integer space shared by all node tables, assigned netflow, then subject, then file | Same order, contiguous from 0 |
| `event_table.src_node/dst_node` | `hash_id` of the node (OpTC stores the uuid; graph building only uses `*_index_id`) | `hash_id`, as in DARPA |
| `src_index_id`/`dst_index_id` | Integers in VARCHAR columns | `str(index_id)` |
| `operation` | Raw TC names; graph building keeps only `rel2id_darpa_tc` (10 types) | Only those 10 names are emitted |
| Edge direction | subject to object, except `edge_reversed` (EVENT_READ, EVENT_OPEN, EVENT_EXECUTE, EVENT_RECVFROM, EVENT_RECVMSG, EVENT_ACCEPT, ...), stored object to subject | Same; `test_constants_match_pidsmaker` re-reads both lists from `dataset_utils.py` |
| `timestamp_rec` | `timestampNanos`, ns since Unix epoch | ns since epoch (UTC), full nanosecond precision |
| Relation map selection | `get_rel2id`: datasets in `DARPA_TC_DATASETS` get `rel2id_darpa_tc` | `ORTSOC_DEV` added to `DARPA_TC_DATASETS` |
| Ground truth matching | `labelling.get_ground_truth` maps column 1 (uuid) to `index_id` via the DB; column 2 is a label, column 3 is informational | Same 3 columns |

## ECS to PIDSMaker field mapping

| PIDSMaker | ECS source |
|---|---|
| host key | `host.id`, else `host.hostname`, else `host.name`, else `agent.id` (event skipped as `no_host` if none) |
| subject `node_uuid` | `process.entity_id`; else `"{host}\|{process.executable or process.name}\|{process.pid}\|{process.start}"`; skipped (`no_process_identity`) if no entity_id and no pid |
| subject `path` | `process.executable` |
| subject `cmd` | `process.command_line`, else `process.name` |
| parent subject | Same rules on `process.parent.*`. If missing, the parent-to-child edge is skipped and counted; no placeholder parent is created |
| file `node_uuid` | `"{host}\|{file.path}"` (host-scoped); event skipped (`no_file_path`) if no path |
| file `path` | `file.path` |
| netflow `node_uuid` | `"{host}\|{network.transport}\|{destination.ip}:{destination.port}"` (host-scoped); skipped (`no_destination_ip`) if no `destination.ip` |
| netflow `src_addr/src_port/dst_addr/dst_port` | `source.ip`, `source.port`, `destination.ip`, `destination.port` (first event seen for that key) |
| `event_uuid` | `event.id`, else hit `_id`, else `synthetic-NNNNNNNNNNNN` (counted). A repeated `event.id` is skipped as `duplicate_event_uuid` |
| `timestamp_rec` | `@timestamp` parsed by regex (no `fromisoformat`): up to 9 fractional digits kept, `Z`/`±HH:MM`/`±HHMM` offsets, no offset means UTC, numbers mean epoch ms. Unparseable gives `bad_timestamp` |

When a process appears in several events, its first non-empty `path` and `cmd` win, and later events fill in fields that earlier ones lacked.

## Operation mapping

| ECS `event.category` / `event.action` | PIDSMaker operation | Stored direction | Fidelity |
|---|---|---|---|
| process / `exec`, `start`, `process_started`, `executed` (or `event.type` contains `start`) | `EVENT_CLONE` | parent to child | Faithful (TC uses EVENT_CLONE/EVENT_FORK for process creation; only CLONE is in `rel2id`) |
| same event, when `process.executable` is set | `EVENT_EXECUTE` | executable file to child (reversed) | Faithful (CADETS EVENT_EXECUTE on the image file) |
| process / `fork` | `EVENT_CLONE` only | parent to child | Faithful; no EXECUTE because no new image is loaded |
| process / `end`, `exit`, `already_running` | dropped | | No `rel2id` type (TC EVENT_EXIT is not in the 10) |
| file / `modification`, `overwrite`, `write` | `EVENT_WRITE` | process to file | Faithful |
| file / `creation` | `EVENT_WRITE` | process to file | **Approximate**: TC EVENT_CREATE_OBJECT is not in `rel2id`; creation in Elastic implies a write |
| file / `open` | `EVENT_OPEN` | file to process (reversed) | Faithful |
| file / `read`, `access` | `EVENT_READ` | file to process (reversed) | Faithful |
| file / other actions | `event.type` fallback: `creation`/`change` give `EVENT_WRITE`, `access` gives `EVENT_READ`, else dropped | | Approximate |
| file / `deletion`, `rename`, `attributes_modified`, `extended_attributes_delete`, `mount` | dropped | | No `rel2id` type (TC EVENT_UNLINK, EVENT_RENAME, EVENT_MODIFY_FILE_ATTRIBUTES are not in the 10) |
| network / `connection_attempted` | `EVENT_CONNECT` | process to netflow | Faithful |
| network / `connection_accepted` | `EVENT_RECVFROM` | netflow to process (reversed) | **Approximate**: TC EVENT_ACCEPT is not in `rel2id` (CADETS' own accepts are dropped by PIDSMaker), and Elastic has no per-read events |
| network / unknown action with `event.type` `start`+`connection` | `EVENT_CONNECT` | process to netflow | Approximate |
| network / `disconnect_received`, `connection_closed`, `lookup_requested`, `lookup_result`, `http_request` | dropped | | No socket-level match |
| any other category (authentication, library, registry, ...) | dropped (`unmapped_category`) | | |

**Decision: drop unmatched actions (option a), do not add an OpTC-style relation map (option b).** Reasons:

1. With only the 10 `rel2id_darpa_tc` types, `num_edge_types` stays 10. Every model config (Orthrus, Kairos, MAGIC, ...) runs unchanged, and edge-type embeddings stay comparable with the CADETS_E3 results.
2. PIDSMaker already drops the same TC events (EVENT_UNLINK, EVENT_RENAME, EVENT_EXIT, EVENT_ACCEPT, ...) for DARPA data, so dropping their Elastic equivalents matches what the models saw on CADETS.
3. A new map would require changes in `get_rel2id`, `get_num_edge_type`, `possible_events` and the triplet code, which is more than the "minimal changes" constraint allows.
4. Dropped events are counted per (category, action) in the summary, so their volume on real ORTSOC data can decide whether option (b) is worth it later.

## How labels are built

`label_attacks.py` treats each answer-key row as one attack. The malicious nodes are:

1. The root process (`subject_node_table.node_uuid = root_process_entity_id`).
2. Every descendant reached through `EVENT_CLONE` edges whose timestamp is within `[start, end]`. The root's own parent is not labeled.
3. Every file and netflow node with any event (either direction) to one of those processes within `[start, end]`.

Each attack is written to `Ground_Truth/orthrus/ORTSOC-DEV/node_<attack_name>.csv` in the CADETS format: no header, `\n` line endings, and rows `<node_uuid>,{'<type>': '<label>'},<index_id>`. Label strings match the DARPA ground-truth files:

| Type | Label | CADETS example |
|---|---|---|
| subject | `f"{path} {cmd}"` | `'None nginx'` |
| file | `path` | `'/tmp/main'` |
| netflow | `f"{src_addr}:{src_port}->{dst_addr}:{dst_port}"` | `'128.55.12.73:80->81.49.200.166:43530'` |

Fields are written with `csv.writer` (minimal quoting). Labels without commas therefore come out byte-identical in structure to CADETS, and a command line containing a comma is quoted instead of breaking the row. The script prints the `ground_truth_relative_path` and `attack_to_time_window` entries, with the window widened to whole minutes in `--timezone`.

For the synthetic attack, 14 nodes are labeled: 5 processes (bash, curl, chmod, x.sh, nc), 7 files (`/usr/bin/bash`, `/usr/bin/curl`, `/tmp/x.sh`, `/usr/bin/chmod`, `/etc/shadow`, `/tmp/.cache/payload`, `/usr/bin/nc`) and 2 netflows (`203.0.113.66:8080`, `198.51.100.23:4444`).

## Files changed in PIDSMaker

| File | Change | Why |
|---|---|---|
| `pidsmaker/config/config.py` | Added the `ORTSOC_DEV` entry after `CADETS_E3` (same keys): `database: ortsoc_dev`, `timezone: US/Pacific`, `num_node_types: 3`, `num_edge_types: 10`, train 2026-11-02..04, val 2026-11-05, test 2026-11-06, ground truth and attack window from the labeler | Dataset registration |
| `pidsmaker/utils/dataset_utils.py` | Added `"ORTSOC_DEV"` to `DARPA_TC_DATASETS` | `get_rel2id` and `uses_darpa_tc_schema` (node tables, ground truth, triage queries) key on this set |

New files (no existing behavior changes): `dataset_preprocessing/elastic_ecs/{create_database_ecs.py,label_attacks.py,README.md}`, `Ground_Truth/orthrus/ORTSOC-DEV/node_curl_dropper.csv`, `tests/fixtures/make_synthetic_ecs.py`, `tests/test_ecs_converter.py`.

I searched `pidsmaker/` for other branches on dataset names. The only remaining ones test `OPTC_DATASETS`, so no other file needs `ORTSOC_DEV`.

## Test results

```bash
cd ~/PIDSMaker-dev
.venv-converter/bin/python -m pytest tests/test_ecs_converter.py -v
```

Result: **75 passed, 0 failed, 0 warnings** (Python 3.10.13, pytest 9.2.0, psycopg2-binary 2.9.13, Postgres at 127.0.0.1:8888).

| Group | Tests | Covers |
|---|---|---|
| `TestTimestamps` | 12 | ns precision kept, ms/µs, offsets, no offset = UTC, epoch ms, unparseable values, >9 digits truncated |
| `TestEntityResolution` | 17 | entity_id vs fallback identity, name fallback, no-id/no-pid skip, host-key precedence incl. `agent.id`, path/cmd, attribute fill-in, host-scoped file and netflow keys, missing path / destination.ip, dotted keys |
| `TestEventUuid` | 6 | `event.id` preserved, `_id` fallback, precedence, synthetic ids, duplicates, search-hit unwrapping |
| `TestOperations` | 22 | constants match `dataset_utils.py`, parent to child CLONE + reversed EXECUTE, fork, missing parent (no placeholder), parent fallback, every file/network mapping with direction, dropped actions, only `rel2id` ops emitted, index order netflow/subject/file |
| `TestSyntheticCounts` | 3 | every planted edge case counted exactly, hit `_id`s used, ns timestamps survive |
| `TestRoundTrip` | 6 | refuses `cadets_e3`; row counts; every `event_table` row references an existing node by `index_id` and `hash_id`; `index_id` unique across tables; sha256 `hash_id`; `event_uuid` and ns timestamps stored |
| `TestLabeler` | 9 | labeled set equals the planted attack exactly; root and descendants; no benign node active on day 5 is labeled (and not the root's parent `sshd`); CSV format matches CADETS by regex and line endings; label strings; `index_id`s match the DB; time window; the committed config entry and ground-truth file equal the labeler's output |

The synthetic set has 3,579 documents. The converter reads 3,579, converts 2,520 and writes 3,313 edge rows (CLONE 793, EXECUTE 794, WRITE 662, READ 538, CONNECT 395, OPEN 131). It skips 1,059: 1,053 dropped actions (790 process end, 131 DNS lookups, 131 deletions, 1 chmod attribute change) plus one each of bad timestamp, malformed JSON, missing file path, missing destination IP, no process identity and unmapped category. Nodes: 802 subjects, 42 files, 8 netflows. Process ids: 99.7% from `entity_id`, 0.3% fallback.

The tests leave `ortsoc_dev` loaded with this synthetic data, which is what the smoke test below expects.

## Smoke test (run 2026-11-22: passed)

The running `pidsmaker-pids` container mounts `~/PIDSMaker`, not this clone, so it cannot see the `ORTSOC_DEV` registration. Option A below was run once no training job was active. Option B has not been tried.

**Option A, a one-off container on this clone** (does not touch the live container or its artifacts). It uses the same image, network and DB settings as `compose-pidsmaker.yml`. Do not pass `-u pids`: the image's `/entrypoint.sh` must start as root, remaps `pids` to the owner of the mounted clone, then drops to `pids` with `gosu`. With `-u pids` it fails with `failed switching to "pids": operation not permitted`.

```bash
mkdir -p ~/PIDSMaker-dev/artifacts
docker run --rm --network shared_network \
  -e DB_HOST=postgres -e DOCKER_PORT=5432 -e DB_USER=postgres -e DB_PASSWORD=postgres \
  -v ~/PIDSMaker-dev:/home/pids -v ~/PIDSMaker-dev/artifacts:/home/artifacts \
  pidsmaker-pids \
  bash -lc 'mkdir -p /home/pids/logs && cd /home/pids && python pidsmaker/main.py orthrus_non_snooped ORTSOC_DEV --cpu \
            --featurization.epochs=1 --training.num_epochs=1 2>&1 | tee /home/pids/logs/smoke_ortsoc_dev.log'
```

**Option B, after merging `ortsoc-ecs-converter` into `~/PIDSMaker`** (only once no queued run depends on the old code):

```bash
cd ~/PIDSMaker && docker compose -f compose-pidsmaker.yml exec -u pids pids bash -lc \
  'cd /home/pids && python pidsmaker/main.py orthrus_non_snooped ORTSOC_DEV --cpu --featurization.epochs=1 --training.num_epochs=1'
```

The `--featurization.epochs` and `--training.num_epochs` overrides only shorten the run; drop them for a real one.

**Result of Option A** (log: `logs/smoke_ortsoc_dev.log`, gitignored; artifacts in `artifacts/`, gitignored). Exit code 0 and "Run finished." after every stage: construction, transformation, featurization, feat_inference, batching, training, evaluation, triage. The container ran as `pids` and imported `pidsmaker` from the mounted clone.

| Check | Result |
|---|---|
| Nodes read from `ortsoc_dev` | netflow 8, process 802, file 42 (matches the converter) |
| Graphs built | one per day, 2026-11-02 to 2026-11-06, each spanning about 07:00 to 19:50 Pacific |
| Split | train 3 graphs, val 1, test 1 |
| Ground truth | "Total distinct malicious nodes across time windows: 14 / 14 ground-truth nodes"; no missing-UUID warning; 11/11 malicious event timestamps matched to test windows |
| Evaluation (1 epoch, not meaningful) | 221 test nodes, TP 0, FP 0, FN 14, TN 207, AUC 0.32 |

The detection numbers only show that evaluation runs. With one featurization epoch and one training epoch the model has learned nothing, and the synthetic data is too small and regular to evaluate Orthrus on.

## Open questions and limitations

1. **Timezone of day boundaries.** `build_default_graphs` converts the date splits with `datetime_to_ns_time_US` at its default US/Eastern unless the dataset timezone is exactly `UTC`. Labelling, though, uses `cfg.dataset.timezone` (US/Pacific). The synthetic data stays between 07:00 and 20:00 Pacific so both readings agree. Real 24/7 SOC data will have events between 21:00 and 24:00 Pacific that land in the next day's graph. Options: set `timezone: UTC` and express the date splits and attack windows in UTC, or fix PIDSMaker to pass the timezone. I did neither, since that would be a non-minimal PIDSMaker change.
2. **Approximate mappings.** File `creation` becomes `EVENT_WRITE`, and network `connection_accepted` becomes `EVENT_RECVFROM`.
3. **Dropped actions.** Process end, file deletion, rename and attribute changes (`chmod` is invisible), DNS lookups, disconnects, and non-process/file/network categories are all dropped. Measure their share on real data (the summary prints it) before deciding whether a dedicated relation map is worth it.
4. **Label rule includes shared binaries.** "Every file touched" labels system binaries that an attack process executes (`/usr/bin/bash`, `/usr/bin/curl`, ...), even though benign processes run them too. That follows the spec but differs from the CADETS ground truth, which lists mostly attacker-created files. Consider excluding `EVENT_EXECUTE` image files that were also executed outside attack windows.
5. **Netflow identity is per destination.** `{host}|{transport}|{dst_ip}:{dst_port}` merges all connections to the same destination, and stores the first connection's source port. For `connection_accepted` the spec keys on `destination.*`, which in Elastic is the local listening socket, so all inbound clients to one port share a node.
6. **Fallback process identities** depend on `process.start` being present and identical across events. Elastic Defend normally sends `entity_id`, so this path should be rare; the summary reports the share.
7. **Memory.** The converter holds all nodes and edges in memory, which is fine for dev-sized data. Multi-day real exports may need a streaming two-pass version.
8. **Exec semantics.** Each Elastic `exec` event is treated as a new process (new `entity_id`) cloned from `process.parent`. If ORTSOC data shows `exec` reusing the `entity_id` of the forked child, the subject node keeps the pre-exec image as its `path`.
9. **Host in the answer key** is not used for matching, because `entity_id` is globally unique. It is only documentation.
10. **Only smoke-tested in PIDSMaker.** The Orthrus pipeline runs end to end on `ortsoc_dev` and finds all 14 ground-truth nodes. Other models (Kairos, MAGIC) and full-length training have not been run on it.
