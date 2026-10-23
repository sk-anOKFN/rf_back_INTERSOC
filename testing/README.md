# Testing Red Flags

```
 Wazuh (local) ──capture_alerts.py──> fixtures/*.ndjson ──label──> fixtures/*.csv
                                            │
                          mock_indexer.py replays the fixture
                                            │
                   log_detector ──> PostgreSQL ──> API ──evaluate.py──> metrics + per-alert report
```

| File | Purpose |
|---|---|
| `mock_indexer.py` | Fake Wazuh Indexer that replays an NDJSON fixture (auth, range, sort, search_after) |
| `docker-compose.test.yml` | Adds the mock indexer to the stack |
| `docker-compose.cpu.yml` | Runs Ollama without an NVIDIA GPU |
| `test.env.example` | Variables for the mock replay test |
| `local-wazuh.env.example` | Variables for a live test against a local Wazuh |
| `capture_alerts.py` | Saves real alerts from an indexer as a fixture + labelling template |
| `evaluate.py` | Compares verdicts with labels; can fail a run on thresholds |
| `generate_events.sh` | Creates safe, marked test events on a Linux Wazuh agent |
| `fixtures/sample_*` | 13 labelled alerts (4 malicious, 9 benign) |

The scripts only need Python 3.9+ (standard library). All commands below run from `red_flags_backend-main/`.

> **One Red Flags stack per Docker host.** Container names (`incident_db`, `db-api`, …) are fixed.
> If another Red Flags stack runs on the same machine (e.g. an older one deployed through a local
> Portainer), stop it first: `docker compose -p <that project> down` or stop it in Portainer.

## A. Mock replay (no Wazuh needed)

```bash
cp testing/test.env.example testing/test.env
docker network create log_ad_network          # once
docker compose --env-file testing/test.env -f docker-compose.yml -f testing/docker-compose.test.yml -f testing/docker-compose.cpu.yml up -d --build
docker logs -f log_detector                    # wait for "Processed page" lines to stop
python testing/evaluate.py --api http://localhost:8000 --labels testing/fixtures/sample_labels.csv
```

Drop `-f testing/docker-compose.cpu.yml` on a GPU machine. On CPU each alert takes 10–30 s.

To replay again with a clean database:

```bash
docker compose --env-file testing/test.env -f docker-compose.yml -f testing/docker-compose.test.yml down -v
```

`down -v` deletes this stack's PostgreSQL volume. Never run it against a stack whose data you need.

To replay your own fixture, put it in `testing/fixtures/` and set `TEST_FIXTURE=<file>.ndjson`.

## B. Live test with a local Wazuh

### 1. Run Wazuh single-node in Docker

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.x.y    # use the latest 4.x release tag
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Ports it publishes, and what to do when one is taken (edit `single-node/docker-compose.yml`, left side only):

| Port | Service | Needed by | If taken |
|---|---|---|---|
| 443 | Dashboard | your browser | `"8443:5601"` and open https://localhost:8443 |
| 9200 | Indexer | Red Flags, `capture_alerts.py` | `"19200:9200"` and use `:19200` in `INDEXER_URL` |
| 1514, 1515 | Agent connection / enrollment | agents | keep if possible; otherwise set the agent's manager port to match |
| 514/udp | Syslog | not needed | remove the mapping |
| 55000 | Manager API | not needed by Red Flags | `"55001:55000"` |

Default credentials are in `single-node/docker-compose.yml` (`INDEXER_PASSWORD`, by default `SecretPassword`).

### 2. Make Wazuh behave like the partner's setup

The partner turns every event into a low-level alert. Closest local equivalent: in the manager's
`ossec.conf` (`docker exec -it single-node-wazuh.manager-1 bash`, file `/var/ossec/etc/ossec.conf`):

```xml
<alerts>
  <log_alert_level>1</log_alert_level>
</alerts>
```

then `docker restart single-node-wazuh.manager-1`. Events matched by level-0 rules are still dropped.
Ask the partner for their exact configuration and copy it here when you have it.

### 3. Create a read-only user (same as you will ask the partner for)

```bash
export ADMIN_PW='SecretPassword'      # the admin password from step 1
export RO_PW='choose-a-password'
curl -k -u admin:$ADMIN_PW -X PUT https://localhost:9200/_plugins/_security/api/roles/redflags_read \
  -H 'Content-Type: application/json' \
  -d '{"cluster_permissions":["cluster_composite_ops_ro"],"index_permissions":[{"index_patterns":["wazuh-alerts-*"],"allowed_actions":["read"]}]}'
curl -k -u admin:$ADMIN_PW -X PUT https://localhost:9200/_plugins/_security/api/internalusers/redflags_ro \
  -H 'Content-Type: application/json' -d "{\"password\":\"$RO_PW\"}"
curl -k -u admin:$ADMIN_PW -X PUT https://localhost:9200/_plugins/_security/api/rolesmapping/redflags_read \
  -H 'Content-Type: application/json' -d '{"users":["redflags_ro"]}'
# check
curl -k -u redflags_ro:$RO_PW "https://localhost:9200/wazuh-alerts-*/_count"
```

### 4. Add agents

- **Windows (this machine):** install the Wazuh agent MSI and point it at the manager:
  `wazuh-agent-4.x.y-1.msi /q WAZUH_MANAGER="127.0.0.1"`, then `NET START WazuhSvc` (admin prompt).
- **Linux (WSL Ubuntu or a VM):** follow the Wazuh agent install docs for Debian/Ubuntu with
  `WAZUH_MANAGER=<IP of the machine running Docker>`. From WSL2, that is the Windows host IP,
  or `127.0.0.1` with WSL mirrored networking. Make sure the agent reads `/var/log/auth.log`, and
  for instant FIM alerts add `<directories realtime="yes">/etc/sudoers.d</directories>` under `<syscheck>`.

Check that the agents show as active in the dashboard.

### 5. Run Red Flags against it

```bash
cp testing/local-wazuh.env.example testing/local-wazuh.env    # set INDEXER_PASSWORD
docker compose --env-file testing/local-wazuh.env -f docker-compose.yml -f testing/docker-compose.cpu.yml up -d --build
docker logs -f log_detector
```

`INDEXER_URL=https://host.docker.internal:9200` reaches Wazuh's published port from inside the
detector container. Use `INDEXER_VERIFY_TLS=false` locally: the demo certificate is issued for
`wazuh.indexer`, so hostname verification fails.

### 6. Generate, capture, label, replay, evaluate

```bash
# on the Linux agent
sudo bash testing/generate_events.sh          # prints a run id, e.g. RFTEST-1792650000

# on the machine running Wazuh
python testing/capture_alerts.py --url https://localhost:9200 --user redflags_ro --password "$RO_PW" --insecure \
    --since 30 --query 'full_log:"RFTEST-1792650000"' \
    --out testing/fixtures/run1.ndjson --labels testing/fixtures/run1.csv
```

Open `run1.csv`, fill the `label` column with `malicious` or `benign` (the script prints which
event is which), then either evaluate the live run directly:

```bash
python testing/evaluate.py --api http://localhost:8000 --labels testing/fixtures/run1.csv
```

or replay the fixture through the mock (section A with `TEST_FIXTURE=run1.ndjson`), which lets
you compare models and settings on exactly the same alerts. Capture normal background activity
too (`--since 1440` without `--query`) and label it: false positives only show up on realistic
benign traffic.

## Reading the evaluation

| Metric | Meaning | Aim |
|---|---|---|
| Malicious detected | labelled malicious → Anomaly | high |
| Malicious surfaced | labelled malicious → Anomaly or Needs Attention | ~100% |
| Benign false anomalies | labelled benign → Anomaly | 0 |
| Benign review noise | labelled benign → Needs Attention | low; this is the analysts' queue |
| LLM alone | the model's own HIGH/CRITICAL verdicts, before indicator rules | compare models with this |

`--min-detected 1.0 --max-false-anomalies 0` makes the script exit with code 1 when a run gets
worse, so it can gate prompt or model changes.

Things to try, one at a time, on the same fixture: a larger `OLLAMA_MODEL` (e.g. `llama3.1:8b`,
`qwen2.5:7b`), `PROMPT_EXAMPLES=true`, `REQUIRE_INDICATOR_FOR_ANOMALY=false`, new rules in
`log_detector/indicators.py`.

## C. University server (Portainer) reading your local Wazuh

The server must reach your indexer port, which usually fails because your machine is behind NAT.
Prefer testing locally (section B) and deploying to the server once the partner's indexer is
available. If you need it anyway, use an SSH reverse tunnel from your machine:

```bash
ssh -N -R 172.17.0.1:19200:localhost:9200 <user>@<server>
```

This needs `GatewayPorts clientspecified` in the server's sshd config (ask the admins). Then set
`INDEXER_URL=https://host.docker.internal:19200` and `INDEXER_VERIFY_TLS=false` in the stack.
Do not expose 9200 publicly.
