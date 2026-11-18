# Red Flags
Backend for Red Flags Log Anomaly Detection System

## Installation & Usage

For GPU inference, Docker Desktop must have NVIDIA GPU support enabled and the
host must have a working NVIDIA driver. The Ollama container is configured to
reserve all available NVIDIA GPUs; Ollama will then place the model on the GPU
automatically.

The production server must have:

- An NVIDIA GPU and a compatible NVIDIA driver
- Docker Engine with the NVIDIA Container Toolkit installed
- A Portainer Environment connected to that Docker Engine
- The external Docker network and volumes created on the same server

**Step 1**: Create Shared Infrastructure

```
docker network create log_ad_network
```

**Step 2**: Deploy the Backend

2.1 Clone repository
```
git clone https://github.com/SecureEU/red_flags_backend
cd red_flags_backend
```

2.2 Configure the environment
Copy `.env.example` to `.env` and fill in the values marked ⚠. Every variable is explained in that file.

```
cp .env.example .env
```

Ports: containers always talk to each other on the default ports (PostgreSQL 5432, Ollama 11434, API `API_PORT`). The `*_PUBLISH_PORT` variables only choose the **host** ports, so changing them never breaks the stack. PostgreSQL and Ollama are published on `127.0.0.1` only; the API must be reachable from users' browsers. If an existing `.env` still has `POSTGRES_PORT` / `OLLAMA_PORT`, they are now ignored.

2.3 Build and start
First boot requires some time in order to pull and deploy the model set in `OLLAMA_MODEL` (**llama3.2:latest** is ~2 GB). Detection begins once Ollama and PostgreSQL are healthy **and** the `INDEXER_*` variables are filled in. Until then the detector stays up and logs `Wazuh indexer not configured`.

By default the detector only reads OpenSSH, Apache and Nginx access-log events: the `INDEXER_DECODERS` and `INDEXER_GROUPS` variables are comma-separated lists matched (exact terms) against `decoder.name` and `rule.groups` in the indexer query itself. Set both to empty to analyze every event.

If the indexer uses a self-signed certificate, copy its CA certificate to `./certs/root-ca.pem` and set `INDEXER_CA_CERT=/certs/root-ca.pem`. `INDEXER_VERIFY_TLS=false` disables verification (testing only).

Check that the indexer is reachable from the server before starting:
```
curl --cacert certs/root-ca.pem -u <user>:<password> "https://<partner-indexer-host>:9200/_cat/indices/wazuh-alerts-*?v"
```
```
docker compose up -d --build
```

Verify that the GPU is visible inside the Ollama container:

```
docker exec detector-ollama nvidia-smi
docker logs detector-ollama | findstr /i "gpu cuda library"
```

The detector continues to call Ollama through its HTTP API, while the model
inference runs in the Ollama container on the reserved GPU.

### Deploy from Portainer

1. On the server, verify GPU support before opening Portainer:

```
nvidia-smi
docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi
```

2. Create the shared resources once on the server:

```
docker network create log_ad_network
```

3. In Portainer, open **Stacks**. If a Red Flags stack already exists, open it and use
	**Pull and redeploy** after adding the new variables: container names are fixed, so a second
	stack would conflict. The database is migrated automatically and old rows stay readable.
	Otherwise choose **Add stack** > **Repository**, set the repository URL and
	`docker-compose.yml` as the Compose path.

	Under **Environment variables** switch to **Advanced mode** and paste the contents of
	`.env.example` without the inline comments, then fill in the ⚠ values.

	Portainer clones Git stacks into its own data folder, so relative bind mounts such as
	`./certs` do not point at a folder you control. Put the indexer CA certificate in a host
	folder (e.g. `sudo mkdir -p /opt/redflags/certs`) and set `INDEXER_CERTS_DIR=/opt/redflags/certs`
	and `INDEXER_CA_CERT=/certs/root-ca.pem`.

4. Deploy the stack and verify GPU inference after the model receives a request:

```
docker exec detector-ollama nvidia-smi
docker exec detector-ollama ollama ps
```

The `ollama ps` output should show the model loaded on `GPU` (or a GPU/CPU
split if the model does not fit entirely in VRAM). If `nvidia-smi` fails, the
problem is on the server's NVIDIA Toolkit/Docker configuration, not in the
Python detector.

### Ports already in use

Check what is taken on the server: `docker ps --format '{{.Names}} {{.Ports}}'` and `sudo ss -tlnp`
(or Portainer > Containers > Published Ports).

| Variable | Default | Who needs it | If taken |
|---|---|---|---|
| `API_PUBLISH_PORT` | 8000 | users' browsers | pick a free port, then set the frontend's `API_BASE_URL=http://<server>:<port>` |
| `POSTGRES_PUBLISH_PORT` | 5432 (localhost only) | admin tools only | pick any free port, e.g. 15432 |
| `OLLAMA_PUBLISH_PORT` | 11434 (localhost only) | debugging only | pick any free port, e.g. 11435 |
| frontend `PORT` | 7274 | users' browsers | pick a free port and add `http://<server>:<port>` to the backend's `CORS_ORIGINS` |

- If the API or dashboard is served behind the university's reverse proxy (e.g. `https://api.redflags.iee.ihu.gr`), the host ports only need to be free locally; set `API_BASE_URL` and `CORS_ORIGINS` to the public URLs.
- A CORS error in the browser console means the dashboard's exact origin (scheme, host, port) is missing from `CORS_ORIGINS`.
- Never change the internal ports (5432, 11434) or the container names: other containers use them.

## Testing

See [testing/README.md](testing/README.md): mock indexer replay, a local Wazuh setup, capturing and labelling alerts, and an evaluation script.

## How detection works

```
Wazuh Indexer (9200) ──poll──> rule filter ──> queue ──> N workers ──> Ollama ──> verdict ──> PostgreSQL
```

- The detector polls `INDEXER_INDEX` in timestamp order. The cursor is stored in the `detector_state` table and only advances once a full page is stored, so restarts neither skip nor duplicate alerts (`wazuh_alert_id` is unique).
- Each alert is mapped to a source family (`system`, `windows`, `web`, `ids`, `firewall`, `fim`, `audit`), stored as `log_type`, which selects extra guidance in the prompt.
- The LLM returns a summary, the most likely benign explanation, quoted evidence, severity and confidence. Evidence that does not appear in the alert is discarded.
- Deterministic strong indicators (`log_detector/indicators.py`) set a minimum severity for unambiguous patterns: injection/traversal payloads, reverse shells, encoded commands, credential dumping, privileged group changes (4728/4732/4756), audit log clearing (1102), and file integrity changes to sudoers, shadow, authorized_keys and cron. The model's own severity is kept in `analysis_result.llm_severity`.
- The classification is decided in code:
  - **Anomaly**: HIGH/CRITICAL, with verified evidence, confidence ≥ `DETECTION_THRESHOLD`, and (while `REQUIRE_INDICATOR_FOR_ANOMALY=true`) a strong-indicator match
  - **Needs Attention**: MEDIUM, or HIGH/CRITICAL without enough evidence, confidence or a matching indicator
  - **Benign**: LOW/INFO
  - **Unanalyzed**: the LLM call failed (kept so it can be reprocessed)
- Log templates (`POST /analyze/templates`) are mined only from Anomaly and Needs Attention incidents.

## Downloading analyzed logs

`GET /incidents/export?format=csv|ndjson` with optional `severity`, `log_type`, `source_host`, `classification` and `hours` filters. CSV contains flat columns; NDJSON contains full records, including the raw Wazuh alert. The dashboard's **CSV** / **NDJSON** buttons use the current filters.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `log_detector` shows "Wazuh indexer not configured" | `INDEXER_URL` / `INDEXER_USER` / `INDEXER_PASSWORD` empty or still placeholders | Fill them in `.env`, then `docker compose up -d log_detector` |
| `log_detector` shows "Indexer rejected credentials" | Wrong user/password or missing index permissions | Ask the partner to check the read-only user's access to `wazuh-alerts-4.x-*` |
| `log_detector` shows "Indexer unreachable" | Firewall, routing or TLS problem | Run the `curl` check above from the server; check `INDEXER_CA_CERT` |
| `log_detector` exits on startup | PostgreSQL not ready | Wait for `incident_db` to show `(healthy)`, then `docker compose restart log_detector` |
| API not reachable | Port conflict or wrong `API_PORT` | Check `docker ps` for port mapping; verify `API_PORT=8000` in `.env` |
| Ollama container unhealthy | Model still downloading | Wait 5–10 minutes on first boot; monitor with `docker logs detector-ollama -f` |
| Frontend cannot reach API | Wrong `API_BASE_URL` | The browser calls the API directly, so it must be a URL users' browsers can reach, e.g. `http://<server_ip>:<API_PUBLISH_PORT>`, not the container name |
| Browser console shows a CORS error | Dashboard origin not allowed | Add the dashboard URL (scheme, host and port) to `CORS_ORIGINS` and redeploy the API |
| Frontend shows blank/error page | Wrong `APP_URL` | Set `APP_URL` to the actual server IP in the frontend `.env` |

### Monitor startup progress
```
# Watch Ollama pull the model
docker logs detector-ollama -f

# Once Ollama is ready, watch the detector
docker logs log_detector -f
```
Expected Outcome:
```
✓ Ollama ready with llama3.2:latest
Connected to PostgreSQL: security_inc
Polling https://<partner-indexer-host>:9200 index=wazuh-alerts-4.x-*, starting 5 min back
Processed page: 200 alerts, 200 analyzed
```

Verify all backend containers are running
```
docker ps --format "table {{.Names}}\t{{.Status}}"
```
Expected outcome:
```
NAMES               STATUS
incident_db         Up X minutes (healthy)
detector-ollama     Up X minutes (healthy)
log_detector        Up X minutes
db-api              Up X minutes
```

Verify the API is responding: open http://<server_ip>:<API_PORT>/docs

### Stopping the system and reseting
```
cd ~/red_flags_backend && docker compose down
```

To fully reset and remove data
```
docker copmpose down -v
```


      
