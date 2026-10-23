import json
import logging
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, Any, Optional

from psycopg2.extras import Json
from psycopg2.pool import ThreadedConnectionPool
import config

log = logging.getLogger("detector.storage")

# Idempotent, so existing deployments are migrated on startup (init.sql only runs on a fresh volume).
SCHEMA_MIGRATIONS = """
ALTER TABLE security_incidents DROP CONSTRAINT IF EXISTS valid_log_type;
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS wazuh_alert_id TEXT;
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS raw_alert JSONB;
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS classification TEXT;
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS is_anomaly BOOLEAN;
CREATE UNIQUE INDEX IF NOT EXISTS idx_wazuh_alert_id ON security_incidents(wazuh_alert_id);
CREATE INDEX IF NOT EXISTS idx_classification ON security_incidents(classification);
CREATE TABLE IF NOT EXISTS detector_state (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
"""

class PostgresStorage:
    def __init__(self, max_conn: int = 5):
        self.pool = ThreadedConnectionPool(
            1, max_conn,
            host = config.POSTGRES_HOST,
            port = config.POSTGRES_PORT,
            database = config.POSTGRES_DB,
            user = config.POSTGRES_USER,
            password = config.POSTGRES_PASSWORD
        )
        log.info("Connected to PostgreSQL: %s", config.POSTGRES_DB)
        with self._cursor() as cur:
            cur.execute(SCHEMA_MIGRATIONS)

    @contextmanager
    def _cursor(self):
        conn = self.pool.getconn()
        try:
            with conn.cursor() as cur:
                yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.pool.putconn(conn)

    def alert_exists(self, wazuh_alert_id: str) -> bool:
        with self._cursor() as cur:
            cur.execute(
                "SELECT 1 FROM security_incidents WHERE wazuh_alert_id = %s",
                (wazuh_alert_id, )
            )
            return cur.fetchone() is not None

    def store_alert(self, alert: Dict[str, Any], log_type: str, source_host: str,
                    raw_message: str, analysis_result: Dict[str, Any]) -> Optional[int]:
        '''Insert one analyzed alert. Idempotent on wazuh_alert_id.'''
        event_timestamp = None
        ts = alert.get('timestamp')
        if ts:
            try:
                # Wazuh uses "+0000" offsets, which fromisoformat only accepts from Python 3.11.
                event_timestamp = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            except ValueError:
                event_timestamp = None

        query = """
            INSERT INTO security_incidents
            (wazuh_alert_id, log_type, source_host, raw_log_message, raw_alert,
             analysis_result, severity, classification, is_anomaly, event_timestamp)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (wazuh_alert_id) DO NOTHING
            RETURNING id
        """
        with self._cursor() as cur:
            cur.execute(query, (
                alert.get('id'),
                log_type,
                source_host,
                raw_message,
                Json(alert),
                Json(analysis_result),
                analysis_result.get('severity', 'UNKNOWN'),
                analysis_result.get('classification'),
                analysis_result.get('is_anomaly'),
                event_timestamp
            ))
            row = cur.fetchone()
        return row[0] if row else None

    def get_cursor(self) -> Optional[list]:
        with self._cursor() as cur:
            cur.execute("SELECT value FROM detector_state WHERE key = 'indexer_cursor'")
            row = cur.fetchone()
        return row[0] if row else None

    def save_cursor(self, sort_values: list):
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO detector_state (key, value, updated_at)
                VALUES ('indexer_cursor', %s, NOW())
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
            """, (json.dumps(sort_values), ))

    def close(self):
        if self.pool:
            self.pool.closeall()
            log.info("PostgreSQL connection closed")
