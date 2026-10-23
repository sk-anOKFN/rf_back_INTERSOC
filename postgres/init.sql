CREATE TABLE IF NOT EXISTS security_incidents (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),

    -- Source family derived from the Wazuh alert (system, windows, web, ids, firewall, fim, audit)
    log_type TEXT NOT NULL,
    source_host TEXT,

    -- full_log of the alert, or a synthesized line when Wazuh provides none
    raw_log_message TEXT NOT NULL,

    wazuh_alert_id TEXT,
    raw_alert JSONB,

    analysis_result JSONB NOT NULL,
    severity TEXT,
    classification TEXT,
    is_anomaly BOOLEAN,
    event_timestamp TIMESTAMPTZ
);

CREATE INDEX idx_log_type ON security_incidents(log_type);
CREATE INDEX idx_severity ON security_incidents(severity);
CREATE INDEX idx_created_at ON security_incidents(created_at DESC);
CREATE INDEX idx_source_host ON security_incidents(source_host);
CREATE INDEX idx_event_timestamp ON security_incidents(event_timestamp);
CREATE UNIQUE INDEX idx_wazuh_alert_id ON security_incidents(wazuh_alert_id);
CREATE INDEX idx_classification ON security_incidents(classification);

CREATE INDEX idx_analysis_source_ip ON security_incidents USING gin ((analysis_result->'source_ip'));
CREATE INDEX idx_analysis_attack_type ON security_incidents USING gin ((analysis_result->'attack_type'));

-- Detector state, e.g. the Wazuh indexer cursor
CREATE TABLE IF NOT EXISTS detector_state (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
