import logging
from datetime import datetime, timedelta, timezone
from typing import List, Tuple, Optional

import requests
import urllib3
import config

log = logging.getLogger("detector.indexer")

if not config.INDEXER_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhIndexerClient:
    '''Reads alerts from the Wazuh Indexer (OpenSearch) in timestamp order.'''

    def __init__(self):
        self.session = requests.Session()
        self.session.auth = (config.INDEXER_USER, config.INDEXER_PASSWORD)
        if not config.INDEXER_VERIFY_TLS:
            self.session.verify = False
        elif config.INDEXER_CA_CERT:
            self.session.verify = config.INDEXER_CA_CERT
        self.search_url = f"{config.INDEXER_URL}/{config.INDEXER_INDEX}/_search"

    def fetch_page(self, cursor: Optional[list]) -> Tuple[List[dict], Optional[list]]:
        '''
        Return (alerts, last_sort_values) for the next page after the cursor.

        The cursor is the "sort" array of the last processed hit: [timestamp_millis, alert_id].
        Without a cursor, start INDEXER_LOOKBACK_MIN minutes in the past.
        '''
        time_range = {"lt": f"now-{config.INDEXER_SETTLE_SEC}s"}
        if cursor is None:
            start = datetime.now(timezone.utc) - timedelta(minutes=config.INDEXER_LOOKBACK_MIN)
            time_range["gte"] = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        body = {
            "size": config.INDEXER_PAGE_SIZE,
            "query": {"range": {"timestamp": time_range}},
            # "id" is the unique Wazuh alert id (keyword), used as a tie-breaker.
            "sort": [
                {"timestamp": {"order": "asc"}},
                {"id": {"order": "asc", "unmapped_type": "keyword"}}
            ]
        }
        if cursor is not None:
            body["search_after"] = cursor

        response = self.session.post(self.search_url, json=body, timeout=30)
        response.raise_for_status()
        hits = response.json().get("hits", {}).get("hits", [])

        alerts = []
        for hit in hits:
            source = hit.get("_source", {})
            source.setdefault("id", hit.get("_id"))
            alerts.append(source)

        last_sort = hits[-1].get("sort") if hits else None
        return alerts, last_sort
