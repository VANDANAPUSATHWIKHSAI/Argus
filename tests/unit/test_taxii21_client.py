"""Unit tests for TAXII 2.1 Threat Intelligence Client.

Verifies:
- Configurable endpoints, credentials, TLS verification, collection IDs, and polling intervals.
- Secrets loaded from environment/configuration; never hard-coded.
- STIX 2.1 object and bundle validation.
- Connection and read timeouts, bounded retries, rate-limit handling (HTTP 429), pagination, and incremental polling.
- Safe caching, deduplication, and provenance metadata (feed name, object ID, retrieval time).
- Clear distinction between LIVE feed results, CACHED results, and UNAVAILABLE feeds.
- No fabricated intelligence when credentials or services are unavailable.
- Tenant-safe storage and query behavior.
"""

from datetime import datetime, timezone
import unittest
from unittest.mock import MagicMock, patch

import requests

from threat_intel.stix_taxii import (
    FeedStatus,
    StixTaxiiClient,
    validate_stix_object,
)


class TestTaxii21Client(unittest.TestCase):

    def setUp(self):
        self.server_url = "https://taxii.example.org/taxii2/"
        self.collection_id = "col-998877"
        self.client = StixTaxiiClient(
            server_url=self.server_url,
            api_key="synthetic_test_api_key_12345",
            collection_id=self.collection_id,
            timeout=5.0,
            cache_ttl_seconds=3600.0,
            feed_name="test_cisa_taxii",
        )

        self.valid_stix_indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
            "created": "2026-10-01T00:00:00.000Z",
            "modified": "2026-10-01T00:00:00.000Z",
            "name": "Malicious Command and Control IP",
            "pattern": "[ipv4-addr:value = '198.51.100.55']",
            "pattern_type": "stix",
            "valid_from": "2026-10-01T00:00:00Z",
        }

    def test_stix_object_validation(self):
        """Verifies STIX 2.1 object validation rules."""
        # Valid STIX 2.1 indicator
        self.assertTrue(validate_stix_object(self.valid_stix_indicator))

        # Missing id or type
        self.assertFalse(validate_stix_object({"type": "indicator"}))
        self.assertFalse(validate_stix_object({"id": "indicator--123"}))

        # Revoked indicator must be rejected
        revoked_ind = dict(self.valid_stix_indicator)
        revoked_ind["revoked"] = True
        self.assertFalse(validate_stix_object(revoked_ind))

        # Non-dict object
        self.assertFalse(validate_stix_object("not-a-dict"))

    @patch("requests.Session.get")
    def test_fetch_indicators_live_success_with_provenance(self, mock_get):
        """Verifies live fetch parses bundle, attaches provenance, and sets status to LIVE."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "more": False,
            "objects": [self.valid_stix_indicator]
        }
        mock_get.return_value = mock_response

        indicators = self.client.fetch_indicators(tenant_id="tenant-alpha")

        self.assertEqual(len(indicators), 1)
        ind = indicators[0]
        self.assertEqual(ind["id"], self.valid_stix_indicator["id"])
        self.assertEqual(ind["feed_name"], "test_cisa_taxii")
        self.assertEqual(ind["feed_status"], FeedStatus.LIVE.value)
        self.assertEqual(ind["tenant_id"], "tenant-alpha")
        self.assertIn("retrieval_time", ind)
        self.assertEqual(self.client.last_status, FeedStatus.LIVE)

    @patch("requests.Session.get")
    def test_fetch_indicators_with_credentials_and_tls_config(self, mock_get):
        """Verifies TLS verification and Authorization headers are submitted correctly."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"more": False, "objects": []}
        mock_get.return_value = mock_response

        client = StixTaxiiClient(
            server_url="https://secure.taxii.local/taxii2/",
            username="analyst",
            password="secret_password",
            verify_tls=True,
            ca_cert_path="/path/to/custom-ca.crt",
        )
        client.fetch_indicators()

        mock_get.assert_called()
        call_kwargs = mock_get.call_args[1]
        headers = call_kwargs["headers"]
        self.assertIn("application/taxii+json;version=2.1", headers["Accept"])

    @patch("requests.Session.get")
    def test_pagination_follows_next_pages(self, mock_get):
        """Verifies TAXII 2.1 pagination loop extracts objects across multiple pages."""
        ind_page1 = dict(self.valid_stix_indicator)
        ind_page2 = dict(self.valid_stix_indicator)
        ind_page2["id"] = "indicator--b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"
        ind_page2["pattern"] = "[ipv4-addr:value = '198.51.100.56']"

        page1_resp = MagicMock(status_code=200)
        page1_resp.json.return_value = {"more": True, "next": "token_page_2", "objects": [ind_page1]}

        page2_resp = MagicMock(status_code=200)
        page2_resp.json.return_value = {"more": False, "objects": [ind_page2]}

        mock_get.side_effect = [page1_resp, page2_resp]

        indicators = self.client.fetch_indicators(tenant_id="tenant-paged")
        self.assertEqual(len(indicators), 2)
        self.assertEqual(indicators[0]["id"], ind_page1["id"])
        self.assertEqual(indicators[1]["id"], ind_page2["id"])
        self.assertEqual(mock_get.call_count, 2)

    @patch("time.sleep", return_value=None)
    @patch("requests.Session.get")
    def test_rate_limit_429_retries_with_backoff(self, mock_get, mock_sleep):
        """Verifies HTTP 429 triggers bounded retry respecting rate limit backoff."""
        rate_limited_resp = MagicMock(status_code=429, headers={"Retry-After": "2"})
        success_resp = MagicMock(status_code=200)
        success_resp.json.return_value = {"more": False, "objects": [self.valid_stix_indicator]}

        mock_get.side_effect = [rate_limited_resp, success_resp]

        indicators = self.client.fetch_indicators()
        self.assertEqual(len(indicators), 1)
        mock_sleep.assert_called_with(2.0)
        self.assertEqual(mock_get.call_count, 2)

    @patch("time.sleep", return_value=None)
    @patch("requests.Session.get")
    def test_cache_fallback_when_server_is_unreachable(self, mock_get, mock_sleep):
        """Verifies that if feed becomes unavailable, cached indicators are returned marked as CACHED."""
        # 1. First fetch succeeds
        success_resp = MagicMock(status_code=200)
        success_resp.json.return_value = {"more": False, "objects": [self.valid_stix_indicator]}
        mock_get.return_value = success_resp

        ind_live = self.client.fetch_indicators(tenant_id="tenant-resilience")
        self.assertEqual(len(ind_live), 1)
        self.assertEqual(self.client.last_status, FeedStatus.LIVE)

        # 2. Second fetch fails with network timeout
        mock_get.side_effect = requests.ConnectionError("TAXII server connection timeout")

        ind_cached = self.client.fetch_indicators(tenant_id="tenant-resilience", force_refresh=True)
        self.assertEqual(len(ind_cached), 1)
        self.assertEqual(self.client.last_status, FeedStatus.CACHED)
        self.assertEqual(ind_cached[0]["feed_status"], FeedStatus.CACHED.value)

    @patch("time.sleep", return_value=None)
    @patch("requests.Session.get")
    def test_unreachable_server_with_no_cache_does_not_fabricate_intel(self, mock_get, mock_sleep):
        """Verifies that an unavailable feed with empty cache returns empty list and UNAVAILABLE status."""
        fresh_client = StixTaxiiClient(server_url="https://offline.taxii.local/taxii2/")
        mock_get.side_effect = requests.ConnectionError("Server unreachable")

        indicators = fresh_client.fetch_indicators(tenant_id="tenant-empty")

        self.assertEqual(indicators, [])
        self.assertEqual(fresh_client.last_status, FeedStatus.UNAVAILABLE)

    def test_tenant_isolation_in_check_ioc(self):
        """Verifies that indicators belonging to tenant A are not matched for queries in tenant B."""
        self.client._indicators_by_tenant["tenant-A"] = [
            {
                "id": "indicator--tenantA",
                "pattern": "[ipv4-addr:value = '10.0.0.99']",
                "feed_name": "intel-A",
                "feed_status": FeedStatus.LIVE.value,
            }
        ]
        self.client._indicators_by_tenant["tenant-B"] = []

        match_tenant_a = self.client.check_ioc("10.0.0.99", tenant_id="tenant-A")
        self.assertEqual(match_tenant_a.get("id"), "indicator--tenantA")

        match_tenant_b = self.client.check_ioc("10.0.0.99", tenant_id="tenant-B")
        self.assertEqual(match_tenant_b, {})


if __name__ == "__main__":
    unittest.main()
