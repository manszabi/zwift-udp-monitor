"""
test_zwift_api_polling.py – Unit tests for zwift_api_polling.py

Uses unittest with mocked HTTP calls so no real Zwift credentials are needed.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

import os
import tempfile

from zwift_api_polling import (
    BROADCAST_HOST,
    BROADCAST_PORT,
    DEFAULT_POLL_INTERVAL,
    SETTINGS_FILE,
    RateLimitError,
    UDPBroadcaster,
    ZwiftAPIClient,
    ZwiftAuth,
    ZwiftDataStore,
    ProtobufDecoder,
    _parse_protobuf_player_state,
    _sleep_remainder,
    load_settings,
    save_settings,
    resolve_credentials,
    build_arg_parser,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_token_response(
    access_token: str = "test_access",
    refresh_token: str = "test_refresh",
    expires_in: int = 3600,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
    }
    resp.raise_for_status.return_value = None
    return resp


def _mock_json_response(payload, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"Content-Type": "application/json"}
    resp.json.return_value = payload
    if status_code >= 400:
        import requests
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            f"{status_code} Error"
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


def _mock_binary_response(
    content: bytes,
    content_type: str = "application/x-protobuf",
    status_code: int = 200,
) -> MagicMock:
    """Create a mock response with binary content and a non-JSON Content-Type."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"Content-Type": content_type}
    resp.content = content
    resp.json.side_effect = ValueError("Not JSON")
    if status_code >= 400:
        import requests
        resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            f"{status_code} Error"
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

# Manually encoded protobuf PlayerState: riderId=123, speed=36000000 mm/h
# (36 km/h), cadenceUHz=1000000 (60 RPM), heartrate=160, power=250.
# Each field is encoded as (tag_varint | value_varint) per the protobuf spec.
_SAMPLE_PLAYER_STATE_PROTO = b'\x08{0\x80\xa2\x95\x11H\xc0\x84=X\xa0\x01`\xfa\x01'


# ---------------------------------------------------------------------------
# ZwiftAuth tests
# ---------------------------------------------------------------------------


class TestZwiftAuth(unittest.TestCase):
    """Tests for the OAuth2 authentication/token lifecycle."""

    @patch("zwift_api_polling.requests.post")
    def test_login_stores_tokens(self, mock_post):
        mock_post.return_value = _mock_token_response("tok_abc", "ref_xyz", 3600)
        auth = ZwiftAuth("user@example.com", "s3cr3t")
        auth.login()
        self.assertEqual(auth.access_token, "tok_abc")

    @patch("zwift_api_polling.requests.post")
    def test_login_sets_expiry(self, mock_post):
        mock_post.return_value = _mock_token_response(expires_in=7200)
        auth = ZwiftAuth("u", "p")
        before = time.time()
        auth.login()
        # expires_at should be approximately now + 7200
        self.assertGreater(auth._expires_at, before + 7190)
        self.assertLess(auth._expires_at, before + 7210)

    @patch("zwift_api_polling.requests.post")
    def test_ensure_valid_token_no_refresh_needed(self, mock_post):
        """ensure_valid_token should NOT call post when token is still fresh."""
        mock_post.return_value = _mock_token_response()
        auth = ZwiftAuth("u", "p")
        auth.login()
        call_count_after_login = mock_post.call_count
        auth._expires_at = time.time() + 3600  # far future
        auth.ensure_valid_token()
        self.assertEqual(mock_post.call_count, call_count_after_login)

    @patch("zwift_api_polling.requests.post")
    def test_ensure_valid_token_refresh_when_close_to_expiry(self, mock_post):
        """ensure_valid_token should refresh when token expires within buffer."""
        mock_post.return_value = _mock_token_response("new_tok", "new_ref", 3600)
        auth = ZwiftAuth("u", "p")
        auth._access_token = "old_tok"
        auth._refresh_token = "old_ref"
        auth._expires_at = time.time() + 10  # within TOKEN_REFRESH_BUFFER (30s)
        auth.ensure_valid_token()
        self.assertEqual(auth.access_token, "new_tok")
        mock_post.assert_called_once()

    @patch("zwift_api_polling.requests.post")
    def test_refresh_falls_back_to_login_on_failure(self, mock_post):
        """On refresh failure, _refresh should fall back to full login."""
        import requests as req_lib

        login_resp = _mock_token_response("fresh_tok")
        # First call (refresh) raises HTTPError; second call (login) succeeds
        mock_post.side_effect = [
            req_lib.exceptions.HTTPError("401"),
            login_resp,
        ]
        auth = ZwiftAuth("u", "p")
        auth._refresh_token = "stale"
        auth._expires_at = time.time() - 1  # already expired
        auth.ensure_valid_token()
        self.assertEqual(auth.access_token, "fresh_tok")

    @patch("zwift_api_polling.requests.post")
    def test_login_raises_on_http_error(self, mock_post):
        import requests as req_lib
        mock_post.return_value = MagicMock(
            raise_for_status=MagicMock(
                side_effect=req_lib.exceptions.HTTPError("401 Unauthorized")
            )
        )
        auth = ZwiftAuth("bad_user", "bad_pass")
        with self.assertRaises(req_lib.exceptions.HTTPError):
            auth.login()


# ---------------------------------------------------------------------------
# ZwiftAPIClient tests
# ---------------------------------------------------------------------------


class TestZwiftAPIClient(unittest.TestCase):
    """Tests for the REST API wrapper."""

    def _make_client(self, access_token: str = "tok") -> ZwiftAPIClient:
        auth = MagicMock(spec=ZwiftAuth)
        auth.access_token = access_token
        return ZwiftAPIClient(auth)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_profile_returns_dict(self, mock_get):
        mock_get.return_value = _mock_json_response({"id": 99999, "firstName": "Test"})
        client = self._make_client()
        profile = client.get_profile()
        self.assertEqual(profile["id"], 99999)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_player_state_success(self, mock_get):
        mock_get.return_value = _mock_binary_response(_SAMPLE_PLAYER_STATE_PROTO)
        client = self._make_client()
        result = client.get_player_state(world_id=1, rider_id=123)
        self.assertEqual(result["power"], 250)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_player_state_returns_none_on_404(self, mock_get):
        mock_get.return_value = _mock_json_response({}, status_code=404)
        client = self._make_client()
        result = client.get_player_state(world_id=1, rider_id=123)
        self.assertIsNone(result)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_player_state_raises_rate_limit_error(self, mock_get):
        mock_get.return_value = _mock_json_response({}, status_code=429)
        client = self._make_client()
        with self.assertRaises(RateLimitError):
            client.get_player_state(world_id=1, rider_id=123)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_active_world_returns_world_id(self, mock_get):
        activities = [{"worldId": 3, "name": "Watopia"}]
        mock_get.return_value = _mock_json_response(activities)
        client = self._make_client()
        world_id = client.get_active_world(rider_id=123)
        self.assertEqual(world_id, 3)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_active_world_returns_none_when_not_riding(self, mock_get):
        mock_get.return_value = _mock_json_response([], status_code=200)
        client = self._make_client()
        result = client.get_active_world(rider_id=123)
        self.assertIsNone(result)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_active_world_returns_none_on_404(self, mock_get):
        mock_get.return_value = _mock_json_response({}, status_code=404)
        client = self._make_client()
        result = client.get_active_world(rider_id=123)
        self.assertIsNone(result)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_active_world_raises_rate_limit_error(self, mock_get):
        mock_get.return_value = _mock_json_response({}, status_code=429)
        client = self._make_client()
        with self.assertRaises(RateLimitError):
            client.get_active_world(rider_id=123)


# ---------------------------------------------------------------------------
# ProtobufDecoder and _parse_protobuf_player_state tests
# ---------------------------------------------------------------------------


class TestProtobufDecoder(unittest.TestCase):
    """Tests for the minimal protobuf field parser."""

    def test_parse_fields_returns_dict(self):
        fields = ProtobufDecoder.parse_fields(_SAMPLE_PLAYER_STATE_PROTO)
        self.assertEqual(fields[1], 123)    # riderId
        self.assertEqual(fields[6], 36000000)  # speed mm/h
        self.assertEqual(fields[9], 1000000)   # cadence µHz
        self.assertEqual(fields[11], 160)  # heartrate
        self.assertEqual(fields[12], 250)  # power

    def test_parse_fields_empty_bytes(self):
        fields = ProtobufDecoder.parse_fields(b"")
        self.assertEqual(fields, {})

    def test_parse_fields_truncated_data(self):
        # Should not raise; truncated varint falls back gracefully
        fields = ProtobufDecoder.parse_fields(b"\x08")
        self.assertIsInstance(fields, dict)

    def test_parse_protobuf_player_state_converts_units(self):
        state = _parse_protobuf_player_state(_SAMPLE_PLAYER_STATE_PROTO)
        self.assertIsNotNone(state)
        self.assertEqual(state["riderId"], 123)
        self.assertEqual(state["power"], 250)
        self.assertEqual(state["heartrate"], 160)
        self.assertEqual(state["cadence"], 60)    # 1 000 000 µHz → 60 RPM
        self.assertAlmostEqual(state["speed_kmh"], 36.0, places=1)

    def test_parse_protobuf_player_state_returns_none_for_empty(self):
        result = _parse_protobuf_player_state(b"")
        self.assertIsNone(result)

    def test_parse_protobuf_player_state_returns_none_when_no_meaningful_data(self):
        # A blob with only zero-value fields should yield None
        result = _parse_protobuf_player_state(b"\x00")  # unknown/empty
        self.assertIsNone(result)


class TestZwiftAPIClientProtobuf(unittest.TestCase):
    """Tests for Content-Type handling and protobuf fallback in ZwiftAPIClient."""

    def _make_client(self, access_token: str = "tok") -> ZwiftAPIClient:
        auth = MagicMock(spec=ZwiftAuth)
        auth.access_token = access_token
        return ZwiftAPIClient(auth)

    # -- get_player_state -----------------------------------------------------

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_player_state_protobuf_response(self, mock_get):
        """Binary protobuf response should be decoded into a usable dict."""
        mock_get.return_value = _mock_binary_response(_SAMPLE_PLAYER_STATE_PROTO)
        client = self._make_client()
        state = client.get_player_state(world_id=1, rider_id=123)
        self.assertIsNotNone(state)
        self.assertEqual(state["power"], 250)
        self.assertEqual(state["heartrate"], 160)
        self.assertEqual(state["cadence"], 60)
        self.assertAlmostEqual(state["speed_kmh"], 36.0, places=1)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_player_state_protobuf_empty_returns_none(self, mock_get):
        """Empty binary response means rider not in world → None."""
        mock_get.return_value = _mock_binary_response(b"")
        client = self._make_client()
        result = client.get_player_state(world_id=1, rider_id=123)
        self.assertIsNone(result)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_player_state_returns_none_on_406(self, mock_get):
        """406 Not Acceptable (relay rejects Accept header) → None, no exception."""
        mock_get.return_value = _mock_json_response({}, status_code=406)
        client = self._make_client()
        result = client.get_player_state(world_id=1, rider_id=123)
        self.assertIsNone(result)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_player_state_does_not_send_accept_json_header(self, mock_get):
        """Relay endpoint must NOT receive Accept: application/json (only protobuf)."""
        mock_get.return_value = _mock_binary_response(_SAMPLE_PLAYER_STATE_PROTO)
        client = self._make_client()
        client.get_player_state(world_id=1, rider_id=1)
        _, kwargs = mock_get.call_args
        headers = kwargs.get("headers", {})
        self.assertNotEqual(headers.get("Accept"), "application/json")
        self.assertEqual(headers.get("Zwift-Api-Version"), "2.6")

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_profile_sends_accept_json_header(self, mock_get):
        """get_profile should send Accept: application/json (endpoint supports JSON)."""
        mock_get.return_value = _mock_json_response({"id": 99})
        client = self._make_client()
        client.get_profile()
        _, kwargs = mock_get.call_args
        headers = kwargs.get("headers", {})
        self.assertEqual(headers.get("Accept"), "application/json")

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_active_world_sends_accept_json_header(self, mock_get):
        """get_active_world should send Accept: application/json (endpoint supports JSON)."""
        mock_get.return_value = _mock_json_response([{"worldId": 1}])
        client = self._make_client()
        client.get_active_world(rider_id=123)
        _, kwargs = mock_get.call_args
        headers = kwargs.get("headers", {})
        self.assertEqual(headers.get("Accept"), "application/json")

    # -- get_active_world -----------------------------------------------------

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_active_world_json_decode_error_tries_profile(self, mock_get):
        """JSONDecodeError on activities should fall back to profile endpoint."""
        activities_resp = MagicMock()
        activities_resp.status_code = 200
        activities_resp.headers = {"Content-Type": "application/json"}
        activities_resp.content = b"\x00\x01invalid"
        activities_resp.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
        activities_resp.raise_for_status.return_value = None

        profile_resp = _mock_json_response({"id": 123, "worldId": 5})

        mock_get.side_effect = [activities_resp, profile_resp]
        client = self._make_client()
        world_id = client.get_active_world(rider_id=123)
        self.assertEqual(world_id, 5)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_active_world_protobuf_response_tries_profile(self, mock_get):
        """Binary activities response should fall back to profile endpoint."""
        activities_resp = _mock_binary_response(b"\x08\x01")
        profile_resp = _mock_json_response({"id": 123, "worldId": 2})

        mock_get.side_effect = [activities_resp, profile_resp]
        client = self._make_client()
        world_id = client.get_active_world(rider_id=123)
        self.assertEqual(world_id, 2)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_world_from_profile_returns_world_id(self, mock_get):
        """_get_world_from_profile should parse worldId from profile JSON."""
        activities_resp = _mock_json_response([], status_code=200)
        profile_resp = _mock_json_response({"id": 456, "worldId": 7})
        mock_get.side_effect = [activities_resp, profile_resp]
        client = self._make_client()
        world_id = client.get_active_world(rider_id=456)
        self.assertEqual(world_id, 7)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_world_from_profile_returns_none_when_not_active(self, mock_get):
        """Profile with no worldId should return None."""
        activities_resp = _mock_json_response([], status_code=200)
        profile_resp = _mock_json_response({"id": 456})
        mock_get.side_effect = [activities_resp, profile_resp]
        client = self._make_client()
        result = client.get_active_world(rider_id=456)
        self.assertIsNone(result)

    @patch("zwift_api_polling.requests.Session.get")
    def test_get_world_from_profile_handles_non_json_response(self, mock_get):
        """Non-JSON profile response should return None gracefully."""
        activities_resp = _mock_json_response([], status_code=200)
        profile_resp = _mock_binary_response(b"\x08\x01")
        mock_get.side_effect = [activities_resp, profile_resp]
        client = self._make_client()
        result = client.get_active_world(rider_id=456)
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# ZwiftDataStore tests
# ---------------------------------------------------------------------------


class TestZwiftDataStore(unittest.TestCase):
    """Tests for the thread-safe data store."""

    def test_initial_state_is_zero(self):
        store = ZwiftDataStore()
        data = store.get_data()
        self.assertEqual(data["power"], 0)
        self.assertEqual(data["heartrate"], 0)
        self.assertEqual(data["cadence"], 0)
        self.assertEqual(data["speed_kmh"], 0.0)
        self.assertEqual(data["rider_id"], 0)
        self.assertEqual(data["total_packets"], 0)

    def test_update_stores_values(self):
        store = ZwiftDataStore()
        store.update({
            "power": 200,
            "heartrate": 155,
            "cadence": 85,
            "speed": 30.5,
            "riderId": 42,
        })
        data = store.get_data()
        self.assertEqual(data["power"], 200)
        self.assertEqual(data["heartrate"], 155)
        self.assertEqual(data["cadence"], 85)
        self.assertEqual(data["speed_kmh"], 30.5)
        self.assertEqual(data["rider_id"], 42)
        self.assertEqual(data["total_packets"], 1)

    def test_update_increments_total_polls(self):
        store = ZwiftDataStore()
        for _ in range(5):
            store.update({"power": 100})
        self.assertEqual(store.total_polls, 5)

    def test_get_data_contains_required_keys(self):
        """Output dict must contain all keys expected by smart_fan_controller."""
        store = ZwiftDataStore()
        data = store.get_data()
        required = {"power", "heartrate", "cadence", "speed_kmh",
                    "rider_id", "last_update", "total_packets", "timestamp"}
        self.assertEqual(required, set(data.keys()))

    def test_get_data_is_json_serializable(self):
        store = ZwiftDataStore()
        store.update({
            "power": 300,
            "heartrate": 170,
            "cadence": 95,
            "speed": 40.2,
            "riderId": 7,
        })
        data = store.get_data()
        # Must not raise
        serialized = json.dumps(data)
        parsed = json.loads(serialized)
        self.assertEqual(parsed["power"], 300)

    def test_speed_accepts_speed_kmh_key(self):
        """Update should also accept 'speed_kmh' key (e.g. if already converted)."""
        store = ZwiftDataStore()
        store.update({"speed_kmh": 25.5})
        data = store.get_data()
        self.assertEqual(data["speed_kmh"], 25.5)

    def test_update_keeps_previous_rider_id_when_not_provided(self):
        store = ZwiftDataStore()
        store.update({"riderId": 99})
        store.update({"power": 150})  # no rider_id in this update
        data = store.get_data()
        self.assertEqual(data["rider_id"], 99)

    def test_thread_safety(self):
        """Concurrent updates must not corrupt the store."""
        store = ZwiftDataStore()
        errors = []

        def writer():
            try:
                for _ in range(100):
                    store.update({"power": 100, "heartrate": 150})
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=writer) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(store.total_polls, 500)


# ---------------------------------------------------------------------------
# UDPBroadcaster tests
# ---------------------------------------------------------------------------


class TestUDPBroadcaster(unittest.TestCase):
    """Tests for the UDP broadcast helper."""

    def test_send_delivers_valid_json(self):
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.bind(("127.0.0.1", 0))
        port = recv_sock.getsockname()[1]
        recv_sock.settimeout(2.0)

        broadcaster = UDPBroadcaster(host="127.0.0.1", port=port)
        data = {
            "power": 245,
            "heartrate": 158,
            "cadence": 92,
            "speed_kmh": 34.2,
            "rider_id": 123456,
            "last_update": 1709571234.56,
            "total_packets": 1842,
            "timestamp": 1709571234.57,
        }
        try:
            broadcaster.send(data)
            raw, _ = recv_sock.recvfrom(4096)
            received = json.loads(raw.decode("utf-8"))
            self.assertEqual(received["power"], 245)
            self.assertEqual(received["rider_id"], 123456)
        finally:
            broadcaster.close()
            recv_sock.close()

    def test_log_console_output(self):
        """log_console should print without raising."""
        import io
        broadcaster = UDPBroadcaster()
        data = {
            "power": 200,
            "heartrate": 150,
            "cadence": 80,
            "speed_kmh": 28.0,
            "total_packets": 10,
        }
        # Should not raise
        with patch("builtins.print") as mock_print:
            broadcaster.log_console(data)
            mock_print.assert_called_once()
        broadcaster.close()


# ---------------------------------------------------------------------------
# sleep_remainder tests
# ---------------------------------------------------------------------------


class TestSleepRemainder(unittest.TestCase):
    def test_sleeps_correct_duration(self):
        stop_event = threading.Event()
        start = time.time()
        loop_start = time.time() - 0.1  # pretend 0.1s already elapsed
        _sleep_remainder(loop_start, 0.3, stop_event)
        elapsed = time.time() - start
        self.assertGreater(elapsed, 0.15)
        self.assertLess(elapsed, 0.5)

    def test_no_sleep_when_interval_already_elapsed(self):
        stop_event = threading.Event()
        loop_start = time.time() - 2.0  # 2s already elapsed for a 1s interval
        start = time.time()
        _sleep_remainder(loop_start, 1.0, stop_event)
        elapsed = time.time() - start
        self.assertLess(elapsed, 0.1)  # should return almost immediately

    def test_respects_stop_event(self):
        stop_event = threading.Event()
        stop_event.set()  # already stopped
        start = time.time()
        _sleep_remainder(time.time(), 5.0, stop_event)
        elapsed = time.time() - start
        self.assertLess(elapsed, 0.5)  # should return quickly


# ---------------------------------------------------------------------------
# load_settings / save_settings tests
# ---------------------------------------------------------------------------


class TestLoadSettings(unittest.TestCase):
    def test_load_settings_file_not_found(self):
        """Non-existent path returns default values."""
        result = load_settings("/nonexistent/path/settings.json")
        self.assertEqual(result["username"], "")
        self.assertEqual(result["password"], "")
        self.assertEqual(result["broadcast_host"], BROADCAST_HOST)
        self.assertEqual(result["broadcast_port"], BROADCAST_PORT)
        self.assertEqual(result["poll_interval"], DEFAULT_POLL_INTERVAL)

    def test_load_settings_valid_json(self):
        """All fields are read from a valid JSON file."""
        data = {
            "username": "user@example.com",
            "password": "s3cr3t",
            "broadcast_host": "192.168.1.100",
            "broadcast_port": 8080,
            "poll_interval": 2.5,
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            json.dump(data, tmp)
            tmp_path = tmp.name
        try:
            result = load_settings(tmp_path)
            self.assertEqual(result["username"], "user@example.com")
            self.assertEqual(result["password"], "s3cr3t")
            self.assertEqual(result["broadcast_host"], "192.168.1.100")
            self.assertEqual(result["broadcast_port"], 8080)
            self.assertAlmostEqual(result["poll_interval"], 2.5)
        finally:
            os.unlink(tmp_path)

    def test_load_settings_invalid_json(self):
        """Invalid JSON triggers a warning and returns defaults."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            tmp.write("not valid json{{{")
            tmp_path = tmp.name
        try:
            with patch("builtins.print") as mock_print:
                result = load_settings(tmp_path)
            mock_print.assert_called_once()
            self.assertEqual(result["broadcast_host"], BROADCAST_HOST)
            self.assertEqual(result["broadcast_port"], BROADCAST_PORT)
            self.assertEqual(result["poll_interval"], DEFAULT_POLL_INTERVAL)
        finally:
            os.unlink(tmp_path)

    def test_load_settings_missing_keys(self):
        """Missing keys are filled with defaults."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            json.dump({"username": "only_user"}, tmp)
            tmp_path = tmp.name
        try:
            result = load_settings(tmp_path)
            self.assertEqual(result["username"], "only_user")
            self.assertEqual(result["password"], "")
            self.assertEqual(result["broadcast_host"], BROADCAST_HOST)
            self.assertEqual(result["broadcast_port"], BROADCAST_PORT)
            self.assertEqual(result["poll_interval"], DEFAULT_POLL_INTERVAL)
        finally:
            os.unlink(tmp_path)

    def test_load_settings_wrong_types(self):
        """Wrong-typed values are replaced with defaults and a warning is printed."""
        data = {
            "username": 12345,          # should be str
            "broadcast_host": "",       # should be non-empty str
            "broadcast_port": "8080",   # should be int
            "poll_interval": "fast",    # should be number
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            json.dump(data, tmp)
            tmp_path = tmp.name
        try:
            with patch("builtins.print") as mock_print:
                result = load_settings(tmp_path)
            self.assertGreater(mock_print.call_count, 0)
            self.assertEqual(result["username"], "")         # default
            self.assertEqual(result["broadcast_host"], BROADCAST_HOST)   # default
            self.assertEqual(result["broadcast_port"], BROADCAST_PORT)   # default
            self.assertEqual(result["poll_interval"], DEFAULT_POLL_INTERVAL)  # default
        finally:
            os.unlink(tmp_path)

    def test_load_settings_port_out_of_range(self):
        """Port outside 1-65535 is replaced with default."""
        data = {"broadcast_port": 70000}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            json.dump(data, tmp)
            tmp_path = tmp.name
        try:
            with patch("builtins.print"):
                result = load_settings(tmp_path)
            self.assertEqual(result["broadcast_port"], BROADCAST_PORT)
        finally:
            os.unlink(tmp_path)

    def test_load_settings_negative_poll_interval(self):
        """Negative poll_interval is replaced with default."""
        data = {"poll_interval": -1.0}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            json.dump(data, tmp)
            tmp_path = tmp.name
        try:
            with patch("builtins.print"):
                result = load_settings(tmp_path)
            self.assertEqual(result["poll_interval"], DEFAULT_POLL_INTERVAL)
        finally:
            os.unlink(tmp_path)


class TestSaveSettings(unittest.TestCase):
    def test_save_settings_creates_file(self):
        """save_settings creates the file if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "settings.json")
            save_settings(path, {"username": "u", "password": "p"})
            self.assertTrue(os.path.exists(path))

    def test_save_settings_content_is_valid_json(self):
        """The saved file contains valid JSON with the expected content."""
        data = {
            "username": "user@example.com",
            "password": "secret",
            "broadcast_host": "127.0.0.1",
            "broadcast_port": 7878,
            "poll_interval": 5.0,
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            tmp_path = tmp.name
        try:
            save_settings(tmp_path, data)
            with open(tmp_path) as fh:
                loaded = json.load(fh)
            self.assertEqual(loaded, data)
        finally:
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Credential resolution tests
# ---------------------------------------------------------------------------


class TestResolveCredentials(unittest.TestCase):
    def _args(self, username="", password=""):
        parser = build_arg_parser()
        return parser.parse_args([])

    def test_from_cli_args(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--username", "cli_user", "--password", "cli_pass"])
        with patch.dict("os.environ", {}, clear=True):
            user, pw = resolve_credentials(args)
        self.assertEqual(user, "cli_user")
        self.assertEqual(pw, "cli_pass")

    def test_from_env_vars(self):
        parser = build_arg_parser()
        args = parser.parse_args([])
        env = {"ZWIFT_USERNAME": "env_user", "ZWIFT_PASSWORD": "env_pass"}
        with patch.dict("os.environ", env):
            user, pw = resolve_credentials(args)
        self.assertEqual(user, "env_user")
        self.assertEqual(pw, "env_pass")

    def test_cli_takes_priority_over_env(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--username", "cli_user", "--password", "cli_pass"])
        env = {"ZWIFT_USERNAME": "env_user", "ZWIFT_PASSWORD": "env_pass"}
        with patch.dict("os.environ", env):
            user, pw = resolve_credentials(args)
        self.assertEqual(user, "cli_user")
        self.assertEqual(pw, "cli_pass")

    def test_prompts_when_not_provided(self):
        parser = build_arg_parser()
        args = parser.parse_args([])
        with patch.dict("os.environ", {}, clear=True):
            with patch("builtins.input", return_value="prompt_user"):
                with patch("getpass.getpass", return_value="prompt_pass"):
                    # settings_path=None means no saving
                    user, pw = resolve_credentials(args, settings={}, settings_path=None)
        self.assertEqual(user, "prompt_user")
        self.assertEqual(pw, "prompt_pass")

    def test_from_settings_file(self):
        """If neither CLI nor env provides credentials, read from settings dict."""
        parser = build_arg_parser()
        args = parser.parse_args([])
        settings = {"username": "json_user", "password": "json_pass"}
        with patch.dict("os.environ", {}, clear=True):
            user, pw = resolve_credentials(args, settings=settings)
        self.assertEqual(user, "json_user")
        self.assertEqual(pw, "json_pass")

    def test_cli_takes_priority_over_settings(self):
        """CLI args take precedence over settings file."""
        parser = build_arg_parser()
        args = parser.parse_args(["--username", "cli_user", "--password", "cli_pass"])
        settings = {"username": "json_user", "password": "json_pass"}
        with patch.dict("os.environ", {}, clear=True):
            user, pw = resolve_credentials(args, settings=settings)
        self.assertEqual(user, "cli_user")
        self.assertEqual(pw, "cli_pass")

    def test_env_takes_priority_over_settings(self):
        """Environment variables take precedence over settings file."""
        parser = build_arg_parser()
        args = parser.parse_args([])
        settings = {"username": "json_user", "password": "json_pass"}
        env = {"ZWIFT_USERNAME": "env_user", "ZWIFT_PASSWORD": "env_pass"}
        with patch.dict("os.environ", env):
            user, pw = resolve_credentials(args, settings=settings)
        self.assertEqual(user, "env_user")
        self.assertEqual(pw, "env_pass")

    def test_saves_settings_after_prompt(self):
        """When credentials are entered via prompt, settings are saved to file."""
        parser = build_arg_parser()
        args = parser.parse_args([])
        settings = {
            "username": "",
            "password": "",
            "broadcast_host": BROADCAST_HOST,
            "broadcast_port": BROADCAST_PORT,
            "poll_interval": DEFAULT_POLL_INTERVAL,
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as tmp:
            tmp_path = tmp.name
        os.unlink(tmp_path)  # remove so save creates it fresh

        try:
            with patch.dict("os.environ", {}, clear=True):
                with patch("builtins.input", return_value="prompt_user"):
                    with patch("getpass.getpass", return_value="prompt_pass"):
                        with patch("builtins.print"):
                            user, pw = resolve_credentials(
                                args, settings=settings, settings_path=tmp_path
                            )
            self.assertEqual(user, "prompt_user")
            self.assertEqual(pw, "prompt_pass")
            self.assertTrue(os.path.exists(tmp_path))
            with open(tmp_path) as fh:
                saved = json.load(fh)
            self.assertEqual(saved["username"], "prompt_user")
            self.assertEqual(saved["password"], "prompt_pass")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Argument parser tests
# ---------------------------------------------------------------------------


class TestArgParser(unittest.TestCase):
    def test_defaults(self):
        parser = build_arg_parser()
        args = parser.parse_args([])
        self.assertEqual(args.username, "")
        self.assertEqual(args.password, "")
        self.assertIsNone(args.poll_interval)
        self.assertFalse(args.debug)
        self.assertFalse(args.no_fan_controller)

    def test_custom_poll_interval(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--poll-interval", "2.5"])
        self.assertEqual(args.poll_interval, 2.5)

    def test_debug_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--debug"])
        self.assertTrue(args.debug)

    def test_no_fan_controller_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--no-fan-controller"])
        self.assertTrue(args.no_fan_controller)


# ---------------------------------------------------------------------------
# Polling loop tests (high-level integration with mocks)
# ---------------------------------------------------------------------------


class TestPollingLoop(unittest.TestCase):
    """Integration-style tests for run_polling_loop using mocked API calls."""

    def _make_dependencies(self, world_id=1, rider_id=123):
        auth = MagicMock(spec=ZwiftAuth)
        auth.access_token = "tok"
        auth.ensure_valid_token = MagicMock()

        client = MagicMock(spec=ZwiftAPIClient)
        client.get_active_world.return_value = world_id
        client.get_player_state.return_value = {
            "riderId": rider_id,
            "power": 250,
            "heartrate": 160,
            "cadence": 90,
            "speed": 35.0,
        }

        store = ZwiftDataStore()
        broadcaster = MagicMock(spec=UDPBroadcaster)
        stop_event = threading.Event()
        return auth, client, store, broadcaster, stop_event

    def test_loop_sends_data_and_stops(self):
        from zwift_api_polling import run_polling_loop

        auth, client, store, broadcaster, stop_event = self._make_dependencies()

        def stop_after_one_iteration(*args, **kwargs):
            stop_event.set()

        broadcaster.send.side_effect = stop_after_one_iteration

        run_polling_loop(
            client, auth, store, broadcaster, stop_event,
            rider_id=123, poll_interval=0.01,
        )

        broadcaster.send.assert_called_once()
        data = broadcaster.send.call_args[0][0]
        self.assertEqual(data["power"], 250)
        self.assertIn("heartrate", data)
        # Verify the data is JSON-serializable (same contract as udp_monitor)
        json.dumps(data)

    def test_loop_handles_none_world(self):
        """If get_active_world returns None, loop should skip without crashing."""
        from zwift_api_polling import run_polling_loop

        auth, client, store, broadcaster, stop_event = self._make_dependencies()
        client.get_active_world.return_value = None

        iterations = [0]

        def fake_sleep(timeout):
            iterations[0] += 1
            if iterations[0] >= 2:
                stop_event.set()
            return False  # event not set

        stop_event.wait = fake_sleep

        run_polling_loop(
            client, auth, store, broadcaster, stop_event,
            rider_id=123, poll_interval=0.01,
        )

        broadcaster.send.assert_not_called()

    def test_loop_resets_world_on_player_not_found(self):
        """If get_player_state returns None, world_id should reset."""
        from zwift_api_polling import run_polling_loop

        auth, client, store, broadcaster, stop_event = self._make_dependencies()
        # First call: player not found; second+ calls: stop
        client.get_player_state.return_value = None

        iterations = [0]

        def fake_sleep(timeout):
            iterations[0] += 1
            if iterations[0] >= 2:
                stop_event.set()
            return False

        stop_event.wait = fake_sleep

        run_polling_loop(
            client, auth, store, broadcaster, stop_event,
            rider_id=123, poll_interval=0.01,
        )

        broadcaster.send.assert_not_called()

    def test_loop_backs_off_on_rate_limit(self):
        """RateLimitError should trigger a back-off sleep, not crash."""
        from zwift_api_polling import run_polling_loop, RATE_LIMIT_BACKOFF

        auth, client, store, broadcaster, stop_event = self._make_dependencies()
        call_count = [0]

        def raise_once(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RateLimitError("429")
            stop_event.set()
            return None

        client.get_player_state.side_effect = raise_once

        waits = []
        original_wait = stop_event.wait

        def capture_wait(timeout):
            waits.append(timeout)
            stop_event.set()  # stop after first wait
            return True

        stop_event.wait = capture_wait

        run_polling_loop(
            client, auth, store, broadcaster, stop_event,
            rider_id=123, poll_interval=0.01,
        )

        # The first wait should be the RATE_LIMIT_BACKOFF
        self.assertTrue(any(w == RATE_LIMIT_BACKOFF for w in waits))


if __name__ == "__main__":
    unittest.main()
