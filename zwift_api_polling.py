"""
zwift_api_polling.py – Zwift API alapú adatlekérés és továbbítás
Polls the Zwift HTTPS API for player state (power/HR/cadence/speed) and
broadcasts identical JSON to 127.0.0.1:7878 so smart_fan_controller.py
works with this script interchangeably with zwift_udp_monitor.py.

Credential handling (in priority order):
  1. --username / --password CLI flags
  2. ZWIFT_USERNAME / ZWIFT_PASSWORD environment variables
  3. zwift_api_settings.json file
  4. Interactive prompt (saved to zwift_api_settings.json if used)
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import socket
import struct
import subprocess
import sys
import time
import threading

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

__version__ = "1.0.0"

BROADCAST_HOST = "127.0.0.1"
BROADCAST_PORT = 7878
DEFAULT_POLL_INTERVAL = 5.0  # seconds

# Settings file – resolved relative to this script's directory
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zwift_api_settings.json")

ZWIFT_AUTH_URL = (
    "https://secure.zwift.com/auth/realms/zwift/protocol/openid-connect/token"
)
ZWIFT_API_BASE = "https://us-or-rly101.zwift.com"
ZWIFT_CLIENT_ID = "Zwift_Mobile_Link"

# How many seconds before expiry to proactively refresh the token
TOKEN_REFRESH_BUFFER = 30  # seconds

# Back-off for rate-limit (429) responses
RATE_LIMIT_BACKOFF = 5.0  # seconds

# Unit conversion factors (same as zwift_udp_monitor.py)
_MICROHERTZ_TO_RPM = 60 / 1_000_000   # cadenceUHz: µHz → RPM
_MM_PER_HOUR_TO_KM_PER_HOUR = 1 / 1_000_000  # speed: mm/h → km/h

# ---------------------------------------------------------------------------
# ProtobufDecoder – raw varint / field parser (no .proto compilation needed)
# Relay API endpoints return binary protobuf; this decoder handles wire types
# 0 (varint), 1 (64-bit fixed), 2 (length-delimited), and 5 (32-bit fixed).
# ---------------------------------------------------------------------------


class ProtobufDecoder:
    """Minimal protobuf decoder supporting wire types 0, 1, 2, and 5."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def _read_varint(self):
        result = 0
        shift = 0
        while self._pos < len(self._data):
            byte = self._data[self._pos]
            self._pos += 1
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                return result
            shift += 7
        raise ValueError("Truncated varint")

    def _read_bytes(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise ValueError(
                f"Not enough data: need {n}, have {len(self._data) - self._pos}"
            )
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def fields(self):
        """Yield (field_number, wire_type, value) tuples."""
        while self._pos < len(self._data):
            tag = self._read_varint()
            field_number = tag >> 3
            wire_type = tag & 0x07
            if wire_type == 0:
                value = self._read_varint()
            elif wire_type == 1:
                value = self._read_bytes(8)
            elif wire_type == 2:
                length = self._read_varint()
                value = self._read_bytes(length)
            elif wire_type == 5:
                value = self._read_bytes(4)
            else:
                break
            yield field_number, wire_type, value

    @classmethod
    def parse_fields(cls, data: bytes) -> dict:
        """Return {field_number: value} keeping the last value per field."""
        result = {}
        try:
            for field_number, _wt, value in cls(data).fields():
                result[field_number] = value
        except (ValueError, struct.error):
            pass
        return result


# PlayerState protobuf field numbers (from zwift_messages.proto)
_PS_FIELD_ID = 1
_PS_FIELD_SPEED = 6
_PS_FIELD_CADENCE_UHZ = 9
_PS_FIELD_HEARTRATE = 11
_PS_FIELD_POWER = 12


def _proto_to_int(value: int | bytes | None, default: int = 0) -> int:
    """Convert a protobuf field value (varint or fixed bytes) to int."""
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        if len(value) == 4:
            return struct.unpack("<I", value)[0]
        if len(value) == 8:
            return struct.unpack("<Q", value)[0]
    return default


def _parse_protobuf_player_state(data: bytes) -> dict | None:
    """Decode a raw PlayerState protobuf blob into a ZwiftDataStore-compatible dict.

    Returns *None* if the blob contains no meaningful data (all zeros).
    """
    fields = ProtobufDecoder.parse_fields(data)
    if not fields:
        return None
    speed_mmh = _proto_to_int(fields.get(_PS_FIELD_SPEED, 0))
    cadence_uhz = _proto_to_int(fields.get(_PS_FIELD_CADENCE_UHZ, 0))
    state = {
        "riderId": _proto_to_int(fields.get(_PS_FIELD_ID, 0)),
        "power": _proto_to_int(fields.get(_PS_FIELD_POWER, 0)),
        "heartrate": _proto_to_int(fields.get(_PS_FIELD_HEARTRATE, 0)),
        "cadence": round(cadence_uhz * _MICROHERTZ_TO_RPM) if cadence_uhz else 0,
        "speed_kmh": round(speed_mmh * _MM_PER_HOUR_TO_KM_PER_HOUR, 1) if speed_mmh else 0.0,
    }
    # Return None when riderId is zero; an active rider always has a valid ID
    if not state["riderId"]:
        return None
    return state


# ---------------------------------------------------------------------------
# ZwiftAuth – OAuth2 token lifecycle
# ---------------------------------------------------------------------------


class ZwiftAuth:
    """Authenticates with Zwift and manages access/refresh tokens in memory."""

    def __init__(self, username: str, password: str, *, debug: bool = False):
        self._username = username
        self._password = password
        self._debug = debug
        self._access_token: str = ""
        self._refresh_token: str = ""
        self._expires_at: float = 0.0  # Unix timestamp when access_token expires

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def login(self) -> None:
        """Perform initial username/password authentication."""
        data = {
            "client_id": ZWIFT_CLIENT_ID,
            "grant_type": "password",
            "username": self._username,
            "password": self._password,
        }
        resp = requests.post(ZWIFT_AUTH_URL, data=data, timeout=15)
        resp.raise_for_status()
        self._store_tokens(resp.json())
        if self._debug:
            print("[DEBUG] Bejelentkezés sikeres / Login successful")

    def ensure_valid_token(self) -> None:
        """Refresh the access token proactively if it is close to expiry."""
        if time.time() >= self._expires_at - TOKEN_REFRESH_BUFFER:
            self._refresh()

    @property
    def access_token(self) -> str:
        return self._access_token

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        """Attempt a token refresh; re-authenticates on failure."""
        if self._debug:
            print("[DEBUG] Token frissítése / Refreshing token …")
        try:
            data = {
                "client_id": ZWIFT_CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
            }
            resp = requests.post(ZWIFT_AUTH_URL, data=data, timeout=15)
            resp.raise_for_status()
            self._store_tokens(resp.json())
            if self._debug:
                print("[DEBUG] Token frissítve / Token refreshed")
        except requests.RequestException as exc:  # broad but not BaseException
            print(
                f"⚠️  Token frissítés sikertelen, újra bejelentkezés / "
                f"Token refresh failed, re-logging in: {exc}"
            )
            self.login()

    def _store_tokens(self, payload: dict) -> None:
        self._access_token = payload["access_token"]
        self._refresh_token = payload.get("refresh_token", "")
        expires_in = int(payload.get("expires_in", 3600))
        self._expires_at = time.time() + expires_in


# ---------------------------------------------------------------------------
# ZwiftAPIClient – REST calls
# ---------------------------------------------------------------------------


class ZwiftAPIClient:
    """Thin wrapper around the Zwift HTTPS REST API."""

    def __init__(self, auth: ZwiftAuth, *, debug: bool = False):
        self._auth = auth
        self._debug = debug
        self._session = requests.Session()

    def _headers(self) -> dict:
        """Base headers without Accept – callers add their own Accept if needed."""
        return {
            "Authorization": f"Bearer {self._auth.access_token}",
            "Zwift-Api-Version": "2.6",
        }

    def _json_headers(self) -> dict:
        """Headers for endpoints that support JSON responses."""
        h = self._headers()
        h["Accept"] = "application/json"
        return h

    def get_profile(self) -> dict:
        """Return the authenticated user's profile (contains ``id``)."""
        url = f"{ZWIFT_API_BASE}/api/profiles/me"
        resp = self._session.get(url, headers=self._json_headers(), timeout=10)
        resp.raise_for_status()
        return resp.json()

    def get_player_state(self, world_id: int, rider_id: int) -> dict | None:
        """Return the latest player state dict or *None* if not riding.

        Tries the relay/worlds endpoint which returns real-time protobuf data.
        Falls back gracefully when the player is not in a world.
        The relay endpoint only supports protobuf; JSON is never requested.
        """
        url = f"{ZWIFT_API_BASE}/relay/worlds/{world_id}/players/{rider_id}"
        resp = self._session.get(url, headers=self._headers(), timeout=10)
        if resp.status_code == 404:
            return None  # player not in this world
        if resp.status_code == 406:
            return None  # relay endpoint does not support the requested format
        if resp.status_code == 429:
            raise RateLimitError("Rate limited (429)")
        resp.raise_for_status()

        if self._debug:
            content_type = resp.headers.get("Content-Type", "")
            print(
                f"\n[DEBUG] Player state response"
                f"\n[DEBUG] Content-Type: {content_type!r}"
                f"\n[DEBUG] Response bytes[:64]: {resp.content[:64]!r}"
            )
        return _parse_protobuf_player_state(resp.content)

    def get_active_world(self, rider_id: int) -> int | None:
        """Try to determine the world the rider is currently in (1=Watopia etc.).

        Queries the activities endpoint; returns the worldId of the most recent
        in-progress activity, or *None* if the rider is not online.
        Falls back to the profile endpoint when the activities response is not
        valid JSON (e.g. protobuf) or contains no worldId.
        """
        url = f"{ZWIFT_API_BASE}/api/profiles/{rider_id}/activities"
        params = {"limit": 1}
        resp = self._session.get(
            url, headers=self._json_headers(), params=params, timeout=10
        )
        if resp.status_code in (404, 204):
            return None
        if resp.status_code == 429:
            raise RateLimitError("Rate limited (429)")
        resp.raise_for_status()

        content_type = resp.headers.get("Content-Type", "")
        activities = None
        if "application/json" in content_type:
            try:
                activities = resp.json()
            except json.JSONDecodeError as exc:
                if self._debug:
                    print(
                        f"\n[DEBUG] JSON decode error on activities: {exc}"
                        f"\n[DEBUG] Content-Type: {content_type}"
                        f"\n[DEBUG] Response bytes[:64]: {resp.content[:64]!r}"
                    )
        else:
            if self._debug:
                print(
                    f"\n[DEBUG] Non-JSON activities response"
                    f"\n[DEBUG] Content-Type: {content_type!r}"
                    f"\n[DEBUG] Response bytes[:64]: {resp.content[:64]!r}"
                )

        if activities:
            latest = activities[0] if isinstance(activities, list) else activities
            world_id = latest.get("worldId") or latest.get("world_id")
            if world_id:
                return world_id

        # Fallback: try the profile endpoint which may carry a current worldId
        return self._get_world_from_profile(rider_id)

    def _get_world_from_profile(self, rider_id: int) -> int | None:
        """Return the worldId from the rider's profile endpoint, or *None*."""
        url = f"{ZWIFT_API_BASE}/api/profiles/{rider_id}"
        try:
            resp = self._session.get(url, headers=self._json_headers(), timeout=10)
            if resp.status_code != 200:
                return None
            content_type = resp.headers.get("Content-Type", "")
            if "application/json" not in content_type:
                if self._debug:
                    print(
                        f"\n[DEBUG] Non-JSON profile response"
                        f"\n[DEBUG] Content-Type: {content_type!r}"
                        f"\n[DEBUG] Response bytes[:64]: {resp.content[:64]!r}"
                    )
                return None
            profile = resp.json()
            if not isinstance(profile, dict):
                return None
            return profile.get("worldId") or profile.get("world_id") or None
        except (json.JSONDecodeError, requests.RequestException):
            return None

    def close(self) -> None:
        self._session.close()


class RateLimitError(Exception):
    """Raised when the Zwift API returns HTTP 429."""


# ---------------------------------------------------------------------------
# ZwiftDataStore – thread-safe store identical in structure to udp_monitor
# ---------------------------------------------------------------------------


class ZwiftDataStore:
    """Thread-safe store for the most recent Zwift rider data.

    Mirrors the same interface as ZwiftDataStore in zwift_udp_monitor.py so
    the output dict is byte-for-byte compatible.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._power: int = 0
        self._heartrate: int = 0
        self._cadence: int = 0
        self._speed_kmh: float = 0.0
        self._rider_id: int = 0
        self._last_update: float = 0.0
        self._total_polls: int = 0

    def update(self, state: dict) -> None:
        """Store the latest values from an API response dict."""
        with self._lock:
            self._power = int(state.get("power", self._power))
            self._heartrate = int(state.get("heartrate", self._heartrate))
            self._cadence = int(state.get("cadence", self._cadence))
            speed_raw = state.get("speed", state.get("speed_kmh", 0))
            self._speed_kmh = round(float(speed_raw), 1)
            if state.get("riderId") or state.get("rider_id"):
                self._rider_id = int(
                    state.get("riderId") or state.get("rider_id", self._rider_id)
                )
            self._last_update = time.time()
            self._total_polls += 1

    def get_data(self) -> dict:
        """Return a dict that is structurally identical to ZwiftDataStore.get_data()."""
        with self._lock:
            return {
                "power": self._power,
                "heartrate": self._heartrate,
                "cadence": self._cadence,
                "speed_kmh": self._speed_kmh,
                "rider_id": self._rider_id,
                "last_update": self._last_update,
                "total_packets": self._total_polls,  # matches key name in udp_monitor
                "timestamp": time.time(),
            }

    @property
    def total_polls(self) -> int:
        with self._lock:
            return self._total_polls


# ---------------------------------------------------------------------------
# UDPBroadcaster – identical to the one in zwift_udp_monitor.py
# ---------------------------------------------------------------------------


class UDPBroadcaster:
    """Sends JSON data via UDP to BROADCAST_HOST:BROADCAST_PORT."""

    def __init__(self, host: str = BROADCAST_HOST, port: int = BROADCAST_PORT):
        self._host = host
        self._port = port
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, data: dict) -> None:
        """JSON-encode *data* and send it via UDP."""
        payload = json.dumps(data).encode("utf-8")
        self._sock.sendto(payload, (self._host, self._port))

    def log_console(self, data: dict) -> None:
        """Print a formatted summary to the console (same format as udp_monitor)."""
        print(
            f"\r⚡ {data['power']:>4}W  "
            f"❤️  {data['heartrate']:>3}bpm  "
            f"🚴 {data['cadence']:>3}rpm  "
            f"🚀 {data['speed_kmh']:>5.1f}km/h  "
            f"📦 {data['total_packets']} polls",
            end="",
            flush=True,
        )

    def close(self) -> None:
        self._sock.close()


# ---------------------------------------------------------------------------
# Polling loop
# ---------------------------------------------------------------------------


def run_polling_loop(
    client: ZwiftAPIClient,
    auth: ZwiftAuth,
    store: ZwiftDataStore,
    broadcaster: UDPBroadcaster,
    stop_event: threading.Event,
    rider_id: int,
    *,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    debug: bool = False,
) -> None:
    """Main polling loop: fetch player state → store → broadcast."""
    world_id: int | None = None
    consecutive_errors = 0

    while not stop_event.is_set():
        loop_start = time.time()
        try:
            auth.ensure_valid_token()

            # Discover world if we don't have it yet
            if world_id is None:
                world_id = client.get_active_world(rider_id)
                if world_id is None:
                    if debug:
                        print(
                            "\n[DEBUG] Nem aktív a lovaglás / Rider not currently active"
                        )
                    _sleep_remainder(loop_start, poll_interval, stop_event)
                    continue

            state = client.get_player_state(world_id, rider_id)
            if state is None:
                if debug:
                    print(
                        f"\n[DEBUG] Rider {rider_id} nem található ebben a világban / "
                        f"not found in world {world_id}"
                    )
                world_id = None  # reset so we re-discover next iteration
                _sleep_remainder(loop_start, poll_interval, stop_event)
                continue

            store.update(state)
            data = store.get_data()
            try:
                broadcaster.send(data)
                broadcaster.log_console(data)
            except OSError:
                pass
            consecutive_errors = 0

        except RateLimitError:
            print(
                f"\n⚠️  Rate limit elérve, várakozás {RATE_LIMIT_BACKOFF}s / "
                f"Rate limited, backing off {RATE_LIMIT_BACKOFF}s"
            )
            stop_event.wait(RATE_LIMIT_BACKOFF)
            continue

        except requests.exceptions.ConnectionError as exc:
            consecutive_errors += 1
            print(
                f"\n⚠️  Hálózati hiba (#{consecutive_errors}) / "
                f"Network error (#{consecutive_errors}): {exc}"
            )
            backoff = min(30.0, 2.0 ** consecutive_errors)
            stop_event.wait(backoff)
            continue

        except requests.exceptions.HTTPError as exc:
            consecutive_errors += 1
            print(f"\n⚠️  HTTP hiba / HTTP error: {exc}")
            backoff = min(30.0, 2.0 ** consecutive_errors)
            stop_event.wait(backoff)
            continue

        except Exception as exc:  # noqa: BLE001
            consecutive_errors += 1
            print(f"\n⚠️  Váratlan hiba / Unexpected error: {exc}")
            if debug:
                import traceback
                traceback.print_exc()
            backoff = min(30.0, 2.0 ** consecutive_errors)
            stop_event.wait(backoff)
            continue

        _sleep_remainder(loop_start, poll_interval, stop_event)


def _sleep_remainder(loop_start: float, interval: float, stop_event: threading.Event) -> None:
    """Sleep for the remaining time in the polling interval."""
    elapsed = time.time() - loop_start
    remaining = interval - elapsed
    if remaining > 0:
        stop_event.wait(remaining)


# ---------------------------------------------------------------------------
# Settings persistence
# ---------------------------------------------------------------------------


def load_settings(path: str) -> dict:
    """Load settings from a JSON file.

    Returns a dict with keys: username, password, broadcast_host,
    broadcast_port, poll_interval.  Missing or invalid values are replaced
    with defaults and a warning is printed.
    """
    defaults = {
        "username": "",
        "password": "",
        "broadcast_host": BROADCAST_HOST,
        "broadcast_port": BROADCAST_PORT,
        "poll_interval": DEFAULT_POLL_INTERVAL,
    }

    if not os.path.exists(path):
        return dict(defaults)

    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except json.JSONDecodeError:
        print(f"⚠️  Érvénytelen JSON a beállításfájlban / Invalid JSON in settings file: {path}")
        return dict(defaults)

    settings = dict(defaults)

    # username
    if "username" in raw:
        if isinstance(raw["username"], str):
            settings["username"] = raw["username"]
        else:
            print("⚠️  Érvénytelen 'username' a beállításfájlban (string szükséges) / Invalid 'username' in settings (must be string)")

    # password
    if "password" in raw:
        if isinstance(raw["password"], str):
            settings["password"] = raw["password"]
        else:
            print("⚠️  Érvénytelen 'password' a beállításfájlban (string szükséges) / Invalid 'password' in settings (must be string)")

    # broadcast_host
    if "broadcast_host" in raw:
        if isinstance(raw["broadcast_host"], str) and raw["broadcast_host"]:
            settings["broadcast_host"] = raw["broadcast_host"]
        else:
            print("⚠️  Érvénytelen 'broadcast_host' a beállításfájlban (nem üres string szükséges) / Invalid 'broadcast_host' in settings (must be non-empty string)")

    # broadcast_port
    if "broadcast_port" in raw:
        val = raw["broadcast_port"]
        if isinstance(val, int) and not isinstance(val, bool) and 1 <= val <= 65535:
            settings["broadcast_port"] = val
        else:
            print("⚠️  Érvénytelen 'broadcast_port' a beállításfájlban (1-65535 közötti int szükséges) / Invalid 'broadcast_port' in settings (must be int in range 1-65535)")

    # poll_interval
    if "poll_interval" in raw:
        val = raw["poll_interval"]
        if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
            settings["poll_interval"] = float(val)
        else:
            print("⚠️  Érvénytelen 'poll_interval' a beállításfájlban (pozitív szám szükséges) / Invalid 'poll_interval' in settings (must be positive number)")

    return settings


def save_settings(path: str, settings_dict: dict) -> None:
    """Save settings to a JSON file with pretty formatting."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(settings_dict, fh, indent=2)


# ---------------------------------------------------------------------------
# Credential resolution
# ---------------------------------------------------------------------------


def resolve_credentials(
    args: argparse.Namespace,
    settings: dict | None = None,
    settings_path: str | None = None,
) -> tuple[str, str]:
    """Return (username, password) from CLI args, env vars, settings file, or prompt.

    Priority:
      1. CLI args (--username / --password)
      2. Environment variables (ZWIFT_USERNAME / ZWIFT_PASSWORD)
      3. settings dict (loaded from zwift_api_settings.json)
      4. Interactive prompt (result saved to settings_path if provided)
    """
    if settings is None:
        settings = {}

    username = (
        args.username
        or os.environ.get("ZWIFT_USERNAME", "")
        or settings.get("username", "")
    )
    password = (
        args.password
        or os.environ.get("ZWIFT_PASSWORD", "")
        or settings.get("password", "")
    )

    from_prompt = False
    if not username:
        username = input("Zwift felhasználónév / Username: ").strip()
        from_prompt = True
    if not password:
        password = getpass.getpass("Zwift jelszó / Password: ")
        from_prompt = True

    if from_prompt and settings_path:
        to_save = {
            "username": username,
            "password": password,
            "broadcast_host": settings.get("broadcast_host", BROADCAST_HOST),
            "broadcast_port": settings.get("broadcast_port", BROADCAST_PORT),
            "poll_interval": settings.get("poll_interval", DEFAULT_POLL_INTERVAL),
        }
        save_settings(settings_path, to_save)
        print(f"✅ Beállítások mentve / Settings saved to {settings_path}")

    return username, password


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Zwift API Polling Monitor – polls Zwift HTTPS API and "
            "broadcasts to smart_fan_controller via UDP:7878"
        )
    )
    parser.add_argument("--username", default="", help="Zwift username / e-mail")
    parser.add_argument("--password", default="", help="Zwift password")
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=None,
        metavar="SECONDS",
        help=f"Polling interval in seconds (default: from settings or {DEFAULT_POLL_INTERVAL})",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    print("=" * 60)
    print(f" Zwift API Polling Monitor v{__version__}")
    print(" HTTPS API lekérdezés + UDP broadcast (127.0.0.1:7878)")
    print("=" * 60)

    # Load settings from JSON file (if it exists)
    settings = load_settings(SETTINGS_FILE)

    # Resolve poll interval: CLI > settings > hard-coded default
    poll_interval = args.poll_interval if args.poll_interval is not None else settings["poll_interval"]

    username, password = resolve_credentials(args, settings=settings, settings_path=SETTINGS_FILE)

    auth = ZwiftAuth(username, password, debug=args.debug)
    print("\nBejelentkezés folyamatban / Logging in …")
    try:
        auth.login()
    except requests.exceptions.HTTPError as exc:
        print(f"❌ Bejelentkezés sikertelen / Login failed: {exc}")
        return 1
    except requests.exceptions.ConnectionError as exc:
        print(f"❌ Hálózati hiba / Network error: {exc}")
        return 1

    client = ZwiftAPIClient(auth, debug=args.debug)
    try:
        print("Profil lekérése / Fetching profile …")
        profile = client.get_profile()
    except Exception as exc:  # noqa: BLE001
        print(f"❌ Profil lekérése sikertelen / Failed to fetch profile: {exc}")
        client.close()
        return 1

    rider_id: int = int(profile.get("id", 0))
    if not rider_id:
        print("❌ Rider ID nem található a profilban / Rider ID not found in profile")
        client.close()
        return 1

    print(f"✅ Rider ID: {rider_id}")
    print(
        f"🔄 Lekérdezési intervallum / Poll interval: {poll_interval}s\n"
        "Press Ctrl+C to stop.\n"
    )

    store = ZwiftDataStore()
    broadcaster = UDPBroadcaster(
        host=settings["broadcast_host"],
        port=settings["broadcast_port"],
    )
    stop_event = threading.Event()

    try:
        run_polling_loop(
            client,
            auth,
            store,
            broadcaster,
            stop_event,
            rider_id,
            poll_interval=poll_interval,
            debug=args.debug,
        )
    except KeyboardInterrupt:
        print("\n\nLeállítás / Stopping …")
    finally:
        stop_event.set()
        broadcaster.close()
        client.close()
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
