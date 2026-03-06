"""
zwift_udp_monitor.py – Zwift Companion App UDP listener és adattovábbító
Listens for Zwift Companion App (ZCA) UDP broadcast packets on port 21587,
decodes protobuf messages, and broadcasts instant power/HR/cadence/speed
data via local UDP (127.0.0.1:7878).

No admin privileges or Npcap required – uses a plain UDP socket.
Requires the Zwift Companion App running on the same Wi-Fi network.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

__version__ = "2.0.0"

# Settings file – resolved relative to this script's directory
SETTINGS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "zwift_udp_monitor_setting.json"
)

_DEFAULT_SETTINGS: dict = {
    "zca_udp_port": 21587,
    "broadcast_host": "127.0.0.1",
    "broadcast_port": 7878,
    "broadcast_interval": 1.0,
    "microhertz_to_hertz": 1_000_000,
    "mm_per_hour_to_km_per_hour": 1_000_000,
}


def load_settings(path: str) -> dict:
    """Load settings from a JSON file, validating every field.

    If the file does not exist or contains invalid JSON the file is (re)created
    with the default values and the defaults are returned.  Individual fields
    that fail validation are reset to their defaults and a warning is printed;
    the corrected settings are then written back to disk.
    """

    def _valid_port(val) -> bool:
        return isinstance(val, int) and not isinstance(val, bool) and 1 <= val <= 65535

    def _valid_positive_int(val) -> bool:
        return isinstance(val, int) and not isinstance(val, bool) and val > 0

    def _valid_positive_number(val) -> bool:
        return isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0

    settings = dict(_DEFAULT_SETTINGS)
    needs_save = False

    if not os.path.exists(path):
        print(
            f"ℹ️  A beállításfájl nem található, létrehozás alapértékekkel / "
            f"Settings file not found, creating with defaults: {path}"
        )
        needs_save = True
    else:
        try:
            with open(path, encoding="utf-8") as fh:
                raw = json.load(fh)
        except json.JSONDecodeError:
            print(
                f"⚠️  Érvénytelen JSON a beállításfájlban, újralétrehozás alapértékekkel / "
                f"Invalid JSON in settings file, recreating with defaults: {path}"
            )
            needs_save = True
            raw = {}

        # zca_udp_port
        if "zca_udp_port" in raw:
            if _valid_port(raw["zca_udp_port"]):
                settings["zca_udp_port"] = raw["zca_udp_port"]
            else:
                print(
                    "⚠️  Érvénytelen 'zca_udp_port' (1-65535 közötti int szükséges) / "
                    "Invalid 'zca_udp_port' (must be int in range 1-65535)"
                )
                needs_save = True

        # broadcast_host
        if "broadcast_host" in raw:
            val = raw["broadcast_host"]
            if isinstance(val, str) and val:
                settings["broadcast_host"] = val
            else:
                print(
                    "⚠️  Érvénytelen 'broadcast_host' (nem üres string szükséges) / "
                    "Invalid 'broadcast_host' (must be non-empty string)"
                )
                needs_save = True

        # broadcast_port
        if "broadcast_port" in raw:
            if _valid_port(raw["broadcast_port"]):
                settings["broadcast_port"] = raw["broadcast_port"]
            else:
                print(
                    "⚠️  Érvénytelen 'broadcast_port' (1-65535 közötti int szükséges) / "
                    "Invalid 'broadcast_port' (must be int in range 1-65535)"
                )
                needs_save = True

        # broadcast_interval
        if "broadcast_interval" in raw:
            val = raw["broadcast_interval"]
            if _valid_positive_number(val):
                settings["broadcast_interval"] = float(val)
            else:
                print(
                    "⚠️  Érvénytelen 'broadcast_interval' (pozitív szám szükséges) / "
                    "Invalid 'broadcast_interval' (must be a positive number)"
                )
                needs_save = True

        # microhertz_to_hertz
        if "microhertz_to_hertz" in raw:
            if _valid_positive_int(raw["microhertz_to_hertz"]):
                settings["microhertz_to_hertz"] = raw["microhertz_to_hertz"]
            else:
                print(
                    "⚠️  Érvénytelen 'microhertz_to_hertz' (pozitív egész szükséges) / "
                    "Invalid 'microhertz_to_hertz' (must be a positive integer)"
                )
                needs_save = True

        # mm_per_hour_to_km_per_hour
        if "mm_per_hour_to_km_per_hour" in raw:
            if _valid_positive_int(raw["mm_per_hour_to_km_per_hour"]):
                settings["mm_per_hour_to_km_per_hour"] = raw["mm_per_hour_to_km_per_hour"]
            else:
                print(
                    "⚠️  Érvénytelen 'mm_per_hour_to_km_per_hour' (pozitív egész szükséges) / "
                    "Invalid 'mm_per_hour_to_km_per_hour' (must be a positive integer)"
                )
                needs_save = True

    if needs_save:
        save_settings(path, settings)

    return settings


def save_settings(path: str, settings_dict: dict) -> None:
    """Save settings to a JSON file with pretty formatting."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(settings_dict, fh, indent=2)
        fh.write("\n")


# Load settings at import time; populate module-level constants
_settings = load_settings(SETTINGS_FILE)

ZCA_UDP_PORT: int = _settings["zca_udp_port"]          # Zwift Companion App local broadcast port
BROADCAST_HOST: str = _settings["broadcast_host"]
BROADCAST_PORT: int = _settings["broadcast_port"]
BROADCAST_INTERVAL: float = _settings["broadcast_interval"]  # seconds

# Unit conversion factors (confirmed from zwift_messages.proto and community repos)
MICROHERTZ_TO_HERTZ: int = _settings["microhertz_to_hertz"]   # cadenceUHz: µHz → Hz; ×60 → RPM
MM_PER_HOUR_TO_KM_PER_HOUR: int = _settings["mm_per_hour_to_km_per_hour"]  # speed: mm/h → km/h

# ---------------------------------------------------------------------------
# ProtobufDecoder – raw varint / field parser (no .proto compilation needed)
# ---------------------------------------------------------------------------

class ProtobufDecoder:
    """Minimal protobuf decoder supporting wire types 0, 1, 2, and 5."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    # ---- low-level reading ------------------------------------------------

    def _read_varint(self):
        """Read a base-128 varint from the current position."""
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
            raise ValueError(f"Not enough data: need {n}, have {len(self._data) - self._pos}")
        chunk = self._data[self._pos:self._pos + n]
        self._pos += n
        return chunk

    # ---- field iteration --------------------------------------------------

    def fields(self):
        """Iterate over (field_number, wire_type, value) tuples.

        Wire types:
          0 – varint
          1 – 64-bit fixed
          2 – length-delimited (returned as bytes)
          5 – 32-bit fixed
        """
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
                # Unknown wire type – cannot continue safely
                break
            yield field_number, wire_type, value

    # ---- convenience class method -----------------------------------------

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

    @classmethod
    def parse_repeated_field(cls, data: bytes, target_field: int) -> list:
        """Return a list of raw bytes values for a repeated length-delimited field."""
        items = []
        try:
            for field_number, wire_type, value in cls(data).fields():
                if field_number == target_field and wire_type == 2:
                    items.append(value)
        except (ValueError, struct.error):
            pass
        return items


# ---------------------------------------------------------------------------
# ZwiftPacketParser – protocol-level decoding
# ---------------------------------------------------------------------------

class ZwiftPacketParser:
    """Parses Zwift UDP packet payloads into PlayerState dicts."""

    # PlayerState field numbers (confirmed from zwift_messages.proto)
    _PS_FIELD_ID = 1
    _PS_FIELD_WORLD_TIME = 2
    _PS_FIELD_DISTANCE = 3
    _PS_FIELD_SPEED = 6
    _PS_FIELD_CADENCE_UHZ = 9
    _PS_FIELD_HEARTRATE = 11
    _PS_FIELD_POWER = 12
    _PS_FIELD_CLIMBING = 15
    _PS_FIELD_TIME = 16

    # Wrapper message field numbers
    _S2C_PLAYER_STATES_FIELD = 8   # ServerToClient: repeated PlayerState
    _C2S_STATE_FIELD = 7           # ClientToServer: PlayerState

    @staticmethod
    def _to_int(value: int | bytes | None, default: int = 0) -> int:
        """Convert a protobuf field value to int, handling bytes from fixed-width wire types.

        Wire type 0 (varint) already returns int; wire types 1 and 5 return raw bytes.
          - 4-byte value (wire type 5 / fixed32): decoded as little-endian uint32
          - 8-byte value (wire type 1 / fixed64): decoded as little-endian uint64
        """
        if isinstance(value, int):
            return value
        if isinstance(value, bytes):
            if len(value) == 4:
                return struct.unpack('<I', value)[0]
            if len(value) == 8:
                return struct.unpack('<Q', value)[0]
        return default

    def parse_player_state(self, data: bytes) -> dict:
        """Extract relevant fields from a raw PlayerState blob."""
        fields = ProtobufDecoder.parse_fields(data)
        return {
            "rider_id": self._to_int(fields.get(self._PS_FIELD_ID, 0)),
            "world_time": self._to_int(fields.get(self._PS_FIELD_WORLD_TIME, 0)),
            "distance": self._to_int(fields.get(self._PS_FIELD_DISTANCE, 0)),
            "speed_mmh": self._to_int(fields.get(self._PS_FIELD_SPEED, 0)),
            "cadence_uhz": self._to_int(fields.get(self._PS_FIELD_CADENCE_UHZ, 0)),
            "heartrate": self._to_int(fields.get(self._PS_FIELD_HEARTRATE, 0)),
            "power": self._to_int(fields.get(self._PS_FIELD_POWER, 0)),
            "climbing": self._to_int(fields.get(self._PS_FIELD_CLIMBING, 0)),
            "elapsed_time": self._to_int(fields.get(self._PS_FIELD_TIME, 0)),
        }

    def parse_incoming(self, data: bytes) -> list:
        """Parse a ServerToClient packet; returns a list of PlayerState dicts."""
        player_state_blobs = ProtobufDecoder.parse_repeated_field(
            data, self._S2C_PLAYER_STATES_FIELD
        )
        return [self.parse_player_state(blob) for blob in player_state_blobs]

    @staticmethod
    def _state_has_data(state: dict | None) -> bool:
        """Return True if the state dict has at least one non-zero meaningful field."""
        if not state:
            return False
        return bool(state.get("rider_id") or state.get("power") or state.get("heartrate"))

    def parse_outgoing(self, raw_data: bytes) -> dict | None:
        """Parse a ClientToServer packet (our own rider data).

        Tries multiple header-skip strategies and fallback parse approaches for
        resilience across different Zwift versions and packet formats.

        Primary strategies (original header-skip heuristics):
          - data[0] == 0x08 → no skip
          - data[5] == 0x08 → skip first 5 bytes
          - otherwise       → skip data[0] - 1 bytes
        Each candidate payload is trimmed of the last 4 bytes (checksum/trailer)
        and then decoded as a ClientToServer wrapper (trying field numbers 7, 6, 8, 5).

        Fallback strategies (if no result with useful data found):
          - Parse trimmed payload directly as a PlayerState (no wrapper)
        """
        if len(raw_data) < 6:
            return None

        # Build candidate payloads from all skip heuristics, preserving order
        candidates: list[bytes] = []
        if raw_data[0] == 0x08:
            candidates.append(raw_data)
        if len(raw_data) > 5 and raw_data[5] == 0x08:
            p = raw_data[5:]
            if p not in candidates:
                candidates.append(p)
        skip = raw_data[0] - 1
        if 0 <= skip < len(raw_data):
            p = raw_data[skip:]
            if p not in candidates:
                candidates.append(p)
        # Always include the raw payload as a last-resort candidate
        if raw_data not in candidates:
            candidates.append(raw_data)

        fallbacks: list[dict] = []

        for payload in candidates:
            if len(payload) <= 4:
                continue
            trimmed = payload[:-4]

            # Try C2S wrapper field numbers.
            # Field 7 is the standard ClientToServer PlayerState field; fields 5, 6, 8
            # are observed in alternative Zwift packet layouts (different app versions
            # or protocol variants may embed the PlayerState at a different field number).
            fields = ProtobufDecoder.parse_fields(trimmed)
            for field_num in (self._C2S_STATE_FIELD, 6, 8, 5):
                state_blob = fields.get(field_num)
                if isinstance(state_blob, bytes) and len(state_blob) >= 2:
                    state = self.parse_player_state(state_blob)
                    if self._state_has_data(state):
                        return state
                    fallbacks.append(state)

            # Try parsing trimmed payload directly as a PlayerState (no wrapper)
            state = self.parse_player_state(trimmed)
            if self._state_has_data(state):
                return state
            if state:
                fallbacks.append(state)

        # Return the first fallback that at least has a non-zero rider_id
        for s in fallbacks:
            if s.get("rider_id", 0) != 0:
                return s
        return None


# ---------------------------------------------------------------------------
# ZwiftDataStore – thread-safe store for the latest instant values
# ---------------------------------------------------------------------------

class ZwiftDataStore:
    """Thread-safe store for the most recent Zwift rider data.

    No averaging is performed here – smart_fan_controller handles buffering.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._power: int = 0
        self._heartrate: int = 0
        self._cadence_uhz: int = 0
        self._speed_mmh: int = 0
        self._rider_id: int = 0
        self._last_update: float = 0.0
        self._total_packets: int = 0

    def update(self, state: dict) -> None:
        """Store the latest values from a parsed PlayerState dict."""
        with self._lock:
            self._power = state.get("power", self._power)
            self._heartrate = state.get("heartrate", self._heartrate)
            self._cadence_uhz = state.get("cadence_uhz", self._cadence_uhz)
            self._speed_mmh = state.get("speed_mmh", self._speed_mmh)
            if state.get("rider_id"):
                self._rider_id = state["rider_id"]
            self._last_update = time.time()
            self._total_packets += 1

    @property
    def rider_id(self) -> int:
        """Return the current rider ID in a thread-safe manner."""
        with self._lock:
            return self._rider_id

    def get_data(self) -> dict:
        """Return a dict with human-readable converted values."""
        with self._lock:
            # Defense-in-depth: ensure stored values are int before arithmetic/JSON
            power = int(self._power)
            heartrate = int(self._heartrate)
            cadence_uhz = int(self._cadence_uhz)
            speed_mmh = int(self._speed_mmh)
            rider_id = int(self._rider_id)
            # cadence: micro-hertz → RPM
            cadence_rpm = int((cadence_uhz * 60) / MICROHERTZ_TO_HERTZ)
            # speed: millimetres/hour → km/h
            speed_kmh = round(speed_mmh / MM_PER_HOUR_TO_KM_PER_HOUR, 1)
            return {
                "power": power,
                "heartrate": heartrate,
                "cadence": cadence_rpm,
                "speed_kmh": speed_kmh,
                "rider_id": rider_id,
                "last_update": self._last_update,
                "total_packets": self._total_packets,
                "timestamp": time.time(),
            }


# ---------------------------------------------------------------------------
# UDPBroadcaster – sends JSON payloads to smart_fan_controller
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
        """Print a formatted summary to the console."""
        print(
            f"\r⚡ {data['power']:>4}W  "
            f"❤️  {data['heartrate']:>3}bpm  "
            f"🚴 {data['cadence']:>3}rpm  "
            f"🚀 {data['speed_kmh']:>5.1f}km/h  "
            f"📦 {data['total_packets']} pkts",
            end="",
            flush=True,
        )

    def close(self) -> None:
        self._sock.close()


# ---------------------------------------------------------------------------
# Broadcast loop (runs in a background thread)
# ---------------------------------------------------------------------------

def run_broadcast_loop(
    store: ZwiftDataStore,
    broadcaster: UDPBroadcaster,
    stop_event: threading.Event,
) -> None:
    """Periodically broadcast the latest data via UDP every BROADCAST_INTERVAL seconds."""
    while not stop_event.is_set():
        data = store.get_data()
        if data["total_packets"] > 0:  # Only send once real Zwift data has arrived
            try:
                broadcaster.send(data)
                broadcaster.log_console(data)
            except OSError:
                pass
        stop_event.wait(BROADCAST_INTERVAL)


# ---------------------------------------------------------------------------
# ZCA UDP listener loop
# ---------------------------------------------------------------------------

def run_listener(
    store: ZwiftDataStore,
    stop_event: threading.Event,
    *,
    debug: bool = False,
) -> None:
    """Listen for Zwift Companion App UDP broadcast packets on ZCA_UDP_PORT.

    Each received datagram is attempted to be decoded first as a
    ServerToClient wrapper (field 8 repeated PlayerState), and if that
    yields no data, as a raw PlayerState directly.
    """
    parser = ZwiftPacketParser()
    parse_errors = 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Bind to all interfaces so broadcast packets from ZCA are received
        # regardless of which network interface the phone uses.
        sock.bind(("0.0.0.0", ZCA_UDP_PORT))
        sock.settimeout(1.0)
    except OSError as exc:
        sock.close()
        raise RuntimeError(
            f"Failed to bind UDP socket on port {ZCA_UDP_PORT}: {exc}"
        ) from exc

    print(f"\nListening for ZCA broadcasts on UDP port {ZCA_UDP_PORT}")
    print("Make sure the Zwift Companion App is running on the same Wi-Fi network.")
    print("Press Ctrl+C to stop.\n")

    try:
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65536)
            except socket.timeout:
                continue

            if debug:
                print(
                    f"\n[DEBUG] {len(data)}B from {addr[0]}:{addr[1]} "
                    f"hex={data[:32].hex()}"
                )

            try:
                # Try ServerToClient wrapper first (field 8 repeated PlayerStates)
                states = parser.parse_incoming(data)
                if states:
                    my_rider_id = store.rider_id
                    if my_rider_id == 0:
                        # Bootstrap: accept first state with a valid rider_id
                        for state in states:
                            if state.get("rider_id", 0) != 0:
                                store.update(state)
                                break
                    else:
                        for state in states:
                            if state.get("rider_id") == my_rider_id:
                                store.update(state)
                    if debug:
                        print(
                            f"[DEBUG] S2C wrapper: {len(states)} state(s), "
                            f"store.rider_id={store.rider_id}"
                        )
                else:
                    # Fall back to direct PlayerState parse when S2C wrapper is empty
                    state = parser.parse_player_state(data)
                    if ZwiftPacketParser._state_has_data(state):
                        store.update(state)
                        if debug:
                            print(f"[DEBUG] direct PlayerState: {state!r}")

            except Exception as exc:
                parse_errors += 1
                if debug or parse_errors <= 3:
                    print(f"[WARN] parse error #{parse_errors}: {exc!r}")
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
    arg_parser = argparse.ArgumentParser(description=f"Zwift UDP Monitor v{__version__}")
    arg_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose packet logging (size, hex dump, parse results)",
    )
    args = arg_parser.parse_args()

    try:
        print("=" * 60)
        print(f" Zwift UDP Monitor v{__version__}")
        print(" Listens for ZCA broadcasts and forwards to smart-fan-controller")
        print("=" * 60)

        store = ZwiftDataStore()
        broadcaster = UDPBroadcaster()
        stop_event = threading.Event()

        broadcast_thread = threading.Thread(
            target=run_broadcast_loop,
            args=(store, broadcaster, stop_event),
            daemon=True,
            name="broadcast",
        )
        broadcast_thread.start()

        try:
            run_listener(store, stop_event, debug=args.debug)
        except KeyboardInterrupt:
            print("\n\nLeállítás… / Stopping…")
        finally:
            stop_event.set()
            broadcast_thread.join(timeout=2)
            broadcaster.close()
            print("Kész / Done.")
    except RuntimeError as e:
        print(f"\n❌ {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
