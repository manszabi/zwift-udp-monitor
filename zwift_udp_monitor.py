"""
zwift_udp_monitor.py – Zwift UDP forgalom figyelő és továbbító
Captures Zwift UDP traffic (port 3024), decodes protobuf messages,
and broadcasts instant power/HR/cadence/speed data via local UDP (127.0.0.1:7878).

Must be run as Administrator (Npcap requires elevated privileges).
"""

from __future__ import annotations

import json
import socket
import struct
import sys
import threading
import time

import pcapy

import ctypes
import os

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

__version__ = "1.0.1"  # Bumped from 1.0.0 due to bugfixes

ZWIFT_UDP_PORT = 3024
BROADCAST_HOST = "127.0.0.1"
BROADCAST_PORT = 7878
BROADCAST_INTERVAL = 1.0  # seconds

# Unit conversion factors (confirmed from zwift_messages.proto and community repos)
MICROHERTZ_TO_HERTZ = 1_000_000   # cadenceUHz: µHz → Hz; ×60 → RPM
MM_PER_HOUR_TO_KM_PER_HOUR = 1_000_000  # speed: mm/h → km/h

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

    def parse_outgoing(self, raw_data: bytes) -> dict | None:
        """Parse a ClientToServer packet (our own rider data).

        Applies the header-skip logic from zwifty-packets:
          - data[0] == 0x08 → no skip
          - data[5] == 0x08 → skip first 5 bytes
          - otherwise       → skip data[0] - 1 bytes
        Trims the last 4 bytes (checksum/trailer) before decoding.
        """
        if len(raw_data) < 6:
            return None

        if raw_data[0] == 0x08:
            payload = raw_data
        elif len(raw_data) > 5 and raw_data[5] == 0x08:
            payload = raw_data[5:]
        else:
            skip = raw_data[0] - 1
            if skip < 0 or skip >= len(raw_data):
                return None
            payload = raw_data[skip:]

        # Trim last 4 bytes (checksum/trailer)
        if len(payload) <= 4:
            return None
        payload = payload[:-4]

        # The ClientToServer wrapper has the PlayerState at field 7
        fields = ProtobufDecoder.parse_fields(payload)
        state_blob = fields.get(self._C2S_STATE_FIELD)
        if not isinstance(state_blob, bytes):
            return None
        return self.parse_player_state(state_blob)


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
# Network interface selection
# ---------------------------------------------------------------------------

def select_network_interface() -> str:
    """Interactive Npcap interface selector. Returns the chosen device name."""
    try:
        devices = pcapy.findalldevs()
    except Exception as exc:
        raise RuntimeError(
            "No network interfaces found. "
            "Make sure Npcap is installed with 'WinPcap API-compatible Mode' enabled."
        ) from exc

    if not devices:
        raise RuntimeError(
            "No network interfaces found. "
            "Make sure Npcap is installed with 'WinPcap API-compatible Mode' enabled."
        )

    print("\nElérhető hálózati interfészek / Available network interfaces:")
    for idx, dev in enumerate(devices):
        print(f"  [{idx}] {dev}")

    while True:
        try:
            choice = input("\nVálassz interfészt (szám) / Select interface (number): ").strip()
            index = int(choice)
            if 0 <= index < len(devices):
                return devices[index]
            print(f"Érvénytelen szám. Adjon meg 0–{len(devices) - 1} közötti értéket.")
        except ValueError:
            print("Kérjük, adjon meg egy számot / Please enter a number.")
        except (EOFError, KeyboardInterrupt):
            raise


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
# Packet capture loop
# ---------------------------------------------------------------------------

def _parse_udp_payload(raw_packet: bytes):
    """Extract (src_port, dst_port, udp_payload) from a raw Ethernet frame.

    Returns None if the frame is not IPv4/UDP or is too short.
    """
    # Ethernet header: 14 bytes
    if len(raw_packet) < 14:
        return None
    eth_type = struct.unpack_from("!H", raw_packet, 12)[0]
    if eth_type != 0x0800:  # IPv4 only
        return None

    ip_start = 14
    if len(raw_packet) < ip_start + 20:
        return None
    ip_ihl = (raw_packet[ip_start] & 0x0F) * 4
    ip_proto = raw_packet[ip_start + 9]
    if ip_proto != 17:  # UDP only
        return None

    udp_start = ip_start + ip_ihl
    if len(raw_packet) < udp_start + 8:
        return None
    src_port, dst_port = struct.unpack_from("!HH", raw_packet, udp_start)
    udp_payload = raw_packet[udp_start + 8:]
    return src_port, dst_port, udp_payload


def run_capture(
    device: str,
    store: ZwiftDataStore,
    stop_event: threading.Event,
) -> None:
    """Open a pcapy capture on *device* and decode Zwift UDP packets."""
    parser = ZwiftPacketParser()

    try:
        cap = pcapy.open_live(device, 65536, True, 1000)
    except Exception as exc:
        raise RuntimeError(
            f"Failed to start capture on '{device}'. "
            "Make sure you are running as Administrator."
        ) from exc

    cap.setfilter(f"udp port {ZWIFT_UDP_PORT}")
    print(f"\nCapturing on {device} – BPF: udp port {ZWIFT_UDP_PORT}")
    print("Press Ctrl+C to stop.\n")

    while not stop_event.is_set():
        try:
            _header, raw_packet = cap.next()
        except pcapy.PcapError:
            continue
        if not raw_packet:  # None, b'', 0-length bytes all caught
            continue

        parsed = _parse_udp_payload(raw_packet)
        if parsed is None:
            continue
        src_port, dst_port, udp_payload = parsed

        try:
            if src_port == ZWIFT_UDP_PORT:
                # ServerToClient – contains other riders as well; only update our own
                states = parser.parse_incoming(udp_payload)
                my_rider_id = store.rider_id
                if my_rider_id != 0:
                    for state in states:
                        if state.get("rider_id") == my_rider_id:
                            store.update(state)

            elif dst_port == ZWIFT_UDP_PORT:
                # ClientToServer – our own rider (primary data source)
                state = parser.parse_outgoing(udp_payload)
                if state:
                    store.update(state)
        except Exception:
            pass

def ensure_admin() -> None:
    """Ensure the script is running with Administrator privileges on Windows.
    
    If not elevated, re-launch itself via UAC (ShellExecuteW 'runas') and exit.
    On non-Windows platforms this is a no-op.
    """
    if os.name != "nt":
        return  # Nem Windows – nem szükséges

    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        is_admin = False

    if is_admin:
        return  # Már adminként futunk

    print("⚠️  Adminisztrátori jogosultság szükséges / Administrator privileges required.")
    print("   UAC prompt megnyitása… / Opening UAC prompt…")

    # Re-launch the same script with 'runas' verb (triggers UAC dialog)
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None,                   # hwnd
            "runas",                # lpOperation – request elevation
            sys.executable,         # lpFile – python.exe
            " ".join(sys.argv),     # lpParameters – script + args
            None,                   # lpDirectory
            1,                      # nShowCmd – SW_SHOWNORMAL
        )
    except Exception as exc:
        print(f"❌ Nem sikerült adminként újraindítani / Failed to re-launch as admin: {exc}")
        sys.exit(1)

    sys.exit(0)  # Az eredeti (nem emelt) folyamat kilép
    
# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
    ensure_admin()
    try:
        print("=" * 60)
        print(f" Zwift UDP Monitor v{__version__}")
        print(" Captures Zwift traffic and broadcasts to smart-fan-controller")
        print("=" * 60)

        device = select_network_interface()
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
            run_capture(device, store, stop_event)
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
