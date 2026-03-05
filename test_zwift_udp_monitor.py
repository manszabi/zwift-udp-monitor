"""
test_zwift_udp_monitor.py – Unit tests for zwift_udp_monitor.py

Uses unittest (consistent with the smart-fan-controller project).
pcapy is mocked so these tests run on any platform without Npcap.
"""

import struct
import sys
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock pcapy before importing the module under test (platform-dependent)
# ---------------------------------------------------------------------------

sys.modules.setdefault("pcapy", MagicMock())

from zwift_udp_monitor import (  # noqa: E402
    ProtobufDecoder,
    UDPBroadcaster,
    ZwiftDataStore,
    ZwiftPacketParser,
)

# ---------------------------------------------------------------------------
# Protobuf encoding helpers (used to build test data)
# ---------------------------------------------------------------------------


def _encode_varint(value: int) -> bytes:
    """Encode an integer as a protobuf base-128 varint."""
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def _make_varint_field(field_number: int, value: int) -> bytes:
    """Create a protobuf varint field (wire type 0)."""
    tag = (field_number << 3) | 0  # wire type 0
    return _encode_varint(tag) + _encode_varint(value)


def _make_fixed32_field(field_number: int, value: int) -> bytes:
    """Create a protobuf 32-bit fixed field (wire type 5)."""
    tag = (field_number << 3) | 5  # wire type 5
    return _encode_varint(tag) + struct.pack('<I', value)


def _make_fixed64_field(field_number: int, value: int) -> bytes:
    """Create a protobuf 64-bit fixed field (wire type 1)."""
    tag = (field_number << 3) | 1  # wire type 1
    return _encode_varint(tag) + struct.pack('<Q', value)


def _make_ld_field(field_number: int, data: bytes) -> bytes:
    """Create a protobuf length-delimited field (wire type 2)."""
    tag = (field_number << 3) | 2  # wire type 2
    return _encode_varint(tag) + _encode_varint(len(data)) + data


def _make_player_state_bytes(
    rider_id=None,
    power=None,
    heartrate=None,
    cadence_uhz=None,
    speed_mmh=None,
) -> bytes:
    """Create a raw PlayerState protobuf blob.

    Pass *None* for a field to omit it (protobuf default / 0).
    """
    data = b""
    if rider_id is not None:
        data += _make_varint_field(1, rider_id)   # field 1 = rider_id
    if speed_mmh is not None:
        data += _make_varint_field(6, speed_mmh)  # field 6 = speed_mmh
    if cadence_uhz is not None:
        data += _make_varint_field(9, cadence_uhz)  # field 9 = cadence_uhz
    if heartrate is not None:
        data += _make_varint_field(11, heartrate)  # field 11 = heartrate
    if power is not None:
        data += _make_varint_field(12, power)      # field 12 = power
    return data


def _make_outgoing_packet(player_state_bytes: bytes, skip_type: str = "no_skip") -> bytes:
    """Create a mock ClientToServer outgoing packet.

    The C2S protobuf starts with field 1 (tag=0x08) so that data[0]==0x08
    for the 'no_skip' path.  Field 7 carries the embedded PlayerState.
    A 4-byte trailer (checksum placeholder) is appended.

    skip_type values:
      'no_skip' – data[0]==0x08, protobuf starts at byte 0
      'skip_5'  – 5-byte padding before protobuf, data[5]==0x08
      'skip_n'  – data[0]==n+1 (n=3), skip n bytes
    """
    # Minimal C2S header: field 1 varint (tag=0x08) so data[0]==0x08
    c2s_header = b"\x08\x01"
    c2s = c2s_header + _make_ld_field(7, player_state_bytes)
    trailer = b"\x00\x00\x00\x00"

    if skip_type == "no_skip":
        # data[0] == 0x08 → no skip applied
        return c2s + trailer
    elif skip_type == "skip_5":
        # 5-byte padding; c2s starts at index 5 so data[5]==0x08
        padding = b"\x01\x00\x00\x00\x00"
        return padding + c2s + trailer
    elif skip_type == "skip_n":
        n = 3  # skip 3 bytes; data[0] = n+1 = 4
        padding = bytes([n + 1]) + b"\x01" * (n - 1)
        return padding + c2s + trailer
    else:
        raise ValueError(f"Unknown skip_type: {skip_type!r}")


# ===========================================================================
# 1. ProtobufDecoder tests
# ===========================================================================


class TestProtobufDecoderVarint(unittest.TestCase):
    """Tests for the low-level varint decoder."""

    def _decode_varint(self, data: bytes) -> int:
        """Decode the first varint from *data* using ProtobufDecoder."""
        decoder = ProtobufDecoder(data)
        return decoder._read_varint()

    def test_decode_varint_zero(self):
        """Decoding a single zero byte returns 0."""
        self.assertEqual(self._decode_varint(b"\x00"), 0)

    def test_decode_varint_single_byte_one(self):
        """Single-byte varint 0x01 decodes to 1."""
        self.assertEqual(self._decode_varint(b"\x01"), 1)

    def test_decode_varint_single_byte_max(self):
        """Single-byte varint 0x7F decodes to 127."""
        self.assertEqual(self._decode_varint(b"\x7f"), 127)

    def test_decode_varint_multi_byte_300(self):
        """Multi-byte varint 0xAC 0x02 decodes to 300."""
        self.assertEqual(self._decode_varint(b"\xac\x02"), 300)

    def test_decode_varint_multi_byte_150(self):
        """Multi-byte varint 0x96 0x01 decodes to 150."""
        self.assertEqual(self._decode_varint(b"\x96\x01"), 150)

    def test_decode_varint_large(self):
        """Large varint value (100000) round-trips correctly."""
        self.assertEqual(self._decode_varint(_encode_varint(100_000)), 100_000)

    def test_decode_varint_truncated_raises(self):
        """A truncated varint (MSB set but no continuation byte) raises ValueError."""
        with self.assertRaises(ValueError):
            self._decode_varint(b"\x80")  # continuation bit set, no next byte


class TestProtobufDecoderParseFields(unittest.TestCase):
    """Tests for ProtobufDecoder.parse_fields()."""

    def test_parse_fields_empty(self):
        """Empty bytes input returns an empty dict."""
        self.assertEqual(ProtobufDecoder.parse_fields(b""), {})

    def test_parse_fields_single_varint(self):
        """A single varint field is parsed correctly."""
        data = _make_varint_field(1, 42)
        result = ProtobufDecoder.parse_fields(data)
        self.assertEqual(result[1], 42)

    def test_parse_fields_multiple_varints(self):
        """Multiple varint fields are all parsed correctly."""
        data = _make_varint_field(1, 100) + _make_varint_field(2, 200)
        result = ProtobufDecoder.parse_fields(data)
        self.assertEqual(result[1], 100)
        self.assertEqual(result[2], 200)

    def test_parse_fields_length_delimited(self):
        """A length-delimited field returns the raw bytes payload."""
        inner = b"\x01\x02\x03"
        data = _make_ld_field(1, inner)
        result = ProtobufDecoder.parse_fields(data)
        self.assertEqual(result[1], inner)

    def test_parse_fields_mixed_wire_types(self):
        """Varint and length-delimited fields coexist in one message."""
        inner = b"hello"
        data = _make_varint_field(1, 42) + _make_ld_field(2, inner)
        result = ProtobufDecoder.parse_fields(data)
        self.assertEqual(result[1], 42)
        self.assertEqual(result[2], inner)

    def test_parse_fields_truncated_data(self):
        """A truncated message returns whatever fields were complete; no crash."""
        # Complete field 1, then a partial tag byte for field 2
        data = _make_varint_field(1, 42) + b"\x10"
        result = ProtobufDecoder.parse_fields(data)
        self.assertEqual(result.get(1), 42)
        # Field 2 is incomplete – it must not appear as a decoded value
        self.assertNotIn(2, result)

    def test_parse_fields_invalid_data(self):
        """Completely random bytes do not crash the parser."""
        data = bytes([0xFF, 0xFE, 0xFD, 0x01, 0x02])
        result = ProtobufDecoder.parse_fields(data)
        self.assertIsInstance(result, dict)

    def test_parse_fields_field_12_value_245(self):
        """Field 12, wire type 0, value 245 – from the spec example."""
        data = b"\x60\xf5\x01"
        result = ProtobufDecoder.parse_fields(data)
        self.assertEqual(result[12], 245)


# ===========================================================================
# 2. ZwiftPacketParser.parse_player_state() tests
# ===========================================================================


class TestParsePlayerState(unittest.TestCase):
    """Tests for ZwiftPacketParser.parse_player_state()."""

    def setUp(self):
        self.parser = ZwiftPacketParser()

    def test_parse_player_state_basic(self):
        """All PlayerState fields are extracted with correct values."""
        ps_bytes = _make_player_state_bytes(
            rider_id=12345,
            power=200,
            heartrate=150,
            cadence_uhz=1_500_000,
            speed_mmh=35_000_000,
        )
        result = self.parser.parse_player_state(ps_bytes)
        self.assertEqual(result["rider_id"], 12345)
        self.assertEqual(result["power"], 200)
        self.assertEqual(result["heartrate"], 150)
        self.assertEqual(result["cadence_uhz"], 1_500_000)
        self.assertEqual(result["speed_mmh"], 35_000_000)

    def test_parse_player_state_zero_power(self):
        """power=0 is valid; rider_id is still present in the result."""
        ps_bytes = _make_player_state_bytes(rider_id=12345, power=0)
        result = self.parser.parse_player_state(ps_bytes)
        self.assertEqual(result["rider_id"], 12345)
        self.assertEqual(result["power"], 0)

    def test_parse_player_state_no_heartrate(self):
        """Missing heartrate field defaults to 0."""
        ps_bytes = _make_player_state_bytes(rider_id=12345, power=200)
        result = self.parser.parse_player_state(ps_bytes)
        self.assertEqual(result["heartrate"], 0)

    def test_parse_player_state_no_rider_id(self):
        """Missing rider_id field defaults to 0 (not None)."""
        ps_bytes = _make_player_state_bytes(power=200, heartrate=150)
        result = self.parser.parse_player_state(ps_bytes)
        self.assertIsNotNone(result)
        self.assertEqual(result["rider_id"], 0)

    def test_parse_player_state_empty(self):
        """Empty bytes returns a dict with all-zero defaults."""
        result = self.parser.parse_player_state(b"")
        self.assertIsNotNone(result)
        self.assertEqual(result["rider_id"], 0)
        self.assertEqual(result["power"], 0)
        self.assertEqual(result["heartrate"], 0)

    def test_parse_player_state_only_rider_id(self):
        """Only rider_id present; other fields default to 0."""
        ps_bytes = _make_player_state_bytes(rider_id=12345)
        result = self.parser.parse_player_state(ps_bytes)
        self.assertEqual(result["rider_id"], 12345)
        self.assertEqual(result["power"], 0)
        self.assertEqual(result["heartrate"], 0)

    def test_parse_player_state_high_power(self):
        """Sprinter power value (2000 W) is parsed correctly."""
        ps_bytes = _make_player_state_bytes(rider_id=12345, power=2000)
        result = self.parser.parse_player_state(ps_bytes)
        self.assertEqual(result["rider_id"], 12345)
        self.assertEqual(result["power"], 2000)


# ===========================================================================
# 3. ZwiftPacketParser.parse_outgoing() tests – header-skip logic
# ===========================================================================


class TestParseOutgoing(unittest.TestCase):
    """Tests for ZwiftPacketParser.parse_outgoing() and its header-skip logic."""

    def setUp(self):
        self.parser = ZwiftPacketParser()

    def test_parse_outgoing_no_skip(self):
        """data[0]==0x08: no bytes are skipped; field 7 is decoded."""
        ps_bytes = _make_player_state_bytes(rider_id=12345, power=200)
        packet = _make_outgoing_packet(ps_bytes, skip_type="no_skip")
        self.assertEqual(packet[0], 0x08)
        result = self.parser.parse_outgoing(packet)
        self.assertIsNotNone(result)
        self.assertEqual(result["rider_id"], 12345)
        self.assertEqual(result["power"], 200)

    def test_parse_outgoing_skip_5(self):
        """data[5]==0x08: first 5 bytes are skipped; field 7 is decoded."""
        ps_bytes = _make_player_state_bytes(rider_id=12345, power=200)
        packet = _make_outgoing_packet(ps_bytes, skip_type="skip_5")
        self.assertNotEqual(packet[0], 0x08)
        self.assertEqual(packet[5], 0x08)
        result = self.parser.parse_outgoing(packet)
        self.assertIsNotNone(result)
        self.assertEqual(result["rider_id"], 12345)
        self.assertEqual(result["power"], 200)

    def test_parse_outgoing_skip_n(self):
        """data[0]==n+1: n bytes are skipped; field 7 is decoded."""
        ps_bytes = _make_player_state_bytes(rider_id=12345, power=200)
        packet = _make_outgoing_packet(ps_bytes, skip_type="skip_n")
        # n=3, data[0]=4
        self.assertEqual(packet[0], 4)
        result = self.parser.parse_outgoing(packet)
        self.assertIsNotNone(result)
        self.assertEqual(result["rider_id"], 12345)
        self.assertEqual(result["power"], 200)

    def test_parse_outgoing_empty(self):
        """Empty or too-short input returns None."""
        self.assertIsNone(self.parser.parse_outgoing(b""))
        self.assertIsNone(self.parser.parse_outgoing(b"\x08\x01\x02"))

    def test_parse_outgoing_no_field_7(self):
        """Valid protobuf starting with 0x08 but no field 7 returns None."""
        # Only field 1; no field 7 (PlayerState)
        data = b"\x08\x01\x00\x00\x00\x00\x00\x00"
        result = self.parser.parse_outgoing(data)
        self.assertIsNone(result)

    def test_parse_outgoing_invalid_skip(self):
        """data[0]==0 gives skip=-1; returns None without crashing."""
        data = b"\x00\x01\x02\x03\x04\x05"
        result = self.parser.parse_outgoing(data)
        self.assertIsNone(result)

    def test_parse_outgoing_returns_rider_state(self):
        """Full outgoing packet round-trip: rider_id, power, heartrate correct."""
        ps_bytes = _make_player_state_bytes(
            rider_id=55555, power=350, heartrate=165
        )
        packet = _make_outgoing_packet(ps_bytes, skip_type="no_skip")
        result = self.parser.parse_outgoing(packet)
        self.assertIsNotNone(result)
        self.assertEqual(result["rider_id"], 55555)
        self.assertEqual(result["power"], 350)
        self.assertEqual(result["heartrate"], 165)


# ===========================================================================
# 4. ZwiftPacketParser.parse_incoming() tests
# ===========================================================================


class TestParseIncoming(unittest.TestCase):
    """Tests for ZwiftPacketParser.parse_incoming()."""

    def setUp(self):
        self.parser = ZwiftPacketParser()

    def test_parse_incoming_single_rider(self):
        """A packet with one PlayerState in field 8 returns a 1-element list."""
        ps_bytes = _make_player_state_bytes(rider_id=12345, power=200)
        data = _make_ld_field(8, ps_bytes)
        result = self.parser.parse_incoming(data)
        self.assertEqual(len(result), 1)

    def test_parse_incoming_multiple_riders(self):
        """A packet with three PlayerStates returns a 3-element list."""
        data = (
            _make_ld_field(8, _make_player_state_bytes(rider_id=1, power=100))
            + _make_ld_field(8, _make_player_state_bytes(rider_id=2, power=200))
            + _make_ld_field(8, _make_player_state_bytes(rider_id=3, power=300))
        )
        result = self.parser.parse_incoming(data)
        self.assertEqual(len(result), 3)

    def test_parse_incoming_empty(self):
        """Empty bytes returns an empty list."""
        result = self.parser.parse_incoming(b"")
        self.assertEqual(result, [])

    def test_parse_incoming_no_field_8(self):
        """A message without field 8 returns an empty list."""
        data = _make_varint_field(1, 42)  # field 1, not field 8
        result = self.parser.parse_incoming(data)
        self.assertEqual(result, [])

    def test_parse_incoming_extracts_correct_data(self):
        """rider_id, power, and heartrate are extracted accurately."""
        ps_bytes = _make_player_state_bytes(
            rider_id=99999, power=275, heartrate=158
        )
        data = _make_ld_field(8, ps_bytes)
        result = self.parser.parse_incoming(data)
        self.assertEqual(len(result), 1)
        state = result[0]
        self.assertEqual(state["rider_id"], 99999)
        self.assertEqual(state["power"], 275)
        self.assertEqual(state["heartrate"], 158)


# ===========================================================================
# 5. ZwiftDataStore tests
# ===========================================================================


class TestZwiftDataStore(unittest.TestCase):
    """Tests for ZwiftDataStore state management and unit conversions."""

    def setUp(self):
        self.store = ZwiftDataStore()

    @staticmethod
    def _make_update_dict(
        rider_id=1,
        power=0,
        heartrate=0,
        cadence_uhz=0,
        speed_mmh=0,
    ) -> dict:
        """Return a minimal PlayerState dict suitable for ZwiftDataStore.update()."""
        return {
            "rider_id": rider_id,
            "power": power,
            "heartrate": heartrate,
            "cadence_uhz": cadence_uhz,
            "speed_mmh": speed_mmh,
        }

    def test_store_initial_state(self):
        """Newly created store has zero/None defaults."""
        self.assertEqual(self.store.rider_id, 0)
        data = self.store.get_data()
        self.assertEqual(data["power"], 0)
        self.assertEqual(data["heartrate"], 0)
        self.assertEqual(data["total_packets"], 0)

    def test_store_update_sets_rider_id(self):
        """First update with a non-zero rider_id stores it."""
        self.store.update(self._make_update_dict(rider_id=12345))
        self.assertEqual(self.store.rider_id, 12345)

    def test_store_rider_id_property(self):
        """rider_id property is thread-safe and returns the stored value."""
        self.store.update(self._make_update_dict(rider_id=77777))
        self.assertEqual(self.store.rider_id, 77777)

    def test_store_update_power_and_hr(self):
        """get_data() reflects the power and heartrate from the latest update."""
        self.store.update(self._make_update_dict(power=250, heartrate=155))
        data = self.store.get_data()
        self.assertEqual(data["power"], 250)
        self.assertEqual(data["heartrate"], 155)

    def test_store_cadence_conversion(self):
        """cadence_uhz 1_500_000 µHz converts to 90 RPM."""
        self.store.update(self._make_update_dict(cadence_uhz=1_500_000))
        data = self.store.get_data()
        self.assertEqual(data["cadence"], 90)

    def test_store_speed_conversion(self):
        """speed_mmh 35_000_000 mm/h converts to 35.0 km/h."""
        self.store.update(self._make_update_dict(speed_mmh=35_000_000))
        data = self.store.get_data()
        self.assertAlmostEqual(data["speed_kmh"], 35.0, places=1)

    def test_store_get_data_includes_timestamp(self):
        """get_data() dict contains a 'timestamp' float field."""
        self.store.update(self._make_update_dict())
        data = self.store.get_data()
        self.assertIn("timestamp", data)
        self.assertIsInstance(data["timestamp"], float)

    def test_store_total_packets_increments(self):
        """Every call to update() increments total_packets by 1."""
        for i in range(3):
            self.store.update(self._make_update_dict(power=i * 10))
        self.assertEqual(self.store.get_data()["total_packets"], 3)


# ===========================================================================
# 6. UDPBroadcaster tests
# ===========================================================================


class TestUDPBroadcaster(unittest.TestCase):
    """Tests for UDPBroadcaster.send() and log_console()."""

    _SAMPLE_DATA = {
        "power": 250,
        "heartrate": 155,
        "cadence": 90,
        "speed_kmh": 35.0,
        "total_packets": 10,
    }

    def _make_broadcaster(self):
        """Create a UDPBroadcaster with a mocked socket."""
        with patch("socket.socket") as mock_socket_class:
            mock_sock = MagicMock()
            mock_socket_class.return_value = mock_sock
            broadcaster = UDPBroadcaster()
        broadcaster._sock = mock_sock  # keep mock accessible
        return broadcaster, mock_sock

    def test_broadcaster_send_valid_data(self):
        """send() JSON-encodes data and calls sendto exactly once."""
        broadcaster, mock_sock = self._make_broadcaster()
        broadcaster.send(self._SAMPLE_DATA)
        mock_sock.sendto.assert_called_once()
        # First positional arg should be bytes (JSON payload)
        payload_bytes = mock_sock.sendto.call_args[0][0]
        self.assertIsInstance(payload_bytes, bytes)

    def test_broadcaster_format_console(self):
        """log_console() prints a line containing power, heartrate and cadence values."""
        broadcaster, _mock_sock = self._make_broadcaster()
        with patch("builtins.print") as mock_print:
            broadcaster.log_console(self._SAMPLE_DATA)
        mock_print.assert_called_once()
        output = mock_print.call_args[0][0]
        self.assertIn("250", output)   # power
        self.assertIn("155", output)   # heartrate
        self.assertIn("90", output)    # cadence
        self.assertIn("35.0", output)  # speed


# ===========================================================================
# 7. Integration tests – run_capture rider-ID filtering (Bug #1 regression)
# ===========================================================================


class TestRunCaptureRiderFiltering(unittest.TestCase):
    """Regression tests for Bug #1: incoming packets must be filtered by rider_id.

    These tests replicate the exact conditional logic from run_capture()
    without touching the network layer (pcapy).
    """

    def setUp(self):
        self.parser = ZwiftPacketParser()
        self.store = ZwiftDataStore()

    # ------------------------------------------------------------------
    # Helpers that mirror the logic inside run_capture()
    # ------------------------------------------------------------------

    def _process_outgoing(self, udp_payload: bytes) -> None:
        """Simulate run_capture handling a ClientToServer packet."""
        state = self.parser.parse_outgoing(udp_payload)
        if state:
            self.store.update(state)

    def _process_incoming(self, udp_payload: bytes) -> None:
        """Simulate run_capture handling a ServerToClient packet."""
        states = self.parser.parse_incoming(udp_payload)
        my_rider_id = self.store.rider_id
        if my_rider_id != 0:
            for state in states:
                if state.get("rider_id") == my_rider_id:
                    self.store.update(state)

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_incoming_ignored_before_rider_id_known(self):
        """Incoming packets are ignored while rider_id has not yet been set."""
        self.assertEqual(self.store.rider_id, 0)
        ps_bytes = _make_player_state_bytes(rider_id=12345, power=200)
        self._process_incoming(_make_ld_field(8, ps_bytes))
        self.assertEqual(self.store.get_data()["total_packets"], 0)

    def test_incoming_only_own_rider_updated(self):
        """Incoming packet for a different rider does not touch the store."""
        # Establish our own rider via an outgoing packet
        own_ps = _make_player_state_bytes(rider_id=12345, power=200)
        self._process_outgoing(_make_outgoing_packet(own_ps, skip_type="no_skip"))
        self.assertEqual(self.store.rider_id, 12345)

        packets_after_outgoing = self.store.get_data()["total_packets"]

        # Incoming packet belongs to a different rider
        other_ps = _make_player_state_bytes(rider_id=99999, power=350)
        self._process_incoming(_make_ld_field(8, other_ps))

        self.assertEqual(
            self.store.get_data()["total_packets"],
            packets_after_outgoing,
            "Store must not be updated for a foreign rider_id",
        )

    def test_incoming_own_rider_updated(self):
        """Incoming packet that matches our rider_id updates the store."""
        own_rider_id = 12345
        own_ps = _make_player_state_bytes(rider_id=own_rider_id, power=200)
        self._process_outgoing(_make_outgoing_packet(own_ps, skip_type="no_skip"))

        packets_after_outgoing = self.store.get_data()["total_packets"]

        # Incoming packet belongs to our own rider
        own_incoming_ps = _make_player_state_bytes(
            rider_id=own_rider_id, power=275
        )
        self._process_incoming(_make_ld_field(8, own_incoming_ps))

        self.assertGreater(
            self.store.get_data()["total_packets"],
            packets_after_outgoing,
            "Store must be updated when incoming rider_id matches our own",
        )


# ===========================================================================
# 8. ZwiftPacketParser._to_int() tests
# ===========================================================================


class TestToInt(unittest.TestCase):
    """Tests for ZwiftPacketParser._to_int() – bytes-to-int conversion."""

    def test_to_int_with_int_value(self):
        """An int value is returned unchanged."""
        self.assertEqual(ZwiftPacketParser._to_int(42), 42)

    def test_to_int_with_zero_int(self):
        """Zero int is returned as zero."""
        self.assertEqual(ZwiftPacketParser._to_int(0), 0)

    def test_to_int_with_4_bytes_fixed32(self):
        """4-byte little-endian bytes are decoded as uint32 (wire type 5)."""
        raw = struct.pack('<I', 300)
        self.assertEqual(ZwiftPacketParser._to_int(raw), 300)

    def test_to_int_with_8_bytes_fixed64(self):
        """8-byte little-endian bytes are decoded as uint64 (wire type 1)."""
        raw = struct.pack('<Q', 1_234_567_890_123)
        self.assertEqual(ZwiftPacketParser._to_int(raw), 1_234_567_890_123)

    def test_to_int_with_unexpected_bytes_length_returns_default(self):
        """bytes of unexpected length (not 4 or 8) returns the default."""
        self.assertEqual(ZwiftPacketParser._to_int(b"\x01\x02\x03"), 0)
        self.assertEqual(ZwiftPacketParser._to_int(b"\x01\x02\x03", default=99), 99)

    def test_to_int_with_none_returns_default(self):
        """None returns the default value."""
        self.assertEqual(ZwiftPacketParser._to_int(None), 0)
        self.assertEqual(ZwiftPacketParser._to_int(None, default=7), 7)


# ===========================================================================
# 9. parse_player_state() with fixed-width wire types (Bug #2 regression)
# ===========================================================================


class TestParsePlayerStateFixedWidth(unittest.TestCase):
    """Regression tests for Bug #2: fixed-width fields must not cause JSON errors."""

    def setUp(self):
        self.parser = ZwiftPacketParser()

    def test_heartrate_as_fixed32_is_int(self):
        """heartrate encoded as wire type 5 (fixed32) is decoded to int."""
        data = _make_fixed32_field(11, 150)  # field 11 = heartrate
        result = self.parser.parse_player_state(data)
        self.assertIsInstance(result["heartrate"], int)
        self.assertEqual(result["heartrate"], 150)

    def test_speed_as_fixed32_is_int(self):
        """speed_mmh encoded as wire type 5 (fixed32) is decoded to int."""
        data = _make_fixed32_field(6, 35_000_000)  # field 6 = speed_mmh
        result = self.parser.parse_player_state(data)
        self.assertIsInstance(result["speed_mmh"], int)
        self.assertEqual(result["speed_mmh"], 35_000_000)

    def test_power_as_fixed32_is_int(self):
        """power encoded as wire type 5 (fixed32) is decoded to int."""
        data = _make_fixed32_field(12, 250)  # field 12 = power
        result = self.parser.parse_player_state(data)
        self.assertIsInstance(result["power"], int)
        self.assertEqual(result["power"], 250)

    def test_rider_id_as_fixed64_is_int(self):
        """rider_id encoded as wire type 1 (fixed64) is decoded to int."""
        data = _make_fixed64_field(1, 99999)  # field 1 = rider_id
        result = self.parser.parse_player_state(data)
        self.assertIsInstance(result["rider_id"], int)
        self.assertEqual(result["rider_id"], 99999)

    def test_parse_player_state_all_fields_are_int(self):
        """All fields in parse_player_state result must be int (JSON-serializable)."""
        import json
        data = (
            _make_fixed32_field(1, 12345)       # rider_id as fixed32
            + _make_fixed32_field(11, 150)      # heartrate as fixed32
            + _make_fixed32_field(12, 250)      # power as fixed32
            + _make_fixed32_field(6, 35_000_000)  # speed_mmh as fixed32
            + _make_fixed32_field(9, 1_500_000)   # cadence_uhz as fixed32
        )
        result = self.parser.parse_player_state(data)
        for key, value in result.items():
            self.assertIsInstance(value, int, f"Field '{key}' should be int, got {type(value)}")
        # Must be JSON-serializable without TypeError
        serialized = json.dumps(result)
        self.assertIsInstance(serialized, str)

    def test_store_get_data_json_serializable_with_fixed_width_fields(self):
        """ZwiftDataStore.get_data() is JSON-serializable even with bytes-derived values."""
        import json
        store = ZwiftDataStore()
        # Simulate what happens when parse_player_state returns int from fixed32
        data = _make_fixed32_field(11, 158)  # heartrate as fixed32
        result = self.parser.parse_player_state(data)
        store.update(result)
        data_dict = store.get_data()
        # Must not raise TypeError
        serialized = json.dumps(data_dict)
        self.assertIsInstance(serialized, str)
        self.assertEqual(json.loads(serialized)["heartrate"], 158)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main()
