# Zwift UDP Monitor

![Version](https://img.shields.io/badge/version-v2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![Platform](https://img.shields.io/badge/platform-Windows%2011-lightgrey)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

**Zwift Companion App UDP broadcast figyelése és valós idejű power/HR adat továbbítása a [smart-fan-controller](https://github.com/manszabi/smart-fan-controller) számára.**

A Zwift Companion App (ZCA) által küldött UDP broadcast csomagokat hallgatja (port 21587), dekódolja a protobuf üzeneteket, és azonnali teljesítmény/pulzus/kadencia/sebesség adatokat küld UDP-n keresztül (127.0.0.1:7878).

> **v2.0.0 – Breaking change:** Az Npcap-alapú csomagelfogást felváltotta a ZCA UDP socket listener. Nem szükséges többé Npcap, rendszergazdai jogosultság, vagy hálózati interfész kiválasztása. Szükséges a Zwift Companion App futtatása ugyanazon a Wi-Fi hálózaton.

---

## Funkciók

- 🔵 **Nincs Zwift bejelentkezés szükséges** – ZCA broadcast figyelés
- ⚡ **Azonnali értékek** – nincs átlagolás/simítás (a fogyasztó kezeli a pufferelést)
- 📡 **UDP broadcast** – alacsony késleltetés, JSON formátum
- 🔧 **Raw protobuf dekóder** – nem szükséges `.proto` fájl fordítás
- 🖥️ **Windows / Linux / macOS** – csak standard Python socket, Npcap nélkül
- 🔓 **Nincs rendszergazdai jogosultság szükséges**

---

## Architektúra

```
[Zwift App] <--> [Zwift Companion App (telefon, azonos Wi-Fi)]
                          |
                          | UDP broadcast (21587)
                          v
              [zwift_udp_monitor.py]       ← ZCA listener + protobuf dekódolás
                          |                  Azonnali értékek, NEM átlagolt
                          |  UDP:7878 (127.0.0.1)
                          v
              [smart_fan_controller.py]    ← buffer_seconds + minimum_samples + cooldown
                          |
                          |  BLE
                          v
              [ESP32 Smart Fan]
```

---

## Előfeltételek

- **Python 3.8+**
- **Zwift Companion App** – telepítve a telefonon, ugyanazon a Wi-Fi hálózaton mint a számítógép
- **Nincs szükség** Npcap-ra, rendszergazdai jogosultságra vagy hálózati interfész kiválasztásra

---

## Telepítés

```bash
# 1. Repository klónozása
git clone https://github.com/manszabi/zwift-udp-monitor.git
cd zwift-udp-monitor

# 2. Virtuális környezet létrehozása (opcionális, de ajánlott)
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/macOS

# 3. Nincs külső függőség – csak standard Python könyvtár szükséges
```

---

## Használat

```bash
python zwift_udp_monitor.py
```

Indítás után a program automatikusan hallgatja a ZCA broadcast csomagjait:

```
============================================================
 Zwift UDP Monitor v2.0.0
 Listens for ZCA broadcasts and forwards to smart-fan-controller
============================================================

Listening for ZCA broadcasts on UDP port 21587
Make sure the Zwift Companion App is running on the same Wi-Fi network.
Press Ctrl+C to stop.

⚡  245W  ❤️  158bpm  🚴  92rpm  🚀  34.2km/h  📦 1842 pkts
```

---

## UDP kimenet formátuma

A program másodpercenként küldi az alábbi JSON üzenetet a `127.0.0.1:7878` címre:

```json
{
  "power": 245,
  "heartrate": 158,
  "cadence": 92,
  "speed_kmh": 34.2,
  "rider_id": 123456,
  "last_update": 1709571234.56,
  "total_packets": 1842,
  "timestamp": 1709571234.57
}
```

| Mező | Típus | Leírás |
|------|-------|--------|
| `power` | int | Azonnali teljesítmény (watt) |
| `heartrate` | int | Pulzus (bpm) |
| `cadence` | int | Kadencia (RPM) |
| `speed_kmh` | float | Sebesség (km/h) |
| `rider_id` | int | Zwift rider azonosító |
| `last_update` | float | Utolsó frissítés Unix időbélyege |
| `total_packets` | int | Fogadott csomagok száma |
| `timestamp` | float | Küldés időpontja Unix időbélyegként |

---

## Integráció a smart-fan-controller-rel

A [smart-fan-controller](https://github.com/manszabi/smart-fan-controller) automatikusan figyeli a `7878`-as UDP portot. Az adatok érkezésekor:

1. `process_power_data(watt)` – ventilátor sebesség számítás
2. `process_heart_rate_data(hr)` – pulzus alapú vezérlés
3. BLE kommunikáció az ESP32 felé

A smart-fan-controller kezeli az összes átlagolást, pufferelést, zónaszámítást, hűtési késleltetést és kiesés-detektálást. A zwift-udp-monitor kizárólag **adathíd**: hallgat → dekódol → továbbít.

---

## Protobuf mezők referencia

### PlayerState mezők (Zwift belső protokoll)

| Mező # | Név | Típus | Konverzió |
|--------|-----|-------|-----------|
| 1 | `id` | int64 | Rider azonosító |
| 2 | `worldTime` | int64 | Milliszekundum |
| 3 | `distance` | int32 | Méter |
| 6 | `speed` | uint32 | mm/h → `÷ 1 000 000` = km/h |
| 9 | `cadenceUHz` | uint32 | µHz → `× 60 ÷ 1 000 000` = RPM |
| 11 | `heartrate` | uint32 | bpm (közvetlen) |
| 12 | `power` | uint32 | watt (közvetlen) |
| 15 | `climbing` | int32 | Méter |
| 16 | `time` | int32 | Eltelt másodpercek |

> **Megjegyzés:** A 7-es és 10-es mezők ki vannak hagyva a standard proto-ban.

### Wrapper üzenetek

| Irány | Mező # | Leírás |
|-------|--------|--------|
| ServerToClient | 8 | `repeated PlayerState player_states` |

---

## Hibaelhárítás

### „Failed to bind UDP socket on port 21587"
- Egy másik alkalmazás már foglalja a portot.
- Ellenőrizd, hogy a tűzfal engedi-e a 21587-es UDP portot.

### „Nincs adat fogadva" / konzol nem frissül
- A Zwift Companion App nincs elindítva, vagy nem ugyanazon a Wi-Fi hálózaton fut.
- Ellenőrizd, hogy a telefon és a számítógép ugyanazon a Wi-Fi hálózaton van-e.
- A Zwift nem fut, vagy offline módban van.

---

## Projekt struktúra

```
zwift-udp-monitor/
├── zwift_udp_monitor.py        # Főprogram (ZCA listener + protobuf + UDP broadcast)
├── test_zwift_udp_monitor.py   # Egységtesztek
├── requirements.txt            # Python függőségek (jelenleg üres – csak stdlib)
├── README.md                   # Ez a fájl
├── LICENSE                     # MIT licenc
└── .gitignore                  # Python standard
```

---

## Licenc

MIT License – © 2025 manszabi

---

## Köszönetnyilvánítás / Credits

A protobuf mezőszámok az alábbi projektekből lettek azonosítva:

- [ursoft/zwift-offline](https://github.com/ursoft/zwift-offline) – legrészletesebb kommentált proto
- [snicker/zwift_hass](https://github.com/snicker/zwift_hass)
- [vincentdavis/zwifty-packets](https://github.com/vincentdavis/zwifty-packets) – fejléc-kihagyás logika
- [zoffline/zwift-offline](https://github.com/zoffline/zwift-offline)
- [maxz000/zwift_capture](https://github.com/maxz000/zwift_capture)
- [GuLinux/Zwift-Autofan](https://github.com/GuLinux/Zwift-Autofan) – sebesség konverzió megerősítése
