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

- 🔵 **Nincs Zwift bejelentkezés szükséges** – tiszta hálózati csomagelfogás (`zwift_udp_monitor.py`)
- 🔑 **API polling alternatíva** – OAuth2 alapú HTTPS lekérdezés, telefon nélkül (`zwift_api_polling.py`)
- ⚡ **Azonnali értékek** – nincs átlagolás/simítás (a fogyasztó kezeli a pufferelést)
- 📡 **UDP broadcast** – alacsony késleltetés, JSON formátum
- 🔧 **Raw protobuf dekóder** – nem szükséges `.proto` fájl fordítás
- 🖥️ **Windows / Linux / macOS** – csak standard Python socket, Npcap nélkül
- 🔓 **Nincs rendszergazdai jogosultság szükséges**

---

## Architektúra

### 1. opció – ZCA listener (`zwift_udp_monitor.py`)

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

### 2. opció – API polling (`zwift_api_polling.py`)

```
[Zwift Cloud API]
    ▲
    │  HTTPS polling (~1s)
    │
[zwift_api_polling.py]          ← OAuth2 auth + REST API polling
    │                              Nincs Zwift Companion App szükséges
    │  UDP:7878 (127.0.0.1)
    ▼
[smart_fan_controller.py]
    │
    │  BLE
    ▼
[ESP32 Smart Fan]
```

---

## Előfeltételek

### `zwift_udp_monitor.py` (ZCA listener)

- **Windows 11**
- **[Npcap](https://npcap.com/#download)** – telepítéskor **be kell pipálni** a `WinPcap API-compatible Mode` opciót!
- **Python 3.8+**
- **Zwift Companion App** – telepítve a telefonon, ugyanazon a Wi-Fi hálózaton mint a számítógép
- **Nincs szükség** Npcap-ra, rendszergazdai jogosultságra vagy hálózati interfész kiválasztásra

### `zwift_api_polling.py` (API polling)

- **Python 3.8+** (bármely platformon)
- **Zwift bejelentkezési adatok** (`ZWIFT_USERNAME` / `ZWIFT_PASSWORD` env változók, CLI flagek, `zwift_api_settings.json` fájl, vagy interaktív prompt)
- Nincs Npcap, nincs Zwift Companion App, nincs Administrator jog szükséges

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

### 1. opció – `zwift_udp_monitor.py` (ZCA listener)

> ⚠️ **A programot Administrator jogosultsággal kell futtatni!**

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

### 2. opció – `zwift_api_polling.py` (API polling)

#### Credential prioritási sorrend / Credential priority order

1. CLI flagek (`--username`, `--password`)
2. Környezeti változók (`ZWIFT_USERNAME`, `ZWIFT_PASSWORD`)
3. `zwift_api_settings.json` fájl
4. Interaktív prompt (az eredmény automatikusan mentésre kerül a `zwift_api_settings.json` fájlba)

#### Settings fájl / Settings file

Másold le a `zwift_api_settings.json.example` fájlt `zwift_api_settings.json` névvel és töltsd ki:

```json
{
  "username": "user@example.com",
  "password": "yourpassword",
  "broadcast_host": "127.0.0.1",
  "broadcast_port": 7878,
  "poll_interval": 5.0
}
```

> ⚠️ **A `zwift_api_settings.json` fájl a `.gitignore`-ban van – jelszavad nem kerül a repóba.**

```bash
# Settings fájllal / With settings file:
cp zwift_api_settings.json.example zwift_api_settings.json
# szerkeszd a fájlt / edit the file
python zwift_api_polling.py

# Env változókkal / With env variables:
export ZWIFT_USERNAME=user@example.com
export ZWIFT_PASSWORD=yourpassword
python zwift_api_polling.py

# CLI flagekkel / With CLI flags:
python zwift_api_polling.py --username user@example.com --password yourpassword

# Interaktív prompt (ha nincs megadva / if not provided):
python zwift_api_polling.py

# Opcionális flagek / Optional flags:
python zwift_api_polling.py --poll-interval 2.0 --debug

# smart_fan_controller.py automatikus indítás letiltása / Disable auto-start:
python zwift_api_polling.py --no-fan-controller
```

```
============================================================
 Zwift API Polling Monitor v1.0.0
 HTTPS API lekérdezés + UDP broadcast (127.0.0.1:7878)
============================================================

Bejelentkezés folyamatban / Logging in …
Profil lekérése / Fetching profile …
✅ Rider ID: 123456
🚀 smart_fan_controller.py elindítva / started (PID 12345)
🔄 Lekérdezési intervallum / Poll interval: 5.0s
Press Ctrl+C to stop.

⚡  245W  ❤️  158bpm  🚴  92rpm  🚀  34.2km/h  📦 42 polls
```

#### `smart_fan_controller.py` automatikus indítása / Auto-start

Ha a `smart_fan_controller.py` ugyanabban a könyvtárban van mint a `zwift_api_polling.py`, akkor a script automatikusan elindítja azt a polling loop előtt. A leálláskor (Ctrl+C) a subprocess is leáll.

Az automatikus indítás letiltható a `--no-fan-controller` flaggel.

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
├── zwift_udp_monitor.py           # ZCA listener (Npcap + protobuf + UDP broadcast)
├── zwift_api_polling.py           # API polling alternatíva (OAuth2 + HTTPS + UDP broadcast)
├── zwift_api_settings.json.example # Minta settings fájl (credentials nélkül)
├── test_zwift_udp_monitor.py      # Egységtesztek (zwift_udp_monitor)
├── test_zwift_api_polling.py      # Egységtesztek (zwift_api_polling)
├── requirements.txt               # Python függőségek
├── README.md                      # Ez a fájl
├── LICENSE                        # MIT licenc
└── .gitignore                     # Python standard + zwift_api_settings.json
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
