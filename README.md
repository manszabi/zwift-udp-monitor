# Zwift UDP Monitor

![Version](https://img.shields.io/badge/version-v1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![Platform](https://img.shields.io/badge/platform-Windows%2011-lightgrey)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

**Zwift UDP forgalom elfogása és valós idejű power/HR adat továbbítása a [smart-fan-controller](https://github.com/manszabi/smart-fan-controller) számára.**

Npcap segítségével elfogja a Zwift UDP csomagjait (port 3022), dekódolja a protobuf üzeneteket, és azonnali teljesítmény/pulzus/kadencia/sebesség adatokat küld UDP-n keresztül (127.0.0.1:7878).

---

## Funkciók

- 🔵 **Nincs Zwift bejelentkezés szükséges** – tiszta hálózati csomagelfogás
- ⚡ **Azonnali értékek** – nincs átlagolás/simítás (a fogyasztó kezeli a pufferelést)
- 📡 **UDP broadcast** – alacsony késleltetés, JSON formátum
- 🔧 **Raw protobuf dekóder** – nem szükséges `.proto` fájl fordítás
- 🖥️ **Windows 11** – Npcap alapú csomagelfogás

---

## Architektúra

```
[Zwift App]
    │
    │  UDP:3022
    ▼
[zwift_udp_monitor.py]          ← Npcap capture + protobuf dekódolás
    │                              Azonnali értékek, NEM átlagolt
    │  UDP:7878 (127.0.0.1)
    ▼
[smart_fan_controller.py]       ← buffer_seconds + minimum_samples + cooldown
    │
    │  BLE
    ▼
[ESP32 Smart Fan]
```

---

## Előfeltételek

- **Windows 11**
- **[Npcap](https://npcap.com/#download)** – telepítéskor **be kell pipálni** a `WinPcap API-compatible Mode` opciót!
- **Python 3.8+**
- **Administrator jogosultság** a szkript futtatásához

---

## Telepítés

```bash
# 1. Repository klónozása
git clone https://github.com/manszabi/zwift-udp-monitor.git
cd zwift-udp-monitor

# 2. Virtuális környezet létrehozása (opcionális, de ajánlott)
python -m venv venv
venv\Scripts\activate

# 3. Függőségek telepítése
pip install -r requirements.txt
```

---

## Használat

> ⚠️ **A programot Administrator jogosultsággal kell futtatni!**

```bash
python zwift_udp_monitor.py
```

Indítás után válaszd ki a megfelelő hálózati interfészt (általában az, amelyiken a Zwift fut):

```
============================================================
 Zwift UDP Monitor v1.0.0
 Captures Zwift traffic and broadcasts to smart-fan-controller
============================================================

Elérhető hálózati interfészek / Available network interfaces:
  [0] \Device\NPF_{XXXXXXXX-...}  (Ethernet)
  [1] \Device\NPF_{YYYYYYYY-...}  (Wi-Fi)

Válassz interfészt (szám) / Select interface (number): 0

Capturing on \Device\NPF_{...} – BPF: udp port 3022
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

A smart-fan-controller kezeli az összes átlagolást, pufferelést, zónaszámítást, hűtési késleltetést és kiesés-detektálást. A zwift-udp-monitor kizárólag **adathíd**: elfog → dekódol → továbbít.

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
| ClientToServer | 7 | `PlayerState state` (saját adataink) |

---

## Hibaelhárítás

### „No network interfaces found"
- Nincs telepítve a Npcap, vagy nem lett bekapcsolva a **WinPcap API-compatible Mode** telepítés közben.
- Töltsd le újra: [https://npcap.com/#download](https://npcap.com/#download)

### „Failed to start capture"
- A szkriptet nem **Administrator** jogosultsággal futtattad.
- Kattints jobb gombbal a parancsorra → „Futtatás rendszergazdaként"

### „Nincs adat fogadva" / konzol nem frissül
- Rossz hálózati interfész lett kiválasztva – próbáld a másikat.
- A Zwift nem fut, vagy offline módban van.
- Ellenőrizd, hogy a tűzfal nem blokkolja-e az UDP 3022-es portot.

---

## Projekt struktúra

```
zwift-udp-monitor/
├── zwift_udp_monitor.py   # Főprogram (Npcap + protobuf + UDP broadcast)
├── requirements.txt       # Python függőségek
├── README.md              # Ez a fájl
├── LICENSE                # MIT licenc
└── .gitignore             # Python standard
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
