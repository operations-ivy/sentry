# overwatch

Watches Bluetooth LE around the house for trackers and surveillance gadgets,
and shows what it hears at `https://overwatch.brick.nozdormu.cloud`. It's the
brick homelab's take on wigle-sync#35 (inspired by SquachWatch-CYD); it
started as a view on brick1982's arena panel (brick-cicd-config#64).

## What it recognises

Each kind has a confidence; only high and medium ones raise alerts.

| Kind | How it's recognised | Confidence |
| --- | --- | --- |
| Apple Find My tag | Apple manufacturer data, offline-finding type `0x12` | high |
| Samsung SmartTag | service `0xFD5A` | high |
| Tile tracker | services `0xFEED` / `0xFEEC` | high |
| Google Find My tag | Eddystone frames `0x40` / `0x41` | medium |
| Axon device (body camera?) | OUI `00:25:DF` (Axon Enterprise), public addresses only | high |
| Remote ID drone | service data `0xFFFA`, ASTM F3411 app code `0x0D` | high |
| Meta device (glasses?) | service `0xFD5F`; companies Meta `0x01AB`, `0x058E`, Luxottica `0x0D53` | medium |
| Snap device (Spectacles?) | company Snap `0x03C2` | medium |
| Flipper Zero | name `Flipper …`, or company Flipper Devices `0x0E29` | high |
| Flipper-like service | services `0x3081`–`0x3083` | low |
| Serial BT module (skimmer?) | names `HC-05`, `HC-06`, … | low |
| iBeacon (shop beacon?) | Apple manufacturer data, iBeacon type `0x02 0x15` | low |

Signatures come from the Bluetooth SIG's assigned numbers, the IEEE OUI
registry and published protocol specs (ASTM F3411, Apple's iBeacon); which
devices to look for follows SquachWatch-CYD, but none of its data is copied.
SquachWatch signatures with no primary source (Flock and Raven, most of its
OUI prefixes) are left out, and Wi-Fi ones need a radio overwatch doesn't
have.

### Wi-Fi attacks

A monitor-mode dongle (brick666's `wlmon0`) watches 802.11 management
frames:

| Kind | How it's recognised | Confidence |
| --- | --- | --- |
| Deauth flood | 30 or more fresh (non-retried) deauth/disassoc frames in 5 s for one BSSID; the alert names the frame count, whether it was broadcast ("to everyone"), whether both subtypes appeared (the ESP8266/Marauder pattern) and the 802.11 reason code | high on the house's networks (any of the frame's addresses: a house BSSID, a sibling of one, or a listed prefix), medium otherwise ("near the house" above -60 dBm, else "a neighbour's") |
| Evil twin | a house SSID from a BSSID that isn't the house's | high |
| Evil twin | a house BSSID offering weaker security (open, WPA2 instead of WPA3, …) | high |
| Evil twin | a house BSSID on a channel the house doesn't use, while the real one is still heard on a house channel (heard there after the other's first beacon, within 60 s) | medium |
| Karma / Pineapple | one non-house BSSID answering probes for 4 or more SSIDs in a minute | high |

A house BSSID heard only on a channel outside its list has moved (the router
restarted, or left a DFS channel for radar): not an alert, but the Wi-Fi
panel's line says so until `overwatch-wifi-home`'s channels are updated (the
router moved from 108 to 116 on 2026-10-17 and this rule fired for days).

Each one alerts as soon as it's heard; it stays on the page until it's gone
quiet for two minutes. The house's networks (name, SSID, BSSIDs, security,
channels) come from the `overwatch-wifi-home` SealedSecret in
brick-k8s-secrets, never this repo, and the page shows only their names.
Without it there are no twins, only floods and karma. The dongle spends 60%
of its time on the house's channels and hops the rest of 2.4 and 5 GHz in
between (the whole band in about 25 s), so a flood on the house is heard at
once and a twin elsewhere within half a minute.

### UPnP port forwards

UPnP lets any device on the LAN ask the router to forward an internet port to
it, with no password and no prompt. Consoles and some apps rely on it, but it
also means malware on one device could open the house to the internet
unnoticed. The UPnP watch lists the router's UPnP port forwards every minute:

| Kind | How it's recognised | Confidence |
| --- | --- | --- |
| UPnP port forward | a forward on the router that isn't on the allowed list | high |

Each one alerts when it appears ("opened"), or at the watch's start if it's
already there ("found open"), and the page lists every forward with the
device and port it reaches. brick9000's board pages on any unexpected
forward (brick-cicd-config). Allowed forwards (`OVERWATCH_UPNP_ALLOW` in
`k8s_config/upnp-deployment.yaml`) are comma-separated `PROTO/PORT[@CLIENT]`
globs, e.g. `UDP/3074@192.168.1.50` for a console. Empty: everything alerts.

The router is found by SSDP, as UPnP clients find it, but only an answer from
the router's own address, pointing at its own address, is believed, so
another device can't pose as the router with an empty table. Only UPnP error
713 counts as the end of the table: a router answering with errors is "not
answering", never "no forwards".

Households are full of trackers, so for 10 minutes after each start overwatch
learns the usual count of each kind. After that, a high or medium kind above
its usual count for two minutes raises an alert. Only devices heard in the
last 30 s count towards an alert, so a passer-by doesn't.

## The page

Laid out like wigle-console and the chuck reader (same palette and fonts),
one design for every feed:

- a status strip: each feed's state (scanning, the Wi-Fi channel, the
  router's forwards, or why one is down), the page's link to the pods, and
  how long ago the last change was;
- the state in one word and a sentence, the most severe across every feed:
  alert (any feed's, in the last 5 minutes), heads up, learning, all clear,
  scanner down or no signal;
- tiles: alerts in the last 30 minutes, then every feed's own (trackers,
  gadgets, mode; Wi-Fi attacks, access points; port forwards);
- a panel per feed, all the same shape. Bluetooth lists each kind nearby, with its maker's icon: how many, how many is usual, how
  close the nearest one is, and a verdict (usual, above usual, unsure,
  learning). A row opens to a card per device: signal now and its range,
  how long it's been here, when it was last heard, adverts and their rate,
  address type (a random address rotates), and what the advert itself says
  (name, TX power, maker data, services, a Find My tag's battery, whether a
  Google tag is away from its owner). Open rows stay open across updates.
  Wi-Fi lists the attacks heard in the last 2 minutes, UPnP every forward on
  the router (unexpected ones first).
- the last half hour's alerts from every feed, labelled with the feed. A new
  one flashes the header for a minute.

### Feeds: adding a scanner

Every watch's state carries a `panel` in one shape (`overwatch/panel.py`:
title, icon, status, a headline with a severity, stats, columns, rows that
can open into cards, an empty line, alerts), and the page renders any panel
the same way. Times travel as timestamps (`{"ago": ts}`, `{"for": ts}`), so
they keep moving between pushes. The web pods follow `OVERWATCH_FEEDS`
(`name=url,...`, in page order; the first is required). A new scanner is:

1. its watch, with a `panel(st)` that builds that shape (and its metrics);
2. a `python -m overwatch <mode>` entry, a Deployment and a Service;
3. one more `name=url` in the web Deployment's `OVERWATCH_FEEDS`.

No relay or page changes. `tests/test_web.py` holds that: a made-up feed
passes straight through to the page.

It's live: nothing polls. Each advert that changes what the page shows is
pushed from the scanner to the web pods to every open browser as it happens
(Server-Sent Events; the test suite holds that path under 100 ms). The
header shows how long ago the last change was. Trackers advertise every
0.1–2 s, so that's how fresh it gets.

## How it runs

One image (`whitepatrick/overwatch`), three roles, in the `overwatch` namespace:

- **`overwatch-scanner`**: one pod, pinned to brick666 (with
  `wlmon0`, so both radios share a node). A radio is a place,
  not a replica, so there's exactly one, and a rollout stops the old pod
  first (`Recreate`). It talks to the host's bluetoothd through the D-Bus
  system socket (a `hostPath` mount), so it runs as `nobody` (the bus refuses
  a uid the host doesn't know) with no
  capabilities, a read-only root filesystem and no host network. It
  publishes on every advert that changes the state, and on a one-second tick
  for the clock-driven changes (devices leaving, alerts, the learning
  countdown). Ready while BlueZ is scanning.
- **`overwatch-wifi`**: a DaemonSet on nodes NFD labels
  `feature.node.kubernetes.io/wifi-monitor=true` (brick-k8s-config `nfd/`),
  i.e. wherever the dongle is plugged in. It needs the host network (to
  reach `wlmon0`) and runs as root with only `NET_ADMIN` (monitor mode,
  channel hops) and `NET_RAW` (reading frames), on host port 8791. Ready
  while it's capturing. The page works without it and says so.
- **`overwatch-upnp`**: one pod on any worker, on the host network (SSDP
  only answers on the LAN, host port 8792), as `nobody` with no
  capabilities and a read-only root filesystem. Ready once it has read the
  router's table. The page works without it and says so.
- **`overwatch-web`**: two pods spread across nodes, with a
  PodDisruptionBudget (`minAvailable: 1`). They hold no state: each keeps
  one stream open to the scanner and passes each change straight on to its
  browsers, and another to the Wi-Fi watch, so either replica gives the same page. Ready once the first
  state has arrived, so a rollout keeps the old pods serving until a new one
  has data. After that, a pod stays ready if the scanner goes away (closed
  connection, or 15 s without its 5 s heartbeat) and the page says "no
  signal". When a web pod goes, browsers reconnect to the other on their own.

```
browser ◀─SSE── Caddy (brick9000) ◀── Traefik ◀── overwatch-web ×2 ◀─SSE── overwatch-scanner ◀─D-Bus── bluetoothd (brick666)
                                                            ◀─SSE── overwatch-wifi ◀─AF_PACKET── wlmon0 (brick666)
                                                            ◀─SSE── overwatch-upnp ◀─SSDP/SOAP── the router
```

| Endpoint | Scanner | Web |
| --- | --- | --- |
| `/` | | the page |
| `/api/stream` | Server-Sent Events: the state now, then each change | the same as `{error, scanner, wifi_error, wifi}` |
| `/api/state` | the state once (counts per kind, alerts, learning, error) | `{now, error, scanner, wifi_error, wifi}` once |
| `/health` | process up | process up |
| `/ready` | BlueZ scanning | has heard from the scanner |

The Wi-Fi and UPnP watches serve the same endpoints as the scanner.

Settings (environment): `OVERWATCH_PORT` (8080), `OVERWATCH_LEARN_SECONDS` (600,
scanner), `OVERWATCH_WIFI_IFACE` (`wlmon0`), `OVERWATCH_WIFI_HOME` (the house
networks' JSON), `OVERWATCH_WIFI_HOME_SHARE` (0.6), `OVERWATCH_DEAUTH_FRAMES` (30)
and `OVERWATCH_DEAUTH_SECONDS` (5, the flood window), `OVERWATCH_SCANNER_URL` and
`OVERWATCH_WIFI_URL` (web), `OVERWATCH_UPNP_ROUTER` (192.168.1.1),
`OVERWATCH_UPNP_ALLOW`, `OVERWATCH_UPNP_INTERVAL` (60) and `OVERWATCH_UPNP_URL` (web).

### The house's networks

`OVERWATCH_WIFI_HOME` is JSON, sealed into `overwatch-wifi-home` (key
`home.json`):

```json
{"networks": [{"name": "home", "ssid": "…", "bssids": ["…"], "security": "WPA2", "channels": [6, 149],
               "prefixes": ["…"]}]}
```

List every BSSID the house's access points use (each band and each mesh
node has its own). Routers also serve clients on BSSIDs they never beacon,
which the survey can't see; a deauth flood on one of those still counts
against the house when it's a sibling of a listed BSSID (the same first five
octets and the last in the same block of 16, or the same last five octets
with other bits set in the first). `prefixes` (optional) covers the rest: any
BSSID starting with one is the house's for deauths (overwatch#5). A flood's
reason says "BSSID not beaconing" when the attacked BSSID sends no beacons. For a draft from what the dongle hears, strongest first:
`kubectl -n overwatch exec ds/overwatch-wifi -- python -m overwatch wifi-survey 60`.
It prints SSIDs and BSSIDs, so it stays in the terminal: copy the house's
networks into the secret and fill in each `name`.

### Privacy

- Device addresses never leave the scanner process (nor do Wi-Fi addresses
  or SSIDs leave the Wi-Fi watch; access points are "AP 3"): each is hashed with a
  per-start salt to tell devices apart. The page numbers devices ("Device
  3") instead. No key material or raw payloads leave it either, only
  decoded fields (`describe` in `overwatch/watch.py`).
- Nothing is stored. A restart forgets everything and learns the house again.

### The host

The scanner node needs bluetoothd running with the radio unblocked
(Raspberry Pi OS starts radios blocked): `sudo rfkill unblock bluetooth`,
which systemd-rfkill then keeps. Check with `bluetoothctl show` (`Powered:
yes`). To listen somewhere else, change the scanner's `nodeSelector`.

## Icons

Inlined in the page, no requests at run time:

- brand marks (Apple, Samsung, Tile, Google, Meta, Bluetooth):
  [Simple Icons](https://simpleicons.org) 16.33.0, CC0. They're the
  companies' trademarks, used only to name their devices;
- the dolphin (Flipper): "Dolphin" by Delapouite,
  [game-icons.net](https://game-icons.net), CC BY 3.0;
- the chip (serial modules): [Lucide](https://lucide.dev) 1.48.0
  `microchip`, ISC.

## Metrics

Each pod serves `/metrics` (`overwatch/metrics.py`), scraped through
`k8s_config/podmonitor.yaml`, and the "Overwatch" Grafana dashboard
(`k8s_config/metrics-dashboard.yaml`) draws them. Counts only, never an
address or a BSSID:

- scanner: `overwatch_ble_*`: scanning, learning time left, devices nearby
  and the learned normal per kind, the closest signal per kind, adverts,
  alerts and scan failures.
- Wi-Fi watch: `overwatch_wifi_*`: capturing, channel, access points heard,
  threats now, management frames by subtype, alerts and capture failures.
- UPnP watch: `overwatch_upnp_*`: router answering, forwards now,
  unexpected forwards now, forwards opened, alerts and polls by result.
- web pods: `overwatch_web_upstream_up` and `_reconnects_total` per feed.
- all of them: `overwatch_stream_clients`, `overwatch_state_changes_total`,
  and brick-observe's `http_server_*`.

## Traces

Set `OTEL_EXPORTER_OTLP_ENDPOINT` and each pod sends spans to Tempo as
`overwatch-scan`, `-wifi`, `-upnp` and `-web`: each request except the
long-lived `/api/stream`, each UPnP poll, and each alert. An alert carries its
`traceparent` in the snapshots, so a web pod's `relay alert` span joins the
watch's trace (`overwatch/tracing.py`). Spans hold a feed and a kind, never an
address or BSSID. The scan loops have no spans of their own: they tick every
second, which would be 86,400 traces a day from each watch.

## Develop

```sh
poetry install
poetry run pytest          # unit tests, plus both HTTP servers for real
poetry run python -m overwatch web   # OVERWATCH_SCANNER_URL=http://<scanner>
```

## Release

1. Bump `version` in `pyproject.toml` and `newTag` in
   `k8s_config/kustomization.yaml` (one line; Kustomize stamps it onto all
   three Deployments and the DaemonSet, which carry the bare image name).
2. Build and push with brick-cicd-config's `build-image` Jenkins job:
   `IMAGE=whitepatrick/overwatch`, `REF=<full commit>`, `TAG=<version>`. It
   builds reproducibly and labels the image with the commit, which the
   nightly `verify-images` job rebuilds and checks.
3. Merge. Argo CD deploys `k8s_config/` from `main` within about 3 minutes
   (brick-k8s-config's `argocd/apps/overwatch.yaml`), and puts back any change
   made by hand. To try the branch on the cluster first: `scripts/trial-branch overwatch <branch>` in brick-k8s-config (and `scripts/trial-branch overwatch main` after the merge).
4. Check: `kubectl -n overwatch get pods -o wide` (one scanner on brick666,
   two web pods on different nodes, all ready) and the page.
