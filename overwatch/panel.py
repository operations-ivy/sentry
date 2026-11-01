"""The feed contract: what every watch hands the page, in one shape.

Each watch's state carries a `panel` (scanner.state adds it), and the page
renders any panel the same way, so a new scanner needs its watch, a
Deployment and Service, and an entry in the web pods' OVERWATCH_FEEDS: no
page or relay changes. A panel is:

    id, title, icon        "wifi"; "Wi-Fi"; an icon key the page knows
                           ("bluetooth", "wifi", "router"; anything else
                           gets a generic one)
    status                 {state: ok | starting | error, text}: the strip
    headline               {severity, word, tone, line}: the page shows the
                           most severe across feeds. 0 all clear, 1 learning,
                           2 heads up (unusual), 3 heads up (a threat or a
                           fault); a fresh alert from any feed outranks them
    stats                  [{label, value, sub, tone}]: summary tiles
    meta                   one line under the title
    columns                [{label, num}]: num right-aligns the column
    rows                   [{key, name, sub, icon, tone, dim, cells, verdict,
                           hot, details}]: verdict {text, tone}; details are
                           cards {title, right, meter (0-100), fields: [[k, v]]}
    empty                  shown when there are no rows
    alerts                 [{kind, label, confidence, at, ...}] as before

Tones: ok, idle, bad, cyan, magenta, unsure, dim. Any text (sub, a cell, a
field value, a headline line) may be a list of segments, each a string or
{"ago": ts} ("3 min ago"), {"for": ts} ("3 min", since ts) or {"mins": ts}
("3 min ago", rounded): the page fills those in from its own clock, so
times keep moving between pushes.
"""

from __future__ import annotations

# Icons for the Bluetooth kinds (the page draws them).
KIND_ICON = {"findmy": "apple", "smarttag": "samsung", "tile": "tile", "googletag": "google", "meta": "meta",
             "flipper": "dolphin", "flipperish": "dolphin", "skimmer": "chip", "ibeacon": "apple"}


def nearness(rssi: int) -> str:
    return "very close" if rssi >= -60 else "close" if rssi >= -75 else "far off"


def strength(rssi: int) -> int:
    """-100 dBm (edge of hearing) to -35 dBm (next to the radio), as a share."""
    return int(min(100, max(4, (rssi + 100) / 65 * 100)))


def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def status(error: str, ready: bool, ready_text: str, starting: str = "starting") -> dict:
    if error:
        return {"state": "error", "text": error}
    return {"state": "ok", "text": ready_text} if ready else {"state": "starting", "text": starting}


def bluetooth(st: dict) -> dict:
    kinds, learning, error = st.get("kinds", []), st.get("learning", 0) > 0, st.get("error", "")
    above = [k for k in kinds if not learning and k["confidence"] != "low" and k["count"] > k["normal"]]
    if error:
        headline = {"severity": 3, "word": "SCANNER DOWN", "tone": "bad", "line": f"{error}; trying again every 30 s."}
    elif above:
        headline = {"severity": 2, "word": "HEADS UP", "tone": "idle",
                    "line": " · ".join(f"{k['count']} × {k['label']}, usually {k['normal']}" for k in above)}
    elif learning:
        headline = {"severity": 1, "word": "LEARNING", "tone": "idle",
                    "line": f"Learning what's normal here: {-(-st['learning'] // 60)} min left."}
    else:
        headline = {"severity": 0, "word": "ALL CLEAR", "tone": "ok",
                    "line": "Only the usual devices nearby." if kinds else "Nothing of interest nearby."}
    trackers = sum(k["count"] for k in kinds if k["tracker"])
    gadgets = sum(k["count"] for k in kinds if not k["tracker"])
    rows = []
    for k in sorted(kinds, key=lambda k: (k not in above, -k["count"])):
        hot = k in above
        verdict = (["learning", "idle"] if learning else ["unsure", "unsure"] if k["confidence"] == "low"
                   else ["above usual", "bad"] if hot else ["usual", "ok"])
        rows.append({
            "key": k["kind"], "name": k["label"],
            "sub": f"{k['confidence']} confidence · closest {nearness(k['closest'])} ({k['closest']} dBm)",
            "icon": KIND_ICON.get(k["kind"], "bluetooth"), "tone": "cyan" if k["tracker"] else "magenta",
            "dim": k["confidence"] == "low",
            "cells": [{"text": str(k["count"]), "tone": "idle" if hot else ""},
                      {"text": "…" if learning else str(k["normal"]), "tone": "dim"}],
            "verdict": {"text": verdict[0], "tone": verdict[1]}, "hot": hot,
            "details": [device(d) for d in k.get("devices", [])],
        })
    return {
        "id": "bluetooth", "title": "Bluetooth", "icon": "bluetooth",
        "status": status(error, st.get("scanning", False), "scanning"),
        "headline": headline,
        "stats": [
            {"label": "Trackers", "value": str(trackers), "sub": "nearby now", "tone": "cyan" if trackers else "dim"},
            {"label": "Gadgets", "value": str(gadgets), "sub": "nearby now", "tone": "magenta" if gadgets else "dim"},
            {"label": "Mode", "value": f"{-(-st['learning'] // 60)}m" if learning else "WATCH",
             "sub": "learning the house" if learning else "comparing to usual", "tone": "idle" if learning else "ok"},
        ],
        "meta": "trackers and gadgets · last 2 min",
        "columns": [{"label": "What"}, {"label": "Here", "num": True}, {"label": "Usual", "num": True}],
        "rows": rows,
        "empty": "Nothing of interest nearby.",
        "alerts": st.get("alerts", []),
    }


def device(d: dict) -> dict:
    span_min = max(1, (d["last"] - d["first"]) / 60)
    fields = [
        ["here for", [{"for": d["first"]}]],
        ["last heard", [{"ago": d["last"]}]],
        ["adverts", f"{d['adverts']} ({d['adverts'] / span_min:.0f}/min)"],
        ["signal range", f"{d['rssi_min']} to {d['rssi_max']} dBm"],
    ]
    for key, label in (("name", "name"), ("battery", "battery"), ("mode", "state")):
        if d.get(key):
            fields.append([label, str(d[key])])
    if d.get("tx_power") is not None:
        fields.append(["tx power", f"{d['tx_power']} dBm"])
    if d.get("address_type"):
        fields.append(["address", "random (rotating, private)" if d["address_type"] == "random" else d["address_type"]])
    for key, label in (("makers", "maker data"), ("services", "services")):
        if d.get(key):
            fields.append([label, ", ".join(d[key])])
    return {"title": f"Device {d['n']}", "right": f"{d['rssi']} dBm · {nearness(d['rssi'])}",
            "meter": strength(d["rssi"]), "fields": fields}


def wifi(st: dict) -> dict:
    threats, error = st.get("threats", []), st.get("error", "")
    rows = []
    for t in threats:
        extra = (f" · {t['frames']} frames{', broadcast' if t.get('broadcast') else ''}" if t["kind"] == "deauth"
                 else f" · {t['ssids']} networks" if t["kind"] == "karma"
                 else f" · {t['networks']} networks" if t["kind"] == "harvester" else "")
        rows.append({
            "key": f"{t['kind']}-{t['n']}", "name": f"{t['label']} · AP {t['n']}",
            "sub": [f"{t['reason']}{extra} · ", {"for": t["first"]}, ", last ", {"ago": t["last"]}],
            "icon": "wifi", "tone": "bad" if t["confidence"] == "high" else "idle",
            "cells": [{"text": str(t["channel"]) if t.get("channel") else "—"},
                      {"text": "—" if t.get("rssi") is None else str(t["rssi"])}],
            "verdict": {"text": t["confidence"], "tone": "bad" if t["confidence"] == "high" else "idle"},
            "hot": True,
        })
    home = st.get("home", [])
    return {
        "id": "wifi", "title": "Wi-Fi", "icon": "wifi",
        "status": status(error, st.get("scanning", False), f"ch {st.get('channel') or '…'}"),
        "headline": ({"severity": 3, "word": "HEADS UP", "tone": "bad",
                      "line": " · ".join(f"{t['label']} (AP {t['n']}): {t['reason']}" for t in threats)}
                     if threats else {"severity": 0, "word": "ALL CLEAR", "tone": "ok", "line": moved_line(st)}),
        "stats": [
            {"label": "Wi-Fi attacks", "value": str(len(threats)), "sub": "going on now", "tone": "bad" if threats else "dim"},
            {"label": "Access points", "value": str(st.get("aps", 0)), "sub": "heard lately", "tone": "dim"},
        ],
        "meta": f"deauth floods · evil twins · karma · {'watching ' + ', '.join(home) if home else 'no house networks set'}",
        "columns": [{"label": "What"}, {"label": "Ch", "num": True}, {"label": "Signal", "num": True}],
        "rows": rows,
        "empty": f"{error}." if error else "No attacks heard.",
        "alerts": st.get("alerts", []),
    }


def moved_line(st: dict) -> str:
    """News, not an alert: a house network now on a channel its list lacks."""
    return " · ".join(f"{name} is on channel {ch}, which isn't in its list: update its channels"
                      for name, ch in st.get("moved", []))


def upnp(st: dict) -> dict:
    forwards, error, polled = st.get("mappings", []), st.get("error", ""), st.get("polled")
    unexpected = [f for f in forwards if not f["allowed"]]
    rows = []
    for f in unexpected + [f for f in forwards if f["allowed"]]:
        sub = [f"{f.get('description') or 'no description'}{'' if f.get('enabled', True) else ' · disabled'}"]
        if f.get("since"):
            sub += [" · seen ", {"mins": f["since"]}]
        lease = f.get("lease") or 0
        rows.append({
            "key": f"{f['protocol']}-{f['external_port']}",
            "name": f"{f['protocol']} {f['external_port']} → {f['client']}:{f['internal_port']}", "sub": sub,
            "icon": "router", "tone": "idle" if f["allowed"] else "bad",
            "cells": [{"text": f"{lease // 60} min" if lease else "∞"}],
            "verdict": {"text": "allowed" if f["allowed"] else "unexpected", "tone": "idle" if f["allowed"] else "bad"},
            "hot": not f["allowed"],
        })
    if error:
        state = {"state": "error", "text": error}
    elif not polled:
        state = {"state": "starting", "text": "asking the router"}
    else:
        state = {"state": "error" if unexpected else "ok", "text": plural(len(forwards), "forward")}
    return {
        "id": "upnp", "title": "UPnP port forwards", "icon": "router",
        "status": state,
        "headline": ({"severity": 3, "word": "HEADS UP", "tone": "bad",
                      "line": f"{plural(len(unexpected), 'UPnP port forward')} open that "
                              f"{'isn' if len(unexpected) == 1 else 'aren'}'t on the allowed list: "
                              + " · ".join(f"{f['protocol']} {f['external_port']} → {f['client']}" for f in unexpected)}
                     if unexpected else {"severity": 0, "word": "ALL CLEAR", "tone": "ok", "line": ""}),
        "stats": [{"label": "Port forwards", "value": str(len(forwards)),
                   "sub": f"{len(unexpected)} unexpected" if unexpected else "none unexpected",
                   "tone": "bad" if unexpected else "dim"}],
        "meta": f"ports opened on the router by devices · {st.get('allowed_rules') or 'none'} allowed · checked every minute",
        "columns": [{"label": "Internet port → device"}, {"label": "Lease", "num": True}],
        "rows": rows,
        "empty": f"{error}." if error else "Asking the router…" if not polled else "No ports forwarded. Good.",
        "alerts": st.get("alerts", []),
    }
