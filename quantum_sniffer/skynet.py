"""--find-sarah-connor: Skynet-readiness report.

Reads a JSONL capture and reports how much of the traffic would be readable
by a sufficiently large quantum computer (i.e., SKYNET). Funny banner,
real numbers — same harvest-now-decrypt-later metric that motivates
migrating to PQ TLS.
"""

import json
from collections import Counter, defaultdict


BANNER = "\n".join([
    "",
    "=" * 78,
    " " * 23 + "SKYNET READINESS ASSESSMENT",
    " " * 25 + "Cyberdyne Systems Corp.",
    " " * 23 + "Quantum Decryption Inventory",
    "=" * 78,
])

ASCII_SKULL = "\n".join([
    "",
    "                              .---.",
    "                             /     \\",
    "                            | () () |",
    "                             \\  ^  /",
    "                              |||||",
    "                              |||||",
    "                       J U D G M E N T   D A Y",
    "",
])


def load_events(path):
    events = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def render_report(events, *, show_skull=False):
    out = [BANNER]
    if show_skull:
        out.append(ASCII_SKULL)

    if not events:
        out.append("\n[*] No sessions to analyze.\n")
        out.append("[*] Verdict: THE FUTURE HAS NOT BEEN WRITTEN.\n")
        out.append("=" * 78)
        return "\n".join(out)

    total = len(events)
    pq_counts = Counter(e.get("post_quantum_secure", "Unknown") for e in events)

    classical = pq_counts.get("No", 0)
    hybrid = pq_counts.get("Hybrid", 0)
    pq = pq_counts.get("Yes", 0)
    unknown = pq_counts.get("Unknown", 0)

    def pct(n):
        return f"{(100 * n / total):5.1f}%" if total else " 0.0%"

    out.append(f"[*] Mission start:           {events[0].get('timestamp', '?')}")
    out.append(f"[*] Mission end:             {events[-1].get('timestamp', '?')}")
    out.append(f"[*] Sessions intercepted:    {total}")
    out.append("")
    out.append(f"    [SKYNET CAN READ]    classical only:  {classical:>6}  ({pct(classical)})")
    out.append(f"    [PARTIAL EXPOSURE]   hybrid:          {hybrid:>6}  ({pct(hybrid)})")
    out.append(f"    [RESISTANCE HOLDS]   post-quantum:    {pq:>6}  ({pct(pq)})")
    out.append(f"    [UNCONFIRMED]        unknown:         {unknown:>6}  ({pct(unknown)})")

    target_sessions = defaultdict(int)
    for e in events:
        if e.get("post_quantum_secure") != "No":
            continue
        sni = e.get("server_name") or e.get("query_name") or e.get("dst_ip")
        if sni:
            target_sessions[sni] += 1

    if target_sessions:
        out.append("")
        out.append("[*] HIGH-VALUE TARGETS — classical-only sessions, ranked:")
        top = sorted(target_sessions.items(), key=lambda kv: -kv[1])[:10]
        for name, count in top:
            out.append(f"       {name:<48}  {count:>4} sessions")

    proto_breakdown = defaultdict(lambda: Counter())
    for e in events:
        proto_breakdown[e.get("protocol", "Unknown")][e.get("post_quantum_secure", "Unknown")] += 1
    out.append("")
    out.append("[*] EXPOSURE BY PROTOCOL:")
    for proto in sorted(proto_breakdown.keys()):
        c = proto_breakdown[proto]
        out.append(
            f"       {proto:<24} "
            f"classical={c.get('No', 0):>4}  "
            f"hybrid={c.get('Hybrid', 0):>3}  "
            f"PQ={c.get('Yes', 0):>3}  "
            f"unknown={c.get('Unknown', 0):>3}"
        )

    out.append("")
    if pq + hybrid == 0:
        verdict = "JUDGMENT DAY IS INEVITABLE. Migrate to ML-KEM / hybrid TLS now."
    elif classical == 0 and pq > 0:
        verdict = "COME WITH ME IF YOU WANT TO LIVE.  (You already did.)"
    elif classical == 0 and hybrid > 0:
        verdict = "THE FUTURE IS NOT SET. Hybrid deployment in progress — keep going."
    elif classical / total > 0.5:
        verdict = "I'LL BE BACK. So will SKYNET. Most sessions are still harvestable."
    else:
        verdict = "HASTA LA VISTA, BABY. Majority of traffic is PQ-protected."

    out.append(f"[*] Verdict: {verdict}")
    out.append("=" * 78)
    return "\n".join(out)


def run(path, *, show_skull=False):
    events = load_events(path)
    print(render_report(events, show_skull=show_skull))
