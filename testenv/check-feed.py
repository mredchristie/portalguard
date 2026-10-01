#!/usr/bin/env python3
"""Checks a -json run's trace: everything it wrote to stdout was JSON lines,
and the events a GUI depends on arrived, in order.

    check-feed.py <trace>
"""
import json
import sys

events = []
for line in open(sys.argv[1]):
    # trace lines: "15:04:05.000 out   <text>"
    parts = line.rstrip("\n").split(None, 2)
    if len(parts) < 3 or parts[1] != "out":
        continue
    try:
        events.append(json.loads(parts[2]))
    except ValueError:
        sys.exit("not a JSON line on stdout: " + parts[2])

types = [e.get("type") for e in events]
for want in ("start", "login_url", "summary", "done"):
    if want not in types:
        sys.exit("no %s event (got %s)" % (want, ", ".join(types)))
states = [e["to"] for e in events if e.get("type") == "transition"]
if "SEALED" not in states:
    sys.exit("no transition to SEALED (got %s)" % ", ".join(states))
if types[0] != "start" or types[-1] != "done":
    sys.exit("start and done are not first and last: " + ", ".join(types))
print("%d events, all JSON: %s" % (len(events), " ".join(types)))
