#!/usr/bin/env python3
"""Parity check: question types in the UI (FIELD_TYPES) vs the database (private.form_field_types),
and the types the runner can answer (--runner a,b,c or --runner-file) vs private.form_runnable_types.
Usage: check_form_type_parity.py UI_DOMAIN_TS MIGRATION_SQL [--runner LIST]"""
import re, sys
ui, mig = open(sys.argv[1]).read(), open(sys.argv[2]).read()
def arr(s, pat):
    m = re.search(pat, s, re.S)
    return re.findall(r"[\"']([a-z_]+)[\"']", m.group(1)) if m else []
ui_t = arr(ui, r"FIELD_TYPES\s*=\s*\[(.*?)\]")
db_t = arr(mig, r"form_field_types\(\).*?select array\[(.*?)\]")
db_r = arr(mig, r"form_runnable_types\(\).*?select array\[(.*?)\]")
bad = 0
if sorted(ui_t) != sorted(db_t):
    bad = 1; print("FAIL builder types differ: ui-only", sorted(set(ui_t) - set(db_t)), "db-only", sorted(set(db_t) - set(ui_t)))
else: print("ok: builder types match (%d)" % len(ui_t))
if "--runner" in sys.argv:
    run = sys.argv[sys.argv.index("--runner") + 1].split(",")
    if sorted(run) != sorted(db_r):
        bad = 1; print("FAIL runner types differ: runner-only", sorted(set(run) - set(db_r)), "db-only", sorted(set(db_r) - set(run)))
    else: print("ok: runner types match (%d)" % len(run))
else: print("note: runner list not given; database runnable types:", ",".join(db_r))
sys.exit(bad)
