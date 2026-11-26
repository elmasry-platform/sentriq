#!/usr/bin/env bash
# Drift guard: every copy of 052 embedded in the pgTAP test must equal the migration file exactly.
# The CI test container cannot read supabase/migrations, so the test embeds the text; this runs outside it.
set -euo pipefail
cd "$(dirname "$0")/.."
M=supabase/migrations/202611250052_snapshot_decisions_conservative.sql
T=supabase/tests/database/snapshot_conservative_052.test.sql
want=$(sha256sum < "$M" | cut -d' ' -f1)
n=$(grep -c '^-- BEGIN EMBEDDED 052' "$T")
[ "$n" -ge 1 ] || { echo "DRIFT: no embedded 052 block in $T" >&2; exit 1; }
for i in $(seq 1 "$n"); do
  got=$(awk -v k="$i" '/^-- BEGIN EMBEDDED 052/{c++; next} /^-- END EMBEDDED 052/{if(c==k)exit} c==k{print}' "$T" | sha256sum | cut -d' ' -f1)
  [ "$got" = "$want" ] || { echo "DRIFT: embedded copy $i in $T differs from $M" >&2; exit 1; }
done
echo "ok: $n embedded copies match the migration ($want)"
