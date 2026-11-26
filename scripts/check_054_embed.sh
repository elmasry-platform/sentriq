#!/usr/bin/env bash
# Drift guard: the 054 body embedded in the pgTAP test must equal the migration file exactly.
set -euo pipefail
cd "$(dirname "$0")/.."
M=supabase/migrations/202611250054_admin_sees_lower_members.sql
T=supabase/tests/database/team_visibility_054.test.sql
want=$(sha256sum < "$M" | cut -d' ' -f1)
n=$(grep -c '^-- BEGIN EMBEDDED 054' "$T")
[ "$n" -ge 1 ] || { echo "DRIFT: no embedded 054 block in $T" >&2; exit 1; }
for i in $(seq 1 "$n"); do
  got=$(awk -v k="$i" '/^-- BEGIN EMBEDDED 054/{c++; next} /^-- END EMBEDDED 054/{if(c==k)exit} c==k{print}' "$T" | sha256sum | cut -d' ' -f1)
  [ "$got" = "$want" ] || { echo "DRIFT: embedded copy $i in $T differs from $M" >&2; exit 1; }
done
echo "ok: $n embedded copy matches the migration ($want)"
