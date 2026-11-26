#!/usr/bin/env bash
# Drift guard: the 054 migration and rollback embedded in the pgTAP test must equal the files exactly.
# The CI test container cannot read the repo folders, so the test embeds both texts; this runs outside it.
set -euo pipefail
cd "$(dirname "$0")/.."
T=supabase/tests/database/team_visibility_054.test.sql
check() { # name file begin-marker end-marker
  local want n i got
  want=$(sha256sum < "$2" | cut -d' ' -f1)
  n=$(grep -c "^$3\$" "$T" || true)
  [ "$n" -ge 1 ] || { echo "DRIFT: no embedded $1 block in $T" >&2; exit 1; }
  for i in $(seq 1 "$n"); do
    got=$(awk -v k="$i" -v b="$3" -v e="$4" '$0==b{c++; next} $0==e{if(c==k)exit} c==k{print}' "$T" | sha256sum | cut -d' ' -f1)
    [ "$got" = "$want" ] || { echo "DRIFT: embedded $1 copy $i in $T differs from $2" >&2; exit 1; }
  done
  echo "ok: $n embedded $1 copy matches ($want)"
}
check migration supabase/migrations/202611250054_admin_sees_lower_members.sql "-- BEGIN EMBEDDED 054" "-- END EMBEDDED 054"
check rollback supabase/rollbacks/202611250054_admin_sees_lower_members.rollback.sql "-- BEGIN EMBEDDED 054 ROLLBACK" "-- END EMBEDDED 054 ROLLBACK"
