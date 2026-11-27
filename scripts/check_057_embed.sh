#!/usr/bin/env bash
# Drift guard: the 057 migration and rollback embedded in the pgTAP test must equal the files exactly.
set -euo pipefail
cd "$(dirname "$0")/.."
T=supabase/tests/database/platform_operator_aal2_057.test.sql
check() { local want n i got
  want=$(sha256sum < "$2" | cut -d' ' -f1)
  n=$(grep -c "^$3\$" "$T" || true)
  [ "$n" -ge 1 ] || { echo "DRIFT: no embedded $1 block in $T" >&2; exit 1; }
  for i in $(seq 1 "$n"); do
    got=$(awk -v k="$i" -v b="$3" -v e="$4" '$0==b{c++; next} $0==e{if(c==k)exit} c==k{print}' "$T" | sha256sum | cut -d' ' -f1)
    [ "$got" = "$want" ] || { echo "DRIFT: embedded $1 copy $i differs from $2" >&2; exit 1; }
  done
  echo "ok: $n embedded $1 copy matches ($want)"; }
check migration supabase/migrations/202611250057_platform_operator_aal2.sql "-- BEGIN EMBEDDED 057" "-- END EMBEDDED 057"
check rollback supabase/rollbacks/202611250057_platform_operator_aal2.rollback.sql "-- BEGIN EMBEDDED 057 ROLLBACK" "-- END EMBEDDED 057 ROLLBACK"
