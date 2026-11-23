#!/usr/bin/env bash
set -euo pipefail
# A disposable database with no application schemas is required. This script
# never resets/drops schemas and must not be pointed at a hosted project.
: "${PGHOST:?Set a local Unix socket directory}"
: "${PGPORT:?Set the disposable local PostgreSQL port}"
: "${PGDATABASE:?Set the disposable database name}"
: "${PGUSER:?Set the local migration owner, normally postgres}"
if [[ "$PGHOST" != /* ]]; then echo 'Only a local Unix socket is accepted.' >&2; exit 1; fi
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
for f in "$ROOT"/supabase/migrations/*.sql; do psql -X -v ON_ERROR_STOP=1 -f "$f"; done
for pass in 1 2 3; do
 for f in "$ROOT"/supabase/tests/database/*.sql; do
  out=$(mktemp)
  PGOPTIONS='-c search_path=public,extensions' psql -X -qAt -v ON_ERROR_STOP=1 -f "$f" > "$out" 2>&1 || { cat "$out"; rm "$out"; exit 1; }
  cat "$out"
  if grep -Eq '^not ok|ERROR:|Looks like' "$out"; then rm "$out"; exit 1; fi
  rm "$out"
 done
done
