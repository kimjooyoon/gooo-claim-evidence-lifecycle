#!/usr/bin/env bash
set -uo pipefail

phase=${1:?phase is required}
result_dir=${2:?result directory is required}
shift 2
mkdir -p "$result_dir"

start=$(date +%s%N)
set +e
/usr/bin/time -f '%M' -o "$result_dir/$phase.peak_rss_kib" "$@" >"$result_dir/$phase.log" 2>&1
exit_code=$?
set -e
end=$(date +%s%N)
wall_ms=$(( (end - start) / 1000000 ))

rss=null
if test -s "$result_dir/$phase.peak_rss_kib"; then
  candidate=$(tr -d '[:space:]' <"$result_dir/$phase.peak_rss_kib")
  if [[ "$candidate" =~ ^[0-9]+$ ]]; then
    rss=$candidate
  fi
fi

if test "$exit_code" -eq 0; then
  conclusion=success
else
  conclusion=failure
fi

jq -n \
  --arg phase "$phase" \
  --arg conclusion "$conclusion" \
  --argjson exit_code "$exit_code" \
  --argjson wall_ms "$wall_ms" \
  --argjson peak_rss_kib "$rss" \
  '{phase:$phase,conclusion:$conclusion,exit_code:$exit_code,wall_ms:$wall_ms,peak_rss_kib:$peak_rss_kib}' \
  >"$result_dir/$phase.json"

exit "$exit_code"
