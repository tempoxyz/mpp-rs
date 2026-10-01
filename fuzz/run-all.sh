#!/usr/bin/env bash
# Build every fuzz target and run each one for a fixed time.
#
#   fuzz/run-all.sh [seconds-per-target] [target...]
#
# FUZZ_JOBS targets run at once (default 1). Exits non-zero if a target
# crashes, hangs or leaks; its log tail and the reproducer (base64) are
# printed. FUZZ_FEATURES selects the crate features (default `tempo`), and
# extra `cargo fuzz` arguments go in CARGO_FUZZ_ARGS.
set -euo pipefail

seconds="${1:-30}"
shift || true
jobs="${FUZZ_JOBS:-1}"
fuzz_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$fuzz_dir/.."

cargo_fuzz=(cargo +nightly fuzz)
# shellcheck disable=SC2206
build_args=(--features "${FUZZ_FEATURES:-tempo}" ${CARGO_FUZZ_ARGS:-})

"${cargo_fuzz[@]}" build "${build_args[@]}"

targets=("$@")
if [[ ${#targets[@]} -eq 0 ]]; then
  while read -r target; do targets+=("$target"); done < <("${cargo_fuzz[@]}" list)
fi

dictionary() {
  case "$1" in
    fuzz_www_authenticate | fuzz_challenge_roundtrip | fuzz_challenge_list | fuzz_challenge_id | \
      fuzz_accept_payment | fuzz_sse_event)
      echo "-dict=$fuzz_dir/dict/http.dict"
      ;;
    fuzz_authorization | fuzz_credential_roundtrip | fuzz_receipt | fuzz_base64url_json | \
      fuzz_mcp | fuzz_session_payload)
      echo "-dict=$fuzz_dir/dict/json.dict"
      ;;
  esac
}

logs="$(mktemp -d)"

stat() {
  awk -v key="stat::$2:" '$1 == key { print $2 }' "$logs/$1.log"
}

run() {
  local target="$1" corpus=("$fuzz_dir/corpus/$1")
  mkdir -p "${corpus[0]}"
  [[ -d "$fuzz_dir/seeds/$target" ]] && corpus+=("$fuzz_dir/seeds/$target")
  # shellcheck disable=SC2046
  "${cargo_fuzz[@]}" run "${build_args[@]}" "$target" "${corpus[@]}" -- \
    -max_total_time="$seconds" -timeout=10 -print_final_stats=1 $(dictionary "$target") \
    >"$logs/$target.log" 2>&1
}

failed=()
for ((i = 0; i < ${#targets[@]}; i += jobs)); do
  batch=("${targets[@]:i:jobs}")
  pids=()
  for target in "${batch[@]}"; do
    run "$target" &
    pids+=($!)
  done
  for j in "${!batch[@]}"; do
    target="${batch[j]}"
    if wait "${pids[j]}"; then
      echo "ok   $target: $(stat "$target" number_of_executed_units) runs, $(stat "$target" average_exec_per_sec) exec/s"
    else
      echo "FAIL $target"
      failed+=("$target")
    fi
  done
done

for target in ${failed[@]+"${failed[@]}"}; do
  echo
  echo "==== $target ===="
  tail -n 60 "$logs/$target.log"
  for artifact in "$fuzz_dir/artifacts/$target"/*; do
    [[ -f "$artifact" ]] || continue
    echo "---- $(basename "$artifact") (base64) ----"
    base64 <"$artifact"
  done
done

[[ ${#failed[@]} -eq 0 ]]
