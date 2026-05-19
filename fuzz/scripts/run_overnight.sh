#!/usr/bin/env bash
#
# Run all fuzzing harnesses with corpus management and time limits.
# Intended for unattended overnight runs.
#
# Usage:
#   ./run_overnight.sh [max_total_seconds]
#
# Default: 6 hours (21600 seconds)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FUZZ_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$FUZZ_DIR/build}"
SEED_DIR="$FUZZ_DIR/seeds"
DICT_DIR="$FUZZ_DIR/dictionaries"
CORPUS_DIR="$FUZZ_DIR/corpus"
FINDINGS_DIR="$FUZZ_DIR/findings"

MAX_TOTAL="${1:-21600}"

HARNESSES=(
    "fuzz_http1_request_parser:http1_requests:http.dict"
    "fuzz_http1_response_parser:http1_responses:http.dict"
    "fuzz_uri_parser:uris:uri.dict"
    "fuzz_http_header_parser:http_headers:http.dict"
    "fuzz_content_length:content_lengths:"
    "fuzz_tls_handshake:tls_handshakes:tls.dict"
    "fuzz_cache_control:cache_control:http.dict"
    "fuzz_dns_message:dns_messages:"
    "fuzz_ftp_parsing:ftp_parsing:"
)

mkdir -p "$CORPUS_DIR" "$FINDINGS_DIR"

PER_HARNESS=$(( MAX_TOTAL / ${#HARNESSES[@]} ))
echo "=== Overnight Fuzzing Run ==="
echo "Total time budget: ${MAX_TOTAL}s"
echo "Per harness: ${PER_HARNESS}s"
echo "Harnesses: ${#HARNESSES[@]}"
echo ""

TOTAL_FINDINGS=0

for entry in "${HARNESSES[@]}"; do
    IFS=':' read -r name seeds dict <<< "$entry"
    
    harness="$BUILD_DIR/$name"
    if [[ ! -x "$harness" ]]; then
        echo "SKIP: $name (not found at $harness)"
        continue
    fi
    
    corpus="$CORPUS_DIR/$name"
    mkdir -p "$corpus"
    
    seed_arg=""
    if [[ -n "$seeds" && -d "$SEED_DIR/$seeds" ]]; then
        seed_arg="$SEED_DIR/$seeds"
    fi
    
    dict_arg=""
    if [[ -n "$dict" && -f "$DICT_DIR/$dict" ]]; then
        dict_arg="-dict=$DICT_DIR/$dict"
    fi
    
    findings="$FINDINGS_DIR/$name"
    mkdir -p "$findings"
    
    echo "--- Running $name (${PER_HARNESS}s) ---"
    
    "$harness" \
        "$corpus" \
        $seed_arg \
        -max_total_time="$PER_HARNESS" \
        -max_len=65536 \
        -artifact_prefix="$findings/" \
        $dict_arg \
        -print_final_stats=1 \
        2>&1 | tee "$findings/${name}.log" || true
    
    crash_count=$(find "$findings" -name 'crash-*' -o -name 'leak-*' -o -name 'timeout-*' 2>/dev/null | wc -l | tr -d ' ')
    echo "  Findings for $name: $crash_count"
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + crash_count))
    echo ""
done

echo "=== Fuzzing Complete ==="
echo "Total findings across all harnesses: $TOTAL_FINDINGS"
echo ""
echo "Findings directory: $FINDINGS_DIR"
echo "Corpus directory: $CORPUS_DIR"

if [[ $TOTAL_FINDINGS -gt 0 ]]; then
    echo ""
    echo "=== Crash/Leak Files ==="
    find "$FINDINGS_DIR" -name 'crash-*' -o -name 'leak-*' -o -name 'timeout-*' 2>/dev/null
fi
