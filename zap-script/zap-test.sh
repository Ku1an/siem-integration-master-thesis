#!/bin/bash

declare -A zap_automation=(
    ["zap-automation-nextjs.yaml"]="report-nextjs.json"
)

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SCRIPT="$SCRIPT_DIR/zap-script.py"

for yaml in "${!zap_automation[@]}"; do
    report="${zap_automation[$yaml]}"
    python3 "$SCRIPT" "$yaml" "$report"
done