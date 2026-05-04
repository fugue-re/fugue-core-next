#!/bin/sh

set -eu

usage() {
    cat <<'EOF'
usage: ./generate-lifters.sh [--sync] [--dir <path>] [--ref <git-ref>]

  --sync        refresh vendored language definitions before regenerating lifters
  --dir <path>  use an existing local Ghidra checkout for sync
  --ref <ref>   sync from a specific upstream ref instead of the latest stable release

After --sync, any *.patch files under <arch>/data/patches/ are re-applied on
the fly during regeneration. If upstream churn moved lines near a patched
region, the build fails loudly and the patch must be re-diffed against the
fresh sources. See fugue-lifter-arm/README.md for patch authoring rules
(paths relative to data/processors/, no fuzz, filename-ordered application).
EOF
}

run_step() {
    STEP_NAME="$1"
    shift

    printf '%s\n' "$STEP_NAME"

    OUTPUT_FILE="$(mktemp)"
    if "$@" >"$OUTPUT_FILE" 2>&1; then
        rm -f "$OUTPUT_FILE"
        return 0
    fi

    printf 'error: %s failed\n' "$STEP_NAME" >&2
    cat "$OUTPUT_FILE" >&2
    rm -f "$OUTPUT_FILE"
    exit 1
}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

SYNC=false
SYNC_DIR=""
SYNC_REF=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --sync)
            SYNC=true
            shift
            ;;
        --dir)
            if [ "$#" -lt 2 ]; then
                usage >&2
                exit 1
            fi
            SYNC_DIR="$2"
            shift 2
            ;;
        --ref)
            if [ "$#" -lt 2 ]; then
                usage >&2
                exit 1
            fi
            SYNC_REF="$2"
            shift 2
            ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
done

if [ "$SYNC" = false ] && { [ -n "$SYNC_DIR" ] || [ -n "$SYNC_REF" ]; }; then
    usage >&2
    exit 1
fi

if [ -n "$SYNC_DIR" ] && [ -n "$SYNC_REF" ]; then
    usage >&2
    exit 1
fi

cd "$SCRIPT_DIR"

if [ "$SYNC" = true ]; then
    set -- cargo run --quiet --bin lifter-packager -- sync

    if [ -n "$SYNC_DIR" ]; then
        set -- "$@" --dir "$SYNC_DIR"
    fi

    if [ -n "$SYNC_REF" ]; then
        set -- "$@" --ref "$SYNC_REF"
    fi

    run_step "Synchronising language definitions..." "$@"
fi

run_step \
    "Generating AArch64 big-endian lifter..." \
    cargo run --quiet --bin lifter-packager -- \
    ./fugue-lifter-aarch64/data/processors \
    AARCH64:BE:64:v8A \
    ./fugue-lifter-aarch64/data/generated/aarch64_be.rs.gz

run_step \
    "Generating AArch64 little-endian lifter..." \
    cargo run --quiet --bin lifter-packager -- \
    ./fugue-lifter-aarch64/data/processors \
    AARCH64:LE:64:v8A \
    ./fugue-lifter-aarch64/data/generated/aarch64_le.rs.gz

run_step \
    "Generating ARM big-endian lifter..." \
    cargo run --quiet --bin lifter-packager -- \
    ./fugue-lifter-arm/data/processors \
    ARM:BE:32:v8 \
    ./fugue-lifter-arm/data/generated/arm_be.rs.gz \
    --variant v8T

run_step \
    "Generating ARM little-endian lifter..." \
    cargo run --quiet --bin lifter-packager -- \
    ./fugue-lifter-arm/data/processors \
    ARM:LE:32:v8 \
    ./fugue-lifter-arm/data/generated/arm_le.rs.gz \
    --variant v8T

run_step \
    "Generating x86 lifter..." \
    cargo run --quiet --bin lifter-packager -- \
    ./fugue-lifter-x86/data/processors \
    x86:LE:32:default \
    ./fugue-lifter-x86/data/generated/x86.rs.gz

run_step \
    "Generating x86-64 lifter..." \
    cargo run --quiet --bin lifter-packager -- \
    ./fugue-lifter-x86/data/processors \
    x86:LE:64:default \
    ./fugue-lifter-x86/data/generated/x86_64.rs.gz \
    --variant compat32

printf '%s\n' "Done"
