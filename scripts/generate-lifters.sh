#!/bin/sh

set -eu

usage() {
    cat <<'EOF'
usage: ./generate-lifters.sh [--sync [--dir <path> | --ref <ref>]]
                             [--dynamic <out-file-or-dir>]

  --sync             refresh vendored language definitions before regenerating lifters
  --dir <path>       use an existing local Ghidra checkout for sync
  --ref <ref>        sync from a specific upstream ref instead of the latest stable release
  --dynamic <out>    after regenerating the static lifters, also build runtime-loadable
                     .flift packages, merge each crate's data/processors/<ARCH>/ tree
                     with the freshly built .flift files for that arch, and write the
                     result to <out>. The output format is selected from <out>'s extension:
                       *.tar.gz | *.tgz   gzip-compressed tar archive
                       *.zip              zip archive
                       (anything else)    directory (must be empty or absent)
EOF
}

run_silent() {
    LABEL="$1"
    shift

    OUTPUT_FILE="$(mktemp)"
    if "$@" >"$OUTPUT_FILE" 2>&1; then
        rm -f "$OUTPUT_FILE"
        return 0
    fi

    printf 'error: %s failed\n' "$LABEL" >&2
    cat "$OUTPUT_FILE" >&2
    rm -f "$OUTPUT_FILE"
    exit 1
}

foreach_target() {
    "$1" AARCH64:BE:64:v8A   ""        aarch64_be
    "$1" AARCH64:LE:64:v8A   ""        aarch64_le
    "$1" ARM:BE:32:v8        v8T       arm_be
    "$1" ARM:LE:32:v8        v8T       arm_le
    "$1" MIPS:BE:32:default  ""        mips_be
    "$1" MIPS:LE:32:default  ""        mips_le
    "$1" x86:LE:32:default   ""        x86
    "$1" x86:LE:64:default   compat32  x86_64
}

build_static() {
    LANGUAGE="$1"
    VARIANTS="$2"
    STATIC_OUT="$3"

    CRATE=$(printf '%s' "$LANGUAGE" | cut -d: -f1 | tr '[:upper:]' '[:lower:]')
    SPECS="./fugue-lifter-${CRATE}/data/processors"
    OUTPUT="./fugue-lifter-${CRATE}/data/generated/${STATIC_OUT}.rs.gz"

    mkdir -p "$(dirname "$OUTPUT")"
    rm -f "$OUTPUT"

    set -- cargo run --quiet --bin lifter-packager -- build-static \
        --language-db "$SPECS" \
        --language "$LANGUAGE" \
        --output "$OUTPUT"
    for V in $VARIANTS; do
        set -- "$@" --variant "$V"
    done

    run_silent "$LANGUAGE (static)" "$@"
}

build_dynamic() {
    LANGUAGE="$1"
    VARIANTS="$2"

    ARCH_DIR=$(printf '%s' "$LANGUAGE" | cut -d: -f1)
    CRATE=$(printf '%s' "$ARCH_DIR" | tr '[:upper:]' '[:lower:]')
    SPECS="./fugue-lifter-${CRATE}/data/processors"
    PREFIX=$(printf '%s' "$LANGUAGE" | cut -d: -f1-3)
    PRIMARY_SUFFIX=$(printf '%s' "$LANGUAGE" | cut -d: -f4)

    [ -d "$STAGE/$ARCH_DIR" ] || cp -R "${SPECS}/${ARCH_DIR}" "$STAGE/"

    for SUFFIX in "$PRIMARY_SUFFIX" $VARIANTS; do
        LANG="${PREFIX}:${SUFFIX}"
        OUTPUT="$STAGE/$ARCH_DIR/$(printf '%s' "$LANG" | tr ':' '_').flift"
        run_silent "$LANG (dynamic)" \
            cargo run --quiet --bin lifter-packager -- build-dynamic \
            --language-db "$SPECS" \
            --language "$LANG" \
            --output "$OUTPUT"
    done
}

INVOCATION_PWD="$PWD"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

SYNC=false
SYNC_DIR=""
SYNC_REF=""
DYNAMIC=""

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
        --dynamic)
            if [ "$#" -lt 2 ]; then
                usage >&2
                exit 1
            fi
            DYNAMIC="$2"
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

if [ -n "$DYNAMIC" ]; then
    case "$DYNAMIC" in
        /*) ;;
        *)  DYNAMIC="$INVOCATION_PWD/$DYNAMIC" ;;
    esac
fi

cd "$SCRIPT_DIR"

if [ "$SYNC" = true ]; then
    printf "Synchronising language definitions...\n"

    set -- cargo run --quiet --bin lifter-packager -- sync
    [ -n "$SYNC_DIR" ] && set -- "$@" --dir "$SYNC_DIR"
    [ -n "$SYNC_REF" ] && set -- "$@" --ref "$SYNC_REF"

    run_silent "sync" "$@"
fi

printf "Generating lifters...\n"
foreach_target build_static

if [ -n "$DYNAMIC" ]; then
    case "$DYNAMIC" in
        *.tar.gz|*.tgz) FORMAT=tar ;;
        *.zip)          FORMAT=zip ;;
        *)              FORMAT=dir ;;
    esac

    if [ "$FORMAT" = dir ] && [ -e "$DYNAMIC" ]; then
        if [ ! -d "$DYNAMIC" ] || [ -n "$(ls -A "$DYNAMIC" 2>/dev/null)" ]; then
            printf 'error: %s exists and is not an empty directory\n' "$DYNAMIC" >&2
            exit 1
        fi
    fi

    STAGE="$(mktemp -d)"
    trap 'rm -rf "$STAGE"' EXIT INT HUP TERM

    foreach_target build_dynamic

    printf "Writing language specification bundle to %s...\n" "$DYNAMIC"
    case "$FORMAT" in
        dir)
            mkdir -p "$DYNAMIC"
            for d in "$STAGE"/*; do
                [ -d "$d" ] && mv "$d" "$DYNAMIC/"
            done
            ;;
        tar)
            mkdir -p "$(dirname "$DYNAMIC")"
            rm -f "$DYNAMIC"
            ( cd "$STAGE" && tar -czf "$DYNAMIC" -- * )
            ;;
        zip)
            mkdir -p "$(dirname "$DYNAMIC")"
            rm -f "$DYNAMIC"
            ( cd "$STAGE" && zip -qr "$DYNAMIC" -- * )
            ;;
    esac
fi

printf '%s\n' "Done"
