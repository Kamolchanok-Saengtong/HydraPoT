#!/usr/bin/env sh
# tools/install_local_model.sh — install the optional on-device model arm.
#
# llama-cpp-python has no wheels, so pip compiles it. On macOS a Command Line
# Tools update can leave an SDK newer than the linker that reads it, and every
# C build fails with:
#
#   ld: tapi error: malformed file ... error: unknown architecture
#
# This finds an SDK that actually links and sets SDKROOT for the build, so the
# install is one command instead of a manual hunt.
#
#     sh tools/install_local_model.sh
set -e

PIP="${PIP:-pip}"
PROBE=$(mktemp -t hydrapot_cc_XXXXXX).c
printf 'int main(void){return 0;}\n' > "$PROBE"
OUT="${PROBE%.c}.out"

cc_works() {
    # $1: optional SDKROOT to try
    if [ -n "$1" ]; then
        SDKROOT="$1" clang "$PROBE" -o "$OUT" 2>/dev/null
    else
        clang "$PROBE" -o "$OUT" 2>/dev/null
    fi
}

if [ "$(uname -s)" = "Darwin" ]; then
    if cc_works ""; then
        echo "  compiler OK, no SDK override needed"
    else
        echo "  clang cannot link — looking for a working SDK ..."
        FOUND=""
        for sdk in /Library/Developer/CommandLineTools/SDKs/MacOSX*.sdk; do
            [ -d "$sdk" ] || continue
            case "$sdk" in */MacOSX.sdk) continue ;; esac   # the broken symlink target
            if cc_works "$sdk"; then
                FOUND="$sdk"
                break
            fi
        done
        if [ -z "$FOUND" ]; then
            echo
            echo "  No SDK in /Library/Developer/CommandLineTools/SDKs can link."
            echo "  Reinstall the Command Line Tools:"
            echo "      sudo rm -rf /Library/Developer/CommandLineTools"
            echo "      sudo xcode-select --install"
            echo
            echo "  Or skip this arm: set agents.on_device.enabled: false in config.yaml"
            rm -f "$PROBE" "$OUT"
            exit 1
        fi
        echo "  using SDKROOT=$FOUND"
        export SDKROOT="$FOUND"
    fi
fi

rm -f "$PROBE" "$OUT"
echo "  building llama-cpp-python (several minutes) ..."
$PIP install -e '.[local-model]'
echo
echo "  done. The model weights still need downloading:"
echo "      hp --init        (pick the on-device model)"
