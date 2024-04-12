# SPDX-License-Identifier: Apache-2.0

#!/bin/bash
set -e

meson_debug="$1"
meson_optimization="$2"
target_dir="$3"
output="$4"

args=( --target-dir "${target_dir}" )
rustflags=()

case "${meson_debug}" in
    true)  rustflags+=( -C debuginfo=2 ) ;;
    false) rustflags+=( -C debuginfo=0 ) ;;
    *)     exit 2 ;;
esac

case "${meson_optimization}" in
    plain)
        # A release build without explicit optimization flags
        profile=release
        args+=( --release )
        ;;
    0)
        profile=debug
        rustflags+=( -C opt-level=0 )
        ;;
    1|2|3|s)
        # Use release profile to enable optimization options other than
        # opt-level.
        profile=release
        args+=( --release )
        rustflags+=( -C opt-level="${meson_optimization}" )
        ;;
    *)
        exit 2
        ;;
esac

if [[ "${profile}" == "debug" ]] && command -v cargo-clippy >/dev/null; then
    (
        cd "$( dirname "$0" )" &&
        set -x &&
        RUSTFLAGS="$RUSTFLAGS ${rustflags[*]}" cargo clippy "${args[@]}" \
            --color always --locked --all-features --all-targets --workspace \
            -- --deny warnings
    )
fi

(
    cd "$( dirname "$0" )" &&
    set -x &&
    RUSTFLAGS="$RUSTFLAGS ${rustflags[*]}" cargo build "${args[@]}" \
        --color always --locked
)

cp -u "${target_dir}/${profile}/libsev.a" "${output}"
