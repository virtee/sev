# SPDX-License-Identifier: Apache-2.0

#!/bin/sh
set -e

cd "$(dirname $0)" || exit 1
src="$(pwd)"
cd - >/dev/null || exit 1

if [ ! -d build]; then
    # configure a debug build (unoptimized and with debug info) for development
    /usr/bin/meson setup build --buildtype=debug
else
    # If using containerized build we must reconfigure inside the container.
    /usr/bin/meson setup --reconfigure build --buildtype=debug
fi
