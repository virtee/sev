#!/bin/sh
set -e

cd $(dirname $0)
src=$(pwd)
cd - >/dev/null

if [ ! -d build]; then
    # configure a debug build (unoptimized and with debug info) for development
    meson setup build --buildtype=debug
else
    # If using containerized build we must reconfigure inside the container.
    meson setup --reconfigure build --buildtype=debug
fi
