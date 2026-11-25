#!/bin/sh
# usage: video/render.sh OUT.mp4 PROPS.json   (npm i here first; system Chrome, concurrency 1; ~30 s for 2 s on 1 CPU). Called by `video-export`, which only passes APPROVED, hash-verified text.
set -e; cd "$(dirname "$0")"
npx remotion render src/index.jsx Clip "$1" --browser-executable="${CHROME:-/opt/google/chrome/chrome}" --concurrency=1 --log=error --props="$2"
