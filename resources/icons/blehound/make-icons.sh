#!/bin/sh
# Regenerate BLEhound Analyzer icons from mark.svg (the full-bleed brand mark).
# Requires: rsvg-convert (brew install librsvg), sips, iconutil (macOS).
# Outputs are committed so normal builds do not need these tools.
set -eu
cd "$(dirname "$0")"
TOP=../../..
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Strip the outer <svg> wrapper so the mark can be nested and clipped.
MARK_BODY=$(sed -e '1d' -e '$d' mark.svg)

# macOS-style app tile: 824px squircle body centered on a 1024 canvas.
# $1 = extra SVG drawn on top (e.g. capture badge).
tile_svg() {
cat <<SVG
<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
  <defs><clipPath id="sq"><rect x="100" y="100" width="824" height="824" rx="185"/></clipPath></defs>
  <g clip-path="url(#sq)"><svg x="100" y="100" width="824" height="824" viewBox="0 0 640 640">$MARK_BODY</svg></g>
  <rect x="100.5" y="100.5" width="823" height="823" rx="185" fill="none" stroke="#5FD07C" stroke-opacity="0.25" stroke-width="3"/>
  $1
</svg>
SVG
}

tile_svg "" > "$TMP/app.svg"
# Capture-in-progress variant: red "recording" badge.
tile_svg '<circle cx="800" cy="800" r="128" fill="#0B0F16"/><circle cx="800" cy="800" r="100" fill="#E5484D"/>' > "$TMP/cap.svg"

for kind in app cap; do
    rsvg-convert -w 1024 -h 1024 "$TMP/$kind.svg" -o "$kind-1024.png"
    for s in 16 24 32 48 64 128 256 512; do
        sips -z $s $s "$kind-1024.png" --out "$kind-$s.png" >/dev/null
    done
done

# macOS bundle icon.
mkdir "$TMP/BLEhound.iconset"
for s in 16 32 128 256 512; do
    sips -z $s $s app-1024.png --out "$TMP/BLEhound.iconset/icon_${s}x${s}.png" >/dev/null
    d=$((s * 2))
    sips -z $d $d app-1024.png --out "$TMP/BLEhound.iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$TMP/BLEhound.iconset" -o "$TOP/packaging/macosx/BLEhound.icns"

# About-dialog wordmark (same 156x64 footprint as Wireshark's splash).
cat > "$TMP/splash.svg" <<SVG
<svg xmlns="http://www.w3.org/2000/svg" width="312" height="128" viewBox="0 0 312 128">
  <image href="$TMP/app.svg" x="0" y="0" width="128" height="128"/>
  <text x="128" y="62" font-family="Helvetica Neue, Helvetica, Arial, sans-serif" font-size="32" font-weight="700" fill="#37B85E">BLEhound</text>
  <text x="132" y="98" font-family="Helvetica Neue, Helvetica, Arial, sans-serif" font-size="24" fill="#8A94A6">Analyzer</text>
</svg>
SVG
rsvg-convert -w 312 -h 128 "$TMP/splash.svg" -o splash@2x.png
rsvg-convert -w 156 -h 64 "$TMP/splash.svg" -o splash.png
