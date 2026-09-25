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

# Toolbar capture icons (replace Wireshark's trademarked shark-fin icons).
# 24-unit viewBox; rendered at 16/24 px and @2x.
toolbar_svg() {  # $1 = ring colour, $2 = glyph
cat <<SVG
<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0%" stop-color="#8CE6A2"/><stop offset="100%" stop-color="#2FA353"/></linearGradient></defs>
  <circle cx="12" cy="12" r="10.5" fill="url(#g)" stroke="$1" stroke-width="1"/>
  $2
</svg>
SVG
}
BT='<path d="M8.6 9.2 L15 14.3 L12 16.8 L12 7.2 L15 9.7 L8.6 14.8" fill="none" stroke="#FFFFFF" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>'
ARROW='<path d="M16.6 10.2 A5 5 0 1 0 16.9 13.4" fill="none" stroke="#FFFFFF" stroke-width="1.7" stroke-linecap="round"/><path d="M17.4 6.9 L17 10.7 L13.3 9.9" fill="none" stroke="#FFFFFF" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>'
toolbar_svg "#1E7A3C" "$BT"    > "$TMP/start.svg"
toolbar_svg "#E5484D" "$BT"    > "$TMP/start.on.svg"
toolbar_svg "#1E7A3C" "$ARROW" > "$TMP/restart.svg"
for size in 16 24; do
    dir="toolbar/${size}x${size}"
    mkdir -p "$dir"
    for v in start start.on restart; do
        rsvg-convert -w $size -h $size "$TMP/$v.svg" -o "$dir/blehound-capture-$v.png"
        rsvg-convert -w $((size * 2)) -h $((size * 2)) "$TMP/$v.svg" -o "$dir/blehound-capture-$v@2x.png"
    done
done
