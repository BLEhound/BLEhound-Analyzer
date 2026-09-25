#!/usr/bin/env python3
"""Build the welcome-page banner images (1020x390) from the pictures in src/.

Each banner: brand mark + wordmark on the left, the product picture
auto-cropped and fitted on the right, on the picture's own light background.
To add a photo: drop it in src/, add a line to BANNERS, run this script, and
reference banners/<name>.png from slides_custom.json.

SPDX-License-Identifier: GPL-2.0-or-later
"""
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
ICON = HERE.parent.parent / "icons" / "blehound" / "app-256.png"
SIZE = (1020, 390)
TEXT_DARK = (22, 30, 40)
TEXT_GREEN = (47, 163, 83)
FONT_CANDIDATES = [
    "/System/Library/Fonts/HelveticaNeue.ttc",
    "/System/Library/Fonts/Helvetica.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
]

# (output name, source picture, caption under the wordmark)
BANNERS = [
    ("banner-case", "case-assembled.png", "3-channel BLE sniffer"),
    ("banner-board", "photo-board-1-cutout.png", "Open hardware"),
    ("banner-exploded", "case-exploded.png", "3D-printed case"),
]


def font(size, bold=False):
    for path in FONT_CANDIDATES:
        try:
            return ImageFont.truetype(path, size, index=1 if bold and path.endswith(".ttc") else 0)
        except OSError:
            continue
    return ImageFont.load_default()


def autocrop(im, bg):
    diff = ImageChops.difference(im.convert("RGB"), Image.new("RGB", im.size, bg))
    box = diff.convert("L").point(lambda v: 255 if v > 12 else 0).getbbox()
    return im.crop(box) if box else im


def make(name, src, caption):
    pic = Image.open(HERE / "src" / src).convert("RGB")
    bg = pic.getpixel((2, 2))
    pic = autocrop(pic, bg)

    banner = Image.new("RGB", SIZE, bg)
    area_w, area_h = 600, 350
    scale = min(area_w / pic.width, area_h / pic.height)
    pic = pic.resize((int(pic.width * scale), int(pic.height * scale)), Image.LANCZOS)
    banner.paste(pic, (SIZE[0] - 30 - area_w + (area_w - pic.width) // 2,
                       (SIZE[1] - pic.height) // 2))

    icon = Image.open(ICON).convert("RGBA").resize((150, 150), Image.LANCZOS)
    banner.paste(icon, (40, 70), icon)
    draw = ImageDraw.Draw(banner)
    draw.text((52, 232), "BLEhound", font=font(52, bold=True), fill=TEXT_GREEN)
    draw.text((54, 296), caption, font=font(28), fill=TEXT_DARK)

    out = HERE / "banners" / f"{name}.png"
    banner.save(out, optimize=True)
    print(out.name, banner.size)


if __name__ == "__main__":
    for spec in BANNERS:
        make(*spec)
