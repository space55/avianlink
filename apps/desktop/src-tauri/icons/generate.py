#!/usr/bin/env python3
"""Generates the app icon source, with no image-library dependency.

The mark is three stacked bars at three brightnesses: the app's central idea
is that an outgoing message is honestly either delivered, sent or still
queued, and the icon says that and nothing else. No gradients, no glyph, no
bird: at 16px a bird is mud, and three bars are still three bars.

Run:  python3 generate.py            # writes source.png
Then: npx tauri icon icons/source.png
"""

import struct
import zlib

SIZE = 1024
# Deep slate, not black: a pure-black icon looks like a hole in a dark dock.
BACKGROUND = (0x12, 0x17, 0x1D)
# One hue, three brightnesses: delivered, sent, queued.
BARS = ((0xE8, 0xEE, 0xF4), (0x9A, 0xAA, 0xB8), (0x5A, 0x68, 0x76))

# Geometry as fractions of the canvas, so the design is resolution-free.
PLATE_INSET = 0.06
PLATE_RADIUS = 0.22
BAR_LEFT = 0.24
BAR_WIDTHS = (0.52, 0.40, 0.28)
BAR_HEIGHT = 0.075
BAR_GAP = 0.085
BAR_RADIUS = 0.0375


def rounded_rect_sdf(x, y, x0, y0, x1, y1, r):
    """Signed distance from (x, y) to a rounded rectangle. Negative inside."""
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    hw, hh = (x1 - x0) / 2 - r, (y1 - y0) / 2 - r
    dx = max(abs(x - cx) - hw, 0.0)
    dy = max(abs(y - cy) - hh, 0.0)
    return (dx * dx + dy * dy) ** 0.5 - r


def coverage(distance):
    """One-pixel analytic antialiasing from a signed distance."""
    return min(max(0.5 - distance, 0.0), 1.0)


def blend(under, over, alpha):
    return tuple(round(u + (o - u) * alpha) for u, o in zip(under, over))


def shapes():
    """The plate, then the bars, in painting order."""
    inset = PLATE_INSET * SIZE
    yield (inset, inset, SIZE - inset, SIZE - inset, PLATE_RADIUS * SIZE, BACKGROUND)

    bar_h = BAR_HEIGHT * SIZE
    gap = BAR_GAP * SIZE
    total = len(BARS) * bar_h + (len(BARS) - 1) * gap
    top = (SIZE - total) / 2
    for index, (width, colour) in enumerate(zip(BAR_WIDTHS, BARS)):
        y0 = top + index * (bar_h + gap)
        x0 = BAR_LEFT * SIZE
        yield (x0, y0, x0 + width * SIZE, y0 + bar_h, BAR_RADIUS * SIZE, colour)


def render():
    plate_and_bars = list(shapes())
    rows = []
    for py in range(SIZE):
        y = py + 0.5
        row = bytearray([0])  # PNG filter type 0
        for px in range(SIZE):
            x = px + 0.5
            # Start fully transparent; the plate establishes opacity.
            pixel, alpha = (0, 0, 0), 0.0
            for x0, y0, x1, y1, radius, colour in plate_and_bars:
                a = coverage(rounded_rect_sdf(x, y, x0, y0, x1, y1, radius))
                if a <= 0.0:
                    continue
                pixel = blend(pixel, colour, a)
                alpha = alpha + (1.0 - alpha) * a
            row += bytes((*pixel, round(alpha * 255)))
        rows.append(bytes(row))
    return b"".join(rows)


def chunk(kind, payload):
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def main():
    header = struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(render(), 9))
        + chunk(b"IEND", b"")
    )
    with open("source.png", "wb") as out:
        out.write(png)
    print(f"wrote source.png ({len(png)} bytes, {SIZE}x{SIZE})")


if __name__ == "__main__":
    main()
