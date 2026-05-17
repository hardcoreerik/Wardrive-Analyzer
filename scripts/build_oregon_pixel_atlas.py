from __future__ import annotations

import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "assets" / "maps" / "oregon" / "classic"
    root.mkdir(parents=True, exist_ok=True)

    w, h = 1024, 768
    base = Image.new("RGBA", (w, h), (5, 14, 28, 255))
    draw = ImageDraw.Draw(base)

    for y in range(-80, h + 80, 34):
        draw.line((0, y, w, y + 120), fill=(70, 88, 118, 110), width=3)
    for x in range(-90, w + 90, 48):
        draw.line((x, 0, x - 130, h), fill=(58, 76, 104, 92), width=2)

    for y in range(20, h, 42):
        for x in range(16, w, 52):
            if ((x * 17 + y * 11) % 7) == 0:
                draw.rectangle((x, y, x + 6, y + 6), fill=(32, 110, 64, 120))

    for i in range(6):
        draw.ellipse(
            (38 + i * 14, h - 240 + i * 10, 330 + i * 20, h - 40 + i * 8),
            outline=(22, 88, 130, max(0, 120 - i * 12)),
            fill=(14, 62, 102, 60 if i < 2 else 0),
        )

    for i, c in enumerate([(0, 205, 255, 200), (0, 170, 220, 140), (0, 120, 180, 80)]):
        draw.rectangle((10 + i, 10 + i, w - 10 - i, h - 10 - i), outline=c, width=1)

    base.save(root / "base.png")

    labels = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ldraw = ImageDraw.Draw(labels)
    try:
        font = ImageFont.truetype("consola.ttf", 18)
    except Exception:
        font = ImageFont.load_default()

    points = [
        ("PORTLAND", (470, 98)),
        ("SALEM", (430, 170)),
        ("CORVALLIS", (380, 236)),
        ("EUGENE", (390, 302)),
        ("SPRINGFIELD", (470, 330)),
        ("BEND", (650, 300)),
        ("MEDFORD", (420, 520)),
        ("COOS BAY", (220, 430)),
        ("ROSEBURG", (330, 420)),
    ]
    for txt, pos in points:
        ldraw.text((pos[0] + 1, pos[1] + 1), txt, fill=(0, 0, 0, 180), font=font)
        ldraw.text(pos, txt, fill=(164, 220, 255, 230), font=font)
    labels.save(root / "labels.png")

    meta = {
        "lat_min": 41.8,
        "lat_max": 46.4,
        "lon_min": -124.8,
        "lon_max": -116.3,
        "width": w,
        "height": h,
        "labels": [
            {"name": "Eugene", "lat": 44.0521, "lon": -123.0868},
            {"name": "Springfield", "lat": 44.0462, "lon": -123.0220},
        ],
        "regions": [],
    }
    (root / "atlas.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"Generated atlas at {root}")


if __name__ == "__main__":
    main()
