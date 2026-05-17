from __future__ import annotations

import os
import sys
import platform
import random
import subprocess
import hashlib
import logging
import re
import time
import json
import csv
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from error_logger import write_diagnostic_snapshot, write_error_report

from PySide6.QtCore import Qt, QThread, Signal, QTimer, QElapsedTimer, QRect, QRectF, QPointF, QUrl
from PySide6.QtGui import QPainter, QLinearGradient, QColor, QFont, QPen, QBrush, QPixmap, QDesktopServices, QMovie
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QListWidget, QListWidgetItem, QFileDialog, QLabel, QMessageBox,
    QTextEdit, QPlainTextEdit, QProgressBar, QFrame, QTabWidget, QLineEdit, QCheckBox, QComboBox, QStackedLayout, QSizePolicy,
    QTableWidget, QTableWidgetItem, QHeaderView, QDialog
)

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
    WEBENGINE_AVAILABLE = True
except Exception:
    QWebEngineView = None  # type: ignore[assignment]
    WEBENGINE_AVAILABLE = False

# -----------------------------
# Asset helpers
# -----------------------------
def resource_path(*parts: str) -> str:
    """Resolve paths for dev + PyInstaller onefile."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)

ASSET_GIFS = [
    "assets/demogif1.gif",
    "assets/demo1.gif",
    "assets/demo2.gif",
    "assets/demo3.gif",
    "assets/demo4.gif",
    "assets/demo5.gif",
    "assets/demo6.gif",
]



try:
    from core import analyze, CORE_REVISION  # new modular package
except ImportError:
    from core_step3d import analyze, CORE_REVISION  # legacy fallback
from project_vault import (
    ensure_project_vault,
    scan_sd_folder,
    ingest_candidates_to_project,
    CandidateFile,
    get_setting,
    set_setting,
    gather_project_inputs_for_analysis,
    sha256_file,
    sha256_exists,
    project_db_stats,
    evidence_summary,
    list_import_history,
    list_project_evidence_detailed,
    discover_project_runs,
    compare_run_masters,
    export_wigle_csv,
    export_wpasec_list,
)
from mascot_engine import MascotEngine, MascotState
from buddy_ai import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    BuddyAIClient,
    BuddyAIConfig,
    build_buddy_context,
    load_token_from_keyring,
    local_buddy_summary,
    save_token_to_keyring,
)
from dropbox_sync import sync_project_to_dropbox


# -----------------------------
# File fingerprinting (per-session list dedupe; project ingest uses full SHA-256)
# -----------------------------

def file_fingerprint(path: str) -> str:
    """
    Practical duplicate detection within the GUI selection lists:
      - Small files: full SHA256
      - Large files: SHA256(size + first 64KB + last 64KB)

    NOTE: Project ingest uses FULL SHA256 for authority.
    """
    st = os.stat(path)
    size = st.st_size
    h = hashlib.sha256()

    h.update(str(size).encode("utf-8"))
    try:
        with open(path, "rb") as f:
            if size <= 2 * 1024 * 1024:  # 2MB
                h.update(f.read())
            else:
                head = f.read(64 * 1024)
                h.update(head)
                if size > 64 * 1024:
                    f.seek(max(0, size - 64 * 1024))
                    h.update(f.read(64 * 1024))
    except Exception:
        h.update(path.encode("utf-8"))
        h.update(str(st.st_mtime_ns).encode("utf-8"))

    return h.hexdigest()


# -----------------------------
# Procedural animated background (QPainter, full-window, per-frame)
# -----------------------------
import math

_MATRIX_CHARS = (
    "ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ"
    "0123456789ABCDEF<>[]{}|\\/*+-=~@#$%^&"
)


@dataclass
class _MatrixDrop:
    x: float
    y: float        # head y position (pixels)
    speed: float    # pixels per tick
    trail: int      # number of chars in trail
    chars: list     # pre-chosen char indices, len == trail + 1


@dataclass
class _CircuitNode:
    x: float
    y: float
    phase_offset: float  # per-node brightness phase


@dataclass
class _CircuitTrace:
    n1: int   # index into nodes list
    n2: int
    signal_t: float        # 0..1, position of traveling signal along trace
    signal_speed: float    # units per tick (0.003 – 0.012)


@dataclass
class _NebulaBlob:
    cx: float
    cy: float
    rx: float
    ry: float
    hue: int
    vx: float   # pixels per tick
    vy: float
    phase_offset: float


class ProceduralBackground(QWidget):
    """Full-window animated background — pure QPainter, no static pixmap, no GIFs."""

    MODES = ["grid_horizon", "circuit_board", "matrix_rain", "nebula_noise"]

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setAutoFillBackground(False)

        # GIF fallback layer (shown only if gif_paths supplied and mode == gif)
        self._gif_label = QLabel(self)
        self._gif_label.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self._gif_label.hide()
        self._movie: QMovie | None = None

        self.mode: str = "grid_horizon"
        self.phase: float = 0.0
        self.current_name: str = "grid_horizon"

        # Per-mode state (rebuilt on regenerate / resize)
        self._drops: list[_MatrixDrop] = []
        self._circuit_nodes: list[_CircuitNode] = []
        self._circuit_traces: list[_CircuitTrace] = []
        self._nebula_blobs: list[_NebulaBlob] = []
        self._rng_seed: int = random.randint(0, 10_000_000)
        self._hue_base: int = random.randint(0, 359)
        self._last_w: int = 0
        self._last_h: int = 0

        self._timer = QTimer(self)
        self._timer.setInterval(16)   # ~60 fps
        self._timer.timeout.connect(self._tick)
        self._timer.start()

        self.randomize()

    # ------------------------------------------------------------------
    # Public API (matches old DemoscenePanel for drop-in replacement)
    # ------------------------------------------------------------------

    def randomize(self) -> None:
        self.set_mode(random.choice(self.MODES))

    def set_mode(self, mode: str) -> None:
        self.mode = mode
        self.current_name = mode
        self.phase = 0.0
        self._rng_seed = random.randint(0, 10_000_000)
        self._hue_base = random.randint(0, 359)
        self._rebuild_state()
        self.update()



    # ------------------------------------------------------------------
    # State initialisation (called on set_mode + resize)
    # ------------------------------------------------------------------

    def _rebuild_state(self) -> None:
        w, h = self.width(), self.height()
        self._last_w, self._last_h = w, h
        rng = random.Random(self._rng_seed)

        if self.mode == "matrix_rain":
            self._build_matrix(w, h, rng)
        elif self.mode == "circuit_board":
            self._build_circuit(w, h, rng)
        elif self.mode == "nebula_noise":
            self._build_nebula(w, h, rng)
        # grid_horizon: fully stateless, driven only by phase

    def _build_matrix(self, w: int, h: int, rng: random.Random) -> None:
        if w <= 0 or h <= 0:
            return
        col_w = 18
        cols = max(1, w // col_w)
        self._drops = []
        for i in range(cols):
            trail = rng.randint(8, 28)
            self._drops.append(_MatrixDrop(
                x=i * col_w + rng.randint(0, col_w // 2),
                y=rng.random() * h,
                speed=rng.uniform(1.5, 5.0),
                trail=trail,
                chars=[rng.randint(0, len(_MATRIX_CHARS) - 1) for _ in range(trail + 1)],
            ))

    def _build_circuit(self, w: int, h: int, rng: random.Random) -> None:
        if w <= 0 or h <= 0:
            return
        n_nodes = 60
        self._circuit_nodes = [
            _CircuitNode(
                x=rng.random() * w,
                y=rng.random() * h,
                phase_offset=rng.random() * math.tau,
            )
            for _ in range(n_nodes)
        ]
        # Connect each node to 1-3 neighbours picked by proximity
        self._circuit_traces = []
        for i, nd in enumerate(self._circuit_nodes):
            candidates = sorted(
                (j for j in range(n_nodes) if j != i),
                key=lambda j: (self._circuit_nodes[j].x - nd.x) ** 2 + (self._circuit_nodes[j].y - nd.y) ** 2,
            )
            for j in candidates[: rng.randint(1, 3)]:
                self._circuit_traces.append(_CircuitTrace(
                    n1=i, n2=j,
                    signal_t=rng.random(),
                    signal_speed=rng.uniform(0.002, 0.010),
                ))

    def _build_nebula(self, w: int, h: int, rng: random.Random) -> None:
        if w <= 0 or h <= 0:
            return
        self._nebula_blobs = [
            _NebulaBlob(
                cx=rng.random() * w,
                cy=rng.random() * h,
                rx=(0.15 + rng.random() * 0.55) * w,
                ry=(0.10 + rng.random() * 0.45) * h,
                hue=rng.randint(0, 359),
                vx=rng.uniform(-0.25, 0.25),
                vy=rng.uniform(-0.15, 0.15),
                phase_offset=rng.random() * math.tau,
            )
            for _ in range(12)
        ]

    # ------------------------------------------------------------------
    # Animation tick
    # ------------------------------------------------------------------

    def _tick(self) -> None:
        self.phase += 0.05
        if self.phase > 99999:
            self.phase = 0.0

        w, h = self.width(), self.height()
        if w != self._last_w or h != self._last_h:
            self._rebuild_state()

        if self.mode == "matrix_rain":
            self._step_matrix(h)
        elif self.mode == "circuit_board":
            self._step_circuit()
        elif self.mode == "nebula_noise":
            self._step_nebula(w, h)

        self.update()

    def _step_matrix(self, h: int) -> None:
        rng = random.Random()
        for drop in self._drops:
            drop.y += drop.speed
            if drop.y - drop.trail * 18 > h + 40:
                drop.y = -rng.randint(10, 80)
                drop.speed = rng.uniform(1.5, 5.0)
                drop.trail = rng.randint(8, 28)
                drop.chars = [rng.randint(0, len(_MATRIX_CHARS) - 1) for _ in range(drop.trail + 1)]
            # Randomly mutate head char for flicker
            if rng.random() < 0.15:
                drop.chars[0] = rng.randint(0, len(_MATRIX_CHARS) - 1)

    def _step_circuit(self) -> None:
        for trace in self._circuit_traces:
            trace.signal_t += trace.signal_speed
            if trace.signal_t > 1.0:
                trace.signal_t = 0.0

    def _step_nebula(self, w: int, h: int) -> None:
        margin = 200
        for b in self._nebula_blobs:
            b.cx += b.vx
            b.cy += b.vy
            if b.cx < -margin:
                b.cx = w + margin
            elif b.cx > w + margin:
                b.cx = -margin
            if b.cy < -margin:
                b.cy = h + margin
            elif b.cy > h + margin:
                b.cy = -margin

    # ------------------------------------------------------------------
    # Painting
    # ------------------------------------------------------------------

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._gif_label.setGeometry(0, 0, self.width(), self.height())

    def paintEvent(self, event):
        w, h = self.width(), self.height()
        if w <= 2 or h <= 2:
            return

        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, True)

        # Base gradient — deep black/midnight
        bg = QLinearGradient(0, 0, 0, h)
        bg.setColorAt(0.0, QColor(2, 4, 8))
        bg.setColorAt(1.0, QColor(0, 0, 0))
        p.fillRect(0, 0, w, h, bg)

        if self.mode == "matrix_rain":
            self._paint_matrix(p, w, h)
        elif self.mode == "circuit_board":
            self._paint_circuit(p, w, h)
        elif self.mode == "nebula_noise":
            self._paint_nebula(p, w, h)
        elif self.mode == "grid_horizon":
            self._paint_horizon(p, w, h)

        # Scanline overlay (subtle)
        p.setRenderHint(QPainter.Antialiasing, False)
        for y in range(0, h, 3):
            p.fillRect(0, y, w, 1, QColor(0, 0, 0, 18))

        # Bottom vignette
        vign = QLinearGradient(0, h * 0.6, 0, h)
        vign.setColorAt(0.0, QColor(0, 0, 0, 0))
        vign.setColorAt(1.0, QColor(0, 0, 0, 180))
        p.fillRect(0, 0, w, h, vign)

        p.end()

    # --- Matrix rain ---
    def _paint_matrix(self, p: QPainter, w: int, h: int) -> None:
        p.setRenderHint(QPainter.Antialiasing, False)
        font = QFont("Consolas", 12)
        p.setFont(font)
        fm_h = 16  # approximate char cell height

        for drop in self._drops:
            head_y = drop.y
            for i, ci in enumerate(drop.chars):
                char_y = head_y - i * fm_h
                if char_y < -fm_h or char_y > h + fm_h:
                    continue
                ch = _MATRIX_CHARS[ci]
                if i == 0:
                    # Head: bright white-green
                    p.setPen(QColor(200, 255, 200, 255))
                else:
                    # Trail: exponential fade
                    fade = int(255 * (0.85 ** i))
                    green = max(80, 255 - i * 12)
                    p.setPen(QColor(0, green, 50, fade))
                p.drawText(QPointF(drop.x, char_y), ch)

    # --- Circuit board ---
    def _paint_circuit(self, p: QPainter, w: int, h: int) -> None:
        nodes = self._circuit_nodes
        if not nodes:
            return

        # Draw traces
        p.setRenderHint(QPainter.Antialiasing, False)
        for trace in self._circuit_traces:
            n1 = nodes[trace.n1]
            n2 = nodes[trace.n2]
            p.setPen(QPen(QColor(0, 200, 160, 35), 1))
            # L-shaped trace (one horizontal + one vertical segment)
            mid_x = n2.x
            mid_y = n1.y
            p.drawLine(int(n1.x), int(n1.y), int(mid_x), int(mid_y))
            p.drawLine(int(mid_x), int(mid_y), int(n2.x), int(n2.y))

            # Traveling signal dot
            t = trace.signal_t
            if t < 0.5:
                sx = n1.x + (mid_x - n1.x) * (t * 2)
                sy = n1.y
            else:
                sx = mid_x
                sy = mid_y + (n2.y - mid_y) * ((t - 0.5) * 2)
            sig_alpha = int(180 + 75 * math.sin(self.phase * 3))
            p.fillRect(int(sx) - 2, int(sy) - 2, 4, 4, QColor(0, 255, 200, sig_alpha))

        # Draw nodes with pulsing brightness
        p.setRenderHint(QPainter.Antialiasing, True)
        for nd in nodes:
            pulse = 0.5 + 0.5 * math.sin(self.phase * 2.5 + nd.phase_offset)
            alpha = int(60 + 140 * pulse)
            size = 3 + int(3 * pulse)
            p.setBrush(QBrush(QColor(0, 255, 190, alpha)))
            p.setPen(Qt.NoPen)
            p.drawEllipse(QPointF(nd.x, nd.y), size, size)

    # --- Nebula noise ---
    def _paint_nebula(self, p: QPainter, w: int, h: int) -> None:
        p.setRenderHint(QPainter.Antialiasing, True)
        for b in self._nebula_blobs:
            pulse = 0.5 + 0.5 * math.sin(self.phase * 1.2 + b.phase_offset)
            alpha = int(12 + 18 * pulse)
            hue = (b.hue + int(self.phase * 8)) % 360
            col = QColor.fromHsl(hue, 200, 55, alpha)
            p.setBrush(QBrush(col))
            p.setPen(Qt.NoPen)
            p.drawEllipse(QRectF(b.cx - b.rx, b.cy - b.ry, b.rx * 2, b.ry * 2))

        # Faint star field
        p.setRenderHint(QPainter.Antialiasing, False)
        rng = random.Random(self._rng_seed ^ 0xABCD)
        for _ in range(80):
            sx = rng.randint(0, w)
            sy = rng.randint(0, h)
            twinkle = int(60 + 60 * math.sin(self.phase * 2.1 + sx * 0.07 + sy * 0.05))
            p.fillRect(sx, sy, 1, 1, QColor(255, 255, 255, twinkle))

    # --- Synthwave horizon grid ---
    def _paint_horizon(self, p: QPainter, w: int, h: int) -> None:
        p.setRenderHint(QPainter.Antialiasing, True)

        # Dusk sky gradient (magenta → deep blue)
        sky = QLinearGradient(0, 0, 0, h * 0.60)
        sky.setColorAt(0.0, QColor(8, 2, 22))
        sky.setColorAt(0.6, QColor(80, 10, 60))
        sky.setColorAt(1.0, QColor(180, 30, 100))
        p.fillRect(0, 0, w, int(h * 0.60), sky)

        # Animated sun glow at horizon
        sun_cx = w * 0.5
        sun_cy = h * 0.55
        sun_r = w * 0.18
        pulse = 0.5 + 0.5 * math.sin(self.phase * 0.6)
        glow_r = sun_r * (1.0 + 0.15 * pulse)
        glow = QLinearGradient(sun_cx - glow_r, sun_cy - glow_r, sun_cx + glow_r, sun_cy + glow_r)
        glow.setColorAt(0.0, QColor(255, 100, 30, 90))
        glow.setColorAt(0.5, QColor(255, 60, 80, 45))
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        p.setBrush(QBrush(glow))
        p.setPen(Qt.NoPen)
        p.drawEllipse(QPointF(sun_cx, sun_cy), glow_r, glow_r * 0.65)

        # Sun disc with horizontal scan lines (retro style)
        p.setBrush(QBrush(QColor(255, 120, 40, 220)))
        p.drawEllipse(QPointF(sun_cx, sun_cy), sun_r, sun_r * 0.55)
        p.setRenderHint(QPainter.Antialiasing, False)
        p.setClipRect(QRect(int(sun_cx - sun_r), int(sun_cy - sun_r * 0.55),
                            int(sun_r * 2), int(sun_r * 1.1)))
        for i in range(1, 10):
            y = sun_cy + (sun_r * 0.55) * (i / 10.0) * 2 - sun_r * 0.55
            a = max(0, 200 - i * 18)
            p.fillRect(0, int(y), w, 3, QColor(20, 0, 10, a))
        p.setClipping(False)

        # Floor
        floor_top = int(h * 0.55)
        floor = QLinearGradient(0, floor_top, 0, h)
        floor.setColorAt(0.0, QColor(30, 0, 50))
        floor.setColorAt(1.0, QColor(5, 0, 15))
        p.fillRect(0, floor_top, w, h - floor_top, floor)

        # Vertical perspective lines (fan out from vanishing point)
        van_x = w * 0.5
        van_y = h * 0.55
        p.setRenderHint(QPainter.Antialiasing, True)
        for i in range(-14, 15):
            x_bottom = van_x + i * (w * 0.075)
            alpha = max(20, 90 - abs(i) * 4)
            p.setPen(QPen(QColor(255, 0, 200, alpha), 1))
            p.drawLine(int(van_x), int(van_y), int(x_bottom), h)

        # Horizontal lines scrolling toward viewer (perspective spacing)
        scroll = (self.phase * 12) % 1.0  # fractional scroll offset
        n_lines = 24
        for i in range(n_lines):
            t = ((i + scroll) / n_lines) ** 2.2   # perspective warp
            y = int(van_y + (h - van_y) * t)
            if y <= floor_top or y > h:
                continue
            alpha = int(15 + 65 * t)
            p.setPen(QPen(QColor(255, 0, 200, alpha), 1))
            p.drawLine(0, y, w, y)


# -----------------------------
# Analyzer worker thread
# -----------------------------
_GUI_TEXT_CONTROL_RE = re.compile(r"[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F-\x9F]")


def _safe_gui_text(value, limit: int = 4000) -> str:
    text = str(value) if value is not None else ""
    text = _GUI_TEXT_CONTROL_RE.sub("", text)
    text = text.replace("\ufffd", "?")
    if len(text) > limit:
        text = text[:limit] + "\n... [truncated]"
    return text


ClassicMapScope = Literal["latest_session", "recent_sessions", "all"]


@dataclass
class PixelAtlasMetadata:
    lat_min: float
    lat_max: float
    lon_min: float
    lon_max: float
    width: int
    height: int
    labels: list[dict]
    regions: list[dict]


@dataclass
class ClassicMapRenderOptions:
    show_route: bool = False
    max_sprites: int = 2200
    decimation_level: int = 1
    label_layer_enabled: bool = True


class ClassicPixelMapRenderer:
    """Atlas-backed Classic map renderer optimized for low-end hardware."""

    def __init__(self):
        self.base: QPixmap | None = None
        self.labels: QPixmap | None = None
        self.meta: PixelAtlasMetadata | None = None
        self._scaled_cache: dict[tuple[int, int, bool], tuple[QPixmap, QPixmap | None]] = {}

    def load(self, base_path: str, labels_path: str, meta_path: str) -> bool:
        try:
            if not (os.path.exists(base_path) and os.path.exists(labels_path) and os.path.exists(meta_path)):
                return False
            with open(meta_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            self.meta = PixelAtlasMetadata(
                lat_min=float(raw.get("lat_min", 41.8)),
                lat_max=float(raw.get("lat_max", 46.4)),
                lon_min=float(raw.get("lon_min", -124.7)),
                lon_max=float(raw.get("lon_max", -116.3)),
                width=int(raw.get("width", 1024)),
                height=int(raw.get("height", 1024)),
                labels=list(raw.get("labels", [])),
                regions=list(raw.get("regions", [])),
            )
            self.base = QPixmap(base_path)
            self.labels = QPixmap(labels_path)
            self._scaled_cache.clear()
            return not self.base.isNull()
        except Exception:
            return False

    def ensure(self, rect: QRect, with_labels: bool) -> tuple[QPixmap | None, QPixmap | None]:
        if self.base is None or self.base.isNull():
            return (None, None)
        key = (rect.width(), rect.height(), with_labels)
        if key in self._scaled_cache:
            return self._scaled_cache[key]
        base_scaled = self.base.scaled(rect.width(), rect.height(), Qt.IgnoreAspectRatio, Qt.FastTransformation)
        label_scaled: QPixmap | None = None
        if with_labels and self.labels is not None and not self.labels.isNull():
            label_scaled = self.labels.scaled(rect.width(), rect.height(), Qt.IgnoreAspectRatio, Qt.FastTransformation)
        self._scaled_cache[key] = (base_scaled, label_scaled)
        return (base_scaled, label_scaled)

    def latlon_to_norm(self, lat: float, lon: float) -> tuple[float, float] | None:
        if self.meta is None:
            return None
        lat_span = max(0.000001, self.meta.lat_max - self.meta.lat_min)
        lon_span = max(0.000001, self.meta.lon_max - self.meta.lon_min)
        nx = (lon - self.meta.lon_min) / lon_span
        ny = (self.meta.lat_max - lat) / lat_span
        return (max(0.0, min(1.0, nx)), max(0.0, min(1.0, ny)))



class PixelIsometricMapWidget(QWidget):
    """Native in-app pixel/isometric map view (clean-room implementation)."""

    FILTERS = ("ALL", "WI-FI", "BLE", "HANDSHAKES", "GPS")
    VIEW_MODES = ("ISOMETRIC", "CLASSIC")

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setMouseTracking(True)
        self._points: list[dict] = []
        self._route: list[tuple[float, float]] = []
        self._route_segments: list[list[tuple[float, float]]] = []
        self._memo: dict[str, list[QPointF]] = {}
        self._filter: str = "ALL"
        self._view_mode: str = "ISOMETRIC"
        self._hover_idx: int = -1
        self._selected_idx: int = -1
        self._pan_x: float = 0.0
        self._pan_y: float = 0.0
        self._zoom: float = 1.0
        self._rotation_deg: float = -18.0
        self._dragging: bool = False
        self._drag_start = QPointF(0, 0)
        self._gps_points: list[tuple[float, float]] = []
        self._summary_label: QLabel | None = None
        self._geo_bounds: tuple[float, float, float, float] | None = None
        self._landmarks: list[dict] = []
        self._classic_renderer = ClassicPixelMapRenderer()
        self._classic_scope: ClassicMapScope = "latest_session"
        self._classic_recent_n: int = 3
        self._classic_options = ClassicMapRenderOptions()
        self._projected_points_cache: dict[str, list[tuple[dict, QPointF]]] = {}
        self._latest_entity_id: str = ""
        self._classic_tile_cache: dict[tuple[int, int, int], QPixmap] = {}
        self._classic_tile_zoom: int = 13
        self._classic_merc_bounds: tuple[float, float, float, float] | None = None
        self._classic_board_cache: QPixmap | None = None
        self._classic_route_cache: list[QPointF] | None = None
        self.setMinimumHeight(420)

    def set_summary_label(self, label: QLabel) -> None:
        self._summary_label = label
        self._refresh_summary()

    def set_filter(self, filter_name: str) -> None:
        if filter_name not in self.FILTERS:
            filter_name = "ALL"
        self._filter = filter_name
        self._selected_idx = -1
        self._hover_idx = -1
        self._projected_points_cache.clear()
        self._refresh_summary()
        self.update()

    def reset_view(self) -> None:
        self._pan_x = 0.0
        self._pan_y = 0.0
        self._zoom = 1.0
        self._rotation_deg = -18.0 if self._view_mode == "ISOMETRIC" else 0.0
        self._projected_points_cache.clear()
        self.update()

    def set_view_mode(self, mode: str) -> None:
        mode = (mode or "").upper()
        if mode not in self.VIEW_MODES:
            mode = "ISOMETRIC"
        self._view_mode = mode
        if mode == "CLASSIC" and abs(self._rotation_deg) > 0.001:
            self._rotation_deg = 0.0
        elif mode == "ISOMETRIC" and abs(self._rotation_deg) < 0.001:
            self._rotation_deg = -18.0
        self._projected_points_cache.clear()
        self._focus_on_latest_entity()
        self.update()

    def nudge_zoom(self, factor: float) -> None:
        self._zoom = max(0.38, min(5.2, self._zoom * factor))
        self._projected_points_cache.clear()
        self.update()

    def rotate_by(self, delta_deg: float) -> None:
        self._rotation_deg += delta_deg
        while self._rotation_deg > 180:
            self._rotation_deg -= 360
        while self._rotation_deg < -180:
            self._rotation_deg += 360
        self._projected_points_cache.clear()
        self.update()

    def load_from_run(self, run_dir: str) -> None:
        self._points = []
        self._route = []
        self._route_segments = []
        self._gps_points = []
        self._memo.clear()
        self._selected_idx = -1
        self._hover_idx = -1
        self._geo_bounds = None
        self._landmarks = []
        self._classic_merc_bounds = None
        self._classic_board_cache = None
        self._classic_route_cache = None
        self._projected_points_cache.clear()
        base_img = resource_path("assets", "maps", "oregon", "classic", "base.png")
        labels_img = resource_path("assets", "maps", "oregon", "classic", "labels.png")
        atlas_meta = resource_path("assets", "maps", "oregon", "classic", "atlas.json")
        self._classic_renderer.load(base_img, labels_img, atlas_meta)
        self.reset_view()
        if not run_dir or not os.path.isdir(run_dir):
            self._refresh_summary()
            self.update()
            return

        csv_path = os.path.join(run_dir, "wardrive_master.csv")
        if os.path.exists(csv_path):
            self._points = self._parse_master_csv(csv_path)

        kml_path = os.path.join(run_dir, "wardrive_map.kml")
        if os.path.exists(kml_path):
            self._route_segments = self._parse_kml_route_segments(kml_path)
            self._route = [pt for seg in self._route_segments for pt in seg]
            self._gps_points = self._route[:: max(1, len(self._route) // 250)] if self._route else []

        if not self._route:
            # fallback pseudo-route from points ordered by strongest signal
            route_seed = sorted(self._points, key=lambda p: (p.get("rssi") or -999), reverse=True)[:600]
            self._route = [(p["lat"], p["lon"]) for p in route_seed if p.get("lat") is not None and p.get("lon") is not None]
            self._route_segments = [self._route] if self._route else []
            self._gps_points = self._route[:: max(1, len(self._route) // 150)] if self._route else []

        self._geo_bounds = self._compute_geo_bounds()
        self._classic_merc_bounds = self._compute_merc_bounds()
        self._landmarks = self._build_landmarks()
        self._focus_on_latest_entity()

        self._refresh_summary()
        self.update()

    def set_classic_map_scope(self, scope: ClassicMapScope) -> None:
        self._classic_scope = scope
        self._projected_points_cache.clear()
        if self._view_mode == "CLASSIC":
            self._focus_on_latest_entity()
        self._refresh_summary()
        self.update()

    def set_classic_render_options(self, options: ClassicMapRenderOptions) -> None:
        self._classic_options = options
        self._projected_points_cache.clear()
        self.update()

    def focus_latest_entity(self) -> None:
        self._focus_on_latest_entity()
        self.update()

    def wheelEvent(self, event):  # noqa: N802
        delta = event.angleDelta().y()
        zoom_factor = 1.12 if delta > 0 else 0.9
        self.nudge_zoom(zoom_factor)

    def mousePressEvent(self, event):  # noqa: N802
        if event.button() == Qt.LeftButton:
            self._dragging = True
            self._drag_start = event.position()
        elif event.button() == Qt.RightButton:
            self._selected_idx = self._nearest_point_index(event.position())
            self._refresh_summary()
            self.update()

    def mouseMoveEvent(self, event):  # noqa: N802
        if self._dragging:
            now = event.position()
            self._pan_x += (now.x() - self._drag_start.x())
            self._pan_y += (now.y() - self._drag_start.y())
            self._drag_start = now
            self._projected_points_cache.clear()
            self.update()
            return
        self._hover_idx = self._nearest_point_index(event.position(), max_dist=16.0)
        self.update()

    def mouseReleaseEvent(self, event):  # noqa: N802
        if event.button() == Qt.LeftButton:
            self._dragging = False

    def paintEvent(self, event):  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, False)
        rect = self.rect()
        p.fillRect(rect, QColor(4, 12, 28))

        if self._view_mode == "CLASSIC":
            self._draw_classic_backdrop(p, rect)
        self._draw_iso_grid(p, rect)
        route_iso = self._project_route(rect)
        self._draw_route(p, route_iso)
        self._draw_points(p, rect)
        self._draw_landmarks(p, rect)
        if self._view_mode == "CLASSIC":
            self._draw_classic_legend(p, rect)
            self._draw_classic_controls(p, rect)
        self._draw_overlay(p, rect)

    def _draw_classic_backdrop(self, p: QPainter, rect: QRect) -> None:
        p.save()
        p.fillRect(rect, QColor(5, 14, 30))
        self._draw_classic_oregon_board(p, rect)
        # subtle dark tint for neon overlay readability
        p.fillRect(rect, QColor(0, 8, 18, 46))
        p.restore()

    def _draw_classic_oregon_board(self, p: QPainter, rect: QRect) -> None:
        base, labels = self._classic_renderer.ensure(rect, self._classic_options.label_layer_enabled)
        if base is None:
            # fallback dark panel if atlas missing
            p.fillRect(rect, QColor(6, 16, 28))
            return
        p.drawPixmap(0, 0, base)
        if labels is not None and not labels.isNull():
            p.drawPixmap(0, 0, labels)

    # OSM live-tile fetch removed from hot render path for performance/stability.

    def _draw_iso_grid(self, p: QPainter, rect: QRect):
        p.save()
        p.setPen(QPen(QColor(34, 90, 160, 90), 1))
        if self._view_mode == "CLASSIC":
            p.restore()
            return
        step = max(24, int(42 * self._zoom))
        w = rect.width()
        h = rect.height()
        for i in range(-8, 30):
            x0 = i * step + self._pan_x % step
            p.drawLine(int(x0), 0, int(x0 - w), h)
            p.drawLine(int(x0), 0, int(x0 + w), h)
        p.restore()

    def _project_route(self, rect: QRect) -> list[list[QPointF]]:
        if not self._route_segments:
            return []
        key = f"route2:{sum(len(s) for s in self._route_segments)}:{len(self._route_segments)}:{rect.width()}:{rect.height()}:{round(self._zoom,2)}:{int(self._pan_x)}:{int(self._pan_y)}:{self._view_mode}:{round(self._rotation_deg,1)}"
        if key in self._memo:
            cached = self._memo[key]
            # Backward compatibility: memo value may be flat list from older runs.
            if cached and isinstance(cached[0], list):
                return cached  # type: ignore[return-value]
        out_segments: list[list[QPointF]] = []
        for seg in self._route_segments:
            out = [self._project_lat_lon(lat, lon, rect) for lat, lon in seg]
            if len(out) > 2200:
                out = out[:: max(1, len(out) // 2200)]
            if len(out) >= 2:
                out_segments.append(out)
        self._memo[key] = out_segments  # type: ignore[assignment]
        return out_segments

    def _draw_route(self, p: QPainter, route_segments: list[list[QPointF]]):
        if not route_segments:
            return
        p.save()
        if self._view_mode == "CLASSIC":
            if self._classic_options.show_route:
                path = self._classic_representative_route(route_segments)
                if len(path) >= 2:
                    p.setPen(QPen(QColor(32, 126, 255, 235), 7))
                    self._draw_route_segment_lines(p, path)
                    p.setPen(QPen(QColor(152, 236, 255, 245), 3))
                    self._draw_route_segment_lines(p, path)
            return
        else:
            p.setPen(QPen(QColor(38, 170, 255, 220), 2))
        for seg in route_segments:
            self._draw_route_segment_lines(p, seg)
        p.restore()

    def _classic_representative_route(self, segments: list[list[QPointF]]) -> list[QPointF]:
        # Single clean route for the retro look (avoid spaghetti).
        longest = max(segments, key=lambda s: len(s), default=[])
        if not longest:
            return []
        if len(longest) > 260:
            step = max(1, len(longest) // 260)
            longest = longest[::step]
        return longest

    def _draw_route_segment_lines(self, p: QPainter, seg: list[QPointF]) -> None:
        # Guard against "teleport" lines when source logs contain disjoint route chunks.
        max_jump = 160.0 if self._view_mode == "CLASSIC" else 120.0
        max_jump2 = max_jump * max_jump
        for i in range(1, len(seg)):
            a = seg[i - 1]
            b = seg[i]
            dx = b.x() - a.x()
            dy = b.y() - a.y()
            if (dx * dx + dy * dy) > max_jump2:
                continue
            p.drawLine(int(a.x()), int(a.y()), int(b.x()), int(b.y()))

    def _draw_points(self, p: QPainter, rect: QRect):
        pts = self._filtered_points()
        if not pts:
            return
        if len(pts) > self._classic_options.max_sprites:
            step = max(1, len(pts) // self._classic_options.max_sprites)
            pts = pts[::step]
        cache_key = (
            f"{self._view_mode}:{self._filter}:{self._classic_scope}:{rect.width()}:{rect.height()}:"
            f"{round(self._zoom,2)}:{int(self._pan_x)}:{int(self._pan_y)}:{round(self._rotation_deg,1)}:{len(pts)}"
        )
        if cache_key in self._projected_points_cache:
            pairs = self._projected_points_cache[cache_key]
        else:
            prj = self._project_points(pts, rect)
            pairs = list(zip(pts, prj))
            if len(self._projected_points_cache) > 14:
                self._projected_points_cache.clear()
            self._projected_points_cache[cache_key] = pairs
        for i, (pt, qpt) in enumerate(pairs):
            if qpt.x() < -10 or qpt.y() < -10 or qpt.x() > rect.width() + 10 or qpt.y() > rect.height() + 10:
                continue
            t = pt.get("type", "WIFI")
            if t == "BLE":
                color = QColor(141, 102, 255)
            elif t == "HANDSHAKE":
                color = QColor(255, 74, 89)
            elif t == "GPS":
                color = QColor(72, 247, 114)
            else:
                color = QColor(18, 200, 255)
            selected = (i == self._selected_idx or i == self._hover_idx)
            self._draw_pixel_sprite(
                p, int(qpt.x()), int(qpt.y()), color, t, scale=2 if selected else 1
            )

    def _draw_pixel_sprite(self, p: QPainter, x: int, y: int, color: QColor, typ: str, scale: int = 1):
        p.save()
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(color))
        px = max(1, scale)
        patterns = {
            "WIFI": ("00100", "01010", "10001", "00100", "00000"),
            "BLE": ("10010", "10110", "11110", "10110", "10010"),
            "GPS": ("00100", "01110", "11111", "01110", "00100"),
            "HANDSHAKE": ("10001", "01010", "00100", "01010", "10001"),
        }
        pattern = patterns.get(typ, ("01110", "11111", "11111", "01110", "00100"))
        half = (len(pattern) * px) // 2
        for r, row in enumerate(pattern):
            for c, bit in enumerate(row):
                if bit != "1":
                    continue
                p.drawRect(x - half + c * px, y - half + r * px, px, px)
        p.restore()

    def _draw_landmarks(self, p: QPainter, rect: QRect) -> None:
        if not self._landmarks:
            return
        for lm in self._landmarks:
            qpt = self._project_lat_lon(float(lm["lat"]), float(lm["lon"]), rect)
            if qpt.x() < -16 or qpt.y() < -16 or qpt.x() > rect.width() + 16 or qpt.y() > rect.height() + 16:
                continue
            self._draw_landmark_sprite(p, int(qpt.x()), int(qpt.y()), str(lm.get("kind", "tower")))

    def _draw_landmark_sprite(self, p: QPainter, x: int, y: int, kind: str) -> None:
        p.save()
        colors = {
            "tower": QColor(90, 170, 255),
            "hub": QColor(76, 255, 120),
            "target": QColor(255, 86, 98),
            "district": QColor(172, 122, 255),
        }
        color = colors.get(kind, QColor(90, 170, 255))
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(color))
        px = 2 if self._view_mode == "CLASSIC" else 1
        patterns = {
            "tower": ("00100", "01110", "00100", "01110", "11111"),
            "hub": ("00100", "01110", "11111", "01110", "00100"),
            "target": ("10001", "01010", "00100", "01010", "10001"),
            "district": ("01110", "11111", "10101", "11111", "01110"),
        }
        patt = patterns.get(kind, patterns["tower"])
        half = (len(patt) * px) // 2
        for r, row in enumerate(patt):
            for c, bit in enumerate(row):
                if bit != "1":
                    continue
                p.drawRect(x - half + c * px, y - half + r * px, px, px)
        p.restore()

    def _draw_classic_legend(self, p: QPainter, rect: QRect) -> None:
        p.save()
        box = QRect(16, 18, 240, 174)
        p.fillRect(box, QColor(6, 14, 28, 228))
        p.setPen(QPen(QColor(78, 108, 144, 200), 1))
        p.drawRect(box)

        entries = [
            ("WI-FI AP", QColor(18, 200, 255), "WIFI"),
            ("BLE Device", QColor(141, 102, 255), "BLE"),
            ("GPS Fix", QColor(72, 247, 114), "GPS"),
            ("Handshake", QColor(255, 74, 89), "HANDSHAKE"),
        ]
        y = 52
        for label, c, t in entries:
            self._draw_pixel_sprite(p, 34, y, c, t, scale=2)
            p.setPen(QPen(QColor(214, 226, 240, 220), 1))
            p.drawText(52, y + 6, label)
            y += 35
        p.restore()

    def _draw_classic_controls(self, p: QPainter, rect: QRect) -> None:
        p.save()
        right = rect.width() - 52
        y0 = max(40, rect.height() // 3)
        labels = ["+", "-", "o"]
        for i, label in enumerate(labels):
            r = QRect(right, y0 + i * 52, 36, 36)
            p.fillRect(r, QColor(8, 20, 38, 225))
            p.setPen(QPen(QColor(84, 120, 156, 220), 1))
            p.drawRect(r)
            p.setPen(QPen(QColor(236, 248, 255, 235), 1))
            p.drawText(r.adjusted(0, 0, 0, 0), Qt.AlignCenter, label)
        p.restore()

    def _draw_overlay(self, p: QPainter, rect: QRect):
        p.save()
        p.setPen(QPen(QColor(14, 200, 255, 190), 1))
        p.drawRect(rect.adjusted(1, 1, -2, -2))
        p.setPen(QPen(QColor(120, 210, 255, 200), 1))
        p.drawText(
            10,
            20,
            f"MODE: {self._view_mode} PIXEL NATIVE   FILTER: {self._filter}   ZOOM: {self._zoom:.2f}x   ROT: {self._rotation_deg:.0f}deg",
        )
        p.restore()

    def _filtered_points(self) -> list[dict]:
        points = self._scoped_points()
        if self._filter == "ALL":
            return points
        mapping = {
            "WI-FI": "WIFI",
            "BLE": "BLE",
            "HANDSHAKES": "HANDSHAKE",
            "GPS": "GPS",
        }
        target = mapping.get(self._filter, "WIFI")
        out = [p for p in points if p.get("type") == target]
        if len(out) > 2600:
            out = out[:: max(1, len(out) // 2600)]
        return out

    def _scoped_points(self) -> list[dict]:
        if self._classic_scope == "all" or self._view_mode != "CLASSIC":
            return self._points
        # Group by inferred session id from source log names (wardrive_N.log).
        with_session = [p for p in self._points if p.get("session_id") is not None]
        if not with_session:
            return self._points
        sessions = sorted({int(p["session_id"]) for p in with_session})
        if not sessions:
            return self._points
        if self._classic_scope == "latest_session":
            sid_set = {sessions[-1]}
        else:
            sid_set = set(sessions[-max(1, self._classic_recent_n):])
        scoped = [p for p in self._points if int(p.get("session_id", -1)) in sid_set]
        return scoped if scoped else self._points

    def _project_points(self, points: list[dict], rect: QRect) -> list[QPointF]:
        usable = [(p.get("lat"), p.get("lon")) for p in points if p.get("lat") is not None and p.get("lon") is not None]
        if not usable:
            return []
        out: list[QPointF] = []
        for lat, lon in usable:
            out.append(self._project_lat_lon(lat, lon, rect))
        return out

    def _project_lat_lon(self, lat: float, lon: float, rect: QRect) -> QPointF:
        return self._project_lat_lon_with(lat, lon, rect, self._zoom, self._pan_x, self._pan_y)

    def _compute_geo_bounds(self) -> tuple[float, float, float, float]:
        lat_vals: list[float] = []
        lon_vals: list[float] = []
        for lat, lon in self._route:
            lat_vals.append(lat)
            lon_vals.append(lon)
        for p in self._points:
            lat = p.get("lat")
            lon = p.get("lon")
            if lat is None or lon is None:
                continue
            lat_vals.append(lat)
            lon_vals.append(lon)
        if not lat_vals or not lon_vals:
            return (0.0, 1.0, 0.0, 1.0)

        lat_vals.sort()
        lon_vals.sort()
        lo_idx = int(len(lat_vals) * 0.01)
        hi_idx = max(lo_idx, int(len(lat_vals) * 0.99) - 1)
        lat_min = lat_vals[lo_idx]
        lat_max = lat_vals[hi_idx]
        lon_min = lon_vals[lo_idx]
        lon_max = lon_vals[hi_idx]
        if lat_max <= lat_min:
            lat_max = lat_min + 0.000001
        if lon_max <= lon_min:
            lon_max = lon_min + 0.000001
        return (lat_min, lat_max, lon_min, lon_max)

    def _build_landmarks(self) -> list[dict]:
        points = [p for p in self._points if p.get("lat") is not None and p.get("lon") is not None]
        if not points:
            return []
        lat_min, lat_max, lon_min, lon_max = self._geo_bounds or self._compute_geo_bounds()
        lat_span = max(0.0000001, lat_max - lat_min)
        lon_span = max(0.0000001, lon_max - lon_min)

        buckets: dict[tuple[int, int], list[dict]] = {}
        for p in points:
            nx = (float(p["lon"]) - lon_min) / lon_span
            ny = (float(p["lat"]) - lat_min) / lat_span
            gx = max(0, min(7, int(nx * 8)))
            gy = max(0, min(7, int(ny * 8)))
            buckets.setdefault((gx, gy), []).append(p)

        ranked = sorted(buckets.items(), key=lambda kv: len(kv[1]), reverse=True)[:10]
        landmarks: list[dict] = []
        for (_gx, _gy), group in ranked:
            if len(group) < 12:
                continue
            lat = sum(float(p["lat"]) for p in group) / len(group)
            lon = sum(float(p["lon"]) for p in group) / len(group)
            wifi = sum(1 for p in group if p.get("type") == "WIFI")
            ble = sum(1 for p in group if p.get("type") == "BLE")
            hs = sum(1 for p in group if p.get("type") == "HANDSHAKE")
            if hs >= max(wifi, ble):
                kind = "target"
            elif ble > wifi:
                kind = "district"
            elif wifi > ble * 2:
                kind = "tower"
            else:
                kind = "hub"
            landmarks.append({"lat": lat, "lon": lon, "kind": kind, "count": len(group)})
        return landmarks[:8]

    def _focus_on_latest_entity(self) -> None:
        latest = None
        latest_ts = ""
        for p in self._scoped_points():
            typ = str(p.get("type") or "")
            if typ not in ("WIFI", "BLE"):
                continue
            ts = str(p.get("last_seen") or "")
            if ts and ts > latest_ts:
                latest_ts = ts
                latest = p
        if not latest:
            return
        lat = latest.get("lat")
        lon = latest.get("lon")
        if lat is None or lon is None:
            return
        target_zoom = 2.2 if self._view_mode == "CLASSIC" else 3.2
        self._zoom = max(0.38, min(5.2, target_zoom))
        self._latest_entity_id = str(latest.get("id", ""))
        if self.width() < 10 or self.height() < 10:
            return
        center = QPointF(self.width() * 0.5, self.height() * 0.52)
        projected = self._project_lat_lon_with(float(lat), float(lon), self.rect(), self._zoom, 0.0, 0.0)
        self._pan_x = center.x() - projected.x()
        self._pan_y = center.y() - projected.y()

    def _project_lat_lon_with(self, lat: float, lon: float, rect: QRect, zoom: float, pan_x: float, pan_y: float) -> QPointF:
        bounds = self._geo_bounds
        if not bounds:
            bounds = self._compute_geo_bounds()
            self._geo_bounds = bounds
        lat_min, lat_max, lon_min, lon_max = bounds
        lat_span = max(0.0000001, lat_max - lat_min)
        lon_span = max(0.0000001, lon_max - lon_min)
        nx = max(0.0, min(1.0, (lon - lon_min) / lon_span))
        ny = max(0.0, min(1.0, (lat - lat_min) / lat_span))
        cx = nx - 0.5
        cy = ny - 0.5

        ang = math.radians(self._rotation_deg)
        rx = (cx * math.cos(ang)) - (cy * math.sin(ang))
        ry = (cx * math.sin(ang)) + (cy * math.cos(ang))
        if self._view_mode == "CLASSIC":
            norm = self._classic_renderer.latlon_to_norm(lat, lon)
            if norm is not None:
                nnx, nny = norm
                base_x = (nnx - 0.5)
                base_y = (nny - 0.5)
                rx = (base_x * math.cos(ang)) - (base_y * math.sin(ang))
                ry = (base_x * math.sin(ang)) + (base_y * math.cos(ang))
            sx = (rect.width() * 0.5) + (rx * rect.width() * 0.96 * zoom) + pan_x
            sy = (rect.height() * 0.5) + (ry * rect.height() * 0.96 * zoom) + pan_y
            return QPointF(sx, sy)
        iso_x = (rx - ry) * 0.92
        iso_y = ((rx + ry) * 0.48)
        sx = (rect.width() * 0.5) + (iso_x * rect.width() * 0.78 * zoom) + pan_x
        sy = (rect.height() * 0.54) + (iso_y * rect.height() * 0.88 * zoom) + pan_y
        return QPointF(sx, sy)

    def _merc_x(self, lon: float) -> float:
        return (lon + 180.0) / 360.0

    def _merc_y(self, lat: float) -> float:
        lat = max(-85.0511, min(85.0511, lat))
        r = math.radians(lat)
        return (1.0 - math.log(math.tan(r) + (1.0 / max(0.000001, math.cos(r)))) / math.pi) / 2.0

    def _compute_merc_bounds(self) -> tuple[float, float, float, float]:
        lat_min, lat_max, lon_min, lon_max = self._geo_bounds or self._compute_geo_bounds()
        x0 = self._merc_x(lon_min)
        x1 = self._merc_x(lon_max)
        y0 = self._merc_y(lat_max)
        y1 = self._merc_y(lat_min)
        if x1 <= x0:
            x1 = x0 + 0.000001
        if y1 <= y0:
            y1 = y0 + 0.000001
        return (x0, y0, x1, y1)

    def _latlon_to_tile(self, lat: float, lon: float, zoom: int) -> tuple[float, float]:
        n = 2.0 ** zoom
        x = (lon + 180.0) / 360.0 * n
        lat = max(-85.0511, min(85.0511, lat))
        lat_rad = math.radians(lat)
        y = (1.0 - math.log(math.tan(lat_rad) + 1 / math.cos(lat_rad)) / math.pi) / 2.0 * n
        return (x, y)

    def _tile_to_latlon(self, x: int, y: int, zoom: int) -> tuple[float, float]:
        n = 2.0 ** zoom
        lon = x / n * 360.0 - 180.0
        lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y / n)))
        lat = math.degrees(lat_rad)
        return (lon, lat)

    def _nearest_point_index(self, pos: QPointF, max_dist: float = 9999.0) -> int:
        pts = self._filtered_points()
        if not pts:
            return -1
        prj = self._project_points(pts, self.rect())
        best_idx = -1
        best_d2 = max_dist * max_dist
        for i, qpt in enumerate(prj):
            dx = pos.x() - qpt.x()
            dy = pos.y() - qpt.y()
            d2 = (dx * dx) + (dy * dy)
            if d2 < best_d2:
                best_d2 = d2
                best_idx = i
        return best_idx

    def _parse_master_csv(self, path: str) -> list[dict]:
        rows: list[dict] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
                rdr = csv.DictReader(f)
                for row in rdr:
                    mac = (row.get("MAC") or "").strip()
                    if not mac:
                        continue
                    auth = (row.get("AuthMode") or "").strip()
                    ssid = (row.get("TopSSID") or "").strip() or "No Data"
                    hs = (row.get("HandshakeSeen") or "").strip().lower() == "yes"
                    lat = self._to_float(row.get("CentroidLat"))
                    lon = self._to_float(row.get("CentroidLon"))
                    if lat is None or lon is None:
                        continue
                    entity_type = "HANDSHAKE" if hs else ("BLE" if "ble" in (ssid + " " + auth).lower() else "WIFI")
                    rows.append({
                        "id": mac,
                        "type": entity_type,
                        "ssid": ssid,
                        "auth": auth,
                        "last_seen": (row.get("LastSeen") or "").strip(),
                        "logfiles": (row.get("LogFiles") or "").strip(),
                        "session_id": self._extract_latest_session_id((row.get("LogFiles") or "").strip()),
                        "lat": lat,
                        "lon": lon,
                        "rssi": self._to_int(row.get("BestRSSI")),
                        "channel": self._to_int(row.get("Channel")),
                    })
            if len(rows) > 9000:
                rows = rows[:: max(1, len(rows) // 9000)]
        except Exception:
            return []
        return rows

    def _parse_kml_route_segments(self, path: str) -> list[list[tuple[float, float]]]:
        try:
            text = open(path, "r", encoding="utf-8", errors="replace").read()
        except Exception:
            return []
        matches = re.findall(r"<coordinates>(.*?)</coordinates>", text, flags=re.S | re.I)
        segments: list[list[tuple[float, float]]] = []
        for block in matches:
            segment: list[tuple[float, float]] = []
            for token in block.strip().split():
                parts = token.split(",")
                if len(parts) < 2:
                    continue
                lon = self._to_float(parts[0])
                lat = self._to_float(parts[1])
                if lat is None or lon is None:
                    continue
                segment.append((lat, lon))
            if len(segment) >= 2:
                if len(segment) > 3000:
                    segment = segment[:: max(1, len(segment) // 3000)]
                segments.append(segment)
        return segments

    def _to_float(self, value):
        try:
            if value is None:
                return None
            return float(str(value).strip())
        except Exception:
            return None

    def _to_int(self, value):
        try:
            if value is None or str(value).strip() == "":
                return None
            return int(float(str(value).strip()))
        except Exception:
            return None

    def _extract_latest_session_id(self, logfiles: str) -> int | None:
        if not logfiles:
            return None
        nums = re.findall(r"wardrive_(\d+)\.log", logfiles, flags=re.I)
        if not nums:
            return None
        try:
            return max(int(n) for n in nums)
        except Exception:
            return None

    def _refresh_summary(self):
        if self._summary_label is None:
            return
        points = self._points
        wifi = sum(1 for p in points if p.get("type") == "WIFI")
        ble = sum(1 for p in points if p.get("type") == "BLE")
        hs = sum(1 for p in points if p.get("type") == "HANDSHAKE")
        gps = len(self._gps_points)
        sel = None
        filt = self._filtered_points()
        if 0 <= self._selected_idx < len(filt):
            sel = filt[self._selected_idx]
        if sel:
            selected = f"Selected: {sel.get('ssid','No Data')} | {sel.get('id','')} | CH {sel.get('channel','-')} RSSI {sel.get('rssi','-')}"
        else:
            selected = "Selected: none"
        scope_txt = self._classic_scope if self._view_mode == "CLASSIC" else "isometric"
        self._summary_label.setText(
            f"Telemetry | AP:{wifi} BLE:{ble} HS:{hs} GPS:{gps} | Scope:{scope_txt} | Filter:{self._filter} | {selected}"
        )


class AnalyzeWorker(QThread):
    stage = Signal(str)
    done = Signal(dict)
    failed = Signal(str)

    # Progress: (completed_steps, total_steps, label)
    progress = Signal(int, int, str)

    def __init__(self, wardrive_files: list[str], pcap_files: list[str], project_dir: str):
        super().__init__()
        self.wardrive_files = wardrive_files
        self.pcap_files = pcap_files
        self.project_dir = project_dir

    def run(self):
        request_path = ""
        proc = None
        try:
            def handle_stage(msg: str):
                msg = _safe_gui_text(msg, limit=1200)
                self.stage.emit(msg)

                # Heuristic progress extraction from core log lines.
                # We keep this lightweight so core remains tool/format agnostic.
                m = re.search(r"P4R51NG (?:PCAP|L0G)\s+(\d+)/(\d+):\s*(.+)$", msg)
                if m:
                    cur = int(m.group(1))
                    tot = int(m.group(2))
                    label = m.group(3).strip()
                    self.progress.emit(cur, tot, label)
                if msg.startswith("[+] ") or msg.startswith("[+] WR1T1NG") or msg.startswith("[+] R3ND3R1NG"):
                    # coarse artifact progress as +1 step; GUI will handle mapping
                    self.progress.emit(-1, -1, msg)

            self.stage.emit("Boot sequence… Initializing run folder")
            self.stage.emit(f"Wardrive logs queued: {len(self.wardrive_files)}")
            self.stage.emit(f"PCAP captures queued: {len(self.pcap_files)}")
            self.stage.emit("Executing analyzer in isolated subprocess…")

            reports_dir = os.path.join(os.getcwd(), "error_reports")
            os.makedirs(reports_dir, exist_ok=True)
            request_path = os.path.join(reports_dir, f"analysis_request_{os.getpid()}_{int(time.time())}.json")
            with open(request_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "project_dir": self.project_dir,
                        "wardrive_files": self.wardrive_files,
                        "pcap_files": self.pcap_files,
                    },
                    f,
                    ensure_ascii=False,
                    indent=2,
                )

            script = resource_path("analysis_subprocess.py")
            child_python = sys.executable
            if os.path.basename(child_python).lower() == "pythonw.exe":
                candidate = os.path.join(os.path.dirname(child_python), "python.exe")
                if os.path.exists(candidate):
                    child_python = candidate
            proc = subprocess.Popen(
                [child_python, script, request_path],
                cwd=os.getcwd(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            stderr_lines: list[str] = []
            assert proc.stderr is not None
            for line in proc.stderr:
                line = line.strip()
                if not line:
                    continue
                stderr_lines.append(line)
                try:
                    event = json.loads(line)
                    msg = str(event.get("event", line))
                except Exception:
                    msg = line
                handle_stage(msg)

            assert proc.stdout is not None
            stdout = proc.stdout.read()
            return_code = proc.wait()

            data = None
            for line in reversed([x.strip() for x in stdout.splitlines() if x.strip()]):
                try:
                    data = json.loads(line)
                    break
                except Exception:
                    continue

            if return_code != 0:
                detail = f"Analyzer subprocess exited with code {return_code}."
                if data and data.get("error"):
                    detail += f"\n{data.get('error')}"
                if data and data.get("report"):
                    detail += f"\nReport: {data.get('report')}"
                if stdout.strip():
                    detail += f"\n\nstdout tail:\n{stdout[-2000:]}"
                if stderr_lines:
                    detail += f"\n\nstderr tail:\n" + "\n".join(stderr_lines[-20:])
                self.failed.emit(_safe_gui_text(detail, limit=5000))
                return

            if not data or data.get("status") != "ok":
                self.failed.emit(_safe_gui_text(f"Analyzer subprocess returned unexpected output:\n{stdout[-3000:]}", limit=5000))
                return

            results = data.get("results") or {}

            self.stage.emit("Complete.")
            self.done.emit(results)
        except Exception as e:
            import traceback as _tb
            err = _safe_gui_text(f"{type(e).__name__}: {e}", limit=1200)
            trace = _safe_gui_text(_tb.format_exc(), limit=4000)
            report = write_error_report(
                "analysis_worker_failure",
                e,
                context={
                    "project_dir": self.project_dir,
                    "wardrive_files": len(self.wardrive_files),
                    "pcap_files": len(self.pcap_files),
                },
                traceback_text=trace,
            )
            self.stage.emit(f"[CRASH] {err}")
            self.stage.emit(f"Error report written: {report}")
            self.stage.emit(trace)
            self.failed.emit(f"{err}\n\nReport: {report}")
        finally:
            if proc is not None and proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass


# -----------------------------
# Ingest worker thread
# -----------------------------
class ScanWorker(QThread):
    """Runs scan_sd_folder on a background thread so the GUI stays live."""
    done   = Signal(list)   # list[CandidateFile]
    failed = Signal(str)

    def __init__(self, folder: str):
        super().__init__()
        self.folder = folder

    def run(self):
        try:
            candidates = scan_sd_folder(self.folder)
            self.done.emit(candidates)
        except Exception as e:
            self.failed.emit(str(e))


class IngestWorker(QThread):
    stage         = Signal(str)            # log line (throttled)
    progress      = Signal(int, int)       # (files_done, files_total)
    file_progress = Signal(str, str, int, int)  # (filename, phase, bytes_done, bytes_total)
    done          = Signal(dict)
    failed        = Signal(str)

    # Emit a stage signal at most every N files to avoid flooding the event loop
    _SIGNAL_EVERY = 5

    def __init__(self, project_dir: str, sd_root: str,
                 candidates: list, label: str, skip_duplicates: bool):
        super().__init__()
        self.project_dir     = project_dir
        self.sd_root         = sd_root
        self.candidates      = candidates
        self.label           = label
        self.skip_duplicates = skip_duplicates
        self._total          = len(candidates)
        self._done_count     = 0

    def run(self):
        try:
            every = max(1, self._SIGNAL_EVERY)

            def cb(msg: str):
                self._done_count += 1
                is_notable = (
                    msg.startswith("ERROR")
                    or msg.startswith("Duplicate")
                    or self._done_count % every == 0
                    or self._done_count == self._total
                )
                if is_notable:
                    self.stage.emit(msg)
                self.progress.emit(self._done_count, self._total)

            def file_cb(filename: str, phase: str, done: int, total: int):
                self.file_progress.emit(filename, phase, done, total)

            stats = ingest_candidates_to_project(
                project_dir=self.project_dir,
                sd_root=self.sd_root,
                candidates=self.candidates,
                label=self.label,
                skip_duplicates=self.skip_duplicates,
                progress_cb=cb,
                file_progress_cb=file_cb,
            )
            self.done.emit(stats)
        except Exception as e:
            self.failed.emit(str(e))


class BuddyAIWorker(QThread):
    done = Signal(str, str, bool)      # action, response, used_ai
    failed = Signal(str, str, str)     # action, error, fallback

    def __init__(self, project_dir: str, action: str, config: BuddyAIConfig):
        super().__init__()
        self.project_dir = project_dir
        self.action = action
        self.config = config

    def run(self):
        try:
            context = build_buddy_context(self.project_dir, self.action)
            used_ai = bool(self.config.enabled and self.config.api_key.strip())
            response = BuddyAIClient(self.config).ask(self.action, context)
            self.done.emit(self.action, _safe_gui_text(response, limit=1200), used_ai)
        except Exception as e:
            try:
                context = build_buddy_context(self.project_dir, self.action)
                fallback = local_buddy_summary(self.action, context)
            except Exception:
                fallback = "I could not read that project state yet. Check the console, then try again."
            self.failed.emit(
                self.action,
                _safe_gui_text(str(e), limit=900),
                _safe_gui_text(fallback, limit=1200),
            )


# -----------------------------
# WIA Intelligence worker thread
# -----------------------------

class WIAWorker(QThread):
    """
    Background thread: loads assistant_engine, reads the wardrive CSV, and
    emits one card at a time so the UI can render progressively.

    Signals
    -------
    card_ready(dict)      — one card emitted per insight; keys match AssistantCard fields
    score_ready(int, str) — (score 0-100, grade A-F) emitted after cards
    finished_analysis(int) — total card count emitted when done
    """
    card_ready        = Signal(dict)
    score_ready       = Signal(int, str, str)   # score, grade, summary
    finished_analysis = Signal(int)

    def __init__(self, results: dict, parent=None):
        super().__init__(parent)
        self.results = results

    def run(self):
        try:
            from assistant_engine import WIAEngine
            engine = WIAEngine()
            cards  = engine.analyze_results(self.results)

            quality = engine.get_quality()
            if quality is not None:
                self.score_ready.emit(quality.score, quality.grade, quality.summary)

            for card in cards:
                self.card_ready.emit({
                    "title":            card.title,
                    "fact":             card.fact,
                    "severity":         card.severity.value,
                    "confidence":       card.confidence.value,
                    "interpretation":   card.interpretation,
                    "educational_note": card.educational_note,
                    "mascot_flavor":    card.mascot_flavor,
                    "recommendation":   card.recommendation,
                    "timestamp":        card.timestamp,
                })
            self.finished_analysis.emit(len(cards))
        except Exception as exc:
            import traceback as _tb
            # Emit a single error card rather than crashing
            self.card_ready.emit({
                "title":      "WIA Engine Error",
                "fact":       str(exc),
                "severity":   "WARN",
                "confidence": "HIGH CONFIDENCE",
                "interpretation": _tb.format_exc()[-800:],
                "educational_note": "",
                "mascot_flavor": "The assistant hit a snag. Check the console.",
                "recommendation": "",
                "timestamp":  datetime.now().strftime("%H:%M:%S"),
            })
            self.finished_analysis.emit(0)


# -----------------------------
# Main GUI
# -----------------------------

class WardriveGUI(QWidget):
    # Maps mascot pose_id → PNG filename in assets/mascot/
    _MASCOT_PNG: dict = {
        "POSE_START":        "start.png",
        "POSE_LOGS":         "logs_added.png",
        "POSE_PCAPS":        "pcaps_added.png",
        "POSE_FOLDER":       "folder_selected.png",
        "POSE_ANALYZING":    "analyzing.png",
        "POSE_DONE":         "finished.png",
        "POSE_ERROR":        "error.png",
        "POSE_IDLE_SPECIAL": "start.png",
    }

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wardrive Mission Control")
        self.setMinimumSize(1280, 820)

        # Core state
        self.project_dir: str = ""
        self.logs: list[str] = []
        self.pcaps: list[str] = []
        self.wardrive_files: list[str] = []
        self.pcap_files: list[str] = []
        self._fp_logs: set[str] = set()
        self._fp_pcaps: set[str] = set()
        self._sd_root: str = ""
        self._sd_candidates: list[CandidateFile] = []
        self._latest_summary: str | None = None
        self._latest_run_dir: str | None = None
        self._project_last_summary: str | None = None
        self._project_last_map: str | None = None
        self._project_last_pcap_summary: str | None = None
        self._project_last_run_dir: str | None = None
        self._jobs: list[dict] = []
        self._active_job_id: int | None = None
        self._analysis_thread = None
        self._ingest_worker: IngestWorker | None = None
        self._ingest_job_id: int | None = None
        self._ingest_total: int = 0
        self._ingest_file_active: bool = False
        self._scan_worker: ScanWorker | None = None
        self._scan_job_id: int | None = None
        self._sd_scan_folder: str = ""
        self.mascot = MascotEngine()
        self._mascot_pixmap_cache: dict = {}
        self._mascot_bob_phase: float = 0.0
        self._buddy_ai_worker: BuddyAIWorker | None = None
        self._wia_worker: WIAWorker | None = None
        self._buddy_override_until: float = 0.0

        # Run-state + progress / ETA tracking
        self._running: bool = False
        self._last_busy_popup_ms: int = 0
        self._stage_total_steps: int = 0
        self._stage_done_steps: int = 0
        self._step_times: list[float] = []
        self.elapsed = QElapsedTimer()

        # QSS first (so widgets created later inherit it)
        self._load_qss()

        # Full-window animated procedural background
        self.demoscene = ProceduralBackground()
        self.demoscene.setObjectName("DemosceneBG")

        # Overlay layer (all interactive UI)
        overlay = QWidget()
        overlay.setObjectName("Overlay")
        overlay.setAttribute(Qt.WA_TranslucentBackground, True)

        overlay.setStyleSheet(
            "QWidget#Overlay{background: transparent;}"
            "QWidget#LeftPane{background-color: rgba(0,0,0,110); border: 1px solid rgba(0,255,220,90); border-radius: 14px;}"
            "QWidget#RightPane{background: transparent;}"
        )

        overlay_v = QVBoxLayout(overlay)
        overlay_v.setContentsMargins(12, 12, 12, 12)
        overlay_v.setSpacing(10)

        overlay_v.addWidget(self._build_hud(), 0)

        # Middle: tabs on the left, reserved "mascot space" on the right (25%)
        mid_row = QHBoxLayout()
        mid_row.setContentsMargins(0, 0, 0, 0)
        mid_row.setSpacing(10)

        left = QWidget()
        left.setObjectName("LeftPane")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)
        left_layout.addWidget(self._build_tabs(), 1)

        mid_row.addWidget(left, 3)

        self.right_panel = QWidget()
        self.right_panel.setObjectName("RightPane")
        self.right_panel.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.right_panel.setMinimumWidth(260)
        right_layout = QVBoxLayout(self.right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)
        right_layout.addWidget(self._build_buddy_panel(), 1)
        mid_row.addWidget(self.right_panel, 1)

        overlay_v.addLayout(mid_row, 1)

        # Bottom: always-visible glass console dock
        overlay_v.addWidget(self._build_console_dock(), 0)

        # Stack: background underneath, overlay on top
        stack = QStackedLayout(self)
        stack.setStackingMode(QStackedLayout.StackAll)
        stack.addWidget(self.demoscene)
        stack.addWidget(overlay)
        # Ensure UI overlays the background
        try:
            self.demoscene.lower()
            overlay.raise_()
        except Exception:
            pass
        self.setLayout(stack)

        # Start on a random demoscene
        self.demoscene.randomize()
        try:
            self.tabs.setCurrentWidget(self.tab_dashboard)
        except Exception:
            pass
        self.refresh_mission_control()
        self._log(f"Background: {self.demoscene.current_name}")
        self._buddy_timer = QTimer(self)
        self._buddy_timer.setInterval(900)
        self._buddy_timer.timeout.connect(self._tick_buddy)
        self._buddy_timer.start()
        self._tick_buddy()
        self._restore_last_project()

        # Fire boot sequence after event loop starts (100ms delay)
        QTimer.singleShot(100, self._boot_sequence)

    def _load_qss(self) -> None:
        """Load and apply the QSS theme (if present).

        Keep this as a soft dependency so the app still launches if the file is missing.
        """
        qss_path = resource_path("style_scene.qss")
        try:
            with open(qss_path, "r", encoding="utf-8") as f:
                qss = f.read()
        except Exception:
            # No theme file, or unreadable; continue without styling.
            return
        # Apply to the main window (propagates to children)
        self.setStyleSheet(qss)


    def _build_hud(self) -> QWidget:
        frame = QFrame()
        frame.setObjectName("HudFrame")
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)

        self.lbl_title = QLabel(f"WARDRIVE // ANALYZER  [{CORE_REVISION}]")
        self.lbl_title.setObjectName("HudTitle")

        self.lbl_project = QLabel("PROJECT: (not selected)")
        self.lbl_project.setObjectName("HudProject")

        self.lbl_status = QLabel("STATUS: IDLE")
        self.lbl_status.setObjectName("HudStatus")

        btn_regen = QPushButton("Regenerate Background")
        btn_regen.clicked.connect(self._regen_bg)

        layout.addWidget(self.lbl_title, 2)
        layout.addWidget(self.lbl_project, 3)
        layout.addWidget(self.lbl_status, 1)
        layout.addWidget(btn_regen, 0)
        return frame

    def _build_tabs(self) -> QWidget:
        self.tabs = QTabWidget()
        self.tabs.setObjectName("MainTabs")

        self.tab_setup = self._build_setup_tab()
        self.tab_dashboard = self._build_dashboard_tab()
        self.tab_evidence = self._build_evidence_vault_tab()
        self.tab_console = self._build_console_tab()
        self.tab_jobs = self._build_jobs_tab()
        self.tab_runs = self._build_runs_tab()
        self.tab_results = self._build_results_tab()
        self.tab_sd = self._build_sd_ingest_tab()
        self.tab_integrations = self._build_integrations_tab()
        self.tab_settings = self._build_settings_tab()
        self.tab_intelligence = self._build_intelligence_tab()

        self.tabs.addTab(self.tab_dashboard, "Dashboard")
        self.tabs.addTab(self.tab_intelligence, "Intelligence")
        self.tabs.addTab(self.tab_evidence, "Evidence Vault")
        self.tabs.addTab(self.tab_sd, "SD Ingest")
        self.tabs.addTab(self.tab_jobs, "Jobs")
        self.tabs.addTab(self.tab_runs, "Runs")
        self.tabs.addTab(self.tab_results, "Map/Reports")
        self.tabs.addTab(self.tab_integrations, "Integrations")
        self.tabs.addTab(self.tab_settings, "Settings")
        self.tabs.addTab(self.tab_console, "Console")

        try:
            self.tabs.setCurrentWidget(self.tab_dashboard)
        except Exception:
            pass

        return self.tabs

    def _build_buddy_panel(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("BuddyFrame")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(10)

        title = QLabel("MARAUDER // BUDDY")
        title.setObjectName("BuddyTitle")
        v.addWidget(title)

        self.lbl_buddy_pose = QLabel()
        self.lbl_buddy_pose.setObjectName("BuddyPose")
        self.lbl_buddy_pose.setFixedHeight(200)
        self.lbl_buddy_pose.setAlignment(Qt.AlignCenter)
        self.lbl_buddy_pose.setScaledContents(False)
        self.lbl_buddy_pose.setCursor(Qt.PointingHandCursor)
        self.lbl_buddy_pose.mousePressEvent = self._on_marauder_pose_clicked  # type: ignore[method-assign]
        v.addWidget(self.lbl_buddy_pose)

        self.lbl_buddy_bubble = QLabel("Ready when you are, operator.")
        self.lbl_buddy_bubble.setObjectName("BuddyBubble")
        self.lbl_buddy_bubble.setWordWrap(True)
        self.lbl_buddy_bubble.setMinimumHeight(84)
        v.addWidget(self.lbl_buddy_bubble)

        self.cmb_buddy_action = QComboBox()
        self.cmb_buddy_action.addItem("Suggest next step", "next_step")
        self.cmb_buddy_action.addItem("Summarize latest run", "summarize_latest_run")
        self.cmb_buddy_action.addItem("Evidence health check", "evidence_health")
        self.cmb_buddy_action.addItem("Strongest unknown APs", "strongest_unknown_aps")
        self.cmb_buddy_action.addItem("Compare latest runs", "compare_latest_runs")
        self.cmb_buddy_action.addItem("Flag suspicious handshakes", "suspicious_handshakes")
        v.addWidget(self.cmb_buddy_action)

        row = QHBoxLayout()
        self.btn_buddy_ask = QPushButton("Ask Buddy")
        self.btn_buddy_ask.setObjectName("PrimaryButton")
        self.btn_buddy_ask.clicked.connect(self._buddy_ask_selected)
        self.btn_buddy_local = QPushButton("Local Tip")
        self.btn_buddy_local.clicked.connect(self._buddy_local_selected)
        row.addWidget(self.btn_buddy_ask)
        row.addWidget(self.btn_buddy_local)
        v.addLayout(row)

        marauder_row = QHBoxLayout()
        self.btn_marauder_next = QPushButton("Marauder: Next Move")
        self.btn_marauder_next.clicked.connect(self._marauder_next_move)
        self.btn_marauder_map = QPushButton("Open Isometric Map")
        self.btn_marauder_map.clicked.connect(self._marauder_open_map)
        self.btn_marauder_summary = QPushButton("Open Last Summary")
        self.btn_marauder_summary.clicked.connect(self.open_latest_summary)
        marauder_row.addWidget(self.btn_marauder_next)
        marauder_row.addWidget(self.btn_marauder_map)
        marauder_row.addWidget(self.btn_marauder_summary)
        v.addLayout(marauder_row)

        self.txt_buddy_readout = QTextEdit()
        self.txt_buddy_readout.setObjectName("BuddyReadout")
        self.txt_buddy_readout.setReadOnly(True)
        self.txt_buddy_readout.setMinimumHeight(150)
        self.txt_buddy_readout.setPlainText(
            "Offline buddy is active. Add an AI token in Settings to unlock model-backed readouts."
        )
        v.addWidget(self.txt_buddy_readout, 1)

        privacy = QLabel("AI mode sends compact sanitized summaries only. Raw PCAPs, tokens, and full paths stay local.")
        privacy.setObjectName("BuddyPrivacy")
        privacy.setWordWrap(True)
        v.addWidget(privacy)

        return panel

    def _make_table(self, headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        try:
            table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            table.verticalHeader().setVisible(False)
        except Exception:
            pass
        return table

    def _build_dashboard_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(10)

        title = QLabel("Mission Control")
        title.setObjectName("PanelTitle")
        v.addWidget(title)

        self.lbl_dash_project = QLabel("Project: not selected")
        self.lbl_dash_project.setObjectName("PathLabel")
        v.addWidget(self.lbl_dash_project)

        stats_row = QHBoxLayout()
        self.lbl_dash_evidence = QLabel("Evidence: 0")
        self.lbl_dash_imports = QLabel("Imports: 0")
        self.lbl_dash_runs = QLabel("Runs: 0")
        self.lbl_dash_tools = QLabel("Tools: tshark pending check")
        for lbl in (self.lbl_dash_evidence, self.lbl_dash_imports, self.lbl_dash_runs, self.lbl_dash_tools):
            lbl.setObjectName("StatChip")
            stats_row.addWidget(lbl)
        v.addLayout(stats_row)

        action_row = QHBoxLayout()
        btn_project = QPushButton("Select Project")
        btn_project.clicked.connect(self.select_project_folder)
        btn_scan = QPushButton("Go to SD Ingest")
        btn_scan.clicked.connect(lambda: self.tabs.setCurrentWidget(self.tab_sd))
        btn_analyze = QPushButton("Analyze Project Evidence")
        btn_analyze.setObjectName("PrimaryButton")
        btn_analyze.clicked.connect(self.sd_analyze_project_evidence)
        btn_summary = QPushButton("Open Latest Summary")
        btn_summary.clicked.connect(self.open_any_latest_summary)
        btn_folder = QPushButton("Open Project Folder")
        btn_folder.clicked.connect(self.open_project_folder)
        btn_sync_dropbox = QPushButton("Sync to Dropbox")
        btn_sync_dropbox.clicked.connect(self.sync_to_dropbox)
        btn_install_android = QPushButton("Install Android App")
        btn_install_android.clicked.connect(self.install_android_app)
        btn_android_devices = QPushButton("Android Devices")
        btn_android_devices.clicked.connect(self.open_android_devices_dialog)
        for b in (btn_project, btn_scan, btn_analyze, btn_summary, btn_folder, btn_sync_dropbox, btn_install_android, btn_android_devices):
            action_row.addWidget(b)
        v.addLayout(action_row)

        self.lbl_dash_latest_import = QLabel("Latest import: none")
        self.lbl_dash_latest_import.setObjectName("Notes")
        self.lbl_dash_latest_run = QLabel("Latest run: none")
        self.lbl_dash_latest_run.setObjectName("Notes")
        v.addWidget(self.lbl_dash_latest_import)
        v.addWidget(self.lbl_dash_latest_run)

        self.tbl_dash_sources = self._make_table(["Source", "Files"])
        self.tbl_dash_sources.setMaximumHeight(170)
        v.addWidget(self.tbl_dash_sources)

        return panel

    def _build_evidence_vault_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(10)

        row = QHBoxLayout()
        title = QLabel("Evidence Vault")
        title.setObjectName("PanelTitle")
        self.lbl_evidence_summary = QLabel("No project selected.")
        self.lbl_evidence_summary.setObjectName("Notes")
        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self.refresh_mission_control)
        row.addWidget(title)
        row.addWidget(self.lbl_evidence_summary, 1)
        row.addWidget(btn_refresh)
        v.addLayout(row)

        self.tbl_evidence = self._make_table(["Source", "Kind", "File", "Size", "Duplicate", "SHA-256", "Imported"])
        v.addWidget(self.tbl_evidence, 1)
        return panel

    def _build_jobs_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(10)

        row = QHBoxLayout()
        title = QLabel("Job Center")
        title.setObjectName("PanelTitle")
        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self.refresh_jobs_table)
        row.addWidget(title)
        row.addStretch(1)
        row.addWidget(btn_refresh)
        v.addLayout(row)

        self.tbl_jobs = self._make_table(["ID", "Type", "Status", "Started", "Ended", "Progress", "Result / Error"])
        v.addWidget(self.tbl_jobs, 1)
        return panel

    def _build_runs_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(10)

        row = QHBoxLayout()
        title = QLabel("Run History")
        title.setObjectName("PanelTitle")
        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self.refresh_mission_control)
        btn_compare = QPushButton("Compare Latest Two")
        btn_compare.clicked.connect(self.compare_latest_runs)
        btn_open = QPushButton("Open Selected Run")
        btn_open.clicked.connect(self.open_selected_run)
        row.addWidget(title)
        row.addStretch(1)
        row.addWidget(btn_refresh)
        row.addWidget(btn_compare)
        row.addWidget(btn_open)
        v.addLayout(row)

        self.tbl_runs = self._make_table(["Run", "Modified", "Outputs", "Missing", "Path"])
        v.addWidget(self.tbl_runs, 2)

        self.tbl_compare = self._make_table(["Metric", "Value", "Details"])
        self.tbl_compare.setMaximumHeight(190)
        v.addWidget(self.tbl_compare, 1)
        return panel

    def _build_setup_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(10)

        # Project
        self.outputLabel = QLabel("Project Folder: Not selected")
        self.outputLabel.setObjectName("PathLabel")
        v.addWidget(self.outputLabel)

        rowp = QHBoxLayout()
        btn_project = QPushButton("Select Project Folder")
        btn_project.clicked.connect(self.select_project_folder)
        self.btn_open_project = QPushButton("Open Project Folder")
        self.btn_open_project.clicked.connect(self.open_project_folder)
        self.btn_open_project.setEnabled(False)
        rowp.addWidget(btn_project)
        rowp.addWidget(self.btn_open_project)
        v.addLayout(rowp)

        # Logs
        v.addWidget(QLabel("Wardrive Logs (.log / .txt)"))
        self.wardriveList = QListWidget()
        v.addWidget(self.wardriveList, 2)

        row1 = QHBoxLayout()
        btn_add_logs = QPushButton("Add Logs")
        btn_add_logs.clicked.connect(self.add_wardrive_files)
        btn_clear_logs = QPushButton("Clear Logs")
        btn_clear_logs.clicked.connect(self.clear_wardrive_files)
        row1.addWidget(btn_add_logs)
        row1.addWidget(btn_clear_logs)
        v.addLayout(row1)

        # PCAPs
        v.addWidget(QLabel("PCAP Files (.pcap / .pcapng)"))
        self.pcapList = QListWidget()
        v.addWidget(self.pcapList, 2)

        row2 = QHBoxLayout()
        btn_add_pcaps = QPushButton("Add PCAPs")
        btn_add_pcaps.clicked.connect(self.add_pcap_files)
        btn_clear_pcaps = QPushButton("Clear PCAPs")
        btn_clear_pcaps.clicked.connect(self.clear_pcap_files)
        row2.addWidget(btn_add_pcaps)
        row2.addWidget(btn_clear_pcaps)
        v.addLayout(row2)

        self.btn_analyze = QPushButton("Analyze")
        self.btn_analyze.setObjectName("PrimaryButton")
        self.btn_analyze.clicked.connect(self.run_analysis)
        v.addWidget(self.btn_analyze)

        return panel

    def _build_console_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(6)

        hdr = QHBoxLayout()
        title = QLabel("CONSOLE // OPERATOR LOG")
        title.setObjectName("PanelTitle")
        hdr.addWidget(title, 1)

        btn_clear = QPushButton("Clear")
        btn_clear.setFixedWidth(70)
        btn_clear.clicked.connect(self._console_clear)
        hdr.addWidget(btn_clear, 0)
        v.addLayout(hdr)

        self.console_big = QTextEdit()
        self.console_big.setReadOnly(True)
        self.console_big.setObjectName("ConsoleBig")
        # Tight monospace, no paragraph margins between lines
        self.console_big.setStyleSheet(
            "QTextEdit#ConsoleBig {"
            "  background-color: rgba(0,0,0,180);"
            "  color: #C8FFFA;"
            "  font-family: Consolas, 'Courier New', monospace;"
            "  font-size: 9pt;"
            "  border: 1px solid rgba(0,255,220,80);"
            "  border-radius: 10px;"
            "}"
        )
        self.console_big.document().setDefaultStyleSheet(
            "p { margin:0; padding:0; line-height: 1.25; }"
        )
        v.addWidget(self.console_big, 1)
        return panel

    # ── Intelligence Panel ────────────────────────────────────────────────

    # Severity → (border-color, background-color, label-color)
    _WIA_SEVERITY_STYLE: dict = {
        "BOOT":    ("#00c8ff", "rgba(0,200,255,18)",  "#00c8ff"),
        "INFO":    ("#7090a0", "rgba(100,130,150,15)", "#90b0c0"),
        "NOTE":    ("#00e0c0", "rgba(0,220,190,18)",  "#00e0c0"),
        "INSIGHT": ("#40e840", "rgba(40,220,40,18)",  "#40e840"),
        "WARN":    ("#ffb020", "rgba(255,160,20,18)", "#ffb020"),
        "ANOMALY": ("#ff6020", "rgba(255,80,20,18)",  "#ff6020"),
        "SCORE":   ("#d060ff", "rgba(180,60,255,18)", "#d060ff"),
    }

    def _build_intelligence_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(8)

        # ── Header row ──────────────────────────────────────────────────
        hdr = QHBoxLayout()
        title = QLabel("WARDRIVE INTELLIGENCE ASSISTANT")
        title.setObjectName("PanelTitle")
        hdr.addWidget(title, 1)

        self.lbl_wia_score = QLabel("QUALITY SCORE: —")
        self.lbl_wia_score.setObjectName("StatChip")
        self.lbl_wia_score.setStyleSheet(
            "QLabel#StatChip { color: #d060ff; border: 1px solid #d060ff; "
            "padding: 3px 10px; border-radius: 6px; }"
        )
        hdr.addWidget(self.lbl_wia_score)

        btn_wia_clear = QPushButton("Clear Feed")
        btn_wia_clear.setFixedWidth(90)
        btn_wia_clear.clicked.connect(self._wia_clear)
        hdr.addWidget(btn_wia_clear)
        v.addLayout(hdr)

        # ── Status / grade description ───────────────────────────────────
        self.lbl_wia_status = QLabel(
            "Run an analysis to populate the intelligence feed. "
            "Cards are generated automatically when analysis completes."
        )
        self.lbl_wia_status.setObjectName("Notes")
        self.lbl_wia_status.setWordWrap(True)
        v.addWidget(self.lbl_wia_status)

        # ── Card feed (rich-text QTextEdit) ──────────────────────────────
        self.txt_wia_feed = QTextEdit()
        self.txt_wia_feed.setReadOnly(True)
        self.txt_wia_feed.setObjectName("WIAFeed")
        self.txt_wia_feed.setAcceptRichText(True)
        self.txt_wia_feed.setStyleSheet(
            "QTextEdit#WIAFeed {"
            "  background-color: rgba(0,0,0,180);"
            "  color: #C8FFFA;"
            "  font-family: Consolas, 'Courier New', monospace;"
            "  font-size: 9pt;"
            "  border: 1px solid rgba(0,255,220,80);"
            "  border-radius: 10px;"
            "}"
        )
        self.txt_wia_feed.document().setDefaultStyleSheet(
            "p { margin:0; padding:0; } "
            "h3 { margin:0; padding:0; } "
            "ul { margin:0 0 0 14px; padding:0; }"
        )
        v.addWidget(self.txt_wia_feed, 1)

        return panel

    def _wia_clear(self) -> None:
        """Clear the intelligence feed and score display."""
        try:
            self.txt_wia_feed.clear()
            self.lbl_wia_score.setText("QUALITY SCORE: —")
            self.lbl_wia_status.setText("Feed cleared. Run analysis to repopulate.")
        except Exception:
            pass

    def _wia_render_card(self, card: dict) -> None:
        """Append one card's HTML to the WIA feed (must be called from the main thread)."""
        severity = card.get("severity", "INFO")
        style    = self._WIA_SEVERITY_STYLE.get(severity, self._WIA_SEVERITY_STYLE["INFO"])
        border_col, bg_col, label_col = style

        title            = _safe_gui_text(card.get("title", ""), 120)
        fact             = _safe_gui_text(card.get("fact", ""), 800)
        interpretation   = _safe_gui_text(card.get("interpretation", ""), 600)
        educational_note = _safe_gui_text(card.get("educational_note", ""), 600)
        mascot_flavor    = _safe_gui_text(card.get("mascot_flavor", ""), 200)
        recommendation   = _safe_gui_text(card.get("recommendation", ""), 400)
        confidence       = _safe_gui_text(card.get("confidence", ""), 40)
        timestamp        = _safe_gui_text(card.get("timestamp", ""), 12)

        def nl2br(s: str) -> str:
            return s.replace("\n", "<br/>")

        html_parts = [
            f'<div style="border-left:3px solid {border_col};'
            f' background:{bg_col};'
            f' margin:6px 0; padding:8px 12px; border-radius:4px;">',
            f'<span style="color:{label_col}; font-weight:bold; font-size:10pt;">'
            f'[{severity}] {title}</span>'
            f'<span style="color:#606878; font-size:8pt;"> &nbsp;{timestamp} &nbsp;'
            f'<em>{confidence}</em></span><br/>',
            f'<span style="color:#b0c8d0;">{nl2br(fact)}</span>',
        ]

        if interpretation:
            html_parts.append(
                f'<br/><span style="color:#90c0b0;"><b>↳ </b>{nl2br(interpretation)}</span>'
            )

        if recommendation:
            html_parts.append(
                f'<br/><span style="color:#ffb020;"><b>→ </b>{nl2br(recommendation)}</span>'
            )

        if educational_note:
            html_parts.append(
                f'<br/><span style="color:#607080; font-style:italic;">'
                f'[edu] {nl2br(educational_note)}</span>'
            )

        if mascot_flavor:
            html_parts.append(
                f'<br/><span style="color:#508878; font-style:italic;">'
                f'» {nl2br(mascot_flavor)}</span>'
            )

        html_parts.append("</div>")

        cursor = self.txt_wia_feed.textCursor()
        cursor.movePosition(cursor.End)
        self.txt_wia_feed.setTextCursor(cursor)
        self.txt_wia_feed.insertHtml("".join(html_parts))

        # Auto-scroll to bottom
        sb = self.txt_wia_feed.verticalScrollBar()
        if sb:
            sb.setValue(sb.maximum())

    def _on_wia_card(self, card: dict) -> None:
        """Slot: receive one InsightCard dict from WIAWorker and render it."""
        try:
            self._wia_render_card(card)
        except Exception:
            pass

    def _on_wia_score(self, score: int, grade: str, summary: str) -> None:
        """Slot: receive quality score from WIAWorker."""
        try:
            score_text = f"CAPTURE QUALITY: {score}/100 (Grade {grade})"
            self.lbl_wia_score.setText(score_text)

            color_map = {
                "A": "#40e840", "B": "#90d050",
                "C": "#ffb020", "D": "#ff8020", "F": "#ff4020",
            }
            col = color_map.get(grade, "#d060ff")
            self.lbl_wia_score.setStyleSheet(
                f"QLabel#StatChip {{ color: {col}; border: 1px solid {col}; "
                "padding: 3px 10px; border-radius: 6px; }"
            )
            short_summary = summary[:120] + ("…" if len(summary) > 120 else "")
            self.lbl_wia_status.setText(short_summary)
        except Exception:
            pass

    def _on_wia_complete(self, total_cards: int) -> None:
        """Slot: WIAWorker finished emitting all cards."""
        try:
            current = self.lbl_wia_status.text()
            self.lbl_wia_status.setText(
                current + f"  |  {total_cards} insight(s) generated."
            )
            self._log(f"[WIA] Intelligence feed populated: {total_cards} card(s).", "OK")
            self._wia_worker = None
        except Exception:
            pass

    def _start_wia_analysis(self, results: dict) -> None:
        """Launch WIAWorker after analysis completes."""
        csv_path = results.get("csv", "")
        if not csv_path:
            return
        try:
            import os as _os
            if not _os.path.exists(csv_path):
                return
        except Exception:
            return

        try:
            self._wia_clear()
            self.lbl_wia_status.setText("Intelligence engine running…")

            worker = WIAWorker(results)
            self._wia_worker = worker
            worker.card_ready.connect(self._on_wia_card)
            worker.score_ready.connect(self._on_wia_score)
            worker.finished_analysis.connect(self._on_wia_complete)
            worker.finished.connect(worker.deleteLater)
            worker.start()
        except Exception as exc:
            self._log(f"[WIA] Could not start intelligence worker: {exc}", "WARN")

    def _wia_emit_event(self, event_name: str, context: dict) -> None:
        """Emit a WIA event card directly into the feed (synchronous, main thread)."""
        try:
            from assistant_engine import WIAEngine, WIAEvent
            engine = WIAEngine()
            try:
                evt = WIAEvent(event_name)
            except ValueError:
                return
            card = engine.on_event(evt, context)
            if card is None:
                return
            self._wia_render_card({
                "title":            card.title,
                "fact":             card.fact,
                "severity":         card.severity.value,
                "confidence":       card.confidence.value,
                "interpretation":   card.interpretation,
                "educational_note": card.educational_note,
                "mascot_flavor":    card.mascot_flavor,
                "recommendation":   card.recommendation,
                "timestamp":        card.timestamp,
            })
        except Exception:
            pass

    def _console_clear(self):
        for attr in ("console_dock", "console_big"):
            w = getattr(self, attr, None)
            if w is None:
                continue
            try:
                w.clear()
            except Exception:
                pass
        self._log("Console cleared.", "BOOT")

    def _boot_sequence(self):
        """Emit a styled boot banner to the console after the UI is ready."""
        divider = "─" * 56

        # Check dpkt
        try:
            import dpkt as _dpkt
            dpkt_ver = getattr(_dpkt, "__version__", "ok")
            dpkt_status = f"dpkt {dpkt_ver} — native 802.11 parser ACTIVE"
            dpkt_ok = True
        except ImportError:
            dpkt_status = "dpkt NOT FOUND — PCAP parsing disabled"
            dpkt_ok = False

        # Check openpyxl
        try:
            import openpyxl as _xl
            xlsx_status = f"openpyxl {getattr(_xl, '__version__','ok')} — XLSX export ACTIVE"
        except ImportError:
            xlsx_status = "openpyxl NOT FOUND — XLSX export disabled"

        # Check leaflet assets
        leaflet_path = resource_path("assets", "leaflet", "leaflet.js")
        leaflet_status = "Leaflet offline assets OK" if os.path.exists(leaflet_path) else "Leaflet offline assets MISSING (CDN fallback)"

        seq = [
            (0,   "BOOT",  divider),
            (40,  "BOOT",  "  WARDRIVE MISSION CONTROL"),
            (80,  "BOOT",  f"  Core: {CORE_REVISION}   |   Python {sys.version.split()[0]}"),
            (120, "BOOT",  f"  OS: {platform.system()} {platform.release()} ({platform.machine()})"),
            (160, "BOOT",  divider),
            (220, "OK" if dpkt_ok else "ERROR", f"  {dpkt_status}"),
            (270, "OK",    f"  {xlsx_status}"),
            (320, "OK" if "OK" in leaflet_status else "WARN", f"  {leaflet_status}"),
            (380, "BOOT",  divider),
            (440, "INFO",  "  Select a Project Folder, then scan your SD card to begin."),
            (500, "INFO",  "  All events — scans, ingests, analysis — are logged here."),
            (560, "BOOT",  divider),
            (620, "BOOT",  "  SYSTEM READY // awaiting operator input"),
            (680, "BOOT",  divider),
        ]

        for delay_ms, level, msg in seq:
            QTimer.singleShot(delay_ms, lambda lv=level, m=msg: self._log(m, lv))

    def _build_results_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(10)

        self.lbl_latest = QLabel("Latest run: (none yet)")
        self.lbl_latest.setObjectName("PathLabel")
        v.addWidget(self.lbl_latest)

        self.lbl_map_telemetry = QLabel("Telemetry | AP:0 BLE:0 HS:0 GPS:0 | Filter:ALL | Selected: none")
        self.lbl_map_telemetry.setObjectName("StatChip")
        v.addWidget(self.lbl_map_telemetry)

        map_mode_row = QHBoxLayout()
        map_mode_row.addWidget(QLabel("Map mode:"))
        self.cmb_map_mode = QComboBox()
        self.cmb_map_mode.addItems(["Isometric (Pixel Native)", "Classic (Pixel Native)", "Legacy HTML"])
        self.cmb_map_mode.currentIndexChanged.connect(self._on_map_mode_changed)
        map_mode_row.addWidget(self.cmb_map_mode, 0)
        self.btn_map_zoom_in = QPushButton("Zoom +")
        self.btn_map_zoom_in.clicked.connect(lambda: self.native_map.nudge_zoom(1.16))
        map_mode_row.addWidget(self.btn_map_zoom_in, 0)
        self.btn_map_zoom_out = QPushButton("Zoom -")
        self.btn_map_zoom_out.clicked.connect(lambda: self.native_map.nudge_zoom(0.86))
        map_mode_row.addWidget(self.btn_map_zoom_out, 0)
        self.btn_map_rot_l = QPushButton("Rotate -")
        self.btn_map_rot_l.clicked.connect(lambda: self.native_map.rotate_by(-7.5))
        map_mode_row.addWidget(self.btn_map_rot_l, 0)
        self.btn_map_rot_r = QPushButton("Rotate +")
        self.btn_map_rot_r.clicked.connect(lambda: self.native_map.rotate_by(7.5))
        map_mode_row.addWidget(self.btn_map_rot_r, 0)
        self.btn_map_reset = QPushButton("Reset Map View")
        self.btn_map_reset.clicked.connect(lambda: self.native_map.reset_view())
        map_mode_row.addWidget(self.btn_map_reset, 0)
        self.btn_map_focus_latest = QPushButton("Focus Latest")
        self.btn_map_focus_latest.clicked.connect(lambda: self.native_map.focus_latest_entity())
        map_mode_row.addWidget(self.btn_map_focus_latest, 0)
        map_mode_row.addStretch(1)
        v.addLayout(map_mode_row)

        scope_row = QHBoxLayout()
        scope_row.addWidget(QLabel("Classic scope:"))
        self.cmb_classic_scope = QComboBox()
        self.cmb_classic_scope.addItems(["Latest Session", "Recent Sessions (3)", "All Data (Statewide)"])
        self.cmb_classic_scope.currentIndexChanged.connect(self._on_classic_scope_changed)
        scope_row.addWidget(self.cmb_classic_scope, 0)
        self.chk_classic_show_route = QCheckBox("Show simplified route")
        self.chk_classic_show_route.setChecked(False)
        self.chk_classic_show_route.stateChanged.connect(self._on_classic_route_toggle)
        scope_row.addWidget(self.chk_classic_show_route, 0)
        scope_row.addStretch(1)
        v.addLayout(scope_row)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Filters:"))
        self._map_filter_buttons: dict[str, QPushButton] = {}
        for filt in PixelIsometricMapWidget.FILTERS:
            b = QPushButton(filt)
            b.clicked.connect(lambda _=False, f=filt: self._set_native_map_filter(f))
            filter_row.addWidget(b)
            self._map_filter_buttons[filt] = b
        filter_row.addStretch(1)
        v.addLayout(filter_row)
        self._set_native_map_filter("ALL")

        self.chk_auto_open = QCheckBox("Auto-open latest summary in app when complete")
        self.chk_auto_open.setChecked(True)
        v.addWidget(self.chk_auto_open)

        row = QHBoxLayout()
        self.btn_open_run = QPushButton("Open Latest Run Folder")
        self.btn_open_run.clicked.connect(lambda: self._open_path(self._latest_run_dir) if self._latest_run_dir else None)
        self.btn_open_run.setEnabled(False)

        self.btn_open_latest = QPushButton("View Latest Summary In App")
        self.btn_open_latest.clicked.connect(self.open_latest_summary)
        self.btn_open_latest.setEnabled(False)

        row.addWidget(self.btn_open_run)
        row.addWidget(self.btn_open_latest)
        v.addLayout(row)

        row2 = QHBoxLayout()
        self.btn_open_latest_map = QPushButton("View Map In App")
        self.btn_open_latest_map.clicked.connect(self._open_latest_map_in_selected_mode)
        self.btn_open_latest_kml = QPushButton("Open Latest KML")
        self.btn_open_latest_kml.clicked.connect(lambda: self._open_path(self._latest_output("wardrive_map.kml")))
        self.btn_open_latest_pcap = QPushButton("View PCAP In App")
        self.btn_open_latest_pcap.clicked.connect(lambda: self._view_report_in_app(self._latest_output("pcap_summary.html"), "PCAP Evidence"))
        row2.addWidget(self.btn_open_latest_map)
        row2.addWidget(self.btn_open_latest_kml)
        row2.addWidget(self.btn_open_latest_pcap)
        v.addLayout(row2)

        row3 = QHBoxLayout()
        self.btn_open_summary_external = QPushButton("Open Summary Externally")
        self.btn_open_summary_external.clicked.connect(lambda: self._open_path(self._latest_summary or self._project_last_summary))
        self.btn_open_map_external = QPushButton("Open Map Externally")
        self.btn_open_map_external.clicked.connect(lambda: self._open_path(self._latest_output("map.html")))
        self.btn_open_pcap_external = QPushButton("Open PCAP Externally")
        self.btn_open_pcap_external.clicked.connect(lambda: self._open_path(self._latest_output("pcap_summary.html")))
        row3.addWidget(self.btn_open_summary_external)
        row3.addWidget(self.btn_open_map_external)
        row3.addWidget(self.btn_open_pcap_external)
        v.addLayout(row3)

        self.lbl_report_viewer = QLabel(
            "Embedded report viewer: WebEngine active" if WEBENGINE_AVAILABLE
            else "Embedded report viewer: WebEngine unavailable; external browser fallback is active"
        )
        self.lbl_report_viewer.setObjectName("Notes")
        v.addWidget(self.lbl_report_viewer)

        self.native_map = PixelIsometricMapWidget()
        self.native_map.set_summary_label(self.lbl_map_telemetry)
        self.native_map.set_classic_render_options(
            ClassicMapRenderOptions(show_route=False, max_sprites=2200, decimation_level=1, label_layer_enabled=True)
        )

        if WEBENGINE_AVAILABLE and QWebEngineView is not None:
            self.report_viewer = QWebEngineView()
            self.report_viewer.setMinimumHeight(430)
            self._set_report_placeholder("Select a generated report to preview it here.")
        else:
            self.report_viewer = QTextEdit()
            self.report_viewer.setReadOnly(True)
            self.report_viewer.setMinimumHeight(260)
            self.report_viewer.setPlainText(
                "PySide6 QtWebEngine is not installed in this runtime.\n\n"
                "Reports are still generated normally and can be opened externally. "
                "Install/ship PySide6-WebEngine to make Wardrive Analyzer fully self-contained for HTML report viewing."
            )

        self.map_stack = QStackedLayout()
        self.map_stack.addWidget(self.native_map)
        self.map_stack.addWidget(self.report_viewer)
        stack_host = QWidget()
        stack_host.setLayout(self.map_stack)
        v.addWidget(stack_host, 1)

        hint = QLabel(
            "Reports are generated locally inside each project run folder. The in-app viewer keeps summary/map/PCAP review inside Mission Control."
        )
        hint.setObjectName("Notes")
        v.addWidget(hint)
        self._on_classic_scope_changed(0)
        self._on_map_mode_changed(self.cmb_map_mode.currentIndex())

        return panel

    def _open_latest_map_in_selected_mode(self) -> None:
        mode = getattr(self, "cmb_map_mode", None)
        if mode is not None and mode.currentIndex() in (0, 1):
            self._marauder_open_map()
            self._load_native_map_from_latest()
            return
        self._view_report_in_app(self._latest_output("map.html"), "Map")

    def _on_map_mode_changed(self, index: int) -> None:
        if not hasattr(self, "map_stack"):
            return
        if index == 0:
            self.native_map.set_view_mode("ISOMETRIC")
            self.map_stack.setCurrentIndex(0)
            self.btn_map_rot_l.setEnabled(True)
            self.btn_map_rot_r.setEnabled(True)
            self.cmb_classic_scope.setEnabled(False)
            self.chk_classic_show_route.setEnabled(False)
            self._log("Map mode: Isometric Pixel Native", "INFO")
        elif index == 1:
            self.native_map.set_view_mode("CLASSIC")
            self.map_stack.setCurrentIndex(0)
            self.btn_map_rot_l.setEnabled(False)
            self.btn_map_rot_r.setEnabled(False)
            self.cmb_classic_scope.setEnabled(True)
            self.chk_classic_show_route.setEnabled(True)
            self._log("Map mode: Classic Pixel Native", "INFO")
        else:
            self.map_stack.setCurrentIndex(1)
            self.cmb_classic_scope.setEnabled(False)
            self.chk_classic_show_route.setEnabled(False)
            self._log("Map mode: Legacy HTML", "INFO")

    def _on_classic_scope_changed(self, index: int) -> None:
        if not hasattr(self, "native_map"):
            return
        scope: ClassicMapScope = "latest_session"
        if index == 1:
            scope = "recent_sessions"
        elif index == 2:
            scope = "all"
        self.native_map.set_classic_map_scope(scope)
        self._log(f"Classic scope: {scope}", "INFO")

    def _on_classic_route_toggle(self, state: int) -> None:
        if not hasattr(self, "native_map"):
            return
        show = bool(state)
        self.native_map.set_classic_render_options(
            ClassicMapRenderOptions(
                show_route=show,
                max_sprites=2200,
                decimation_level=1,
                label_layer_enabled=True,
            )
        )
        self._log(f"Classic route: {'on' if show else 'off'}", "INFO")

    def _set_native_map_filter(self, filt: str) -> None:
        if not hasattr(self, "native_map"):
            return
        self.native_map.set_filter(filt)
        for name, btn in getattr(self, "_map_filter_buttons", {}).items():
            btn.setEnabled(name != filt)

    def _load_native_map_from_latest(self) -> None:
        run_dir = self._latest_run_dir or self._project_last_run_dir or ""
        if hasattr(self, "native_map"):
            self.native_map.load_from_run(run_dir)

    def _build_sd_ingest_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(10)

        banner = QLabel(
            "SD ingest copies selected evidence into the project vault (Option A).\n"
            "Auto-select is allow-list based, so your old SD filenames resetting won't trick us."
        )
        banner.setObjectName("Notes")
        v.addWidget(banner)

        # Project selector (shared)
        rowp = QHBoxLayout()
        self.lbl_sd_project = QLabel("Project: (not selected)")
        self.lbl_sd_project.setObjectName("PathLabel")
        btn_project = QPushButton("Select Project Folder")
        btn_project.clicked.connect(self.select_project_folder)
        self.btn_open_last_summary = QPushButton("Open Last Summary")
        self.btn_open_last_summary.clicked.connect(self.open_last_summary)
        self.btn_open_last_summary.setEnabled(False)

        rowp.addWidget(self.lbl_sd_project, 1)
        rowp.addWidget(btn_project, 0)
        rowp.addWidget(self.btn_open_last_summary, 0)
        v.addLayout(rowp)

        # SD root
        rowsd = QHBoxLayout()
        self.lbl_sd_root = QLabel("SD folder: (not selected)")
        self.lbl_sd_root.setObjectName("PathLabel")
        btn_sd = QPushButton("Select SD Folder")
        btn_sd.clicked.connect(self.select_sd_folder)
        rowsd.addWidget(self.lbl_sd_root, 1)
        rowsd.addWidget(btn_sd, 0)
        v.addLayout(rowsd)

        # Profile filter checkboxes (single list; hide/show items by source app)
        rowf = QHBoxLayout()
        rowf.addWidget(QLabel("Show:"))
        self.chk_show_marauder = QCheckBox("Marauder")
        self.chk_show_porkchop = QCheckBox("Porkchop")
        self.chk_show_bruce = QCheckBox("Bruce")
        self.chk_show_nemo = QCheckBox("Nemo")
        self.chk_show_other = QCheckBox("Other")
        for cb in (self.chk_show_marauder, self.chk_show_porkchop, self.chk_show_bruce, self.chk_show_nemo, self.chk_show_other):
            cb.setChecked(True)
            cb.stateChanged.connect(self._apply_sd_filters)
            rowf.addWidget(cb)
        rowf.addStretch(1)
        v.addLayout(rowf)

        self.sd_list_all = self._make_check_list_widget()
        v.addWidget(self.sd_list_all, 1)

        # Controls
        rowc = QHBoxLayout()
        self.chk_sd_skip_dupes = QCheckBox("Skip duplicates (SHA-256 match)")
        self.chk_sd_skip_dupes.setChecked(True)
        rowc.addWidget(self.chk_sd_skip_dupes)

        self.btn_sd_select_rec = QPushButton("Select Recommended")
        self.btn_sd_select_rec.clicked.connect(self.sd_select_recommended)
        self.btn_sd_clear = QPushButton("Select None")
        self.btn_sd_clear.clicked.connect(self.sd_select_none)
        rowc.addWidget(self.btn_sd_select_rec)
        rowc.addWidget(self.btn_sd_clear)
        v.addLayout(rowc)

        rowi = QHBoxLayout()
        self.btn_sd_ingest = QPushButton("Attach Selected to Project")
        self.btn_sd_ingest.setObjectName("PrimaryButton")
        self.btn_sd_ingest.clicked.connect(self.sd_ingest_selected)
        rowi.addWidget(self.btn_sd_ingest)
        v.addLayout(rowi)

        rowa0 = QHBoxLayout()
        self.btn_sd_analyze_now = QPushButton("Analyze Selected Now (from SD)")
        self.btn_sd_analyze_now.setObjectName("PrimaryButton")
        self.btn_sd_analyze_now.clicked.connect(self.sd_analyze_selected_now)
        rowa0.addWidget(self.btn_sd_analyze_now)
        v.addLayout(rowa0)

        rowa = QHBoxLayout()
        self.btn_sd_analyze = QPushButton("Analyze Imported Evidence (Project)")
        self.btn_sd_analyze.clicked.connect(self.sd_analyze_project_evidence)
        rowa.addWidget(self.btn_sd_analyze)
        v.addLayout(rowa)

        self.lbl_sd_stats = QLabel("Ready.")
        self.lbl_sd_stats.setObjectName("Notes")
        v.addWidget(self.lbl_sd_stats)

        return panel

    def _build_integrations_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(10)

        self.int_tabs = QTabWidget()

        self.int_tabs.addTab(self._build_wigle_tab(), "WiGLE.net")
        self.int_tabs.addTab(self._build_wpasec_tab(), "WPA-SEC")

        v.addWidget(self.int_tabs, 1)

        note = QLabel(
            "These tabs store keys per project. Upload wiring comes next (safe-by-default).\n"
            "Operator tip: treat tokens like passwords."
        )
        note.setObjectName("Notes")
        v.addWidget(note)

        return panel

    def _build_wigle_tab(self) -> QWidget:
        w = QFrame()
        w.setObjectName("Panel")
        v = QVBoxLayout(w)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(10)

        self.wigle_name = QLineEdit()
        self.wigle_token = QLineEdit()
        self.wigle_token.setEchoMode(QLineEdit.Password)
        self.lbl_wigle_status = QLabel("Status: not loaded")
        self.lbl_wigle_status.setObjectName("Notes")

        v.addWidget(QLabel("API Name"))
        v.addWidget(self.wigle_name)
        v.addWidget(QLabel("API Token"))
        v.addWidget(self.wigle_token)
        v.addWidget(self.lbl_wigle_status)

        row = QHBoxLayout()
        btn_load = QPushButton("Load from Project")
        btn_load.clicked.connect(self._load_integrations)
        btn_save = QPushButton("Save to Project")
        btn_save.clicked.connect(self._save_integrations)
        row.addWidget(btn_load)
        row.addWidget(btn_save)
        v.addLayout(row)

        btn_export = QPushButton("Export Wigle CSV (from latest run)")
        btn_export.clicked.connect(self._export_wigle)
        v.addWidget(btn_export)

        return w

    def _export_wigle(self) -> None:
        if not self.project_dir:
            QMessageBox.warning(self, "Missing Project", "Select a Project Folder first.")
            return
        runs = discover_project_runs(self.project_dir)
        csv_path = ""
        for run in runs:
            outputs = run.get("outputs") or {}
            candidate = outputs.get("wardrive_master.csv", "")
            if candidate and os.path.exists(str(candidate)):
                csv_path = str(candidate)
                break
        if not csv_path:
            QMessageBox.information(self, "Wigle Export", "No wardrive_master.csv found. Run an analysis first.")
            return
        out_path = os.path.join(self.project_dir, "exports", "wigle", "wigle_upload.csv")
        try:
            n = export_wigle_csv(csv_path, out_path)
            self._log(f"Wigle export: {n} networks → {out_path}")
            QMessageBox.information(self, "Wigle Export", f"Exported {n} networks to:\n{out_path}")
        except Exception as e:
            QMessageBox.critical(self, "Wigle Export Error", str(e))

    def _build_wpasec_tab(self) -> QWidget:
        w = QFrame()
        w.setObjectName("Panel")
        v = QVBoxLayout(w)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(10)

        self.wpasec_key = QLineEdit()
        self.wpasec_key.setEchoMode(QLineEdit.Password)
        self.lbl_wpasec_status = QLabel("Status: not loaded")
        self.lbl_wpasec_status.setObjectName("Notes")

        v.addWidget(QLabel("WPA-SEC Key"))
        v.addWidget(self.wpasec_key)
        v.addWidget(self.lbl_wpasec_status)

        row = QHBoxLayout()
        btn_load = QPushButton("Load from Project")
        btn_load.clicked.connect(self._load_integrations)
        btn_save = QPushButton("Save to Project")
        btn_save.clicked.connect(self._save_integrations)
        row.addWidget(btn_load)
        row.addWidget(btn_save)
        v.addLayout(row)

        btn_export_list = QPushButton("Export PCAP Manifest (for WPA-sec upload)")
        btn_export_list.clicked.connect(self._export_wpasec)
        v.addWidget(btn_export_list)

        return w

    def _export_wpasec(self) -> None:
        if not self.project_dir:
            QMessageBox.warning(self, "Missing Project", "Select a Project Folder first.")
            return
        out_path = os.path.join(self.project_dir, "exports", "wpa-sec", "upload_manifest.txt")
        try:
            n = export_wpasec_list(self.project_dir, out_path)
            self._log(f"WPA-sec manifest: {n} PCAP files → {out_path}")
            QMessageBox.information(self, "WPA-sec Export", f"Listed {n} PCAP files in:\n{out_path}\n\nUpload each file at wpa-sec.stanev.org")
        except Exception as e:
            QMessageBox.critical(self, "WPA-sec Export Error", str(e))

    def _build_settings_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(12)

        title = QLabel("Settings")
        title.setObjectName("PanelTitle")
        v.addWidget(title)

        # Auto-open reports after analysis
        self.chk_setting_auto_open = QCheckBox("Auto-open run folder when analysis completes")
        self.chk_setting_auto_open.setChecked(True)
        v.addWidget(self.chk_setting_auto_open)

        # Preferred background mode
        bg_row = QHBoxLayout()
        bg_row.addWidget(QLabel("Background mode:"))
        self.cmb_bg_mode = QComboBox()
        self.cmb_bg_mode.addItems(["random", "grid_horizon", "circuit_board", "matrix_rain", "nebula_noise"])
        self.cmb_bg_mode.currentIndexChanged.connect(self._regen_bg)
        bg_row.addWidget(self.cmb_bg_mode)
        v.addLayout(bg_row)

        # PCAP parallel workers
        w_row = QHBoxLayout()
        w_row.addWidget(QLabel("PCAP parallel workers (1–8):"))
        self.cmb_pcap_workers = QComboBox()
        for n in range(1, 9):
            self.cmb_pcap_workers.addItem(str(n))
        self.cmb_pcap_workers.setCurrentIndex(3)  # default 4
        w_row.addWidget(self.cmb_pcap_workers)
        v.addLayout(w_row)

        ai_title = QLabel("AI Buddy")
        ai_title.setObjectName("PanelTitle")
        v.addWidget(ai_title)

        self.chk_buddy_ai_enabled = QCheckBox("Enable model-backed Buddy responses")
        self.chk_buddy_ai_enabled.setChecked(False)
        v.addWidget(self.chk_buddy_ai_enabled)

        self.chk_buddy_sanitize = QCheckBox("Send sanitized summaries only")
        self.chk_buddy_sanitize.setChecked(True)
        self.chk_buddy_sanitize.setEnabled(False)
        v.addWidget(self.chk_buddy_sanitize)

        ai_base_row = QHBoxLayout()
        ai_base_row.addWidget(QLabel("OpenAI-compatible base URL:"))
        self.txt_buddy_base_url = QLineEdit(DEFAULT_BASE_URL)
        ai_base_row.addWidget(self.txt_buddy_base_url)
        v.addLayout(ai_base_row)

        ai_model_row = QHBoxLayout()
        ai_model_row.addWidget(QLabel("Model:"))
        self.txt_buddy_model = QLineEdit(DEFAULT_MODEL)
        ai_model_row.addWidget(self.txt_buddy_model)
        v.addLayout(ai_model_row)

        self.txt_buddy_api_token = QLineEdit()
        self.txt_buddy_api_token.setEchoMode(QLineEdit.Password)
        self.txt_buddy_api_token.setPlaceholderText("API token (keyring preferred; local project fallback)")
        v.addWidget(self.txt_buddy_api_token)

        self.lbl_buddy_ai_status = QLabel("Buddy AI: offline/local mode")
        self.lbl_buddy_ai_status.setObjectName("Notes")
        v.addWidget(self.lbl_buddy_ai_status)

        dropbox_title = QLabel("Dropbox Sync")
        dropbox_title.setObjectName("PanelTitle")
        v.addWidget(dropbox_title)

        self.txt_dropbox_token = QLineEdit()
        self.txt_dropbox_token.setEchoMode(QLineEdit.Password)
        self.txt_dropbox_token.setPlaceholderText("Dropbox access token")
        v.addWidget(self.txt_dropbox_token)

        dropbox_path_row = QHBoxLayout()
        dropbox_path_row.addWidget(QLabel("Dropbox folder path:"))
        self.txt_dropbox_folder = QLineEdit("/WardriveAnalyzerSync")
        dropbox_path_row.addWidget(self.txt_dropbox_folder)
        v.addLayout(dropbox_path_row)

        self.lbl_dropbox_help = QLabel("Setup: create a Dropbox app token and paste it here. Desktop uploads latest_project.zip; Android downloads it.")
        self.lbl_dropbox_help.setObjectName("Notes")
        v.addWidget(self.lbl_dropbox_help)

        self.lbl_dropbox_steps = QLabel(
            "Token setup:\n"
            "1) Open Dropbox App Console\n"
            "2) Create app -> Scoped access -> Full Dropbox (or App folder)\n"
            "3) Permissions: files.content.write, files.content.read\n"
            "4) Generate access token and paste above\n"
        )
        self.lbl_dropbox_steps.setObjectName("Notes")
        v.addWidget(self.lbl_dropbox_steps)

        dropbox_links_row = QHBoxLayout()
        btn_dropbox_console = QPushButton("Open Dropbox App Console")
        btn_dropbox_console.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl("https://www.dropbox.com/developers/apps"))
        )
        btn_dropbox_oauth_docs = QPushButton("Open Dropbox OAuth Docs")
        btn_dropbox_oauth_docs.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl("https://www.dropbox.com/developers/documentation/http/documentation#oauth2-token"))
        )
        btn_dropbox_validate = QPushButton("Validate Dropbox Token")
        btn_dropbox_validate.clicked.connect(self.validate_dropbox_token)
        dropbox_links_row.addWidget(btn_dropbox_console)
        dropbox_links_row.addWidget(btn_dropbox_oauth_docs)
        dropbox_links_row.addWidget(btn_dropbox_validate)
        v.addLayout(dropbox_links_row)

        btn_save = QPushButton("Save Settings")
        btn_save.clicked.connect(self._save_settings)
        btn_load = QPushButton("Load Settings")
        btn_load.clicked.connect(self._load_settings)
        row = QHBoxLayout()
        row.addWidget(btn_save)
        row.addWidget(btn_load)
        v.addLayout(row)

        # First-run onboarding checklist
        v.addWidget(QLabel(""))
        checklist_title = QLabel("First-Run Checklist")
        checklist_title.setObjectName("PanelTitle")
        v.addWidget(checklist_title)

        self.lbl_check_project = QLabel("○  Select a Project Folder (Dashboard → Select Project)")
        self.lbl_check_evidence = QLabel("○  Import evidence from SD card (SD Ingest tab)")
        self.lbl_check_analyze = QLabel("○  Run analysis (Dashboard → Analyze Project Evidence)")
        self.lbl_check_map = QLabel("○  Open Map/Reports to see your results")
        self.lbl_check_tshark = QLabel("○  tshark: checking…")

        for lbl in (self.lbl_check_project, self.lbl_check_evidence,
                    self.lbl_check_analyze, self.lbl_check_map, self.lbl_check_tshark):
            lbl.setObjectName("Notes")
            v.addWidget(lbl)

        v.addStretch(1)
        self._update_onboarding_checklist()
        return panel

    def _update_onboarding_checklist(self) -> None:
        def mark(lbl: QLabel, done: bool, text: str) -> None:
            lbl.setText(("✅" if done else "○") + "  " + text)

        has_project = bool(getattr(self, "project_dir", ""))
        mark(self.lbl_check_project, has_project, "Select a Project Folder (Dashboard → Select Project)")

        has_evidence = False
        if has_project:
            try:
                stats = project_db_stats(self.project_dir)
                has_evidence = stats.get("evidence", 0) > 0
            except Exception:
                pass
        mark(self.lbl_check_evidence, has_evidence, "Import evidence from SD card (SD Ingest tab)")

        has_runs = False
        if has_project:
            try:
                has_runs = len(discover_project_runs(self.project_dir)) > 0
            except Exception:
                pass
        mark(self.lbl_check_analyze, has_runs, "Run analysis (Dashboard → Analyze Project Evidence)")
        mark(self.lbl_check_map, has_runs, "Open Map/Reports to see your results")

        tshark_ok = self._check_tool_ready("tshark")
        dpkt_ok = True
        try:
            import dpkt  # noqa: F401
        except ImportError:
            dpkt_ok = False

        if dpkt_ok:
            self.lbl_check_tshark.setText("✅  dpkt installed — PCAP parsing works offline (no tshark needed)")
        elif tshark_ok:
            self.lbl_check_tshark.setText("✅  tshark found in PATH — PCAP parsing active")
        else:
            self.lbl_check_tshark.setText(
                "⚠  dpkt not installed and tshark not in PATH. "
                "Install dpkt: pip install dpkt"
            )

    def _save_settings(self) -> None:
        if not self.project_dir:
            QMessageBox.warning(self, "Missing Project", "Select a Project Folder first.")
            return
        db = os.path.join(self.project_dir, "project.db")
        try:
            set_setting(db, "auto_open_run", "1" if self.chk_setting_auto_open.isChecked() else "0")
            set_setting(db, "bg_mode", self.cmb_bg_mode.currentText())
            set_setting(db, "pcap_workers", self.cmb_pcap_workers.currentText())
            set_setting(db, "buddy_ai_enabled", "1" if self.chk_buddy_ai_enabled.isChecked() else "0")
            set_setting(db, "buddy_ai_sanitize", "1" if self.chk_buddy_sanitize.isChecked() else "0")
            set_setting(db, "buddy_ai_base_url", self.txt_buddy_base_url.text().strip() or DEFAULT_BASE_URL)
            set_setting(db, "buddy_ai_model", self.txt_buddy_model.text().strip() or DEFAULT_MODEL)
            set_setting(db, "dropbox_token", self._sanitize_dropbox_token(self.txt_dropbox_token.text()))
            set_setting(db, "dropbox_folder", self.txt_dropbox_folder.text().strip() or "/WardriveAnalyzerSync")
            token = self.txt_buddy_api_token.text().strip()
            if token and save_token_to_keyring(self.project_dir, token):
                set_setting(db, "buddy_ai_token", "")
                set_setting(db, "buddy_ai_token_store", "keyring")
            else:
                set_setting(db, "buddy_ai_token", token)
                set_setting(db, "buddy_ai_token_store", "project_db" if token else "")
            self._refresh_buddy_ai_status()
            self._log("Settings saved.")
        except Exception as e:
            QMessageBox.critical(self, "Settings Error", str(e))

    def _load_settings(self) -> None:
        if not self.project_dir:
            return
        db = os.path.join(self.project_dir, "project.db")
        if not os.path.exists(db):
            return
        try:
            auto_open = get_setting(db, "auto_open_run", "1")
            self.chk_setting_auto_open.setChecked(auto_open == "1")
            bg = get_setting(db, "bg_mode", "")
            if bg:
                idx = self.cmb_bg_mode.findText(bg)
                if idx >= 0:
                    self.cmb_bg_mode.setCurrentIndex(idx)
            workers = get_setting(db, "pcap_workers", "4")
            idx = self.cmb_pcap_workers.findText(workers)
            if idx >= 0:
                self.cmb_pcap_workers.setCurrentIndex(idx)
            self.chk_buddy_ai_enabled.setChecked(get_setting(db, "buddy_ai_enabled", "0") == "1")
            self.chk_buddy_sanitize.setChecked(True)
            self.txt_buddy_base_url.setText(get_setting(db, "buddy_ai_base_url", DEFAULT_BASE_URL) or DEFAULT_BASE_URL)
            self.txt_buddy_model.setText(get_setting(db, "buddy_ai_model", DEFAULT_MODEL) or DEFAULT_MODEL)
            self.txt_dropbox_token.setText(get_setting(db, "dropbox_token", ""))
            self.txt_dropbox_folder.setText(get_setting(db, "dropbox_folder", "/WardriveAnalyzerSync") or "/WardriveAnalyzerSync")
            token_store = get_setting(db, "buddy_ai_token_store", "")
            token = load_token_from_keyring(self.project_dir) if token_store == "keyring" else ""
            if not token:
                token = get_setting(db, "buddy_ai_token", "")
            self.txt_buddy_api_token.setText(token)
            self._refresh_buddy_ai_status()
            self._log("Settings loaded.")
        except Exception:
            pass

    def _sanitize_dropbox_token(self, raw: str) -> str:
        text = (raw or "").strip()
        if not text:
            return ""
        if text.lower().startswith("bearer "):
            text = text[7:].strip()
        m = re.search(r"(sl\.[A-Za-z0-9._-]+)", text)
        if m:
            return m.group(1)
        return text[:512]

    def _validate_dropbox_token(self) -> tuple[bool, str]:
        token = self._sanitize_dropbox_token(self.txt_dropbox_token.text() if hasattr(self, "txt_dropbox_token") else "")
        if not token:
            return False, "Missing token."
        req = urllib.request.Request(
            "https://api.dropboxapi.com/2/users/get_current_account",
            data=b"null",
            method="POST",
        )
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                if resp.status in (200, 201):
                    return True, "Token is valid."
                return False, f"Unexpected status: {resp.status}"
        except urllib.error.HTTPError as e:
            try:
                detail = e.read().decode("utf-8", errors="ignore")
            except Exception:
                detail = str(e)
            return False, f"HTTP {e.code}: {detail}"
        except Exception as e:
            return False, str(e)

    def validate_dropbox_token(self) -> None:
        ok, msg = self._validate_dropbox_token()
        if ok:
            QMessageBox.information(self, "Dropbox Token", msg)
        else:
            QMessageBox.warning(self, "Dropbox Token Invalid", msg)

    def sync_to_dropbox(self) -> None:
        if not self.project_dir:
            QMessageBox.warning(self, "Missing Project", "Select a Project Folder first.")
            return
        token = self.txt_dropbox_token.text().strip() if hasattr(self, "txt_dropbox_token") else ""
        folder = self.txt_dropbox_folder.text().strip() if hasattr(self, "txt_dropbox_folder") else "/WardriveAnalyzerSync"
        if not token:
            QMessageBox.information(
                self,
                "Dropbox Setup",
                "Open Settings -> Dropbox Sync, paste your Dropbox access token, then click Save Settings."
            )
            self.tabs.setCurrentWidget(self.tab_settings)
            return
        try:
            self._log("Starting Dropbox sync for current project...")
            result = sync_project_to_dropbox(self.project_dir, token, folder)
            self._log(f"Dropbox sync complete: {result.get('remote_latest')}")
            QMessageBox.information(
                self,
                "Dropbox Sync Complete",
                f"Uploaded project snapshot to Dropbox.\n\nFolder: {result.get('remote_folder')}\nLatest file: {result.get('remote_latest')}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Dropbox Sync Error", str(e))

    def install_android_app(self) -> None:
        adb_cmd = self._resolve_adb_cmd()
        if not adb_cmd:
            QMessageBox.critical(
                self,
                "ADB Not Found",
                "Could not find adb.exe. Install Android Platform Tools or set ANDROID_SDK_ROOT."
            )
            return

        apk_path = self._resolve_android_apk_path()
        if not apk_path:
            QMessageBox.critical(
                self,
                "APK Not Found",
                "Could not find app-debug.apk. Build the Android app first."
            )
            return

        try:
            devices_proc = subprocess.run(
                [adb_cmd, "devices"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            lines = [ln.strip() for ln in devices_proc.stdout.splitlines() if ln.strip() and not ln.startswith("List of devices")]
            online = [ln.split()[0] for ln in lines if ln.endswith("\tdevice")]
            if not online:
                QMessageBox.warning(
                    self,
                    "No Authorized Device",
                    "No authorized Android device detected. Connect phone, enable USB debugging, and accept RSA prompt."
                )
                return

            serial = online[0]
            install_proc = subprocess.run(
                [adb_cmd, "-s", serial, "install", "-r", apk_path],
                capture_output=True,
                text=True,
                timeout=180,
            )
            out = (install_proc.stdout or "") + "\n" + (install_proc.stderr or "")
            if install_proc.returncode != 0 or "Success" not in out:
                raise RuntimeError(out.strip() or "adb install failed")

            self._log(f"Android install success on {serial}: {apk_path}")
            QMessageBox.information(
                self,
                "Install Complete",
                f"Installed Android app on device {serial}.\n\nAPK: {apk_path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Install Android App Error", str(e))

    def _resolve_adb_cmd(self) -> str | None:
        adb_candidates = [
            os.path.join(os.environ.get("ANDROID_SDK_ROOT", ""), "platform-tools", "adb.exe"),
            r"C:\Users\hardc\AppData\Local\Android\Sdk\platform-tools\adb.exe",
            "adb",
        ]
        for candidate in adb_candidates:
            if candidate == "adb" or os.path.exists(candidate):
                return candidate
        return None

    def _resolve_android_apk_path(self) -> str | None:
        apk_candidates = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Wardrive-Analyzer-Android", "app", "build", "outputs", "apk", "debug", "app-debug.apk"),
            r"F:\Ai\WardriveAPP\Wardrive-Analyzer-Android\app\build\outputs\apk\debug\app-debug.apk",
        ]
        for candidate in apk_candidates:
            normalized = os.path.abspath(candidate)
            if os.path.exists(normalized):
                return normalized
        return None

    def _list_adb_devices(self, adb_cmd: str) -> list[dict[str, str]]:
        proc = subprocess.run([adb_cmd, "devices", "-l"], capture_output=True, text=True, timeout=20)
        rows: list[dict[str, str]] = []
        for raw in proc.stdout.splitlines():
            line = raw.strip()
            if not line or line.startswith("List of devices"):
                continue
            parts = line.split()
            serial = parts[0]
            state = parts[1] if len(parts) > 1 else "unknown"
            transport = "Wi-Fi" if ":" in serial else "USB"
            model = ""
            for token in parts[2:]:
                if token.startswith("model:"):
                    model = token.split(":", 1)[1].replace("_", " ")
                    break
            rows.append({
                "serial": serial,
                "state": state,
                "transport": transport,
                "model": model,
            })
        return rows

    def _adb_wifi_connect_for_serial(self, adb_cmd: str, serial: str) -> str:
        ip_proc = subprocess.run(
            [adb_cmd, "-s", serial, "shell", "ip", "-f", "inet", "addr", "show", "wlan0"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", ip_proc.stdout or "")
        if not m:
            raise RuntimeError(f"Could not read Wi-Fi IP from device {serial}.")
        ip = m.group(1)
        subprocess.run([adb_cmd, "-s", serial, "tcpip", "5555"], capture_output=True, text=True, timeout=20)
        conn = subprocess.run([adb_cmd, "connect", f"{ip}:5555"], capture_output=True, text=True, timeout=20)
        out = ((conn.stdout or "") + "\n" + (conn.stderr or "")).strip()
        if "connected to" not in out and "already connected to" not in out:
            raise RuntimeError(out or f"Failed to connect to {ip}:5555")
        return f"{ip}:5555"

    def open_android_devices_dialog(self) -> None:
        adb_cmd = self._resolve_adb_cmd()
        if not adb_cmd:
            QMessageBox.critical(self, "ADB Not Found", "Could not find adb.exe. Install Android Platform Tools or set ANDROID_SDK_ROOT.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Android Devices")
        dlg.resize(820, 420)
        layout = QVBoxLayout(dlg)

        lbl = QLabel("Connected Android devices (USB and Wi-Fi).")
        layout.addWidget(lbl)

        tbl = QTableWidget(0, 4)
        tbl.setHorizontalHeaderLabels(["Serial / IP", "Transport", "State", "Model"])
        tbl.setSelectionBehavior(QTableWidget.SelectRows)
        tbl.setSelectionMode(QTableWidget.SingleSelection)
        tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(tbl, 1)

        def selected_serial() -> str | None:
            r = tbl.currentRow()
            if r < 0:
                return None
            item = tbl.item(r, 0)
            return item.text().strip() if item else None

        def refresh_table() -> None:
            rows = self._list_adb_devices(adb_cmd)
            tbl.setRowCount(0)
            for d in rows:
                r = tbl.rowCount()
                tbl.insertRow(r)
                tbl.setItem(r, 0, QTableWidgetItem(d["serial"]))
                tbl.setItem(r, 1, QTableWidgetItem(d["transport"]))
                tbl.setItem(r, 2, QTableWidgetItem(d["state"]))
                tbl.setItem(r, 3, QTableWidgetItem(d["model"]))

        button_row = QHBoxLayout()
        btn_refresh = QPushButton("Refresh")
        btn_wifi = QPushButton("Connect Wi-Fi ADB")
        btn_install = QPushButton("Install APK")
        btn_launch = QPushButton("Launch App")
        btn_push_dropbox = QPushButton("Send Dropbox Config")
        btn_logcat = QPushButton("View Logcat (Wardrive)")
        btn_close = QPushButton("Close")
        button_row.addWidget(btn_refresh)
        button_row.addWidget(btn_wifi)
        button_row.addWidget(btn_install)
        button_row.addWidget(btn_launch)
        button_row.addWidget(btn_push_dropbox)
        button_row.addWidget(btn_logcat)
        button_row.addStretch(1)
        button_row.addWidget(btn_close)
        layout.addLayout(button_row)

        def do_install() -> None:
            serial = selected_serial()
            if not serial:
                QMessageBox.information(dlg, "Select Device", "Select a device row first.")
                return
            apk_path = self._resolve_android_apk_path()
            if not apk_path:
                QMessageBox.critical(dlg, "APK Not Found", "Could not find app-debug.apk. Build the Android app first.")
                return
            proc = subprocess.run([adb_cmd, "-s", serial, "install", "-r", apk_path], capture_output=True, text=True, timeout=180)
            out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            if proc.returncode != 0 or "Success" not in out:
                QMessageBox.critical(dlg, "Install Failed", out or "adb install failed")
                return
            self._log(f"Android install success on {serial}: {apk_path}")
            QMessageBox.information(dlg, "Install Complete", f"Installed app on {serial}.")

        def do_launch() -> None:
            serial = selected_serial()
            if not serial:
                QMessageBox.information(dlg, "Select Device", "Select a device row first.")
                return
            subprocess.run(
                [adb_cmd, "-s", serial, "shell", "monkey", "-p", "com.wardrive.analyzer.android", "-c", "android.intent.category.LAUNCHER", "1"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            QMessageBox.information(dlg, "Launch Sent", f"Launch command sent to {serial}.")

        def do_wifi() -> None:
            serial = selected_serial()
            if not serial:
                QMessageBox.information(dlg, "Select Device", "Select a device row first.")
                return
            if ":" in serial:
                QMessageBox.information(dlg, "Already Wi-Fi", f"{serial} is already a Wi-Fi ADB endpoint.")
                return
            try:
                wifi_serial = self._adb_wifi_connect_for_serial(adb_cmd, serial)
                refresh_table()
                QMessageBox.information(dlg, "Wi-Fi Connected", f"Connected: {wifi_serial}")
            except Exception as e:
                QMessageBox.critical(dlg, "Wi-Fi ADB Error", str(e))

        def do_logcat() -> None:
            serial = selected_serial()
            if not serial:
                QMessageBox.information(dlg, "Select Device", "Select a device row first.")
                return
            log_dlg = QDialog(dlg)
            log_dlg.setWindowTitle(f"Wardrive Logcat - {serial}")
            log_dlg.resize(980, 560)
            log_layout = QVBoxLayout(log_dlg)
            txt = QPlainTextEdit()
            txt.setReadOnly(True)
            log_layout.addWidget(txt, 1)
            btns = QHBoxLayout()
            btn_refresh_logs = QPushButton("Refresh Logs")
            btn_clear_logs = QPushButton("Clear Device Logcat")
            btn_close_logs = QPushButton("Close")
            btns.addWidget(btn_refresh_logs)
            btns.addWidget(btn_clear_logs)
            btns.addStretch(1)
            btns.addWidget(btn_close_logs)
            log_layout.addLayout(btns)

            def refresh_logs() -> None:
                proc = subprocess.run(
                    [adb_cmd, "-s", serial, "logcat", "-d", "-t", "400"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                raw = (proc.stdout or "") + "\n" + (proc.stderr or "")
                lines = [ln for ln in raw.splitlines() if "com.wardrive.analyzer.android" in ln or "Wardrive" in ln or "AndroidRuntime" in ln]
                txt.setPlainText("\n".join(lines) if lines else "No Wardrive-specific log lines found in recent buffer.")

            def clear_logs() -> None:
                subprocess.run(
                    [adb_cmd, "-s", serial, "logcat", "-c"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                txt.setPlainText("Device logcat cleared.")

            btn_refresh_logs.clicked.connect(refresh_logs)
            btn_clear_logs.clicked.connect(clear_logs)
            btn_close_logs.clicked.connect(log_dlg.accept)
            refresh_logs()
            log_dlg.exec()

        def do_push_dropbox_config() -> None:
            serial = selected_serial()
            if not serial:
                QMessageBox.information(dlg, "Select Device", "Select a device row first.")
                return
            token = self._sanitize_dropbox_token(self.txt_dropbox_token.text() if hasattr(self, "txt_dropbox_token") else "")
            folder = self.txt_dropbox_folder.text().strip() if hasattr(self, "txt_dropbox_folder") else "/WardriveAnalyzerSync"
            if not token:
                QMessageBox.warning(dlg, "Missing Token", "Dropbox token is empty. Set it in Settings first.")
                return
            if not folder:
                folder = "/WardriveAnalyzerSync"
            proc = subprocess.run(
                [
                    adb_cmd, "-s", serial, "shell", "am", "start",
                    "-n", "com.wardrive.analyzer.android/.MainActivity",
                    "--ez", "dropbox_apply", "true",
                    "--es", "dropbox_token", token,
                    "--es", "dropbox_folder", folder,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            if proc.returncode != 0:
                QMessageBox.critical(dlg, "Push Config Failed", out or "Failed to send config to Android app.")
                return
            self._log(f"Pushed Dropbox config to Android device {serial}.")
            QMessageBox.information(dlg, "Config Sent", f"Dropbox config sent to {serial}.")

        btn_refresh.clicked.connect(refresh_table)
        btn_wifi.clicked.connect(do_wifi)
        btn_install.clicked.connect(do_install)
        btn_launch.clicked.connect(do_launch)
        btn_push_dropbox.clicked.connect(do_push_dropbox_config)
        btn_logcat.clicked.connect(do_logcat)
        btn_close.clicked.connect(dlg.accept)

        refresh_table()
        dlg.exec()

    def _build_footer(self) -> QWidget:
        frame = QFrame()
        frame.setObjectName("Footer")
        h = QHBoxLayout(frame)
        h.setContentsMargins(12, 10, 12, 10)
        h.setSpacing(10)

        self.progress = QProgressBar()
        self.progress.setObjectName("Progress")
        self.progress.setTextVisible(True)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)

        self.lbl_timer = QLabel("Elapsed: 00:00")
        self.lbl_timer.setObjectName("TimerLabel")

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel_not_supported)

        h.addWidget(self.progress, 3)
        h.addWidget(self.lbl_timer, 1)
        h.addWidget(self.btn_cancel, 0)

        self._ui_timer = QTimer(self)
        self._ui_timer.setInterval(200)
        self._ui_timer.timeout.connect(self._tick_elapsed)

        return frame

    def _build_console_dock(self) -> QFrame:
        """Always-visible bottom console (smaller + lower opacity)."""
        frame = QFrame()
        frame.setObjectName("ConsoleDockFrame")
        box = QVBoxLayout(frame)
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(6)

        header = QLabel("Console (live)")
        header.setObjectName("ConsoleDockHeader")
        box.addWidget(header)

        self.console_dock = QPlainTextEdit()
        self.console_dock.setReadOnly(True)
        self.console_dock.setMaximumBlockCount(5000)
        self.console_dock.setObjectName("ConsoleDock")
        self.console_dock.setMinimumHeight(120)
        self.console_dock.setMaximumHeight(180)
        box.addWidget(self.console_dock)

        # Glass console styling (keep background visible behind)
        frame.setStyleSheet(
            "QFrame#ConsoleDockFrame{background-color: rgba(0,0,0,70); border: 1px solid rgba(0,255,220,80); border-radius: 14px;}"
            "QLabel#ConsoleDockHeader{color: rgba(180,255,245,220); font-weight: 600;}"
            "QPlainTextEdit#ConsoleDock{background-color: rgba(0,0,0,110); color: rgba(200,255,250,230); border: 1px solid rgba(0,255,220,90); border-radius: 12px;}"
        )

        return frame

    def _make_check_list_widget(self) -> QListWidget:
        lw = QListWidget()
        lw.setSelectionMode(QListWidget.ExtendedSelection)
        return lw

    def _set_table_cell(self, table: QTableWidget, row: int, col: int, value: object, data: object | None = None) -> None:
        item = QTableWidgetItem("" if value is None else str(value))
        if data is not None:
            item.setData(Qt.UserRole, data)
        table.setItem(row, col, item)

    def _fill_table(self, table: QTableWidget, rows: list[list[object]]) -> None:
        table.setRowCount(0)
        for values in rows:
            r = table.rowCount()
            table.insertRow(r)
            for c, value in enumerate(values):
                self._set_table_cell(table, r, c, value)
        try:
            table.resizeRowsToContents()
        except Exception:
            pass

    def _check_tool_ready(self, name: str) -> bool:
        try:
            return subprocess.run([name, "--version"], capture_output=True, text=True, timeout=3).returncode == 0
        except Exception:
            return False

    def _new_job(self, job_type: str, detail: str = "") -> int:
        job_id = len(self._jobs) + 1
        self._jobs.append(
            {
                "id": job_id,
                "type": job_type,
                "status": "Running",
                "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ended": "",
                "progress": detail,
                "result": "",
            }
        )
        self._active_job_id = job_id
        self.refresh_jobs_table()
        return job_id

    def _update_job(self, job_id: int | None, **updates) -> None:
        if not job_id:
            return
        for job in self._jobs:
            if job.get("id") == job_id:
                job.update(updates)
                break
        self.refresh_jobs_table()

    def refresh_jobs_table(self) -> None:
        table = getattr(self, "tbl_jobs", None)
        if table is None:
            return
        rows = []
        for job in reversed(self._jobs):
            rows.append([
                job.get("id", ""),
                job.get("type", ""),
                job.get("status", ""),
                job.get("started", ""),
                job.get("ended", ""),
                job.get("progress", ""),
                job.get("result", ""),
            ])
        self._fill_table(table, rows)

    def refresh_mission_control(self) -> None:
        """Refresh all Mission Control read-only views from the project vault."""
        if not getattr(self, "project_dir", ""):
            for attr, text in (
                ("lbl_dash_project", "Project: not selected"),
                ("lbl_dash_evidence", "Evidence: 0"),
                ("lbl_dash_imports", "Imports: 0"),
                ("lbl_dash_runs", "Runs: 0"),
                ("lbl_dash_latest_import", "Latest import: none"),
                ("lbl_dash_latest_run", "Latest run: none"),
                ("lbl_evidence_summary", "No project selected."),
            ):
                w = getattr(self, attr, None)
                if w is not None:
                    w.setText(text)
            for attr in ("tbl_dash_sources", "tbl_evidence", "tbl_runs", "tbl_compare"):
                t = getattr(self, attr, None)
                if t is not None:
                    t.setRowCount(0)
            return

        project = self.project_dir
        try:
            summary = evidence_summary(project)
            imports = list_import_history(project)
            runs = discover_project_runs(project)
        except Exception as e:
            self._log(f"Mission Control refresh failed: {e}")
            return

        self.lbl_dash_project.setText(f"Project: {project}")
        self.lbl_dash_evidence.setText(f"Evidence: {summary.get('total', 0)}")
        self.lbl_dash_imports.setText(f"Imports: {len(imports)}")
        self.lbl_dash_runs.setText(f"Runs: {len(runs)}")
        self.lbl_dash_tools.setText(f"Tools: tshark {'ready' if self._check_tool_ready('tshark') else 'not found'}")

        latest_import = summary.get("latest_import") or {}
        if isinstance(latest_import, dict) and latest_import:
            self.lbl_dash_latest_import.setText(
                f"Latest import: {latest_import.get('created_utc', '')}  {latest_import.get('label', '')}  {latest_import.get('source_path', '')}"
            )
        else:
            self.lbl_dash_latest_import.setText("Latest import: none")

        if runs:
            latest = runs[0]
            expected_count = len((latest.get("outputs") or {})) or 9
            self._project_last_run_dir = str(latest.get("run_dir") or "")
            outputs = latest.get("outputs") or {}
            if isinstance(outputs, dict):
                self._project_last_summary = str(outputs.get("summary.html") or "") or None
                self._project_last_map = str(outputs.get("map.html") or "") or None
                self._project_last_pcap_summary = str(outputs.get("pcap_summary.html") or "") or None
            self.lbl_dash_latest_run.setText(
                f"Latest run: {latest.get('run_id', '')}  outputs {latest.get('present_count', 0)}/{expected_count}"
            )
            self.lbl_latest.setText(f"Latest run: {self._project_last_run_dir}")
            self.btn_open_latest.setEnabled(bool(self._project_last_summary))
            self.btn_open_run.setEnabled(bool(self._project_last_run_dir))
            self._load_native_map_from_latest()
            try:
                self.btn_open_last_summary.setEnabled(bool(self._project_last_summary))
            except Exception:
                pass
        else:
            self.lbl_dash_latest_run.setText("Latest run: none")
            self._load_native_map_from_latest()

        by_source = summary.get("by_source") or {}
        source_rows = [[k, v] for k, v in sorted(dict(by_source).items())]
        self._fill_table(self.tbl_dash_sources, source_rows)

        try:
            evidence = list_project_evidence_detailed(project)
        except Exception:
            evidence = []
        self.lbl_evidence_summary.setText(
            f"{len(evidence)} file(s), {summary.get('duplicates', 0)} duplicate record(s)"
        )
        self.tbl_evidence.setRowCount(0)
        for row in evidence:
            r = self.tbl_evidence.rowCount()
            self.tbl_evidence.insertRow(r)
            vals = [
                row.get("source_app", ""),
                row.get("kind", ""),
                row.get("rel_path", ""),
                row.get("size", ""),
                "yes" if int(row.get("is_duplicate", 0) or 0) else "no",
                row.get("sha256", ""),
                row.get("created_utc", ""),
            ]
            for c, val in enumerate(vals):
                self._set_table_cell(self.tbl_evidence, r, c, val, row.get("stored_path") if c == 2 else None)

        self.tbl_runs.setRowCount(0)
        for run in runs:
            expected_count = len((run.get("outputs") or {})) or 9
            r = self.tbl_runs.rowCount()
            self.tbl_runs.insertRow(r)
            missing = run.get("missing") or []
            vals = [
                run.get("run_id", ""),
                run.get("modified", ""),
                f"{run.get('present_count', 0)}/{expected_count}",
                ", ".join(missing[:3]) + (" ..." if len(missing) > 3 else ""),
                run.get("run_dir", ""),
            ]
            for c, val in enumerate(vals):
                self._set_table_cell(self.tbl_runs, r, c, val, run.get("run_dir") if c == 4 else None)
        self._update_marauder_assistant_hint()

    def _selected_run_dir(self) -> str:
        table = getattr(self, "tbl_runs", None)
        if table is None or table.currentRow() < 0:
            return ""
        item = table.item(table.currentRow(), 4)
        return item.text() if item else ""

    def open_selected_run(self) -> None:
        p = self._selected_run_dir()
        if not p:
            QMessageBox.information(self, "Run History", "Select a run first.")
            return
        self._open_path(p)

    def open_any_latest_summary(self) -> None:
        p = self._latest_summary or self._project_last_summary
        if p and os.path.exists(p):
            self._view_report_in_app(p, "Summary")
            return
        QMessageBox.information(self, "Latest Summary", "No summary.html found yet.")

    def _latest_output(self, filename: str) -> str:
        candidates: list[str] = []
        if self._latest_run_dir:
            candidates.append(os.path.join(self._latest_run_dir, filename))
        if self.project_dir:
            runs = discover_project_runs(self.project_dir)
            for run in runs:
                outputs = run.get("outputs") or {}
                if isinstance(outputs, dict) and outputs.get(filename):
                    candidates.append(str(outputs.get(filename)))
        for p in candidates:
            if p and os.path.exists(p):
                return p
        QMessageBox.information(self, "Output", f"No {filename} found yet.")
        return ""

    def compare_latest_runs(self) -> None:
        if not self.project_dir:
            QMessageBox.warning(self, "Missing Project", "Select a Project Folder first.")
            return
        runs = discover_project_runs(self.project_dir)
        usable = []
        for run in runs:
            outputs = run.get("outputs") or {}
            if isinstance(outputs, dict) and outputs.get("wardrive_master.csv"):
                usable.append(run)
        if len(usable) < 2:
            QMessageBox.information(self, "Compare Runs", "At least two runs with wardrive_master.csv are required.")
            return
        newest, previous = usable[0], usable[1]
        newest_csv = (newest.get("outputs") or {}).get("wardrive_master.csv")
        previous_csv = (previous.get("outputs") or {}).get("wardrive_master.csv")
        diff = compare_run_masters(str(newest_csv), str(previous_csv))
        rows = [
            ["Newest run", newest.get("run_id", ""), str(newest_csv)],
            ["Previous run", previous.get("run_id", ""), str(previous_csv)],
            ["BSSID count", diff.get("new_total", 0), f"previous {diff.get('old_total', 0)}"],
            ["New networks", diff.get("added_count", 0), ", ".join(list(diff.get("added", []))[:8])],
            ["Missing networks", diff.get("missing_count", 0), ", ".join(list(diff.get("missing", []))[:8])],
            ["Changed networks", diff.get("changed_count", 0), "; ".join([f"{r.get('MAC')} {r.get('fields')}" for r in list(diff.get("changed", []))[:5]])],
        ]
        self._fill_table(self.tbl_compare, rows)
        self._log(
            f"Run comparison: new={diff.get('added_count', 0)} missing={diff.get('missing_count', 0)} changed={diff.get('changed_count', 0)}"
        )

    # -----------------------------
    # Buddy companion
    # -----------------------------
    def _set_buddy_state(self, state: MascotState) -> None:
        try:
            self.mascot.set_state(state)
            self._tick_buddy()
        except Exception:
            pass

    def _marauder_open_map(self) -> None:
        try:
            self.tabs.setCurrentWidget(self.tab_results)
            if hasattr(self, "cmb_map_mode"):
                self.cmb_map_mode.setCurrentIndex(0)
        except Exception:
            pass
        self._buddy_say("Marauder: Isometric grid online. Use filters and right-click markers to inspect details.", seconds=35.0)

    def _marauder_next_move(self) -> None:
        if not self.project_dir:
            self._buddy_say("Marauder: Select a project folder first. That anchors all ingest, runs, and reports.", seconds=40.0)
            try:
                self.tabs.setCurrentWidget(self.tab_dashboard)
            except Exception:
                pass
            return
        if not self.logs and not self.pcaps:
            self._buddy_say("Marauder: Next move is ingest. Scan SD in the SD tab, then attach selected evidence.", seconds=40.0)
            try:
                self.tabs.setCurrentWidget(self.tab_sd)
            except Exception:
                pass
            return
        if not (self._latest_run_dir or self._project_last_run_dir):
            self._buddy_say("Marauder: Evidence is staged. Hit Analyze to generate map, summary, and PCAP reports.", seconds=40.0)
            try:
                self.tabs.setCurrentWidget(self.tab_dashboard)
            except Exception:
                pass
            return
        self._buddy_say("Marauder: Run exists. Open Map/Reports and inspect isometric hotspots and handshake clusters.", seconds=40.0)
        self._marauder_open_map()

    def _on_marauder_pose_clicked(self, event) -> None:  # noqa: ANN001
        if event is not None and hasattr(event, "button") and event.button() != Qt.LeftButton:
            return
        self._buddy_say("Marauder: You tapped in. I will route you to the best next move.", seconds=18.0, append=False)
        self._marauder_next_move()

    def _update_marauder_assistant_hint(self) -> None:
        try:
            if not self.project_dir:
                self.btn_marauder_summary.setEnabled(False)
            else:
                self.btn_marauder_summary.setEnabled(bool(self._latest_summary or self._project_last_summary))
        except Exception:
            pass

    def _buddy_say(self, text: str, seconds: float = 45.0, append: bool = True) -> None:
        text = _safe_gui_text(text, limit=1200)
        self._buddy_override_until = time.time() + seconds
        try:
            self.lbl_buddy_bubble.setText(text)
        except Exception:
            pass
        if append:
            try:
                stamp = datetime.now().strftime("%H:%M:%S")
                self.txt_buddy_readout.append(f"[{stamp}] {text}")
            except Exception:
                pass

    def _tick_buddy(self) -> None:
        try:
            render = self.mascot.tick()

            # --- Sprite display ---
            png_name = self._MASCOT_PNG.get(render.pose_id, "start.png")
            if png_name not in self._mascot_pixmap_cache:
                pix_path = resource_path("assets", "mascot", png_name)
                loaded = QPixmap(pix_path)
                self._mascot_pixmap_cache[png_name] = loaded

            src_pix = self._mascot_pixmap_cache.get(png_name, QPixmap())

            if not src_pix.isNull():
                label_w = max(self.lbl_buddy_pose.width(), 220)
                label_h = self.lbl_buddy_pose.height() or 200

                # Scale to fit panel, preserving aspect ratio
                scaled = src_pix.scaledToWidth(min(label_w - 8, 210), Qt.SmoothTransformation)
                if scaled.height() > label_h - 8:
                    scaled = scaled.scaledToHeight(label_h - 8, Qt.SmoothTransformation)

                # Bob: sine wave ±4px
                self._mascot_bob_phase = (self._mascot_bob_phase + 0.12) % (2 * math.pi)
                bob_y = int(math.sin(self._mascot_bob_phase) * 4)

                # Scanline alpha: pulse during ANALYZING
                if render.pose_id == "POSE_ANALYZING":
                    scan_alpha = int((0.12 + 0.08 * abs(math.sin(self._mascot_bob_phase * 2.5))) * 255)
                else:
                    scan_alpha = int(0.15 * 255)

                # Compose into canvas
                canvas = QPixmap(label_w, label_h)
                canvas.fill(QColor(0, 0, 0, 0))
                painter = QPainter(canvas)
                x_off = (label_w - scaled.width()) // 2
                y_off = (label_h - scaled.height()) // 2 + bob_y
                painter.drawPixmap(x_off, y_off, scaled)

                # VGA scanlines overlay
                painter.setRenderHint(QPainter.Antialiasing, False)
                scan_pen = QPen(QColor(0, 0, 0, scan_alpha), 1)
                painter.setPen(scan_pen)
                for sl_y in range(0, label_h, 2):
                    painter.drawLine(0, sl_y, label_w, sl_y)
                painter.end()

                self.lbl_buddy_pose.setPixmap(canvas)
            else:
                # PNG missing — fall back to text
                self.lbl_buddy_pose.setText(render.frame_text)

            if time.time() >= getattr(self, "_buddy_override_until", 0.0):
                self.lbl_buddy_bubble.setText(render.bubble_text)
        except Exception:
            pass

    def _buddy_config_from_ui(self, force_local: bool = False) -> BuddyAIConfig:
        enabled = False if force_local else bool(getattr(self, "chk_buddy_ai_enabled", None) and self.chk_buddy_ai_enabled.isChecked())
        return BuddyAIConfig(
            enabled=enabled,
            api_key=self.txt_buddy_api_token.text().strip() if hasattr(self, "txt_buddy_api_token") else "",
            base_url=self.txt_buddy_base_url.text().strip() if hasattr(self, "txt_buddy_base_url") else DEFAULT_BASE_URL,
            model=self.txt_buddy_model.text().strip() if hasattr(self, "txt_buddy_model") else DEFAULT_MODEL,
            sanitize_only=bool(getattr(self, "chk_buddy_sanitize", None) and self.chk_buddy_sanitize.isChecked()),
        )

    def _refresh_buddy_ai_status(self) -> None:
        lbl = getattr(self, "lbl_buddy_ai_status", None)
        if lbl is None:
            return
        enabled = bool(getattr(self, "chk_buddy_ai_enabled", None) and self.chk_buddy_ai_enabled.isChecked())
        has_token = bool(getattr(self, "txt_buddy_api_token", None) and self.txt_buddy_api_token.text().strip())
        if enabled and has_token:
            store = "local project fallback"
            if self.project_dir:
                try:
                    db = os.path.join(self.project_dir, "project.db")
                    if get_setting(db, "buddy_ai_token_store", "") == "keyring":
                        store = "system keyring"
                except Exception:
                    pass
            lbl.setText(f"Buddy AI: enabled; token store: {store}; sanitized readouts available")
        elif enabled:
            lbl.setText("Buddy AI: enabled but no token saved")
        else:
            lbl.setText("Buddy AI: offline/local mode")

    def _buddy_selected_action(self) -> str:
        try:
            return str(self.cmb_buddy_action.currentData() or "next_step")
        except Exception:
            return "next_step"

    def _buddy_ask_selected(self) -> None:
        self._run_buddy_action(self._buddy_selected_action(), force_local=False)

    def _buddy_local_selected(self) -> None:
        self._run_buddy_action(self._buddy_selected_action(), force_local=True)

    def _run_buddy_action(self, action: str, force_local: bool = False) -> None:
        if not self.project_dir:
            self._buddy_say("Select a project first. I need a vault before I can read the room.")
            QMessageBox.information(self, "Buddy", "Select a Project Folder first.")
            return
        if getattr(self, "_buddy_ai_worker", None) is not None:
            self._buddy_say("Already thinking. Give me a second; dramatic pauses are part of the service.")
            return

        config = self._buddy_config_from_ui(force_local=force_local)
        mode = "local" if force_local or not (config.enabled and config.api_key.strip()) else "AI"
        self._buddy_say(f"Running {mode} readout: {action.replace('_', ' ')}...", seconds=20.0, append=False)
        try:
            self.btn_buddy_ask.setEnabled(False)
            self.btn_buddy_local.setEnabled(False)
        except Exception:
            pass

        worker = BuddyAIWorker(self.project_dir, action, config)
        self._buddy_ai_worker = worker
        worker.done.connect(self._on_buddy_done)
        worker.failed.connect(self._on_buddy_failed)
        try:
            worker.finished.connect(worker.deleteLater)
        except Exception:
            pass
        worker.start()

    def _finish_buddy_worker(self) -> None:
        self._buddy_ai_worker = None
        try:
            self.btn_buddy_ask.setEnabled(True)
            self.btn_buddy_local.setEnabled(True)
        except Exception:
            pass

    def _on_buddy_done(self, action: str, response: str, used_ai: bool) -> None:
        self._finish_buddy_worker()
        source = "AI" if used_ai else "local"
        self._buddy_say(response, seconds=60.0)
        self._log(f"Buddy {source} readout complete: {action}", "OK")

    def _on_buddy_failed(self, action: str, error: str, fallback: str) -> None:
        self._finish_buddy_worker()
        self._buddy_say(fallback, seconds=60.0)
        self._log_warn(f"Buddy AI fallback for {action}: {error}")

    # -----------------------------
    # Helpers
    # -----------------------------
    def _sync_bg_geometry(self):
        # Background is now a dedicated right-side panel (no full-window overlay).
        pass

    def _regen_bg(self):
        mode = self.cmb_bg_mode.currentText() if hasattr(self, "cmb_bg_mode") else "random"
        if mode == "random" or mode not in ProceduralBackground.MODES:
            self.demoscene.randomize()
        else:
            self.demoscene.set_mode(mode)
        self._log(f"Background: {self.demoscene.current_name}")

    

    # ------------------------------------------------------------------
    # Console / logging
    # ------------------------------------------------------------------
    _LOG_STYLES: dict = {
        # level  → (prefix, hex_color, plain_prefix)
        "INFO":  ("[*]", "#C8FFFA", "[*]"),
        "OK":    ("[+]", "#50FF90", "[+]"),
        "WARN":  ("[!]", "#FFD080", "[!]"),
        "ERROR": ("[X]", "#FF5555", "[X]"),
        "DEBUG": ("[~]", "#7A9090", "[~]"),
        "BOOT":  ("[>]", "#00FFCC", "[>]"),
        "SCAN":  ("[S]", "#A0CFFF", "[S]"),
    }

    def _log(self, msg: str, level: str = "INFO"):
        stamp = datetime.now().strftime("%H:%M:%S")
        _, color, prefix = self._LOG_STYLES.get(level, self._LOG_STYLES["INFO"])
        plain = f"[{stamp}] {prefix} {msg}"

        try:
            logging.info(plain)
        except Exception:
            pass

        # Dock → always plain text (compact strip)
        dock = getattr(self, "console_dock", None)
        if dock is not None:
            try:
                dock.appendPlainText(plain)
                dock.verticalScrollBar().setValue(dock.verticalScrollBar().maximum())
            except Exception:
                pass

        # Big console → colored HTML
        big = getattr(self, "console_big", None)
        if big is not None:
            try:
                safe = (msg
                        .replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;"))
                html = (
                    f'<span style="color:#808080;">[{stamp}]</span> '
                    f'<span style="color:{color}; font-weight:600;">{prefix}</span> '
                    f'<span style="color:{color};">{safe}</span>'
                )
                big.append(html)
                big.verticalScrollBar().setValue(big.verticalScrollBar().maximum())
            except Exception:
                pass

    def _log_ok(self, msg: str):    self._log(msg, "OK")
    def _log_warn(self, msg: str):  self._log(msg, "WARN")
    def _log_err(self, msg: str):   self._log(msg, "ERROR")
    def _log_debug(self, msg: str): self._log(msg, "DEBUG")
    def _log_scan(self, msg: str):  self._log(msg, "SCAN")

    def _log_from_core(self, msg: str):
        """Route core/worker messages to the right log level by inspecting prefix."""
        ml = msg.lstrip()
        if ml.startswith("[warn]") or ml.startswith("    [warn]"):
            self._log(msg, "WARN")
        elif ml.startswith("ERROR") or ml.startswith("[X]"):
            self._log(msg, "ERROR")
        elif ml.startswith("[+]") or ml.startswith("Complete"):
            self._log(msg, "OK")
        elif ml.startswith("[*] P4R51NG") or ml.startswith("[*] WR1T1NG") or ml.startswith("[*] R3ND3R1NG"):
            self._log(msg, "SCAN")
        else:
            self._log(msg, "INFO")

    def _open_path(self, path: str | None):
        if not path:
            return
        try:
            if os.path.isdir(path):
                os.startfile(path)  # type: ignore[attr-defined]
            else:
                os.startfile(os.path.abspath(path))  # type: ignore[attr-defined]
        except Exception:
            try:
                QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.abspath(path)))
            except Exception:
                pass

    def _set_report_placeholder(self, message: str) -> None:
        viewer = getattr(self, "report_viewer", None)
        if viewer is None:
            return
        safe = (message or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        html = (
            "<html><body style='background:#050607;color:#00ff88;"
            "font-family:Consolas,monospace;padding:24px'>"
            "<h2 style='color:#00ccff'>Wardrive Report Viewer</h2>"
            f"<p>{safe}</p>"
            "</body></html>"
        )
        try:
            if WEBENGINE_AVAILABLE and QWebEngineView is not None and isinstance(viewer, QWebEngineView):
                viewer.setHtml(html, QUrl.fromLocalFile(os.getcwd() + os.sep))
            elif hasattr(viewer, "setHtml"):
                viewer.setHtml(html)
            elif hasattr(viewer, "setPlainText"):
                viewer.setPlainText(message)
        except Exception:
            pass

    def _view_report_in_app(self, path: str | None, title: str = "Report") -> None:
        if not path:
            return
        if not os.path.exists(path):
            QMessageBox.information(self, title, f"No report found:\n{path}")
            return
        viewer = getattr(self, "report_viewer", None)
        if hasattr(self, "cmb_map_mode"):
            try:
                self.cmb_map_mode.setCurrentIndex(2)
            except Exception:
                pass
        if WEBENGINE_AVAILABLE and QWebEngineView is not None and isinstance(viewer, QWebEngineView):
            try:
                viewer.setUrl(QUrl.fromLocalFile(os.path.abspath(path)))
                self.lbl_report_viewer.setText(f"Embedded report viewer: {title} - {os.path.abspath(path)}")
                try:
                    self.tabs.setCurrentWidget(self.tab_results)
                except Exception:
                    pass
                self._log(f"In-app report loaded: {os.path.basename(path)}", "OK")
                return
            except Exception as exc:
                self._log_warn(f"In-app report load failed, opening externally: {exc}")
        else:
            self._set_report_placeholder(
                "QtWebEngine is unavailable in this runtime. Opening this report externally instead."
            )
        self._open_path(path)

    def _set_running(self, running: bool):
        # Track running state for re-entrancy guards and safe shutdown.
        # (This was previously checked but never set, allowing multiple concurrent runs.)
        self._running = bool(running)

        # NOTE: As we retire legacy tabs (Run Setup), some legacy controls may not
        # exist in certain layouts. Never let UI state toggles prevent analysis.
        if hasattr(self, "btn_analyze") and self.btn_analyze is not None:
            self.btn_analyze.setEnabled(not running)
        # Cancel isn't wired in this build; keep it disabled if present.
        if hasattr(self, "btn_cancel") and self.btn_cancel is not None:
            self.btn_cancel.setEnabled(False)
        if hasattr(self, "lbl_status") and self.lbl_status is not None:
            self.lbl_status.setText("STATUS: RUNNING" if running else "STATUS: IDLE")
        if running:
            if hasattr(self, "progress") and self.progress is not None:
                self.progress.setValue(0)
            if hasattr(self, "elapsed") and self.elapsed is not None:
                try:
                    self.elapsed.restart()
                except Exception:
                    pass
            if hasattr(self, "_ui_timer") and self._ui_timer is not None:
                self._ui_timer.start()
        else:
            if hasattr(self, "_ui_timer") and self._ui_timer is not None:
                self._ui_timer.stop()

    def closeEvent(self, event):  # noqa: N802
        """Prevent the app from closing while analysis is running.

        Otherwise, Python/Qt can destroy the QThread while it is still running,
        producing: "QThread: Destroyed while thread is still running".
        """
        try:
            if getattr(self, "_running", False) and getattr(self, "worker", None) is not None:
                QMessageBox.warning(
                    self,
                    "Analysis Running",
                    "Analysis is still running.\n\nWait for it to finish before closing the app.",
                )
                event.ignore()
                return
        except Exception:
            pass
        super().closeEvent(event)

    def _tick_elapsed(self):
        ms = self.elapsed.elapsed()
        sec = ms // 1000
        mm = sec // 60
        ss = sec % 60

        eta_txt = "--:--"
        try:
            if self._stage_total_steps > 0 and self._stage_done_steps > 0 and self._step_times:
                avg = sum(self._step_times[-50:]) / max(1, len(self._step_times[-50:]))
                remaining = max(0, self._stage_total_steps - self._stage_done_steps)
                eta_s = int(round(avg * remaining))
                eta_m = eta_s // 60
                eta_r = eta_s % 60
                eta_txt = f"{eta_m:02d}:{eta_r:02d}"
        except Exception:
            pass

        self.lbl_timer.setText(f"Elapsed: {mm:02d}:{ss:02d} | ETA: {eta_txt}")

    def _cancel_not_supported(self):
        QMessageBox.information(self, "Cancel", "Cancel isn't wired yet. (We keep our hands off the main breaker.)")

    # -----------------------------
    # Project / Integrations
    # -----------------------------
    def _app_state_path(self) -> str:
        base = os.getenv("APPDATA") or os.path.expanduser("~")
        root = os.path.join(base, "WardriveAnalyzer")
        os.makedirs(root, exist_ok=True)
        return os.path.join(root, "app_state.json")

    def _save_last_project(self, folder: str) -> None:
        try:
            payload = {"last_project": folder or ""}
            with open(self._app_state_path(), "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception:
            pass

    def _restore_last_project(self) -> None:
        try:
            path = self._app_state_path()
            if not os.path.exists(path):
                return
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            folder = str(data.get("last_project") or "").strip()
            if not folder or not os.path.isdir(folder):
                return
            self._apply_project_folder(folder, restored=True)
        except Exception:
            pass

    def _apply_project_folder(self, folder: str, restored: bool = False) -> None:
        self.project_dir = folder
        self._set_buddy_state(MascotState.FOLDER_SELECTED)
        db_path = os.path.join(folder, "project.db")
        existed_before = os.path.exists(db_path)
        ensure_project_vault(folder)

        # Inspect prior runs (if any)
        self._project_last_summary = None
        self._project_last_map = None
        self._project_last_pcap_summary = None
        self._project_last_run_dir = None

        runs_dir = os.path.join(folder, "runs")
        last_run = None
        if os.path.isdir(runs_dir):
            cand = [os.path.join(runs_dir, d) for d in os.listdir(runs_dir) if os.path.isdir(os.path.join(runs_dir, d)) and d.lower().startswith("run_")]
            if cand:
                cand.sort(key=lambda p: os.path.getmtime(p))
                last_run = cand[-1]
        if last_run:
            self._project_last_run_dir = last_run
            s = os.path.join(last_run, "summary.html")
            m = os.path.join(last_run, "map.html")
            ps = os.path.join(last_run, "pcap_summary.html")
            self._project_last_summary = s if os.path.exists(s) else None
            self._project_last_map = m if os.path.exists(m) else None
            self._project_last_pcap_summary = ps if os.path.exists(ps) else None

        self.outputLabel.setText(f"Project Folder: {folder}")
        self.lbl_project.setText(f"PROJECT: {folder}")
        self.lbl_sd_project.setText(f"Project: {folder}")
        self.btn_open_project.setEnabled(True)

        stats = project_db_stats(folder)
        status = "EXISTING" if existed_before else "NEW"
        self._log("=== PROJECT SELECTED ===")
        self._log(f"Path: {folder}")
        self._log(f"Status: {status}")
        self._log(f"DB: {os.path.join(folder, 'project.db')}")
        self._log(f"Prior imports: {stats.get('imports', 0)} | Evidence files: {stats.get('evidence', 0)}")
        if self._project_last_run_dir:
            self._log(f"Last run folder: {self._project_last_run_dir}")
            if self._project_last_summary:
                self._log(f"Last summary: {self._project_last_summary}")
            if self._project_last_map:
                self._log(f"Last map: {self._project_last_map}")
            if self._project_last_pcap_summary:
                self._log(f"Last PCAP summary: {self._project_last_pcap_summary}")
        else:
            self._log("Last run folder: (none yet)")

        try:
            self.btn_open_last_summary.setEnabled(bool(self._project_last_summary))
        except Exception:
            pass

        self._log(f"Project folder {'restored' if restored else 'selected'}: {folder}")
        self._load_integrations()
        self._load_settings()
        self.refresh_mission_control()
        self._update_onboarding_checklist()
        self._buddy_say("Project locked. I can summarize runs, inspect evidence health, or suggest the next move.")
        self._wia_emit_event("project_selected", {"path": folder, "restored": bool(restored)})
        self._save_last_project(folder)

    def select_project_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Project Folder")
        if folder:
            self._apply_project_folder(folder, restored=False)

    def open_last_summary(self):
        p = getattr(self, "_project_last_summary", None)
        if p and os.path.exists(p):
            self._view_report_in_app(p, "Summary")
            return
        QMessageBox.information(self, "Open Last Summary", "No prior summary.html found for this project yet.")

    def open_project_folder(self):
        if self.project_dir:
            self._open_path(self.project_dir)

    def _load_integrations(self):
        if not self.project_dir:
            return
        db = os.path.join(self.project_dir, "project.db")
        if not os.path.exists(db):
            return
        self.wigle_name.setText(get_setting(db, "wigle_api_name", ""))
        self.wigle_token.setText(get_setting(db, "wigle_api_token", ""))
        self.wpasec_key.setText(get_setting(db, "wpasec_key", ""))
        try:
            self.lbl_wigle_status.setText("Status: token saved" if self.wigle_token.text().strip() else "Status: no token saved")
            self.lbl_wpasec_status.setText("Status: key saved" if self.wpasec_key.text().strip() else "Status: no key saved")
        except Exception:
            pass
        self._log("Loaded integration keys from project.")

    def _save_integrations(self):
        if not self.project_dir:
            QMessageBox.warning(self, "Missing Project", "Select a Project Folder first.")
            return
        db = ensure_project_vault(self.project_dir)
        set_setting(db, "wigle_api_name", self.wigle_name.text().strip())
        set_setting(db, "wigle_api_token", self.wigle_token.text().strip())
        set_setting(db, "wpasec_key", self.wpasec_key.text().strip())
        try:
            self.lbl_wigle_status.setText("Status: token saved" if self.wigle_token.text().strip() else "Status: no token saved")
            self.lbl_wpasec_status.setText("Status: key saved" if self.wpasec_key.text().strip() else "Status: no key saved")
        except Exception:
            pass
        self._log("Saved integration keys to project.")
        QMessageBox.information(self, "Saved", "Integration keys saved to this project.")

    # -----------------------------
    # Add/clear inputs (manual mode)
    # -----------------------------
    def add_wardrive_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Wardrive Logs", filter="Logs (*.log *.txt);;All Files (*)")
        if not files:
            return
        added = 0
        skipped = 0
        for f in files:
            try:
                fp = file_fingerprint(f)
            except Exception:
                fp = ""
            if fp and fp in self._fp_logs:
                skipped += 1
                continue
            self.wardrive_files.append(f)
            self.wardriveList.addItem(f)
            if fp:
                self._fp_logs.add(fp)
            added += 1
        if added:
            self._log(f"Loaded {added} log(s).")
            self._set_buddy_state(MascotState.LOGS_ADDED)
            self._wia_emit_event("logs_added", {"count": added})
        if skipped:
            self._log(f"Duplicate logs skipped: {skipped} (fingerprint match)")

    def clear_wardrive_files(self):
        self.wardrive_files = []
        self.wardriveList.clear()
        self._fp_logs.clear()
        self._log("Wardrive log list cleared.")

    def add_pcap_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select PCAP Files", filter="PCAP (*.pcap *.pcapng);;All Files (*)")
        if not files:
            return
        added = 0
        skipped = 0
        for f in files:
            try:
                fp = file_fingerprint(f)
            except Exception:
                fp = ""
            if fp and fp in self._fp_pcaps:
                skipped += 1
                continue
            self.pcap_files.append(f)
            self.pcapList.addItem(f)
            if fp:
                self._fp_pcaps.add(fp)
            added += 1
        if added:
            self._log(f"Loaded {added} PCAP(s).")
            self._set_buddy_state(MascotState.PCAPS_ADDED)
            self._wia_emit_event("pcaps_added", {"count": added})
        if skipped:
            self._log(f"Duplicate PCAPs skipped: {skipped} (fingerprint match)")

    def clear_pcap_files(self):
        self.pcap_files = []
        self.pcapList.clear()
        self._fp_pcaps.clear()
        self._log("PCAP list cleared.")

    # -----------------------------
    # Analysis (threaded)
    # -----------------------------
    def run_analysis(self):
        # Guard: prevent starting a second analysis while one is running
        if getattr(self, '_running', False):
            msg = '⛔ Currently generating reports — please wait… (R3P0RT5 1N PR0GR355)'
            self._log(msg)
            # Popup throttle: don't spam dialogs if the user clicks repeatedly.
            try:
                import time
                now = time.time()
                last = getattr(self, '_last_busy_popup_ts', 0.0)
                if (now - last) > 3.0:
                    self._last_busy_popup_ts = now
                    QMessageBox.information(self, "Busy", msg)
            except Exception:
                pass
            return

        if not self.wardrive_files and not self.pcap_files:
            QMessageBox.warning(self, "Missing Input", "Select at least one wardrive log or one PCAP.")
            return
        if not self.project_dir:
            QMessageBox.warning(self, "Missing Project Folder", "Select a Project Folder first.")
            return

        try:
            snapshot = write_diagnostic_snapshot(
                "analysis_start",
                context={
                    "project_dir": self.project_dir,
                    "wardrive_files": len(self.wardrive_files),
                    "pcap_files": len(self.pcap_files),
                    "mode": "manual_or_project_analysis",
                    "first_wardrive_files": [os.path.basename(p) for p in self.wardrive_files[:10]],
                    "first_pcap_files": [os.path.basename(p) for p in self.pcap_files[:10]],
                },
            )
            self._log(f"Crash diagnostics armed: {snapshot}", "DEBUG")
        except Exception as exc:
            self._log_warn(f"Could not write analysis diagnostic snapshot: {exc}")

        self._log(f"=== ANALYZE === {len(self.wardrive_files)} log(s) + {len(self.pcap_files)} PCAP(s)", "SCAN")
        self._log("Wardrive logs = GPS evidence. PCAPs = radio/handshake evidence.", "INFO")
        self._set_buddy_state(MascotState.ANALYZING)
        job_id = self._new_job("Analysis", f"{len(self.wardrive_files)} logs, {len(self.pcap_files)} pcaps")
        self._set_running(True)
        self._log("Engine initializing — parsing evidence, computing centroids, rendering HTML…", "BOOT")

        # Snap to console so it feels alive while it runs
        try:
            self.tabs.setCurrentWidget(self.tab_console)
        except Exception:
            pass

        self.worker = AnalyzeWorker(self.wardrive_files, self.pcap_files, self.project_dir)
        self.worker._mission_job_id = job_id
        self.worker.stage.connect(self._log_from_core)
        self.worker.progress.connect(self._on_progress)
        self.worker.done.connect(self._on_done)
        self.worker.failed.connect(self._on_failed)
        # Ensure the thread object is cleaned up after finishing.
        try:
            self.worker.finished.connect(self.worker.deleteLater)
        except Exception:
            pass
        self.worker.start()

        # Heartbeat timer: emit a console line every 5s while analysis is running
        # so the user can see it has not frozen during long PCAP parsing.
        self._analysis_heartbeat_secs = 0
        self._analysis_heartbeat_timer = QTimer(self)
        self._analysis_heartbeat_timer.setInterval(5000)
        self._analysis_heartbeat_timer.timeout.connect(self._on_analysis_heartbeat)
        self._analysis_heartbeat_timer.start()

    def _on_analysis_heartbeat(self):
        """Emit a periodic alive-signal to the console while analysis is running."""
        if not getattr(self, "_running", False):
            self._stop_analysis_heartbeat()
            return
        self._analysis_heartbeat_secs = getattr(self, "_analysis_heartbeat_secs", 0) + 5
        elapsed = self._analysis_heartbeat_secs
        mins, secs = divmod(elapsed, 60)
        self._log(f"[*] Analysis running... {mins}m {secs:02d}s elapsed (parsing PCAPs / building reports)", "INFO")

    def _stop_analysis_heartbeat(self):
        t = getattr(self, "_analysis_heartbeat_timer", None)
        if t is not None:
            try:
                t.stop()
            except Exception:
                pass
            self._analysis_heartbeat_timer = None

    def _on_progress(self, cur: int, tot: int, label: str):
        """Update footer progress bar + ETA using a moving average of per-step times."""
        self._update_job(getattr(self, "_active_job_id", None), progress=label)
        try:
            # Init the overall expected step count (logs + pcaps + report artifacts).
            if self._stage_total_steps <= 0:
                base_total = int(len(getattr(self, "wardrive_files", []) or []) + len(getattr(self, "pcap_files", []) or []))
                # Writing artifacts is a smaller fixed tail.
                self._stage_total_steps = max(1, base_total + 12)
                self._stage_done_steps = 0
                self._step_times = []
                self._last_step_ms = self.elapsed.elapsed() if hasattr(self, "elapsed") else 0
        except Exception:
            pass

        # If core is emitting per-file parse progress (cur/tot >= 0), map into our overall counter.
        if cur >= 0 and tot > 0:
            # Treat each completed file as one step.
            # We can't perfectly map logs vs pcaps here, but the UX goal is "it is moving".
            done = max(0, min(cur, tot))
            # Keep the base parse portion proportional and leave room for artifact steps.
            parse_total = int(len(getattr(self, "wardrive_files", []) or []) + len(getattr(self, "pcap_files", []) or []))
            parse_total = max(1, parse_total)
            # done-files is cur-1 when the line says "Parsing X/Y: file" (we count after finishing).
            est_done = max(0, done - 1)
            self._stage_done_steps = max(self._stage_done_steps, est_done)
            pct = int(round((self._stage_done_steps / max(1, self._stage_total_steps)) * 100))
            try:
                self.progress.setValue(max(0, min(100, pct)))
                self.progress.setFormat(f"{pct}% — {label}")
            except Exception:
                pass

            # Timing sample
            try:
                now_ms = self.elapsed.elapsed()
                dt = max(0.05, (now_ms - getattr(self, "_last_step_ms", now_ms)) / 1000.0)
                # Only record when we advance
                if est_done > 0:
                    self._step_times.append(dt)
                self._last_step_ms = now_ms
            except Exception:
                pass
            return

        # Artifact-style progress: bump +1 step.
        if label:
            try:
                now_ms = self.elapsed.elapsed()
                dt = max(0.05, (now_ms - getattr(self, "_last_step_ms", now_ms)) / 1000.0)
                self._step_times.append(dt)
                self._last_step_ms = now_ms
            except Exception:
                pass
            self._stage_done_steps = min(self._stage_total_steps, self._stage_done_steps + 1)
            pct = int(round((self._stage_done_steps / max(1, self._stage_total_steps)) * 100))
            try:
                self.progress.setValue(max(0, min(100, pct)))
                self.progress.setFormat(f"{pct}% — {label[:60]}")
            except Exception:
                pass

    def _on_done(self, results: dict):
        self._stop_analysis_heartbeat()
        self._latest_summary = results.get("summary")
        self._latest_run_dir = results.get("run_dir")
        self._update_job(
            getattr(self, "_active_job_id", None),
            status="Complete",
            ended=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            progress="Analysis complete",
            result=self._latest_run_dir or self._latest_summary or "",
        )
        self._active_job_id = None

        self._set_running(False)

        # Drop reference to worker (thread has finished).
        try:
            self.worker = None
        except Exception:
            pass

        self.btn_open_latest.setEnabled(bool(self._latest_summary))
        self.btn_open_run.setEnabled(bool(self._latest_run_dir))

        if self._latest_run_dir:
            self.lbl_latest.setText(f"Latest run: {self._latest_run_dir}")

        msg = "Analysis completed successfully.\n\nGenerated:\n"
        for k in ("csv", "xlsx", "map", "summary", "pcap_summary_html", "pcap_master_csv", "pcap_per_file_csv", "kml"):
            if k in results:
                try:
                    msg += f"- {os.path.basename(str(results[k]))}\n"
                except Exception:
                    pass

        QMessageBox.information(self, "Complete", msg)

        self._log("=== ANALYSIS COMPLETE === all artifacts written.", "OK")
        self._set_buddy_state(MascotState.DONE)
        self._buddy_say("Reports are generated. I can summarize the latest run or compare it against the previous one.")
        try:
            write_diagnostic_snapshot(
                "analysis_complete",
                context={
                    "project_dir": self.project_dir,
                    "run_dir": self._latest_run_dir or "",
                    "summary": self._latest_summary or "",
                    "outputs": sorted(str(k) for k in results.keys()),
                },
            )
        except Exception:
            pass
        for k in ("csv", "xlsx", "map", "summary", "pcap_summary_html", "pcap_master_csv", "kml"):
            if k in results:
                try:
                    self._log(f"  {k}: {os.path.basename(str(results[k]))}", "OK")
                except Exception:
                    pass
        self.refresh_mission_control()

        # Launch WIA intelligence engine in background
        try:
            self._start_wia_analysis(results)
            # Switch to the Intelligence tab so the user sees cards populating
            if hasattr(self, "tab_intelligence"):
                self.tabs.setCurrentWidget(self.tab_intelligence)
        except Exception:
            pass

        # Auto-open: prefer summary.html if available, else open the run folder
        if self.chk_auto_open.isChecked():
            if self._latest_summary and os.path.exists(self._latest_summary):
                self._view_report_in_app(self._latest_summary, "Summary")
            elif self._latest_run_dir and os.path.exists(self._latest_run_dir):
                self._open_path(self._latest_run_dir)

    def _refresh_lists(self):
        """Refresh list widgets that mirror currently selected inputs.

        The legacy Run Setup tab is scrapped/hidden, but its widgets still
        exist in-memory. Keeping them refreshed prevents stale state and
        avoids attribute errors when SD ingest hands off to analysis.
        """
        try:
            if hasattr(self, "wardriveList") and self.wardriveList is not None:
                self.wardriveList.clear()
                for p in (getattr(self, "wardrive_files", []) or []):
                    try:
                        self.wardriveList.addItem(os.path.basename(str(p)))
                    except Exception:
                        pass
        except Exception:
            pass

        try:
            if hasattr(self, "pcapList") and self.pcapList is not None:
                self.pcapList.clear()
                for p in (getattr(self, "pcap_files", []) or []):
                    try:
                        self.pcapList.addItem(os.path.basename(str(p)))
                    except Exception:
                        pass
        except Exception:
            pass

    def _on_failed(self, err: str):
        err = _safe_gui_text(err, limit=1200)
        try:
            report = write_error_report(
                "analysis_failure",
                context={"project_dir": self.project_dir, "error": err},
            )
            err = f"{err}\n\nReport: {report}"
        except Exception:
            pass
        self._stop_analysis_heartbeat()
        self._set_running(False)
        self._set_buddy_state(MascotState.ERROR)
        self._log_err(f"ANALYSIS FAILED: {err}")
        try:
            write_diagnostic_snapshot(
                "analysis_failed",
                context={
                    "project_dir": self.project_dir,
                    "error": err,
                    "wardrive_files": len(getattr(self, "wardrive_files", []) or []),
                    "pcap_files": len(getattr(self, "pcap_files", []) or []),
                },
            )
        except Exception:
            pass
        self._update_job(
            getattr(self, "_active_job_id", None),
            status="Failed",
            ended=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            result=err,
        )
        self._active_job_id = None
        try:
            self.worker = None
        except Exception:
            pass
        QMessageBox.critical(self, "Analysis Error", err)

    def open_latest_summary(self):
        s = self._latest_summary or self._project_last_summary
        if s and os.path.exists(s):
            self._view_report_in_app(s, "Summary")
        else:
            QMessageBox.information(self, "Open Latest Summary", "No summary found yet for this session.")

    # -----------------------------
    # SD ingest
    # -----------------------------
    def select_sd_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select SD Folder")
        if not folder:
            return
        if self._scan_worker is not None:
            QMessageBox.information(self, "Busy", "SD scan already running.")
            return

        self._sd_root = folder
        self._sd_scan_folder = folder
        self.lbl_sd_root.setText(f"SD folder: {folder}  [scanning…]")
        self._log(f"=== SD SCAN === {folder}", "SCAN")
        self._log("Walking directory tree… (UI stays live)", "INFO")

        # Disable ingest buttons while scanning
        try:
            self.btn_sd_ingest.setEnabled(False)
        except Exception:
            pass

        job_id = self._new_job("SD Scan", folder)
        self._scan_job_id = job_id

        worker = ScanWorker(folder)
        self._scan_worker = worker
        worker.done.connect(self._on_scan_done)
        worker.failed.connect(self._on_scan_failed)
        try:
            worker.finished.connect(worker.deleteLater)
        except Exception:
            pass
        worker.start()

    def _on_scan_done(self, candidates: list):
        self._scan_worker = None
        self._sd_candidates = candidates
        folder = self._sd_scan_folder

        from collections import Counter
        by_kind: Counter = Counter(c.kind for c in candidates)
        by_app:  Counter = Counter(c.source_app for c in candidates)
        unknowns  = [c for c in candidates if c.source_app == "unknown"]
        rec_count = sum(1 for c in candidates if c.recommended)
        total_mb  = sum(c.size for c in candidates) / (1024 * 1024)

        self._log_scan(f"Found {len(candidates)} files ({total_mb:.1f} MB)  |  {rec_count} recommended")
        if any(c.kind.lower().startswith("pcap") or "pcap" in c.kind.lower() for c in candidates):
            self._set_buddy_state(MascotState.PCAPS_ADDED)
        elif candidates:
            self._set_buddy_state(MascotState.LOGS_ADDED)
        for app, n in sorted(by_app.items()):
            self._log(f"  [{app}]  {n} file(s)", "OK" if app != "unknown" else "WARN")

        self._log_scan("File types detected:")
        for kind, n in sorted(by_kind.items()):
            self._log(f"  {n:3d}  {kind}", "DEBUG")

        large = [c for c in candidates if c.ext in (".pcap", ".pcapng") and c.size > 50 * 1024 * 1024]
        for c in large:
            self._log_warn(f"Large PCAP ({c.size // (1024 * 1024)}MB) — parse capped at 2M packets: {c.rel_path}")

        if unknowns:
            self._log_warn(f"{len(unknowns)} file(s) NOT recognized — will not be auto-selected:")
            for c in unknowns:
                self._log_warn(f"  UNKNOWN  {c.rel_path}  [{c.ext}]")
        else:
            self._log_ok("All files recognized.")

        self.lbl_sd_root.setText(f"SD folder: {folder}")
        self._populate_sd_lists()

        try:
            self.btn_sd_ingest.setEnabled(True)
        except Exception:
            pass

        self._update_job(
            self._scan_job_id,
            status="Complete",
            ended=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            progress=f"{len(candidates)} candidate file(s)",
            result=folder,
        )

    def _on_scan_failed(self, err: str):
        self._scan_worker = None
        self._set_buddy_state(MascotState.ERROR)
        self._log_err(f"SD scan failed: {err}")
        self.lbl_sd_root.setText("SD folder: (scan failed)")
        try:
            self.btn_sd_ingest.setEnabled(True)
        except Exception:
            pass
        self._update_job(
            self._scan_job_id,
            status="Failed",
            ended=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            result=err,
        )
        QMessageBox.critical(self, "SD Scan Error", err)

    def _populate_sd_lists(self):
        # Clear
        self.sd_list_all.clear()

        counts = {"marauder": 0, "porkchop": 0, "bruce": 0, "nemo": 0, "unknown": 0}

        for idx, c in enumerate(self._sd_candidates):
            counts[c.source_app] = counts.get(c.source_app, 0) + 1
            txt = f"{c.rel_path}  [{c.kind}]"
            tip = f"{c.reason}\nSize: {c.size} bytes"

            # All list always shows
            it_all = QListWidgetItem(txt)
            it_all.setToolTip(tip)
            it_all.setData(Qt.UserRole, idx)
            it_all.setFlags(it_all.flags() | Qt.ItemIsUserCheckable)
            it_all.setCheckState(Qt.Checked if c.recommended else Qt.Unchecked)
            self.sd_list_all.addItem(it_all)

        # Apply current filters after (re)build
        try:
            self._apply_sd_filters()
        except Exception:
            pass

        total = len(self._sd_candidates)
        self.lbl_sd_stats.setText(
            f"Found {total} file(s). Marauder: {counts['marauder']} | Porkchop: {counts['porkchop']} | Bruce: {counts['bruce']} | Nemo: {counts['nemo']} | Other: {counts['unknown']}."
        )

    def _current_sd_list(self) -> QListWidget:
        # Single list mode (filters hide/show items)
        return self.sd_list_all

    def _apply_sd_filters(self):
        """Hide/show SD items based on source app filter checkboxes."""
        show = {
            "marauder": bool(self.chk_show_marauder.isChecked()),
            "porkchop": bool(self.chk_show_porkchop.isChecked()),
            "bruce": bool(self.chk_show_bruce.isChecked()),
            "nemo": bool(self.chk_show_nemo.isChecked()),
            "unknown": bool(self.chk_show_other.isChecked()),
        }
        lw = self.sd_list_all
        for i in range(lw.count()):
            it = lw.item(i)
            idx = it.data(Qt.UserRole)
            if idx is None:
                continue
            try:
                cand = self._sd_candidates[int(idx)]
                app = str(getattr(cand, "source_app", "unknown"))
            except Exception:
                app = "unknown"
            it.setHidden(not show.get(app, True))

    def sd_select_recommended(self):
        lw = self._current_sd_list()
        for i in range(lw.count()):
            it = lw.item(i)
            idx = it.data(Qt.UserRole)
            if idx is None:
                continue
            try:
                cand = self._sd_candidates[int(idx)]
            except Exception:
                continue
            it.setCheckState(Qt.Checked if cand.recommended else Qt.Unchecked)

    def sd_select_none(self):
        lw = self._current_sd_list()
        for i in range(lw.count()):
            lw.item(i).setCheckState(Qt.Unchecked)

    def sd_ingest_selected(self):
        if not self.project_dir:
            QMessageBox.warning(self, "Missing Project", "Select a Project Folder first.")
            return
        if not self._sd_root:
            QMessageBox.warning(self, "Missing SD Folder", "Select an SD Folder first.")
            return
        if getattr(self, "_ingest_worker", None) is not None:
            QMessageBox.information(self, "Busy", "Ingest already running — wait for it to finish.")
            return

        lw = self._current_sd_list()
        selected_idxs: List[int] = []
        for i in range(lw.count()):
            it = lw.item(i)
            if it.checkState() == Qt.Checked:
                idx = it.data(Qt.UserRole)
                if idx is not None:
                    selected_idxs.append(int(idx))

        selected_idxs = sorted(set(selected_idxs))
        if not selected_idxs:
            QMessageBox.information(self, "Nothing Selected", "Select at least one file to attach.")
            return

        candidates = [self._sd_candidates[i] for i in selected_idxs]
        skip_dupes = self.chk_sd_skip_dupes.isChecked()
        total_mb = sum(c.size for c in candidates) / (1024 * 1024)

        self._log(
            f"=== SD INGEST === {len(candidates)} file(s)  ({total_mb:.1f} MB)  skip_dupes={skip_dupes}",
            "SCAN",
        )
        job_id = self._new_job("SD Ingest", f"{len(candidates)} selected")

        # Disable button so user can't double-fire; switch to console tab
        self.btn_sd_ingest.setEnabled(False)
        self.btn_sd_ingest.setText("Attaching…")
        try:
            self.tabs.setCurrentWidget(self.tab_console)
        except Exception:
            pass

        # Progress bar
        try:
            self.progress.setValue(0)
            self.progress.setFormat("Ingest 0%")
        except Exception:
            pass

        worker = IngestWorker(
            project_dir=self.project_dir,
            sd_root=self._sd_root,
            candidates=candidates,
            label="SD",
            skip_duplicates=skip_dupes,
        )
        self._ingest_worker = worker
        self._ingest_job_id = job_id
        self._ingest_total = len(candidates)

        worker.stage.connect(self._on_ingest_stage)
        worker.progress.connect(self._on_ingest_progress)
        worker.file_progress.connect(self._on_ingest_file_progress)
        worker.done.connect(self._on_ingest_done)
        worker.failed.connect(self._on_ingest_failed)
        try:
            worker.finished.connect(worker.deleteLater)
        except Exception:
            pass
        worker.start()

    def _on_ingest_stage(self, msg: str):
        lvl = "ERROR" if msg.startswith("ERROR") else "WARN" if "Duplicate" in msg else "DEBUG"
        self._log(msg, lvl)
        self._update_job(getattr(self, "_ingest_job_id", None), progress=msg)

    def _on_ingest_progress(self, done: int, total: int):
        if total > 0:
            pct = int(done / total * 100)
            try:
                self.progress.setValue(pct)
                # Only update format if no active per-file operation is being shown
                if not getattr(self, "_ingest_file_active", False):
                    self.progress.setFormat(f"Ingest {pct}%  ({done}/{total} files)")
            except Exception:
                pass

    def _on_ingest_file_progress(self, filename: str, phase: str, bdone: int, btotal: int):
        """Per-file byte-level progress for large files during hash or copy phase."""
        try:
            self._ingest_file_active = True
            pct = int(bdone / btotal * 100) if btotal > 0 else 0
            mb_done = bdone / (1024 * 1024)
            mb_total = btotal / (1024 * 1024)
            verb = "Hashing" if phase == "hash" else "Copying"
            file_total = getattr(self, "_ingest_total", 0)
            file_done  = getattr(self, "_ingest_worker", None)
            # Get current file count from worker's internal counter (best effort)
            n = getattr(file_done, "_done_count", 0) if file_done else 0
            counter = f"  —  File {n}/{file_total}" if file_total else ""
            label = f"{verb} {filename}  {pct}%  ({mb_done:.0f} MB / {mb_total:.0f} MB){counter}"
            self.progress.setValue(pct)
            self.progress.setFormat(label)
            # Clear the per-file lock once done so overall progress takes back over
            if bdone >= btotal:
                self._ingest_file_active = False
        except Exception:
            self._ingest_file_active = False

    def _on_ingest_done(self, stats: dict):
        self._ingest_worker = None
        self._ingest_file_active = False
        candidates_count = getattr(self, "_ingest_total", stats.get("total", 0))
        summary = (
            f"Copied {stats['imported']} | "
            f"Duplicates {stats['duplicates']} | "
            f"Errors {stats['errors']}  "
            f"(of {candidates_count} selected)"
        )
        lvl = "ERROR" if stats["errors"] else "OK"
        self._log(f"=== INGEST COMPLETE === {summary}", lvl)
        self._set_buddy_state(MascotState.LOGS_ADDED if stats["errors"] == 0 else MascotState.ERROR)
        if stats["errors"]:
            self._log_warn("Some files failed to copy — check console for details.")

        try:
            self.lbl_sd_stats.setText(summary)
        except Exception:
            pass
        try:
            self.progress.setValue(100)
            self.progress.setFormat("Ingest complete")
        except Exception:
            pass

        self.btn_sd_ingest.setEnabled(True)
        self.btn_sd_ingest.setText("Attach Selected to Project")

        job_id = getattr(self, "_ingest_job_id", None)
        self._update_job(
            job_id,
            status="Complete" if stats["errors"] == 0 else "Complete with errors",
            ended=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            progress=summary,
            result=self.project_dir,
        )
        self.refresh_mission_control()
        QMessageBox.information(self, "Ingest Complete", summary)

        # WIA event
        self._wia_emit_event("ingest_done", {
            "imported": stats.get("imported", 0),
            "duplicates": stats.get("duplicates", 0),
        })

        try:
            resp = QMessageBox.question(
                self,
                "Analyze Now?",
                "Evidence attached.\n\nAnalyze now and generate reports?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if resp == QMessageBox.Yes:
                self.sd_analyze_project_evidence()
        except Exception:
            pass

    def _on_ingest_failed(self, err: str):
        self._ingest_worker = None
        self._ingest_file_active = False
        self._set_buddy_state(MascotState.ERROR)
        self._log_err(f"Ingest failed: {err}")
        self.btn_sd_ingest.setEnabled(True)
        self.btn_sd_ingest.setText("Attach Selected to Project")
        try:
            self.progress.setValue(0)
            self.progress.setFormat("Ingest failed")
        except Exception:
            pass
        job_id = getattr(self, "_ingest_job_id", None)
        self._update_job(
            job_id,
            status="Failed",
            ended=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            result=err,
        )
        QMessageBox.critical(self, "Ingest Error", err)


    def sd_analyze_selected_now(self):
        """Analyze checked files from the SD scan WITHOUT requiring ingest/attach first."""
        if not self._sd_root:
            QMessageBox.warning(self, "Missing SD Folder", "Select an SD Folder first.")
            return
        if not self.project_dir:
            QMessageBox.warning(self, "Missing Project", "Select a Project Folder first (run outputs go here).")
            return

        lw = self._current_sd_list()
        selected_idxs: List[int] = []
        for i in range(lw.count()):
            it = lw.item(i)
            if it.checkState() == Qt.Checked:
                idx = it.data(Qt.UserRole)
                if idx is not None:
                    selected_idxs.append(int(idx))
        selected_idxs = sorted(set(selected_idxs))
        if not selected_idxs:
            QMessageBox.information(self, "Nothing Selected", "Select at least one file to analyze.")
            return

        candidates = [self._sd_candidates[i] for i in selected_idxs]

        # Fingerprint-aware classification (SD ingest replaces Run Setup)
        logs: List[str] = []
        pcaps: List[str] = []
        structured: List[str] = []
        unknown: List[str] = []

        def _is_structured(ext: str) -> bool:
            return ext in (".csv", ".json", ".ndjson")

        def _is_text(ext: str) -> bool:
            return ext in (".txt", ".log", ".md")

        for c in candidates:
            p = getattr(c, "abs_path", "") or ""
            kind = str(getattr(c, "kind", "") or "").lower()
            ext = os.path.splitext(p)[1].lower()

            if ext in (".pcap", ".pcapng") or kind.startswith("pcap") or "pcap" in kind:
                pcaps.append(p)
                continue

            # Structured evidence (common for Bruce/Porkchop/Nemo)
            if _is_structured(ext) or kind in ("bruce_creds", "loot_meta", "nemo_output") or kind.endswith("_output"):
                structured.append(p)
                continue

            # Text logs
            if _is_text(ext) or kind.startswith("log") or kind.endswith("_log"):
                logs.append(p)
                continue

            # Anything else: keep (we may still want to archive/attach later)
            unknown.append(p)

        logs = sorted(dict.fromkeys([p for p in logs if os.path.exists(p)]))
        pcaps = sorted(dict.fromkeys([p for p in pcaps if os.path.exists(p)]))
        structured = sorted(dict.fromkeys([p for p in structured if os.path.exists(p)]))
        unknown = sorted(dict.fromkeys([p for p in unknown if os.path.exists(p)]))

        # Console + log banner (no silent failures)
        self._log("=== ANALYZE STARTED (SD INGEST MODE) ===")
        self._log(f"Selected files: {len(candidates)}")
        self._log(f"Recognized PCAPs: {len(pcaps)}")
        self._log(f"Recognized text logs: {len(logs)}")
        self._log(f"Recognized structured: {len(structured)}")
        if unknown:
            self._log(f"Unknown/ignored (kept for reference): {len(unknown)}")

        if not logs and not pcaps and not structured:
            QMessageBox.information(self, "No Supported Evidence", "No supported evidence was detected in your selection. (Try Select Recommended.)")
            return

        # Feed analysis engine
        self.wardrive_files = logs + structured
        self.pcap_files = pcaps
        self._refresh_lists()

        self._log(f"Ready to analyze: {len(self.wardrive_files)} logs/structured, {len(pcaps)} pcaps")
        try:
            self.tabs.setCurrentWidget(self.tab_console)
        except Exception:
            pass
        self.run_analysis()

    def sd_analyze_project_evidence(self):
        """Analyze ALL evidence currently attached to the project vault."""
        if not self.project_dir:
            QMessageBox.warning(self, "Missing Project", "Select a Project Folder first.")
            return

        logs, pcaps = gather_project_inputs_for_analysis(self.project_dir)
        if not logs and not pcaps:
            QMessageBox.information(
                self,
                "No Evidence",
                "No attached logs/pcaps found for this project yet. Attach from SD or use Analyze Selected Now (from SD).",
            )
            return

        self.wardrive_files = logs
        self.pcap_files = pcaps
        self._refresh_lists()

        self._log("=== ANALYZE (PROJECT EVIDENCE) ===")
        self._log(f"Ready to analyze: {len(logs)} logs, {len(pcaps)} pcaps")

        # Snap to live console while it runs
        try:
            self.tabs.setCurrentWidget(self.tab_console)
        except Exception:
            pass

        self.run_analysis()
