from __future__ import annotations

import os
import sys
import random
import subprocess
import hashlib
import logging
import re
from dataclasses import dataclass
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal, QTimer, QElapsedTimer, QRect, QRectF, QPointF, QUrl
from PySide6.QtGui import QPainter, QLinearGradient, QColor, QFont, QPen, QBrush, QPixmap, QDesktopServices, QMovie
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QListWidget, QListWidgetItem, QFileDialog, QLabel, QMessageBox,
    QTextEdit, QPlainTextEdit, QProgressBar, QFrame, QTabWidget, QLineEdit, QCheckBox, QComboBox, QStackedLayout, QSizePolicy,
    QTableWidget, QTableWidgetItem, QHeaderView
)

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
# Procedural cyberpunk background (Qt painter)
# -----------------------------
@dataclass
class BgSeed:
    a: int
    b: int
    c: int
    mode: str


class CyberBackground(QWidget):
    MODES = ["pixel_demo_gif", "grid_horizon", "circuit_board", "matrix_rain", "nebula_noise"]

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setAutoFillBackground(False)

        # Pixel demoscene GIF layer (behind UI)
        self.gif_label = QLabel(self)
        self.gif_label.setScaledContents(True)
        self.gif_label.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.gif_label.hide()
        self._movie: QMovie | None = None
        self._gif_choice: str | None = None

        self.seed = BgSeed(0, 0, 0, "grid_horizon")
        self.phase = 0.0
        self._static = QPixmap()
        self._drops: list[tuple[float, float, float]] = []

        self.regenerate(initial=True)

        self._anim = QTimer(self)
        self._anim.setInterval(16)
        self._anim.timeout.connect(self._tick)
        self._anim.start()

    def regenerate(self, initial: bool = False):
        self.seed = BgSeed(
            random.randint(0, 10_000_000),
            random.randint(0, 10_000_000),
            random.randint(0, 10_000_000),
            random.choices(self.MODES, weights=[6,1,1,1,1], k=1)[0],
        )
        self.phase = 0.0
        self._static = QPixmap()
        self._drops = []
        self._apply_mode()
        if not initial:
            self.update()

    def _apply_mode(self):
        # If pixel_demo_gif: load one of our baked GIFs and let QMovie animate it.
        if self.seed.mode == "pixel_demo_gif":
            choice = random.choice(ASSET_GIFS)
            if choice != self._gif_choice:
                self._gif_choice = choice
                try:
                    path = resource_path(choice)
                    mv = QMovie(path)
                    self._movie = mv
                    self.gif_label.setMovie(mv)
                    mv.start()
                except Exception:
                    self._movie = None
            self.gif_label.show()
        else:
            self.gif_label.hide()
            if self._movie:
                try:
                    self._movie.stop()
                except Exception:
                    pass
                self._movie = None
            self._gif_choice = None

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.gif_label.setGeometry(0, 0, self.width(), self.height())

    def _tick(self):
        self.phase += 0.04
        if self.phase > 9999:
            self.phase = 0.0
        self.update()

    def _ensure_static(self):
        w, h = self.width(), self.height()
        if w <= 2 or h <= 2:
            return
        if not self._static.isNull() and self._static.size().width() == w and self._static.size().height() == h:
            return

        pm = QPixmap(w, h)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing, True)

        g = QLinearGradient(0, 0, w, h)
        hue1 = (self.seed.a % 360)
        hue2 = (self.seed.b % 360)
        c1 = QColor.fromHsl(hue1, 180, 25)
        c2 = QColor.fromHsl(hue2, 200, 12)
        g.setColorAt(0.0, QColor(3, 5, 6))
        g.setColorAt(0.35, c2)
        g.setColorAt(0.75, c1)
        g.setColorAt(1.0, QColor(0, 0, 0))
        p.fillRect(pm.rect(), g)

        rng = random.Random(self.seed.c)

        if self.seed.mode == "grid_horizon":
            self._draw_horizon_grid(p, w, h, rng)
        elif self.seed.mode == "circuit_board":
            self._draw_circuit(p, w, h, rng)
        elif self.seed.mode == "matrix_rain":
            p.fillRect(pm.rect(), QColor(0, 0, 0, 60))
        elif self.seed.mode == "nebula_noise":
            self._draw_nebula(p, w, h, rng)

        vign = QLinearGradient(w * 0.5, h * 0.5, w * 0.5, h)
        vign.setColorAt(0.0, QColor(0, 0, 0, 0))
        vign.setColorAt(1.0, QColor(0, 0, 0, 190))
        p.fillRect(pm.rect(), vign)

        p.setPen(QPen(QColor(0, 255, 204, 35), 1))
        font = QFont("Consolas")
        font.setPointSize(9)
        p.setFont(font)
        glyphs = ["0xDEAD", "0xBEEF", "WIGLE", "PCAP", "RSSI", "BSSID", "SCAN", "NODE", "RUN"]
        for _ in range(18):
            txt = rng.choice(glyphs)
            x = rng.randint(0, max(1, w - 60))
            y = rng.randint(20, max(21, h - 10))
            p.drawText(QPointF(x, y), txt)

        p.end()
        self._static = pm

        if self.seed.mode == "matrix_rain":
            cols = max(10, w // 20)
            self._drops = [(i * (w / cols), rng.random() * h, 30 + rng.random() * 120) for i in range(cols)]

    def _draw_horizon_grid(self, p: QPainter, w: int, h: int, rng: random.Random):
        for _ in range(6):
            x = rng.random() * w
            y = rng.random() * h
            rw = (0.25 + rng.random() * 0.6) * w
            rh = (0.15 + rng.random() * 0.5) * h
            hue = rng.randint(0, 359)
            col = QColor.fromHsl(hue, 220, 55, 28)
            p.setBrush(QBrush(col))
            p.setPen(Qt.NoPen)
            p.drawEllipse(QRectF(x - rw / 2, y - rh / 2, rw, rh))

        p.setRenderHint(QPainter.Antialiasing, False)
        grid_y = int(h * 0.70)
        van_x = w * 0.5
        van_y = h * 0.55
        for i in range(-18, 19):
            x = van_x + i * (w * 0.06)
            p.setPen(QPen(QColor(0, 255, 170, 60), 1))
            p.drawLine(int(x), grid_y, int(van_x), int(van_y))
        for i in range(1, 26):
            y = grid_y + int((i ** 1.35) * (h * 0.008))
            if y >= h:
                break
            alpha = max(10, 70 - i * 2)
            p.setPen(QPen(QColor(0, 255, 170, alpha), 1))
            p.drawLine(0, y, w, y)

    def _draw_circuit(self, p: QPainter, w: int, h: int, rng: random.Random):
        p.setRenderHint(QPainter.Antialiasing, False)
        for _ in range(120):
            x1 = rng.randint(0, w)
            y1 = rng.randint(0, h)
            x2 = x1 + rng.randint(-120, 120)
            y2 = y1 + rng.randint(-120, 120)
            col = QColor(0, 255, 208, rng.randint(15, 60))
            p.setPen(QPen(col, 1))
            p.drawLine(x1, y1, x2, y1)
            p.drawLine(x2, y1, x2, y2)
            p.fillRect(max(0, x2 - 2), max(0, y2 - 2), 4, 4, QColor(0, 255, 208, rng.randint(30, 80)))

    def _draw_nebula(self, p: QPainter, w: int, h: int, rng: random.Random):
        p.setRenderHint(QPainter.Antialiasing, True)
        for _ in range(10):
            x = rng.random() * w
            y = rng.random() * h
            rw = (0.2 + rng.random() * 0.8) * w
            rh = (0.2 + rng.random() * 0.7) * h
            hue = rng.randint(0, 359)
            col = QColor.fromHsl(hue, 180, 40, 22)
            p.setBrush(QBrush(col))
            p.setPen(Qt.NoPen)
            p.drawEllipse(QRectF(x - rw / 2, y - rh / 2, rw, rh))

    def paintEvent(self, event):
        if self.seed.mode == "pixel_demo_gif":
            # GIF handled by QLabel/QMovie.
            return
        self._ensure_static()
        painter = QPainter(self)
        painter.drawPixmap(0, 0, self._static)

        w, h = self.width(), self.height()

        painter.setRenderHint(QPainter.Antialiasing, False)
        for y in range(0, h, 4):
            a = 10 if (int(self.phase * 10) + y) % 12 else 20
            painter.fillRect(0, y, w, 1, QColor(0, 255, 150, a))

        if self.seed.mode == "matrix_rain" and self._drops:
            painter.setPen(QPen(QColor(0, 255, 120, 90), 1))
            font = QFont("Consolas")
            font.setPointSize(10)
            painter.setFont(font)
            for i, (x, y, spd) in enumerate(self._drops):
                y2 = (y + self.phase * spd) % (h + 100)
                txt = chr(33 + ((int(x + y2) + i) % 60))
                painter.drawText(QPointF(x, y2), txt)

        painter.end()


# -----------------------------
# Analyzer worker thread
# -----------------------------
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
        try:
            def cb(msg: str):
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
            self.stage.emit("Executing analyzer…")

            results = analyze(self.wardrive_files, self.pcap_files, self.project_dir, status_cb=cb)

            self.stage.emit("Complete.")
            self.done.emit(results)
        except Exception as e:
            self.failed.emit(str(e))


# -----------------------------
# Main GUI
# -----------------------------

class DemoscenePanel(QWidget):
    """Right-side pixel demoscene GIF panel.

    Renders the *right side* of the GIF as the focal point (scaled-to-fill, cropped, anchored right).
    """

    def __init__(self, parent: QWidget | None = None, gif_paths: list[str] | None = None):
        super().__init__(parent)
        self.setObjectName("DemoscenePanel")
        self._gif_paths = gif_paths or ASSET_GIFS
        self._movie: QMovie | None = None
        self.current_name = "(none)"
        self._start_random()

    def _start_random(self) -> None:
        if not self._gif_paths:
            return
        path = random.choice(self._gif_paths)
        self.set_gif(path)

    def randomize(self) -> None:
        self._start_random()

    def set_gif(self, path: str) -> None:
        abspath = resource_path(path)
        if not os.path.exists(abspath):
            # Try relative to current working dir as a fallback
            if os.path.exists(path):
                abspath = path
            else:
                return
        if self._movie:
            self._movie.stop()
        self._movie = QMovie(abspath)
        self._movie.setCacheMode(QMovie.CacheMode.CacheAll)
        self._movie.frameChanged.connect(lambda _=None: self.update())
        self._movie.start()
        self.current_name = os.path.basename(path)

    def paintEvent(self, event):  # noqa: N802
        super().paintEvent(event)
        if not self._movie:
            return
        pix = self._movie.currentPixmap()
        if pix.isNull():
            return

        w = self.width()
        h = self.height()
        if w <= 0 or h <= 0:
            return

        # Scale-to-fill while preserving aspect ratio
        pw = pix.width()
        ph = pix.height()
        if pw <= 0 or ph <= 0:
            return

        sx = w / pw
        sy = h / ph
        s = max(sx, sy)
        sw = int(pw * s)
        sh = int(ph * s)

        # Anchor RIGHT: place scaled pix so its right edge aligns with widget right edge
        x = w - sw
        y = (h - sh) // 2

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
        painter.drawPixmap(QRect(x, y, sw, sh), pix, QRect(0, 0, pw, ph))
        painter.end()


class WardriveGUI(QWidget):
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

        # Run-state + progress / ETA tracking
        self._running: bool = False
        self._last_busy_popup_ms: int = 0
        self._stage_total_steps: int = 0
        self._stage_done_steps: int = 0
        self._step_times: list[float] = []
        self.elapsed = QElapsedTimer()

        # QSS first (so widgets created later inherit it)
        self._load_qss()

        # Full-window background layer (pixel demoscene)
        self.demoscene = DemoscenePanel(gif_paths=ASSET_GIFS)
        self.demoscene.setObjectName("DemosceneBG")

        # Overlay layer (all interactive UI)
        overlay = QWidget()
        overlay.setObjectName("Overlay")
        overlay.setAttribute(Qt.WA_TranslucentBackground, True)

        overlay.setStyleSheet(
            "QWidget#Overlay{background: transparent;}"
            "QWidget#LeftPane{background-color: rgba(0,0,0,140); border: 1px solid rgba(0,255,220,80); border-radius: 14px;}"
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
        # NOTE: Leave empty for now; background art remains visible behind it.
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
        self._log(f"Demoscene: {self.demoscene.current_name}")
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

        self.tabs.addTab(self.tab_dashboard, "Dashboard")
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
        for b in (btn_project, btn_scan, btn_analyze, btn_summary, btn_folder):
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
        v.setSpacing(8)

        title = QLabel("Console / Operator Log")
        title.setObjectName("PanelTitle")
        v.addWidget(title)

        # Big in-tab console (separate from the always-visible docked console)
        self.console_big = QTextEdit()
        self.console_big.setReadOnly(True)
        self.console_big.setObjectName("ConsoleBig")
        self.console_big.setPlaceholderText(
            "Output appears here while things run.\n"
            "(If it looks idle, check STATUS + progress bar — no fake loading spinners in this basement.)"
        )
        v.addWidget(self.console_big, 1)
        return panel
    def _build_results_tab(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("Panel")
        v = QVBoxLayout(panel)
        v.setContentsMargins(12, 12, 12, 12)
        v.setSpacing(10)

        self.lbl_latest = QLabel("Latest run: (none yet)")
        self.lbl_latest.setObjectName("PathLabel")
        v.addWidget(self.lbl_latest)

        self.chk_auto_open = QCheckBox("Auto-open run folder when complete")
        self.chk_auto_open.setChecked(True)
        v.addWidget(self.chk_auto_open)

        row = QHBoxLayout()
        self.btn_open_run = QPushButton("Open Latest Run Folder")
        self.btn_open_run.clicked.connect(lambda: self._open_path(self._latest_run_dir) if self._latest_run_dir else None)
        self.btn_open_run.setEnabled(False)

        self.btn_open_latest = QPushButton("Open Latest Summary")
        self.btn_open_latest.clicked.connect(self.open_latest_summary)
        self.btn_open_latest.setEnabled(False)

        row.addWidget(self.btn_open_run)
        row.addWidget(self.btn_open_latest)
        v.addLayout(row)

        row2 = QHBoxLayout()
        self.btn_open_latest_map = QPushButton("Open Latest Map")
        self.btn_open_latest_map.clicked.connect(lambda: self._open_path(self._latest_output("map.html")))
        self.btn_open_latest_kml = QPushButton("Open Latest KML")
        self.btn_open_latest_kml.clicked.connect(lambda: self._open_path(self._latest_output("wardrive_map.kml")))
        self.btn_open_latest_pcap = QPushButton("Open Latest PCAP Summary")
        self.btn_open_latest_pcap.clicked.connect(lambda: self._open_path(self._latest_output("pcap_summary.html")))
        row2.addWidget(self.btn_open_latest_map)
        row2.addWidget(self.btn_open_latest_kml)
        row2.addWidget(self.btn_open_latest_pcap)
        v.addLayout(row2)

        hint = QLabel(
            "Reports are generated locally inside each project run folder. Use Run History for older outputs."
        )
        hint.setObjectName("Notes")
        v.addWidget(hint)

        return panel

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
        self.cmb_bg_mode.addItems(["random_gif", "grid_horizon", "circuit_board", "matrix_rain", "nebula_noise"])
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
            self._log("Settings loaded.")
        except Exception:
            pass

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
            self._project_last_run_dir = str(latest.get("run_dir") or "")
            outputs = latest.get("outputs") or {}
            if isinstance(outputs, dict):
                self._project_last_summary = str(outputs.get("summary.html") or "") or None
                self._project_last_map = str(outputs.get("map.html") or "") or None
                self._project_last_pcap_summary = str(outputs.get("pcap_summary.html") or "") or None
            self.lbl_dash_latest_run.setText(
                f"Latest run: {latest.get('run_id', '')}  outputs {latest.get('present_count', 0)}/9"
            )
            self.lbl_latest.setText(f"Latest run: {self._project_last_run_dir}")
            self.btn_open_latest.setEnabled(bool(self._project_last_summary))
            self.btn_open_run.setEnabled(bool(self._project_last_run_dir))
            try:
                self.btn_open_last_summary.setEnabled(bool(self._project_last_summary))
            except Exception:
                pass
        else:
            self.lbl_dash_latest_run.setText("Latest run: none")

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
            r = self.tbl_runs.rowCount()
            self.tbl_runs.insertRow(r)
            missing = run.get("missing") or []
            vals = [
                run.get("run_id", ""),
                run.get("modified", ""),
                f"{run.get('present_count', 0)}/9",
                ", ".join(missing[:3]) + (" ..." if len(missing) > 3 else ""),
                run.get("run_dir", ""),
            ]
            for c, val in enumerate(vals):
                self._set_table_cell(self.tbl_runs, r, c, val, run.get("run_dir") if c == 4 else None)

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
            self._open_path(p)
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
    # Helpers
    # -----------------------------
    def _sync_bg_geometry(self):
        # Background is now a dedicated right-side panel (no full-window overlay).
        pass

    def _regen_bg(self):
        # Randomly pick a new demoscene background (full-window).
        self.demoscene.randomize()
        self._log(f"Demoscene: {self.demoscene.current_name}")

    

    def _log(self, msg: str):
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {msg}"
        try:
            logging.info(msg)
        except Exception:
            pass
        for attr in ("console_dock", "console_big"):
            w = getattr(self, attr, None)
            if w is None:
                continue
            try:
                # QPlainTextEdit supports appendPlainText; QTextEdit supports append.
                if hasattr(w, "appendPlainText"):
                    w.appendPlainText(line)
                elif hasattr(w, "append"):
                    w.append(line)
            except Exception:
                pass

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
    def select_project_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Project Folder")
        if folder:
            self.project_dir = folder
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

            # Update all project labels
            self.outputLabel.setText(f"Project Folder: {folder}")
            self.lbl_project.setText(f"PROJECT: {folder}")
            self.lbl_sd_project.setText(f"Project: {folder}")
            self.btn_open_project.setEnabled(True)

            # Verbose project state
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

            self._log(f"Project folder selected: {folder}")
            self._load_integrations()
            self._load_settings()
            self.refresh_mission_control()
            self._update_onboarding_checklist()

    def open_last_summary(self):
        p = getattr(self, "_project_last_summary", None)
        if p and os.path.exists(p):
            self._open_path(p)
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

        self._log("=== ANALYZE REQUESTED ===")
        self._log("Logs = GPS evidence. PCAPs = radio evidence. Overlap = confidence.")
        job_id = self._new_job("Analysis", f"{len(self.wardrive_files)} logs, {len(self.pcap_files)} pcaps")
        self._set_running(True)

        # Busy banner (big console + dock)
        self._log('=== LIVE CONSOLE ENGAGED ===')
        self._log('[*] 1N1T… b00t s3qu3nc3 // generating reports…')
        self._log('[*] Stand by… parsing evidence + rendering HTML…')

        # Snap to console so it feels alive while it runs
        try:
            self.tabs.setCurrentWidget(self.tab_console)
        except Exception:
            pass

        self.worker = AnalyzeWorker(self.wardrive_files, self.pcap_files, self.project_dir)
        self.worker._mission_job_id = job_id
        self.worker.stage.connect(self._log)
        self.worker.progress.connect(self._on_progress)
        self.worker.done.connect(self._on_done)
        self.worker.failed.connect(self._on_failed)
        # Ensure the thread object is cleaned up after finishing.
        try:
            self.worker.finished.connect(self.worker.deleteLater)
        except Exception:
            pass
        self.worker.start()

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

        self._log("Boot sequence complete. Awaiting next scan…")
        self.refresh_mission_control()

        # Auto-open: prefer summary.html if available, else open the run folder
        if self.chk_auto_open.isChecked():
            if self._latest_summary and os.path.exists(self._latest_summary):
                self._open_path(self._latest_summary)
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
        self._set_running(False)
        self._log(f"ERROR: {err}")
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
            self._open_path(s)
        else:
            QMessageBox.information(self, "Open Latest Summary", "No summary found yet for this session.")

    # -----------------------------
    # SD ingest
    # -----------------------------
    def select_sd_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select SD Folder")
        if not folder:
            return
        self._sd_root = folder
        self.lbl_sd_root.setText(f"SD folder: {folder}")
        self._log(f"Scanning SD folder: {folder}")
        job_id = self._new_job("SD Scan", folder)

        try:
            self._sd_candidates = scan_sd_folder(folder)
        except Exception as e:
            self._update_job(job_id, status="Failed", ended=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), result=str(e))
            QMessageBox.critical(self, "SD Scan Error", str(e))
            return

        self._populate_sd_lists()
        self._update_job(
            job_id,
            status="Complete",
            ended=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            progress=f"{len(self._sd_candidates)} candidate file(s)",
            result=folder,
        )

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
        self._log(self.lbl_sd_stats.text())

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

        lw = self._current_sd_list()
        selected_idxs: List[int] = []
        for i in range(lw.count()):
            it = lw.item(i)
            if it.checkState() == Qt.Checked:
                idx = it.data(Qt.UserRole)
                if idx is not None:
                    selected_idxs.append(int(idx))

        # De-duplicate indexes (same file appears in multiple tabs)
        selected_idxs = sorted(set(selected_idxs))
        if not selected_idxs:
            QMessageBox.information(self, "Nothing Selected", "Select at least one file to attach.")
            return

        candidates = [self._sd_candidates[i] for i in selected_idxs]
        skip_dupes = self.chk_sd_skip_dupes.isChecked()

        self._log(f"=== SD INGEST ===")
        self._log(f"Selected: {len(candidates)} file(s). Skip duplicates: {skip_dupes}")
        job_id = self._new_job("SD Ingest", f"{len(candidates)} selected")

        def cb(msg: str):
            self._log(msg)
            self._update_job(job_id, progress=msg)

        try:
            stats = ingest_candidates_to_project(
                project_dir=self.project_dir,
                sd_root=self._sd_root,
                candidates=candidates,
                label="SD",
                skip_duplicates=skip_dupes,
                progress_cb=cb,
            )
        except Exception as e:
            self._update_job(job_id, status="Failed", ended=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), result=str(e))
            QMessageBox.critical(self, "Ingest Error", str(e))
            return

        self.lbl_sd_stats.setText(
            f"Attached {len(candidates)} selected | Copied {stats['imported']} | Duplicates {stats['duplicates']} | Errors {stats['errors']}"
        )
        self._update_job(
            job_id,
            status="Complete" if stats["errors"] == 0 else "Complete with errors",
            ended=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            progress=self.lbl_sd_stats.text(),
            result=self.project_dir,
        )
        QMessageBox.information(self, "Ingest Complete", self.lbl_sd_stats.text())
        self._log(self.lbl_sd_stats.text())
        self.refresh_mission_control()

        # Immediately offer to analyze after ingest (fast workflow).
        try:
            resp = QMessageBox.question(
                self,
                "Analyze Now?",
                "Evidence has been attached to this project.\n\nAnalyze now and generate reports?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if resp == QMessageBox.Yes:
                self.sd_analyze_project_evidence()
        except Exception:
            pass


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

        # NEW vs ALREADY SEEN detection (project DB sha256)
        already = None
        new = None
        try:
            dbp = os.path.join(self.project_dir, "project.db")
            if os.path.exists(dbp):
                already = 0
                new = 0
                # only hash selected evidence types (pcaps can be large, but this is the most accurate check)
                for p in (pcaps + logs + structured):
                    try:
                        sha = sha256_file(p)
                        if sha256_exists(dbp, sha):
                            already += 1
                        else:
                            new += 1
                    except Exception:
                        pass
                self._log(f"Project evidence match (by hash): already ingested {already} | new to project {new}")
        except Exception:
            pass

        # Allow re-analysis even if everything was already seen, but confirm first.
        if already is not None and new is not None and already > 0 and new == 0:
            resp = QMessageBox.question(
                self,
                "Analyze Anyway?",
                "All selected evidence appears to have been ingested into this project already (hash match).\n\nAnalyze anyway and generate a fresh run folder?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if resp != QMessageBox.Yes:
                self._log("Analyze cancelled (operator declined re-analysis of already-seen evidence).")
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
