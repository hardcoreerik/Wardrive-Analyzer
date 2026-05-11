import sys
import os
import logging
from PySide6.QtWidgets import QApplication
from gui_step3d_scene import WardriveGUI


def setup_logging() -> str:
    """Write wardrive_run.log to the folder the program is launched from."""
    try:
        log_path = os.path.join(os.getcwd(), "wardrive_run.log")
        logging.basicConfig(
            filename=log_path,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
        )
        logging.info("=== Wardrive Alpha starting ===")
        logging.info("cwd=%s", os.getcwd())
        return log_path
    except Exception:
        return ""

def load_stylesheet():
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    qss_path = os.path.join(base_path, "style_scene.qss")
    if os.path.exists(qss_path):
        with open(qss_path, "r", encoding="utf-8") as f:
            return f.read()
    return ""

def main():
    log_path = setup_logging()
    app = QApplication(sys.argv)
    app.setStyleSheet(load_stylesheet())
    window = WardriveGUI()
    try:
        window._log(f"Log file: {log_path}" if log_path else "Log file: (failed to init)")
    except Exception:
        pass
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
