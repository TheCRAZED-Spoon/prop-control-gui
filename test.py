import os, sys
# Force safest rendering path for Qt/pyqtgraph on Windows
os.environ["QT_OPENGL"] = "software"         # fallback to software (harmless on Qt6)
os.environ["QT_SCALE_FACTOR"] = "1"          # avoid fractional DPI jitter
os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "0"

from PySide6.QtWidgets import QApplication, QMainWindow
from PySide6.QtCore import Qt
import pyqtgraph as pg
import numpy as np

# Use non-GL painter, explicit colors for contrast
pg.setConfigOptions(useOpenGL=False, antialias=True, background='w', foreground='k')

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        w = pg.PlotWidget()
        self.setCentralWidget(w)
        x = np.linspace(0, 2*np.pi, 200)
        y = np.sin(x)
        # Disable auto-range feedback, set explicit ranges
        w.enableAutoRange(x=False, y=False)
        w.getViewBox().setDefaultPadding(0.0)
        w.showGrid(x=True, y=True)
        w.setXRange(0, 2*np.pi, padding=0)
        w.setYRange(-1.2, 1.2, padding=0)
        # Draw both a line and visible markers
        w.plot(x, y, pen=pg.mkPen((0, 120, 255), width=2),
               symbol='o', symbolSize=5, symbolBrush=(255, 80, 80), connect='finite')

app = QApplication(sys.argv)
# Optional: avoid DPI rounding oscillation
try:
    app.setHighDpiScaleFactorRoundingPolicy(
        getattr(Qt.HighDpiScaleFactorRoundingPolicy, "PassThrough")
    )
except Exception:
    pass

win = MainWindow()
win.resize(640, 480)
win.show()
sys.exit(app.exec())