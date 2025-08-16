"""
Barebones PySide6 GUI skeleton for talking to a FastAPI backend
and tailing a Redis pub/sub channel.

Run locally with:
  uv add PySide6 httpx redis pyqtgraph
  uv run python main.py

Adjust API_BASE and REDIS settings below.
"""
from __future__ import annotations

import json
import sys
import threading
import re
from math import isfinite
from dataclasses import dataclass
import numpy as np
from typing import Any, Optional

import httpx
import pyqtgraph as pg
from PySide6.QtCore import QObject, QThread, QThreadPool, QRunnable, Signal, Slot, Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QVBoxLayout,
    QScrollArea,
    QSplitter,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QWidget,
)

pg.setConfigOptions(useOpenGL=False, antialias=True)


# -----------------------------
# Config
# -----------------------------

@dataclass
class Config:
    api_base: str = "http://192.168.1.100:8000"
    commands_path: str = "/v1/command"
    api_username: str = "noah"
    api_password: str = "stinkylion"
    redis_host: str = "192.168.1.100"
    redis_port: int = 6379
    redis_channel: str = "log"
    redis_username: str = "roclient"
    redis_password: str = "password"


CONFIG = Config()

# Strip ANSI color codes from Redis messages
ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

# Strict data-line matcher: "DEVICE <t> NAME:VAL" (no ANSI, one line)
LOG_RE = re.compile(
    r'^(?P<device>\S+)\s+(?P<t>[+-]?\d+(?:\.\d+)?)\s+(?P<name>[A-Za-z0-9_]+):(?P<val>[+-]?\d+(?:\.\d+)?)$'
)


class HttpRequestSignals(QObject):
    success = Signal(object)
    error = Signal(str)
    finished = Signal()  # always emitted at the end of work (success or error)


class HttpRequestWorker(QRunnable):
    def __init__(self, method: str,
                 url: str,
                 *,
                 json_body: Optional[dict] = None,
                 timeout: float = 5.0,
                 auth: Optional[tuple[str, str]] = None):
        super().__init__()
        self.method = method.upper()
        self.url = url
        self.json_body = json_body
        self.timeout = timeout
        self.auth = auth
        self.signals = HttpRequestSignals()

    @Slot()
    def run(self) -> None:
        try:
            with httpx.Client(timeout=self.timeout, auth=self.auth) as client:
                if self.method == "GET":
                    resp = client.get(self.url)
                elif self.method == "POST":
                    resp = client.post(self.url, json=self.json_body)
                else:
                    resp = client.request(self.method, self.url, json=self.json_body)

            resp.raise_for_status()
            try:
                payload: Any = resp.json()
            except Exception:
                payload = resp.text
            self.signals.success.emit(payload)
        except Exception as e:
            self.signals.error.emit(str(e))
        finally:
            # ensure cleanup hooks in the GUI always fire
            self.signals.finished.emit()


class RedisTailer(QThread):
    message = Signal(str)
    status = Signal(str)
    error = Signal(str)

    def __init__(self, host: str, port: int, channel: str, username: str, password: str, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.host = host
        self.port = port
        self.channel = channel
        self.username = username
        self.password = password
        self._stop_flag = threading.Event()
        self._pubsub = None

    def run(self) -> None:
        try:
            import redis
            client = redis.Redis(
                host=self.host, port=self.port,
                username=self.username, password=self.password,
                decode_responses=True,
            )
            self._pubsub = client.pubsub(ignore_subscribe_messages=True)
            self._pubsub.subscribe(self.channel)
            self.status.emit(f"Subscribed to redis://{self.host}:{self.port} channel '{self.channel}'")

            while not self._stop_flag.is_set():
                item = self._pubsub.get_message(timeout=1.0)  # seconds
                if not item:
                    continue
                if item.get("type") == "message":
                    data = item.get("data")
                    if not isinstance(data, str):
                        try:
                            data = json.dumps(data)
                        except Exception:
                            data = str(data)
                    # optional: strip ANSI here if you've filled in the regex
                    data = ANSI_RE.sub("", data)
                    # emit per-line to be safe
                    for line in str(data).splitlines():
                        line = line.strip()
                        if line:
                            self.message.emit(line)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            try:
                if self._pubsub is not None:
                    self._pubsub.close()
            except Exception:
                pass
            self.status.emit("Redis tailer stopped.")


    def stop(self) -> None:
        self._stop_flag.set()


# -----------------------------
# Dynamic graph panel using pyqtgraph
# -----------------------------
class GraphPanel(QWidget):
    def __init__(self, columns: int):
        super().__init__()
        self.columns = columns
        self.layout = QGridLayout(self)
        self.setLayout(self.layout)

        # Hardcoded: display a sine wave on startup
        x = np.linspace(0, 2 * np.pi, 500)
        y = np.sin(x)

        plot_widget = pg.PlotWidget(title="Sine Wave")
        # Stop auto-range jitter and padding feedback
        plot_widget.enableAutoRange(x=False, y=False)
        plot_widget.getViewBox().setDefaultPadding(0.0)
        plot_widget.showGrid(x=True, y=True)

        curve = plot_widget.plot(
            x, y,
            pen=pg.mkPen((0, 150, 255), width=2),
            symbol='o',            # ensure visibility even if the line path glitches
            symbolSize=4,
            symbolBrush=(255, 120, 120),
            symbolPen=None,
            connect='finite',
        )
        # Explicit ranges so nothing auto-resizes
        plot_widget.setXRange(0.0, 2*np.pi, padding=0)
        plot_widget.setYRange(-1.2, 1.2, padding=0)

        # Give it a stable size to avoid layout oscillation in ScrollArea/Splitter
        from PySide6.QtWidgets import QSizePolicy
        plot_widget.setMinimumHeight(260)
        plot_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.layout.addWidget(plot_widget, 0, 0)

class MainWindow(QMainWindow):
    def __init__(self, config: Config):
        super().__init__()
        self.config = config
        self.setWindowTitle("Prop Control - Barebones GUI")
        self.resize(1000, 700)

        self.thread_pool = QThreadPool.globalInstance()
        # Avoid saturating the machine with too many concurrent requests
        try:
            self.thread_pool.setMaxThreadCount(4)
        except Exception:
            pass
        self._http_workers: set[HttpRequestWorker] = set()  # keep refs to prevent GC/segfaults
        self.redis_thread: Optional[RedisTailer] = None

        api_box = QGroupBox("API Endpoint")
        api_layout = QGridLayout()
        self.api_base_edit = QLineEdit(self.config.api_base)
        self.api_path_edit = QLineEdit(self.config.commands_path)
        self.api_user_edit = QLineEdit(self.config.api_username)
        self.api_pass_edit = QLineEdit(self.config.api_password)
        self.api_pass_edit.setEchoMode(QLineEdit.Password)
        api_layout.addWidget(QLabel("Base"), 0, 0)
        api_layout.addWidget(self.api_base_edit, 0, 1)
        api_layout.addWidget(QLabel("Path"), 1, 0)
        api_layout.addWidget(self.api_path_edit, 1, 1)
        api_layout.addWidget(QLabel("User"), 2, 0)
        api_layout.addWidget(self.api_user_edit, 2, 1)
        api_layout.addWidget(QLabel("Pass"), 3, 0)
        api_layout.addWidget(self.api_pass_edit, 3, 1)
        api_box.setLayout(api_layout)

        redis_box = QGroupBox("Redis")
        redis_layout = QGridLayout()
        self.redis_host_edit = QLineEdit(self.config.redis_host)
        self.redis_port_edit = QLineEdit(str(self.config.redis_port))
        self.redis_chan_edit = QLineEdit(self.config.redis_channel)
        self.redis_user_edit = QLineEdit(self.config.redis_username)
        self.redis_pass_edit = QLineEdit(self.config.redis_password)
        self.redis_pass_edit.setEchoMode(QLineEdit.Password)
        self.btn_redis_start = QPushButton("Start Log Tail")
        self.btn_redis_stop = QPushButton("Stop Log Tail")
        self.btn_redis_stop.setEnabled(False)
        redis_layout.addWidget(QLabel("Host"), 0, 0)
        redis_layout.addWidget(self.redis_host_edit, 0, 1)
        redis_layout.addWidget(QLabel("Port"), 1, 0)
        redis_layout.addWidget(self.redis_port_edit, 1, 1)
        redis_layout.addWidget(QLabel("Channel"), 2, 0)
        redis_layout.addWidget(self.redis_chan_edit, 2, 1)
        redis_layout.addWidget(QLabel("User"), 3, 0)
        redis_layout.addWidget(self.redis_user_edit, 3, 1)
        redis_layout.addWidget(QLabel("Pass"), 4, 0)
        redis_layout.addWidget(self.redis_pass_edit, 4, 1)
        redis_layout.addWidget(self.btn_redis_start, 5, 0)
        redis_layout.addWidget(self.btn_redis_stop, 5, 1)
        redis_box.setLayout(redis_layout)

        cmd_box = QGroupBox("Controls & Telemetry")
        cmd_layout = QHBoxLayout()
        self.control_combo = QComboBox()
        self.control_combo.addItems(["AVFILL", "AVRUN", "AVDUMP", "AVPURGE1", "AVPURGE2", "AVVENT", "SAFE24", "IGN"])
        self.btn_ctrl_open = QPushButton("CONTROL OPEN")
        self.btn_ctrl_close = QPushButton("CONTROL CLOSE")
        self.btn_gets = QPushButton("GETS")
        self.btn_stop = QPushButton("STOP")
        self.stream_rate_edit = QLineEdit("10")
        self.stream_rate_edit.setPlaceholderText("Hz")
        self.btn_stream = QPushButton("STREAM")
        self.btn_ping = QPushButton("Ping Backend")
        cmd_layout.addWidget(QLabel("Control"))
        cmd_layout.addWidget(self.control_combo)
        cmd_layout.addWidget(self.btn_ctrl_open)
        cmd_layout.addWidget(self.btn_ctrl_close)
        cmd_layout.addWidget(self.btn_gets)
        cmd_layout.addWidget(self.btn_stop)
        cmd_layout.addWidget(QLabel("Hz"))
        cmd_layout.addWidget(self.stream_rate_edit)
        cmd_layout.addWidget(self.btn_stream)
        cmd_layout.addWidget(self.btn_ping)
        cmd_box.setLayout(cmd_layout)

        self.log = QTextEdit()
        self.log.setReadOnly(True)

        # --- Right side: commands + graphs + log
        self.graphs = GraphPanel(columns=2)
        graphs_scroll = QScrollArea()
        graphs_scroll.setWidget(self.graphs)
        graphs_scroll.setWidgetResizable(True)
        graphs_scroll.setMinimumHeight(300)

        # Right stack: commands on top, splitter between graphs and log
        right_splitter = QSplitter(Qt.Vertical)
        right_splitter.addWidget(graphs_scroll)
        right_splitter.addWidget(self.log)
        right_splitter.setSizes([500, 200])

        right_container = QWidget()
        right_v = QVBoxLayout(right_container)
        right_v.addWidget(cmd_box)
        right_v.addWidget(right_splitter, 1)

        # Left side: config panel
        side = QWidget()
        side_v = QVBoxLayout(side)
        side_v.addWidget(api_box)
        side_v.addWidget(redis_box)
        side_v.addStretch(1)
        side.setMinimumWidth(360)

        # Main splitter: side <-> right
        main_splitter = QSplitter(Qt.Horizontal)
        main_splitter.addWidget(side)
        main_splitter.addWidget(right_container)
        main_splitter.setSizes([360, 800])

        self.setCentralWidget(main_splitter)

        act_quit = QAction("Quit", self)
        act_quit.triggered.connect(self.close)
        self.menuBar().addAction(act_quit)

        self.btn_ping.clicked.connect(self.on_ping)
        self.btn_ctrl_open.clicked.connect(lambda: self.send_control_command("OPEN"))
        self.btn_ctrl_close.clicked.connect(lambda: self.send_control_command("CLOSE"))
        self.btn_gets.clicked.connect(self.on_gets)
        self.btn_stream.clicked.connect(self.on_stream)
        self.btn_stop.clicked.connect(self.on_stop)
        self.btn_redis_start.clicked.connect(self.start_redis)
        self.btn_redis_stop.clicked.connect(self.stop_redis)

        self.statusBar().showMessage("Ready")

    def build_url(self) -> str:
        base, _ = self._base_and_auth()
        path = self.api_path_edit.text()
        if not path.startswith("/"):
            path = "/" + path
        return base + path

    @Slot()
    def on_ping(self) -> None:
        base, auth = self._base_and_auth()
        url = base.rstrip("/") + "/health"
        self.append_log(f"GET {url}")
        worker = HttpRequestWorker("GET", url, auth=auth)
        worker.signals.success.connect(lambda payload: self.append_log(f"Ping OK: {payload}"))
        worker.signals.error.connect(lambda msg: self.append_log(f"Ping ERROR: {msg}"))
        self.thread_pool.start(worker)

    def send_command(self, payload: dict[str, Any]) -> HttpRequestWorker:
        url = self.build_url()
        _, auth = self._base_and_auth()
        self.append_log(f"POST {url} -> {payload}")
        worker = HttpRequestWorker("POST", url, json_body=payload, auth=auth)
        worker.signals.success.connect(lambda resp: self.append_log(f"Command OK: {resp}"))
        worker.signals.error.connect(lambda msg: self.append_log(f"Command ERROR: {msg}"))
        # track worker to prevent premature GC while running
        self._http_workers.add(worker)
        worker.signals.finished.connect(lambda: self._http_workers.discard(worker))
        self.thread_pool.start(worker)
        return worker

    @Slot()
    def start_redis(self) -> None:
        if self.redis_thread and self.redis_thread.isRunning():
            return
        try:
            host = self.redis_host_edit.text().strip()
            port = int(self.redis_port_edit.text().strip())
            chan = self.redis_chan_edit.text().strip()
            user = self.redis_user_edit.text().strip()
            pwd = self.redis_pass_edit.text().strip()
        except Exception:
            QMessageBox.warning(self, "Redis", "Invalid host/port/channel/user/pass")
            return

        self.redis_thread = RedisTailer(host, port, chan, user, pwd)
        self.redis_thread.message.connect(lambda m: self.append_log(f"[redis] {m}"))
        self.redis_thread.message.connect(self.on_redis_message)
        self.redis_thread.status.connect(self.append_log)
        self.redis_thread.error.connect(lambda e: self.append_log(f"Redis ERROR: {e}"))
        self.redis_thread.start()
        self.btn_redis_start.setEnabled(False)
        self.btn_redis_stop.setEnabled(True)

    @Slot()
    def stop_redis(self) -> None:
        if self.redis_thread and self.redis_thread.isRunning():
            self.redis_thread.stop()
            self.redis_thread.wait(2000)
        self.btn_redis_start.setEnabled(True)
        self.btn_redis_stop.setEnabled(False)

    def send_control_command(self, action: str) -> None:
        name = self.control_combo.currentText().strip()
        if action not in {"OPEN", "CLOSE"}:
            QMessageBox.warning(self, "Command", f"Unknown action: {action}")
            return
        # disable to debounce rapid back-to-back clicks that can saturate the pool
        self.btn_ctrl_open.setEnabled(False)
        self.btn_ctrl_close.setEnabled(False)
        w = self.send_command({"command": "CONTROL", "args": [name, action]})
        w.signals.finished.connect(lambda: (self.btn_ctrl_open.setEnabled(True), self.btn_ctrl_close.setEnabled(True)))

    def on_gets(self) -> None:
        self.btn_gets.setEnabled(False)
        w = self.send_command({"command": "GETS", "args": []})
        w.signals.finished.connect(lambda: self.btn_gets.setEnabled(True))


    def on_stream(self) -> None:
        text = self.stream_rate_edit.text().strip()
        try:
            hz = int(text)
            if hz < 0:
                raise ValueError
        except Exception:
            QMessageBox.warning(self, "STREAM", f"Invalid Hz: {text}")
            return
        self.send_command({"command": "STREAM", "args": [str(hz)]})
        self.stream_rate_edit.setEnabled(False)
        self.btn_stream.setEnabled(False)

    def on_stop(self) -> None:
        self.send_command({"command": "STOP", "args": []})
        self.btn_stream.setEnabled(True)
        self.stream_rate_edit.setEnabled(True)

    def on_redis_message(self, m: str) -> None:
        m = m.split("]", 1)[-1]  # strip any leading timestamp
        m = m.strip()
        match = LOG_RE.match(m)
        if not match:
            return  # ignore non-data lines
        try:
            device = match.group("device")
            t = float(match.group("t"))
            name = match.group("name")
            val = float(match.group("val"))
        except Exception:
            return

        # Fix: Use proper finite value check instead of truthy check
        if not (isfinite(t) and isfinite(val)):
            return

        # Keep device streams separate so they don't merge
        series = f"{device}:{name}"
        self.graphs.add_point(series, t, val, self.log, self.statusBar)

    def append_log(self, line: str) -> None:
        self.log.append(line)
        self.statusBar().showMessage(line, 3000)

    def closeEvent(self, event) -> None:
        try:
            self.stop_redis()
        finally:
            super().closeEvent(event)

    def _base_and_auth(self) -> tuple[str, Optional[tuple[str, str]]]:
        from urllib.parse import urlsplit, urlunsplit

        raw = self.api_base_edit.text().strip()
        parts = urlsplit(raw)
        user = self.api_user_edit.text().strip() or (parts.username or "")
        pwd = self.api_pass_edit.text().strip() or (parts.password or "")
        host = parts.hostname or ""
        netloc = host + (f":{parts.port}" if parts.port else "")
        base = urlunsplit((parts.scheme or "http", netloc, parts.path, parts.query, parts.fragment))
        auth = (user, pwd) if user and pwd else None
        return base, auth


def main() -> int:
    app = QApplication(sys.argv)
    win = MainWindow(CONFIG)
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
