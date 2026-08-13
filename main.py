#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAN-Play / ldn_mitm 房间监控网页（零第三方依赖版 · 优化版）
"""
from __future__ import annotations

import base64
import copy
import gc
import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import sys
import zlib
import threading
import time
import uuid
import ssl
import socketserver
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import http.client
import urllib.request
import urllib.error
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

# ============================================================================
# SECTION 1 · 日志捕获器
# ============================================================================

class LogCapturer:
    """日志捕获器：同一种类的重复日志采用“替换”方式。

    “种类”判定：把时间戳、UUID、长十六进制串、数字等易变内容归一化后，
    剩余文本相同的日志视为同一种类。再次出现时直接替换原条目的内容和更新时间，
    不追加新行，也不显示重复次数；条目在列表中的原位置保持不变。
    """

    _RE_ISO_TS = re.compile(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    )
    _RE_TIME = re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b")
    _RE_UUID = re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I
    )
    _RE_HEX = re.compile(r"\b[0-9a-f]{12,}\b", re.I)
    _RE_NUM = re.compile(r"\d+")

    # 单条日志最大保留长度，防止超长异常/报文把内存撑爆
    MAX_LINE = 1000
    # 归一化 key 的最大长度（key 只用于去重，截断不影响判定质量）
    MAX_KEY = 200

    def __init__(self, maxlen: int = 200):
        self.terminal = sys.stdout
        self.maxlen = maxlen
        # kind_key -> [最新原文, 首次时间, 最后更新时间]
        # OrderedDict 的顺序代表首次出现顺序；重复日志只替换内容，不移动位置。
        self.entries: OrderedDict[str, list[Any]] = OrderedDict()
        self.lock = threading.Lock()
        self.changed = threading.Condition(self.lock)
        self.version = 0
        # 渲染结果缓存：日志版本未变时复用同一个列表，避免每次请求重建
        self._render_cache: list[str] | None = None
        self._render_version = -1

    @classmethod
    def _kind_key(cls, msg: str) -> str:
        """归一化日志为“种类”标识：剔除时间戳/UUID/哈希/数字等易变内容。

        优化：先截断再做 5 次正则替换。原实现对超长文本（如异常报文、
        base64 片段）整串跑正则，既慢又生成多份大字符串副本。
        """
        key = msg[: cls.MAX_KEY]
        key = cls._RE_ISO_TS.sub("<T>", key)
        key = cls._RE_TIME.sub("<T>", key)
        key = cls._RE_UUID.sub("<U>", key)
        key = cls._RE_HEX.sub("<H>", key)
        key = cls._RE_NUM.sub("#", key)
        return key

    def write(self, message: str):
        msg_stripped = message.strip()
        if not msg_stripped:
            if self.terminal:
                self.terminal.write(message)
            return
        if msg_stripped.startswith("Traceback") or "File \"/" in msg_stripped:
            return
        if self.terminal:
            self.terminal.write(message)
            self.terminal.flush()
        # 超长日志截断，避免单条几 MB 的内容常驻内存
        if len(msg_stripped) > self.MAX_LINE:
            msg_stripped = msg_stripped[: self.MAX_LINE] + f"…(已截断 {len(msg_stripped) - self.MAX_LINE} 字符)"
        now = time.time()
        key = self._kind_key(msg_stripped)
        with self.lock:
            entry = self.entries.get(key)
            if entry is not None:
                # 同种类：直接替换原条目；不追加、不计数、不改变条目位置。
                entry[0] = msg_stripped
                entry[2] = now
            else:
                self.entries[key] = [msg_stripped, now, now]
                while len(self.entries) > self.maxlen:
                    self.entries.popitem(last=False)  # 淘汰最早出现的条目
            self.version += 1
            self._render_cache = None
            self.changed.notify_all()

    def _render_locked(self, n: int = 200) -> list[str]:
        """在持锁状态下渲染日志列表，并按版本缓存结果。"""
        if self._render_cache is not None and self._render_version == self.version:
            return self._render_cache
        entries = list(self.entries.values())
        if len(entries) > n:
            entries = entries[-n:]
        rendered = [self._format(e) for e in entries]
        self._render_cache = rendered
        self._render_version = self.version
        return rendered

    def flush(self):
        if self.terminal:
            self.terminal.flush()

    @staticmethod
    def _format(entry: list[Any]) -> str:
        text, _first, last = entry
        last_dt = datetime.fromtimestamp(last)
        fmt = "%H:%M:%S" if last_dt.date() == datetime.now().date() else "%m-%d %H:%M:%S"
        ts = last_dt.strftime(fmt)
        return f"{text} | 更新于 {ts}"

    def get_logs(self) -> list[str]:
        with self.lock:
            return self._render_locked(self.maxlen)

    def get_logs_snapshot(self, n: int = 200) -> tuple[int, list[str]]:
        with self.lock:
            return self.version, self._render_locked(n)

    def wait_for_change(self, version: int, timeout: float = 300.0) -> tuple[int, list[str]]:
        """等待日志版本变化。

        优化：加超时上限。原实现无限期 wait，客户端断开后（尤其是移动端
        切后台/被系统回收）线程会永久挂住，每个僵尸连接常驻一个线程栈
        （默认 8MB 虚拟内存 / 数十 KB 实际）+ 一份 handler 对象。
        """
        deadline = time.monotonic() + timeout
        with self.changed:
            while self.version == version:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.changed.wait(min(remaining, 30.0))
            return self.version, self._render_locked(200)

    def get_logs_tail(self, n: int = 200) -> list[str]:
        _version, items = self.get_logs_snapshot(n)
        return items


log_capturer = LogCapturer()
sys.stdout = log_capturer
sys.stderr = log_capturer

# 线程栈从默认 8MB 降到 512KB。本程序的线程都只做 IO 转发与简单解析，
# 递归极浅。Android 上每个线程栈会实打实计入进程内存映射，
# 几十个连接线程的差异可达数百 MB 虚拟内存 / 数十 MB RSS。
try:
    threading.stack_size(512 * 1024)
except (ValueError, RuntimeError):
    pass

# ============================================================
# 原生桥接：沉浸式状态栏 + 电池优化 + 主题同步 + WebView 文件选择
# (整合自原 android_filechooser.py，统一入口)
# ============================================================
try:
    import android_native
    android_native_ok = android_native.install()
except Exception as _native_exc:
    print("[原生桥接] 初始化失败:", repr(_native_exc))
    android_native_ok = False


def _request_ignore_battery_optimizations_once() -> None:
    if not android_native_ok:
        return
    try:
        android_native.request_ignore_battery_optimizations()
    except Exception as _exc:
        print("[电池优化] 请求失败:", repr(_exc))


import threading as _threading_battery
_threading_battery.Thread(
    target=_request_ignore_battery_optimizations_once,
    daemon=True,
    name="battery-opt-request",
).start()

info = lambda *a, **k: print("[INFO]", *a, **k)
warn = lambda *a, **k: print("[WARN]", *a, **k)
err = lambda *a, **k: print("[ERROR]", *a, **k)

# ============================================================================
# SECTION 2 · 网络连通性检测
# ============================================================================

NETWORK_CHECK_URL = "https://www.baidu.com"

# ---------------------------------------------------------------------------
# 共享 SSL 上下文（内存优化关键项）
#
# 原代码在 10 处、每次网络请求都调用 ssl.create_default_context()。
# 每次调用都会重新加载系统 CA 证书库（数百 KB ~ 数 MB 的证书对象），
# 在“每秒轮询 + 多客户端”的场景下会造成剧烈的内存抖动（锯齿状 RSS）。
# 这些调用点随后又统一关掉了校验（check_hostname=False / CERT_NONE），
# 因此完全等价于一个共享的免校验上下文——建一次全局复用即可。
# ---------------------------------------------------------------------------
def _make_unverified_ssl_context() -> ssl.SSLContext:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


SSL_CTX = _make_unverified_ssl_context()

_network_status_cache: dict[str, Any] = {
    "online": True,
    "last_check": 0.0,
    "last_success": 0.0,
    "consecutive_failures": 0,
}
_network_status_lock = threading.Lock()


def check_network_reachability() -> bool:
    ctx_ssl = SSL_CTX  # 复用全局免校验上下文，避免重复加载 CA 证书库
    req = urllib.request.Request(
        NETWORK_CHECK_URL,
        headers={"User-Agent": f"{APP_NAME}/1.0", "Accept": "text/html"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx_ssl) as resp:
            return 200 <= resp.status < 600
    except (urllib.error.URLError, socket.timeout, OSError):
        return False


def get_network_status(force: bool = False) -> dict[str, Any]:
    global _network_status_cache
    now = time.time()
    with _network_status_lock:
        cached = _network_status_cache
        if not force and now - cached["last_check"] < 5:
            return {"online": cached["online"], "last_success": cached["last_success"]}
        is_online = check_network_reachability()
        cached["last_check"] = now
        if is_online:
            cached["online"] = True
            cached["last_success"] = now
            cached["consecutive_failures"] = 0
        else:
            cached["consecutive_failures"] += 1
            if cached["consecutive_failures"] >= 2:
                cached["online"] = False
        return {"online": cached["online"], "last_success": cached["last_success"]}

# ============================================================================
# SECTION 3 · 常量 & 配置
# ============================================================================

SCRIPT_DIR = Path(__file__).resolve().parent
LOCAL_SERVERS_FILE = str(SCRIPT_DIR / "servers.json")
MANUAL_SERVERS_FILE = str(SCRIPT_DIR / "servers_manual.json")
SERVERS_FILE = os.getenv("SERVERS_FILE", "").strip() or MANUAL_SERVERS_FILE
DEFAULT_SERVERS_FILE = MANUAL_SERVERS_FILE

REMOTE_DOWNLOAD_INTERVAL = 60
APP_NAME = "lan-play-room-monitor"
CACHE_TTL = max(1, float(os.getenv("CACHE_TTL", "1")))
REQUEST_TIMEOUT = max(1, float(os.getenv("REQUEST_TIMEOUT", "1")))
# 扫描线程数：原为 32（上限 64）。每个线程 = 一个栈 + 一份运行时对象，
# 而扫描是 IO 密集且服务器通常只有个位数台，开这么多纯属浪费常驻内存。
# 现按“服务器数”自适应，最多 8。
MAX_WORKERS = max(2, int(os.getenv("MAX_WORKERS", "8")))
# JSON 接口请求体上限（非文件上传），防止异常大包撑爆内存
MAX_JSON_BODY_BYTES = 2 * 1024 * 1024
# 内存看门狗执行间隔（秒）：定期 gc + 把空闲堆归还操作系统
GC_INTERVAL = max(30, int(os.getenv("GC_INTERVAL", "120")))

# 可选代理前缀（为空则直连，失败自动重试直连）# 例：https://v6.gh-proxy.org 或 https://gh-proxy.com
REMOTE_UPDATE_PROXY = os.getenv("REMOTE_UPDATE_PROXY", "https://v6.gh-proxy.org").strip().rstrip("/")
# 远程资源原始地址（直连）；实际请求时若 REMOTE_UPDATE_PROXY 非空则优先走 代理/原始URL
REMOTE_CHINESE_DB_URL = "https://raw.githubusercontent.com/jieluojun/LanPlayMonitor/refs/heads/main/chinese_db.json"
REMOTE_SERVERS_URL = "https://raw.githubusercontent.com/jieluojun/LanPlayMonitor/refs/heads/main/servers.json"

# 前后端远程更新地址（同上，直连原始地址）
REMOTE_FRONTEND_URL = "https://raw.githubusercontent.com/jieluojun/LanPlayMonitor/refs/heads/main/script.js"
REMOTE_BACKEND_URL = "https://raw.githubusercontent.com/jieluojun/LanPlayMonitor/refs/heads/main/main.py"
LOCAL_FRONTEND_FILE = str(SCRIPT_DIR / "script.js")
LOCAL_BACKEND_FILE = str(SCRIPT_DIR / "main.py")

def _remote_candidate_urls(url: str) -> list[str]:
    """根据 REMOTE_UPDATE_PROXY 生成候选 URL 列表：优先代理，失败自动重试直连。"""
    if REMOTE_UPDATE_PROXY:
        return [f"{REMOTE_UPDATE_PROXY}/{url}", url]
    return [url]

LOCAL_CHINESE_DB_FILE = str(SCRIPT_DIR / "chinese_db.json")

DEFAULT_SERVERS: list[dict[str, Any]] = [
    {
        "id": "1",
        "name": "内置服务器",
        "host": "example.com",
        "port": 11451,
        "type": "graphql",
        "region": "🇨🇳"
    }
]

BUILTIN_GAME_TITLES: dict[str, str] = {
    "FFFFFFFFFFFFFFFF": "未知游戏"
}

# ============================================================================
# SECTION 3.5 · Cloudflare R2 存储（聊天媒体上传）
# ============================================================================

import hashlib
import hmac
import mimetypes

# 不再内置任何 GoEasy / R2 账号、密钥、桶名、域名或容量值。
# 仅从环境变量或 env.json 读取；未配置时保持为空并禁用对应功能。
R2_ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID", "").strip()
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "").strip()
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "").strip()
R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME", "").strip()
R2_PUBLIC_URL = os.getenv("R2_PUBLIC_URL", "").strip()
try:
    R2_MAX_UPLOAD_MB = max(0, int(os.getenv("R2_MAX_UPLOAD_MB", "0") or 0))
except (TypeError, ValueError):
    R2_MAX_UPLOAD_MB = 0
try:
    R2_MAX_STORAGE_MB = max(0, int(os.getenv("R2_MAX_STORAGE_MB", "0") or 0))
except (TypeError, ValueError):
    R2_MAX_STORAGE_MB = 0

# Cloudflare API Token（可选，仅从外部配置读取）
CF_API_TOKEN = os.getenv("CF_API_TOKEN", "").strip()

# 内置下载器：Android 默认公共下载目录，可通过 DOWNLOAD_DIR 覆盖
DOWNLOAD_DIR = Path(os.getenv("DOWNLOAD_DIR", "/storage/emulated/0/Download")).expanduser()
DOWNLOAD_MAX_MB = int(os.getenv("DOWNLOAD_MAX_MB", "2048"))  # 内置下载最大容量（单位：MB，默认 2GB）
DOWNLOAD_MAX_BYTES = DOWNLOAD_MAX_MB * 1024 * 1024
DOWNLOAD_TIMEOUT = max(10, float(os.getenv("DOWNLOAD_TIMEOUT", "300")))
DOWNLOAD_XOR_KEY = 0x5A
# 预计算 XOR 转换表：bytes.translate 是 C 层实现，单次分配、零中间对象。
# 原写法 bytes(b ^ KEY for b in chunk) 会为 1MB 分块生成 100 万个 Python int
# 与一个生成器，峰值内存可达数十 MB，且慢一个数量级。
_XOR_TABLE = bytes(i ^ DOWNLOAD_XOR_KEY for i in range(256))
# 流式分块大小：1MB → 256KB，降低每连接的常驻缓冲（多并发下差异明显）
DOWNLOAD_CHUNK_SIZE = 256 * 1024
_download_path_lock = threading.Lock()


def _cos_guess_file_type(filename: str, content_type: str) -> str:
    ct = (content_type or "").lower()
    name = (filename or "").lower()
    if ct.startswith("image/") or any(name.endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic")):
        return "image"
    if ct.startswith("video/") or any(name.endswith(ext) for ext in (".mp4", ".webm", ".mov", ".mkv", ".avi", ".m4v")):
        return "video"
    if ct.startswith("audio/") or any(name.endswith(ext) for ext in (".mp3", ".wav", ".ogg", ".m4a", ".aac", ".flac", ".amr", ".opus")):
        return "audio"
    return "file"


def _cos_safe_filename(name: str) -> str:
    """生成 R2 安全文件名：保留中文、字母、数字、点、短横、下划线、空格用下划线替换。"""
    base = Path(name or "file").name
    # 替换空格为下划线，移除路径不安全字符（保留中文、日文、韩文等 CJK、字母数字点短横下划线）
    base = base.replace(" ", "_")
    base = re.sub(r"[^\w.\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af\-]+", "", base, flags=re.UNICODE)
    return (base[:120] or "file")


def _download_filename_from_headers(headers: Any) -> str:
    """从 Content-Disposition 中读取下载文件名，兼容 filename*。"""
    value = str(headers.get("Content-Disposition", "") or "")
    match = re.search(r"filename\*\s*=\s*UTF-8''([^;]+)", value, re.I)
    if match:
        return urllib.parse.unquote(match.group(1).strip().strip('"'))
    match = re.search(r"filename\s*=\s*\"([^\"]+)\"", value, re.I)
    if match:
        return match.group(1)
    match = re.search(r"filename\s*=\s*([^;]+)", value, re.I)
    return match.group(1).strip().strip('"') if match else ""


def _download_unique_path(directory: Path, filename: str) -> Path:
    """在下载目录中生成不覆盖旧文件的目标路径。"""
    safe_name = _cos_safe_filename(filename or "download")
    stem = Path(safe_name).stem or "download"
    suffix = Path(safe_name).suffix
    with _download_path_lock:
        candidate = directory / safe_name
        index = 1
        while candidate.exists():
            candidate = directory / f"{stem} ({index}){suffix}"
            index += 1
        return candidate


def download_url_to_android(url: str, filename: str = "", xor: bool = False) -> dict[str, Any]:
    """将远程文件流式下载到 Android 公共 Download 目录。

    xor=True 用于下载上传时为绕过 R2 检测而 XOR 加密的文件，并在写入本地时还原。
    不把整个文件读入内存，适合视频、大文件和安装包。
    """
    parsed = urllib.parse.urlparse(str(url or "").strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("只支持 http/https 文件地址")

    try:
        DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        raise RuntimeError(f"无法创建下载目录 {DOWNLOAD_DIR}: {exc}") from exc
    if not DOWNLOAD_DIR.is_dir():
        raise RuntimeError(f"下载目录不可用：{DOWNLOAD_DIR}")

    req = urllib.request.Request(
        parsed.geturl(),
        headers={"User-Agent": f"{APP_NAME}/1.0", "Accept": "*/*"},
    )
    ctx_ssl = SSL_CTX  # 复用全局免校验上下文，避免重复加载 CA 证书库
    temp_path: Path | None = None
    try:
        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT, context=ctx_ssl) as resp:
            status = int(getattr(resp, "status", 200) or 200)
            if not 200 <= status < 400:
                raise RuntimeError(f"下载失败 HTTP {status}")

            header_name = _download_filename_from_headers(resp.headers)
            url_name = urllib.parse.unquote(Path(parsed.path).name)
            final_name = _cos_safe_filename(filename or header_name or url_name or "download")
            target_path = _download_unique_path(DOWNLOAD_DIR, final_name)
            temp_path = DOWNLOAD_DIR / f".{target_path.name}.{uuid.uuid4().hex[:8]}.part"

            content_length = 0
            try:
                content_length = int(resp.headers.get("Content-Length", "0") or 0)
            except (TypeError, ValueError):
                content_length = 0
            if content_length > DOWNLOAD_MAX_BYTES:
                raise ValueError(f"文件过大，最大允许 {DOWNLOAD_MAX_BYTES // (1024 * 1024)}MB")

            written = 0
            with open(temp_path, "wb") as out:
                while True:
                    chunk = resp.read(DOWNLOAD_CHUNK_SIZE)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > DOWNLOAD_MAX_BYTES:
                        raise ValueError(f"文件过大，最大允许 {DOWNLOAD_MAX_BYTES // (1024 * 1024)}MB")
                    if xor:
                        chunk = chunk.translate(_XOR_TABLE)
                    out.write(chunk)
                out.flush()
                try:
                    os.fsync(out.fileno())
                except OSError:
                    pass

            os.replace(temp_path, target_path)
            temp_path = None
            return {
                "file_name": target_path.name,
                "file_path": str(target_path),
                "directory": str(DOWNLOAD_DIR),
                "file_size": written,
                "mime_type": resp.headers.get("Content-Type", "application/octet-stream"),
                "xor_restored": bool(xor),
            }
    except urllib.error.HTTPError as exc:
        detail = exc.read(256).decode("utf-8", errors="replace") if exc.fp else ""
        raise RuntimeError(f"下载失败 HTTP {exc.code}{(': ' + detail[:120]) if detail else ''}") from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise RuntimeError(f"下载失败：{reason}") from exc
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def stream_url_to_browser(handler: BaseHTTPRequestHandler, url: str, filename: str = "",
                          xor: bool = False, mime_hint: str = "") -> None:
    """把远程文件流式转发给当前浏览器下载，不写入服务端 Android Download 目录。

    公网模式使用该响应；xor=True 时边转发边还原 .dlp 内容，避免把大文件整体读入内存。
    """
    parsed = urllib.parse.urlparse(str(url or "").strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("只支持 http/https 文件地址")

    req = urllib.request.Request(
        parsed.geturl(),
        headers={"User-Agent": f"{APP_NAME}/1.0", "Accept": "*/*"},
    )
    ctx_ssl = SSL_CTX  # 复用全局免校验上下文，避免重复加载 CA 证书库

    with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT, context=ctx_ssl) as resp:
        status = int(getattr(resp, "status", 200) or 200)
        if not 200 <= status < 400:
            raise RuntimeError(f"下载失败 HTTP {status}")

        header_name = _download_filename_from_headers(resp.headers)
        url_name = urllib.parse.unquote(Path(parsed.path).name)
        final_name = _cos_safe_filename(filename or header_name or url_name or "download")

        content_length = 0
        try:
            content_length = int(resp.headers.get("Content-Length", "0") or 0)
        except (TypeError, ValueError):
            content_length = 0
        if content_length > DOWNLOAD_MAX_BYTES:
            raise ValueError(f"文件过大，最大允许 {DOWNLOAD_MAX_BYTES // (1024 * 1024)}MB")

        content_type = str(mime_hint or resp.headers.get("Content-Type", "application/octet-stream") or "application/octet-stream")
        # 防止响应头注入；只接受常规 MIME 形式。
        if not re.fullmatch(r"[A-Za-z0-9.+_-]+/[A-Za-z0-9.+_-]+(?:\s*;\s*charset=[A-Za-z0-9._-]+)?", content_type):
            content_type = "application/octet-stream"

        ascii_name = re.sub(r"[^A-Za-z0-9._-]+", "_", final_name).strip("._")
        if not ascii_name:
            suffix = Path(final_name).suffix
            ascii_name = "download" + (suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,10}", suffix or "") else "")
        encoded_name = urllib.parse.quote(final_name, safe="")

        handler._browser_download_started = True
        handler.send_response(200)
        handler.send_header("Content-Type", content_type)
        handler.send_header(
            "Content-Disposition",
            'attachment; filename="{}"; filename*=UTF-8\'\'{}'.format(ascii_name, encoded_name),
        )
        if content_length > 0:
            handler.send_header("Content-Length", str(content_length))
        handler.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.end_headers()

        written = 0
        while True:
            chunk = resp.read(DOWNLOAD_CHUNK_SIZE)
            if not chunk:
                break
            written += len(chunk)
            if written > DOWNLOAD_MAX_BYTES:
                raise ValueError(f"文件过大，最大允许 {DOWNLOAD_MAX_BYTES // (1024 * 1024)}MB")
            if xor:
                chunk = chunk.translate(_XOR_TABLE)
            handler.wfile.write(chunk)

        info(f"[浏览器下载] 已转发 name={final_name} size={written} xor={xor}")


def _r2_authorization(method: str, object_key: str, headers: dict[str, str],
                       params: dict[str, str] | None = None,
                       data: bytes = b"") -> tuple[str, str]:
    """Cloudflare R2 AWS Signature V4（零第三方依赖）。"""
    params = params or {}
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    
    # R2 Endpoint
    host = f"{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
    region = "auto"
    service = "s3"
    
    # Canonical Request
    canonical_uri = "/" + object_key.lstrip("/")
    canonical_querystring = "&".join(
        f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(params[k]), safe='')}"
        for k in sorted(params.keys())
    )
    
    header_map = {k.lower(): str(v).strip() for k, v in headers.items()}
    header_list = sorted(header_map.keys())
    signed_headers = ";".join(header_list)
    
    canonical_headers = "\n".join(
        f"{k}:{header_map[k]}" for k in header_list
    ) + "\n"
    
    payload_hash = hashlib.sha256(data).hexdigest()
    
    canonical_request = (
        f"{method}\n"
        f"{canonical_uri}\n"
        f"{canonical_querystring}\n"
        f"{canonical_headers}\n"
        f"{signed_headers}\n"
        f"{payload_hash}"
    )
    
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    
    hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    
    string_to_sign = (
        f"{algorithm}\n"
        f"{amz_date}\n"
        f"{credential_scope}\n"
        f"{hashed_canonical_request}"
    )
    
    # Signing Key
    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
    
    k_date = _sign(("AWS4" + R2_SECRET_ACCESS_KEY).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")
    
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    
    authorization = (
        f"{algorithm} "
        f"Credential={R2_ACCESS_KEY_ID}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )
    
    return authorization, amz_date


def r2_put_object(data: bytes, object_key: str, content_type: str = "application/octet-stream") -> str:
    """上传对象到 R2，返回公共 URL。"""
    if not R2_ACCOUNT_ID or not R2_ACCESS_KEY_ID or not R2_SECRET_ACCESS_KEY or not R2_BUCKET_NAME:
        raise RuntimeError("R2 未配置，请设置环境变量 R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET_NAME")
    
    object_key = object_key.lstrip("/")
    host = f"{R2_BUCKET_NAME}.{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
    
    headers = {
        "Host": host,
        "Content-Type": content_type or "application/octet-stream",
        "Content-Length": str(len(data)),
        "x-amz-content-sha256": hashlib.sha256(data).hexdigest(),
    }
    
    auth, amz_date = _r2_authorization("PUT", object_key, headers, data=data)
    headers["Authorization"] = auth
    headers["x-amz-date"] = amz_date
    
    url = f"https://{host}/{object_key}"
    req = urllib.request.Request(url, data=data, method="PUT", headers=headers)
    
    ctx_ssl = SSL_CTX  # 复用全局免校验上下文，避免重复加载 CA 证书库
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx_ssl) as resp:
            if resp.status not in (200, 201):
                body = resp.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"R2 上传失败 HTTP {resp.status}: {body[:200]}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
        raise RuntimeError(f"R2 上传失败 HTTP {e.code}: {body[:300]}") from e

    return r2_public_object_url(object_key)


def r2_public_object_url(object_key: str, version: str = "") -> str:
    """生成对象公共 URL；version 用于覆盖同名头像后的浏览器缓存刷新。"""
    clean_key = str(object_key or "").lstrip("/")
    if R2_PUBLIC_URL:
        url = f"{R2_PUBLIC_URL.rstrip('/')}/{clean_key}"
    else:
        url = f"https://{R2_BUCKET_NAME}.{R2_ACCOUNT_ID}.r2.dev/{clean_key}"
    if version:
        url += "?v=" + urllib.parse.quote(str(version), safe="")
    return url


def avatar_object_key(user_id: str, extension: str = ".png") -> str:
    """使用用户 ID 哈希生成稳定对象键：同一 ID 重装/异地登录仍指向同一头像。"""
    uid = str(user_id or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,64}", uid):
        raise ValueError("用户 ID 格式无效")
    ext = extension.lower() if extension.lower() in {".png", ".jpg", ".jpeg", ".webp"} else ".png"
    if ext == ".jpeg":
        ext = ".jpg"
    digest = hashlib.sha256(uid.encode("utf-8")).hexdigest()
    return f"avatars/{digest}{ext}"


def r2_head_object(object_key: str) -> dict[str, Any]:
    """通过签名 HEAD 判断 R2 对象是否存在，并返回 ETag 作为缓存版本。"""
    if not R2_ACCOUNT_ID or not R2_ACCESS_KEY_ID or not R2_SECRET_ACCESS_KEY or not R2_BUCKET_NAME:
        return {"exists": False, "etag": ""}
    clean_key = str(object_key or "").lstrip("/")
    host = f"{R2_BUCKET_NAME}.{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
    headers = {
        "Host": host,
        "x-amz-content-sha256": hashlib.sha256(b"").hexdigest(),
    }
    auth, amz_date = _r2_authorization("HEAD", clean_key, headers, data=b"")
    headers["Authorization"] = auth
    headers["x-amz-date"] = amz_date
    req = urllib.request.Request(f"https://{host}/{clean_key}", method="HEAD", headers=headers)
    ctx_ssl = SSL_CTX  # 复用全局免校验上下文，避免重复加载 CA 证书库
    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx_ssl) as resp:
            etag = str(resp.headers.get("ETag", "") or "").strip().strip('"')
            return {"exists": 200 <= int(getattr(resp, "status", 200) or 200) < 300, "etag": etag}
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 404):
            return {"exists": False, "etag": ""}
        raise


def find_r2_avatar(user_id: str) -> dict[str, Any]:
    """查找用户稳定头像对象；兼容未来格式及当前 PNG/JPEG/WebP。"""
    for ext in (".png", ".jpg", ".webp"):
        key = avatar_object_key(user_id, ext)
        meta = r2_head_object(key)
        if meta.get("exists"):
            version = str(meta.get("etag") or "")[:24]
            return {"exists": True, "object_key": key, "url": r2_public_object_url(key, version)}
    return {"exists": False, "object_key": "", "url": ""}


def get_r2_bucket_total_size() -> int:
    """通过 R2 S3 ListObjectsV2 计算当前桶总大小（字节）。"""
    if not R2_ACCOUNT_ID or not R2_ACCESS_KEY_ID or not R2_SECRET_ACCESS_KEY or not R2_BUCKET_NAME:
        return 0
    host = f"{R2_BUCKET_NAME}.{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
    total = 0
    continuation = ""
    ctx_ssl = SSL_CTX  # 复用全局免校验上下文，避免重复加载 CA 证书库
    while True:
        params = {"list-type": "2", "max-keys": "1000"}
        if continuation:
            params["continuation-token"] = continuation
        canonical_qs = "&".join(
            f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(params[k]), safe='')}"
            for k in sorted(params)
        )
        headers = {
            "Host": host,
            "x-amz-content-sha256": hashlib.sha256(b"").hexdigest(),
        }
        auth, amz_date = _r2_authorization("GET", "/", headers, params=params, data=b"")
        headers["Authorization"] = auth
        headers["x-amz-date"] = amz_date
        url = f"https://{host}/?{canonical_qs}"
        req = urllib.request.Request(url, method="GET", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30, context=ctx_ssl) as resp:
                xml_data = resp.read()
        except Exception as exc:
            err(f"[R2] 获取列表失败: {exc}")
            return 0
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_data)
            # 去除 XML 命名空间，兼容 S3/R2 列表响应
            for elem in root.iter():
                if isinstance(elem.tag, str) and '}' in elem.tag:
                    elem.tag = elem.tag.split('}', 1)[1]
            for contents in root.iter("Contents"):
                size_el = contents.find("Size")
                if size_el is not None and size_el.text:
                    try:
                        total += int(size_el.text)
                    except ValueError:
                        pass
            truncated_el = root.find("IsTruncated")
            is_truncated = truncated_el is not None and truncated_el.text == "true"
            next_token_el = root.find("NextContinuationToken")
            continuation = (next_token_el.text or "") if (next_token_el is not None and next_token_el.text) else ""
            if not is_truncated:
                break
        except Exception as exc:
            err(f"[R2] XML 解析失败: {exc}")
            break
    return total


def disable_r2_public_access() -> bool:
    """调用 Cloudflare API 关闭 R2 公开访问（managed r2.dev）。"""
    token = os.getenv("CF_API_TOKEN", CF_API_TOKEN).strip()
    if not token:
        warn("[CF API] 缺少 CF_API_TOKEN，无法自动关闭公共访问")
        return False
    account_id = R2_ACCOUNT_ID
    bucket = R2_BUCKET_NAME
    if not account_id or not bucket:
        warn("[CF API] R2_ACCOUNT_ID 或 R2_BUCKET_NAME 为空，无法调用 API")
        return False
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/r2/buckets/{bucket}/domains/managed"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = json.dumps({"enabled": False}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="PUT", headers=headers)
    ctx_ssl = SSL_CTX  # 复用全局免校验上下文，避免重复加载 CA 证书库
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx_ssl) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            info(f"[CF API] 关闭公共访问成功 HTTP {resp.status}: {body[:200]}")
            return resp.status == 200
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
        err(f"[CF API] 关闭公共访问失败 HTTP {e.code}: {body[:300]}")
        return False
    except Exception as exc:
        err(f"[CF API] 关闭公共访问异常: {exc}")
        return False


def empty_r2_bucket(preserve_avatars: bool = True) -> bool:
    """清理 R2 存储桶；默认永久保留 avatars/ 下的用户头像。"""
    warn("[R2] ⚠️ 执行存储桶清理" + ("（保留用户头像）" if preserve_avatars else "（删除全部对象）"))
    if not R2_ACCOUNT_ID or not R2_ACCESS_KEY_ID or not R2_SECRET_ACCESS_KEY or not R2_BUCKET_NAME:
        err("[R2] 清空存储桶失败：R2 未配置")
        return False
    host = f"{R2_BUCKET_NAME}.{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
    keys: list[str] = []
    continuation = ""
    ctx_ssl = SSL_CTX  # 复用全局免校验上下文，避免重复加载 CA 证书库
    while True:
        params = {"list-type": "2", "max-keys": "1000"}
        if continuation:
            params["continuation-token"] = continuation
        canonical_qs = "&".join(
            f"{urllib.parse.quote(str(k), safe='')}={urllib.parse.quote(str(params[k]), safe='')}"
            for k in sorted(params)
        )
        headers = {
            "Host": host,
            "x-amz-content-sha256": hashlib.sha256(b"").hexdigest(),
        }
        auth, amz_date = _r2_authorization("GET", "/", headers, params=params, data=b"")
        headers["Authorization"] = auth
        headers["x-amz-date"] = amz_date
        url = f"https://{host}/?{canonical_qs}"
        req = urllib.request.Request(url, method="GET", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30, context=ctx_ssl) as resp:
                xml_data = resp.read()
        except Exception as exc:
            err(f"[R2] 清空存储桶 - 列表失败: {exc}")
            return False
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_data)
            for elem in root.iter():
                if isinstance(elem.tag, str) and '}' in elem.tag:
                    elem.tag = elem.tag.split('}', 1)[1]
            for contents in root.iter("Contents"):
                key_el = contents.find("Key")
                if key_el is not None and key_el.text:
                    keys.append(key_el.text)
            truncated_el = root.find("IsTruncated")
            is_truncated = truncated_el is not None and truncated_el.text == "true"
            next_token_el = root.find("NextContinuationToken")
            continuation = (next_token_el.text or "") if (next_token_el is not None and next_token_el.text) else ""
            if not is_truncated:
                break
        except Exception as exc:
            err(f"[R2] 清空存储桶 - XML 解析失败: {exc}")
            break
    total_deleted = 0
    preserved = 0
    for key in keys:
        try:
            clean_key = key.lstrip("/")
            if preserve_avatars and clean_key.startswith("avatars/"):
                preserved += 1
                continue
            del_headers = {
                "Host": host,
                "x-amz-content-sha256": hashlib.sha256(b"").hexdigest(),
            }
            auth_del, amz_del = _r2_authorization("DELETE", "/" + clean_key, del_headers, data=b"")
            del_headers["Authorization"] = auth_del
            del_headers["x-amz-date"] = amz_del
            del_url = f"https://{host}/{clean_key}"
            del_req = urllib.request.Request(del_url, method="DELETE", headers=del_headers)
            with urllib.request.urlopen(del_req, timeout=30, context=ctx_ssl) as resp:
                total_deleted += 1
        except Exception as exc:
            err(f"[R2] 清空存储桶 - 删除对象 {key} 失败: {exc}")
    info(f"[R2] 存储桶清理完成，删除对象数: {total_deleted}，保留头像数: {preserved}")
    return True


def check_r2_bucket_capacity(source: str = "检查") -> int:
    """检查 R2 桶容量：记录当前大小与剩余空间；达上限则清理聊天媒体并保留头像。"""
    if not (
        R2_ACCOUNT_ID and R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY and R2_BUCKET_NAME
        and R2_MAX_STORAGE_MB > 0
    ):
        return 0
    try:
        sz = get_r2_bucket_total_size()
        used_mb = sz // (1024 * 1024)
        info(f"[R2 {source}] 当前桶总大小: {used_mb} MB ({sz} bytes)")
        limit_bytes = R2_MAX_STORAGE_MB * 1024 * 1024
        if sz >= limit_bytes:
            info(f"[R2 {source}] ⚠️ 已达到 {R2_MAX_STORAGE_MB}MB 上限，清理聊天媒体并保留头像")
            empty_r2_bucket(preserve_avatars=True)
        else:
            remaining_mb = max(0, (limit_bytes - sz) // (1024 * 1024))
            info(f"[R2 {source}] 距离 {R2_MAX_STORAGE_MB}MB 上限还有 {remaining_mb}MB 空间")
        return sz
    except Exception as e:
        err(f"[R2 {source}] 失败: {e}")
        return 0


def parse_multipart(body: bytes, content_type: str) -> list[dict[str, Any]]:
    """简易 multipart/form-data 解析，返回 parts: name/filename/content_type/data。

    内存优化：原实现用 body.split(delimiter) 一次性切出所有段，等于把整个
    请求体再复制一份（10MB 上传 → 瞬时 +10MB），随后 chunk[2:]/[:-2] 等
    切片又各复制一次。这里改为：
    - 用 find() 逐段定位，只记录 (start, end) 偏移；
    - 头部用小切片解析；
    - 段体用 memoryview 零拷贝定位，只在最后对真正需要的字段物化一次 bytes。
    峰值内存从约 3×文件大小降到约 1×。
    """
    m = re.search(r"boundary=([^;]+)", content_type or "", re.I)
    if not m:
        raise ValueError("缺少 multipart boundary")
    boundary = m.group(1).strip().strip('"').encode("utf-8")
    delimiter = b"--" + boundary
    parts: list[dict[str, Any]] = []
    view = memoryview(body)
    dlen = len(delimiter)

    pos = body.find(delimiter)
    while pos >= 0:
        start = pos + dlen
        nxt = body.find(delimiter, start)
        end = nxt if nxt >= 0 else len(body)
        pos = nxt

        # 归一化段边界（去掉分隔符后的 CRLF、段尾 CRLF 与结束标记 "--"）
        if body[start:start + 2] == b"\r\n":
            start += 2
        elif body[start:start + 2] == b"--":
            continue  # 结束分隔符 "--boundary--"
        # 只剥离紧邻下一个分隔符的那一个 CRLF（与原实现语义一致）
        if end - start >= 2 and body[end - 2:end] == b"\r\n":
            end -= 2
        if end <= start:
            continue

        sep = body.find(b"\r\n\r\n", start, end)
        if sep < 0 or sep >= end:
            continue
        header_blob = bytes(view[start:sep]).decode("utf-8", errors="replace")
        data_start, data_end = sep + 4, end
        # data 保持为 memoryview 切片，调用方按需 bytes() 物化
        data = view[data_start:data_end]
        name = ""
        filename = ""
        ctype = "application/octet-stream"
        for line in header_blob.split("\r\n"):
            if line.lower().startswith("content-disposition:"):
                nm = re.search(r'name="([^"]*)"', line)
                fn = re.search(r'filename="([^"]*)"', line)
                # RFC 5987: filename*=UTF-8''encoded_name
                fn_star = re.search(r"filename\*=?UTF-8''([^\";\s]+)", line, re.I) if not fn else None
                if nm:
                    name = nm.group(1)
                if fn:
                    filename = fn.group(1)
                elif fn_star:
                    filename = urllib.parse.unquote(fn_star.group(1))
            elif line.lower().startswith("content-type:"):
                ctype = line.split(":", 1)[1].strip()
        parts.append({
            "name": name,
            "filename": filename,
            "content_type": ctype,
            "data": data,
        })
    return parts


# ============================================================================
# SECTION 3.6 · 环境变量配置（env.json 可视化编辑）
# 将 GoEasy（聊天）与 Cloudflare R2（存储桶）两类配置分开保存到一个
# JSON 文件里；若文件不存在会自动创建。保存 R2 配置后会即时应用到运行时。
# 安全密码（加盐哈希）也一并保存在 env.json 的 security 字段中。
# ============================================================================

ENV_CONFIG_FILE = str(SCRIPT_DIR / "env.json")

# 默认配置不含任何服务值；可通过环境变量预置，或在网页设置中手动填写。
DEFAULT_ENV_CONFIG: dict[str, Any] = {
    "goeasy": {
        "appkey": os.getenv("GOEASY_APPKEY", "").strip(),
        "host": os.getenv("GOEASY_HOST", "").strip(),
        "force_tls": True,
    },
    "cloudflare_r2": {
        "account_id": R2_ACCOUNT_ID,
        "access_key_id": R2_ACCESS_KEY_ID,
        "secret_access_key": R2_SECRET_ACCESS_KEY,
        "bucket_name": R2_BUCKET_NAME,
        "public_url": R2_PUBLIC_URL,
        "max_upload_mb": R2_MAX_UPLOAD_MB if R2_MAX_UPLOAD_MB > 0 else "",
        "max_storage_mb": R2_MAX_STORAGE_MB if R2_MAX_STORAGE_MB > 0 else "",
        "cf_api_token": CF_API_TOKEN,
    },
    "security": {                           # 新增：存储密码哈希
        "password_hash": "",
        "salt": "",
        "set_at": 0.0,
    },
}


def ensure_env_config() -> str:
    """若 env.json 不存在则用默认值自动创建，返回文件路径。"""
    p = Path(ENV_CONFIG_FILE)
    if p.is_file():
        return ENV_CONFIG_FILE
    try:
        p.write_text(
            json.dumps(DEFAULT_ENV_CONFIG, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        info(f"[env配置] 未检测到环境变量配置文件，已自动创建: {ENV_CONFIG_FILE}")
    except Exception as exc:
        err(f"[env配置] 自动创建配置文件失败: {exc}")
    return ENV_CONFIG_FILE


def load_env_config() -> dict[str, Any]:
    """读取环境变量配置；文件不存在时返回默认值，但**不自动创建** env.json。

    按需求：env.json 只在「设置安全密码」或「保存环境变量」时才生成，
    纯读取路径（启动、安全检测、上传前刷新等）一律不落盘。
    """
    try:
        data = json.loads(Path(ENV_CONFIG_FILE).read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
        warn("[env配置] 配置文件格式不是对象，使用默认值")
    except FileNotFoundError:
        # 文件未生成：返回默认配置，不创建文件
        return copy.deepcopy(DEFAULT_ENV_CONFIG)
    except Exception as exc:
        err(f"[env配置] 读取配置文件失败: {exc}")
    return copy.deepcopy(DEFAULT_ENV_CONFIG)


def _build_runtime_env_config(cfg: dict[str, Any]) -> dict[str, Any]:
    """聊天启动所需的最小公开配置（不含 R2 密钥等敏感字段）。

    GoEasy appkey 属于客户端 SDK 密钥，聊天功能必须下发；完整 env 仍受密码保护。
    """
    src = cfg if isinstance(cfg, dict) else {}
    go = src.get("goeasy") if isinstance(src.get("goeasy"), dict) else {}
    r2 = src.get("cloudflare_r2") if isinstance(src.get("cloudflare_r2"), dict) else {}
    return {
        "goeasy": {
            "appkey": str(go.get("appkey", "") or "").strip(),
            "host": str(go.get("host", "") or "").strip(),
            "force_tls": bool(go.get("force_tls", True)),
        },
        "cloudflare_r2": {
            "max_upload_mb": r2.get("max_upload_mb", "") if r2.get("max_upload_mb", "") != "" else "",
            "max_storage_mb": r2.get("max_storage_mb", "") if r2.get("max_storage_mb", "") != "" else "",
        },
    }


def apply_r2_config_to_runtime(cfg: dict[str, Any]) -> None:
    """把 cloudflare_r2 配置即时应用到运行时的全局变量（上传接口立即生效）。"""
    global R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, \
        R2_BUCKET_NAME, R2_PUBLIC_URL, R2_MAX_UPLOAD_MB, R2_MAX_STORAGE_MB, \
        CF_API_TOKEN
    r2 = cfg.get("cloudflare_r2") if isinstance(cfg, dict) else {}
    if not isinstance(r2, dict):
        r2 = {}
    R2_ACCOUNT_ID = str(r2.get("account_id", "") or "").strip()
    R2_ACCESS_KEY_ID = str(r2.get("access_key_id", "") or "").strip()
    R2_SECRET_ACCESS_KEY = str(r2.get("secret_access_key", "") or "").strip()
    R2_BUCKET_NAME = str(r2.get("bucket_name", "") or "").strip()
    R2_PUBLIC_URL = str(r2.get("public_url", "") or "").strip()
    try:
        R2_MAX_UPLOAD_MB = max(0, int(r2.get("max_upload_mb", 0) or 0))
    except (TypeError, ValueError):
        R2_MAX_UPLOAD_MB = 0
    try:
        R2_MAX_STORAGE_MB = max(0, int(r2.get("max_storage_mb", 0) or 0))
    except (TypeError, ValueError):
        R2_MAX_STORAGE_MB = 0
    CF_API_TOKEN = str(r2.get("cf_api_token", "") or "").strip()


# env.json 上次应用的时间戳（mtime_ns），用于检测文件是否被外部移动/恢复/编辑
_env_config_applied_mtime: int | None = None


def reload_r2_config_if_changed() -> None:
    """若 env.json 在磁盘上被外部改动（移动后再放回、编辑等），重新应用到运行时。

    问题背景：R2 凭据存放在模块级全局变量中，原本只在进程启动时
    （main 里 apply_r2_config_to_runtime）和应用内保存（/api/env/save）时更新。
    一旦 env.json 被移出再放回，运行时的 R2 全局仍是旧的空值，
    导致聊天/头像上传全部失败，直到重启或重新保存。
    此函数以文件 mtime 为指纹，检测到变化即重新读取并应用。
    """
    global _env_config_applied_mtime
    path = Path(ENV_CONFIG_FILE)
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        mtime = None
    if mtime is not None and mtime == _env_config_applied_mtime:
        return  # 未变化，跳过磁盘读取与应用
    cfg = load_env_config()
    apply_r2_config_to_runtime(cfg)
    _env_config_applied_mtime = mtime


def save_env_config(data: dict[str, Any]) -> dict[str, Any]:
    """合并并保存环境变量配置（支持任意顶层键，包括 security），随后把 R2 配置应用到运行时。"""
    ensure_env_config()
    # 读取现有配置
    try:
        existing = json.loads(Path(ENV_CONFIG_FILE).read_text(encoding="utf-8"))
        if not isinstance(existing, dict):
            existing = {}
    except Exception:
        existing = {}

    # 深度合并传入的数据（递归合并字典，其他类型直接覆盖）
    for key, value in data.items():
        if isinstance(value, dict) and key in existing and isinstance(existing[key], dict):
            existing[key].update(value)
        else:
            existing[key] = value

    # 确保必要 section 存在
    for section in ("goeasy", "cloudflare_r2", "security"):
        if section not in existing:
            existing[section] = {}

    Path(ENV_CONFIG_FILE).write_text(
        json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    # 应用 R2 配置
    if "cloudflare_r2" in existing:
        apply_r2_config_to_runtime(existing)

    # 记录本次应用后的文件 mtime，避免紧接着的上传重复读取磁盘
    global _env_config_applied_mtime
    try:
        _env_config_applied_mtime = Path(ENV_CONFIG_FILE).stat().st_mtime_ns
    except OSError:
        _env_config_applied_mtime = None

    info(f"[env配置] 环境变量配置已保存并应用: {ENV_CONFIG_FILE}")
    return existing


# ============================================================================
# SECTION 3.7 · 环境变量配置安全（公网强制密码 + 局域网跳过）
# 安全密码（加盐哈希）保存在 env.json 的 security 字段中；一旦设置，
# 之后无论局域网/公网修改配置都需输入正确密码。
# ============================================================================

# 注意：不再使用独立的 SECURITY_FILE 常量，所有数据存于 env.json 的 security 字段。

# 局域网/保留地址段一律视为「非公网」
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("10.0.0.0/8"),       # 私网 A 类
    ipaddress.ip_network("172.16.0.0/12"),    # 私网 B 类
    ipaddress.ip_network("192.168.0.0/16"),   # 私网 C 类
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("fc00::/7"),         # IPv6 唯一本地
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("0.0.0.0/8"),        # 本网络
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT 运营商 NAT
)


def is_lan_ip(client_ip: str) -> bool:
    """判断来源 IP 是否属于局域网/本机（含 localhost）；无法解析时视为安全。"""
    if not client_ip:
        return True
    s = str(client_ip).strip().lower()
    # 去除 IPv6 端口/方括号
    if s.startswith("["):
        s = s[1:].split("]")[0]
    if "%" in s:            # IPv6 zone id
        s = s.split("%")[0]
    if s in ("localhost", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return True  # 非 IP（如主机名）视为安全
    if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved or addr.is_multicast:
        return True
    for net in _PRIVATE_NETWORKS:
        if addr.version == net.version and addr in net:
            return True
    return False


def _normalize_request_ip(value: Any) -> str:
    """从代理头/连接信息中提取一个可解析的纯 IP（兼容引号、IPv6 方括号和端口）。"""
    raw = str(value or "").strip().strip('"').strip("'")
    if not raw:
        return ""
    # RFC 7239: for=1.2.3.4 / for="[2001:db8::1]:1234"
    if raw.lower().startswith("for="):
        raw = raw[4:].strip().strip('"').strip("'")
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    elif raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            raw = host
    if "%" in raw:
        raw = raw.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def get_request_client_ip(handler: Any) -> str:
    """获取真实客户端 IP。

    直连来源是公网时永远优先使用连接 IP，防止伪造转发头把公网请求冒充成局域网；
    只有连接来自本机/局域网反向代理时，才读取 Cloudflare/X-Forwarded-* 等头。
    """
    peer = ""
    try:
        peer = _normalize_request_ip(handler.client_address[0] if handler.client_address else "")
    except Exception:
        peer = ""
    if peer and not is_lan_ip(peer):
        return peer

    candidates: list[str] = []
    try:
        headers = handler.headers
        for key in ("CF-Connecting-IP", "True-Client-IP", "X-Real-IP"):
            value = headers.get(key, "")
            if value:
                candidates.append(value)
        # 标准 XFF 左侧为原始客户端；逐个检查以兼容多级代理。
        xff = headers.get("X-Forwarded-For", "")
        if xff:
            candidates.extend(part.strip() for part in xff.split(","))
        forwarded = headers.get("Forwarded", "")
        if forwarded:
            for item in forwarded.split(","):
                for token in item.split(";"):
                    if token.strip().lower().startswith("for="):
                        candidates.append(token.strip())
    except Exception:
        pass

    first_valid = ""
    for value in candidates:
        candidate = _normalize_request_ip(value)
        if not candidate:
            continue
        if not first_valid:
            first_valid = candidate
        if not is_lan_ip(candidate):
            return candidate
    return first_valid or peer


def _request_host_name(handler: Any) -> str:
    """提取访问 Host，作为未传递真实 IP 的反向代理场景兜底。"""
    try:
        raw = str(handler.headers.get("X-Forwarded-Host", "") or handler.headers.get("Host", "")).split(",", 1)[0].strip()
    except Exception:
        return ""
    if not raw:
        return ""
    # urlsplit 能正确处理 [IPv6]:port；无 scheme 时补 //。
    try:
        return (urllib.parse.urlsplit("//" + raw).hostname or "").strip().lower()
    except Exception:
        return raw.strip("[]").split(":", 1)[0].lower()


def is_public_request(handler: Any) -> tuple[bool, str]:
    """判断本次页面访问是否来自公网，返回 (is_public, effective_client_ip)。"""
    client_ip = get_request_client_ip(handler)
    if client_ip and not is_lan_ip(client_ip):
        return True, client_ip

    # 直连的私网来源明确属于局域网。只有连接来自本机反向代理（常见于公网隧道）
    # 或拿不到连接 IP 时，才依据 Host 兜底，避免局域网自定义域名被误判为公网。
    peer_ip = ""
    try:
        peer_ip = _normalize_request_ip(handler.client_address[0] if handler.client_address else "")
        if peer_ip and not ipaddress.ip_address(peer_ip).is_loopback:
            return False, client_ip
    except Exception:
        pass

    # 本机反向代理若未传真实 IP，可依据访问域名兜底：本机/私网 Host 为局域网，其它域名为公网。
    host = _request_host_name(handler)
    if not host or host == "localhost" or host.endswith(".local") or host.endswith(".lan"):
        return False, client_ip
    try:
        addr = ipaddress.ip_address(host)
        return (not is_lan_ip(str(addr))), client_ip
    except ValueError:
        # 含点的普通域名按公网入口处理；Android 内置短主机名仍视为局域网。
        return ("." in host), client_ip


def _hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def load_security() -> dict[str, Any]:
    """从 env.json 读取 security 配置"""
    cfg = load_env_config()
    sec = cfg.get("security") if isinstance(cfg.get("security"), dict) else {}
    sec.setdefault("password_hash", "")
    sec.setdefault("salt", "")
    sec.setdefault("set_at", 0.0)
    return sec


def is_password_set() -> bool:
    return bool(load_security().get("password_hash"))


def verify_password(password: Any) -> bool:
    """校验密码；未设置密码时恒为通过。"""
    sec = load_security()
    h = sec.get("password_hash")
    if not h:
        return True
    salt = sec.get("salt", "")
    return h == _hash_password(str(password or ""), salt)


def set_security_password(password: str) -> bool:
    """设置/修改安全密码（存入 env.json 的 security 字段）。"""
    if not password or len(password) < 4:
        raise ValueError("安全密码长度至少为 4 位")
    salt = secrets.token_hex(16)
    new_hash = _hash_password(password, salt)

    cfg = load_env_config()
    cfg["security"] = {
        "password_hash": new_hash,
        "salt": salt,
        "set_at": time.time(),
    }
    save_env_config(cfg)
    info(f"[安全] 环境变量配置安全密码已保存至 {ENV_CONFIG_FILE}")
    return True


_download_status_lock = threading.Lock()
_download_status: dict[str, Any] = {
    "chinese_db_last_success": 0.0,
    "chinese_db_last_error": "",
    "servers_last_success": 0.0,
    "servers_last_error": "",
    "remote_servers_available": False,
}


def _download_remote_file(url: str, dest_path: str) -> bool:
    tmp_path = f"{dest_path}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp"
    for cand_url in _remote_candidate_urls(url):
        try:
            req = urllib.request.Request(
                cand_url,
                headers={"User-Agent": f"{APP_NAME}/1.0", "Accept": "application/json"}
            )
            ctx_ssl = SSL_CTX  # 复用全局免校验上下文，避免重复加载 CA 证书库
            with urllib.request.urlopen(req, timeout=10, context=ctx_ssl) as resp:
                data = resp.read()
                json.loads(data.decode("utf-8-sig"))
                with open(tmp_path, "wb") as f:
                    f.write(data)
                os.replace(tmp_path, dest_path)
                if cand_url != url:
                    info(f"[远程下载] 经代理成功 {cand_url}")
                return True
        except Exception as exc:
            warn(f"[远程下载] 下载失败 {cand_url} -> {dest_path}: {exc}")
            continue
    try:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    except OSError:
        pass
    return False


def remote_download_worker():
    while True:
        try:
            ok_db = _download_remote_file(REMOTE_CHINESE_DB_URL, LOCAL_CHINESE_DB_FILE)
            with _download_status_lock:
                st = _download_status
                if ok_db:
                    st["chinese_db_last_success"] = time.time()
                    st["chinese_db_last_error"] = ""
                    info("[远程下载] ✅ 标题映射已更新")
                else:
                    st["chinese_db_last_error"] = "下载失败"

            ok_srv = _download_remote_file(REMOTE_SERVERS_URL, LOCAL_SERVERS_FILE)
            with _download_status_lock:
                st = _download_status
                if ok_srv:
                    st["servers_last_success"] = time.time()
                    st["servers_last_error"] = ""
                    st["remote_servers_available"] = True
                    info("[远程下载] ✅ 服务器列表已更新")
                else:
                    st["servers_last_error"] = "下载失败"
                    if not Path(LOCAL_SERVERS_FILE).is_file():
                        st["remote_servers_available"] = False
        except Exception as exc:
            err(f"[远程下载] 意外错误: {exc}")
        time.sleep(REMOTE_DOWNLOAD_INTERVAL)


# ============================================================================
# SECTION 4.5 · 前后端远程更新（哈希对比手动更新 + 启动时前端缺失自动下载）
# ============================================================================

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _sha256_file(path: Path) -> str | None:
    try:
        if not path.is_file():
            return None
        return _sha256_bytes(path.read_bytes())
    except Exception:
        return None

def _fetch_remote_bytes(url: str, timeout: float = 15) -> bytes | None:
    urls = _remote_candidate_urls(url)
    for u in urls:
        try:
            req = urllib.request.Request(u, headers={"User-Agent": f"{APP_NAME}/1.0"})
            ctx = SSL_CTX  # 复用全局免校验上下文
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if 200 <= resp.status < 300:
                    return resp.read()
        except Exception as e:
            warn(f"[更新] 拉取远程失败 {u}: {e}")
            continue
    return None

def ensure_frontend_exists() -> None:
    fp = Path(LOCAL_FRONTEND_FILE)
    if fp.is_file() and fp.stat().st_size > 0:
        return
    info("[更新] 未检测到前端文件 script.js，尝试从远程下载…")
    data = _fetch_remote_bytes(REMOTE_FRONTEND_URL)
    if data and len(data) > 100:
        try:
            tmp = str(fp) + f".tmp.{uuid.uuid4().hex[:6]}"
            Path(tmp).write_bytes(data)
            os.replace(tmp, str(fp))
            info(f"[更新] ✅ 前端已自动下载 {len(data)} bytes hash={_sha256_bytes(data)[:8]}")
        except Exception as e:
            err(f"[更新] 前端自动下载写入失败: {e}")
    else:
        warn("[更新] 前端自动下载失败（远程无数据）")

def check_update_status() -> dict[str, Any]:
    frontend_local = _sha256_file(Path(LOCAL_FRONTEND_FILE))
    fe_data = _fetch_remote_bytes(REMOTE_FRONTEND_URL)
    fe_remote = _sha256_bytes(fe_data) if fe_data else None
    be_data = _fetch_remote_bytes(REMOTE_BACKEND_URL)
    backend_local = _sha256_file(Path(LOCAL_BACKEND_FILE))
    backend_remote = _sha256_bytes(be_data) if be_data else None
    backend_need = bool(backend_remote and backend_local != backend_remote)
    return {
        "frontend": {
            "local_hash": frontend_local,
            "remote_hash": fe_remote,
            "need_update": bool(fe_remote and frontend_local != fe_remote),
            "local_exists": frontend_local is not None,
            "remote_available": fe_remote is not None,
        },
        "backend": {
            "local_hash": backend_local,
            "remote_hash": backend_remote,
            "need_update": backend_need,
            "remote_available": backend_remote is not None,
            "mode": "py",
        },
    }

def do_update_frontend() -> dict[str, Any]:
    fp = Path(LOCAL_FRONTEND_FILE)
    local_hash = _sha256_file(fp)
    data = _fetch_remote_bytes(REMOTE_FRONTEND_URL)
    if not data:
        return {"ok": False, "error": "远程前端获取失败", "skipped": False}
    remote_hash = _sha256_bytes(data)
    if local_hash == remote_hash:
        return {"ok": True, "skipped": True, "message": "前端已是最新，无需更新", "local_hash": local_hash, "remote_hash": remote_hash}
    try:
        tmp = str(fp) + f".tmp.{uuid.uuid4().hex[:6]}"
        Path(tmp).write_bytes(data)
        os.replace(tmp, str(fp))
        info(f"[更新] ✅ 前端已更新 {local_hash[:8] if local_hash else 'none'} -> {remote_hash[:8]}")
        return {"ok": True, "skipped": False, "message": "前端更新完成请重启应用", "local_hash": local_hash, "remote_hash": remote_hash}
    except Exception as e:
        return {"ok": False, "error": str(e), "skipped": False}

def do_update_backend() -> dict[str, Any]:
    fp = Path(LOCAL_BACKEND_FILE)
    data = _fetch_remote_bytes(REMOTE_BACKEND_URL)
    if not data:
        return {"ok": False, "error": "远程后端获取失败", "skipped": False}
    local_hash = _sha256_file(fp)
    remote_hash = _sha256_bytes(data)
    if local_hash == remote_hash:
        return {"ok": True, "skipped": True, "message": "后端已是最新，无需更新", "local_hash": local_hash, "remote_hash": remote_hash, "mode": "py"}
    try:
        try:
            tmp = str(fp) + f".tmp.{uuid.uuid4().hex[:6]}"
            Path(tmp).write_bytes(data)
            os.replace(tmp, str(fp))
        except Exception:
            if not fp.is_file():
                tmp = str(fp) + f".tmp.{uuid.uuid4().hex[:6]}"
                Path(tmp).write_bytes(data)
                os.replace(tmp, str(fp))
        info(f"[更新] ✅ 后端已更新 {local_hash[:8] if local_hash else 'none'} -> {remote_hash[:8]} [py]")
        return {"ok": True, "skipped": False, "message": "后端更新完成请重启应用", "local_hash": local_hash, "remote_hash": remote_hash, "mode": "py"}
    except Exception as e:
        return {"ok": False, "error": str(e), "skipped": False}

def start_remote_download_thread():
    def _first_then_loop():
        try:
            ok_db = _download_remote_file(REMOTE_CHINESE_DB_URL, LOCAL_CHINESE_DB_FILE)
            with _download_status_lock:
                if ok_db:
                    _download_status["chinese_db_last_success"] = time.time()
                    info("[远程下载] ✅ 首次标题映射下载成功")
                else:
                    _download_status["chinese_db_last_error"] = "首次下载失败"

            ok_srv = _download_remote_file(REMOTE_SERVERS_URL, LOCAL_SERVERS_FILE)
            with _download_status_lock:
                if ok_srv:
                    _download_status["servers_last_success"] = time.time()
                    _download_status["remote_servers_available"] = True
                    info("[远程下载] ✅ 首次服务器列表下载成功")
                else:
                    _download_status["servers_last_error"] = "首次下载失败"
                    if not Path(LOCAL_SERVERS_FILE).is_file():
                        _download_status["remote_servers_available"] = False
        except Exception as exc:
            err(f"[远程下载] 首次下载异常: {exc}")
        remote_download_worker()

    t = threading.Thread(target=_first_then_loop, daemon=True, name="remote-downloader")
    t.start()
    info(f"[远程下载] 后台下载线程已启动，间隔 {REMOTE_DOWNLOAD_INTERVAL} 秒")

# ============================================================================
# SECTION 5 · 标题映射加载
# ============================================================================

# 标题映射加载结果缓存：避免每秒轮询 refresh_config 时重复刷日志
_game_titles_cache: dict[str, str] | None = None
_game_titles_mtime: float | None = None
_game_titles_logged_sig: str = ""


def load_game_titles() -> dict[str, str]:
    """加载标题映射；仅在文件变更或首次加载时写日志，避免跟随轮询重复叠加。

    内存优化：命中缓存时直接返回**共享只读字典**，不再 dict() 复制。
    chinese_db.json 常有上万条，原实现每次 refresh_config（每秒）都整份
    复制一遍，既吃内存又制造 GC 压力。调用方只做只读查询。
    """
    global _game_titles_cache, _game_titles_mtime, _game_titles_logged_sig
    local_path = Path(LOCAL_CHINESE_DB_FILE)
    mtime: float | None = None
    try:
        st = local_path.stat()
        mtime = st.st_mtime
    except OSError:
        mtime = None

    if _game_titles_cache is not None and mtime == _game_titles_mtime:
        return _game_titles_cache

    merged = dict(BUILTIN_GAME_TITLES)
    if not local_path.is_file():
        sig = f"builtin:{len(merged)}"
        if sig != _game_titles_logged_sig:
            info(f"[配置] 使用内置标题映射，共 {len(merged)} 条")
            _game_titles_logged_sig = sig
        _game_titles_cache = merged
        _game_titles_mtime = mtime
        return merged
    try:
        with open(local_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for k, v in data.items():
                if k and v:
                    merged[str(k).upper()] = str(v)
            sig = f"file:{len(data)}:{len(merged)}"
            if sig != _game_titles_logged_sig:
                info(f"[配置] 标题映射已加载: {len(data)} 条，合并后总数: {len(merged)}")
                _game_titles_logged_sig = sig
            _game_titles_cache = merged
            _game_titles_mtime = mtime
            return merged
        warn("[配置警告] 本地标题映射格式不正确")
    except Exception as exc:
        warn(f"[配置警告] 读取本地标题映射失败（{exc}）")
    sig = f"builtin-fallback:{len(merged)}"
    if sig != _game_titles_logged_sig:
        info(f"[配置] 使用内置标题映射，共 {len(merged)} 条")
        _game_titles_logged_sig = sig
    _game_titles_cache = merged
    _game_titles_mtime = mtime
    return merged

# ============================================================================
# SECTION 6 · TTL 缓存
# ============================================================================

@dataclass(slots=True)
class CacheItem:
    """slots 版缓存条目：去掉 __dict__，单条约省 100+ 字节。"""
    value: Any
    expires_at: float


class TTLCache:
    """轻量 TTL 缓存（内存优化版）。

    优化点：
    1. 不再 deepcopy。扫描结果（scan_server 产出）在写入缓存后即视为
       **只读快照**，调用方只读不改；原实现每秒 get/set 各深拷贝一次，
       一份数据在内存里同时存在 3 份，是常驻内存的主要来源。
    2. 过期条目惰性清理 + 定期批量清理，避免过期对象长期占着内存。
    3. max_items 从 2048 降到 256（实际条目数 = 服务器数，几十足够）。
    """

    __slots__ = ("_items", "_lock", "max_items", "_last_purge")

    def __init__(self, max_items: int = 256):
        self._items: OrderedDict[str, CacheItem] = OrderedDict()
        self._lock = threading.Lock()
        self.max_items = max_items
        self._last_purge = 0.0

    def get(self, key: str) -> Any | None:
        now = time.monotonic()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            if item.expires_at <= now:
                del self._items[key]
                return None
            return item.value

    def set(self, key: str, value: Any, ttl: float = CACHE_TTL) -> None:
        now = time.monotonic()
        with self._lock:
            self._items[key] = CacheItem(value, now + ttl)
            self._items.move_to_end(key)
            # 每 30 秒批量清理一次过期条目，避免死键常驻
            if now - self._last_purge > 30:
                self._last_purge = now
                for k in [k for k, v in self._items.items() if v.expires_at <= now]:
                    del self._items[k]
            while len(self._items) > self.max_items:
                self._items.popitem(last=False)

    def clear(self):
        with self._lock:
            self._items.clear()


cache = TTLCache(max_items=256)

# 房间保活：连续扫描中至少出现一次则保留；连续 ROOM_KEEPALIVE_MISSES 次未扫到再移除
ROOM_KEEPALIVE_MISSES = 5
# 单服务器保活房间上限，防止异常/恶意数据把内存撑爆
MAX_KEEPALIVE_ROOMS_PER_SERVER = int(os.getenv("MAX_KEEPALIVE_ROOMS", "300"))
_room_keepalive: dict[str, dict[str, list[Any]]] = {}
_room_keepalive_lock = threading.Lock()


_RE_INDEX_ID = re.compile(r"^(.*)-(\d+)$")


def room_stable_key(room: dict[str, Any], server_id: str = "") -> str:
    """生成跨扫描稳定的房间标识，避免 index 型 id 导致保活失效。

    优化：原实现每次调用都用 f-string 拼一条正则再 re.match 编译，
    每秒扫描 × 房间数会产生大量临时 Pattern 对象并污染 re 缓存。
    改为一条预编译正则 + 字符串比较。
    """
    sid = str(room.get("server_id") or server_id or "")
    session = str(room.get("sessionId") or room.get("session_id") or "").strip()
    rid = str(room.get("id") or "").strip()
    # 真实 session 优先；排除 normalize 时用的 `{server}-{index}` 临时 id
    if session:
        return f"{sid}:sess:{session}"
    if rid:
        m = _RE_INDEX_ID.match(rid)
        if not (m and m.group(1) == sid):
            return f"{sid}:id:{rid}"
    content = str(room.get("content_id") or room.get("title_id") or "")
    host = str(room.get("host") or room.get("node_id") or "")
    game = str(room.get("game") or "")
    return f"{sid}:ch:{content}:{host}:{game}"


def apply_room_keepalive(server_id: str, current_rooms: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """合并本轮扫描结果与保活缓存（内存优化版）。

    - 本轮扫到：重置 miss 计数并更新房间数据
    - 本轮未扫到：miss + 1
    - miss >= ROOM_KEEPALIVE_MISSES：从卡片移除

    内存优化：
    1. 去掉两处 copy.deepcopy。房间 dict 由 normalize_room 每轮新建，
       本来就没有外部别名，直接持有引用即可；原实现每轮每房间产生
       2 份深拷贝副本（写入一份、输出一份），高频轮询下是最大的垃圾来源。
    2. 用 [room, misses] 的 list 代替 {"room":..., "misses":...} 的 dict，
       每条省一个 dict 对象（约 180 字节）。
    3. 增加每服务器保活房间数上限，防止异常数据把桶撑爆。
    """
    seen: dict[str, dict[str, Any]] = {}
    for room in current_rooms:
        seen[room_stable_key(room, server_id)] = room

    with _room_keepalive_lock:
        bucket = _room_keepalive.get(server_id)
        if bucket is None:
            if not seen:
                return []
            bucket = {}
            _room_keepalive[server_id] = bucket

        # 更新本轮出现的房间（复用已有 list 容器，避免重复分配）
        for rid, room in seen.items():
            entry = bucket.get(rid)
            if entry is None:
                bucket[rid] = [room, 0]
            else:
                entry[0] = room
                entry[1] = 0

        # 未出现的房间累加 miss，超限剔除
        if len(bucket) != len(seen):
            for rid in [k for k in bucket if k not in seen]:
                entry = bucket[rid]
                entry[1] += 1
                if entry[1] >= ROOM_KEEPALIVE_MISSES:
                    del bucket[rid]

        # 上限保护：只保留最近出现的 MAX_KEEPALIVE_ROOMS_PER_SERVER 个
        if len(bucket) > MAX_KEEPALIVE_ROOMS_PER_SERVER:
            for rid in sorted(bucket, key=lambda k: bucket[k][1], reverse=True)[
                : len(bucket) - MAX_KEEPALIVE_ROOMS_PER_SERVER
            ]:
                del bucket[rid]

        if not bucket:
            _room_keepalive.pop(server_id, None)
            return []

        return [v[0] for v in bucket.values()]


def prune_room_keepalive(valid_ids: set[str]) -> None:
    """服务器被删除后清掉它遗留的保活桶，避免内存里挂死数据。"""
    with _room_keepalive_lock:
        for sid in [s for s in _room_keepalive if s not in valid_ids]:
            del _room_keepalive[sid]


# ============================================================================
# SECTION 7 · 工具函数
# ============================================================================

def translate_error_message(msg: str) -> str:
    if not msg:
        return "未知错误"
    msg_lower = msg.lower()
    if "404" in msg:
        return "HTTP 404 未找到"
    if "timed out" in msg_lower:
        return "连接超时"
    if "remote end closed connection" in msg_lower:
        return "远程服务器关闭连接，未响应"
    if "connection refused" in msg_lower:
        return "连接被拒绝"
    if "name or service not known" in msg_lower:
        return "DNS 解析失败"
    if "network is unreachable" in msg_lower:
        return "网络不可达"
    if "ssl" in msg_lower:
        return "SSL 证书错误"
    if "graphql" in msg_lower:
        return f"GraphQL 查询失败: {msg}"
    return f"服务器错误: {msg}"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def int_or_zero(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])$")
ID_RE = re.compile(r"^[A-Za-z0-9_ -]{1,64}$")

_QUESTION_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">'
                 '<circle cx="24" cy="24" r="22" fill="#34495e"/>'
                 '<text x="24" y="34" text-anchor="middle" font-size="30" fill="white" '
                 'font-family="sans-serif" font-weight="bold">?</text></svg>')
QUESTION_ICON = "data:image/svg+xml," + urllib.parse.quote(_QUESTION_SVG)
UNKNOWN_ID = "FFFFFFFFFFFFFFFF"


def get_game_info(content_id: str, titles_map: dict[str, str]) -> dict[str, str]:
    normalized = str(content_id or "").upper()
    game_name = titles_map.get(normalized)
    is_unknown = False
    if not game_name:
        game_name = f"未知游戏 ({normalized})" if normalized else "未知游戏"
        is_unknown = True
    if game_name and game_name.startswith("未知游戏") and normalized != UNKNOWN_ID:
        is_unknown = True
    if normalized == UNKNOWN_ID:
        is_unknown = False
        game_name = "未知游戏"

    if is_unknown:
        icon = QUESTION_ICON
    else:
        icon = f"https://api.nlib.cc/nx/{normalized or 'FFFFFFFFFFFFFFFF'}/icon/128/128"
        # 备用图库 icon = f"https://tinfoil.media/ti/{normalized or 'FFFFFFFFFFFFFFFF'}/128/128"

    return {
        "name": game_name,
        "icon": icon
    }

# ============================================================================
# SECTION 8 · HTTP 客户端
# ============================================================================

class HTTPResponse:
    def __init__(self, raw: http.client.HTTPResponse | None, body: bytes, url: str, error: str | None = None):
        self._raw = raw
        self._body = body
        self.url = url
        self.error = error
        self.status_code = raw.status if raw else 0
        self.reason = raw.reason if raw else (error or "")
        self.headers = {k.lower(): v for k, v in raw.getheaders()} if raw else {}
        self._json: Any = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400 and not self.error

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    def raise_for_status(self) -> None:
        if not self.ok:
            raise RuntimeError(f"HTTP {self.status_code} {self.reason}")

    def json(self) -> Any:
        if self._json is None:
            self._json = json.loads(self._body.decode("utf-8"))
        return self._json

    @property
    def text(self) -> str:
        return self._body.decode("utf-8", errors="replace")


class HTTPClient:
    # 复用 opener：urllib.request.build_opener() 每次都会实例化整条 handler
    # 链（约 10 个 handler 对象 + 内部字典）。扫描是每秒 × 每服务器一次，
    # 原实现等于每秒凭空造几十个对象丢给 GC。opener 本身是无状态可共享的。
    _OPENER = urllib.request.build_opener()
    _OPENER_NOREDIRECT = urllib.request.build_opener(urllib.request.HTTPErrorProcessor())

    def __init__(self, user_agent: str = "", default_timeout: float = REQUEST_TIMEOUT):
        self.user_agent = user_agent or f"{APP_NAME}/1.0 (read-only room monitor)"
        self.default_timeout = default_timeout

    def _open(self, method: str, url: str, data: bytes | None = None,
              headers: dict[str, str] | None = None, timeout: float | None = None,
              allow_redirects: bool = True, **_: Any) -> HTTPResponse:
        req_headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
        opener = self._OPENER if allow_redirects else self._OPENER_NOREDIRECT
        try:
            resp = opener.open(req, timeout=timeout or self.default_timeout)
            body = resp.read()
            return HTTPResponse(resp, body, url)
        except urllib.error.HTTPError as e:
            body = e.read() or b""
            return HTTPResponse(e, body, url, str(e))
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            err_msg = e.reason if hasattr(e, "reason") else str(e)
            raise RuntimeError(err_msg) from e

    def get(self, url: str, **kw: Any) -> HTTPResponse:
        return self._open("GET", url, **kw)

    def post(self, url: str, json_body: Any = None, **kw: Any) -> HTTPResponse:
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers = kw.pop("headers", {}) or {}
            headers.setdefault("Content-Type", "application/json")
            return self._open("POST", url, data=data, headers=headers, **kw)
        return self._open("POST", url, **kw)


http = HTTPClient()

# ============================================================================
# SECTION 9 · LDN UDP 扫描
# ============================================================================

GRAPHQL_QUERY = """
query PublicRoomSnapshot {
  serverInfo { online idle }
  room {
    sessionId
    contentId
    hostPlayerName
    nodeCount
    nodeCountMax
    advertiseData
    nodes { playerName }
  }
}
""".strip()

UDP_SCAN_SECONDS = max(0.5, float(os.getenv("UDP_SCAN_SECONDS", "0.5")))
LDN_PORT = 11452
LDN_MAGIC = bytes.fromhex("00144511")
LDN_SCAN_HEADER = LDN_MAGIC + bytes(8)
SCANNER_VIRTUAL_IP = "10.13.37.0"
LDN_BROADCAST_IP = "10.13.255.255"
MAX_REASSEMBLED_PACKET = 65535
MAX_SCAN_ITERATIONS = 2000
SOCKET_MAX_LIFETIME = 300


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ldn_scan_frame() -> bytes:
    source = socket.inet_aton(SCANNER_VIRTUAL_IP)
    destination = socket.inet_aton(LDN_BROADCAST_IP)
    udp_length = 8 + len(LDN_SCAN_HEADER)
    udp_without_checksum = struct.pack("!HHHH", LDN_PORT, LDN_PORT, udp_length, 0)
    pseudo_header = source + destination + struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_length)
    udp_checksum = internet_checksum(pseudo_header + udp_without_checksum + LDN_SCAN_HEADER)
    udp_header = struct.pack("!HHHH", LDN_PORT, LDN_PORT, udp_length, udp_checksum)
    total_length = 20 + udp_length
    ip_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 0, 0x4000, 64, socket.IPPROTO_UDP, 0,
        source, destination,
    )
    ip_checksum = internet_checksum(ip_without_checksum)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length, 0, 0x4000, 64, socket.IPPROTO_UDP, ip_checksum,
        source, destination,
    )
    return b"\x01" + ip_header + udp_header + LDN_SCAN_HEADER


LDN_SCAN_FRAME = build_ldn_scan_frame()


def decompress_ldn(data: bytes, expected_size: int) -> bytes:
    if expected_size <= 0 or expected_size > 8192:
        raise ValueError("ldn_mitm 解压长度异常")
    output = bytearray()
    index = 0
    while index < len(data) and len(output) < expected_size:
        value = data[index]; index += 1
        output.append(value)
        if value == 0:
            if index >= len(data):
                raise ValueError("ldn_mitm 压缩数据不完整")
            repeat = data[index]; index += 1
            output.extend(b"\x00" * repeat)
        if len(output) > expected_size:
            raise ValueError("ldn_mitm 解压数据越界")
    if index != len(data) or len(output) != expected_size:
        raise ValueError("ldn_mitm 解压长度不匹配")
    return bytes(output)


def decode_player_name(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()


def parse_network_info(payload: bytes, source_ip: str) -> dict[str, Any]:
    if len(payload) < 0x480:
        raise ValueError("NetworkInfo 长度不足")
    payload = payload[:0x480]
    content_id = payload[0:8][::-1].hex().upper()
    session_id = payload[16:32].hex()
    node_count_max = min(payload[0x66], 8)
    node_count = min(payload[0x67], 8)
    players: list[str] = []
    nodes: list[dict[str, str]] = []
    for index in range(node_count):
        start = 0x68 + 0x40 * index
        node = payload[start:start + 0x40]
        if len(node) < 0x40:
            break
        player_name = decode_player_name(node[0x0C:0x2C])
        if not player_name:
            player_name = "未命名玩家"
        players.append(player_name)
        nodes.append({"playerName": player_name})
    host = decode_player_name(payload[0x74:0x94])
    if not host:
        host = players[0] if players else "未命名玩家"
    elif not players:
        players.append(host)
    advertise_length = min(int.from_bytes(payload[0x26A:0x26C], "little"), 384)
    advertise_data = payload[0x26C:0x26C + advertise_length].hex()
    return {
        "sessionId": session_id or f"{source_ip}-{content_id}",
        "contentId": content_id,
        "hostPlayerName": host,
        "nodeCount": node_count,
        "nodeCountMax": node_count_max,
        "advertiseData": advertise_data,
        "nodes": nodes,
        "sourceIp": source_ip,
        "players": players,
    }


def parse_ipv4_ldn_response(packet: bytes) -> dict[str, Any] | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header_length = (packet[0] & 0x0F) * 4
    if header_length < 20 or len(packet) < header_length + 8:
        return None
    total_length = int.from_bytes(packet[2:4], "big")
    if total_length >= header_length + 8:
        packet = packet[:min(total_length, len(packet))]
    if packet[9] != socket.IPPROTO_UDP:
        return None
    source_ip = socket.inet_ntoa(packet[12:16])
    udp = packet[header_length:]
    source_port, destination_port, udp_length, _checksum = struct.unpack("!HHHH", udp[:8])
    if source_port != LDN_PORT or destination_port != LDN_PORT or udp_length < 8:
        return None
    ldn = udp[8:min(len(udp), udp_length)]
    if len(ldn) < 12 or ldn[:4] != LDN_MAGIC:
        return None
    packet_type = ldn[4]
    compressed = ldn[5] == 1
    body_length = int.from_bytes(ldn[6:8], "little")
    decompressed_length = int.from_bytes(ldn[8:10], "little")
    if body_length > len(ldn) - 12:
        return None
    body = ldn[12:12 + body_length]
    if packet_type != 1:
        return None
    if compressed:
        body = decompress_ldn(body, decompressed_length)
    return parse_network_info(body, source_ip)


class FragmentCollector:
    def __init__(self) -> None:
        self.parts: dict[tuple[bytes, int], dict[str, Any]] = {}

    def add(self, frame: bytes) -> bytes | None:
        if len(frame) < 16:
            return None
        source = frame[0:4]
        identification = int.from_bytes(frame[8:10], "big")
        part = frame[10]
        total_parts = frame[11]
        part_length = int.from_bytes(frame[12:14], "little")
        pmtu = int.from_bytes(frame[14:16], "big")
        if not 1 <= total_parts <= 64 or part >= total_parts or pmtu <= 0:
            return None
        if part_length > len(frame) - 16:
            return None
        key = (source, identification)
        item = self.parts.setdefault(key, {"total": total_parts, "pmtu": pmtu, "parts": {}})
        if item["total"] != total_parts or item["pmtu"] != pmtu:
            self.parts.pop(key, None)
            return None
        item["parts"][part] = frame[16:16 + part_length]
        if len(item["parts"]) != total_parts:
            return None
        final_size = max(i * pmtu + len(v) for i, v in item["parts"].items())
        if final_size <= 0 or final_size > MAX_REASSEMBLED_PACKET:
            self.parts.pop(key, None)
            return None
        output = bytearray(final_size)
        for i, v in item["parts"].items():
            output[i * pmtu:i * pmtu + len(v)] = v
        self.parts.pop(key, None)
        return bytes(output)


class ActiveRoomScanner:
    def __init__(self, server: dict[str, Any]):
        self.server = server
        self._sock: socket.socket | None = None
        self._sock_created_at: float = 0.0
        self._lock = threading.Lock()

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            self._sock_created_at = 0.0

    def _ensure_socket(self) -> socket.socket:
        now = time.monotonic()
        if self._sock is not None:
            if now - self._sock_created_at < SOCKET_MAX_LIFETIME:
                return self._sock
            self.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)
        sock.connect((self.server["host"], self.server["port"]))
        self._sock = sock
        self._sock_created_at = now
        return sock

    @staticmethod
    def _drain(sock: socket.socket) -> None:
        sock.setblocking(False)
        try:
            while True:
                sock.recv(65535)
        except (BlockingIOError, OSError):
            pass
        finally:
            sock.setblocking(True)

    def scan(self) -> tuple[list[dict[str, Any]], str]:
        with self._lock:
            try:
                sock = self._ensure_socket()
                self._drain(sock)
                collector = FragmentCollector()
                found: dict[str, dict[str, Any]] = {}
                deadline = time.monotonic() + UDP_SCAN_SECONDS
                next_send = 0.0
                iterations = 0

                while time.monotonic() < deadline:
                    iterations += 1
                    if iterations > MAX_SCAN_ITERATIONS:
                        warn(f"[扫描] {self.server['name']} 达到最大迭代上限，提前退出")
                        break
                    now = time.monotonic()
                    if now >= next_send:
                        try:
                            sock.send(LDN_SCAN_FRAME)
                        except OSError as e:
                            warn(f"[扫描] send 失败 {self.server['name']}: {e}")
                            self.close()
                            break
                        next_send = now + 0.7
                    timeout = min(0.2, max(0.01, deadline - time.monotonic()))
                    sock.settimeout(timeout)
                    try:
                        frame = sock.recv(65535)
                    except socket.timeout:
                        continue
                    except OSError as e:
                        warn(f"[扫描] recv 错误 {self.server['name']}: {e}")
                        self.close()
                        break
                    if not frame:
                        continue
                    packet: bytes | None = None
                    if frame[0] == 1:
                        packet = frame[1:]
                    elif frame[0] == 3:
                        packet = collector.add(frame[1:])
                    if packet is None:
                        continue
                    try:
                        room = parse_ipv4_ldn_response(packet)
                    except (ValueError, struct.error, OSError):
                        continue
                    if room is not None:
                        key = room.get("sessionId") or f"{room.get('sourceIp')}:{room.get('contentId')}"
                        found[str(key)] = room
                return list(found.values()), ""
            except (OSError, socket.gaierror) as exc:
                self.close()
                return [], str(exc)

# ============================================================================
# SECTION 10 · 应用上下文
# ============================================================================

class AppContext:
    # 配置文件重载最小间隔（秒）。前端每秒轮询 /api/snapshot 会调用
    # refresh_config，原实现每次都重新读盘 + 解析 servers.json /
    # chinese_db.json（可能上万条），既是 CPU 也是内存分配热点。
    CONFIG_RELOAD_INTERVAL = max(1.0, float(os.getenv("CONFIG_RELOAD_INTERVAL", "10")))

    def __init__(self):
        self.lock = threading.RLock()
        self.servers: list[dict[str, Any]] = []
        self.servers_by_id: dict[str, dict[str, Any]] = {}
        self.scanners: dict[str, ActiveRoomScanner] = {}
        self.game_titles: dict[str, str] = BUILTIN_GAME_TITLES
        self.download_status: dict[str, Any] = dict(_download_status)
        self._last_reload: float = 0.0
        self._config_sig: tuple = ()

    @staticmethod
    def _config_signature() -> tuple:
        """用相关配置文件的 (mtime, size) 组成签名，变化才真正重载。"""
        sig: list[Any] = []
        for p in (LOCAL_SERVERS_FILE, MANUAL_SERVERS_FILE, SERVERS_FILE, LOCAL_CHINESE_DB_FILE):
            try:
                st = os.stat(p)
                sig.append((st.st_mtime_ns, st.st_size))
            except OSError:
                sig.append(None)
        return tuple(sig)

    def refresh_config(self, force: bool = False):
        now = time.monotonic()
        with self.lock:
            if not force and self.servers and now - self._last_reload < self.CONFIG_RELOAD_INTERVAL:
                # 冷却期内只同步一下下载状态，不碰磁盘和 JSON 解析
                with _download_status_lock:
                    if self.download_status != _download_status:
                        self.download_status = dict(_download_status)
                return
            self._last_reload = now

            sig = self._config_signature()
            if not force and self.servers and sig == self._config_sig:
                with _download_status_lock:
                    if self.download_status != _download_status:
                        self.download_status = dict(_download_status)
                return
            self._config_sig = sig

            self.game_titles = load_game_titles()
            new_servers = _load_servers_merged()
            self.servers = new_servers
            self.servers_by_id = {s["id"]: s for s in new_servers}

            current_ids = set(self.servers_by_id.keys())
            for sid in [k for k in self.scanners if k not in current_ids]:
                self.scanners[sid].close()
                del self.scanners[sid]
            for s in self.servers:
                if s["id"] not in self.scanners:
                    self.scanners[s["id"]] = ActiveRoomScanner(s)

            # 服务器被删除后，同步清掉它遗留的房间保活桶与扫描缓存
            prune_room_keepalive(current_ids)

            with _download_status_lock:
                self.download_status = dict(_download_status)

    def get_server(self, sid: str) -> dict[str, Any] | None:
        with self.lock:
            return self.servers_by_id.get(sid)

    def get_scanner(self, sid: str) -> ActiveRoomScanner | None:
        with self.lock:
            return self.scanners.get(sid)

    def get_all_servers(self) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.servers)


ctx = AppContext()

# ============================================================================
# SECTION 11 · 服务器配置管理（含 ID 唯一性校验 + 严格 IPv4）
# ============================================================================

def is_id_available(new_id: str, exclude_id: str | None = None) -> bool:
    """检查 new_id 是否在所有服务器中唯一（排除 exclude_id）"""
    if not new_id:
        return False
    all_servers = ctx.get_all_servers()
    for s in all_servers:
        if s["id"] == new_id and (exclude_id is None or s["id"] != exclude_id):
            return False
    return True


def is_valid_host(host: str) -> bool:
    """严格校验主机地址，防止 'x.x.x.x.x' 等错误格式通过"""
    if not host:
        return False
    host = host.strip()
    # 纯数字和点：必须为IPv4（4段，每段0-255，无前导零）
    if re.fullmatch(r"^[\d.]+$", host):
        if not re.fullmatch(r"^(\d{1,3}\.){3}\d{1,3}$", host):
            return False
        parts = host.split('.')
        return all(0 <= int(p) <= 255 and p == str(int(p)) for p in parts)
    # IPv6（方括号包裹）
    if host.startswith('[') and host.endswith(']'):
        ipv6 = host[1:-1]
        return re.fullmatch(
            r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::|^([0-9a-fA-F]{1,4}:){1,7}:$",
            ipv6
        ) is not None
    # 域名（标准格式）
    return re.fullmatch(r"^(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$", host) is not None


def validate_server(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("服务器配置项必须是对象")
    server_id = str(raw.get("id", "")).strip()
    name = str(raw.get("name", server_id)).strip()
    host = str(raw.get("host", "")).strip()
    protocol = str(raw.get("type", "graphql")).strip().lower()
    region = str(raw.get("region", "")).strip()
    try:
        port = int(raw.get("port", 11451))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"服务器 {server_id or host} 的端口无效") from exc
    if not ID_RE.fullmatch(server_id):
        raise ValueError(f"服务器 id 无效：{server_id!r}")
    if not name:
        raise ValueError(f"服务器 {server_id} 的名称不能为空")
    if len(name) > 255:
        raise ValueError(f"服务器 {server_id} 的名称过长（最大255字符）")
    if not is_valid_host(host):
        raise ValueError(f"服务器 {server_id} 的主机名无效")
    if not 1 <= port <= 65535:
        raise ValueError(f"服务器 {server_id} 的端口无效")
    if protocol not in {"graphql", "rest"}:
        raise ValueError(f"服务器 {server_id} 的 type 仅支持 graphql/rest")

    res = {"id": server_id, "name": name, "host": host, "port": port, "type": protocol, "region": region}
    for flag in ("is_builtin", "is_remote", "is_manual", "is_env"):
        if flag in raw:
            res[flag] = raw[flag]
    return res


def _load_servers_from_file(file_path: str) -> list[dict[str, Any]]:
    servers: list[dict[str, Any]] = []
    path = Path(file_path)
    if not path.is_file():
        return servers
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(raw, list):
            for item in raw:
                try:
                    servers.append(validate_server(item))
                except Exception as exc:
                    warn(f"[配置警告] 服务器项解析失败: {exc}")
        else:
            warn(f"[配置警告] 服务器列表格式不正确: {file_path}")
    except Exception as exc:
        warn(f"[配置警告] 读取服务器列表失败 {file_path}: {exc}")
    return servers


# 服务器列表加载签名：仅在内容变化时写日志，避免跟随轮询重复叠加
_servers_load_logged_sig: str = ""
_servers_missing_local_logged: bool = False


def _load_servers_merged() -> list[dict[str, Any]]:
    global _servers_load_logged_sig, _servers_missing_local_logged
    merged: dict[str, dict[str, Any]] = {}
    builtin_ids: set[str] = set()
    remote_ids: set[str] = set()
    env_ids: set[str] = set()

    local_exists = Path(LOCAL_SERVERS_FILE).is_file()
    if local_exists:
        remote_servers = _load_servers_from_file(LOCAL_SERVERS_FILE)
        if remote_servers:
            for srv in remote_servers:
                srv.setdefault("is_remote", True)
                merged[srv["id"]] = srv
                remote_ids.add(srv["id"])
            _servers_missing_local_logged = False
        else:
            if not _servers_missing_local_logged:
                info("[配置警告] 本地服务器列表为空，使用内置兜底")
                _servers_missing_local_logged = True
            local_exists = False

    use_builtin = not local_exists
    if use_builtin:
        if not _servers_missing_local_logged:
            info("[配置] 本地服务器列表不存在，使用内置兜底")
            _servers_missing_local_logged = True
        for item in DEFAULT_SERVERS:
            try:
                srv = validate_server(item)
                srv["is_builtin"] = True
                merged[srv["id"]] = srv
                builtin_ids.add(srv["id"])
            except Exception as exc:
                warn(f"[配置警告] 内置服务器项解析失败: {exc}")

    env_path_str = os.getenv("SERVERS_FILE", "").strip()
    if env_path_str and env_path_str != DEFAULT_SERVERS_FILE:
        env_path = Path(env_path_str).expanduser()
        if env_path.is_file():
            for srv in _load_servers_from_file(str(env_path)):
                srv["is_env"] = True
                merged[srv["id"]] = srv
                env_ids.add(srv["id"])

    manual_path = Path(MANUAL_SERVERS_FILE)
    if manual_path.is_file():
        for srv in _load_servers_from_file(str(manual_path)):
            if srv["id"] not in builtin_ids and srv["id"] not in remote_ids and srv["id"] not in env_ids:
                srv.setdefault("is_manual", True)
                merged[srv["id"]] = srv

    env_manual = Path(SERVERS_FILE)
    if env_manual.is_file() and str(env_manual) != str(manual_path):
        for srv in _load_servers_from_file(str(env_manual)):
            if srv["id"] not in builtin_ids and srv["id"] not in remote_ids and srv["id"] not in env_ids:
                srv.setdefault("is_manual", True)
                merged[srv["id"]] = srv

    total = len(merged)
    builtin_count = sum(1 for s in merged.values() if s.get("is_builtin"))
    remote_count = sum(1 for s in merged.values() if s.get("is_remote"))
    manual_count = sum(1 for s in merged.values() if s.get("is_manual"))
    # 仅在服务器列表实际变化时打日志，避免每秒轮询 refresh_config 重复叠加
    sig = f"{total}:{builtin_count}:{remote_count}:{manual_count}:" + ",".join(sorted(merged.keys()))
    if sig != _servers_load_logged_sig:
        info(f"[配置] 服务器列表加载完成，共 {total} 台（内置 {builtin_count}，远程 {remote_count}，自定义 {manual_count}）")
        _servers_load_logged_sig = sig
    return list(merged.values())

# ============================================================================
# SECTION 12 · 房间扫描 & 规范化
# ============================================================================

SCAN_EXECUTOR = ThreadPoolExecutor(
    max_workers=min(MAX_WORKERS, 16),
    thread_name_prefix="scanner"
)


def normalize_room(raw: Any, server: dict[str, Any], index: int,
                  titles_map: dict[str, str]) -> dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    content_id = str(raw.get("contentId") or raw.get("content_id") or "").upper()
    g_info = get_game_info(content_id, titles_map)
    nodes = raw.get("nodes") if isinstance(raw.get("nodes"), list) else []
    players: list[str] = []
    for node in nodes:
        if isinstance(node, dict):
            name = str(node.get("playerName") or node.get("player_name") or "").strip()
        else:
            name = str(node).strip()
        if not name:
            name = "未命名玩家"
        players.append(name)
    host = str(raw.get("hostPlayerName") or raw.get("host_player_name") or "").strip()
    if not host:
        host = players[0] if players else "未知玩家"
    elif not players:
        players.append(host)
    node_count = int_or_zero(raw.get("nodeCount", raw.get("node_count", len(players))))
    node_max = int_or_zero(raw.get("nodeCountMax", raw.get("node_count_max", 0)))
    return {
        "id": str(raw.get("sessionId") or raw.get("session_id") or f"{server['id']}-{index}"),
        "server_id": server["id"],
        "server_name": server["name"],
        "server_address": f"{server['host']}:{server['port']}",
        "content_id": content_id,
        "game": g_info["name"],
        "game_icon": g_info["icon"],
        "host": host,
        "node_count": node_count or len(players),
        "node_count_max": node_max,
        "players": players,
    }


def base_result(server: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": server["id"], "name": server["name"], "host": server["host"],
        "port": server["port"], "address": f"{server['host']}:{server['port']}",
        "type": server["type"], "region": server.get("region", ""),
        "is_manual": server.get("is_manual", False),
        "is_builtin": server.get("is_builtin", False),
        "is_remote": server.get("is_remote", False),
        "status": "offline", "online": 0, "idle": 0, "active": 0,
        "room_count": 0, "rooms": [], "latency_ms": None, "error": "",
        "scanner_error": "", "detection": "active-udp-scan",
        "checked_at": utc_now(),
    }


def scan_graphql(server: dict[str, Any]) -> dict[str, Any]:
    result = base_result(server)
    url = f"http://{server['host']}:{server['port']}/"
    started = time.monotonic()
    try:
        response = http.post(url, json_body={"query": GRAPHQL_QUERY},
                             timeout=REQUEST_TIMEOUT, allow_redirects=False)
        elapsed_ms = max(1, int((time.monotonic() - started) * 1000))
        result["latency_ms"] = elapsed_ms
        if response.is_redirect:
            raise RuntimeError("服务器返回意外重定向")
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("响应不是 JSON 对象")
        if payload.get("errors"):
            first = payload["errors"][0] if isinstance(payload["errors"], list) else payload["errors"]
            message = first.get("message") if isinstance(first, dict) else str(first)
            raise RuntimeError(f"GraphQL：{message}")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise RuntimeError("GraphQL 缺少 data")
        info_block = data.get("serverInfo") if isinstance(data.get("serverInfo"), dict) else {}
        online = int_or_zero(info_block.get("online"))
        idle = int_or_zero(info_block.get("idle"))
        raw_rooms = data.get("room") if isinstance(data.get("room"), list) else []
        rooms = [normalize_room(item, server, i + 1, ctx.game_titles) for i, item in enumerate(raw_rooms)]
        result.update({
            "status": "online", "online": online, "idle": idle,
            "active": max(0, online - idle), "room_count": len(rooms), "rooms": rooms
        })
    except Exception as exc:
        result["error"] = translate_error_message(str(exc))
    return result


def scan_rest(server: dict[str, Any]) -> dict[str, Any]:
    result = base_result(server)
    url = f"http://{server['host']}:{server['port']}/info"
    started = time.monotonic()
    try:
        response = http.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        elapsed_ms = max(1, int((time.monotonic() - started) * 1000))
        result["latency_ms"] = elapsed_ms
        if response.is_redirect:
            raise RuntimeError("服务器返回意外重定向")
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise RuntimeError("响应不是 JSON 对象")
        online = int_or_zero(data.get("online", data.get("clientCount", 0)))
        idle = int_or_zero(data.get("idle", 0))
        raw_rooms = data.get("rooms") if isinstance(data.get("rooms"), list) else []
        rooms = [normalize_room(item, server, i + 1, ctx.game_titles) for i, item in enumerate(raw_rooms)]
        result.update({
            "status": "online", "online": online, "idle": idle,
            "active": max(0, online - idle), "room_count": len(rooms), "rooms": rooms
        })
    except Exception as exc:
        result["error"] = translate_error_message(str(exc))
    return result


def scan_server(server: dict[str, Any], force: bool = False) -> tuple[dict[str, Any], bool]:
    key = f"scan:{server['id']}"
    if not force:
        cached = cache.get(key)
        if cached is not None:
            return cached, True

    result = scan_graphql(server) if server["type"] == "graphql" else scan_rest(server)
    http_ok = (result.get("status") == "online" and not result.get("error"))

    scanner = ctx.get_scanner(server["id"])
    active_raw, scanner_error = scanner.scan() if scanner else ([], "Scanner not found")
    active_rooms = [normalize_room(item, server, i + 1, ctx.game_titles) for i, item in enumerate(active_raw)]
    udp_has_rooms = len(active_rooms) > 0

    merged: dict[str, dict[str, Any]] = {}
    for room in (*result.get("rooms", []), *active_rooms):
        rid = str(room.get("id") or f"{room.get('server_id')}:{room.get('host')}:{room.get('content_id')}")
        merged[rid] = room
    # 房间保活：5 次扫描内出现过则保留，连续 5 次未扫到再消失
    result["rooms"] = apply_room_keepalive(server["id"], list(merged.values()))
    result["room_count"] = len(result["rooms"])
    result["scanner_error"] = scanner_error
    result["detection"] = "active-udp-scan+monitor-api"

    if http_ok or udp_has_rooms:
        result["status"] = "online"
        http_online = int_or_zero(result.get("online"))
        udp_online = sum(max(1, r["node_count"]) for r in active_rooms) if udp_has_rooms else 0
        result["online"] = max(http_online, udp_online)
        result["active"] = max(0, result["online"] - int_or_zero(result.get("idle")))
        result["error"] = ""
        if not http_ok:
            result["latency_ms"] = None
    else:
        result["status"] = "offline"
        result["online"] = 0
        result["idle"] = 0
        result["active"] = 0
        result["latency_ms"] = None
        if not result.get("error"):
            result["error"] = "服务器不可达或未响应"

    cache.set(key, result)
    return result, False


def scan_all(force: bool = False) -> tuple[list[dict[str, Any]], bool]:
    ctx.refresh_config()
    servers_snapshot = ctx.get_all_servers()
    if not servers_snapshot:
        return [], True

    results: dict[str, dict[str, Any]] = {}
    all_cached = True
    futures = {
        SCAN_EXECUTOR.submit(scan_server, s, force): s["id"]
        for s in servers_snapshot
    }
    for future in as_completed(futures):
        sid = futures[future]
        try:
            result, hit = future.result()
            results[sid] = result
            all_cached = all_cached and hit
        except Exception as exc:
            srv = ctx.get_server(sid) or {"id": sid, "name": "?", "host": "?", "port": 0}
            fallback = base_result(srv)
            fallback["error"] = str(exc)
            fallback["latency_ms"] = None
            results[sid] = fallback
            all_cached = False

    return [results[s["id"]] for s in servers_snapshot if s["id"] in results], all_cached

# ============================================================================
# SECTION 13 · HTTP 请求参数 & 响应辅助
# ============================================================================

def parse_query(query_string: str) -> dict[str, str]:
    if not query_string:
        return {}
    parsed = urllib.parse.parse_qs(query_string, keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items()}


def wants_refresh(query: dict[str, str]) -> bool:
    return query.get("refresh", "0").strip().lower() in {"1", "true", "yes"}


def bounded_int(query: dict[str, str], name: str, default: int,
               minimum: int, maximum: int) -> int:
    raw = query.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"参数 {name} 必须是整数") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"参数 {name} 必须在 {minimum} 到 {maximum} 之间")
    return value


def make_json_response(data: dict[str, Any], cache_hit: bool = False,
                       status: int = 200) -> tuple[bytes, dict[str, str], int]:
    body = json.dumps(data, ensure_ascii=False, sort_keys=False).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "X-Cache": "HIT" if cache_hit else "MISS",
        "Cache-Control": f"public, max-age={CACHE_TTL}",
        "Access-Control-Allow-Origin": "*",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    return body, headers, status

# ============================================================================
# SECTION 14 · 前端页面模板（读取外部文件）
# ============================================================================

def get_static_file(filename: str) -> str:
    file_path = SCRIPT_DIR / filename
    if file_path.is_file():
        try:
            return file_path.read_text(encoding="utf-8")
        except Exception:
            return ""
    return ""


PWA_CACHE_VERSION = "20260808_4"
_PWA_ICON_CACHE: dict[int, bytes] = {}


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    return struct.pack("!I", len(data)) + chunk_type + data + struct.pack(
        "!I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    )


def build_pwa_icon_png(size: int) -> bytes:
    """从前端 script.js 的 Base64 常量自动还原 PWA 图标，无需额外图片文件。"""
    size = 512 if int(size) >= 512 else 192
    cached = _PWA_ICON_CACHE.get(size)
    if cached is not None:
        return cached

    try:
        frontend = get_static_file("script.js")
        pattern = rf"const\s+PWA_ICON_{size}_BASE64\s*=\s*['\"]([A-Za-z0-9+/=]+)['\"]"
        match = re.search(pattern, frontend)
        if match:
            data = base64.b64decode(match.group(1), validate=True)
            if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) > 100:
                _PWA_ICON_CACHE[size] = data
                return data
    except Exception as exc:
        warn(f"[PWA] 从前端还原内嵌图标失败 size={size}: {exc}")

    # 前端常量缺失或损坏时，使用零依赖备用图标，确保 PWA 接口仍有效。
    raw = bytearray()
    # 三个网络节点组成三角形，适合 any/maskable 图标安全区。
    nodes = (
        (int(size * 0.50), int(size * 0.25)),
        (int(size * 0.28), int(size * 0.69)),
        (int(size * 0.72), int(size * 0.69)),
    )
    node_r = size * 0.085
    line_w = size * 0.030

    def near_segment(px: float, py: float, a: tuple[int, int], b: tuple[int, int]) -> bool:
        ax, ay = a; bx, by = b
        vx, vy = bx - ax, by - ay
        denom = vx * vx + vy * vy
        if denom <= 0:
            return False
        t = max(0.0, min(1.0, ((px - ax) * vx + (py - ay) * vy) / denom))
        dx = px - (ax + t * vx)
        dy = py - (ay + t * vy)
        return dx * dx + dy * dy <= line_w * line_w

    for y in range(size):
        raw.append(0)  # PNG scanline filter: None
        for x in range(size):
            # 深蓝至青色渐变背景，整块铺满以兼容 maskable。
            fx = x / max(1, size - 1)
            fy = y / max(1, size - 1)
            r = int(13 + 10 * fx)
            g = int(31 + 62 * (1.0 - fy) + 18 * fx)
            b = int(48 + 58 * fx + 18 * (1.0 - fy))

            on_line = (
                near_segment(x, y, nodes[0], nodes[1]) or
                near_segment(x, y, nodes[0], nodes[2]) or
                near_segment(x, y, nodes[1], nodes[2])
            )
            if on_line:
                r, g, b = 166, 238, 231

            for index, (nx, ny) in enumerate(nodes):
                d2 = (x - nx) * (x - nx) + (y - ny) * (y - ny)
                if d2 <= node_r * node_r:
                    if d2 <= (node_r * 0.58) ** 2:
                        r, g, b = 245, 255, 255
                    else:
                        r, g, b = (36, 216, 190) if index else (75, 190, 255)
                    break
            raw.extend((r, g, b, 255))

    png = (
        b"\x89PNG\r\n\x1a\n" +
        _png_chunk(b"IHDR", struct.pack("!IIBBBBB", size, size, 8, 6, 0, 0, 0)) +
        _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9)) +
        _png_chunk(b"IEND", b"")
    )
    _PWA_ICON_CACHE[size] = png
    return png


def build_pwa_manifest() -> bytes:
    manifest = {
        "id": "/",
        "name": "LAN-Play 房间监控",
        "short_name": "LAN-Play",
        "description": "LAN-Play 在线服务器、房间与聊天监控",
        "lang": "zh-CN",
        "start_url": "/?source=pwa",
        "scope": "/",
        "display": "standalone",
        "display_override": ["window-controls-overlay", "standalone", "minimal-ui"],
        "orientation": "any",
        "background_color": "#0f1923",
        "theme_color": "#0f1923",
        "categories": ["utilities", "social"],
        "icons": [
            {"src": "/static/pwa-icon-192.png?v=20260808_4", "sizes": "192x192", "type": "image/png", "purpose": "any"},
            {"src": "/static/pwa-icon-512.png?v=20260808_4", "sizes": "512x512", "type": "image/png", "purpose": "any"},
        ],
    }
    return json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def build_service_worker() -> bytes:
    script = f"""'use strict';
const CACHE_NAME = 'lanplay-pwa-{PWA_CACHE_VERSION}';
const APP_SHELL = [
  '/',
  '/manifest.webmanifest',
  '/static/script.js?v=20260808_9',
  '/static/pwa-icon-192.png?v=20260808_4',
  '/static/pwa-icon-512.png?v=20260808_4'
];

self.addEventListener('install', event => {{
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .catch(() => undefined)
      .then(() => self.skipWaiting())
  );
}});

self.addEventListener('activate', event => {{
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  );
}});

self.addEventListener('fetch', event => {{
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  // API、下载与实时数据始终走网络，绝不缓存。
  if (url.pathname.startsWith('/api/')) return;

  event.respondWith((async () => {{
    try {{
      const response = await fetch(request);
      if (response && response.ok) {{
        const cache = await caches.open(CACHE_NAME);
        cache.put(request, response.clone()).catch(() => undefined);
      }}
      return response;
    }} catch (_) {{
      const cached = await caches.match(request, {{ignoreSearch: true}});
      if (cached) return cached;
      if (request.mode === 'navigate') return caches.match('/');
      throw _;
    }}
  }})());
}});
"""
    return script.encode("utf-8")


def build_html() -> str:
    """页面壳：带 PWA 清单、安装元信息，并加载合并后的前端脚本。"""
    return """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
  <meta name="theme-color" content="#0f1923">
  <meta name="application-name" content="LAN-Play">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="LAN-Play">
  <link rel="manifest" href="/manifest.webmanifest">
  <link rel="icon" type="image/png" sizes="192x192" href="/static/pwa-icon-192.png?v=20260808_4">
  <link rel="apple-touch-icon" href="/static/pwa-icon-192.png?v=20260808_4">
  <title>LAN-Play 房间监控</title>
</head>
<body>
<script src="/static/script.js?v=20260808_9"></script>
</body>
</html>"""

# ============================================================================
# SECTION 15 · HTTP 请求处理器（含 ID 添加/编辑支持）
# ============================================================================

class MonitorHandler(BaseHTTPRequestHandler):

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        try:
            parsed_url = urllib.parse.urlparse(self.path)
            path = parsed_url.path
            query = parse_query(parsed_url.query)

            if path in {"", "/"}:
                body = build_html().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/manifest.webmanifest":
                body = build_pwa_manifest()
                self.send_response(200)
                self.send_header("Content-Type", "application/manifest+json; charset=utf-8")
                self.send_header("Cache-Control", "no-cache, must-revalidate")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path == "/service-worker.js":
                body = build_service_worker()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                self.send_header("Service-Worker-Allowed", "/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path in {"/static/pwa-icon-192.png", "/static/pwa-icon-512.png"}:
                size = 512 if path.endswith("512.png") else 192
                body = build_pwa_icon_png(size)
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Cache-Control", "public, max-age=86400")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if path.startswith("/static/"):
                filename = path[8:]
                if ".." in filename or filename.startswith("/"):
                    self.send_response(403)
                    self.end_headers()
                    return
                file_path = SCRIPT_DIR / filename
                # 单文件版：前端只保留 script.js（含全部 HTML/CSS）与 GoEasy SDK
                if file_path.is_file() and filename in ("script.js", "goeasy.min.js"):
                    content_type = {
                        "script.js": "application/javascript; charset=utf-8",
                        "goeasy.min.js": "application/javascript; charset=utf-8",
                    }.get(filename, "application/octet-stream")
                    try:
                        body = file_path.read_bytes()
                        self.send_response(200)
                        self.send_header("Content-Type", content_type)
                        self.send_header("Content-Length", str(len(body)))
                        # script.js 禁止缓存，确保前端逻辑能及时生效
                        if filename == "script.js":
                            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                            self.send_header("Pragma", "no-cache")
                        self.end_headers()
                        self.wfile.write(body)
                        return
                    except Exception:
                        pass
                self.send_response(404)
                self.end_headers()
                return

            if path == "/api/servers":
                try:
                    servers = ctx.get_all_servers()
                    data = {"ok": True, "servers": servers}
                    body, headers, status = make_json_response(data)
                    self._send(body, headers, status)
                    return
                except Exception as e:
                    err(f"[API] /api/servers 异常: {e}")
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=500)
                    self._send(body, headers, status)
                    return

            if path == "/api/env/runtime":
                # 公开最小配置：仅供前端初始化聊天，不含 R2 密钥。
                try:
                    cfg = load_env_config()
                    data = {
                        "ok": True,
                        "config": _build_runtime_env_config(cfg),
                        "full": False,
                    }
                    body, headers, status = make_json_response(data)
                    headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
                    self._send(body, headers, status)
                    return
                except Exception as e:
                    err(f"[API] /api/env/runtime 异常: {e}")
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=500)
                    self._send(body, headers, status)
                    return

            if path == "/api/env":
                try:
                    cfg = load_env_config()
                    is_public, client_ip = is_public_request(self)
                    password_set = is_password_set()
                    provided_pw = (
                        str(self.headers.get("X-Env-Password", "") or "").strip()
                        or str(query.get("password", "") or "").strip()
                    )
                    pw_ok = bool(provided_pw) and verify_password(provided_pw)

                    # 完整 /api/env（含全部密钥）访问策略：
                    # - 已设密码：必须提供正确密码
                    # - 公网且未设密码：拒绝，要求先设密码
                    # - 局域网且未设密码：允许（与设置页「局域网跳过」一致）
                    allow_full = False
                    if password_set:
                        if not pw_ok:
                            data = {
                                "ok": False,
                                "error": "需要正确的安全密码才能查看环境变量配置",
                                "need_password": True,
                                "is_public": is_public,
                                "client_ip": client_ip,
                            }
                            body, headers, status = make_json_response(data, status=403)
                            headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
                            self._send(body, headers, status)
                            return
                        allow_full = True
                    elif is_public:
                        data = {
                            "ok": False,
                            "error": "公网访问请先设置安全密码后再查看环境变量配置",
                            "need_password": False,
                            "need_set_password": True,
                            "is_public": True,
                            "client_ip": client_ip,
                        }
                        body, headers, status = make_json_response(data, status=403)
                        headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
                        self._send(body, headers, status)
                        return
                    else:
                        allow_full = True

                    data = {
                        "ok": True,
                        "config": cfg,
                        "file": ENV_CONFIG_FILE,
                        "full": True,
                        "is_public": is_public,
                        "client_ip": client_ip,
                    }
                    body, headers, status = make_json_response(data)
                    headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
                    self._send(body, headers, status)
                    return
                except Exception as e:
                    err(f"[API] /api/env 异常: {e}")
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=500)
                    self._send(body, headers, status)
                    return

            if path == "/api/env/security-status":
                try:
                    is_public, client_ip = is_public_request(self)
                    data = {
                        "ok": True,
                        "is_public": is_public,
                        "password_set": is_password_set(),
                        "client_ip": client_ip,
                    }
                    body, headers, status = make_json_response(data)
                    self._send(body, headers, status)
                    return
                except Exception as e:
                    err(f"[API] /api/env/security-status 异常: {e}")
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=500)
                    self._send(body, headers, status)
                    return

            if path == "/api/avatar":
                try:
                    user_id = str(query.get("user_id", "")).strip()
                    if not user_id:
                        raise ValueError("缺少用户 ID")
                    result = find_r2_avatar(user_id)
                    data = {"ok": True, **result}
                    body, headers, status = make_json_response(data)
                    headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
                except Exception as e:
                    data = {"ok": False, "exists": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=400)
                self._send(body, headers, status)
                return

            if path == "/api/snapshot":
                try:
                    force = wants_refresh(query)
                    servers_data, all_cached = scan_all(force=force)
                    # 内存优化：房间对象只做引用聚合，不再 dict(r) 逐个浅拷贝。
                    # 序列化是只读操作，拷贝纯属浪费（房间多时每秒一份垃圾）。
                    all_rooms: list[dict[str, Any]] = []
                    for s in servers_data:
                        rooms = s.get("rooms")
                        if rooms:
                            all_rooms.extend(rooms)
                    # servers 里的 rooms 前端并不使用（只用 room_count），
                    # 剔除后响应体体积可减半，序列化缓冲同步减小。
                    servers_slim = [
                        {k: v for k, v in s.items() if k != "rooms"} for s in servers_data
                    ]
                    data = {"ok": True, "servers": servers_slim, "rooms": all_rooms}
                    body, headers, status = make_json_response(data, cache_hit=all_cached)
                except Exception as e:
                    err(f"[API] /api/snapshot 异常: {e}")
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=500)
                self._send(body, headers, status)
                return

            if path == "/api/browser-download":
                self._browser_download_started = False
                try:
                    download_url = str(query.get("url", "")).strip()
                    download_name = str(query.get("filename", query.get("file_name", ""))).strip()
                    restore_xor = str(query.get("xor", "0")).strip().lower() in {"1", "true", "yes"}
                    mime_hint = str(query.get("mime", "")).strip()
                    if not download_url:
                        raise ValueError("缺少下载地址")
                    stream_url_to_browser(self, download_url, download_name, restore_xor, mime_hint)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except Exception as e:
                    err(f"[浏览器下载] 转发失败: {e}")
                    # 若响应头尚未发出，可返回明确错误；流式传输中途失败则直接结束连接。
                    try:
                        if not getattr(self, "_browser_download_started", False):
                            self.send_response(400)
                            body = ("下载失败：" + str(e)).encode("utf-8", errors="replace")
                            self.send_header("Content-Type", "text/plain; charset=utf-8")
                            self.send_header("Content-Length", str(len(body)))
                            self.end_headers()
                            self.wfile.write(body)
                    except Exception:
                        pass
                return

            if path == "/api/access-mode":
                try:
                    is_public, client_ip = is_public_request(self)
                    data = {
                        "ok": True,
                        "is_public": bool(is_public),
                        "mode": "public" if is_public else "lan",
                        "client_ip": client_ip,
                    }
                    body, headers, status = make_json_response(data)
                    # 网络类型用于下载分流，禁止代理/浏览器缓存旧结果。
                    headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
                except Exception as e:
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=500)
                self._send(body, headers, status)
                return

            if path == "/api/network-status":
                try:
                    force_check = wants_refresh(query)
                    net_status = get_network_status(force=force_check)
                    data = {"ok": True, "online": net_status["online"]}
                    body, headers, status = make_json_response(data)
                except Exception as e:
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=500)
                self._send(body, headers, status)
                return

            if path == "/api/native-info":
                try:
                    try:
                        import android_native
                        info = android_native.get_native_info()
                    except Exception:
                        info = {"available": False, "error": "android_native not loaded"}
                    data = {"ok": True, **info}
                    body, headers, status = make_json_response(data)
                except Exception as e:
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=500)
                self._send(body, headers, status)
                return

            if path == "/api/update/check":
                try:
                    st = check_update_status()
                    data = {"ok": True, **st}
                    body, headers, status = make_json_response(data)
                except Exception as e:
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=500)
                self._send(body, headers, status)
                return

            if path == "/api/logs":
                try:
                    # 日志采用长轮询：只有日志版本发生变化时才立即返回，
                    # 不再按固定间隔跟随页面轮询刷新。
                    try:
                        since_version = max(0, int(query.get("version", "-1")))
                    except (TypeError, ValueError):
                        since_version = -1
                    wait_logs = query.get("wait", "0").strip().lower() in {"1", "true", "yes"}
                    if wait_logs and since_version >= 0:
                        log_version, logs = log_capturer.wait_for_change(since_version)
                    else:
                        log_version, logs = log_capturer.get_logs_snapshot(200)
                    with _download_status_lock:
                        st = dict(_download_status)
                    log_lines = list(logs)
                    
                    # ★ 拼接常驻日志，确保可以在 App 查看状态
                    # (原 android_filechooser 日志已整合到 android_native.get_status_logs() 中)
                    try:
                        import android_native
                        log_lines.extend(android_native.get_status_logs())
                    except Exception:
                        pass

                    # 新增：把"是否已加入电池白名单"也展示出来
                    try:
                        import android_native
                        if android_native.is_ignoring_battery_optimizations():
                            log_lines.append("[电池优化] ✅ 已在白名单(应用不会被系统杀进程)")
                        else:
                            log_lines.append("[电池优化] ⚠️ 仍在电池优化名单中(建议在系统设置里放行)")
                    except Exception:
                        pass

                    if st.get("remote_servers_available"):
                        ts = st.get("servers_last_success", 0)
                        log_lines.append(f"[远程下载] 服务器列表: 正常 | 上次成功: {time.strftime('%H:%M:%S', time.localtime(ts))}")
                    else:
                        log_lines.append("[远程下载] 服务器列表: 不可用（使用内置兜底）")
                    if st.get("chinese_db_last_error"):
                        ts = st.get("chinese_db_last_success", 0)
                        msg = f"标题映射: {st['chinese_db_last_error']}"
                        log_lines.append(f"[远程下载] {msg} | 上次成功: {time.strftime('%H:%M:%S', time.localtime(ts))}" if ts else f"[远程下载] {msg}")
                    else:
                        ts = st.get("chinese_db_last_success", 0)
                        log_lines.append(f"[远程下载] 标题映射: 正常 | 上次成功: {time.strftime('%H:%M:%S', time.localtime(ts))}" if ts else "[远程下载] 标题映射: 正常")
                    data = {"ok": True, "logs": log_lines, "version": log_version}
                    body, headers, status = make_json_response(data)
                except Exception as e:
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=500)
                self._send(body, headers, status)
                return

            self.send_response(404)
            self.end_headers()
        except Exception as e:
            err(f"[HTTP] GET {self.path} 处理异常: {e}")
            try:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
            except Exception:
                pass

    def do_POST(self) -> None:
        try:
            parsed_url = urllib.parse.urlparse(self.path)
            path = parsed_url.path
            content_length = int(self.headers.get("Content-Length", 0))
            content_type = self.headers.get("Content-Type", "") or ""

            # ---- 用户头像上传 → R2 稳定对象键（同一 userId 永久覆盖同一路径） ----
            if path == "/api/avatar/upload":
                try:
                    # ★ 先按磁盘上的 env.json 刷新运行时 R2 配置，
                    #   避免 env.json 被移出再放回后运行时的旧空凭据导致上传失败。
                    reload_r2_config_if_changed()
                    missing_r2 = []
                    if not R2_ACCOUNT_ID: missing_r2.append("account_id")
                    if not R2_ACCESS_KEY_ID: missing_r2.append("access_key_id")
                    if not R2_SECRET_ACCESS_KEY: missing_r2.append("secret_access_key")
                    if not R2_BUCKET_NAME: missing_r2.append("bucket_name")
                    if R2_MAX_UPLOAD_MB <= 0: missing_r2.append("max_upload_mb")
                    if R2_MAX_STORAGE_MB <= 0: missing_r2.append("max_storage_mb")
                    if missing_r2:
                        raise ValueError("R2 未配置完整，请先设置：" + ", ".join(missing_r2))
                    if content_length <= 0:
                        raise ValueError("空请求体")
                    avatar_limit = min(R2_MAX_UPLOAD_MB, 5) * 1024 * 1024
                    if content_length > avatar_limit + 256 * 1024:
                        raise ValueError(f"头像文件过大，最大允许 {avatar_limit // (1024 * 1024)}MB")
                    if "multipart/form-data" not in content_type.lower():
                        raise ValueError("请使用 multipart/form-data 上传")
                    raw_body = self.rfile.read(content_length)
                    parts = parse_multipart(raw_body, content_type)
                    user_id = ""
                    file_part = None
                    for part in parts:
                        if part.get("name") == "user_id" and not part.get("filename"):
                            user_id = bytes(part.get("data") or b"").decode("utf-8", errors="replace").strip()
                        if part.get("filename") and part.get("name") in ("file", "avatar", "upload"):
                            file_part = part
                    if not re.fullmatch(r"[A-Za-z0-9_-]{2,64}", user_id):
                        raise ValueError("用户 ID 格式无效")
                    if not file_part or not file_part.get("data"):
                        raise ValueError("未找到头像文件")
                    avatar_data = bytes(file_part["data"])
                    # 头像已物化，尽快释放整个请求体与所有 memoryview 切片
                    for _p in parts:
                        _d = _p.get("data")
                        if isinstance(_d, memoryview):
                            _d.release()
                        _p["data"] = b""
                    parts = None
                    raw_body = None
                    if len(avatar_data) > avatar_limit:
                        raise ValueError(f"头像文件过大，最大允许 {avatar_limit // (1024 * 1024)}MB")
                    avatar_type = str(file_part.get("content_type") or "").lower().split(";", 1)[0].strip()
                    if avatar_type == "image/png" and avatar_data.startswith(b"\x89PNG\r\n\x1a\n"):
                        ext = ".png"
                    elif avatar_type in ("image/jpeg", "image/jpg") and avatar_data.startswith(b"\xff\xd8\xff"):
                        ext = ".jpg"
                        avatar_type = "image/jpeg"
                    elif avatar_type == "image/webp" and avatar_data[:4] == b"RIFF" and avatar_data[8:12] == b"WEBP":
                        ext = ".webp"
                    else:
                        raise ValueError("头像仅支持 PNG、JPEG 或 WebP 图片")

                    # 达到容量阈值时只清理聊天媒体，avatars/ 始终保留。
                    total_bytes = get_r2_bucket_total_size()
                    if total_bytes >= R2_MAX_STORAGE_MB * 1024 * 1024:
                        empty_r2_bucket(preserve_avatars=True)

                    object_key = avatar_object_key(user_id, ext)
                    r2_put_object(avatar_data, object_key, avatar_type)
                    version = hashlib.sha256(avatar_data).hexdigest()[:24]
                    avatar_url = r2_public_object_url(object_key, version)
                    info(f"[R2头像] 上传成功 user={user_id} size={len(avatar_data)} key={object_key}")
                    check_r2_bucket_capacity("上传后检查")
                    data = {
                        "ok": True,
                        "url": avatar_url,
                        "object_key": object_key,
                        "file_size": len(avatar_data),
                        "mime_type": avatar_type,
                    }
                    body, headers, status = make_json_response(data)
                except Exception as e:
                    err(f"[R2头像] 上传失败: {e}")
                    body, headers, status = make_json_response({"ok": False, "error": str(e)}, status=400)
                self._send(body, headers, status)
                return

            # ---- 聊天媒体上传 → Cloudflare R2 ----
            if path == "/api/upload":
                try:
                    # ★ 先按磁盘上的 env.json 刷新运行时 R2 配置（同上，兼容外部恢复文件）。
                    reload_r2_config_if_changed()
                    missing_r2 = []
                    if not R2_ACCOUNT_ID: missing_r2.append("account_id")
                    if not R2_ACCESS_KEY_ID: missing_r2.append("access_key_id")
                    if not R2_SECRET_ACCESS_KEY: missing_r2.append("secret_access_key")
                    if not R2_BUCKET_NAME: missing_r2.append("bucket_name")
                    if R2_MAX_UPLOAD_MB <= 0: missing_r2.append("max_upload_mb")
                    if R2_MAX_STORAGE_MB <= 0: missing_r2.append("max_storage_mb")
                    if missing_r2:
                        raise ValueError("R2 未配置完整，请先设置：" + ", ".join(missing_r2))
                    if content_length <= 0:
                        raise ValueError("空请求体")
                    if content_length > R2_MAX_UPLOAD_MB * 1024 * 1024 + 1024 * 1024:
                        raise ValueError(f"文件过大，最大允许 {R2_MAX_UPLOAD_MB}MB")
                    # 按用户配置的容量限制检查；不再内置固定桶容量值。
                    try:
                        total_bytes = get_r2_bucket_total_size()
                        limit_bytes = R2_MAX_STORAGE_MB * 1024 * 1024
                        if total_bytes >= limit_bytes:
                            try:
                                info(f"[R2] 已达 {R2_MAX_STORAGE_MB}MB 上限，清理聊天媒体并保留头像...")
                                empty_r2_bucket(preserve_avatars=True)
                                info("[R2] 聊天媒体已清理，用户头像已保留，继续本次上传")
                            except Exception as exc:
                                err(f"[R2] 清空存储桶异常: {exc}")
                            # 清空后继续本次上传，不再拒绝
                    except ValueError:
                        raise
                    except Exception as exc:
                        err(f"[R2] 容量检查异常: {exc}")
                        raise ValueError("存储状态异常，已关闭上传")
                    raw_body = self.rfile.read(content_length)
                    if "multipart/form-data" not in content_type.lower():
                        raise ValueError("请使用 multipart/form-data 上传")
                    parts = parse_multipart(raw_body, content_type)
                    file_part = None
                    for p in parts:
                        if p.get("filename") or p.get("name") in ("file", "media", "upload"):
                            file_part = p
                            if p.get("filename"):
                                break
                    if not file_part or not file_part.get("data"):
                        raise ValueError("未找到上传文件字段（name=file）")
                    if len(file_part["data"]) > R2_MAX_UPLOAD_MB * 1024 * 1024:
                        raise ValueError(f"文件过大，最大允许 {R2_MAX_UPLOAD_MB}MB")
                    data = bytes(file_part["data"])
                    # 原始文件名（含中文），返回给前端显示
                    original_filename = file_part.get("filename") or "file"
                    part_ctype = file_part.get("content_type") or ""
                    # 文件已物化，立刻释放请求体与所有段的 memoryview 引用，
                    # 避免整份 raw_body 在 R2 上传（网络耗时）期间一直驻留内存
                    for _p in parts:
                        _d = _p.get("data")
                        if isinstance(_d, memoryview):
                            _d.release()
                        _p["data"] = b""
                    parts = None
                    file_part = None
                    raw_body = None
                    # object_key 只用 UUID+ASCII扩展名，避免中文导致 R2 签名/URL 问题
                    filename = _cos_safe_filename(original_filename)
                    ctype = part_ctype or mimetypes.guess_type(filename)[0] or "application/octet-stream"
                    file_type = _cos_guess_file_type(filename, ctype)
                    day = datetime.now(timezone.utc).strftime("%Y%m%d")
                    # 从安全文件名提取纯 ASCII 扩展名
                    safe_base = re.sub(r"[^a-zA-Z0-9._-]", "", filename)
                    ext_match = re.search(r"(\.[a-zA-Z0-9_.-]+)$", safe_base)
                    ext = ext_match.group(1) if ext_match else ""
                    object_key = f"chat/{file_type}/{day}/{uuid.uuid4().hex}{ext}"
                    url = r2_put_object(data, object_key, ctype)
                    info(f"[R2] 上传成功 type={file_type} size={len(data)} key={object_key}")
                    check_r2_bucket_capacity("上传后检查")
                    resp = {
                        "ok": True,
                        "url": url,
                        "file_type": file_type,
                        "file_name": original_filename,
                        "file_size": len(data),
                        "mime_type": ctype,
                        "object_key": object_key,
                    }
                    body, headers, status = make_json_response(resp)
                except Exception as e:
                    err(f"[R2] 上传失败: {e}")
                    body, headers, status = make_json_response(
                        {"ok": False, "error": str(e)}, status=400
                    )
                self._send(body, headers, status)
                return

            # 其余 POST 接口使用 JSON body
            try:
                # 上限保护：JSON 接口不该收到大包，避免恶意/异常请求一次性
                # 吃掉几百 MB（原实现无条件按 Content-Length 全量读入）
                if content_length > MAX_JSON_BODY_BYTES:
                    raise ValueError("请求体过大")
                raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
                req_json = json.loads(raw_body.decode("utf-8") or "{}")
                raw_body = None
                if not isinstance(req_json, dict):
                    req_json = {}
            except Exception:
                req_json = {}

            # ---- 内置下载器：流式下载到 Android /Download ----
            if path == "/api/download":
                try:
                    download_url = str(req_json.get("url", "")).strip()
                    download_name = str(req_json.get("filename", req_json.get("file_name", ""))).strip()
                    restore_xor = bool(req_json.get("xor", False))
                    if not download_url:
                        raise ValueError("缺少下载地址")
                    # 后端再次兜底：公网请求禁止写入服务端手机 Download 目录，通知前端改走浏览器。
                    is_public, client_ip = is_public_request(self)
                    if is_public:
                        data = {
                            "ok": False,
                            "use_browser": True,
                            "error": "公网访问请使用浏览器下载",
                            "client_ip": client_ip,
                        }
                        body, headers, status = make_json_response(data, status=409)
                        self._send(body, headers, status)
                        return
                    result = download_url_to_android(download_url, download_name, restore_xor)
                    info(
                        f"[下载器] 下载完成 name={result['file_name']} size={result['file_size']} "
                        f"path={result['file_path']} xor={restore_xor}"
                    )
                    data = {"ok": True, **result}
                    body, headers, status = make_json_response(data)
                except Exception as e:
                    err(f"[下载器] 下载失败: {e}")
                    data = {"ok": False, "error": str(e), "directory": str(DOWNLOAD_DIR)}
                    body, headers, status = make_json_response(data, status=400)
                self._send(body, headers, status)
                return

            if path == "/api/servers/add":
                try:
                    name = str(req_json.get("name", "")).strip()
                    host = str(req_json.get("host", "")).strip()
                    port = int(req_json.get("port", 11451))
                    stype = str(req_json.get("type", "graphql")).strip().lower()
                    region = str(req_json.get("region", "")).strip()
                    if not region:
                        region = "🌐 未知"
                    srv_id = str(req_json.get("id", "")).strip()

                    if srv_id:
                        if not ID_RE.fullmatch(srv_id):
                            raise ValueError("ID 格式无效，仅允许字母、数字、下划线、空格和连字符，长度1-64")
                        if not is_id_available(srv_id):
                            raise ValueError(f"ID '{srv_id}' 已被其他服务器占用")
                    else:
                        srv_id = f"manual_{uuid.uuid4().hex[:8]}"

                    new_server = {
                        "id": srv_id,
                        "name": name,
                        "host": host,
                        "port": port,
                        "type": stype,
                        "region": region,
                        "is_manual": True
                    }
                    validated = validate_server(new_server)
                    local_path = Path(MANUAL_SERVERS_FILE)
                    existing_list = []
                    if local_path.is_file():
                        try:
                            existing_list = json.loads(local_path.read_text(encoding="utf-8"))
                            if not isinstance(existing_list, list):
                                existing_list = []
                        except Exception:
                            existing_list = []
                    existing_list.append(validated)
                    local_path.write_text(json.dumps(existing_list, ensure_ascii=False, indent=2), encoding="utf-8")
                    ctx.refresh_config(force=True)
                    data = {"ok": True, "server": validated}
                    body, headers, status = make_json_response(data)
                except Exception as e:
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=400)
                self._send(body, headers, status)
                return

            if path == "/api/servers/delete":
                try:
                    sid = str(req_json.get("id", "")).strip()
                    local_path = Path(MANUAL_SERVERS_FILE)
                    if not local_path.is_file():
                        raise RuntimeError("没有找到本地配置文件")
                    existing_list = json.loads(local_path.read_text(encoding="utf-8"))
                    if not isinstance(existing_list, list):
                        existing_list = []
                    new_list = [item for item in existing_list if str(item.get("id")) != sid]
                    local_path.write_text(json.dumps(new_list, ensure_ascii=False, indent=2), encoding="utf-8")
                    ctx.refresh_config(force=True)
                    data = {"ok": True}
                    body, headers, status = make_json_response(data)
                except Exception as e:
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=400)
                self._send(body, headers, status)
                return

            if path == "/api/servers/edit":
                try:
                    old_id = str(req_json.get("id", "")).strip()
                    new_id = str(req_json.get("new_id", old_id)).strip()
                    name = str(req_json.get("name", "")).strip()
                    host = str(req_json.get("host", "")).strip()
                    port = int(req_json.get("port", 11451))
                    stype = str(req_json.get("type", "graphql")).strip().lower()
                    region = str(req_json.get("region", "")).strip()

                    if new_id != old_id:
                        if not ID_RE.fullmatch(new_id):
                            raise ValueError("新 ID 格式无效，仅允许字母、数字、下划线、空格和连字符，长度1-64")
                        if not is_id_available(new_id, exclude_id=old_id):
                            raise ValueError(f"ID '{new_id}' 已被其他服务器占用")

                    local_path = Path(MANUAL_SERVERS_FILE)
                    if not local_path.is_file():
                        raise RuntimeError("没有找到本地配置文件")
                    existing_list = json.loads(local_path.read_text(encoding="utf-8"))
                    if not isinstance(existing_list, list):
                        existing_list = []
                    found = False
                    for item in existing_list:
                        if str(item.get("id")) == old_id:
                            item["id"] = new_id
                            item["name"] = name
                            item["host"] = host
                            item["port"] = port
                            item["type"] = stype
                            item["region"] = region
                            found = True
                            break
                    if not found:
                        raise RuntimeError("未找到指定 ID 的服务器")
                    validated = validate_server(item)
                    for k, v in validated.items():
                        item[k] = v
                    local_path.write_text(json.dumps(existing_list, ensure_ascii=False, indent=2), encoding="utf-8")
                    ctx.refresh_config(force=True)
                    data = {"ok": True}
                    body, headers, status = make_json_response(data)
                except Exception as e:
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=400)
                self._send(body, headers, status)
                return

            if path == "/api/env/set-password":
                try:
                    # 若已设置密码，则需先用旧密码验证才能修改
                    if is_password_set():
                        old_pw = str(req_json.get("old_password", ""))
                        if not verify_password(old_pw):
                            raise PermissionError("需要正确的旧密码才能修改安全密码")
                    password = str(req_json.get("password", ""))
                    set_security_password(password)
                    data = {"ok": True}
                    body, headers, status = make_json_response(data)
                except PermissionError as e:
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=403)
                except Exception as e:
                    err(f"[API] /api/env/set-password 异常: {e}")
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=400)
                self._send(body, headers, status)
                return

            if path == "/api/env/verify-password":
                try:
                    ok = verify_password(req_json.get("password", ""))
                    data = {"ok": True, "verified": ok}
                    body, headers, status = make_json_response(data)
                except Exception as e:
                    err(f"[API] /api/env/verify-password 异常: {e}")
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=400)
                self._send(body, headers, status)
                return

            if path == "/api/env/save":
                try:
                    # 安全：若已设置密码，必须提供正确密码才能修改配置
                    if is_password_set():
                        pw = str(req_json.get("password", ""))
                        if not verify_password(pw):
                            raise PermissionError("需要正确的安全密码才能修改环境变量配置")
                    cfg = save_env_config(req_json)
                    data = {"ok": True, "config": cfg, "file": ENV_CONFIG_FILE}
                    body, headers, status = make_json_response(data)
                except PermissionError as e:
                    data = {"ok": False, "error": str(e), "need_password": True}
                    body, headers, status = make_json_response(data, status=403)
                except Exception as e:
                    err(f"[API] /api/env/save 异常: {e}")
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=400)
                self._send(body, headers, status)
                return

            if path == "/api/update/frontend":
                try:
                    result = do_update_frontend()
                    if result.get("ok"):
                        if result.get("skipped"):
                            data = {"ok": True, "skipped": True, "message": result.get("message"), "target": "frontend"}
                        else:
                            data = {"ok": True, "skipped": False, "message": result.get("message", "前端更新完成请重启应用"), "target": "frontend"}
                        body, headers, status = make_json_response(data)
                    else:
                        data = {"ok": False, "error": result.get("error", "更新失败"), "target": "frontend"}
                        body, headers, status = make_json_response(data, status=500)
                except Exception as e:
                    data = {"ok": False, "error": str(e), "target": "frontend"}
                    body, headers, status = make_json_response(data, status=500)
                self._send(body, headers, status)
                return

            if path == "/api/update/backend":
                try:
                    result = do_update_backend()
                    if result.get("ok"):
                        if result.get("skipped"):
                            data = {"ok": True, "skipped": True, "message": result.get("message"), "target": "backend", "mode": result.get("mode")}
                        else:
                            data = {"ok": True, "skipped": False, "message": result.get("message", "后端更新完成请重启应用"), "target": "backend", "mode": result.get("mode")}
                        body, headers, status = make_json_response(data)
                    else:
                        data = {"ok": False, "error": result.get("error", "更新失败"), "target": "backend"}
                        body, headers, status = make_json_response(data, status=500)
                except Exception as e:
                    data = {"ok": False, "error": str(e), "target": "backend"}
                    body, headers, status = make_json_response(data, status=500)
                self._send(body, headers, status)
                return

            if path == "/api/update/all":
                try:
                    fe = do_update_frontend()
                    be = do_update_backend()
                    data = {"ok": True, "frontend": fe, "backend": be}
                    body, headers, status = make_json_response(data)
                except Exception as e:
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=500)
                self._send(body, headers, status)
                return

            if path == "/api/servers/reorder":
                try:
                    order = req_json.get("order", [])
                    is_reset = req_json.get("reset", False)
                    local_path = Path(MANUAL_SERVERS_FILE)
                    if is_reset:
                        if local_path.is_file():
                            try:
                                ex_list = json.loads(local_path.read_text(encoding="utf-8"))
                                if isinstance(ex_list, list):
                                    local_path.write_text(json.dumps(ex_list, ensure_ascii=False, indent=2), encoding="utf-8")
                            except Exception:
                                pass
                        ctx.refresh_config(force=True)
                    elif isinstance(order, list) and order:
                        existing_map: dict[str, dict] = {}
                        if local_path.is_file():
                            try:
                                ex_list = json.loads(local_path.read_text(encoding="utf-8"))
                                if isinstance(ex_list, list):
                                    existing_map = {str(item.get("id")): item for item in ex_list}
                            except Exception:
                                pass
                        reordered = [existing_map[sid] for sid in order if sid in existing_map]
                        for sid, item in existing_map.items():
                            if sid not in order:
                                reordered.append(item)
                        if reordered:
                            local_path.write_text(json.dumps(reordered, ensure_ascii=False, indent=2), encoding="utf-8")
                            ctx.refresh_config(force=True)
                    data = {"ok": True}
                    body, headers, status = make_json_response(data)
                except Exception as e:
                    data = {"ok": False, "error": str(e)}
                    body, headers, status = make_json_response(data, status=400)
                self._send(body, headers, status)
                return

            self.send_response(404)
            self.end_headers()
        except Exception as e:
            err(f"[HTTP] POST {self.path} 处理异常: {e}")
            try:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
            except Exception:
                pass

    def _send(self, body: bytes, headers: dict[str, str], status: int):
        try:
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            err(f"[HTTP] _send 异常: {e}")

# ============================================================================
# SECTION 16 · 入口
# ============================================================================

class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """内存优化版 HTTP 服务器。

    1. block_on_close=False：不再保留所有已结束线程对象的引用。
       ThreadingMixIn 默认会把每个 handler 线程放进 self._threads 列表，
       并且**永不清理**——长时间运行后这个列表会累积上万个 Thread 对象，
       是典型的隐性内存泄漏。
    2. 限制并发连接数，避免突发请求瞬间创建大量线程栈。
    3. 开启 TCP_NODELAY，减少发送缓冲堆积。
    """

    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True
    request_queue_size = 64
    # 同时处理的请求上限（长轮询日志接口会长期占用连接，故留有余量）
    max_concurrent_requests = int(os.getenv("MAX_CONCURRENT_REQUESTS", "48"))

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._slots = threading.BoundedSemaphore(self.max_concurrent_requests)

    def process_request(self, request, client_address):  # type: ignore[override]
        if not self._slots.acquire(blocking=False):
            # 达到并发上限：直接关闭，不再新建线程（宁可拒绝也不 OOM）
            try:
                self.shutdown_request(request)
            except Exception:
                pass
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def shutdown_request(self, request):  # type: ignore[override]
        try:
            super().shutdown_request(request)
        finally:
            pass

    def process_request_thread(self, request, client_address):  # type: ignore[override]
        try:
            super().process_request_thread(request, client_address)
        finally:
            try:
                self._slots.release()
            except ValueError:
                pass


def _memory_watchdog() -> None:
    """周期性回收：给长期运行的移动端进程一个稳定的内存基线。

    - 定期 gc.collect()，回收扫描/聊天产生的循环引用（dict 互指很常见）
    - 调用 malloc_trim 把 glibc/bionic 已释放但未归还系统的堆归还 OS，
      这一步能显著降低 Android 上观察到的 RSS（Python 层 free 不等于
      进程 RSS 下降）
    """
    trim = None
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        trim = libc.malloc_trim
        trim.argtypes = [ctypes.c_size_t]
    except Exception:
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so")
            trim = getattr(libc, "malloc_trim", None)
            if trim is not None:
                trim.argtypes = [ctypes.c_size_t]
        except Exception:
            trim = None

    while True:
        time.sleep(GC_INTERVAL)
        try:
            gc.collect()
            if trim is not None:
                trim(0)
        except Exception:
            pass


def main() -> None:
    time.sleep(1.0) # 启动等待时长

    # GC 调优：默认阈值 (700,10,10) 对“每秒产生大量短命 dict”的轮询型
    # 服务过于激进，会频繁做全代扫描。放大阈值可减少 CPU 抖动，
    # 同时由 watchdog 定期做完整回收 + 归还堆内存。
    gc.set_threshold(2000, 25, 25)
    if gc.isenabled():
        gc.freeze()  # 把启动期常驻对象移出 GC 扫描范围，永久降低每次 GC 成本
    threading.Thread(target=_memory_watchdog, daemon=True, name="mem-watchdog").start()
    ensure_frontend_exists()
    # 不再启动时自动创建 env.json；文件仅在「设置安全密码 / 保存环境变量」时生成。
    runtime_env_config = load_env_config()
    apply_r2_config_to_runtime(runtime_env_config)
    ctx.refresh_config(force=True)
    info(f"[配置] 环境变量配置文件: {ENV_CONFIG_FILE}")
    info(f"[配置] 初始服务器数: {len(ctx.servers)}")
    info(f"[配置] 远程文件下载间隔: {REMOTE_DOWNLOAD_INTERVAL} 秒")
    info(f"[配置] 远程服务器列表本地路径: {LOCAL_SERVERS_FILE}")
    info(f"[配置] 远程标题映射本地路径: {LOCAL_CHINESE_DB_FILE}")
    info(f"[配置] 全局 TTL: {CACHE_TTL} 秒")

    # 仅配置完整时检查 R2；无内置值的全新安装直接跳过。
    r2_ready = bool(
        R2_ACCOUNT_ID and R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY and R2_BUCKET_NAME
        and R2_MAX_UPLOAD_MB > 0 and R2_MAX_STORAGE_MB > 0
    )
    if r2_ready:
        check_r2_bucket_capacity("启动检查")
    else:
        info("[R2 启动检查] 未配置，已跳过")

    start_remote_download_thread()

    port = int(os.getenv("PORT", "11451"))
    server_address = ("0.0.0.0", port)
    httpd = ThreadingHTTPServer(server_address, MonitorHandler)
    info(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 监控服务已启动，监听端口: {port}")
    info(f"[访问地址] http://0.0.0.0:{port}/")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        info("\n[服务] 正在关闭...")
        for scanner in ctx.scanners.values():
            scanner.close()
        SCAN_EXECUTOR.shutdown(wait=False)
        httpd.server_close()

if __name__ == "__main__":
    main()