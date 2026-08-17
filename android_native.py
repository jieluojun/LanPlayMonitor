#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Android 原生桥接封装 v2（整合自 android_filechooser）
=====================================================

本模块统一封装了以下三类 Android 原生能力：

  1. WebView 文件选择 / 麦克风录音（FileChooserHelper.java）
     原 android_filechooser.py 完整保留，等价函数：
       - install()             同时挂载 FileChooser / ImmersiveStatusBar / BatteryOptimization
       - get_status_logs()     返回 [文件选择] / [原生桥接] 两类日志
       - install_async         install 的别名，兼容旧调用

  2. 沉浸式状态栏 + 主题图标色（ImmersiveStatusBarHelper.java）
     WebView 延伸到状态栏下方，前端通过 `window.LanPlayNative.syncPageTheme(true|false)` 切换图标色。
     本模块仅提供信息查询 / 状态回调，无 Python 端直接调用入口。

  3. 主动请求"忽略电池优化"（BatteryOptimizationHelper.java）
       - request_ignore_battery_optimizations()    启动时一次性弹窗
       - is_ignoring_battery_optimizations()       查询当前是否在白名单
       - reset_battery_opt_prompted_flag()         清掉"已询问"标记（用于手动重试）

设计原则：
  1. 桌面环境 (ANDROID_APP_PATH 为空) 下所有方法都是 no-op，绝不抛异常。
  2. 必须在主线程启动时同步调用 install()（与原 android_filechooser.install() 同样的规则）。
  3. 不强依赖具体 Java 类：类加载失败时只打日志、不抛异常，并继续尝试其它类。
  4. 提供清晰的 Python 端 API，main.py 不再需要单独 import android_filechooser。
"""
from __future__ import annotations

import os
from typing import Any

# =============================================================================
# 1. 统一日志缓冲区（同时承载 [文件选择] / [原生桥接] 两类日志）
# =============================================================================
_STATUS_LOGS: list[str] = []


def _log(tag: str, msg: str) -> None:
    """带 [tag] 前缀的日志，tag 取 '文件选择' 或 '原生桥接'"""
    full_msg = f"[{tag}] {msg}"
    print(full_msg)
    _STATUS_LOGS.append(full_msg)


def _log_filechooser(msg: str) -> None:
    """兼容原 android_filechooser._log 的调用方式（保持 [文件选择] 前缀）"""
    _log("文件选择", msg)


def get_status_logs() -> list[str]:
    """供 main.py 的 /api/logs 在最底部常驻展示（同时包含文件选择和原生桥接状态）"""
    if not _STATUS_LOGS:
        return ["[原生桥接] 状态: 未执行 android_native.install()"]
    return list(_STATUS_LOGS)


# =============================================================================
# 2. jnius 句柄（延迟加载 / 失败缓存）
# =============================================================================
_autoclass_fn = None
_autoclass_tried = False
_autoclass_error = None       # pyjnius 加载失败的错误信息
_PythonActivity_cls = None
_PythonActivity_failed = False  # 类加载失败后不再重试
_PythonActivity_error = None    # 失败原因（仅记录一次）
_mactivity_cached = None          # 在 install() 所在线程预取，供后续 Python 子线程复用
_mactivity_error_logged = False  # mActivity 读取失败只打印一次


def _get_autoclass():
    """获取 pyjnius.autoclass，失败返回 None 且不再重试"""
    global _autoclass_fn, _autoclass_tried, _autoclass_error
    if _autoclass_fn is not None:
        return _autoclass_fn
    if _autoclass_tried:
        return None
    _autoclass_tried = True
    try:
        from jnius import autoclass  # type: ignore
        _autoclass_fn = autoclass
        return _autoclass_fn
    except Exception as exc:
        _autoclass_error = repr(exc)
        _log("原生桥接", f"❌ pyjnius 不可用，原生桥接将被禁用: {exc!r}")
        return None


def _get_python_activity_cls():
    """获取 org.kivy.android.PythonActivity 类引用，失败返回 None（且只报错一次）"""
    global _PythonActivity_cls, _PythonActivity_failed, _PythonActivity_error
    if _PythonActivity_cls is not None:
        return _PythonActivity_cls
    if _PythonActivity_failed:
        return None
    autoclass = _get_autoclass()
    if autoclass is None:
        return None
    try:
        _PythonActivity_cls = autoclass("org.kivy.android.PythonActivity")
        return _PythonActivity_cls
    except Exception as exc:
        _PythonActivity_failed = True
        _PythonActivity_error = repr(exc)
        _log("原生桥接", f"❌ PythonActivity 类加载失败: {exc!r}")
        return None


def _get_mactivity():
    """取得 PythonActivity.mActivity，并缓存供后续 Python 子线程使用。

    pyjnius 首次 autoclass() 会使用当前线程的 Java ClassLoader。应用启动后创建的
    Python 子线程可能拿不到 APK 的 ClassLoader，从而误报 ClassNotFoundException；
    因此 install() 会在启动线程中预取本对象，后续线程不再重新加载 Activity 类。
    """
    global _mactivity_cached, _mactivity_error_logged
    if _mactivity_cached is not None:
        return _mactivity_cached
    cls = _get_python_activity_cls()
    if cls is None:
        return None
    try:
        activity = cls.mActivity
        if activity is None:
            raise RuntimeError("PythonActivity.mActivity 尚未就绪")
        _mactivity_cached = activity
        return _mactivity_cached
    except Exception as exc:
        if not _mactivity_error_logged:
            _mactivity_error_logged = True
            _log("原生桥接", f"❌ 读取 PythonActivity.mActivity 失败: {exc!r}")
        return None


# =============================================================================
# 3. 公共入口 install() - 整合了原 android_filechooser.install()
# =============================================================================
def install() -> bool:
    """
    必须在 main.py 主线程启动时同步调用（切勿在 Python 子线程里调 autoclass，
    否则 Android JNI 会报 ClassNotFoundException）。

    这一步会按顺序做三件事：
      a) 加载 Java 类（FileChooserHelper / ImmersiveStatusBarHelper / BatteryOptimizationHelper）
      b) 真正干活：调用 FileChooserHelper.install()，Java 端会：
           - 挂载 WebChromeClient（相册/视频选择 + 麦克风录音）
           - 启用沉浸式状态栏
           - 通过 FileChooserHelper 内部调用 BatteryOptimizationHelper
      c) 记录日志供 /api/logs 展示

    返回 True 表示至少有一个 Java 类加载成功。
    """
    _STATUS_LOGS.clear()
    app_path = os.environ.get("ANDROID_APP_PATH")
    _log_filechooser(f"install() 被调用, ANDROID_APP_PATH={app_path!r}")

    if not app_path:
        _log_filechooser("非 Android 真机环境（桌面调试），跳过原生挂载")
        return False

    # ----- 3.1 检查 jnius -----
    if _get_autoclass() is None:
        _log_filechooser("请检查 buildozer.spec 的 requirements 是否包含 pyjnius")
        return False
    _log_filechooser("pyjnius 导入成功")

    # 必须在 install() 所在的启动线程预加载 PythonActivity 和 mActivity。
    # main.py 随后会在 battery-opt-request Python 子线程调用电池接口；若到那时才
    # 首次 autoclass PythonActivity，子线程的 ClassLoader 可能看不到 APK 类。
    activity = _get_mactivity()
    if activity is not None:
        _log("原生桥接", "✅ PythonActivity/mActivity 已在启动线程预加载")
    else:
        _log("原生桥接", "⚠️ PythonActivity/mActivity 预加载失败，依赖 Activity 的接口将不可用")

    # ----- 3.2 探测三个 Java 类（只加载，不调用 install） -----
    classes_to_probe = [
        "org.kivy.android.FileChooserHelper",
        "org.kivy.android.ImmersiveStatusBarHelper",
        "org.kivy.android.BatteryOptimizationHelper",
    ]
    loaded_any = False
    for cls_name in classes_to_probe:
        try:
            _ = _get_autoclass()(cls_name)
            _log("原生桥接", f"✅ Java 类已加载: {cls_name}")
            loaded_any = True
        except Exception as exc:
            _log("原生桥接",
                 f"⚠️ Java 类未找到 {cls_name}: {exc!r}（可在 buildozer.spec 检查 android.add_src 是否正确）")

    if not loaded_any:
        _log("原生桥接", "❌ 三个 Java 类都加载失败，跳过 FileChooserHelper.install()")
        return False

    # ----- 3.3 真正挂载：FileChooserHelper.install() 内部会调沉浸式+电池优化 -----
    try:
        Helper = _get_autoclass()("org.kivy.android.FileChooserHelper")
        ok = bool(Helper.install())
        if ok:
            _log_filechooser("✅ WebChromeClient 已成功挂载到 WebView！（相册/视频选择 + 麦克风录音已启用）")
            _log("原生桥接", "✅ Android 原生桥接就绪（沉浸式状态栏 + 电池优化 + 主题同步）")
            return True
        else:
            _log_filechooser("⚠️ Helper.install() 返回 false（PythonActivity 或 WebView 未就绪）")
            return False
    except Exception as exc:
        _log_filechooser(f"❌ Helper.install() 启动失败: {exc!r}")
        return False


# 兼容原 android_filechooser 的别名
install_async = install


# =============================================================================
# 4. 电池优化：Python 端接口
# =============================================================================
def request_ignore_battery_optimizations() -> bool:
    """
    主动请求"忽略电池优化"。
    Java 端有去重逻辑：同一进程只弹一次，重启后用户没拒绝过才会再弹。
    返回 True 表示本次"真的弹了"或"已经跳到系统设置"。
    """
    Helper = _get_autoclass()
    if Helper is None:
        return False
    mactivity = _get_mactivity()
    if mactivity is None:
        return False
    try:
        BatteryHelper = Helper("org.kivy.android.BatteryOptimizationHelper")
        ok = bool(BatteryHelper.requestIgnoreBatteryOptimizationsIfNeeded(mactivity))
        _log("电池优化", f"请求忽略电池优化 → {ok}")
        return ok
    except Exception as exc:
        _log("电池优化", f"❌ request_ignore_battery_optimizations 失败: {exc!r}")
        return False


def is_ignoring_battery_optimizations() -> bool:
    """查询当前是否已经在电池优化白名单中（用于 /api/logs 展示）"""
    mactivity = _get_mactivity()
    if mactivity is None:
        return False
    try:
        pm = mactivity.getSystemService("power")  # Context.POWER_SERVICE = "power"
        if pm is None:
            return False
        return bool(pm.isIgnoringBatteryOptimizations(mactivity.getPackageName()))
    except Exception as exc:
        _log("原生桥接", f"❌ is_ignoring_battery_optimizations 失败: {exc!r}")
        return False


def reset_battery_opt_prompted_flag() -> bool:
    """
    重置 Java 端"已询问过电池优化"的标记。
    主要用途：用户主动在导航栏点击"再次申请"按钮时，先清标记再调 request。
    """
    Helper = _get_autoclass()
    if Helper is None:
        return False
    mactivity = _get_mactivity()
    if mactivity is None:
        return False
    try:
        BatteryHelper = Helper("org.kivy.android.BatteryOptimizationHelper")
        BatteryHelper.resetPromptedFlag(mactivity.getApplicationContext())
        _log("电池优化", "已重置电池优化询问标记")
        return True
    except Exception as exc:
        _log("原生桥接", f"❌ reset_battery_opt_prompted_flag 失败: {exc!r}")
        return False


# =============================================================================
# 5. 主题 / 沉浸式：Python 端信息查询
# =============================================================================
def get_system_dark_mode() -> bool:
    """读取当前 Android 系统的白天/夜间模式（Configuration.uiMode）"""
    mactivity = _get_mactivity()
    if mactivity is None:
        return False
    try:
        config = mactivity.getResources().getConfiguration()
        # Configuration.UI_MODE_NIGHT_YES = 0x20, UI_MODE_NIGHT_NO = 0x10
        return bool(config.uiMode & 0x20)
    except Exception as exc:
        _log("原生桥接", f"❌ get_system_dark_mode 失败: {exc!r}")
        return False


def get_native_info() -> dict[str, Any]:
    """统一返回原生层信息，给前端 /api/logs 排查用"""
    info: dict[str, Any] = {"available": _get_autoclass() is not None}
    if not info["available"]:
        info["error"] = "pyjnius not loaded"
        return info
    try:
        info["isSystemDark"] = get_system_dark_mode()
    except Exception:
        info["isSystemDark"] = False
    try:
        info["isIgnoringBatteryOptimizations"] = is_ignoring_battery_optimizations()
    except Exception:
        info["isIgnoringBatteryOptimizations"] = False
    return info


# =============================================================================
# 6. 兼容旧版 android_filechooser 公开 API（仅暴露函数，不暴露内部变量）
# =============================================================================
# 让外部代码可以这样写：
#     from android_native import filechooser
#     filechooser.install()                # 等价于 android_native.install()
#     filechooser.get_status_logs()        # 实际就是 android_native.get_status_logs()
# 这样在过渡期 main.py 仍可保留 `import android_filechooser as filechooser` 写法。
class _FileChooserCompat:
    """兼容层：等价于原来的 android_filechooser 模块"""
    install = staticmethod(install)
    install_async = staticmethod(install_async)
    get_status_logs = staticmethod(get_status_logs)


# 用法： from android_native import filechooser
filechooser = _FileChooserCompat()
