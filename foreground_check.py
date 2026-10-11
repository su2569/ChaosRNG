#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Termux 前台检测

三级降级：
  A. shizuku/rish + dumpsys activity  → 精确
  B. root + /proc/ 检测              → 次优
  C. 无工具，假定在前台              → 兜底
"""

import os
import shutil
import subprocess
import logging
import time

logger = logging.getLogger("chaos_rng.foreground")


def _have_cmd(name):
    return shutil.which(name) is not None


class ForegroundChecker:
    def __init__(self, method="auto"):
        self.method = method
        self.package = "com.termux"
        self._check_interval = 0.5
        self._last_result = True
        self._last_check_time = 0.0

        if method == "auto":
            if _have_cmd("rish_auto") or _have_cmd("rish"):
                self._method = "shizuku"
            elif os.path.exists("/system/bin/su") or os.path.exists("/system/xbin/su"):
                self._method = "root"
            else:
                self._method = "assume"
        else:
            self._method = method

        logger.info(f"🔍 前台检测方法: {self._method}")

    def is_foreground(self) -> bool:
        """检查 Termux 是否在前台（带缓存）"""
        now = time.time()
        if now - self._last_check_time < self._check_interval:
            return self._last_result

        self._last_check_time = now
        try:
            if self._method == "shizuku":
                result = self._check_via_shizuku()
            elif self._method == "root":
                result = self._check_via_root()
            else:
                result = True

            self._last_result = result
            return result
        except Exception as e:
            logger.debug(f"前台检测失败: {e}")
            return self._last_result

    def _check_via_shizuku(self) -> bool:
        rish = "rish_auto" if _have_cmd("rish_auto") else "rish"
        try:
            r = subprocess.run(
                [rish, "-c",
                 f"dumpsys activity activities | grep -A 40 'packageName={self.package}'"],
                capture_output=True, text=True, timeout=5
            )
            return "nowVisible=true" in r.stdout
        except Exception:
            return self._last_result

    def _check_via_root(self) -> bool:
        try:
            r = subprocess.run(
                ["su", "-c",
                 f"dumpsys activity activities | grep -A 40 'packageName={self.package}'"],
                capture_output=True, text=True, timeout=5
            )
            return "nowVisible=true" in r.stdout
        except Exception:
            return self._last_result
