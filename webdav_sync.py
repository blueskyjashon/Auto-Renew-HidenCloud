# -*- coding: utf-8 -*-
"""
通过 Infinicloud (WebDAV) 持久化 HidenCloud 登录态 (Playwright cookies)。

环境变量:
  WEBDAV_URL   WebDAV 根地址 (Infinicloud My Page -> Apps Connection 里查看)
  WEBDAV_USER  WebDAV 用户名
  WEBDAV_PASS  WebDAV Apps Connection 密码
  WEBDAV_DIR   可选, 云端子目录, 默认 hidencloud (不存在会自动创建);
               填 "-" 表示直接放在 WEBDAV_URL 根目录 (和旧脚本一致)
               子目录创建失败时, 也会自动回退到根目录

未配置 WEBDAV_* 时, 所有方法静默跳过, 不影响原有流程。
"""
import os
import json
import time
import hashlib
import requests


class CookieStore:
    def __init__(self, account_key, log=print):
        self.log = log
        url = (os.environ.get("WEBDAV_URL") or "").strip()
        self.user = (os.environ.get("WEBDAV_USER") or "").strip()
        self.pwd = os.environ.get("WEBDAV_PASS") or ""
        self.enabled = bool(url and self.user and self.pwd)
        self._last_fingerprint = None

        if not self.enabled:
            return

        if not url.endswith("/"):
            url += "/"
        directory = (os.environ.get("WEBDAV_DIR") or "hidencloud").strip().strip("/")
        if directory == "-":
            directory = ""
        self.root_url = url
        self.dir_url = f"{url}{directory}/" if directory else url
        # 文件名用账号哈希, 避免在云端暴露邮箱, 也支持多账号共用一个目录
        digest = hashlib.sha256(account_key.encode("utf-8")).hexdigest()[:12]
        name = f"hiden_session_{digest}.json"
        self.file_url = f"{self.dir_url}{name}"
        # 候选位置: 首选子目录, 其次根目录 (旧脚本验证过根目录可写)
        self.candidates = [self.file_url]
        if self.dir_url != self.root_url:
            self.candidates.append(f"{self.root_url}{name}")

        self.http = requests.Session()
        self.http.trust_env = False          # 不走 HTTP(S)_PROXY, WebDAV 直连
        self.http.auth = (self.user, self.pwd)

    # ---------- 内部工具 ----------
    @staticmethod
    def _fingerprint(cookies):
        items = sorted(
            (c.get("name", ""), c.get("domain", ""), c.get("path", ""), c.get("value", ""))
            for c in cookies
        )
        return hashlib.sha256(json.dumps(items).encode("utf-8")).hexdigest()

    @staticmethod
    def _usable(cookies):
        """只保留 hidencloud 域名且未过期的 cookie。"""
        now = time.time()
        out = []
        for c in cookies:
            if "hidencloud.com" not in (c.get("domain") or ""):
                continue
            exp = c.get("expires", -1)
            if isinstance(exp, (int, float)) and exp != -1 and exp < now:
                continue
            out.append(c)
        return out

    def _mkcol(self):
        try:
            r = self.http.request("MKCOL", self.dir_url, timeout=30)
            self.log(f"📁 创建云端目录返回: {r.status_code}")
            return r.status_code in (201, 405)   # 405 = 已存在
        except Exception as e:
            self.log(f"❌ WebDAV 创建目录失败: {e}")
            return False

    # ---------- 对外接口 ----------
    def load(self):
        """返回 Playwright 格式的 cookie 列表; 无缓存/失败返回 None。"""
        if not self.enabled:
            self.log("⚠️ 未配置 WebDAV，跳过云端 Cookie 同步")
            return None
        self.log("☁️ 正在从 Infinicloud 读取登录态缓存...")
        for url in self.candidates:
            r = None
            try:
                r = self.http.get(url, timeout=30)
            except Exception as e:
                self.log(f"❌ WebDAV 读取异常: {e}")
                continue
            if r.status_code == 404:
                continue
            if r.status_code != 200:
                self.log(f"⚠️ WebDAV 读取失败，状态码: {r.status_code}")
                continue
            try:
                data = json.loads(r.content.decode("utf-8"))
                cookies = self._usable(data.get("cookies", []))
            except Exception as e:
                self.log(f"⚠️ 云端缓存解析失败: {e}")
                continue
            if not cookies:
                continue
            self._last_fingerprint = self._fingerprint(cookies)
            self.log(f"✅ 已读取云端缓存，共 {len(cookies)} 个 Cookie")
            return cookies
        self.log("⚪ 云端暂无缓存 (首次运行)")
        return None

    def save(self, cookies, force=False):
        """上传最新 cookie (context.cookies() 的返回值)。内容没变化则跳过。"""
        if not self.enabled:
            return False
        cookies = self._usable(cookies)
        if not cookies:
            self.log("⚪ 无可保存的 Cookie，跳过上传")
            return False
        fp = self._fingerprint(cookies)
        if not force and fp == self._last_fingerprint:
            self.log("⚪ Cookie 无变化，跳过上传")
            return True

        body = json.dumps(
            {"version": 1, "saved_at": int(time.time()), "cookies": cookies},
            ensure_ascii=False, indent=2,
        ).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8"}
        self.log("☁️ 正在上传最新登录态到 Infinicloud...")

        def put(url):
            return self.http.put(url, data=body, headers=headers, timeout=30)

        def brief(r):
            text = " ".join((r.text or "").split())[:120]
            return f"{r.status_code} {text}".strip()

        try:
            target = self.candidates[0]
            r = put(target)
            # 父目录不存在时, 不同 WebDAV 服务返回码不一致 (403/404/409 都见过), 统一尝试创建目录
            if r.status_code in (403, 404, 409) and len(self.candidates) > 1:
                self.log(f"⚠️ 上传返回 {r.status_code}，尝试创建目录后重试...")
                if self._mkcol():
                    r = put(target)
            # 仍失败: 回退到根目录
            if r.status_code not in (200, 201, 204) and len(self.candidates) > 1:
                self.log(f"⚠️ 子目录上传失败 ({brief(r)})，回退到根目录保存...")
                target = self.candidates[1]
                r = put(target)
            if r.status_code in (200, 201, 204):
                self.file_url = target
                self._last_fingerprint = fp
                where = "子目录" if target == self.candidates[0] else "根目录"
                self.log(f"✅ 云端缓存上传成功 ({where})")
                return True
            self.log(f"❌ WebDAV 上传失败: {brief(r)}")
        except Exception as e:
            self.log(f"❌ WebDAV 上传异常: {e}")
        return False
