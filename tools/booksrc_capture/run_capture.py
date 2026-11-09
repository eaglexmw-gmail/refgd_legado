#!/usr/bin/env python3
"""在本地 Android 模拟器中跑通一条书源的全链路，并按时间顺序导出原始 HTTP 报文。

流程：导入书源 -> 搜索 -> 书籍详情 -> 目录 -> 章节正文，全程经 mitmproxy 抓包。

依赖：pip install -r requirements.txt  (mitmproxy, websocket-client)
运行：run.ps1（Windows 一键脚本）或
      python run_capture.py --sdk-root <SDK> --apk <APK> --source1 a.json --source2 b.json
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

IS_WIN = os.name == "nt"
HERE = Path(__file__).resolve().parent

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def log(msg):
    print(time.strftime("[%H:%M:%S] ") + msg, flush=True)


def exe(name):
    return name + ".exe" if IS_WIN else name


class App:
    def __init__(self, args):
        self.args = args
        self.sdk = Path(args.sdk_root).expanduser().resolve()
        self.adb_path = self.sdk / "platform-tools" / exe("adb")
        self.emulator_path = self.sdk / "emulator" / exe("emulator")
        self.out = Path(args.out_dir).expanduser().resolve()
        self.raw_dir = self.out / "raw"
        self.report_dir = self.out / "report"
        self.artifact_dir = self.out / "artifacts"
        self.log_dir = self.out / "logs"
        self.package = args.package
        self.web_port = args.web_port
        self.ws_port = args.web_port + 1
        self.steps = []
        self.mitm = None
        self.device_started = False
        self.proxy_set = False

    # ---------- 基础执行 ----------
    def run(self, cmd, timeout=180, check=False):
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        out = (p.stdout or b"").decode("utf-8", "replace").strip()
        err = (p.stderr or b"").decode("utf-8", "replace").strip()
        if check and p.returncode != 0:
            raise RuntimeError("命令失败: %s\n%s\n%s" % (" ".join(map(str, cmd)), out, err))
        return p.returncode, out, err

    def adb(self, *args, timeout=180, check=False):
        return self.run([str(self.adb_path)] + [str(a) for a in args], timeout=timeout, check=check)

    # ---------- 环境准备 ----------
    def preflight(self):
        if not self.adb_path.exists():
            raise RuntimeError("找不到 adb：%s（请用 --sdk-root 指定 Android SDK 目录）" % self.adb_path)
        for f in (self.args.source1, self.args.source2):
            if not Path(f).exists():
                raise RuntimeError("找不到书源文件：%s" % f)
        apk = Path(self.args.apk)
        if not apk.exists():
            raise RuntimeError("找不到 APK：%s" % apk)
        for d in (self.raw_dir, self.report_dir, self.artifact_dir, self.log_dir):
            d.mkdir(parents=True, exist_ok=True)
        log("输出目录：%s" % self.out)

    def ensure_device(self):
        rc, out, _ = self.adb("devices")
        online = [l.split("\t")[0] for l in out.splitlines()[1:] if l.strip().endswith("device")]
        if online:
            log("使用已连接的设备：%s" % ", ".join(online))
            return
        if not self.args.avd:
            raise RuntimeError("没有已连接的模拟器。请先启动 AVD，或用 --avd <名称> 让脚本自动启动。")
        if not self.emulator_path.exists():
            raise RuntimeError("找不到 emulator：%s" % self.emulator_path)
        log("启动模拟器 %s ..." % self.args.avd)
        cmd = [str(self.emulator_path), "-avd", self.args.avd,
               "-no-snapshot-save", "-no-boot-anim", "-netdelay", "none", "-netspeed", "full"]
        kwargs = {}
        if IS_WIN:
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)
        self.device_started = True
        self.adb("wait-for-device", timeout=300)
        deadline = time.time() + 300
        while time.time() < deadline:
            _, booted, _ = self.adb("shell", "getprop", "sys.boot_completed")
            if booted.strip() == "1":
                log("模拟器启动完成")
                time.sleep(5)
                return
            time.sleep(3)
        raise RuntimeError("模拟器启动超时")

    def ensure_root(self):
        self.adb("root")
        time.sleep(2)
        self.adb("wait-for-device", timeout=120)
        _, out, _ = self.adb("shell", "id")
        if "uid=0" not in out:
            raise RuntimeError(
                "当前模拟器无法 adb root（多半是带 Google Play 的镜像）。\n"
                "请在 AVD Manager 中新建/改用 \"Google APIs\" 或 AOSP 镜像后重试，"
                "否则无法自动开启应用的 Web 服务。")

    def start_mitm(self):
        log("启动 mitmdump（127.0.0.1:%d）..." % self.args.proxy_port)
        logfile = open(self.log_dir / "mitmdump.log", "wb")
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        cmd = [sys.executable, "-m", "mitmdump",
               "-q",
               "--listen-host", "127.0.0.1",
               "-p", str(self.args.proxy_port),
               "-s", str(HERE / "mitm_addon.py"),
               "--set", "rawdir=%s" % self.raw_dir,
               "--set", "capture_max_body=%d" % self.args.max_body]
        kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if IS_WIN else {}
        self.mitm = subprocess.Popen(cmd, stdout=logfile, stderr=subprocess.STDOUT, env=env, **kwargs)
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.mitm.poll() is not None:
                raise RuntimeError("mitmdump 启动失败，详见 %s" % (self.log_dir / "mitmdump.log"))
            try:
                with socket.create_connection(("127.0.0.1", self.args.proxy_port), timeout=1):
                    log("mitmdump 已就绪")
                    return
            except OSError:
                time.sleep(0.5)
        raise RuntimeError("mitmdump 端口未监听，详见 %s" % (self.log_dir / "mitmdump.log"))

    def set_proxy(self, enable=True):
        if enable:
            self.adb("shell", "settings", "put", "global", "http_proxy",
                     "10.0.2.2:%d" % self.args.proxy_port)
            self.adb("shell", "settings", "put", "global", "global_http_proxy_host", "10.0.2.2")
            self.adb("shell", "settings", "put", "global", "global_http_proxy_port", str(self.args.proxy_port))
            self.proxy_set = True
            log("已设置模拟器全局代理 10.0.2.2:%d" % self.args.proxy_port)
        else:
            self.adb("shell", "settings", "put", "global", "http_proxy", ":0")
            self.adb("shell", "settings", "delete", "global", "global_http_proxy_host")
            self.adb("shell", "settings", "delete", "global", "global_http_proxy_port")
            self.proxy_set = False
            log("已清除模拟器代理")

    def install_apk(self):
        log("安装 APK：%s" % self.args.apk)
        rc, out, err = self.adb("install", "-r", "-g", str(Path(self.args.apk).resolve()), timeout=600)
        if "Success" not in out:
            raise RuntimeError("APK 安装失败：\n%s\n%s" % (out, err))

    def start_web_service(self):
        log("启动应用与 Web 服务（端口 %d）..." % self.web_port)
        self.adb("shell", "am", "force-stop", self.package)
        self.adb("shell", "am", "start", "-n", "%s/io.legado.app.ui.main.MainActivity" % self.package)
        time.sleep(5)
        self.adb("shell", "am", "start-foreground-service", "-n",
                 "%s/io.legado.app.service.WebService" % self.package)
        for port in (self.web_port, self.ws_port):
            self.adb("forward", "tcp:%d" % port, "tcp:%d" % port)
        deadline = time.time() + 45
        last_err = ""
        while time.time() < deadline:
            try:
                data = self.api_get("/getBookSources", timeout=5)
                if isinstance(data, dict):
                    log("Web 服务已就绪")
                    return
            except Exception as e:  # noqa: BLE001
                last_err = str(e)
            time.sleep(2)
        raise RuntimeError(
            "Web 服务未就绪（%s）。\n"
            "请手动打开 App：设置 -> 其他设置 -> Web 服务，打开开关后重试。" % last_err)

    # ---------- Web API ----------
    def api_get(self, path, params=None, timeout=180):
        url = "http://127.0.0.1:%d%s" % (self.web_port, path)
        if params:
            url += "?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        with _OPENER.open(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))

    def api_post(self, path, payload, timeout=180):
        url = "http://127.0.0.1:%d%s" % (self.web_port, path)
        if not isinstance(payload, (str, bytes)):
            payload = json.dumps(payload, ensure_ascii=False)
        data = payload.encode("utf-8") if isinstance(payload, str) else payload
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json; charset=utf-8"})
        with _OPENER.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))

    # ---------- 步骤 ----------
    def begin(self, name):
        self.steps.append({"step": name, "start": time.time(), "end": None})
        log("==> %s" % name)

    def end(self):
        if self.steps and self.steps[-1]["end"] is None:
            self.steps[-1]["end"] = time.time()

    def import_sources(self):
        self.begin("导入书源")
        imported = []
        for path in (self.args.source1, self.args.source2):
            raw = Path(path).read_text(encoding="utf-8-sig")
            payload = json.loads(raw)
            if isinstance(payload, str):
                payload = json.loads(payload)
            if isinstance(payload, dict):
                for key in ("bookSources", "sources", "data", "items"):
                    if isinstance(payload.get(key), list):
                        payload = payload[key]
                        break
                else:
                    payload = [payload]
            resp = self.api_post("/saveBookSources", payload)
            if not resp.get("isSuccess"):
                raise RuntimeError("导入 %s 失败：%s" % (path, resp.get("errorMsg")))
            imported.extend(resp.get("data") or [])
            log("已导入 %s：%d 条" % (Path(path).name, len(resp.get("data") or [])))
        (self.artifact_dir / "imported_sources.json").write_text(
            json.dumps(imported, ensure_ascii=False, indent=2), encoding="utf-8")
        self.end()
        return imported

    def pick_source(self, imported):
        sources = imported
        if self.args.source_url:
            sources = [s for s in sources if s.get("bookSourceUrl") == self.args.source_url]
            if not sources:
                raise RuntimeError("导入结果里没有 bookSourceUrl=%s 的书源" % self.args.source_url)
        score = [s for s in sources if s.get("enabled") and s.get("searchUrl")]
        if not score:
            score = [s for s in sources if s.get("searchUrl")]
        if not score:
            raise RuntimeError("没有可搜索的书源（searchUrl 为空）")
        source = score[0]
        if not source.get("enabled"):
            log("书源默认未启用，正在启用：%s" % source.get("bookSourceName"))
            source["enabled"] = True
            self.api_post("/saveBookSource", source)
        log("选用书源：%s (%s)" % (source.get("bookSourceName"), source.get("bookSourceUrl")))
        return source

    def isolate_source(self, chosen):
        """搜索接口无法指定书源，这里把其它书源临时停用，保证只搜目标书源。"""
        target = chosen.get("bookSourceUrl")
        listing = self.api_get("/getBookSources")
        others = [s for s in (listing.get("data") or [])
                  if s.get("bookSourceUrl") != target and s.get("enabled")]
        for s in others:
            s["enabled"] = False
            self.api_post("/saveBookSource", s)
        if others:
            log("已临时停用其它 %d 个书源，只搜索目标书源" % len(others))

    def search(self, key):
        self.begin("搜索")
        import websocket  # 延迟导入，避免 --help 时缺少依赖
        candidates = [key] + [k for k in self.args.fallback_keys if k]
        books = []
        for kw in candidates:
            log("搜索关键词：%s" % kw)
            try:
                ws = websocket.create_connection(
                    "ws://127.0.0.1:%d/searchBook" % self.ws_port, timeout=20)
            except Exception as e:  # noqa: BLE001
                raise RuntimeError("连接搜索 WebSocket 失败：%s" % e)
            ws.send(json.dumps({"key": kw}, ensure_ascii=False))
            deadline = time.time() + self.args.search_timeout
            while time.time() < deadline:
                try:
                    msg = ws.recv()
                except websocket.WebSocketTimeoutException:
                    continue
                except Exception:  # noqa: BLE001  连接关闭即搜索结束
                    break
                if not msg:
                    continue
                try:
                    data = json.loads(msg)
                except ValueError:
                    log("搜索服务返回：%s" % msg)
                    continue
                if isinstance(data, list):
                    books.extend(data)
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
            seen = {b.get("bookUrl") for b in books}
            if seen:
                break
        # 去重
        unique = {}
        for b in books:
            unique[b.get("bookUrl")] = b
        books = list(unique.values())
        (self.artifact_dir / "search_result.json").write_text(
            json.dumps(books, ensure_ascii=False, indent=2), encoding="utf-8")
        self.end()
        if not books:
            raise RuntimeError("搜索没有结果，可换关键词（--key / --fallback-keys）后重试")
        log("搜索到 %d 本书" % len(books))
        return books

    def pick_book(self, books, source):
        same = [b for b in books if b.get("origin") == source.get("bookSourceUrl")]
        book = (same or books)[0]
        log("选用书籍：%s / %s" % (book.get("name"), book.get("author")))
        return book

    def save_book(self, book):
        payload = {
            "bookUrl": book.get("bookUrl", ""),
            "tocUrl": book.get("tocUrl", "") or "",
            "origin": book.get("origin", ""),
            "originName": book.get("originName", "") or "",
            "name": book.get("name", ""),
            "author": book.get("author", "") or "",
            "kind": book.get("kind"),
            "customTag": None,
            "coverUrl": book.get("coverUrl"),
            "customCoverUrl": None,
            "intro": book.get("intro"),
            "customIntro": None,
            "charset": None,
            "type": int(book.get("type") or 0),
            "group": 0,
            "latestChapterTitle": book.get("latestChapterTitle"),
            "latestChapterTime": int(time.time() * 1000),
            "lastCheckTime": int(time.time() * 1000),
            "lastCheckCount": 0,
            "totalChapterNum": 0,
            "durChapterTitle": None,
            "durChapterIndex": 0,
            "durVolumeIndex": 0,
            "chapterInVolumeIndex": 0,
            "durChapterPos": 0,
            "durChapterTime": int(time.time() * 1000),
            "wordCount": book.get("wordCount"),
            "canUpdate": True,
            "order": 0,
            "originOrder": 0,
            "variable": book.get("variable"),
            "readConfig": None,
            "syncTime": 0,
        }
        resp = self.api_post("/saveBook", payload)
        if not resp.get("isSuccess"):
            raise RuntimeError("加入书架失败：%s" % resp.get("errorMsg"))
        (self.artifact_dir / "selected_book.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def ui_step(self, name, activity, extras, wait, shot_name):
        self.begin(name)
        cmd = ["shell", "am", "start", "-n", "%s/%s" % (self.package, activity)]
        for k, v in extras:
            cmd += ["--es", k, str(v)]
        self.adb(*cmd)
        time.sleep(wait)
        shot = self.artifact_dir / shot_name
        p = subprocess.run([str(self.adb_path), "exec-out", "screencap", "-p"],
                           capture_output=True, timeout=60)
        if p.returncode == 0 and p.stdout:
            shot.write_bytes(p.stdout)
            log("截图：%s" % shot)
        self.end()

    def fetch_toc(self, book):
        self.begin("目录（读取）")
        resp = self.api_get("/getChapterList", {"url": book.get("bookUrl")})
        self.end()
        chapters = resp.get("data") or []
        (self.artifact_dir / "toc.json").write_text(
            json.dumps(chapters, ensure_ascii=False, indent=2), encoding="utf-8")
        if not chapters:
            raise RuntimeError("目录为空：%s" % resp.get("errorMsg"))
        log("目录共 %d 章，第一章：%s" % (len(chapters), chapters[0].get("title")))
        return chapters

    def fetch_content(self, book, chapters):
        self.begin("章节正文（读取）")
        index = self.args.chapter_index
        if index >= len(chapters):
            index = 0
        resp = self.api_get("/getBookContent", {"url": book.get("bookUrl"), "index": index})
        self.end()
        content = resp.get("data") or ""
        (self.artifact_dir / ("chapter_%d.txt" % index)).write_text(content, encoding="utf-8")
        if not content:
            raise RuntimeError("正文为空：%s" % resp.get("errorMsg"))
        log("正文 %d 字：%s" % (len(content), chapters[index].get("title")))
        return index, content

    # ---------- 报表 ----------
    def build_report(self):
        files = sorted(self.raw_dir.glob("flow-*.json"))
        flows = []
        for f in files:
            try:
                flows.append(json.loads(f.read_text(encoding="utf-8")))
            except ValueError:
                continue
        flows.sort(key=lambda x: x["request"]["timestamp_start"])

        windows = [s for s in self.steps if s.get("end")]
        for f in flows:
            f["step"] = None
            ts = f["request"]["timestamp_start"]
            for s in windows:
                if s["start"] <= ts <= s["end"]:
                    f["step"] = s["step"]

        with open(self.report_dir / "flows.jsonl", "w", encoding="utf-8") as fp:
            for f in flows:
                fp.write(json.dumps(f, ensure_ascii=False) + "\n")

        md = ["# 书源 HTTP 交互记录（按时间顺序）", ""]
        md.append("- 生成时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S"))
        md.append("- 模拟器代理：10.0.2.2:%d -> mitmproxy" % self.args.proxy_port)
        md.append("- 交互总数：%d" % len(flows))
        md.append("")
        md.append("## 步骤概览")
        md.append("")
        md.append("| 步骤 | 开始 | 请求数 |")
        md.append("| --- | --- | --- |")
        for s in windows:
            count = sum(1 for f in flows if f.get("step") == s["step"])
            md.append("| %s | %s | %d |" % (
                s["step"], time.strftime("%H:%M:%S", time.localtime(s["start"])), count))
        md.append("")

        for i, f in enumerate(flows, 1):
            req, resp = f["request"], f.get("response") or {}
            ts = time.strftime("%H:%M:%S", time.localtime(req["timestamp_start"])) + \
                (".%03d" % int((req["timestamp_start"] % 1) * 1000))
            dur = ""
            if resp:
                dur = " / %.2fs" % max(0.0, resp.get("timestamp_end", req["timestamp_start"]) - req["timestamp_start"])
            md.append("## [%04d] %s %s %s%s" % (
                i, ts, req["method"], req["url"], dur))
            md.append("")
            md.append("- 步骤：%s" % (f.get("step") or "未归类"))
            md.append("- HTTP 版本：%s" % req.get("http_version"))
            md.append("")
            md.append("**请求头**")
            md.append("")
            md.append("```http")
            for k, v in req.get("headers") or []:
                md.append("%s: %s" % (k, v))
            md.append("```")
            md.append("")
            body = req.get("body")
            if body and body.get("size", 0) > 0:
                md.append("**请求载荷**（%d 字节%s）" % (
                    body.get("size", 0), "，已截断" if body.get("truncated") else ""))
                md.append("")
                md.append("```")
                md.append(body.get("text") if body.get("encoding") == "utf-8" else "[binary base64, 见 raw JSON]")
                md.append("```")
                md.append("")
            if resp:
                md.append("**响应**：%s %s" % (resp.get("status_code"), resp.get("reason")))
                md.append("")
                md.append("```http")
                for k, v in resp.get("headers") or []:
                    md.append("%s: %s" % (k, v))
                md.append("```")
                md.append("")
                rbody = resp.get("body")
                if rbody and rbody.get("encoding") == "utf-8":
                    text = rbody.get("text") or ""
                    truncated = len(text) > 3000
                    md.append("**响应体**（%d 字节%s）" % (rbody.get("size", 0), "，此处截断" if truncated else ""))
                    md.append("")
                    md.append("```")
                    md.append(text[:3000])
                    md.append("```")
                elif rbody:
                    md.append("**响应体**：二进制 %d 字节（base64 见 raw JSON）" % rbody.get("size", 0))
                md.append("")
            if f.get("error"):
                md.append("**错误**：%s" % f["error"])
                md.append("")

        (self.report_dir / "index.md").write_text("\n".join(md), encoding="utf-8")
        log("报文清单：%s" % (self.report_dir / "index.md"))
        return len(flows)

    # ---------- 主流程 ----------
    def run_all(self):
        self.preflight()
        self.ensure_device()
        self.ensure_root()
        self.start_mitm()
        try:
            self.set_proxy(True)
            self.install_apk()
            self.start_web_service()
            imported = self.import_sources()
            source = self.pick_source(imported)
            if not self.args.no_isolate:
                self.isolate_source(source)
            books = self.search(self.args.key)
            book = self.pick_book(books, source)
            self.save_book(book)

            if not self.args.skip_ui:
                self.ui_step("书籍详情", "io.legado.app.ui.book.info.BookInfoActivity", [
                    ("bookUrl", book.get("bookUrl") or ""),
                    ("name", book.get("name") or ""),
                    ("author", book.get("author") or ""),
                    ("origin", book.get("origin") or ""),
                    ("originName", book.get("originName") or ""),
                ], self.args.ui_wait, "01_book_detail.png")
                self.ui_step("目录", "io.legado.app.ui.book.toc.BookTocLoadingActivity", [
                    ("bookUrl", book.get("bookUrl") or ""),
                    ("name", book.get("name") or ""),
                    ("author", book.get("author") or ""),
                ], self.args.ui_wait, "02_toc.png")
                self.ui_step("章节正文", "io.legado.app.ui.book.read.ReadBookActivity", [
                    ("bookUrl", book.get("bookUrl")),
                    ("index", self.args.chapter_index),
                    ("chapterPos", 0),
                ], self.args.ui_wait + 4, "03_chapter.png")

            chapters = self.fetch_toc(book)
            index, _ = self.fetch_content(book, chapters)

            (self.out / "meta.json").write_text(json.dumps({
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "package": self.package,
                "apk": str(Path(self.args.apk).resolve()),
                "source": {"name": source.get("bookSourceName"), "url": source.get("bookSourceUrl")},
                "keyword": self.args.key,
                "book": {"name": book.get("name"), "author": book.get("author"),
                         "bookUrl": book.get("bookUrl"), "tocUrl": book.get("tocUrl")},
                "chapter_index": index,
                "chapter_count": len(chapters),
                "steps": self.steps,
            }, ensure_ascii=False, indent=2), encoding="utf-8")
        finally:
            try:
                self.set_proxy(False)
            except Exception:  # noqa: BLE001
                pass
            if self.mitm and self.mitm.poll() is None:
                if IS_WIN:
                    subprocess.run(["taskkill", "/PID", str(self.mitm.pid), "/T", "/F"],
                                   capture_output=True)
                else:
                    self.mitm.terminate()
                try:
                    self.mitm.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.mitm.kill()
            time.sleep(1)
            if self.args.uninstall:
                self.adb("uninstall", self.package)
        count = self.build_report()
        log("完成：共抓取 %d 条 HTTP 交互" % count)
        log("结果目录：%s" % self.out)
        log("查看：%s" % (self.report_dir / "index.md"))


def parse_args():
    p = argparse.ArgumentParser(description="模拟器内跑书源并抓 HTTP 原始报文")
    p.add_argument("--sdk-root", required=True, help="Android SDK 根目录")
    p.add_argument("--apk", required=True, help="要安装的 APK")
    p.add_argument("--source1", required=True, help="书源 JSON 1")
    p.add_argument("--source2", required=True, help="书源 JSON 2")
    p.add_argument("--out-dir", required=True, help="结果输出目录")
    p.add_argument("--avd", default="", help="设备未启动时自动启动的 AVD 名称")
    p.add_argument("--package", default="io.legado.app.debug", help="应用包名")
    p.add_argument("--key", default="斗破苍穹", help="搜索关键词")
    p.add_argument("--fallback-keys", nargs="*", default=["剑来", "诡秘之主"], help="备用关键词")
    p.add_argument("--source-url", default="", help="指定书源 bookSourceUrl")
    p.add_argument("--chapter-index", type=int, default=0, help="要阅读的章节序号")
    p.add_argument("--web-port", type=int, default=1122, help="应用 Web 服务端口")
    p.add_argument("--proxy-port", type=int, default=8899, help="mitmproxy 端口")
    p.add_argument("--search-timeout", type=int, default=90, help="单次搜索最长等待秒数")
    p.add_argument("--ui-wait", type=int, default=10, help="每个界面等待秒数")
    p.add_argument("--max-body", type=int, default=2 * 1024 * 1024, help="单条报文保存上限")
    p.add_argument("--skip-ui", action="store_true", help="只走 API，不打开界面")
    p.add_argument("--no-isolate", action="store_true", help="搜索前不临时停用其它书源")
    p.add_argument("--uninstall", action="store_true", help="结束前卸载 App")
    return p.parse_args()


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    application = App(parse_args())
    try:
        application.run_all()
    except KeyboardInterrupt:
        log("已中断")
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        log("失败：%s" % exc)
        if application.steps:
            log("已完成步骤：%s" % ", ".join(s["step"] for s in application.steps))
        sys.exit(1)
