"""mitmproxy addon：把每条 HTTP 交互按完成顺序落盘为 raw/flow-*.json。

用法（由 run_capture.py 自动拉起）：
    mitmdump -p 8899 -s mitm_addon.py --set rawdir=<目录> --set capture_max_body=2097152
"""
import base64
import json
import os
import threading

from mitmproxy import ctx


class CaptureAddon:
    def __init__(self):
        self._seq = 0
        self._lock = threading.Lock()
        self._rawdir = ""

    def load(self, loader):
        loader.add_option("rawdir", str, "", "抓包结果输出目录")
        loader.add_option("capture_max_body", int, 2 * 1024 * 1024, "单条报文 body 最大保存字节数")

    def configure(self, updated):
        rawdir = ctx.options.rawdir
        if rawdir and rawdir != self._rawdir:
            os.makedirs(rawdir, exist_ok=True)
            self._rawdir = rawdir

    def _next_seq(self):
        with self._lock:
            self._seq += 1
            return self._seq

    @staticmethod
    def _dump_body(message):
        if message is None:
            return None
        raw = message.raw_content or b""
        limit = ctx.options.capture_max_body
        truncated = len(raw) > limit
        raw = raw[:limit]
        try:
            text = raw.decode("utf-8")
            return {
                "encoding": "utf-8",
                "text": text,
                "truncated": truncated,
                "size": len(message.raw_content or b""),
            }
        except UnicodeDecodeError:
            return {
                "encoding": "base64",
                "base64": base64.b64encode(raw).decode("ascii"),
                "truncated": truncated,
                "size": len(message.raw_content or b""),
            }

    def response(self, flow):
        if not self._rawdir:
            return
        req = flow.request
        resp = flow.response
        record = {
            "seq": self._next_seq(),
            "request": {
                "method": req.method,
                "url": req.pretty_url,
                "scheme": req.scheme,
                "host": req.host,
                "path": req.path,
                "http_version": req.http_version,
                "headers": [[k, v] for k, v in req.headers.items(multi=True)],
                "body": self._dump_body(req),
                "timestamp_start": req.timestamp_start,
                "timestamp_end": req.timestamp_end,
            },
            "response": None,
            "error": str(flow.error) if flow.error else None,
            "client": {
                "peername": flow.client_conn.peername[0] if flow.client_conn.peername else None,
                "tls_sni": req.sni if req.scheme == "https" else None,
            },
        }
        if resp is not None:
            record["response"] = {
                "status_code": resp.status_code,
                "reason": resp.reason,
                "headers": [[k, v] for k, v in resp.headers.items(multi=True)],
                "body": self._dump_body(resp),
                "timestamp_start": resp.timestamp_start,
                "timestamp_end": resp.timestamp_end,
            }
        name = "flow-%d-%05d.json" % (int(req.timestamp_start * 1000), record["seq"])
        path = os.path.join(self._rawdir, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False, indent=2)


addons = [CaptureAddon()]
