#!/usr/bin/env python3
"""RED LAND 抓包工具（独立命令行工具，主程序 app.py 不依赖它）

用法:
    ./venv/bin/python capture.py start                  # 开始抓包（自动切系统代理，串联原代理）
    ./venv/bin/python capture.py stop                   # 停止 + 恢复代理 + 提取 App 令牌
    ./venv/bin/python capture.py extract [flow_file]    # 仅从抓包文件提取令牌
    ./venv/bin/python capture.py status                 # 查看抓包/代理状态

抓包期间请在电脑版小红书 App 里操作（如「主会场 → 我的 → 我的门票」；
需要抓绑定请求就去绑定页提交一次）。停止后令牌写入 app_identity.json，
抓包明细写入 data/last_capture.json，主程序页面会读取这两个文件。
"""

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
APP_IDENTITY_FILE = os.path.join(DATA_DIR, "app_identity.json")
LAST_CAPTURE_FILE = os.path.join(DATA_DIR, "last_capture.json")
CAPTURE_DIR = os.path.join(DATA_DIR, "captures")
CAPTURE_PORT = 8080
STATE_FILE = os.path.join(CAPTURE_DIR, "state.json")
SERVER_URL = "http://127.0.0.1:8787"

EXTRACT_ADDON_TMPL = '''
from mitmproxy import http
import json
OUT = {out!r}
items = []
latest = {{}}
def response(flow: http.HTTPFlow):
    try:
        path = flow.request.path
        if not any(k in path for k in ("activity_platform", "redland", "damai", "ticket")):
            return
        hdrs = {{k: v for k, v in flow.request.headers.items()}}
        if not any(k.lower() == "authorization" for k in hdrs):
            return
        latest = hdrs
        items.append({{
            "method": flow.request.method,
            "path": path,
            "url": flow.request.pretty_url,
            "req_body": (flow.request.get_text() or "")[:2000],
            "status": flow.response.status_code if flow.response else None,
            "resp_body": (flow.response.get_text() or "")[:4000] if flow.response else "",
        }})
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump({{"headers": latest, "items": items}}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
'''


# ---------------------------------------------------------------- proxy helpers

def _net_service():
    try:
        out = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True, text=True, timeout=10,
        ).stdout
        services = [ln.strip().lstrip("*").strip() for ln in out.splitlines()[1:] if ln.strip()]
        return "Wi-Fi" if "Wi-Fi" in services else (services[0] if services else "Wi-Fi")
    except Exception:  # noqa: BLE001
        return "Wi-Fi"


def _get_proxy(kind):
    out = subprocess.run(
        ["networksetup", f"-get{kind}proxy", _net_service()],
        capture_output=True, text=True, timeout=10,
    ).stdout
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def _set_proxy(kind, server, port):
    subprocess.run(
        ["networksetup", f"-set{kind}proxy", _net_service(), server, str(port)],
        capture_output=True, timeout=10,
    )


def _disable_proxy(kind):
    subprocess.run(
        ["networksetup", f"-set{kind}proxystate", _net_service(), "off"],
        capture_output=True, timeout=10,
    )


def _load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:  # noqa: BLE001
            return None
    return None


def _save_state(state):
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- extract

def extract(flow_file=None):
    mitm = shutil.which("mitmdump")
    if not mitm:
        raise RuntimeError("未找到 mitmdump，请先 brew install mitmproxy")
    if not flow_file:
        candidates = [c for c in glob.glob(os.path.join(CAPTURE_DIR, "*.mitm"))
                      if os.path.getsize(c) > 0]
        if not candidates:
            raise RuntimeError("找不到抓包文件")
        flow_file = max(candidates, key=os.path.getmtime)
    flow_file = os.path.expanduser(flow_file)
    if not os.path.exists(flow_file):
        raise RuntimeError(f"抓包文件不存在: {flow_file}")

    out = tempfile.mktemp(suffix=".json")
    addon = tempfile.mktemp(suffix=".py")
    with open(addon, "w", encoding="utf-8") as f:
        f.write(EXTRACT_ADDON_TMPL.format(out=out))
    try:
        proc = subprocess.run(
            [mitm, "-nr", flow_file, "-q", "-s", addon],
            capture_output=True, text=True, timeout=300,
        )
    finally:
        try:
            os.remove(addon)
        except OSError:
            pass

    if not os.path.exists(out):
        raise RuntimeError(
            f"没有找到带 authorization 的 redland 请求（rc={proc.returncode}），"
            "请确认操作时 App 已登录并打开过相关页面"
        )
    with open(out, encoding="utf-8") as f:
        data = json.load(f)
    os.remove(out)

    items = data.get("items") or []
    ident = {
        "captured_at": int(time.time()),
        "flow_file": flow_file,
        "headers": data.get("headers") or {},
        "recent": items[-30:],
        "last_request": items[-1] if items else {},
    }
    with open(APP_IDENTITY_FILE, "w", encoding="utf-8") as f:
        json.dump(ident, f, ensure_ascii=False, indent=2)

    capture_result = {
        "captured_at": ident["captured_at"],
        "flow_file": flow_file,
        "request_count": len(items),
        "recent": items[-30:],
        "bind_events": [it for it in items if "ticket" in (it.get("path") or "")],
        "reserve_events": [it for it in items
                           if "reserve" in (it.get("path") or "") and it.get("method") == "POST"],
    }
    with open(LAST_CAPTURE_FILE, "w", encoding="utf-8") as f:
        json.dump(capture_result, f, ensure_ascii=False, indent=2)

    print(f"[extract] 抓包文件: {flow_file}")
    print(f"[extract] 捕获 redland 请求 {len(items)} 条，令牌已写入 app_identity.json")
    for it in items[-8:]:
        print(f"  {it.get('method'):4s} {it.get('path')} -> {it.get('status')}")
    return capture_result


def _try_server_verify():
    try:
        req = urllib.request.Request(SERVER_URL + "/api/app/identity/verify", method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            j = json.loads(resp.read())
        if j.get("ok"):
            print(f"[verify] 我的门票 HTTP {j.get('my_ticket_http')} · "
                  f"{j.get('ticket_count')} 张 · has_ticket={j.get('has_ticket')}")
            (j.get("tickets") or []) and print("         门票:", json.dumps(j["tickets"], ensure_ascii=False)[:300])
        else:
            print("[verify] 验证失败:", j.get("msg"))
    except Exception:  # noqa: BLE001
        print("[verify] 主程序未运行，跳过验证（打开网页点「验证令牌」即可）")


# ---------------------------------------------------------------- commands

def cmd_start():
    mitm = shutil.which("mitmdump")
    if not mitm:
        raise RuntimeError("未找到 mitmdump，请先 brew install mitmproxy")
    if _load_state():
        raise RuntimeError("已有抓包在运行，先执行 capture.py stop")
    os.makedirs(CAPTURE_DIR, exist_ok=True)

    prev_web = _get_proxy("web")
    prev_sec = _get_proxy("secureweb")
    upstream = None
    if prev_web.get("Enabled") == "Yes" and prev_web.get("Server") in ("127.0.0.1", "localhost"):
        upstream = f"http://{prev_web.get('Server')}:{prev_web.get('Port')}"

    flow_file = os.path.join(CAPTURE_DIR, f"redland_{int(time.time())}.mitm")
    args = [mitm, "-w", flow_file, "-p", str(CAPTURE_PORT)]
    if upstream:
        args[1:1] = ["--mode", f"upstream:{upstream}"]
    log = open(os.path.join(CAPTURE_DIR, "capture.log"), "ab")
    proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
    time.sleep(2)
    if proc.poll() is not None:
        raise RuntimeError("mitmdump 启动失败，请查看 data/captures/capture.log")

    _set_proxy("web", "127.0.0.1", CAPTURE_PORT)
    _set_proxy("secureweb", "127.0.0.1", CAPTURE_PORT)
    _save_state({
        "pid": proc.pid,
        "flow_file": flow_file,
        "prev": {"web": prev_web, "secureweb": prev_sec},
        "started_at": int(time.time()),
    })
    print(f"[start] 抓包已启动 -> {flow_file}")
    if upstream:
        print(f"[start] 上游代理: {upstream}")
    print("[start] 现在去电脑版小红书 App 操作；完成后执行: ./venv/bin/python capture.py stop")


def cmd_stop():
    state = _load_state()
    if state:
        pid = state.get("pid")
        if pid:
            try:
                os.kill(pid, 15)
                time.sleep(1.5)
                os.kill(pid, 0)
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
        prev = state.get("prev") or {}
        for kind, cfg in (("web", prev.get("web")), ("secureweb", prev.get("secureweb"))):
            if cfg and cfg.get("Enabled") == "Yes":
                _set_proxy(kind, cfg.get("Server") or "127.0.0.1", cfg.get("Port") or 7890)
            else:
                _disable_proxy(kind)
        flow_file = state.get("flow_file")
        os.remove(STATE_FILE)
        print("[stop] 抓包已停止，系统代理已恢复")
    else:
        subprocess.run(["pkill", "-f", "mitmdump -w"], capture_output=True)
        print("[stop] 未找到状态文件，已尝试停止 mitmdump（代理未改动）")
        flow_file = None

    if not flow_file and os.path.isdir(CAPTURE_DIR):
        candidates = [c for c in glob.glob(os.path.join(CAPTURE_DIR, "*.mitm"))
                      if os.path.getsize(c) > 0]
        flow_file = max(candidates, key=os.path.getmtime) if candidates else None
    if flow_file:
        try:
            extract(flow_file)
            _try_server_verify()
        except Exception as exc:  # noqa: BLE001
            print("[extract] 失败:", exc)


def cmd_status():
    state = _load_state()
    print("抓包状态:", "运行中" if state else "未运行")
    if state:
        print("  文件:", state.get("flow_file"))
        print("  开始于:", time.strftime("%H:%M:%S", time.localtime(state.get("started_at") or 0)))
    print("系统代理: web", _get_proxy("web").get("Enabled"),
          f"{_get_proxy('web').get('Server')}:{_get_proxy('web').get('Port')}",
          "| secure", _get_proxy("secureweb").get("Enabled"))
    print("令牌文件:", "有" if os.path.exists(APP_IDENTITY_FILE) else "无",
          "| 抓包明细:", "有" if os.path.exists(LAST_CAPTURE_FILE) else "无")


def main():
    parser = argparse.ArgumentParser(description="RED LAND 抓包工具")
    parser.add_argument("command", choices=["start", "stop", "extract", "status"])
    parser.add_argument("flow_file", nargs="?", help="extract 时的抓包文件路径")
    args = parser.parse_args()
    try:
        if args.command == "start":
            cmd_start()
        elif args.command == "stop":
            cmd_stop()
        elif args.command == "extract":
            extract(args.flow_file)
        elif args.command == "status":
            cmd_status()
    except Exception as exc:  # noqa: BLE001
        print("错误:", exc, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
