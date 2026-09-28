#!/usr/bin/env python3
"""
小红书网页扫码登录服务（无浏览器，基于 Spider_XHS 纯 HTTP 登录实现）
支持多账号保存、切换、校验。

运行:
    ./venv/bin/python app.py            # 默认 http://127.0.0.1:8787
    ./venv/bin/python app.py --port 9000

依赖: Node.js 20+（brew install node）、vendor/Spider_XHS、
      curl_cffi==0.15.0 loguru qrcode[pil] flask requests
"""

import argparse
import base64
import io
import json
import os
import subprocess
import sys
import threading
import time
import traceback

import qrcode
import requests
from flask import Flask, jsonify, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VENDOR_DIR = os.path.join(BASE_DIR, "vendor", "Spider_XHS")
DATA_DIR = os.path.join(BASE_DIR, "data")
ACCOUNTS_FILE = os.path.join(DATA_DIR, "accounts.json")
LEGACY_SESSION_FILE = os.path.join(DATA_DIR, "session.json")
APP_IDENTITY_FILE = os.path.join(DATA_DIR, "app_identity.json")
TICKET_FILE = os.path.join(DATA_DIR, "ticket.json")
LAST_CAPTURE_FILE = os.path.join(DATA_DIR, "last_capture.json")

if VENDOR_DIR not in sys.path:
    sys.path.insert(0, VENDOR_DIR)

from apis.xhs_pc_login_apis import XHSLoginApi  # noqa: E402

def _ensure_data_dir():
    """用户数据统一存放 data/（已 gitignore），自动迁移旧路径文件。"""
    os.makedirs(DATA_DIR, exist_ok=True)
    for name in ("accounts.json", "session.json", "app_identity.json",
                 "ticket.json", "last_capture.json"):
        old = os.path.join(BASE_DIR, name)
        new = os.path.join(DATA_DIR, name)
        if os.path.exists(old) and not os.path.exists(new):
            os.replace(old, new)


_ensure_data_dir()

EDITH = "https://edith.xiaohongshu.com"
REDLAND_API = EDITH + "/api/sns/v1/activity_platform/redland/"

app = Flask(__name__)
lock = threading.RLock()
_verify_cache = {}
VERIFY_TTL = 300


# ---------------------------------------------------------------- accounts

def _account_key(user):
    return str(user.get("user_id") or user.get("red_id") or user.get("nickname") or "")


def _empty_store():
    return {"current": "", "accounts": {}}


def load_accounts():
    if os.path.exists(ACCOUNTS_FILE):
        try:
            with open(ACCOUNTS_FILE, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data.get("accounts"), dict):
                return data
        except Exception:  # noqa: BLE001
            pass
    # 兼容旧的单账号 session.json
    if os.path.exists(LEGACY_SESSION_FILE):
        try:
            with open(LEGACY_SESSION_FILE, encoding="utf-8") as f:
                old = json.load(f)
            key = _account_key(old.get("user") or {})
            if key and old.get("cookies"):
                store = _empty_store()
                store["current"] = key
                store["accounts"][key] = {
                    "user": old.get("user") or {},
                    "cookies": old["cookies"],
                    "saved_at": old.get("saved_at") or int(time.time()),
                }
                save_accounts(store)
                os.remove(LEGACY_SESSION_FILE)
                return store
        except Exception:  # noqa: BLE001
            pass
    return _empty_store()


def save_accounts(store):
    with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
        json.dump(store, f, ensure_ascii=False, indent=2)


def upsert_account(user, cookies, make_current=True):
    store = load_accounts()
    key = _account_key(user)
    if not key:
        raise RuntimeError("登录信息缺少 user_id，无法保存")
    store["accounts"][key] = {
        "user": user,
        "cookies": cookies,
        "saved_at": int(time.time()),
    }
    if make_current or not store.get("current"):
        store["current"] = key
    save_accounts(store)
    _verify_cache.pop(key, None)
    return key


def get_current_account():
    store = load_accounts()
    key = store.get("current")
    if not key:
        return None, None
    acc = store["accounts"].get(key)
    if not acc:
        return None, None
    return key, acc


def verify_account(key=None, force=False):
    """校验某个账号的登录态，返回 {valid, user, reason}；None 表示账号不存在。"""
    store = load_accounts()
    key = key or store.get("current")
    acc = store["accounts"].get(key) if key else None
    if not acc:
        return None
    now = time.time()
    cached = _verify_cache.get(key)
    if not force and cached and now - cached["ts"] < VERIFY_TTL:
        return cached["result"]
    try:
        api = XHSLoginApi()
        ok, user, cookies = api.get_user_info(dict(acc["cookies"]))
    except Exception as exc:  # noqa: BLE001
        result = {"valid": False, "reason": f"校验失败: {exc}"}
    else:
        if ok and user.get("guest") is False:
            acc["user"] = user
            acc["cookies"] = cookies
            store["accounts"][key] = acc
            save_accounts(store)
            result = {"valid": True, "user": user}
        else:
            result = {"valid": False, "reason": "登录态已失效，请重新扫码"}
    _verify_cache[key] = {"ts": now, "result": result}
    return result


def account_summary(key, acc, current_key):
    user = acc.get("user") or {}
    cached = _verify_cache.get(key)
    return {
        "key": key,
        "user_id": user.get("user_id"),
        "nickname": user.get("nickname"),
        "red_id": user.get("red_id"),
        "avatar": user.get("imageb") or user.get("images"),
        "current": key == current_key,
        "valid": (cached or {}).get("result", {}).get("valid"),
        "saved_at": acc.get("saved_at"),
    }


# ---------------------------------------------------------------- app identity (RN token)

import urllib.parse  # noqa: E402

APP_HEADER_KEEP = {
    "authorization", "user-agent", "xy-common-params", "xy-platform-info", "xy-direction",
    "xy-scene", "x-legacy-did", "x-legacy-fid", "x-mini-sig", "x-mini-nsig", "x-mini-mua",
    "x-mini-gid", "x-mini-s1", "x-b3-traceid", "x-xray-traceid", "shield", "x-net-core",
    "rn-name", "rn-version", "accept", "accept-language",
}


def load_app_identity():
    if not os.path.exists(APP_IDENTITY_FILE):
        return None
    try:
        with open(APP_IDENTITY_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return None


def save_app_identity(data):
    with open(APP_IDENTITY_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _hget(headers, name):
    for k, v in (headers or {}).items():
        if k.lower() == name:
            return v
    return ""


def app_identity_summary():
    ident = load_app_identity()
    if not ident:
        return {"has_identity": False}
    h = ident.get("headers") or {}
    auth = _hget(h, "authorization")
    params = dict(urllib.parse.parse_qsl(_hget(h, "xy-common-params")))
    return {
        "has_identity": True,
        "captured_at": ident.get("captured_at"),
        "flow_file": ident.get("flow_file"),
        "authorization": (auth[:24] + "..." + auth[-6:]) if len(auth) > 34 else auth,
        "device_id": params.get("deviceId"),
        "did": params.get("did"),
    }


def app_api_headers():
    ident = load_app_identity()
    if not ident:
        return None
    h = ident.get("headers") or {}
    return {k: v for k, v in h.items() if k.lower() in APP_HEADER_KEEP}


def app_api_get(uri, params=None, timeout=20):
    headers = app_api_headers()
    if not headers:
        raise RuntimeError("未导入 App 身份令牌")
    return requests.get(REDLAND_API + uri, params=params, headers=headers, timeout=timeout)


def app_verify():
    ident = load_app_identity()
    if not ident:
        raise RuntimeError("未导入 App 身份令牌")
    result = {"ok": True}
    r1 = app_api_get("2026_my_ticket_list")
    j1 = r1.json()
    tickets = (j1.get("data") or {}).get("ticket_list") or []
    result["my_ticket_http"] = r1.status_code
    result["tickets"] = tickets
    result["ticket_count"] = len(tickets)
    result["ticket_msg"] = j1.get("msg")
    r2 = app_api_get("2026_reserve_ip_activity_list", {"ip_no": "1003"})
    j2 = r2.json()
    d2 = j2.get("data") or {}
    result["has_ticket"] = bool(d2.get("has_ticket"))
    result["activities"] = [
        {
            "name": a.get("activity_name"),
            "button": a.get("reserve_button"),
            "start_text": a.get("reserve_start_text"),
        }
        for a in (d2.get("activities") or [])
    ]
    return result


# ---------------------------------------------------------------- auto reserve tasks

import collections  # noqa: E402

TASKS_FILE = os.path.join(DATA_DIR, "tasks.json")
TASK_LOG_FILE = os.path.join(DATA_DIR, "task_logs.jsonl")
_task_lock = threading.RLock()
_task_logs = collections.deque(maxlen=800)
_scheduler_started = False


def load_tasks():
    if os.path.exists(TASKS_FILE):
        try:
            with open(TASKS_FILE, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except Exception:  # noqa: BLE001
            pass
    return []


def save_tasks(tasks):
    with open(TASKS_FILE, "w", encoding="utf-8") as f:
        json.dump(tasks, f, ensure_ascii=False, indent=2)


def task_log(task_id, msg):
    entry = {"ts": int(time.time() * 1000), "task": task_id, "msg": msg}
    _task_logs.append(entry)
    try:
        with open(TASK_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass
    print(f"[task:{task_id}] {msg}", flush=True)


def _walk_dicts(obj):
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            yield cur
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)


def parse_sessions(detail_data):
    out, seen = [], set()
    for node in _walk_dicts(detail_data or {}):
        key = next((k for k in node if k.lower() in ("session_id", "sessionid")), None)
        if not key:
            continue
        sid = node.get(key)
        if not sid or str(sid) in seen:
            continue
        seen.add(str(sid))
        out.append(
            {
                "session_id": sid,
                "date": node.get("date") or node.get("arrive_date") or node.get("date_text"),
                "start": node.get("start_time") or node.get("start_text") or node.get("begin_time"),
                "end": node.get("end_time") or node.get("end_text") or node.get("finish_time"),
                "status": node.get("status") or node.get("session_status"),
                "raw": node,
            }
        )
    return out


def _app_post(uri, payload):
    headers = app_api_headers()
    if not headers:
        raise RuntimeError("未导入 App 身份令牌")
    headers = {**headers, "Content-Type": "application/json"}
    return requests.post(REDLAND_API + uri, headers=headers,
                         data=json.dumps(payload, ensure_ascii=False), timeout=20)


def _web_signed(account_key, uri, payload=None, method="POST"):
    from xhs_utils.xhs_pc.params import build_pc_login_headers  # noqa: PLC0415

    store = load_accounts()
    acc = store.get("accounts", {}).get(account_key)
    if not acc:
        raise RuntimeError(f"账号不存在: {account_key}")
    cookies = dict(acc["cookies"])
    client = XHSLoginApi()
    headers, data = client._signed_request_params(
        cookies, uri, payload or "", method=method, tier="0301", mns_profile="qrcode_poll"
    )
    headers = build_pc_login_headers(
        headers, client._cookies_for_url(client.base_url, cookies),
        kind="post" if method == "POST" else "get",
    )
    if method == "POST":
        return client.http.post(client.base_url + uri, headers=headers, data=data,
                                proxies=None, timeout=20)
    return client.http.get(client.base_url + uri, headers=headers, proxies=None, timeout=20)


def _fetch_activity_status(ip_no):
    r = requests.get(
        REDLAND_API + "2026_reserve_ip_activity_list",
        params={"ip_no": ip_no},
        headers={"User-Agent": _UA_DESKTOP},
        timeout=15,
    )
    return (r.json().get("data") or {})


def _choose_session(sessions, task):
    def match(sess):
        text = " ".join(str(sess.get(k) or "") for k in ("date", "start", "end"))
        if task.get("date_hint") and task["date_hint"] not in text:
            return False
        if task.get("session_hint") and task["session_hint"] not in text:
            return False
        return True

    preferred = [s for s in sessions if match(s)]
    return (preferred or sessions or [None])[0]


def run_task_cycle(task, live_override=None):
    """执行一轮预约尝试；返回 (status, message)。"""
    tid = task["id"]
    ip_no = task.get("ip_no")
    aid = task.get("activity_id")
    mode = live_override or task.get("mode") or "dry_run"
    identity = task.get("identity") or "auto"

    data = _fetch_activity_status(ip_no)
    acts = data.get("activities") or []
    act = next((a for a in acts if a.get("activity_id") == aid), None)
    if not act:
        return "failed", f"未找到活动 activity_id={aid}"
    button = act.get("reserve_button")
    task_log(tid, f"状态: {act.get('activity_name')} -> {button} {act.get('reserve_start_text') or ''}")
    if button == "ENDED":
        return "failed", "活动已结束"
    if button == "SOLD_OUT":
        return "failed", "已约满"

    detail = None
    try:
        if identity in ("app", "auto") and app_api_headers():
            r = app_api_get("2026_reserve_activity_detail", {"activity_id": aid})
        else:
            key = task.get("account_key") or (load_accounts().get("current") or "")
            r = _web_signed(key, f"/api/sns/v1/activity_platform/redland/2026_reserve_activity_detail?activity_id={aid}",
                            method="GET")
        detail = r.json()
        task_log(tid, f"详情 HTTP {r.status_code}: {str(detail)[:400]}")
    except Exception as exc:  # noqa: BLE001
        task_log(tid, f"详情请求失败: {exc}")

    sessions = parse_sessions((detail or {}).get("data") or {})
    if not sessions:
        sessions = parse_sessions(detail or {})
    if not sessions:
        return "failed", "未解析到场次（接口未返回 sessionId，见日志）"
    sess = _choose_session(sessions, task)
    sid = sess["session_id"]
    task_log(tid, f"选择场次: {sess.get('date')} {sess.get('start')}-{sess.get('end')} sessionId={sid}")

    if mode == "dry_run":
        return "dry_run", f"[演练] 目标场次 sessionId={sid}，未提交"

    try:
        if identity in ("app", "auto") and app_api_headers():
            resp = _app_post("2026_reserve", {"sessionId": sid})
            who = "app"
        else:
            key = task.get("account_key") or (load_accounts().get("current") or "")
            resp = _web_signed(key, "/api/sns/v1/activity_platform/redland/2026_reserve",
                               {"sessionId": sid}, method="POST")
            who = f"web:{key}"
    except Exception as exc:  # noqa: BLE001
        return "failed", f"提交异常: {exc}"

    body = (resp.text or "")[:400]
    task_log(tid, f"提交({who}) HTTP {resp.status_code}: {body}")
    try:
        j = resp.json()
    except ValueError:
        return "failed", f"提交返回非 JSON: {body}"
    if j.get("success") and j.get("code") == 0:
        if j.get("data"):
            return "success", f"提交成功: {str(j.get('data'))[:200]}"
        return "failed", f"提交返回成功但无数据（可能被风控/参数不完整）: {body}"
    return "failed", f"提交失败: {j.get('msg') or body}"


def _task_thread(task, live_override=None, manual=False):
    tid = task["id"]

    def worker():
        dry = (live_override or task.get("mode")) == "dry_run"
        try:
            for attempt in range(1, int(task.get("max_attempts") or 20) + 1):
                with _task_lock:
                    tasks = load_tasks()
                    cur = next((t for t in tasks if t["id"] == tid), None)
                    if not cur or (not manual and not cur.get("enabled")):
                        task_log(tid, "任务被暂停/删除，停止")
                        return
                    cur["state"] = "running"
                    cur["attempts"] = attempt
                    save_tasks(tasks)
                status, msg = run_task_cycle(task, live_override=live_override)
                with _task_lock:
                    tasks = load_tasks()
                    cur = next((t for t in tasks if t["id"] == tid), None)
                    if cur:
                        if status == "success":
                            new_state = "success"
                        elif status == "dry_run":
                            new_state = "dry_run"
                        else:
                            new_state = "failed" if (dry or attempt >= int(task.get("max_attempts") or 20)) else "waiting"
                        cur["last_msg"] = msg
                        cur["state"] = new_state
                        cur["updated_at"] = int(time.time())
                        save_tasks(tasks)
                if status in ("success", "dry_run", "failed"):
                    if dry:
                        return
                    if status != "failed":
                        return
                    if attempt >= int(task.get("max_attempts") or 20):
                        return
                time.sleep(max(0.2, (task.get("retry_interval_ms") or 400) / 1000.0))
        finally:
            with _task_lock:
                tasks = load_tasks()
                cur = next((t for t in tasks if t["id"] == tid), None)
                if cur and cur.get("state") == "running":
                    cur["state"] = "waiting"
                    save_tasks(tasks)

    threading.Thread(target=worker, daemon=True).start()


def _refresh_fire_at():
    cache = {}
    for task in load_tasks():
        if not task.get("enabled"):
            continue
        ip_no = task.get("ip_no")
        try:
            if ip_no not in cache:
                cache[ip_no] = _fetch_activity_status(ip_no)
            acts = cache[ip_no].get("activities") or []
            act = next((a for a in acts if a.get("activity_id") == task.get("activity_id")), None)
            ts = (act or {}).get("reserve_start_timestamp") or 0
            if ts and ts != task.get("fire_at"):
                with _task_lock:
                    tasks = load_tasks()
                    cur = next((t for t in tasks if t["id"] == task["id"]), None)
                    if cur:
                        cur["fire_at"] = ts
                        cur["fire_at_text"] = (act or {}).get("reserve_start_text")
                        save_tasks(tasks)
        except Exception:  # noqa: BLE001
            continue


def _scheduler_loop():
    last_refresh = 0
    while True:
        try:
            now_ms = int(time.time() * 1000)
            if now_ms - last_refresh > 15000:
                _refresh_fire_at()
                last_refresh = now_ms
            for task in load_tasks():
                if not task.get("enabled") or task.get("state") in ("running", "success"):
                    continue
                fire_at = task.get("fire_at") or 0
                if fire_at and now_ms >= fire_at - int(task.get("advance_ms") or 300):
                    task_log(task["id"], f"到达开约时间({task.get('fire_at_text') or fire_at})，开始执行")
                    _task_thread(task)
        except Exception as exc:  # noqa: BLE001
            print("[scheduler]", exc, flush=True)
        time.sleep(0.3)


def start_scheduler():
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True
    threading.Thread(target=_scheduler_loop, daemon=True).start()


# ---------------------------------------------------------------- ticket bind

TICKET_ID_TYPES = {
    1: "身份证",
    2: "护照",
    3: "港澳居民来往内地通行证",
    4: "台湾居民来往大陆通行证",
    5: "外国人永久居留身份证",
}


def load_ticket():
    if not os.path.exists(TICKET_FILE):
        return None
    try:
        with open(TICKET_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return None


def save_ticket(data):
    with open(TICKET_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def ticket_summary():
    t = load_ticket() or {}
    cert = str(t.get("cert_no") or "")
    masked = (cert[:3] + "*" * max(0, len(cert) - 7) + cert[-4:]) if len(cert) > 7 else "*" * len(cert)
    return {
        "has_info": bool(t.get("voucher_id")),
        "voucher_id": t.get("voucher_id"),
        "user_name": t.get("user_name"),
        "id_type": t.get("id_type"),
        "id_type_text": TICKET_ID_TYPES.get(int(t.get("id_type") or 0), ""),
        "cert_no_masked": masked,
    }


# ---------------------------------------------------------------- reserve list

_reserve_cache = {"ts": 0.0, "data": None}
RESERVE_CACHE_TTL = 15
_UA_DESKTOP = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)


def fetch_reserve_list():
    now = time.time()
    if _reserve_cache["data"] is not None and now - _reserve_cache["ts"] < RESERVE_CACHE_TTL:
        return _reserve_cache["data"]
    headers = {"User-Agent": _UA_DESKTOP}
    plaza = requests.get(
        REDLAND_API + "2026_reserve_plaza_list", headers=headers, timeout=15
    ).json()
    items = (plaza.get("data") or {}).get("ip_list") or []
    targets = [x for x in items if x.get("need_reserve")]
    rows = []
    for x in targets:
        ip_no = x.get("ip_no")
        try:
            j = requests.get(
                REDLAND_API + "2026_reserve_ip_activity_list",
                params={"ip_no": ip_no},
                headers=headers,
                timeout=15,
            ).json()
        except Exception:  # noqa: BLE001
            continue
        for a in (j.get("data") or {}).get("activities") or []:
            rows.append(
                {
                    "booth_no": x.get("booth_no"),
                    "ip_no": x.get("ip_no"),
                    "ip_name": x.get("ip_name"),
                    "activity_id": a.get("activity_id"),
                    "activity_name": a.get("activity_name"),
                    "activity_desc": a.get("activity_desc"),
                    "date_text": a.get("date_text"),
                    "reserve_button": a.get("reserve_button"),
                    "reserve_start_text": a.get("reserve_start_text"),
                    "reserve_start_timestamp": a.get("reserve_start_timestamp"),
                    "jump_url": x.get("jump_url"),
                }
            )
    order = {"NOT_START": 0, "RESERVE": 0, "SOLD_OUT": 1, "ENDED": 2}
    rows.sort(
        key=lambda r: (
            order.get(r.get("reserve_button") or "", 3),
            r.get("reserve_start_timestamp") or 0,
            r.get("booth_no") or "",
        )
    )
    data = {"updated_at": int(now), "count": len(rows), "rows": rows}
    _reserve_cache.update(ts=now, data=data)
    return data


# ---------------------------------------------------------------- qr login

class LoginState:
    def __init__(self):
        self.api = None
        self.cookies = None
        self.qr_id = None
        self.code = None
        self.qr_url = None
        self.created_at = 0
        self.user = None
        self.last_error = None


state = LoginState()


def retry_call(fn, attempts=3, delay=1.0, label=""):
    last = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            last = exc
            print(f"[retry] {label} 第{i + 1}次失败: {exc}", flush=True)
            time.sleep(delay * (i + 1))
    raise last


def make_qr_data_uri(url):
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def create_login_session():
    state.api = XHSLoginApi()
    state.cookies = retry_call(state.api.generate_init_cookies, label="init_cookies")
    ok, msg, data = retry_call(
        lambda: state.api.generate_qrcode(state.cookies), label="generate_qrcode"
    )
    if not ok:
        raise RuntimeError(f"获取二维码失败: {msg}")
    state.cookies = data["cookies"]
    state.qr_id = data["qr_id"]
    state.code = data["code"]
    state.qr_url = data["qr_url"]

    ok, msg, cookies = state.api.check_qrcode_status(state.qr_id, state.code, state.cookies)
    state.cookies = cookies
    if ok:
        raise RuntimeError("二维码创建后已被确认，拒绝复用异常登录状态")
    if msg != "请扫描二维码":
        raise RuntimeError(f"二维码预检查状态异常: {msg}")

    state.api.ensure_webprofile(state.cookies)
    state.created_at = time.time()
    state.user = None
    state.last_error = None


# ---------------------------------------------------------------- routes

@app.get("/")
def index():
    with open(os.path.join(BASE_DIR, "ui.html"), encoding="utf-8") as f:
        return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}


@app.post("/api/login/qr")
def api_login_qr():
    with lock:
        try:
            create_login_session()
        except Exception as exc:  # noqa: BLE001
            state.last_error = str(exc)
            traceback.print_exc()
            return jsonify({"ok": False, "msg": str(exc)}), 500
        return jsonify(
            {
                "ok": True,
                "qr": make_qr_data_uri(state.qr_url),
                "qr_url": state.qr_url,
                "created_at": int(state.created_at),
            }
        )


STATUS_MAP = {
    "请扫描二维码": "pending",
    "请确认登录": "scanned",
    "二维码已过期": "expired",
    "验证成功": "confirmed",
}


@app.get("/api/login/status")
def api_login_status():
    with lock:
        if not state.qr_id:
            return jsonify({"status": "none"})
        try:
            ok, msg, cookies = state.api.check_qrcode_status(
                state.qr_id, state.code, state.cookies
            )
        except Exception as exc:  # noqa: BLE001
            # 手机确认后的会话交换有概率性失败，重试几次再报错
            print(f"[login] status error: {exc}", flush=True)
            ok, msg, cookies = False, None, state.cookies
            for attempt in range(3):
                time.sleep(0.8 * (attempt + 1))
                try:
                    ok, msg, cookies = state.api.check_qrcode_status(
                        state.qr_id, state.code, state.cookies
                    )
                    print(f"[login] status retry {attempt + 1} ok: {msg}", flush=True)
                    break
                except Exception as exc2:  # noqa: BLE001
                    state.last_error = str(exc2)
                    print(f"[login] status retry {attempt + 1} failed: {exc2}", flush=True)
            else:
                return jsonify({"status": "error", "msg": state.last_error or str(exc)})
        state.cookies = cookies

        status = STATUS_MAP.get(msg, "unknown")
        print(f"[login] status={status} msg={msg}", flush=True)
        if status != "confirmed":
            return jsonify({"status": status, "msg": msg})

        success, user, cookies = state.api.get_user_info(state.cookies)
        state.cookies = cookies
        if not success or user.get("guest") is not False:
            return jsonify({"status": "error", "msg": "正式会话校验失败，请重试"})

        store_before = load_accounts()
        before_keys = set(store_before.get("accounts", {}).keys())
        key = upsert_account(user, cookies, make_current=True)
        print(f"[login] confirmed: {user.get('nickname')} ({key})", flush=True)
        state.user = user
        state.qr_id = None
        return jsonify(
            {
                "status": "confirmed",
                "key": key,
                "is_new": key not in before_keys,
                "user": {
                    "nickname": user.get("nickname"),
                    "red_id": user.get("red_id"),
                    "user_id": user.get("user_id"),
                },
            }
        )


@app.get("/api/accounts")
def api_accounts():
    store = load_accounts()
    current = store.get("current")
    items = [
        account_summary(k, v, current) for k, v in store.get("accounts", {}).items()
    ]
    items.sort(key=lambda x: (not x["current"], -(x.get("saved_at") or 0)))
    return jsonify({"current": current, "accounts": items})


@app.post("/api/accounts/switch")
def api_accounts_switch():
    body = request.get_json(silent=True) or {}
    key = str(body.get("key") or "")
    store = load_accounts()
    if key not in store.get("accounts", {}):
        return jsonify({"ok": False, "msg": "账号不存在"}), 404
    store["current"] = key
    save_accounts(store)
    verified = verify_account(key)
    return jsonify(
        {
            "ok": True,
            "current": key,
            "valid": bool((verified or {}).get("valid")),
            "reason": (verified or {}).get("reason"),
            "user": (verified or {}).get("user"),
        }
    )


@app.post("/api/accounts/remove")
def api_accounts_remove():
    body = request.get_json(silent=True) or {}
    key = str(body.get("key") or "")
    store = load_accounts()
    if key not in store.get("accounts", {}):
        return jsonify({"ok": False, "msg": "账号不存在"}), 404
    store["accounts"].pop(key, None)
    _verify_cache.pop(key, None)
    if store.get("current") == key:
        store["current"] = next(iter(store["accounts"]), "")
    save_accounts(store)
    return jsonify({"ok": True, "current": store.get("current")})


@app.get("/api/session")
def api_session():
    key, acc = get_current_account()
    if not acc:
        return jsonify({"logged_in": False})
    verified = verify_account(key)
    return jsonify(
        {
            "logged_in": True,
            "key": key,
            "valid": bool((verified or {}).get("valid")),
            "reason": (verified or {}).get("reason"),
            "user": (verified or {}).get("user") or acc.get("user"),
            "saved_at": acc.get("saved_at"),
        }
    )


@app.post("/api/session/verify")
def api_session_verify():
    body = request.get_json(silent=True) or {}
    key = str(body.get("key") or "") or None
    verified = verify_account(key, force=True)
    if verified is None:
        return jsonify({"logged_in": False, "valid": False})
    return jsonify(
        {
            "logged_in": True,
            "valid": bool(verified.get("valid")),
            "reason": verified.get("reason"),
            "user": verified.get("user"),
        }
    )


@app.get("/api/app/identity")
def api_app_identity():
    return jsonify(app_identity_summary())


@app.get("/api/app/last_capture")
def api_app_last_capture():
    if not os.path.exists(LAST_CAPTURE_FILE):
        return jsonify({"has_capture": False})
    try:
        with open(LAST_CAPTURE_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"has_capture": False, "msg": str(exc)})
    return jsonify({"has_capture": True, **data})


@app.post("/api/app/identity/verify")
def api_app_identity_verify():
    try:
        return jsonify({"ok": True, **app_verify()})
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "msg": str(exc)}), 500


@app.post("/api/app/identity/clear")
def api_app_identity_clear():
    if os.path.exists(APP_IDENTITY_FILE):
        os.remove(APP_IDENTITY_FILE)
    return jsonify({"ok": True})


@app.get("/api/ticket")
def api_ticket_get():
    return jsonify(ticket_summary())


@app.get("/api/reserve/list")
def api_reserve_list():
    try:
        return jsonify({"ok": True, **fetch_reserve_list()})
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "msg": str(exc)}), 502


@app.get("/api/tasks")
def api_tasks():
    tasks = load_tasks()
    now = int(time.time() * 1000)
    out = []
    for t in tasks:
        fire_at = t.get("fire_at") or 0
        out.append(
            {
                **t,
                "countdown_ms": max(0, fire_at - now) if fire_at else None,
            }
        )
    return jsonify({"ok": True, "tasks": out})


@app.post("/api/tasks")
def api_tasks_create():
    body = request.get_json(silent=True) or {}
    ip_no = str(body.get("ip_no") or "")
    activity_id = body.get("activity_id")
    if not ip_no or not activity_id:
        return jsonify({"ok": False, "msg": "缺少 ip_no / activity_id"}), 400
    with _task_lock:
        tasks = load_tasks()
        task = {
            "id": f"t{int(time.time() * 1000) % 10 ** 9}",
            "ip_no": ip_no,
            "activity_id": activity_id,
            "booth_no": body.get("booth_no"),
            "ip_name": body.get("ip_name"),
            "activity_name": body.get("activity_name"),
            "date_hint": body.get("date_hint") or "",
            "session_hint": body.get("session_hint") or "",
            "advance_ms": int(body.get("advance_ms") or 300),
            "retry_interval_ms": int(body.get("retry_interval_ms") or 400),
            "max_attempts": int(body.get("max_attempts") or 20),
            "identity": body.get("identity") or "auto",
            "account_key": body.get("account_key") or None,
            "mode": body.get("mode") or "dry_run",
            "enabled": False,
            "state": "waiting",
            "attempts": 0,
            "last_msg": "",
            "fire_at": 0,
            "fire_at_text": "",
            "created_at": int(time.time()),
        }
        tasks.append(task)
        save_tasks(tasks)
    try:
        data = _fetch_activity_status(ip_no)
        act = next((a for a in (data.get("activities") or []) if a.get("activity_id") == activity_id), None)
        if act:
            with _task_lock:
                tasks = load_tasks()
                cur = next((t for t in tasks if t["id"] == task["id"]), None)
                if cur:
                    cur["fire_at"] = act.get("reserve_start_timestamp") or 0
                    cur["fire_at_text"] = act.get("reserve_start_text") or ""
                    save_tasks(tasks)
                    task = cur
    except Exception:  # noqa: BLE001
        pass
    return jsonify({"ok": True, "task": task})


@app.post("/api/tasks/<tid>/update")
def api_tasks_update(tid):
    body = request.get_json(silent=True) or {}
    allowed = {"mode", "identity", "account_key", "advance_ms", "retry_interval_ms",
               "max_attempts", "date_hint", "session_hint", "enabled"}
    with _task_lock:
        tasks = load_tasks()
        cur = next((t for t in tasks if t["id"] == tid), None)
        if not cur:
            return jsonify({"ok": False, "msg": "任务不存在"}), 404
        for k, v in body.items():
            if k in allowed:
                cur[k] = v
        if body.get("enabled") is True:
            cur["state"] = "waiting"
            cur["attempts"] = 0
            cur["last_msg"] = ""
        save_tasks(tasks)
    return jsonify({"ok": True, "task": cur})


@app.post("/api/tasks/<tid>/delete")
def api_tasks_delete(tid):
    with _task_lock:
        tasks = load_tasks()
        tasks = [t for t in tasks if t["id"] != tid]
        save_tasks(tasks)
    return jsonify({"ok": True})


@app.post("/api/tasks/<tid>/run")
def api_tasks_run(tid):
    body = request.get_json(silent=True) or {}
    live = bool(body.get("live"))
    tasks = load_tasks()
    task = next((t for t in tasks if t["id"] == tid), None)
    if not task:
        return jsonify({"ok": False, "msg": "任务不存在"}), 404
    if task.get("state") == "running":
        return jsonify({"ok": False, "msg": "任务正在执行"}), 409
    task_log(tid, f"手动{'正式' if live else '演练'}执行")
    _task_thread(task, live_override="live" if live else "dry_run", manual=True)
    return jsonify({"ok": True})


@app.get("/api/tasks/logs")
def api_tasks_logs():
    tid = request.args.get("task")
    limit = int(request.args.get("limit") or 120)
    logs = [e for e in _task_logs if not tid or e["task"] == tid]
    return jsonify({"ok": True, "logs": logs[-limit:]})


@app.post("/api/ticket")
def api_ticket_save():
    body = request.get_json(silent=True) or {}
    voucher = str(body.get("voucher_id") or "").strip()
    name = str(body.get("user_name") or "").strip()
    cert = str(body.get("cert_no") or "").strip()
    try:
        id_type = int(body.get("id_type") or 1)
    except (TypeError, ValueError):
        id_type = 1
    if not voucher or not name:
        return jsonify({"ok": False, "msg": "票单号 / 姓名 不能为空"}), 400
    old = load_ticket() or {}
    if not cert and old.get("cert_no"):
        cert = old["cert_no"]
    if not cert:
        return jsonify({"ok": False, "msg": "证件号不能为空"}), 400
    save_ticket(
        {
            "voucher_id": voucher,
            "user_name": name,
            "id_type": id_type,
            "cert_no": cert,
            "saved_at": int(time.time()),
        }
    )
    return jsonify({"ok": True, **ticket_summary()})


@app.post("/api/ticket/copy")
def api_ticket_copy():
    body = request.get_json(silent=True) or {}
    field = str(body.get("field") or "")
    t = load_ticket() or {}
    value = {
        "voucher_id": t.get("voucher_id"),
        "user_name": t.get("user_name"),
        "cert_no": t.get("cert_no"),
    }.get(field)
    if not value:
        return jsonify({"ok": False, "msg": "字段不存在或尚未保存"}), 400
    subprocess.run(["pbcopy"], input=str(value).encode(), timeout=10)
    return jsonify({"ok": True, "field": field})


@app.post("/api/ticket/open_bind_page")
def api_ticket_open_bind_page():
    try:
        subprocess.run(
            ["open", "xhsdiscover://rn/activity-redland/ticket-bind?source=redland_book"],
            timeout=15,
        )
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "msg": str(exc)}), 500
    return jsonify({"ok": True, "msg": "已唤起小红书 App 的绑定门票页面"})


@app.get("/api/redland/status")
def api_redland_status():
    key = request.args.get("key") or None
    store = load_accounts()
    if key:
        if key not in store.get("accounts", {}):
            return jsonify({"ok": False, "msg": "账号不存在"}), 404
        acc = store["accounts"][key]
    else:
        key, acc = get_current_account()
    if not acc:
        return jsonify({"ok": False, "msg": "尚未登录，请先扫码"}), 401
    cookies = acc["cookies"]
    try:
        r = requests.get(
            REDLAND_API + "2026_reserve_ip_activity_list",
            params={"ip_no": "1008"},
            cookies=cookies,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
                )
            },
            timeout=15,
        )
        j = r.json()
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "msg": f"请求预约接口失败: {exc}"}), 502

    if not j.get("success"):
        return jsonify({"ok": False, "msg": j.get("msg") or "接口返回失败"}), 502

    d = j.get("data") or {}
    acts = [
        {
            "activity_id": a.get("activity_id"),
            "name": a.get("activity_name"),
            "button": a.get("reserve_button"),
            "start_text": a.get("reserve_start_text"),
        }
        for a in (d.get("activities") or [])
    ]
    user = (acc.get("user") or {})
    return jsonify(
        {
            "ok": True,
            "nickname": user.get("nickname"),
            "has_ticket": bool(d.get("has_ticket")),
            "activities": acts,
            "server_time": d.get("server_time"),
        }
    )


@app.post("/api/logout")
def api_logout():
    """退出当前账号（从列表移除）。"""
    with lock:
        state.api = None
        state.cookies = None
        state.qr_id = None
        state.user = None
    key, _ = get_current_account()
    if key:
        store = load_accounts()
        store["accounts"].pop(key, None)
        _verify_cache.pop(key, None)
        store["current"] = next(iter(store["accounts"]), "")
        save_accounts(store)
    return jsonify({"ok": True})


INDEX_HTML = ""  # 页面模板见 ui.html，/ 路由动态读取



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    store = load_accounts()
    current = store.get("current")
    if not current:
        print("[session] 本地无账号，请在网页扫码添加", flush=True)
    else:
        verified = verify_account(current, force=True)
        user = (verified or {}).get("user") or {}
        if verified and verified.get("valid"):
            print(f"[session] 当前账号有效：{user.get('nickname')}（{user.get('red_id')}）", flush=True)
        else:
            print(f"[session] 当前账号失效：{(verified or {}).get('reason')}", flush=True)
    start_scheduler()
    print("[scheduler] 自动预约任务引擎已启动", flush=True)
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
