#!/usr/bin/env python3
"""Trae CN 签到脚本

【接口一】查询签到状态
  请求: POST {BASE_URL}/trae/api/v2/ug/checkin_credits/status
  响应: {"checked_in": true, "code": 0, "credits": 100, "enable": true, ...}
  含义: enable=活动是否开启; checked_in=今日是否已签; credits=当前积分

【接口二】签到 (领取)
  请求: POST {BASE_URL}/trae/api/v2/ug/checkin_credits/claim
  响应: {"code": 0, "credits": 100, "extra_credits": 100, "checked_in": true, ...}
  业务码: 9090=unavailable, 9095=该设备今日已参与签到, 9102=not_signed,
          1002=auth(登录态失效), 4001=parameters

【共同参数】
  Body(相同): {"req_source": 1}        # IDE=1, Lite=2
  Headers: Authorization + 设备五件套 (x-device-id/brand/type/os-version/app-version)

实现流程: 查询签到状态 → 活动开启且未签 → 执行签到;
使用方法: 
  python3 trae_checkin_status.py            # 查询签到状态 + 自动签到
  python3 trae_checkin_status.py --check-only   # 仅查询签到状态
"""
import argparse
import json
import time
import urllib.error
import urllib.request

# ====================== 手动填入以下 6 项 ======================
AUTHORIZATION = ""     # JWT, 14 天有效, 过期需重新获取
X_DEVICE_ID = ""       # aha 注册的远程设备 ID
X_DEVICE_BRAND = ""    # 设备型号(如 Mac14,10,)
X_DEVICE_TYPE = ""     # 平台映射小写, macOS="mac", Windows="windows"
X_OS_VERSION = ""      # 系统版本(如 "macOS 14.1")
X_APP_VERSION = ""     # TRAE CN 客户端版本 (1.107.1)
# ==============================================================

BASE_URL = "https://api.trae.cn"  # 官方由 bootService 动态解析, 社区实测域名
STATUS_PATH = "/trae/api/v2/ug/checkin_credits/status"
CLAIM_PATH = "/trae/api/v2/ug/checkin_credits/claim"
REQ_SOURCE = 1        # IDE=1, Lite=2
TIMEOUT = 30          # 官方客户端超时 30s

BUSINESS_CODE = {
    9090: "unavailable (权益不可用)",
    9095: "该设备今日已参与签到 (服务端设备级去重)",
    9102: "not_signed (今日未签到)",
    1002: "auth (登录态失效, 需更新 token)",
    4001: "parameters (参数错误)",
}

FIELDS = [
    ("AUTHORIZATION", AUTHORIZATION),
    ("X_DEVICE_ID", X_DEVICE_ID),
    ("X_DEVICE_BRAND", X_DEVICE_BRAND),
    ("X_DEVICE_TYPE", X_DEVICE_TYPE),
    ("X_OS_VERSION", X_OS_VERSION),
    ("X_APP_VERSION", X_APP_VERSION),
]


def build_headers() -> dict[str, str]:
    """构建签到接口请求头。"""
    auth = AUTHORIZATION
    if auth and not auth.startswith("Cloud-IDE-JWT"):
        auth = f"Cloud-IDE-JWT {auth}"  # 只填了 token 时自动补前缀
    return {
        "Content-Type": "application/json",
        "Authorization": auth,               # 账号身份
        "x-device-id": X_DEVICE_ID,          # 设备唯一 ID (去重键)
        "x-device-brand": X_DEVICE_BRAND,    # 设备型号
        "x-device-type": X_DEVICE_TYPE,      # 平台 (mac/windows)
        "x-os-version": X_OS_VERSION,        # 系统版本
        "x-app-version": X_APP_VERSION,      # 客户端版本
    }


def _preflight() -> bool:
    """
    发请求前的前置校验。
    1. 检查 6 个必填变量是否齐全 (缺则提示并返回 False);
    2. 对 x-device-id 做格式提示 (官方远程 ID 为数字型, 非数字可能被风控拒绝)。
    """
    missing = [name for name, v in FIELDS if not v]
    if missing:
        print(f"[未填入] {', '.join(missing)} — 请填写文件顶部的变量后重试")
        return False
    if not X_DEVICE_ID.isdigit():
        print(f"[警告] x-device-id={X_DEVICE_ID!r} 不是纯数字, "
              "官方远程 ID 为数字型; 非注册 ID 可能被风控拒绝")
    return True


def _post(path: str) -> tuple[int, dict | None, str]:
    """POST 请求封装, 返回 (http_status, json_or_None, raw_text)。"""
    url = BASE_URL + path
    body = {"req_source": REQ_SOURCE}
    print(f"POST {url}")
    print(f"body: {json.dumps(body)}")
    print(f"headers: {json.dumps({**build_headers(), 'Authorization': 'Cloud-IDE-JWT ***'})}\n")

    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers=build_headers(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            status_code, raw = r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status_code = e.code
        raw = e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        print(f"[网络错误] {e}")
        return 0, None, ""
    print(f"HTTP {status_code}")
    if status_code != 200:
        print(f"[失败] 非 200 响应: {raw[:300]}")
        return status_code, None, raw
    try:
        return status_code, json.loads(raw), raw
    except json.JSONDecodeError:
        print(f"[失败] 响应非 JSON: {raw[:300]}")
        return status_code, None, raw


def _data_of(body_json: dict) -> dict:
    inner = body_json.get("data")
    return inner if isinstance(inner, dict) else body_json


def check_status() -> dict | None:
    """查询签到状态; 返回 {enable, checked_in, credits} 或 None。"""
    _, body_json, _ = _post(STATUS_PATH)
    if body_json is None:
        return None
    data = _data_of(body_json)
    code = body_json.get("code")
    enable, checked_in = data.get("enable"), data.get("checked_in")

    if code not in (0, None):
        print(f"[业务错误] code={code}: "
              f"{BUSINESS_CODE.get(code, body_json.get('message', 'unknown'))}")
        return None
    if not isinstance(enable, bool) or not isinstance(checked_in, bool):
        print(f"[协议错误] data.enable={enable!r}, data.checked_in={checked_in!r} "
              "应均为 boolean (官方校验规则)")
        print(f"原始响应: {json.dumps(body_json, ensure_ascii=False)[:500]}")
        return None

    credits = data.get("credits")
    today = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 8 * 3600))  # 北京日键(本地近似)
    print("[签到状态]")
    print(f"  活动开启 enable   : {enable}")
    print(f"  今日已签 checked_in: {checked_in}")
    print(f"  当前积分 credits   : {credits}")
    print(f"  北京日键(本地近似) : {today} (官方以服务器校准时间为准)")
    return {"enable": enable, "checked_in": checked_in, "credits": credits}


def claim_checkin() -> bool:
    """领取今日签到。官方实现 retry=0 不自动重试 (防重复提交), 此处同样只发一次。"""
    _, body_json, raw = _post(CLAIM_PATH)
    if body_json is None:
        return False
    data = _data_of(body_json)
    code = body_json.get("code")
    if code not in (0, None):
        print(f"[业务错误] code={code}: "
              f"{BUSINESS_CODE.get(code, body_json.get('message', 'unknown'))}")
        return False
    print("[签到成功]")
    for k in ("credits", "extra_credits", "total_credits", "checked_in"):
        if k in data:
            print(f"  {k:14}: {data[k]}")
    print(f"  原始响应       : {json.dumps(body_json, ensure_ascii=False)[:300]}")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="Trae CN 签到: 查询状态 + 领取")
    ap.add_argument("--check-only", action="store_true", help="仅查询状态, 不执行签到")
    args = ap.parse_args()

    if not _preflight():
        return 1
    state = check_status()
    if state is None:
        return 1
    if args.check_only:
        return 0
    if not state["enable"]:
        print("\n[跳过] 签到活动未开启")
        return 0
    if state["checked_in"]:
        print("\n[跳过] 今日已签到, 无需重复")
        return 0
    print("\n--- 执行签到 ---")
    return 0 if claim_checkin() else 1


if __name__ == "__main__":
    raise SystemExit(main())
