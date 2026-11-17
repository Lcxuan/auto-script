#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WorkBuddy 每日自动签到。

流程：探测 API 端点 → 查询签到状态 → 活动开启且今日未签到时执行签到。
仅依赖 Python 标准库（urllib），无需 pip 安装。

涉及接口（均为 POST，请求体 {}）：
  /v2/feature-flag/api/product-config        探测服务端下发的 API 端点
  /v2/billing/meter/checkin-activity-status  查询活动状态、今日是否已签
  /v2/billing/meter/daily-checkin            执行签到并领奖

业务码：1001=今日已签到（幂等）  1002=不满足签到条件  1003=活动已结束

使用方法：
  1. 运行 python3 get_wb_headers_mac.py，得到 Authorization / X-User-Id / X-Device-Token
  2. 把这三个值填入下方「配置区」
  3. 运行 python3 workbuddy-checkin.py
"""

import json
import sys
import urllib.error
import urllib.request

# =====================================================================
# 配置区：填写请求头脚本输出的三个值
# =====================================================================

AUTHORIZATION = ""               # 完整值形如 "Bearer eyJ..."，由请求头脚本输出
X_USER_ID = ""                   # 账号 uid
X_DEVICE_TOKEN = ""              # 可选；留空则请求不带此头
X_CUSTOM_CHANNEL_ID = "unknown"  # 固定值，一般无需修改
X_ENTERPRISE_ID = ""             # 企业账号才需要，个人账号留空
X_TENANT_ID = ""                 # 企业账号才需要；留空时沿用 X_ENTERPRISE_ID

# 默认端点：脚本会先用 product-config 探测服务端下发的端点，探测失败则回退到此值
BASE_ENDPOINT = "https://www.workbuddy.cn"

# =====================================================================


def build_headers() -> dict:
    """把配置区的内容组装成请求头。"""
    headers = {
        "Authorization": AUTHORIZATION.strip(),
        "X-User-Id": X_USER_ID.strip(),
        "X-Custom-Channel-Id": X_CUSTOM_CHANNEL_ID,
        "Content-Type": "application/json",
    }
    if X_DEVICE_TOKEN.strip():
        headers["X-Device-Token"] = X_DEVICE_TOKEN.strip()
    if X_ENTERPRISE_ID.strip():
        headers["X-Enterprise-Id"] = X_ENTERPRISE_ID.strip()
        headers["X-Tenant-Id"] = X_TENANT_ID.strip() or X_ENTERPRISE_ID.strip()
    return headers


def post(path: str, base: str, headers: dict, body: dict | None = None):
    """POST JSON，返回 (http_status, json_dict)。

    网络异常与非 2xx 响应都转成 (status, {"code": -1, "msg": ...}) 返回，
    不向上抛异常，方便调用方统一判断。
    """
    url = base.rstrip("/") + path
    data = json.dumps(body if body is not None else {}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {"code": -1, "msg": "HTTP %d" % e.code}
    except Exception as e:
        return -1, {"code": -1, "msg": str(e)}


def detect_endpoint(headers: dict) -> str:
    """用 product-config 探测服务端下发的端点；失败或无效则退回默认端点。"""
    status, data = post("/v2/feature-flag/api/product-config", BASE_ENDPOINT, headers)
    if status == 200 and isinstance(data, dict):
        ep = data.get("endpoint")
        official = data.get("officialEndpoints") or []
        if ep and (not official or ep in official):
            print("[product-config] 服务端端点 = %s" % ep)
            return ep
        print("[product-config] 未获得有效端点，沿用 %s" % BASE_ENDPOINT)
    else:
        print("[product-config] 探测失败（%s），沿用 %s"
              % (data.get("msg") if isinstance(data, dict) else data, BASE_ENDPOINT))
    return BASE_ENDPOINT


def main() -> None:
    if not AUTHORIZATION.strip() or not X_USER_ID.strip():
        sys.exit("缺少凭据：请先运行 python3 get_wb_headers_mac.py，把输出的值填入本文件"
                 "「配置区」后再运行。")

    headers = build_headers()
    base = detect_endpoint(headers)

    # 1) 查询签到状态
    status, resp = post("/v2/billing/meter/checkin-activity-status", base, headers)
    if status != 200 or resp.get("code") != 0:
        print("[查状态] 失败：code=%s msg=%s" % (resp.get("code"), resp.get("msg")))
        return
    d = resp.get("data") or {}
    print("[查状态] active=%s today_checked_in=%s streak=%s天 today_credit=%s total_credits=%s"
          % (d.get("active"), d.get("today_checked_in"), d.get("streak_days"),
             d.get("today_credit"), d.get("total_credits")))
    if not d.get("active"):
        print("签到活动未开启或已结束，无需签到。")
        return
    if d.get("today_checked_in"):
        print("今天已签到过（幂等），无需重复签到。")
        return

    # 2) 执行签到
    status, resp = post("/v2/billing/meter/daily-checkin", base, headers)
    if status == 200 and resp.get("code") == 0:
        d = resp.get("data") or {}
        print("[签到成功] 获得 credit=%s 连续=%s天 is_streak_day=%s"
              % (d.get("credit"), d.get("streak_days"), d.get("is_streak_day")))
    else:
        code = resp.get("code")
        msg = {1001: "今日已签到过（幂等）",
               1002: "不满足签到条件",
               1003: "活动已结束"}.get(code, resp.get("msg"))
        print("[签到失败] code=%s msg=%s" % (code, msg))


if __name__ == "__main__":
    main()
