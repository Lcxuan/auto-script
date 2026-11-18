"""iKuuu VPN 每日签到脚本

签到实现：向 https://ikuuu.top/user/checkin 发空体 POST 请求，
靠登录后的 Cookie 鉴权，响应为 JSON（ret=1 签到成功，ret=0 今日已签到）。

Cookie 最少需要 5 项：uid、email、key、expire_in、session_version。
其中 expire_in 是服务端会话过期时间（unix 秒），过期后需重新登录获取。

使用方式：
  1. 浏览器登录 https://ikuuu.top，建议登录时勾选「记住我」，勾选后cookie有效期为7天，未勾选cookie有效期为24小时
  2. 在开发者工具的网络请求里复制 Cookie 请求头的完整值
  3. 把该值填入下方 COOKIE，或设置环境变量 IKUUU_COOKIE（也可按字段分别设置）
  4. 运行 python ikuuu_checkin.py

用法：
  python ikuuu_checkin.py                                     # Cookie 读脚本常量，未填则读环境变量
  IKUUU_COOKIE="uid=...; email=...; key=..." python ikuuu_checkin.py   # 整串 Cookie 走环境变量
  IKUUU_UID=... IKUUU_EMAIL=... IKUUU_KEY=... IKUUU_EXPIRE_IN=... \
  IKUUU_SESSION_VERSION=... python ikuuu_checkin.py           # 按字段拆分设置

  脚本不接受命令行参数，重复执行是安全的：今日已签到会直接返回成功。

退出码：0=签到成功或今日已签到  1=签到失败/网络异常  2=Cookie 过期或鉴权被拒
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE_URL = "https://ikuuu.top"
CHECKIN_URL = f"{BASE_URL}/user/checkin"

REQUIRED_COOKIES = ("uid", "email", "key", "expire_in", "session_version")

# 直接粘贴浏览器 Cookie 请求头的完整值；留空则读取下方环境变量
COOKIE = ""

ENV_COOKIE = "IKUUU_COOKIE"
ENV_FIELDS = {
    "uid": "IKUUU_UID",
    "email": "IKUUU_EMAIL",
    "key": "IKUUU_KEY",
    "expire_in": "IKUUU_EXPIRE_IN",
    "session_version": "IKUUU_SESSION_VERSION",
    "PHPSESSID": "IKUUU_PHPSESSID",
    "ip": "IKUUU_IP",
}

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
)


class CookieExpired(Exception):
    """本地 Cookie 已过期，需要重新登录获取。"""


class AuthRejected(Exception):
    """服务端拒绝鉴权（跳转登录页），Cookie 无效或会话已吊销。"""


def build_cookie_header() -> str:
    """按优先级组装 Cookie：脚本常量 > 整串环境变量 > 单项环境变量。"""
    if COOKIE.strip():
        raw = COOKIE.strip()
    elif os.environ.get(ENV_COOKIE, "").strip():
        raw = os.environ[ENV_COOKIE].strip()
    else:
        pairs = [
            f"{name}={os.environ[env]}"
            for name, env in ENV_FIELDS.items()
            if os.environ.get(env, "").strip()
        ]
        raw = "; ".join(pairs)

    if not raw:
        raise ValueError(
            "未配置 Cookie：请在脚本顶部填写 COOKIE，或设置环境变量 "
            + ENV_COOKIE
            + "（至少包含 "
            + "、".join(REQUIRED_COOKIES)
            + "）"
        )

    names = {item.split("=", 1)[0].strip() for item in raw.split(";") if "=" in item}
    missing = [name for name in REQUIRED_COOKIES if name not in names]
    if missing:
        raise ValueError(f"Cookie 缺少必需字段：{'、'.join(missing)}")
    return raw


def ensure_not_expired(cookie_header: str) -> None:
    for item in cookie_header.split(";"):
        name, _, value = item.strip().partition("=")
        if name != "expire_in":
            continue
        try:
            expire_at = int(value)
        except ValueError:
            return
        if expire_at <= int(time.time()):
            expired = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expire_at))
            raise CookieExpired(f"Cookie 已于 {expired} 过期，请重新登录后更新")
        return


def post_checkin(cookie_header: str) -> dict:
    request = urllib.request.Request(
        CHECKIN_URL,
        data=b"",
        method="POST",
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": BASE_URL,
            "Referer": f"{BASE_URL}/user",
            "Cookie": cookie_header,
        },
    )

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        # 未登录时服务端返回 302 跳登录页，这里不让 urllib 跟随，便于直接判定
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=20) as response:
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        if error.code in (301, 302, 303, 307, 308):
            raise AuthRejected("服务端跳转登录页，Cookie 无效或会话已失效") from error
        raise

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise ValueError(f"响应不是 JSON：{body[:200]}") from error
    if not isinstance(payload, dict) or "ret" not in payload:
        raise ValueError(f"响应缺少 ret 字段：{body[:200]}")
    return payload


def main() -> int:
    try:
        cookie_header = build_cookie_header()
        ensure_not_expired(cookie_header)
        payload = post_checkin(cookie_header)
    except (CookieExpired, AuthRejected) as error:
        print(str(error), file=sys.stderr)
        return 2
    except (ValueError, urllib.error.URLError, OSError) as error:
        print(f"签到未完成：{error}", file=sys.stderr)
        return 1

    ret = payload.get("ret")
    message = str(payload.get("msg", ""))
    if ret == 1:
        print(f"签到成功：{message}")
        return 0
    if ret == 0 and "签到" in message:
        print(f"今日已签到：{message}")
        return 0
    print(f"签到失败（ret={ret}）：{message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
