"""掘金每日签到脚本"""

import sys
import time
import traceback
from dataclasses import dataclass


HOME_URL = "https://juejin.cn"
# 将浏览器中 Cookie 请求头的完整值粘贴到此处；不要提交包含真实 Cookie 的脚本。
COOKIE = ""

CHECKIN_URL = "https://api.juejin.cn/growth_api/v1/check_in?aid=2608&uuid=1"

# 页内捕获异常（Failed to fetch 属于页内 TypeError），由 Python 侧重试，而不是直接抛出。
CHECKIN_SCRIPT = """async (url) => {
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'include',
      body: JSON.stringify({}),
    });
    return {ok: true, body: await response.json()};
  } catch (error) {
    return {ok: false, error: String(error)};
  }
}"""

# 等待安全 SDK 接管 window.fetch（包装后的 fetch 不再是 [native code]）。
SDK_READY_SCRIPT = "!String(window.fetch).includes('[native code]')"


@dataclass(frozen=True)
class CheckinResult:
    exit_code: int
    message: str

def classify_checkin_response(response: dict) -> CheckinResult:
    err_no = response.get("err_no")
    message = str(response.get("err_msg", ""))
    if err_no == 0:
        streak = response.get("data", {}).get("sum")
        suffix = f"，连续签到 {streak} 天" if streak is not None else ""
        return CheckinResult(0, f"签到成功{suffix}")
    if err_no == 15001 or "已签到" in message:
        return CheckinResult(0, "今日已签到")
    if err_no == 401 or "登录" in message:
        return CheckinResult(2, "登录已失效，请更新脚本顶部的 COOKIE")
    return CheckinResult(1, f"签到失败（错误码：{err_no}）")


def post_checkin(page, retries: int = 5, delay_ms: int = 2000) -> dict:
    """页内发起签到。请求必须由 sdk-glue 包装后的 fetch 发出才会携带签名。

    SDK 初始化窗口内的请求会被拦截（TypeError: Failed to fetch），
    因此这里捕获页内异常并重试，直到拿到 JSON 业务响应。
    """
    for attempt in range(1, retries + 1):
        outcome = page.evaluate(CHECKIN_SCRIPT, CHECKIN_URL)
        if outcome.get("ok"):
            return outcome["body"]
        print(f"[重试 {attempt}/{retries}] 签到请求被安全 SDK 拦截: {outcome.get('error')}",
              file=sys.stderr)
        page.wait_for_timeout(delay_ms)
    raise RuntimeError(f"签到请求连续 {retries} 次被安全 SDK 拦截，未获得业务响应")


def checkin() -> int:
    if not COOKIE.strip():
        print("请先在脚本顶部配置 COOKIE", file=sys.stderr)
        return 2

    from http.cookies import SimpleCookie
    from playwright.sync_api import sync_playwright

    cookies = SimpleCookie()
    cookies.load(COOKIE)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chrome", headless=True)
            context = browser.new_context()
            context.add_cookies([
                {"name": morsel.key, "value": morsel.value, "domain": ".juejin.cn", "path": "/"}
                for morsel in cookies.values()
            ])
            page = context.new_page()
            # load 事件后页面主资源与安全 SDK (sdk-glue.js) 均已就绪，避免落在初始化窗口内
            page.goto(HOME_URL, wait_until="load", timeout=30000)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if page.evaluate(SDK_READY_SCRIPT):
                    break
                page.wait_for_timeout(500)
            result = classify_checkin_response(post_checkin(page))
            browser.close()
    except Exception as error:
        print(f"签到请求未完成：{type(error).__name__}: {error}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1

    stream = sys.stdout if result.exit_code == 0 else sys.stderr
    print(result.message, file=stream)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(checkin())
