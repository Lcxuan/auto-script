"""Cookie-based Juejin daily check-in command for cron or Task Scheduler."""

import sys
import traceback
from dataclasses import dataclass


HOME_URL = "https://juejin.cn"
# 将浏览器中 Cookie 请求头的完整值粘贴到此处；不要提交包含真实 Cookie 的脚本。
COOKIE = ""
CHECKIN_SCRIPT = """async () => {
  const response = await fetch(
    'https://api.juejin.cn/growth_api/v1/check_in?aid=2608&uuid=1',
    {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'include',
      body: JSON.stringify({}),
    },
  );
  return response.json();
}"""


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
            page.goto(HOME_URL, wait_until="domcontentloaded")
            result = classify_checkin_response(page.evaluate(CHECKIN_SCRIPT))
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
