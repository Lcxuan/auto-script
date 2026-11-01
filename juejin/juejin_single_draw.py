"""掘金幸运抽奖 - 单抽"""

import json
import sys
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


# 在此填写已登录浏览器会话中的 Cookie 请求头值。
COOKIE = ""

LOTTERY_PAGE = "https://juejin.cn/user/center/lottery?from=lucky_lottery_menu_bar"
DRAW_PATH = "/growth_api/v1/lottery/draw"
DRAW_URL = "https://api.juejin.cn/growth_api/v1/lottery/draw?aid=2608"

# 页内捕获异常（Failed to fetch 属于页内 TypeError），由 Python 侧重试，而不是直接抛出。
# 每次尝试重新生成 uuid/spider 参数，与官方前端行为一致。
DRAW_SCRIPT = """async (base) => {
  try {
    const url = new URL(base);
    url.searchParams.set('uuid', crypto.randomUUID());
    url.searchParams.set('spider', '0');

    const response = await fetch(url.toString(), {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'include',
      body: JSON.stringify({}),
    });

    const text = await response.text();
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    return {ok: true, status: response.status, statusText: response.statusText, body};
  } catch (error) {
    return {ok: false, error: String(error)};
  }
}"""

# 等待安全 SDK 接管 window.fetch（包装后的 fetch 不再是 [native code]）。
SDK_READY_SCRIPT = "!String(window.fetch).includes('[native code]')"


def mask_security_query_values(url: str) -> str:
    """保留有用的请求信息，同时隐藏短时有效的安全参数。"""
    parts = urlsplit(url)
    safe_query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in {"mstoken", "a_bogus"}:
            value = "<已遮盖>"
        safe_query.append((key, value))
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(safe_query), parts.fragment)
    )


def parse_cookies(cookie_header: str) -> list[dict[str, str]]:
    cookie_jar = SimpleCookie()
    try:
        cookie_jar.load(cookie_header)
    except Exception as error:
        raise ValueError("COOKIE 格式无法解析，请填写浏览器 Cookie 请求头") from error

    cookies = [
        {
            "name": morsel.key,
            "value": morsel.value,
            "domain": ".juejin.cn",
            "path": "/",
            "secure": True,
        }
        for morsel in cookie_jar.values()
    ]
    if not cookies:
        raise ValueError("COOKIE 为空或格式无法解析，请填写浏览器 Cookie 请求头")
    return cookies


def draw_once(page, retries: int = 5, delay_ms: int = 2000) -> dict:
    """页内发起单抽。请求必须由 sdk-glue 包装后的 fetch 发出才会携带签名。

    SDK 初始化窗口内的请求会被拦截（TypeError: Failed to fetch），
    因此这里捕获页内异常并重试，直到拿到响应。
    """
    for attempt in range(1, retries + 1):
        outcome = page.evaluate(DRAW_SCRIPT, DRAW_URL)
        if outcome.get("ok"):
            return outcome
        print(f"[重试 {attempt}/{retries}] 抽奖请求被安全 SDK 拦截: {outcome.get('error')}",
              file=sys.stderr)
        page.wait_for_timeout(delay_ms)
    raise RuntimeError(f"抽奖请求连续 {retries} 次被安全 SDK 拦截，未获得业务响应")


def main() -> int:
    if not COOKIE.strip():
        print("请先在脚本顶部填写 COOKIE。", file=sys.stderr)
        return 2

    try:
        cookies = parse_cookies(COOKIE.strip())
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            "缺少 Playwright。请先安装：python -m pip install playwright。",
            file=sys.stderr,
        )
        return 2

    captured_draw_requests: list[str] = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chrome", headless=True)
            try:
                context = browser.new_context()
                context.add_cookies(cookies)
                page = context.new_page()

                def record_draw_request(request) -> None:
                    if DRAW_PATH in request.url:
                        captured_draw_requests.append(
                            mask_security_query_values(request.url)
                        )

                page.on("request", record_draw_request)
                page.goto(LOTTERY_PAGE, wait_until="load", timeout=60_000)
                # 轮询等待安全 SDK (sdk-glue.js) 接管 window.fetch，避免落在初始化窗口内
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if page.evaluate(SDK_READY_SCRIPT):
                        break
                    page.wait_for_timeout(500)
                result = draw_once(page)
            finally:
                browser.close()
    except Exception as error:
        print(f"单抽请求未完成：{type(error).__name__}: {error}", file=sys.stderr)
        return 1

    print("请求路径：")
    if captured_draw_requests:
        for request_url in captured_draw_requests:
            print(request_url)
    else:
        print("未捕获到抽奖请求 URL")

    print(f"HTTP 状态码：{result['status']} {result['statusText']}")
    print("响应正文：")
    print(json.dumps(result["body"], ensure_ascii=False, indent=2))
    return 0 if result["status"] < 400 else 1


if __name__ == "__main__":
    raise SystemExit(main())
