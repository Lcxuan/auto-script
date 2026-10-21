"""在抽奖页面的浏览器上下文中发送一次掘金单抽请求。"""

import json
import sys
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


# 在此填写已登录浏览器会话中的 Cookie 请求头值。
COOKIE = ""

LOTTERY_PAGE = "https://juejin.cn/user/center/lottery?from=lucky_lottery_menu_bar"
DRAW_PATH = "/growth_api/v1/lottery/draw"

# 在掘金页面中执行请求处理逻辑
DRAW_SCRIPT = """async () => {
  const url = new URL('https://api.juejin.cn/growth_api/v1/lottery/draw');
  url.searchParams.set('aid', '2608');
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
  return {status: response.status, statusText: response.statusText, body};
}"""


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
                # 等待页面异步加载请求和安全参数相关代码完成初始化。
                page.wait_for_timeout(2_000)
                result = page.evaluate(DRAW_SCRIPT)
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
