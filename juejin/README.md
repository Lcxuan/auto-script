# 掘金脚本

本目录包含两个使用 Playwright 和本机 Chrome 访问掘金的脚本。运行前需要在对应脚本顶部的 `COOKIE` 变量中填写已登录掘金账号的 Cookie 请求头值，例如：

```text
name1=value1; name2=value2
```

## 环境要求

- Python 3.9 或更高版本
- 已安装 Google Chrome
- 已安装 Playwright Python 包：

  ```bash
  python -m pip install playwright
  ```

脚本通过 Playwright 的 `channel="chrome"` 启动本机 Chrome，不需要下载 Playwright 自带的浏览器。

## 脚本说明

### `juejin_checkin.py`

执行一次掘金每日签到，并输出签到结果。可从本目录运行：

```bash
python juejin_checkin.py
``
```

签到成功或今日已签到时返回成功状态；Cookie 失效或请求失败时会输出错误信息并返回非零状态。

### `juejin_single_draw.py`

执行一次掘金抽奖，并打印捕获到的抽奖请求地址、HTTP 状态码和响应正文。可从本目录运行：

```bash
python juejin_single_draw.py
```

每次运行都会实际提交一次抽奖请求，可能消耗一次抽奖机会。输出的请求地址会遮盖短时有效的安全参数。
