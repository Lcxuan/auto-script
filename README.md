# 自动化脚本

本目录存放独立运行的自动化脚本，目前包含掘金和 Trae CN 相关脚本：

| 脚本                                                                           | 用途                                   | 运行方式                                         |
| ---------------------------------------------------------------------------- | ------------------------------------ | -------------------------------------------- |
| [`juejin/juejin_checkin.py`](juejin/juejin_checkin.py)                       | 使用已登录账号的 Cookie 执行一次掘金每日签到。          | `python juejin/juejin_checkin.py`            |
| [`juejin/juejin_single_draw.py`](juejin/juejin_single_draw.py)               | 使用已登录账号的 Cookie 执行一次掘金抽奖，并打印请求和响应信息。 | `python juejin/juejin_single_draw.py`        |
| [`trae-cn/trae_checkin.py`](trae-cn/trae_checkin.py)                         | 查询 Trae CN 签到状态，并在活动开启且今日未签到时领取积分。   | `python trae-cn/trae_checkin.py`             |
| [`trae-cn/trae_headers_extract_mac.py`](trae-cn/trae_headers_extract_mac.py) | 从 macOS 上的 Trae CN 客户端提取签到所需请求头。     | `python trae-cn/trae_headers_extract_mac.py` |
| [`trae-cn/trae_headers_extract_win.py`](trae-cn/trae_headers_extract_win.py) | 从 Windows 上的 Trae CN 客户端提取签到所需请求头。   | `python trae-cn/trae_headers_extract_win.py` |

掘金脚本的配置、依赖和运行说明见 [`juejin/README.md`](juejin/README.md)；Trae CN 脚本的配置、依赖和运行说明见 [`trae-cn/README.md`](trae-cn/README.md)。
