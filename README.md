# 自动化脚本

本目录存放独立运行的自动化脚本。目前包含掘金相关脚本：

| 脚本 | 用途 | 运行方式 |
| --- | --- | --- |
| [`juejin/juejin_checkin.py`](juejin/juejin_checkin.py) | 使用已登录账号的 Cookie 执行一次掘金每日签到。 | `python juejin/juejin_checkin.py` |
| [`juejin/juejin_single_draw.py`](juejin/juejin_single_draw.py) | 使用已登录账号的 Cookie 执行一次掘金抽奖，并打印请求和响应信息。 | `python juejin/juejin_single_draw.py` |

两个脚本的配置方法、依赖和运行说明见 [`juejin/README.md`](juejin/README.md)。
