# WorkBuddy 自动化脚本

本目录包含 WorkBuddy 每日签到脚本，以及用于获取签到请求头、提取构建期密钥的辅助脚本，提供 macOS 与 Windows 两个版本。

## 脚本说明

| 脚本 | 平台 | 用途 | 依赖 |
| --- | --- | --- | --- |
| [`extract_atrest_key_mac.py`](extract_atrest_key_mac.py) | macOS | 通过调试端口从运行中的 WorkBuddy 主进程提取 AtRest 构建期密钥，并校验其与本地 auth 文件的 keyId 是否匹配。 | Python 标准库 |
| [`get_wb_headers_mac.py`](get_wb_headers_mac.py) | macOS | 从本地 auth 文件解密出 `Authorization`、读取 `X-User-Id`，并从钥匙串获取 `X-Device-Token`。 | `cryptography` |
| [`extract_atrest_key_win.py`](extract_atrest_key_win.py) | Windows | 同上，Windows 版；需与 `get_wb_headers_win.py` 放在同一目录。 | Python 标准库 |
| [`get_wb_headers_win.py`](get_wb_headers_win.py) | Windows | 同上，Windows 版；设备令牌由 Node 加载 `native/turing-sdk` 现取。 | `cryptography`（缺失时改用 Node） |
| [`workbuddy-checkin.py`](workbuddy-checkin.py) | 通用 | 查询签到活动状态，在活动开启且今日未签到时执行签到。 | Python 标准库 |

## 环境要求

- Python 3.10 或更高版本。
- 已安装并登录 WorkBuddy 客户端。
- 只有请求头脚本需要额外安装依赖：

  ```bash
  python -m pip install cryptography
  ```

- Windows 版请求头脚本在未安装 `cryptography` 时会改用 Node.js 内置 crypto，此时需要机器上有 `node` 可执行文件。

## 使用步骤

### 1. 获取请求头

macOS：

```bash
python3 get_wb_headers_mac.py
```

Windows：

```bash
python get_wb_headers_win.py
```

脚本会输出 `Authorization`、`X-User-Id` 和 `X-Device-Token`。macOS 的设备令牌优先从钥匙串实时读取；Windows 没有钥匙串，由 Node 加载原生模块现取，取不到时可不带该头（签到接口可省略）。

如果提示信封 `keyId` 与当前密钥不匹配，说明 WorkBuddy 升级后更换了构建期密钥，需要重新提取。

macOS：

```bash
# 1. 完全退出 WorkBuddy（Cmd+Q）
# 2. 以调试模式启动应用
open -a "WorkBuddy" --args --inspect=9229
# 3. 等应用启动后运行提取脚本
python3 extract_atrest_key_mac.py
```

Windows：

```powershell
# 1. 完全退出 WorkBuddy
taskkill /IM WorkBuddy.exe /F
# 2. 以调试模式启动应用（路径换成实际安装目录）
& "D:\workbuddy\WorkBuddy.exe" --inspect=9229
# 3. 等应用启动后运行提取脚本
python extract_atrest_key_win.py
```

将输出的 `AT_REST_SECRET_KEY` 填入对应请求头脚本顶部的同名变量，然后重新运行请求头脚本。

### 2. 配置签到脚本

把上一步得到的值填入 [`workbuddy-checkin.py`](workbuddy-checkin.py) 顶部的「配置区」：

- `AUTHORIZATION`
- `X_USER_ID`
- `X_DEVICE_TOKEN`

`Authorization` 需包含 `Bearer ` 前缀。企业账号可选填 `X_ENTERPRISE_ID` / `X_TENANT_ID`。

### 3. 执行签到

```bash
python workbuddy-checkin.py
```

脚本会先探测服务端端点并查询签到状态，仅在活动开启且今日未签到时提交签到。错误码含义：`1001` 今日已签到（幂等）、`1002` 不满足签到条件、`1003` 活动已结束。

## 敏感信息

仓库中的脚本均不包含真实凭据，相关变量默认为空，需要在本机填写后使用。

`Authorization`（JWT）、`X-User-Id`、`X-Device-Token` 和 `AT_REST_SECRET_KEY` 均为账号相关凭据，不要将真实值提交到代码仓库、公开日志或聊天中。JWT 过期后需重新运行请求头脚本获取。`AT_REST_SECRET_KEY` 由客户端构建期生成，随 WorkBuddy 版本变化。
