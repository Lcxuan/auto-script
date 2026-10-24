# Trae CN 自动化脚本

本目录包含 Trae CN 签到脚本，以及用于从已安装的 Trae CN 客户端提取签到请求参数的辅助脚本。

## 脚本说明

| 脚本 | 用途 | 适用系统 |
| --- | --- | --- |
| [`trae_checkin.py`](trae_checkin.py) | 查询签到活动状态；活动开启且今日尚未签到时领取签到积分。 | macOS、Windows、Linux |
| [`trae_headers_extract_mac.py`](trae_headers_extract_mac.py) | 从本机 Trae CN 客户端数据中提取签到所需请求头。 | macOS |
| [`trae_headers_extract_win.py`](trae_headers_extract_win.py) | 从本机 Trae CN 客户端数据中提取签到所需请求头。 | Windows |

## 环境要求

- Python 3.10 或更高版本。
- 请求头提取脚本应在安装并登录了 Trae CN 的对应操作系统上运行。
- 签到脚本只使用 Python 标准库。请求头提取器如需从客户端登录态自动读取 JWT，运行前需要安装 `pycryptodome`；也可以通过 `TRAE_JWT` 环境变量或备用令牌文件提供 JWT，从而不使用解密功能。

## 使用步骤

### 1. 提取请求头

在已安装并登录 Trae CN 的电脑上运行对应系统的提取器：

如需从客户端登录态自动读取 JWT，先安装依赖：


```bash
python -m pip install pycryptodome
```

然后运行对应系统的提取器：

macOS：

```bash
python trae_headers_extract_mac.py
```

Windows：

```powershell
python trae_headers_extract_win.py
```

需要 JSON 格式时添加 `--json`：

```bash
python trae_headers_extract_mac.py --json
```

提取器会输出 `Authorization`、`x-device-id`、`x-device-brand`、`x-device-type`、`x-os-version` 和 `x-app-version` 等请求头。也可以通过 `TRAE_JWT` 环境变量提供 JWT；`trae_token.txt` 是可选的手动备用来源。

### 2. 配置签到脚本

将提取到的六项值填写到 [`trae_checkin.py`](trae_checkin.py) 文件顶部对应的变量中：

- `AUTHORIZATION`
- `X_DEVICE_ID`
- `X_DEVICE_BRAND`
- `X_DEVICE_TYPE`
- `X_OS_VERSION`
- `X_APP_VERSION`

`AUTHORIZATION` 可以填写完整的 `Cloud-IDE-JWT ...` 值，也可以只填写 JWT；脚本会自动补上前缀。

### 3. 执行签到

在本目录运行：

```bash
python trae_checkin.py
```

脚本会先查询状态，再在活动开启且今日未签到时提交一次签到。只查询状态、不领取积分：

```bash
python trae_checkin.py --check-only
```

签到脚本只使用 Python 标准库，不依赖浏览器或 Playwright。可以将它部署到 Linux 服务器运行，但请求头提取器读取的是本机 Trae CN 客户端数据，通常需要先在已安装并登录客户端的 macOS 或 Windows 电脑上提取参数，再将参数安全地配置到服务器。

## 敏感信息

`Authorization` 是账号令牌，请求头中还包含设备标识。不要将令牌、完整提取结果或填写了真实参数的脚本提交到代码仓库、公开日志或聊天中。令牌过期后，请重新获取并更新配置。
