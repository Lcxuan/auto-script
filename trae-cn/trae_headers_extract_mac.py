#!/usr/bin/env python3
"""提取 Trae CN 签到接口所需的全部请求头参数 (macOS系统专用)。

可提取:
  x-device-id    ← aha 注册的远程设备 ID
  x-device-brand ← 设备型号(如 Mac14,10,)
  x-device-type  ← 固定 "mac"
  x-os-version   ← 系统版本(如 "macOS 14.1")
  x-app-version  ← TRAE CN 客户端版本 (1.107.1)
  Authorization  ← JWT Token

Authorization 的查找顺序：环境变量 TRAE_JWT > 解密 storage.json 取登录态真实 token > trae_token.txt
  真实 token 与客户端签到所用一致: 登录后为 7 天 v1, 客户端自动刷新后为 14 天 v2 (含 refreshToken);
  trae_token.txt 为可选手动兜底。不读 trae-jwt-token (GenerateTempToken 临时 token, 签到接口会拒绝)

用法:
  python3 trae_headers_extract.py                  # 提取并完整显示
  python3 trae_headers_extract.py --json           # 输出 JSON
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time

try:
    from Crypto.Cipher import AES  # 依赖 pycryptodome: pip install pycryptodome
except ImportError:
    AES = None  # 解密 storage.json 需要, 未安装时自动跳过该来源

# macOS Electron userData 目录
APP_SUPPORT = pathlib.Path.home() / "Library" / "Application Support" / "Trae CN"

# 登录态 storage.json (加密存储 access_token / refresh_token)
STORAGE_JSON = APP_SUPPORT / "User/globalStorage/storage.json"
AUTH_INFO_KEY = "iCubeAuthInfo://icube.cloudide"

# byteCrypto 内置 64 字节密钥 (复刻自 app 主进程 out/main.js, 用于解密 storage.json)
_XDE = bytes.fromhex(
    "BF C0 D8 FA 7A F6 DC 61 1F FE 62 1B 08 48 47 B0 87 63 60 12 7F 65 CB 68 "
    "D3 66 BF 7D 25 48 96 9C 33 E5 79 23 11 99 8D B1 6E 83 96 80 AC FF FE 06 "
    "12 8C 37 3E EC F9 87 40 87 0C 75 04 59 95 A8 D1")
_ODE = bytes.fromhex(
    "52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB 7C E3 39 82 9B 2F FF 87 "
    "34 8E 43 44 C4 DE E9 CB 54 7B 94 32 A6 C2 23 3D EE 4C 95 0B 42 FA C3 4E "
    "08 2E A1 66 28 D9 24 B2 76 5B A2 49 6D 8B D1 25")
_NDE = bytes.fromhex(
    "1F DD A8 33 88 07 C7 31 B1 12 10 59 27 80 EC 5F 60 51 7F A9 19 B5 4A 0D "
    "2D E5 7A 9F 93 C9 9C EF A0 E0 3B 4D AE 2A F5 B0 C8 EB BB 3C 83 53 99 61 "
    "17 2B 04 7E BA 77 D6 26 E1 69 14 63 55 21 0C 7D")
_AES_MAGIC = bytes([0x74, 0x63, 0x05, 0x10, 0x00, 0x00])  # b"tc\x05\x10\x00\x00"

# 包内 package.json (macOS 安装位置)
APP_PKG_CANDIDATES = [
    pathlib.Path("/Applications/Trae CN.app/Contents/Resources/app/package.json"),
]

# 含 JWT 的兜底候选文件: 手动放置的 trae_token.txt (放脚本同目录)
TOKEN_CANDIDATE_FILES = [
    pathlib.Path(__file__).resolve().parent / "trae_token.txt",
]
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def _run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()


def get_device_id() -> str | None:
    """x-device-id: 远程注册 ID (数字型)。tt_net_config.config 为 aha SDK 明文存储,
    格式: key&#*value@$*key&#*value@$*..."""
    f = APP_SUPPORT / "ahanet/tt_net_config.config"
    if f.exists():
        for seg in f.read_text("utf-8", errors="ignore").split("@$*"):
            if "&#*" in seg:
                k, _, v = seg.partition("&#*")
                if k.strip() == "device_id" and v.strip().isdigit():
                    return v.strip()
    # 兜底: 主进程日志 [ICDRS] 行
    pat = re.compile(r"initialization done, did: (\d+)")
    hits: list[str] = []
    logs = APP_SUPPORT / "logs"
    if logs.exists():
        for f in logs.rglob("*.log"):
            try:
                hits += pat.findall(f.read_text("utf-8", errors="ignore"))
            except OSError:
                pass
    return hits[-1] if hits else None


def get_brand() -> str:
    """x-device-brand: 设备型号。官方取 ahaDeviceService.deviceInfo.model:
    macOS = 机型标识 (如 Mac14,10)。"""
    return _run(["sysctl", "-n", "hw.model"])


def get_device_type() -> str:
    """x-device-type: 官方映射 darwin→'mac' (小写)。"""
    return "mac"


def get_os_version() -> str:
    """x-os-version: 官方实现 = 'macOS ' + sw_vers 版本。"""
    ver = _run(["sw_vers", "-productVersion"])
    return f"macOS {ver}" if ver else ""


def get_app_version() -> str:
    """x-app-version: 打包时写死在包内 package.json, 动态读取跟随自动更新。"""
    for pkg in APP_PKG_CANDIDATES:
        try:
            return json.loads(pkg.read_text())["version"]
        except (OSError, KeyError, json.JSONDecodeError):
            continue
    return ""


def _decrypt_storage_value(value: str) -> bytes:
    """复刻 app 内置 byteCrypto (SHA-512 链派生 + AES-128-CBC) 解密 storage.json 条目。
    布局: base64(magic(6) || 随机r(32) || AES-CBC密文), 明文 = SHA512(data) || data。"""
    if AES is None:
        raise RuntimeError("缺少 pycryptodome, 请先执行: pip install pycryptodome")
    raw = base64.b64decode(value)
    if raw[:6] != _AES_MAGIC:
        raise ValueError(f"magic 不匹配: {raw[:6].hex()}")
    r = raw[6:38]  # 32 字节随机数
    # kde(r,16,16,AES): o=SHA512(r); n=o||(ODE^NDE); n=SHA512(n)||n[64:]; key=n[0:16], iv=n[16:32]
    mix = bytes(x ^ y for x, y in zip(_ODE, _NDE))
    n = hashlib.sha512(r).digest() + mix
    n = hashlib.sha512(n).digest() + n[64:]
    plain = AES.new(n[0:16], AES.MODE_CBC, n[16:32]).decrypt(raw[38:])
    pad = plain[-1]
    if not (1 <= pad <= 16) or plain[-pad:] != bytes([pad]) * pad:
        raise ValueError("PKCS7 padding 校验失败")
    plain = plain[:-pad]
    if hashlib.sha512(plain[64:]).digest() != plain[:64]:
        raise ValueError("SHA-512 校验失败")
    return plain[64:]


def get_storage_userinfo() -> dict | None:
    """解密 storage.json 的 iCubeAuthInfo 条目, 返回登录态 userInfo。
    与应用自身签到所用的 token 完全一致 (登录后 v1, 自动刷新后 v2 含 refreshToken)。"""
    if not STORAGE_JSON.exists():
        return None
    try:
        store = json.loads(STORAGE_JSON.read_text("utf-8", errors="ignore"))
        value = store.get(AUTH_INFO_KEY)
        if not value:
            return None
        return json.loads(_decrypt_storage_value(value))
    except Exception as e:
        print(f"[storage] 读取失败: {e}", file=sys.stderr)
        return None


def find_token() -> str | None:
    """Authorization 的 JWT。查找顺序: 环境变量 TRAE_JWT > 解密 storage.json 取
    登录态真实 token > trae_token.txt。不读 trae-jwt-token (临时 token 会被签到拒绝)。"""
    env = os.environ.get("TRAE_JWT")
    if env:
        return env
    user = get_storage_userinfo()
    if user:
        tok = user.get("token")
        if tok and JWT_RE.match(tok):
            return tok
    for f in TOKEN_CANDIDATE_FILES:
        if f.exists():
            m = JWT_RE.search(f.read_text("utf-8", errors="ignore"))
            if m:
                return m.group(0)
    return None


def decode_jwt(token: str) -> dict | None:
    """解 JWT payload (不验签, 仅读取声明)。"""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="提取 Trae CN 签到请求头参数 (macOS)")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = ap.parse_args()

    device_id = get_device_id()
    brand = get_brand()
    dtype = get_device_type()
    osver = get_os_version()
    appver = get_app_version()
    token = find_token()

    headers = {
        "x-device-id": device_id or "",
        "x-device-brand": brand,
        "x-device-type": dtype,
        "x-os-version": osver,
        "x-app-version": appver,
        "Authorization": f"Cloud-IDE-JWT {token}" if token else "",
    }

    if args.json:
        print(json.dumps(headers, indent=2, ensure_ascii=False))
    else:
        print("=== Trae CN 签到请求头 ===")
        print(f"x-device-id    : {device_id or '(未找到)'}")
        print(f"x-device-brand : {brand or '(未找到)'}")
        print(f"x-device-type  : {dtype}")
        print(f"x-os-version   : {osver or '(未找到)'}")
        print(f"x-app-version  : {appver or '(未找到)'}")
        if token:
            print(f"Authorization  : Cloud-IDE-JWT {token}")
        else:
            print("Authorization  : (未提供 — 见下方说明)")

    # JWT 有效期检查 (走 stderr, --json 时保持 stdout 为纯 JSON)
    if token:
        payload = decode_jwt(token)
        if payload and isinstance(payload.get("exp"), (int, float)):
            left = payload["exp"] - time.time()
            exp_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(payload["exp"]))
            uid = (payload.get("data") or {}).get("id", "?")
            note = f"剩余约 {left / 86400:.1f} 天" if left > 0 else "已过期!"
            print(f"[JWT] 账号 {uid} | 过期时间 {exp_str} | {note}", file=sys.stderr)

    if not token and not args.json:
        print(
            "\n[说明] Authorization 的 JWT 读取顺序:\n"
            "  1. 环境变量  export TRAE_JWT='<JWT>'\n"
            "  2. 解密 storage.json 取登录态真实 access token (与应用签到所用一致)\n"
            "     位置: ~/Library/Application Support/Trae CN/User/globalStorage/storage.json\n"
            "  3. 脚本同目录 trae_token.txt (可选, 手动放置兜底)\n"
            "  依赖: 解密需要 pycryptodome, 未安装请执行 pip install pycryptodome\n"
            "  注意: 不要使用 ~/.trae-cn/trae-jwt-token (临时 token, 签到会返回 code=1001)"
        )

    # 汇总缺失项
    missing = [k for k, v in headers.items() if not v]
    if missing and not args.json:
        print(f"\n[缺失] {', '.join(missing)}")
    return 0 if not missing else 1


if __name__ == "__main__":
    sys.exit(main())
