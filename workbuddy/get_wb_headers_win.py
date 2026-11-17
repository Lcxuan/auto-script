#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows 版
获取 WorkBuddy 每日签到所需的请求头：Authorization / X-User-Id / X-Device-Token

输出内容与来源：
  X-User-Id       auth 文件里的 account.uid，明文
  Authorization   auth 文件里的 auth.accessToken 是加密信封，用构建期密钥离线解密出 JWT
  X-Device-Token  TuringShield 风控令牌。Windows 没有钥匙串，由 Node 子进程加载原生模块
                  native/turing-sdk（turing_sdk.node + TuringShieldSDK.dll）现取，无需启动应用

使用方式：
  1. 运行 extract_atrest_key_win.py，把输出的密钥填入下方配置区 AT_REST_SECRET_KEY
  2. 运行本脚本，拿到 Authorization / X-User-Id / X-Device-Token
  3. 把这三个值填到 workbuddy-checkin.py 的配置区，再运行签到脚本

用法：
  python get_wb_headers_win.py                     # 默认：密钥读配置区，设备令牌由 Node 现取
  python get_wb_headers_win.py --device-token XXX  # 直接指定设备令牌
  python get_wb_headers_win.py --no-device-token   # 跳过设备令牌获取
  python get_wb_headers_win.py --auth-file PATH    # 指定 auth 文件

参数：
  --auth-file <路径>       指定 auth 文件（默认自动探测候选路径）
  --device-token <TOKEN>   直接指定设备令牌
  --no-device-token        跳过设备令牌获取（签到接口可省略该头）

解密依赖：优先 cryptography；未安装时自动改用 Node 内置 crypto（需要 node 可执行文件）。
"""

import argparse
import base64
import glob
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

# 构建期密钥载荷中的 atRestSecretKey（与 macOS 版同一把，实测 keyId=9127dea1b44020a7）。
# 获取方式：运行 extract_atrest_key_win.py 会打印该值，复制到这里；App 升级后若提示
# keyId 不匹配，需要用同样的方式重新提取。填好后不要把该文件提交上去。
AT_REST_SECRET_KEY = ""

# auth 文件候选路径（按优先级探测）
AUTH_FILE_CANDIDATES = [
    os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.expanduser(r"~\AppData\Local")),
        "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info",
    ),
    os.path.expanduser(r"~/.workbuddy-ai/app/Data/Public/auth/workbuddy-desktop.info"),
]

# TuringShield 渠道号（product.json -> config.turingSdk.channelId）
TURING_CHANNEL_ID = 109144
PRODUCT_NAME = "WorkBuddy"

# 安装目录探测：先读注册表 InstallLocation，再退回常见路径
INSTALL_REGISTRY_KEY = r"Software\BFD312E9-1019-4F57-9F44-F86246833B50"
INSTALL_CANDIDATES = [
    r"D:\workbuddy",
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "WorkBuddy"),
    os.path.join(os.environ.get("ProgramFiles", ""), "WorkBuddy"),
    os.path.join(os.environ.get("ProgramFiles(x86)", ""), "WorkBuddy"),
]

NODE_CANDIDATE_GLOBS = [
    os.path.expanduser(r"~/.workbuddy/binaries/node/versions/*/node.exe"),
    os.path.join(os.environ.get("ProgramFiles", ""), "nodejs", "node.exe"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "nodejs", "node.exe"),
]


# ---------------------------------------------------------------------------
# 解密链（与已离线验证的链路一致）
# ---------------------------------------------------------------------------

def derive_atrest_key(secret: str) -> tuple[bytes, str]:
    """AES 密钥 = sha256(atRestSecretKey UTF-8)；keyId = sha256(AES密钥).hex()[:16]"""
    aes_key = hashlib.sha256(secret.encode("utf-8")).digest()
    key_id = hashlib.sha256(aes_key).hexdigest()[:16]
    return aes_key, key_id


def build_aad(key_id: str) -> bytes:
    """字段级结构化 AAD（54 字节）"""
    def lp(s: bytes) -> bytes:
        return struct.pack(">I", len(s)) + s
    return b"".join([
        b"WB-AAD\x00",
        b"\x01",
        lp(b"WBEV1"),
        lp(b"sym-v1"),
        struct.pack(">I", 1),
        lp(key_id.encode("ascii")),
        b"\x02\x00\x00",
    ])


def decrypt_access_token(env: dict, aes_key: bytes) -> str:
    """解密 accessToken 信封 -> JWT"""
    nonce = base64.b64decode(env["nonce"])
    tag = base64.b64decode(env["authTag"])
    ct = base64.b64decode(env["ciphertext"])
    aad = build_aad(env["keyId"])
    if _HAS_CRYPTO:
        return AESGCM(aes_key).decrypt(nonce, ct + tag, aad).decode("utf-8")

    # 未安装 cryptography 时，借用 Node 的 crypto 做 AES-256-GCM
    node = _node_executable()
    if not node:
        raise RuntimeError(
            "缺少解密依赖：未安装 cryptography，且找不到 node 可执行文件。\n"
            "请任选其一：pip install cryptography，或安装 Node.js"
        )
    payload = {
        "key": base64.b64encode(aes_key).decode("ascii"),
        "nonce": env["nonce"],
        "authTag": env["authTag"],
        "ciphertext": env["ciphertext"],
        "aad": base64.b64encode(aad).decode("ascii"),
    }
    out = _run_node_script(_NODE_DECRYPT_JS, payload)
    return out.strip()


_NODE_DECRYPT_JS = r"""
const fs = require('fs');
const crypto = require('crypto');
const j = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const d = crypto.createDecipheriv('aes-256-gcm', Buffer.from(j.key, 'base64'), Buffer.from(j.nonce, 'base64'), { authTagLength: 16 });
d.setAAD(Buffer.from(j.aad, 'base64'));
d.setAuthTag(Buffer.from(j.authTag, 'base64'));
process.stdout.write(Buffer.concat([d.update(Buffer.from(j.ciphertext, 'base64')), d.final()]).toString('utf8'));
"""


# ---------------------------------------------------------------------------
# Node 辅助（解密 / 取设备令牌）
# ---------------------------------------------------------------------------

def _node_executable() -> str | None:
    exe = shutil.which("node")
    if exe:
        return exe
    for pattern in NODE_CANDIDATE_GLOBS:
        hits = sorted(glob.glob(pattern), reverse=True)
        if hits:
            return hits[0]
    return None


def _run_node_script(source: str, json_payload: dict | None = None, argv: list[str] | None = None,
                     timeout: int = 60) -> str:
    """把 JS 写到临时文件后交给 node 执行，返回 stdout。"""
    node = _node_executable()
    if not node:
        raise RuntimeError("找不到 node 可执行文件（可用 --device-token 跳过设备令牌获取）")

    script_path = None
    payload_path = None
    try:
        fd, script_path = tempfile.mkstemp(suffix=".cjs", prefix="wb_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(source)

        cmd = [node, script_path]
        if json_payload is not None:
            fd2, payload_path = tempfile.mkstemp(suffix=".json", prefix="wb_")
            with os.fdopen(fd2, "w", encoding="utf-8") as f:
                json.dump(json_payload, f)
            cmd.append(payload_path)
        if argv:
            cmd.extend(argv)

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout).strip() or "node 执行失败")
        return proc.stdout
    finally:
        for p in (script_path, payload_path):
            if p:
                try:
                    os.unlink(p)
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# 安装目录 / 版本
# ---------------------------------------------------------------------------

def find_install_dir() -> str | None:
    """定位 WorkBuddy 安装目录（含 resources/app.asar 的那层）。"""
    candidates = []

    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INSTALL_REGISTRY_KEY) as k:
            loc, _ = winreg.QueryValueEx(k, "InstallLocation")
            if loc:
                candidates.append(loc)
    except (ImportError, OSError):
        pass

    candidates.extend(c for c in INSTALL_CANDIDATES if c)
    for c in candidates:
        if os.path.isfile(os.path.join(c, "resources", "app.asar")):
            return c
    return None


def read_app_version(install_dir: str) -> str:
    manifest = os.path.join(install_dir, "resources", "install-manifest.json")
    try:
        with open(manifest, "r", encoding="utf-8") as f:
            ver = json.load(f).get("appVersion")
            if ver:
                return str(ver)
    except (OSError, ValueError):
        pass
    try:
        with open(os.path.join(install_dir, "resources", "version"), "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        pass
    return "0.0.0"


# ---------------------------------------------------------------------------
# X-Device-Token 获取
# ---------------------------------------------------------------------------

_NODE_DEVICE_TOKEN_JS = r"""
const addonDir = process.argv[2];
const channelId = Number(process.argv[3]);
const productName = process.argv[4];
const productVersion = process.argv[5];

(async () => {
  try {
    const addon = require(addonDir);
    if (!addon.isSupported()) {
      throw new Error(addon.getLoadError() || 'Turing SDK native binding unavailable');
    }
    addon.configure(channelId, productName, productVersion);
    const token = await addon.fetchDeviceToken({
      usingCachedMessage: true,
      includesOutdatedMessage: true,
      includesDeviceInfo: true,
      timeoutMs: 15000,
    });
    process.stdout.write(JSON.stringify({ ok: true, token: String(token) }));
  } catch (e) {
    process.stdout.write(JSON.stringify({ ok: false, error: String((e && e.message) || e) }));
  }
})();
"""


def fetch_device_token_via_node() -> tuple[str | None, str]:
    install_dir = find_install_dir()
    if not install_dir:
        return None, "未找到 WorkBuddy 安装目录（native/turing-sdk 不可用）"

    addon_dir = os.path.join(install_dir, "resources", "app.asar.unpacked", "native", "turing-sdk")
    if not os.path.isdir(addon_dir):
        return None, f"缺少原生模块目录：{addon_dir}"
    if not _node_executable():
        return None, "找不到 node 可执行文件"

    version = read_app_version(install_dir)
    try:
        out = _run_node_script(
            _NODE_DEVICE_TOKEN_JS,
            argv=[addon_dir, str(TURING_CHANNEL_ID), PRODUCT_NAME, version],
            timeout=60,
        )
    except Exception as e:
        return None, f"Node 调用失败: {e}"

    try:
        res = json.loads(out.strip())
    except ValueError:
        return None, f"Node 返回无法解析: {out.strip()[:200]}"

    if res.get("ok") and res.get("token"):
        return res["token"], f"native/turing-sdk（Node 现取，WorkBuddy {version}）"
    return None, str(res.get("error") or "Turing SDK 未返回令牌")


def get_device_token(args) -> tuple[str | None, str]:
    """返回 (token, 来源说明)。优先级：--no-device-token → --device-token → Node 现取。"""
    if args.no_device_token:
        return None, "参数 --no-device-token"
    if args.device_token:
        return args.device_token, "参数 --device-token"
    return fetch_device_token_via_node()


# ---------------------------------------------------------------------------
# 读取 auth 文件
# ---------------------------------------------------------------------------

def find_auth_file(path_override: str | None) -> str:
    if path_override:
        return path_override
    for p in AUTH_FILE_CANDIDATES:
        if os.path.isfile(p):
            return p
    raise FileNotFoundError(
        "未找到 auth 文件，请先登录 WorkBuddy。候选路径：\n" + "\n".join(AUTH_FILE_CANDIDATES)
    )


def load_auth(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="获取 WorkBuddy 签到请求头（Windows）")
    parser.add_argument("--auth-file", help="指定 auth 文件路径（默认自动探测）")
    parser.add_argument("--device-token", help="直接指定 X-Device-Token")
    parser.add_argument("--no-device-token", action="store_true",
                        help="跳过设备令牌获取（签到接口可省略该头）")
    args = parser.parse_args()

    auth_path = find_auth_file(args.auth_file)
    auth = load_auth(auth_path)

    secret = AT_REST_SECRET_KEY.strip()
    if not secret:
        print("[错误] 未配置 atRestSecretKey。请先运行 extract_atrest_key_win.py 获取，"
              "填入本文件顶部 AT_REST_SECRET_KEY 后再运行。",
              file=sys.stderr)
        return 1

    aes_key, key_id = derive_atrest_key(secret)

    # X-User-Id
    uid = auth.get("account", {}).get("uid")
    if not uid:
        print("[错误] auth 文件中没有 account.uid", file=sys.stderr)
        return 1

    # Authorization
    token_wrap = auth["auth"]["accessToken"]
    env = json.loads(base64.b64decode(token_wrap["envelope"]).decode("utf-8"))
    if env.get("keyId") != key_id:
        print(f"[警告] 信封 keyId({env.get('keyId')}) 与当前密钥推导 keyId({key_id}) 不匹配，"
              f"说明构建期密钥已更新，需用 extract_atrest_key_win.py 重新提取 atRestSecretKey",
              file=sys.stderr)
    jwt = decrypt_access_token(env, aes_key)
    authorization = f"Bearer {jwt}"

    # X-Device-Token
    dev_token, dev_src = get_device_token(args)

    print("=== WorkBuddy 签到请求头（Windows）===")
    print(f"X-User-Id         : {uid}")
    print(f"Authorization     : {authorization}")
    if dev_token:
        print(f"X-Device-Token    : {dev_token}   (来源: {dev_src})")
    else:
        print(f"X-Device-Token    : (未获取到；{dev_src}。签到接口可省略此头)")
    print("---")
    print(f"auth 文件         : {auth_path}")
    print(f"密钥 keyId        : {key_id}  (与信封匹配: {env.get('keyId') == key_id})")
    expires = auth.get("auth", {}).get("expiresAt")
    if isinstance(expires, (int, float)):
        import datetime
        dt = datetime.datetime.fromtimestamp(expires / 1000)
        print(f"token 过期时间    : {dt:%Y-%m-%d %H:%M:%S}（本地时区）")
    enterprise = auth.get("account", {}).get("enterpriseId")
    if enterprise:
        print(f"企业账号提示      : 请求时再加 X-Enterprise-Id / X-Tenant-Id = {enterprise}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
