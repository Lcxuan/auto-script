#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""macOS：获取 WorkBuddy 每日签到所需的三个请求头。

输出内容与来源：
  X-User-Id       auth 文件里的 account.uid，明文
  Authorization   auth 文件里的 auth.accessToken 是加密信封，用构建期密钥离线解密出 JWT
  X-Device-Token  TuringShield 风控令牌，每次运行从 macOS 钥匙串实时读取

使用方式：
  1. 运行 extract_atrest_key_mac.py，把输出的密钥填入下方配置区 AT_REST_SECRET_KEY
  2. 运行本脚本，拿到 Authorization / X-User-Id / X-Device-Token
  3. 把这三个值填到 workbuddy-checkin.py 的配置区，再运行签到脚本

用法：
  python3 get_wb_headers_mac.py                     # 默认：密钥读配置区，设备令牌读钥匙串
  python3 get_wb_headers_mac.py --device-token XXX  # 直接指定设备令牌
  python3 get_wb_headers_mac.py --try-cdp           # 从运行中的应用取设备令牌（需 --inspect 启动）
  python3 get_wb_headers_mac.py --auth-file PATH    # 指定 auth 文件

参数：
  --auth-file <路径>       指定 auth 文件（默认自动探测候选路径）
  --device-token <TOKEN>   直接指定设备令牌，不读钥匙串
  --cdp-port <端口>        从运行中的应用取设备令牌（应用需以 --inspect 启动）
  --try-cdp                自动尝试 9229-9231 端口取设备令牌

依赖：pip install cryptography
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# =====================================================================
# 配置区
# =====================================================================

# 构建期密钥 atRestSecretKey。
# 获取方式：运行 extract_atrest_key_mac.py 会打印该值，复制到这里；
# App 升级后若提示 keyId 不匹配，需要用同样的方式重新提取。填好后不要把该文件提交上去。
AT_REST_SECRET_KEY = ""

# auth 文件候选路径（按顺序探测，找到第一个存在的即用）
AUTH_FILE_CANDIDATES = [
    os.path.expanduser("~/Library/Application Support/CodeBuddyExtension/Data/Public/auth/workbuddy-desktop.info"),
    os.path.expanduser("~/.workbuddy-ai/app/Data/Public/auth/workbuddy-desktop.info"),
    os.path.expanduser("~/Library/Application Support/WorkBuddy AI/Data/Public/auth/workbuddy-desktop.info"),
]

# TuringShield 在钥匙串中持久化的服务名
# （appId=com.tencent.workbuddy.mac, channelId=109144）
TURING_KEYCHAIN_SERVICE = "com.turingshield.identifying.com.tencent.workbuddy.mac.109144"

# --try-cdp 时依次尝试的调试端口
DEFAULT_CDP_PORTS = [9229, 9230, 9231]


# =====================================================================
# 密钥派生与信封解密
# =====================================================================

def derive_atrest_key(secret: str) -> tuple[bytes, str]:
    """由 atRestSecretKey 推导 AES 密钥与 keyId。

    AES 密钥 = sha256(atRestSecretKey)；keyId = sha256(AES 密钥).hex()[:16]（双重哈希）。
    """
    aes_key = hashlib.sha256(secret.encode("utf-8")).digest()
    key_id = hashlib.sha256(aes_key).hexdigest()[:16]
    return aes_key, key_id


def build_aad(key_id: str) -> bytes:
    """构造字段级结构化 AAD（54 字节），与客户端加密实现保持一致。"""
    def lp(s: bytes) -> bytes:
        # length-prefixed：4 字节大端长度 + 内容
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
    """解密 accessToken 信封，返回 JWT 明文。"""
    nonce = base64.b64decode(env["nonce"])
    tag = base64.b64decode(env["authTag"])
    ct = base64.b64decode(env["ciphertext"])
    aad = build_aad(env["keyId"])
    plain = AESGCM(aes_key).decrypt(nonce, ct + tag, aad)
    return plain.decode("utf-8")


# =====================================================================
# 读取 auth 文件
# =====================================================================

def find_auth_file(path_override: str | None) -> str:
    """返回第一个存在的 auth 文件路径。"""
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


# =====================================================================
# X-Device-Token 获取
# =====================================================================

def read_keychain_device_token() -> tuple[str | None, str | None]:
    """从 macOS 钥匙串读取 TuringShield 持久化的设备标识。

    返回 (token, 错误说明)。注意：非交互环境下调用 security 可能触发系统
    钥匙串授权弹窗并阻塞，因此设置较短超时并允许失败。
    """
    try:
        out = subprocess.run(
            ["security", "find-generic-password", "-w", "-s", TURING_KEYCHAIN_SERVICE],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        return None, "系统钥匙串授权超时（可能弹窗等待确认，已跳过）"
    except Exception as e:
        return None, f"钥匙串读取异常: {e}"
    val = out.stdout.strip() if out.returncode == 0 else ""
    if val:
        return val, None
    return None, f"钥匙串中无该条目 (security rc={out.returncode})"


# ---------------------------------------------------------------------
# 极简 WebSocket 客户端：CDP 协议只需要「发一条文本帧、收一条文本帧」
# ---------------------------------------------------------------------

def _ws_connect(port: int):
    """连上调试端口的第一个目标，返回已完成握手的 socket。"""
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=3) as r:
        targets = json.load(r)
    ws_url = next((t["webSocketDebuggerUrl"] for t in targets if t.get("webSocketDebuggerUrl")), None)
    if not ws_url:
        raise ConnectionError(f"端口 {port} 没有可调试目标")
    rest = ws_url[len("ws://"):]
    hostport, _, path = rest.partition("/")
    host, _, port_s = hostport.rpartition(":")
    path = "/" + path

    sock = socket.create_connection((host, int(port_s)), timeout=10)
    ws_key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port_s}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(req.encode("ascii"))
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += sock.recv(4096)
    status_line = resp.split(b"\r\n", 1)[0]
    if b"101" not in status_line:
        sock.close()
        raise ConnectionError("WebSocket 握手失败: " + repr(status_line))
    return sock


def _ws_send(sock, text: str):
    """按客户端规范发送一个掩码的文本帧。"""
    payload = text.encode("utf-8")
    mask = os.urandom(4)
    header = bytearray([0x81])  # FIN + text
    ln = len(payload)
    if ln < 126:
        header.append(0x80 | ln)
    elif ln < 65536:
        header.append(0x80 | 126)
        header += struct.pack(">H", ln)
    else:
        header.append(0x80 | 127)
        header += struct.pack(">Q", ln)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + mask + masked)


def _ws_recv(sock) -> bytes:
    """接收一帧数据（只关心 payload，不区分控制帧）。"""
    head = sock.recv(2)
    if len(head) < 2:
        raise ConnectionError("连接已关闭")
    ln = head[1] & 0x7F
    if ln == 126:
        ln = struct.unpack(">H", sock.recv(2))[0]
    elif ln == 127:
        ln = struct.unpack(">Q", sock.recv(8))[0]
    data = b""
    while len(data) < ln:
        data += sock.recv(ln - len(data))
    return data


def _cdp_call(sock, msg_id: int, method: str, params: dict) -> dict:
    """发送一条 CDP 请求，忽略事件通知，返回 id 匹配的响应。"""
    _ws_send(sock, json.dumps({"id": msg_id, "method": method, "params": params}))
    while True:
        frame = _ws_recv(sock)
        if not frame:
            continue
        try:
            msg = json.loads(frame.decode("utf-8"))
        except Exception:
            continue
        if msg.get("id") == msg_id:
            return msg


def fetch_device_token_via_cdp(port: int) -> str:
    """让运行中的应用调用 Turing SDK 原生接口，取到运行时真实使用的设备令牌。"""
    expr = """
    (async () => {
      const path = require('path');
      const { app } = require('electron');
      try {
        const appPath = app.getAppPath();
        const mod = process.mainModule.require(path.join(appPath, 'native', 'turing-sdk', 'index.cjs'));
        mod.configure(109144, app.getName(), app.getVersion(), true);
        const token = await mod.fetchDeviceToken({
          usingCachedMessage: true, includesOutdatedMessage: true,
          includesDeviceInfo: true, timeoutMs: 15000
        });
        return { ok: true, token: String(token) };
      } catch (e) {
        return { ok: false, error: String((e && e.message) || e) };
      }
    })()
    """
    sock = _ws_connect(port)
    try:
        _cdp_call(sock, 1, "Runtime.enable", {})
        resp = _cdp_call(sock, 2, "Runtime.evaluate", {
            "expression": expr,
            "awaitPromise": True,
            "returnByValue": True,
            "includeCommandLineAPI": False,
        })
        val = resp.get("result", {}).get("result", {}).get("value")
        if isinstance(val, dict) and val.get("ok"):
            return val["token"]
        err = val.get("error") if isinstance(val, dict) else resp.get("result", {}).get("exceptionDetails", "未知错误")
        raise ConnectionError(f"运行时获取失败: {err}")
    finally:
        sock.close()


def get_device_token(args) -> tuple[str | None, str]:
    """按优先级获取 X-Device-Token，返回 (token, 来源说明)。

    优先级：--device-token 参数 → CDP 运行时读取（仅显式指定时）→ 钥匙串实时读取。
    """
    if args.device_token:
        return args.device_token, "参数 --device-token"
    if args.cdp_port or args.try_cdp:
        ports = [args.cdp_port] if args.cdp_port else DEFAULT_CDP_PORTS
        for p in ports:
            try:
                tok = fetch_device_token_via_cdp(p)
                return tok, f"运行时 CDP 端口 {p}"
            except Exception:
                continue
    kc, kc_err = read_keychain_device_token()
    if kc:
        return kc, "钥匙串 TuringShield（实时读取）"
    return None, kc_err or "Turing SDK 未初始化或未安装"


# =====================================================================
# 主流程
# =====================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="获取 WorkBuddy 签到请求头")
    parser.add_argument("--auth-file", help="指定 auth 文件路径（默认自动探测）")
    parser.add_argument("--device-token", help="直接指定 X-Device-Token")
    parser.add_argument("--cdp-port", type=int, help="应用调试端口（需以 --inspect 启动应用）")
    parser.add_argument("--try-cdp", action="store_true",
                        help="自动探测常见调试端口(9229-9231)尝试运行时获取 X-Device-Token")
    args = parser.parse_args()

    auth_path = find_auth_file(args.auth_file)
    auth = load_auth(auth_path)

    secret = AT_REST_SECRET_KEY.strip()
    if not secret:
        print("[错误] 未配置 atRestSecretKey。请先运行 extract_atrest_key_mac.py 获取，"
              "填入本文件顶部 AT_REST_SECRET_KEY 后再运行。",
              file=sys.stderr)
        return 1

    aes_key, key_id = derive_atrest_key(secret)

    # X-User-Id：明文
    uid = auth.get("account", {}).get("uid")
    if not uid:
        print("[错误] auth 文件中没有 account.uid", file=sys.stderr)
        return 1

    # Authorization：解密 accessToken 信封得到 JWT
    token_wrap = auth["auth"]["accessToken"]
    env = json.loads(base64.b64decode(token_wrap["envelope"]).decode("utf-8"))
    if env.get("keyId") != key_id:
        print(f"[警告] 信封 keyId({env.get('keyId')}) 与当前密钥推导 keyId({key_id}) 不匹配，"
              f"说明构建期密钥已更新，需重新从运行时提取 atRestSecretKey", file=sys.stderr)
    jwt = decrypt_access_token(env, aes_key)
    authorization = f"Bearer {jwt}"

    # X-Device-Token
    dev_token, dev_src = get_device_token(args)

    print("=== WorkBuddy 签到请求头 ===")
    print(f"X-User-Id         : {uid}")
    print(f"Authorization     : {authorization}")
    if dev_token:
        print(f"X-Device-Token    : {dev_token}   (来源: {dev_src})")
    else:
        print(f"X-Device-Token    : (未获取到；{dev_src}。签到接口可省略此头)")
        print("                  如需与运行时实际值比对：退出应用后启动 "
              "`open -a \"WorkBuddy\" --args --inspect=9229`，再运行本脚本加 --try-cdp")
    print("---")
    print(f"auth 文件         : {auth_path}")
    print(f"密钥 keyId        : {key_id}  (与信封匹配: {env.get('keyId') == key_id})")
    expires = auth.get("auth", {}).get("expiresAt")
    if isinstance(expires, (int, float)):
        import datetime
        dt = datetime.datetime.fromtimestamp(expires / 1000)
        print(f"token 过期时间    : {dt:%Y-%m-%d %H:%M:%S}（本地时区）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
