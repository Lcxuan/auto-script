#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows 版
提取 WorkBuddy 的 AT_REST_SECRET_KEY（AtRest 构建期密钥）

为什么需要这个脚本：
  get_wb_headers_win.py 要解开 auth 文件里加密的 accessToken，而 AES 密钥由
  atRestSecretKey 派生。该密钥不落盘，只存在于运行中的应用主进程内存中，由
  electron.workbuddyStorage.loggerGet() 返回，所以只能从运行时取。

实现原理：
  应用以 --inspect=9229 启动后会开放 CDP 调试端口。本脚本用标准库实现了一个
  最小 WebSocket 客户端，连上主进程目标，执行一次 Runtime.evaluate 调用上述
  接口，从返回的 JSON 中取出 atRestSecretKey。

用法（换机器 / App 升级后 keyId 不匹配时用）：
  1. 完全退出 WorkBuddy（托盘退出，或 taskkill /IM WorkBuddy.exe /F）
  2. 调试模式启动：  & "D:\\workbuddy\\WorkBuddy.exe" --inspect=9229
  3. 运行：          python extract_atrest_key_win.py [端口，默认 9229]

输出 atRestSecretKey 及推导的 keyId，并自动与本地 auth 文件信封的
keyId 比对，给出「匹配/不匹配」结论。仅依赖 Python 标准库。
注意：本脚本会导入同目录下的 get_wb_headers_win.py，两者需放在一起。
"""

import base64
import hashlib
import json
import os
import socket
import struct
import sys
import urllib.request

from get_wb_headers_win import AUTH_FILE_CANDIDATES, find_install_dir

DEFAULT_PORT = 9229


def auth_file_path() -> str:
    for p in AUTH_FILE_CANDIDATES:
        if os.path.isfile(p):
            return p
    return AUTH_FILE_CANDIDATES[0]


def http_json(url, timeout=5):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def ws_connect(url, timeout=10):
    """极简 WebSocket 客户端：握手 + 返回已连接的 socket（仅支持文本帧收发）"""
    rest = url.replace("ws://", "")
    hostport, _, path = rest.partition("/")
    host, _, port = hostport.rpartition(":")
    port = int(port)
    key = base64.b64encode(os.urandom(16)).decode()
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    req = (
        "GET /%s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ) % (path, host, port, key)
    sock.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("WebSocket 握手失败：连接被关闭")
        resp += chunk
    if b" 101 " not in resp.split(b"\r\n", 1)[0]:
        raise RuntimeError("WebSocket 握手失败：%s" % resp.split(b"\r\n", 1)[0].decode(errors="replace"))
    return sock


def ws_send(sock, payload):
    mask = os.urandom(4)
    n = len(payload)
    header = bytearray([0x81])
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        header += bytes([0x80 | 127]) + struct.pack(">Q", n)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + mask + masked)


def ws_recv(sock):
    while True:
        b1, b2 = sock.recv(2)
        opcode = b1 & 0x0F
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack(">H", sock.recv(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", sock.recv(8))[0]
        data = b""
        while len(data) < n:
            data += sock.recv(n - len(data))
        if opcode == 9:  # ping -> pong
            ws_send(sock, bytes([0x8A]) + data)  # 简化：直接回未掩码 pong（多数实现容忍）
            continue
        if opcode == 1:
            return data


def cdp_eval(sock, expr, msg_id):
    payload = json.dumps({
        "id": msg_id,
        "method": "Runtime.evaluate",
        "params": {"expression": expr, "returnByValue": True},
    }).encode("utf-8")
    ws_send(sock, payload)
    while True:
        data = ws_recv(sock)
        try:
            obj = json.loads(data)
        except Exception:
            continue
        if obj.get("id") == msg_id:
            return obj


def extract_key(port):
    targets = http_json("http://127.0.0.1:%d/json/list" % port)
    if not isinstance(targets, list):
        targets = [t for t in targets.get("webSocketDebuggerUrl", [])] if isinstance(targets, dict) else []
    # 优先 node 类型目标（Electron 主进程），其次名字含 WorkBuddy 的
    candidates = []
    for t in targets:
        ws = t.get("webSocketDebuggerUrl")
        if not ws:
            continue
        score = 0
        typ = (t.get("type") or "").lower()
        title = (t.get("title") or "").lower()
        if typ == "node":
            score = 3
        elif "workbuddy" in title or "codebuddy" in title:
            score = 2
        else:
            score = 1
        candidates.append((score, ws))
    candidates.sort(reverse=True)

    expr = (
        "(() => { const m = process.mainModule.require('electron'); "
        "const s = m.workbuddyStorage.loggerGet(); "
        "return typeof s === 'string' ? s : JSON.stringify(s); })()"
    )
    last_err = None
    for i, (_, ws_url) in enumerate(candidates):
        try:
            sock = ws_connect(ws_url)
            try:
                resp = cdp_eval(sock, expr, i + 1)
                if resp.get("exceptionDetails"):
                    last_err = resp["exceptionDetails"].get("text", "eval 异常")
                    continue
                val = resp.get("result", {}).get("result", {}).get("value")
                if val:
                    raw = val if isinstance(val, str) else json.dumps(val)
                    return json.loads(raw), ws_url
            finally:
                sock.close()
        except Exception as e:
            last_err = str(e)
            continue
    raise RuntimeError("所有目标执行失败，最后错误：%s" % last_err)


def auth_envelope_keyid():
    """从本地 auth 文件取出任一信封的 keyId，用于比对"""
    try:
        with open(auth_file_path(), encoding="utf-8") as f:
            auth = json.load(f)

        def find(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, dict) and v.get("$wbEncrypted") == 1:
                        try:
                            env = json.loads(base64.b64decode(v["envelope"]))
                            if env.get("keyId"):
                                return env["keyId"]
                        except Exception:
                            pass
                    r = find(v)
                    if r:
                        return r
            elif isinstance(obj, list):
                for v in obj:
                    r = find(v)
                    if r:
                        return r
            return None

        return find(auth)
    except Exception:
        return None


def launch_hint(port: int) -> str:
    install_dir = find_install_dir()
    exe = os.path.join(install_dir, "WorkBuddy.exe") if install_dir else r"D:\workbuddy\WorkBuddy.exe"
    return (
        "端口 %d 无调试服务。请先：\n"
        "  1) 完全退出 WorkBuddy（托盘退出，或 taskkill /IM WorkBuddy.exe /F）\n"
        "  2) 调试模式启动：  & \"%s\" --inspect=%d\n"
        "  3) 等应用起来后再运行本脚本" % (port, exe, port)
    )


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    try:
        http_json("http://127.0.0.1:%d/json/list" % port, timeout=3)
    except Exception:
        sys.exit(launch_hint(port))

    payload, ws_url = extract_key(port)
    secret = (payload.get("atRestSecretKey") or "").strip()
    if not secret:
        sys.exit("响应中没有 atRestSecretKey，请确认 App 版本：\n%s" % json.dumps(payload, indent=2)[:500])

    # keyId 推导：AES 密钥 = sha256(atRestSecretKey 的 UTF-8 字节)，keyId = sha256(AES 密钥).hex()[:16]（双重哈希）
    key_id = hashlib.sha256(
        hashlib.sha256(secret.encode("utf-8")).digest()
    ).hexdigest()[:16]
    env_kid = auth_envelope_keyid()

    print("提取来源 : %s" % ws_url)
    print("atRestSecretKey = %s" % secret)
    print("推导 keyId     = %s" % key_id)
    if env_kid:
        match = "匹配 ✓（可正常解密）" if env_kid == key_id else "不匹配 ✗（密钥过旧，请更新脚本）"
        print("auth 信封 keyId = %s  →  %s" % (env_kid, match))
    else:
        print("（未能在本地 auth 文件找到信封 keyId，跳过比对）")
    print()
    print("复制下面这行，粘贴到 get_wb_headers_win.py 的 AT_REST_SECRET_KEY = \"\" 中：")
    print("AT_REST_SECRET_KEY = \"%s\"" % secret)


if __name__ == "__main__":
    main()
