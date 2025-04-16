#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
本模块实现以下哈希及密钥派生算法：
    - 哈希算法：SHA1, SHA256, SHA3 (SHA3-256), RIPEMD160
    - HMAC 算法：HMacSHA1, HmacSHA256
    - 密钥派生：PBKDF2（默认基于 HMAC-SHA256）

要求：
    （1）输入、输出及执行过程可见（verbose 模式下输出详细信息）。
    （2）提供统一接口 compute_operation，供第三方程序调用，并返回 (结果, 状态码)。

依赖：
    pip install pycryptodome
"""

import hashlib
import hmac
from Crypto.Hash import RIPEMD160  # 来自 PyCryptodome


# -------------------------------------
# 哈希算法实现

def sha1_hash(data: bytes, verbose: bool = False) -> bytes:
    if verbose:
        print("[SHA1] 原始数据:", data)
    hasher = hashlib.sha1()
    hasher.update(data)
    digest = hasher.digest()
    if verbose:
        print("[SHA1] 计算结果 (hex):", digest.hex())
    return digest


def sha256_hash(data: bytes, verbose: bool = False) -> bytes:
    if verbose:
        print("[SHA256] 原始数据:", data)
    hasher = hashlib.sha256()
    hasher.update(data)
    digest = hasher.digest()
    if verbose:
        print("[SHA256] 计算结果 (hex):", digest.hex())
    return digest


def sha3_hash(data: bytes, verbose: bool = False) -> bytes:
    # 这里选择 SHA3-256 作为示例实现
    if verbose:
        print("[SHA3] 原始数据:", data)
    hasher = hashlib.sha3_256()
    hasher.update(data)
    digest = hasher.digest()
    if verbose:
        print("[SHA3] 计算结果 (hex):", digest.hex())
    return digest


def ripemd160_hash(data: bytes, verbose: bool = False) -> bytes:
    if verbose:
        print("[RIPEMD160] 原始数据:", data)
    hasher = RIPEMD160.new()
    hasher.update(data)
    digest = hasher.digest()
    if verbose:
        print("[RIPEMD160] 计算结果 (hex):", digest.hex())
    return digest


# -------------------------------------
# HMAC 算法实现

def hmac_sha1(key: bytes, data: bytes, verbose: bool = False) -> bytes:
    if verbose:
        print("[HMAC-SHA1] 密钥 (hex):", key.hex())
        print("[HMAC-SHA1] 数据:", data)
    result = hmac.new(key, data, hashlib.sha1).digest()
    if verbose:
        print("[HMAC-SHA1] 计算结果 (hex):", result.hex())
    return result


def hmac_sha256(key: bytes, data: bytes, verbose: bool = False) -> bytes:
    if verbose:
        print("[HMAC-SHA256] 密钥 (hex):", key.hex())
        print("[HMAC-SHA256] 数据:", data)
    result = hmac.new(key, data, hashlib.sha256).digest()
    if verbose:
        print("[HMAC-SHA256] 计算结果 (hex):", result.hex())
    return result


# -------------------------------------
# PBKDF2 实现（基于 HMAC-SHA256）

def pbkdf2(password: bytes, salt: bytes, iterations: int = 100000, dklen: int = 32, verbose: bool = False) -> bytes:
    if verbose:
        print("[PBKDF2] 密码:", password)
        print("[PBKDF2] 盐值 (hex):", salt.hex())
        print("[PBKDF2] 迭代次数:", iterations)
        print("[PBKDF2] 衍生密钥长度:", dklen)
    dk = hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen)
    if verbose:
        print("[PBKDF2] 计算结果 (hex):", dk.hex())
    return dk


# -------------------------------------
# 统一接口，供第三方程序调用
def compute_operation(operation: str, data: bytes, key: bytes = None, verbose: bool = False, **kwargs):
    """
    参数：
        operation: 算法类型，可选值：
                   "sha1", "sha256", "sha3", "ripemd160",
                   "hmac_sha1", "hmac_sha256", "pbkdf2"（不区分大小写）
        data: 对于哈希/HMAC，此处为待处理数据；对于 PBKDF2，作为密码输入（bytes）
        key: 对 HMAC 运算必须提供密钥
        verbose: 是否显示详细执行过程
        对于 PBKDF2，额外参数：
            - salt: 盐值 bytes（必须提供）
            - iterations: 迭代次数，默认为 100000
            - dklen: 衍生密钥长度，默认为 32
    返回：
        (结果 bytes 或 None, 状态码 int)，状态码 0 表示成功，其它值表示错误。
    """
    try:
        op = operation.lower()
        if op == "sha1":
            result = sha1_hash(data, verbose)
        elif op == "sha256":
            result = sha256_hash(data, verbose)
        elif op == "sha3":
            result = sha3_hash(data, verbose)
        elif op == "ripemd160":
            result = ripemd160_hash(data, verbose)
        elif op == "hmac_sha1":
            if key is None:
                print("错误：hmac_sha1 运算必须提供 key 参数。")
                return None, 1
            result = hmac_sha1(key, data, verbose)
        elif op == "hmac_sha256":
            if key is None:
                print("错误：hmac_sha256 运算必须提供 key 参数。")
                return None, 1
            result = hmac_sha256(key, data, verbose)
        elif op == "pbkdf2":
            salt = kwargs.get("salt")
            iterations = kwargs.get("iterations", 100000)
            dklen = kwargs.get("dklen", 32)
            if salt is None:
                print("错误：PBKDF2 运算必须提供 salt 参数。")
                return None, 1
            result = pbkdf2(data, salt, iterations, dklen, verbose)
        else:
            print("不支持的运算类型：", operation)
            return None, 1
        return result, 0
    except Exception as e:
        print("执行", operation, "过程中出现异常：", e)
        return None, -1


# -------------------------------------
# 示例：直接执行脚本进行简单测试
if __name__ == "__main__":
    test_data = "Test message for crypto operations".encode("utf-8")
    print("原始数据:", test_data)

    # 测试哈希算法
    hash_ops = ["sha1", "sha256", "sha3", "ripemd160"]
    for op in hash_ops:
        print("\n==============================")
        print("运算类型：", op.upper())
        result, code = compute_operation(op, test_data, verbose=True)
        if code == 0:
            print(f"[{op.upper()}] 结果 (hex):", result.hex())
        else:
            print(f"[{op.upper()}] 运算失败，状态码：", code)

    # 测试 HMAC 运算（需要提供 key 参数）
    key = b"secret_key_12345"
    hmac_ops = ["hmac_sha1", "hmac_sha256"]
    for op in hmac_ops:
        print("\n==============================")
        print("运算类型：", op.upper())
        result, code = compute_operation(op, test_data, key=key, verbose=True)
        if code == 0:
            print(f"[{op.upper()}] 结果 (hex):", result.hex())
        else:
            print(f"[{op.upper()}] 运算失败，状态码：", code)

    # 测试 PBKDF2 运算（data作为密码输入，另外传入 salt, iterations, dklen）
    print("\n==============================")
    print("运算类型：PBKDF2")
    salt = b"salt_value"
    result, code = compute_operation("pbkdf2", test_data, verbose=True, salt=salt, iterations=100000, dklen=32)
    if code == 0:
        print("[PBKDF2] 衍生密钥 (hex):", result.hex())
    else:
        print("[PBKDF2] 运算失败，状态码：", code)
