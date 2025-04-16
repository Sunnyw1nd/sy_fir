#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
本模块实现 Base64 与 UTF-8 编码/解码操作：
    1. Base64 编码/解码：使用 Python 内置的 base64 模块实现 Base64 编码与解码。
    2. UTF-8 编码/解码：利用 Python 字符串的 encode 与 bytes 的 decode 方法实现 UTF-8 编码与解码。

要求：
    （1）输入、输出以及执行过程（在 verbose 模式下）均可见、可测。
    （2）提供统一接口 perform_encoding_operation，供第三方程序调用后返回 (结果, 状态码)。
"""

import base64

#-------------------------------------
# Base64 操作

def base64_encode(data: bytes, verbose: bool = False) -> bytes:
    if verbose:
        print("[Base64 Encode] 原始数据 (bytes):", data)
    encoded = base64.b64encode(data)
    if verbose:
        print("[Base64 Encode] 编码后数据 (bytes):", encoded)
        print("[Base64 Encode] 编码后数据 (str):", encoded.decode('ascii'))
    return encoded

def base64_decode(data: bytes, verbose: bool = False) -> bytes:
    if verbose:
        print("[Base64 Decode] 原始数据 (bytes):", data)
    try:
        decoded = base64.b64decode(data)
    except Exception as e:
        if verbose:
            print("[Base64 Decode] 解码过程异常：", e)
        raise e
    if verbose:
        print("[Base64 Decode] 解码后数据 (bytes):", decoded)
    return decoded

#-------------------------------------
# UTF-8 编码与解码

def utf8_encode(data: str, verbose: bool = False) -> bytes:
    if verbose:
        print("[UTF-8 Encode] 原始字符串:", data)
    encoded = data.encode('utf-8')
    if verbose:
        print("[UTF-8 Encode] 编码后数据 (bytes):", encoded)
    return encoded

def utf8_decode(data: bytes, verbose: bool = False) -> str:
    if verbose:
        print("[UTF-8 Decode] 原始数据 (bytes):", data)
    decoded = data.decode('utf-8')
    if verbose:
        print("[UTF-8 Decode] 解码后字符串:", decoded)
    return decoded

#-------------------------------------
# 统一接口函数，供第三方程序调用

def perform_encoding_operation(operation: str, data, verbose: bool = False):
    """
    参数：
        operation: 操作类型（不区分大小写），支持以下选项：
                   "base64_encode" —— Base64 编码，输入：bytes，输出：bytes
                   "base64_decode" —— Base64 解码，输入：bytes，输出：bytes
                   "utf8_encode"   —— UTF-8 编码，输入：str，输出：bytes
                   "utf8_decode"   —— UTF-8 解码，输入：bytes，输出：str
        data: 待处理数据，其数据类型需与选定的操作匹配。
        verbose: 是否打印详细调试信息。
    返回：
        (结果, 状态码) —— 状态码 0 表示成功，非 0 表示出现错误或参数不匹配。
    """
    op = operation.lower()
    try:
        if op == "base64_encode":
            if not isinstance(data, bytes):
                print("[Base64 Encode] 错误：输入数据必须为 bytes 类型。")
                return None, 1
            result = base64_encode(data, verbose)
        elif op == "base64_decode":
            if not isinstance(data, bytes):
                print("[Base64 Decode] 错误：输入数据必须为 bytes 类型。")
                return None, 1
            result = base64_decode(data, verbose)
        elif op == "utf8_encode":
            if not isinstance(data, str):
                print("[UTF-8 Encode] 错误：输入数据必须为 str 类型。")
                return None, 1
            result = utf8_encode(data, verbose)
        elif op == "utf8_decode":
            if not isinstance(data, bytes):
                print("[UTF-8 Decode] 错误：输入数据必须为 bytes 类型。")
                return None, 1
            result = utf8_decode(data, verbose)
        else:
            print("不支持的操作类型：", operation)
            return None, 1
        return result, 0
    except Exception as e:
        print("执行", operation, "过程中出现异常：", e)
        return None, -1

#-------------------------------------
# 示例测试代码：直接运行脚本时进行简单测试

if __name__ == "__main__":
    verbose_mode = True

    # 示例 1: UTF-8 编码（字符串 -> bytes）
    test_string = "Hello, this is a test for UTF-8 encoding!"
    print("原始字符串:", test_string)
    utf8_encoded, status = perform_encoding_operation("utf8_encode", test_string, verbose=verbose_mode)
    if status == 0:
        print("[Main] UTF-8 编码结果 (bytes):", utf8_encoded)
    else:
        print("[Main] UTF-8 编码失败，状态码:", status)

    # 示例 2: UTF-8 解码（bytes -> 字符串）
    utf8_decoded, status = perform_encoding_operation("utf8_decode", utf8_encoded, verbose=verbose_mode)
    if status == 0:
        print("[Main] UTF-8 解码结果 (str):", utf8_decoded)
    else:
        print("[Main] UTF-8 解码失败，状态码:", status)

    # 示例 3: Base64 编码（对 UTF-8 编码后的 bytes 进行 Base64 编码）
    base64_encoded, status = perform_encoding_operation("base64_encode", utf8_encoded, verbose=verbose_mode)
    if status == 0:
        print("[Main] Base64 编码结果 (bytes):", base64_encoded)
        print("[Main] Base64 编码结果 (str):", base64_encoded.decode('ascii'))
    else:
        print("[Main] Base64 编码失败，状态码:", status)

    # 示例 4: Base64 解码（将上面的 Base64 字节数据解码还原为原始 bytes）
    base64_decoded, status = perform_encoding_operation("base64_decode", base64_encoded, verbose=verbose_mode)
    if status == 0:
        print("[Main] Base64 解码结果 (bytes):", base64_decoded)
    else:
        print("[Main] Base64 解码失败，状态码:", status)
