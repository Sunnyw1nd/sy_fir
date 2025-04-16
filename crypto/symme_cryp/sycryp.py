#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
本模块实现 AES、SM4 与 RC6 对称加密算法：
    - 每个算法类都包含 encrypt / decrypt 方法（支持分组加解密及 PKCS7 填充）
    - 内部可选开启 verbose（详细调试输出）
    - 统一接口 encrypt_data / decrypt_data 提供给第三方调用，返回 (结果, 状态码)

依赖：
    pip install pycryptodome
    pip install gmssl
"""

from Crypto.Cipher import AES
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT


# -------------------------------------
# 工具函数：PKCS7 填充与去填充（适用于 16 字节分组）
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


# -------------------------------------
# AES 加解密实现（使用 PyCryptodome）
class AESCipher:
    def __init__(self, key: bytes, verbose: bool = False):
        self.key = key
        self.block_size = AES.block_size  # 通常为16字节
        self.verbose = verbose
        # 这里为了方便测试，固定使用一个初始化向量 iv（实际环境中建议随机生成 iv 并传输之）
        self.iv = b'0000000000000000'
        if self.verbose:
            print("[AES] 初始化：密钥 =", key.hex())

    def encrypt(self, data: bytes) -> bytes:
        if self.verbose:
            print("[AES] 原始明文：", data)
        padded_data = pkcs7_pad(data, self.block_size)
        if self.verbose:
            print("[AES] PKCS7 填充后：", padded_data)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        ciphertext = cipher.encrypt(padded_data)
        if self.verbose:
            print("[AES] 密文：", ciphertext.hex())
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self.verbose:
            print("[AES] 输入密文：", ciphertext.hex())
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_data = cipher.decrypt(ciphertext)
        if self.verbose:
            print("[AES] 解密后带填充数据：", padded_data)
        data = pkcs7_unpad(padded_data)
        if self.verbose:
            print("[AES] 去除填充后明文：", data)
        return data


# -------------------------------------
# SM4 加解密实现（使用 gmssl）
class SM4Cipher:
    def __init__(self, key: bytes, verbose: bool = False):
        if len(key) != 16:
            raise ValueError("SM4 密钥长度必须为16字节")
        self.key = key
        self.block_size = 16
        self.verbose = verbose
        self.sm4_cryptor = CryptSM4()
        if self.verbose:
            print("[SM4] 初始化：密钥 =", key.hex())

    def encrypt(self, data: bytes) -> bytes:
        if self.verbose:
            print("[SM4] 原始明文：", data)
        padded_data = pkcs7_pad(data, self.block_size)
        if self.verbose:
            print("[SM4] PKCS7 填充后：", padded_data)
        self.sm4_cryptor.set_key(self.key, SM4_ENCRYPT)
        ciphertext = self.sm4_cryptor.crypt_ecb(padded_data)
        if self.verbose:
            print("[SM4] 密文：", ciphertext.hex())
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self.verbose:
            print("[SM4] 输入密文：", ciphertext.hex())
        self.sm4_cryptor.set_key(self.key, SM4_DECRYPT)
        padded_data = self.sm4_cryptor.crypt_ecb(ciphertext)
        if self.verbose:
            print("[SM4] 解密后带填充数据：", padded_data)
        data = pkcs7_unpad(padded_data)
        if self.verbose:
            print("[SM4] 去除填充后明文：", data)
        return data


# -------------------------------------
# RC6 加解密实现
# 内部实现参考 RC6 算法说明，默认参数：w=32, r=20, 块大小=16 字节
def _rotl(x, n):
    n = n % 32
    return ((x << n) & 0xffffffff) | (x >> (32 - n))


def _rotr(x, n):
    n = n % 32
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


class RC6Cipher:
    def __init__(self, key: bytes, rounds: int = 20, verbose: bool = False):
        self.rounds = rounds
        self.word_size = 32
        self.block_size = 16  # 128位数据块（4个32位字）
        self.modulo = 2 ** 32
        self.verbose = verbose
        self.key = key
        if self.verbose:
            print("[RC6] 初始化：密钥 =", key.hex())
        self._key_schedule()

    def _key_schedule(self):
        # 将 key 按 4 字节分块（小端序）
        c = (len(self.key) + 3) // 4
        L = [0] * c
        for i in range(len(self.key)):
            L[i // 4] += self.key[i] << (8 * (i % 4))
        if self.verbose:
            print("[RC6] L 数组（密钥分块）:", L)
        # 初始化 S 数组：大小 t = 2 * rounds + 4
        t = 2 * self.rounds + 4
        P32 = 0xB7E15163
        Q32 = 0x9E3779B9
        self.S = [0] * t
        self.S[0] = P32
        for i in range(1, t):
            self.S[i] = (self.S[i - 1] + Q32) % self.modulo
        if self.verbose:
            print("[RC6] 初始化 S 数组:", self.S)
        # 将 S 和 L 混合（共 3 * max(t, c) 轮）
        A = 0
        B = 0
        i = 0
        j = 0
        iterations = 3 * max(t, c)
        for k in range(iterations):
            A = self.S[i] = _rotl((self.S[i] + A + B) % self.modulo, 3)
            B = L[j] = _rotl((L[j] + A + B) % self.modulo, (A + B) % 32)
            i = (i + 1) % t
            j = (j + 1) % c
        if self.verbose:
            print("[RC6] 混合后 S 数组:", self.S)

    def encrypt_block(self, plaintext: bytes) -> bytes:
        if len(plaintext) != self.block_size:
            raise ValueError("RC6: 明文必须为16字节")
        # 拆分 16 字节明文为 4 个 32 位字（小端序）
        A = int.from_bytes(plaintext[0:4], byteorder='little')
        B = int.from_bytes(plaintext[4:8], byteorder='little')
        C = int.from_bytes(plaintext[8:12], byteorder='little')
        D = int.from_bytes(plaintext[12:16], byteorder='little')
        if self.verbose:
            print(f"[RC6] 初始块: A={A:08x}, B={B:08x}, C={C:08x}, D={D:08x}")

        B = (B + self.S[0]) % self.modulo
        D = (D + self.S[1]) % self.modulo
        if self.verbose:
            print(f"[RC6] 加初始轮密钥后: B={B:08x}, D={D:08x}")
        # 轮变换
        for i in range(1, self.rounds + 1):
            t = _rotl((B * ((2 * B + 1) % self.modulo)) % self.modulo, 5)
            u = _rotl((D * ((2 * D + 1) % self.modulo)) % self.modulo, 5)
            if self.verbose:
                print(f"[RC6] 轮 {i}: t={t:08x}, u={u:08x}")
            A = (_rotl((A ^ t) % self.modulo, u % 32) + self.S[2 * i]) % self.modulo
            C = (_rotl((C ^ u) % self.modulo, t % 32) + self.S[2 * i + 1]) % self.modulo
            if self.verbose:
                print(f"[RC6] 轮 {i} 后: A={A:08x}, C={C:08x}")
            # 循环旋转寄存器: (A,B,C,D) = (B, C, D, A)
            A, B, C, D = B, C, D, A
            if self.verbose:
                print(f"[RC6] 轮 {i} 旋转后: A={A:08x}, B={B:08x}, C={C:08x}, D={D:08x}")
        A = (A + self.S[2 * self.rounds + 2]) % self.modulo
        C = (C + self.S[2 * self.rounds + 3]) % self.modulo
        if self.verbose:
            print(f"[RC6] 最终加轮密钥后: A={A:08x}, C={C:08x}")
        # 合并4个 32 位字
        out = (A.to_bytes(4, byteorder='little') +
               B.to_bytes(4, byteorder='little') +
               C.to_bytes(4, byteorder='little') +
               D.to_bytes(4, byteorder='little'))
        if self.verbose:
            print("[RC6] 加密后块密文:", out.hex())
        return out

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != self.block_size:
            raise ValueError("RC6: 密文必须为16字节")
        # 拆分密文为 4 个 32 位字
        A = int.from_bytes(ciphertext[0:4], byteorder='little')
        B = int.from_bytes(ciphertext[4:8], byteorder='little')
        C = int.from_bytes(ciphertext[8:12], byteorder='little')
        D = int.from_bytes(ciphertext[12:16], byteorder='little')
        if self.verbose:
            print(f"[RC6] 解密 初始块: A={A:08x}, B={B:08x}, C={C:08x}, D={D:08x}")
        C = (C - self.S[2 * self.rounds + 3]) % self.modulo
        A = (A - self.S[2 * self.rounds + 2]) % self.modulo
        if self.verbose:
            print(f"[RC6] 减最终轮密钥后: A={A:08x}, C={C:08x}")
        # 逆轮变换
        for i in range(self.rounds, 0, -1):
            # 逆旋转寄存器: (A,B,C,D) = (D, A, B, C)
            A, B, C, D = D, A, B, C
            u = _rotl((D * ((2 * D + 1) % self.modulo)) % self.modulo, 5)
            t = _rotl((B * ((2 * B + 1) % self.modulo)) % self.modulo, 5)
            if self.verbose:
                print(f"[RC6] 轮 {i}（逆）: t={t:08x}, u={u:08x}")
            C = _rotr((C - self.S[2 * i + 1]) % self.modulo, t % 32) ^ u
            A = _rotr((A - self.S[2 * i]) % self.modulo, u % 32) ^ t
            if self.verbose:
                print(f"[RC6] 轮 {i}（逆） 后: A={A:08x}, C={C:08x}")
        D = (D - self.S[1]) % self.modulo
        B = (B - self.S[0]) % self.modulo
        if self.verbose:
            print(f"[RC6] 最终减初始轮密钥后: B={B:08x}, D={D:08x}")
        out = (A.to_bytes(4, byteorder='little') +
               B.to_bytes(4, byteorder='little') +
               C.to_bytes(4, byteorder='little') +
               D.to_bytes(4, byteorder='little'))
        if self.verbose:
            print("[RC6] 解密后块明文:", out.hex())
        return out

    # 支持任意长度数据的加解密（使用 PKCS7 填充，ECB 模式演示，不建议用于生产环境）
    def encrypt(self, data: bytes) -> bytes:
        padded_data = pkcs7_pad(data, self.block_size)
        if self.verbose:
            print("[RC6] 整体数据 PKCS7 填充后：", padded_data.hex())
        ciphertext = b""
        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i + self.block_size]
            ciphertext += self.encrypt_block(block)
        if self.verbose:
            print("[RC6] 最终密文：", ciphertext.hex())
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        plaintext = b""
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            plaintext += self.decrypt_block(block)
        plaintext = pkcs7_unpad(plaintext)
        if self.verbose:
            print("[RC6] 解密后去填充明文：", plaintext)
        return plaintext


# -------------------------------------
# 统一接口，供第三方程序调用
def encrypt_data(algorithm: str, key: bytes, data: bytes, verbose: bool = False):
    """
    参数：
        algorithm: "aes", "sm4" 或 "rc6"（不区分大小写）
        key: 密钥 bytes
        data: 明文 bytes
        verbose: 是否打印详细调试信息
    返回：
        (密文 bytes 或 None, 状态码 int)，状态码 0 表示成功，否则为错误码
    """
    try:
        if algorithm.lower() == "aes":
            cipher = AESCipher(key, verbose=verbose)
            ciphertext = cipher.encrypt(data)
        elif algorithm.lower() == "sm4":
            cipher = SM4Cipher(key, verbose=verbose)
            ciphertext = cipher.encrypt(data)
        elif algorithm.lower() == "rc6":
            cipher = RC6Cipher(key, verbose=verbose)
            ciphertext = cipher.encrypt(data)
        else:
            print("不支持的算法：", algorithm)
            return None, 1
        return ciphertext, 0
    except Exception as e:
        print("加密过程中出现异常：", e)
        return None, -1


def decrypt_data(algorithm: str, key: bytes, data: bytes, verbose: bool = False):
    """
    参数：
        algorithm: "aes", "sm4" 或 "rc6"（不区分大小写）
        key: 密钥 bytes
        data: 密文 bytes
        verbose: 是否打印详细调试信息
    返回：
        (明文 bytes 或 None, 状态码 int)，状态码 0 表示成功，否则为错误码
    """
    try:
        if algorithm.lower() == "aes":
            cipher = AESCipher(key, verbose=verbose)
            plaintext = cipher.decrypt(data)
        elif algorithm.lower() == "sm4":
            cipher = SM4Cipher(key, verbose=verbose)
            plaintext = cipher.decrypt(data)
        elif algorithm.lower() == "rc6":
            cipher = RC6Cipher(key, verbose=verbose)
            plaintext = cipher.decrypt(data)
        else:
            print("不支持的算法：", algorithm)
            return None, 1
        return plaintext, 0
    except Exception as e:
        print("解密过程中出现异常：", e)
        return None, -1


# -------------------------------------

if __name__ == "__main__":
    # 示例输入
    test_text = "Hello, this is a test message for encryption!"
    data = test_text.encode("utf-8")
    print("原始文本:", test_text)

    # 采用16字节密钥示例（实际请使用更随机的密钥）
    key_aes = b'0123456789abcdef'  # 对于 AES 要求16/24/32字节；SM4 固定 16 字节；这里 RC6 也采用 16 字节
    algorithms = ["aes", "sm4", "rc6"]

    for algo in algorithms:
        print("\n==============================")
        print("算法：", algo.upper())
        ciphertext, code = encrypt_data(algo, key_aes, data, verbose=True)
        if code == 0:
            print(f"[{algo.upper()}] 加密成功，密文(hex)：", ciphertext.hex())
            plaintext, code = decrypt_data(algo, key_aes, ciphertext, verbose=True)
            if code == 0:
                print(f"[{algo.upper()}] 解密成功，明文：", plaintext.decode("utf-8"))
            else:
                print(f"[{algo.upper()}] 解密失败，状态码：", code)
        else:
            print(f"[{algo.upper()}] 加密失败，状态码：", code)
