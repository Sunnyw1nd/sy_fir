#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
本模块实现非对称加密与数字签名算法：
    1. RSA-1024bit：生成密钥、加解密（基于 PKCS1_OAEP 模式）
    2. RSA-SHA1：利用 RSA 密钥对数据进行签名（采用 SHA1 哈希）及验证
    3. ECC-160bit / ECDSA：使用 ECC 密钥（SECP160r1 曲线）生成密钥对，并实现 ECDSA 签名及验证

要求：
    （1）输入、输出及执行过程在 verbose 模式下均可打印显示，方便测试与调试
    （2）提供统一接口 perform_asymmetric_operation，第三方程序调用后可获得结果及状态码

依赖：
    pip install pycryptodome
    pip install ecdsa
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1
import ecdsa

#-------------------------------------
# RSA 部分实现（1024 位密钥）

def rsa_generate_keys(verbose: bool = False):
    """生成 RSA-1024bit 密钥对，返回 (私钥 PEM, 公钥 PEM)"""
    try:
        key = RSA.generate(1024)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        if verbose:
            print("[RSA] 生成的私钥 (PEM):")
            print(private_key.decode())
            print("[RSA] 生成的公钥 (PEM):")
            print(public_key.decode())
        return (private_key, public_key), 0
    except Exception as e:
        print("[RSA] 生成密钥过程中出现异常：", e)
        return None, -1

def rsa_encrypt(data: bytes, public_key_pem: bytes, verbose: bool = False):
    """使用 RSA 公钥对数据进行加密，返回密文 bytes"""
    try:
        key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(data)
        if verbose:
            print("[RSA] 加密前数据:", data)
            print("[RSA] 加密后密文 (hex):", ciphertext.hex())
        return ciphertext, 0
    except Exception as e:
        print("[RSA] 加密过程中出现异常：", e)
        return None, -1

def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes, verbose: bool = False):
    """使用 RSA 私钥对密文进行解密，返回明文 bytes"""
    try:
        key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(key)
        plaintext = cipher.decrypt(ciphertext)
        if verbose:
            print("[RSA] 解密后数据:", plaintext)
        return plaintext, 0
    except Exception as e:
        print("[RSA] 解密过程中出现异常：", e)
        return None, -1

def rsa_sign(data: bytes, private_key_pem: bytes, verbose: bool = False):
    """使用 RSA 私钥对数据进行签名（采用 SHA1 哈希），返回签名 bytes"""
    try:
        key = RSA.import_key(private_key_pem)
        h = SHA1.new(data)
        signature = pkcs1_15.new(key).sign(h)
        if verbose:
            print("[RSA-SHA1] 数据 SHA1 摘要:", h.hexdigest())
            print("[RSA-SHA1] 签名 (hex):", signature.hex())
        return signature, 0
    except Exception as e:
        print("[RSA-SHA1] 签名过程中出现异常：", e)
        return None, -1

def rsa_verify(data: bytes, signature: bytes, public_key_pem: bytes, verbose: bool = False):
    """使用 RSA 公钥验证签名（采用 SHA1 哈希），返回 (True/False, 状态码)"""
    try:
        key = RSA.import_key(public_key_pem)
        h = SHA1.new(data)
        try:
            pkcs1_15.new(key).verify(h, signature)
            if verbose:
                print("[RSA-SHA1] 签名验证成功。")
            return True, 0
        except (ValueError, TypeError) as e:
            if verbose:
                print("[RSA-SHA1] 签名验证失败：", e)
            return False, 1
    except Exception as e:
        print("[RSA-SHA1] 验证过程中出现异常：", e)
        return False, -1

#-------------------------------------
# ECC / ECDSA 部分实现（160 位曲线）
# 这里选用 ecdsa 库生成基于 SECP160r1 曲线的密钥对及 ECDSA 签名

def ecc_generate_keys(verbose: bool = False):
    """
    生成 ECC-160bit 密钥对（使用 SECP160r1 曲线）。
    返回 (签名私钥 SigningKey, 验证公钥 VerifyingKey)
    """
    try:
        # 注意：如果环境不支持 SECP160r1，可更改为其他 ecdsa 库支持的 160 位曲线
        sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP160r1)
        vk = sk.get_verifying_key()
        if verbose:
            print("[ECC] 生成的私钥 (hex):", sk.to_string().hex())
            print("[ECC] 生成的公钥 (hex):", vk.to_string().hex())
        return (sk, vk), 0
    except Exception as e:
        print("[ECC] 生成密钥过程中出现异常：", e)
        return None, -1

def ecdsa_sign(data: bytes, sk: ecdsa.SigningKey, verbose: bool = False):
    """使用 ECC 私钥对数据进行 ECDSA 签名，返回签名 bytes"""
    try:
        signature = sk.sign(data)
        if verbose:
            print("[ECDSA] 签名结果 (hex):", signature.hex())
        return signature, 0
    except Exception as e:
        print("[ECDSA] 签名过程中出现异常：", e)
        return None, -1

def ecdsa_verify(data: bytes, signature: bytes, vk: ecdsa.VerifyingKey, verbose: bool = False):
    """使用 ECC 公钥验证 ECDSA 签名，返回 (True/False, 状态码)"""
    try:
        valid = vk.verify(signature, data)
        if verbose:
            if valid:
                print("[ECDSA] 签名验证成功。")
            else:
                print("[ECDSA] 签名验证失败。")
        return valid, 0 if valid else 1
    except Exception as e:
        print("[ECDSA] 验证过程中出现异常：", e)
        return False, -1

#-------------------------------------
# 统一接口，供第三方程序调用
def perform_asymmetric_operation(operation: str,
                                   data: bytes = None,
                                   private_key: bytes = None,
                                   public_key: bytes = None,
                                   ecc_sk=None,
                                   ecc_vk=None,
                                   signature: bytes = None,
                                   verbose: bool = False):
    """
    参数：
        operation: 操作类型（不区分大小写），包括：
           "rsa_generate_keys" —— 生成 RSA-1024bit 密钥对
           "rsa_encrypt"       —— 使用 RSA 公钥加密 data
           "rsa_decrypt"       —— 使用 RSA 私钥解密 data（密文）
           "rsa_sign"          —— 使用 RSA 私钥对 data 进行签名（RSA-SHA1）
           "rsa_verify"        —— 使用 RSA 公钥验证 data 与 signature
           "ecc_generate_keys" —— 生成 ECC-160bit 密钥对
           "ecdsa_sign"        —— 使用 ECC 私钥对 data 进行 ECDSA 签名
           "ecdsa_verify"      —— 使用 ECC 公钥验证 data 与 signature（ECDSA）
        data: 待加解密、签名或验证的数据 (bytes)
        private_key: RSA 私钥 PEM 格式 (bytes)，仅 RSA 加解密与 RSA 签名使用
        public_key: RSA 公钥 PEM 格式 (bytes)，仅 RSA 加解密与 RSA 签名验证使用
        ecc_sk: ECC 签名私钥对象（ecdsa.SigningKey），仅用于 ECDSA 签名
        ecc_vk: ECC 验证公钥对象（ecdsa.VerifyingKey），仅用于 ECDSA 验证
        signature: 签名 bytes，用于验证操作
        verbose: 是否打印详细调试信息
    返回：
        (结果, 状态码) ，状态码 0 表示成功，非 0 表示出现异常或参数不足。
    """
    op = operation.lower()
    try:
        if op == "rsa_generate_keys":
            return rsa_generate_keys(verbose)
        elif op == "rsa_encrypt":
            if data is None or public_key is None:
                print("rsa_encrypt 需要 data 和 public_key 参数。")
                return None, 1
            return rsa_encrypt(data, public_key, verbose)
        elif op == "rsa_decrypt":
            if data is None or private_key is None:
                print("rsa_decrypt 需要 data 和 private_key 参数。")
                return None, 1
            return rsa_decrypt(data, private_key, verbose)
        elif op == "rsa_sign":
            if data is None or private_key is None:
                print("rsa_sign 需要 data 和 private_key 参数。")
                return None, 1
            return rsa_sign(data, private_key, verbose)
        elif op == "rsa_verify":
            if data is None or signature is None or public_key is None:
                print("rsa_verify 需要 data, signature 和 public_key 参数。")
                return None, 1
            return rsa_verify(data, signature, public_key, verbose)
        elif op == "ecc_generate_keys":
            return ecc_generate_keys(verbose)
        elif op == "ecdsa_sign":
            if data is None or ecc_sk is None:
                print("ecdsa_sign 需要 data 和 ecc_sk 参数。")
                return None, 1
            return ecdsa_sign(data, ecc_sk, verbose)
        elif op == "ecdsa_verify":
            if data is None or signature is None or ecc_vk is None:
                print("ecdsa_verify 需要 data, signature 和 ecc_vk 参数。")
                return None, 1
            return ecdsa_verify(data, signature, ecc_vk, verbose)
        else:
            print("不支持的操作类型：", operation)
            return None, 1
    except Exception as e:
        print("执行", operation, "过程中出现异常：", e)
        return None, -1

#-------------------------------------
# 示例测试代码：直接运行脚本时进行简单测试
if __name__ == "__main__":
    test_data = "Test message for asymmetric crypto".encode("utf-8")
    print("测试数据:", test_data)
    verbose_flag = True

    print("\n========== RSA 操作测试 ==========")
    # 生成 RSA 密钥
    (rsa_keys, status) = perform_asymmetric_operation("rsa_generate_keys", verbose=verbose_flag)
    if status == 0:
        rsa_private, rsa_public = rsa_keys
        # RSA 加密 / 解密测试
        ciphertext, status = perform_asymmetric_operation("rsa_encrypt",
                                                            data=test_data,
                                                            public_key=rsa_public,
                                                            verbose=verbose_flag)
        if status == 0:
            plaintext, status = perform_asymmetric_operation("rsa_decrypt",
                                                               data=ciphertext,
                                                               private_key=rsa_private,
                                                               verbose=verbose_flag)
            if status == 0:
                print("[RSA] 解密结果:", plaintext.decode("utf-8"))
        # RSA 签名 / 验证测试
        signature, status = perform_asymmetric_operation("rsa_sign",
                                                         data=test_data,
                                                         private_key=rsa_private,
                                                         verbose=verbose_flag)
        if status == 0:
            valid, status = perform_asymmetric_operation("rsa_verify",
                                                         data=test_data,
                                                         signature=signature,
                                                         public_key=rsa_public,
                                                         verbose=verbose_flag)
            print("[RSA-SHA1] 签名验证结果:", "通过" if valid else "失败")
    else:
        print("[RSA] 密钥生成失败。")

    print("\n========== ECC / ECDSA 操作测试 ==========")
    # 生成 ECC 密钥对
    (ecc_keys, status) = perform_asymmetric_operation("ecc_generate_keys", verbose=verbose_flag)
    if status == 0:
        ecc_sk, ecc_vk = ecc_keys
        # ECDSA 签名 / 验证测试
        signature, status = perform_asymmetric_operation("ecdsa_sign",
                                                         data=test_data,
                                                         ecc_sk=ecc_sk,
                                                         verbose=verbose_flag)
        if status == 0:
            valid, status = perform_asymmetric_operation("ecdsa_verify",
                                                         data=test_data,
                                                         signature=signature,
                                                         ecc_vk=ecc_vk,
                                                         verbose=verbose_flag)
            print("[ECDSA] 签名验证结果:", "通过" if valid else "失败")
    else:
        print("[ECC] 密钥生成失败。")
