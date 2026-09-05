from pow import proof_of_work

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# ===================== 配置 =====================
NICKNAME = "leoliiiiiiiii64"  # 替换为你的昵称
POW_TARGET = "0000"         # POW 目标：4 个前导零

# ===================== 工具函数 =====================

def generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """生成 2048 位 RSA 公私钥对（标准安全参数）"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # 行业标准公钥指数
        key_size=2048,          # 密钥长度
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """使用私钥签名消息（PSS 填充 + SHA256 哈希，业界安全标准）"""
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """使用公钥验证签名，返回 True/False"""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# ===================== 主流程 =====================
if __name__ == "__main__":
    # 1. 生成 RSA 公私钥对
    print("=" * 60)
    print("1. 生成 RSA 公私钥对")
    print("=" * 60)
    private_key, public_key = generate_rsa_keypair()

    # 输出 PEM 格式密钥
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    print("私钥（PEM 格式）：")
    print(private_pem.decode("utf-8"))

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("公钥（PEM 格式）：")
    print(public_pem.decode("utf-8"))

    # 2. 计算符合 POW 要求的消息
    print("=" * 60)
    print("2. 计算符合 POW 要求的消息")
    print("=" * 60)
    nonce, pow_hash, elapsed = proof_of_work(NICKNAME, POW_TARGET)
    # proof_of_work 第三个返回值是耗时（秒），签名消息需自行构造
    message_bytes = f"{NICKNAME}{nonce}".encode("utf-8")
    print(f"昵称 + Nonce: {NICKNAME}{nonce}")
    print(f"SHA256 哈希: {pow_hash}")
    print(f"满足 {len(POW_TARGET)} 个前导零要求（耗时 {elapsed:.4f} 秒）\n")

    # 3. 私钥签名
    print("=" * 60)
    print("3. 使用私钥对消息签名")
    print("=" * 60)
    signature = sign_message(private_key, message_bytes)
    print(f"签名结果（十六进制）：\n{signature.hex()}\n")

    # 4. 公钥验签
    print("=" * 60)
    print("4. 使用公钥验证签名")
    print("=" * 60)
    is_valid = verify_signature(public_key, message_bytes, signature)
    if is_valid:
        print("✅ 验证通过：消息未篡改，且由对应私钥签发")
    else:
        print("❌ 验证失败：签名无效")

    # 5. 测试：篡改消息后验签
    print("\n" + "=" * 60)
    print("5. 测试：篡改消息后验证签名")
    print("=" * 60)
    tampered_msg = f"{NICKNAME}{nonce}_tampered".encode("utf-8")
    is_valid_tampered = verify_signature(public_key, tampered_msg, signature)
    if is_valid_tampered:
        print("❌ 异常：篡改消息后仍验证通过")
    else:
        print("✅ 符合预期：消息篡改后签名验证失败")