from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import to_checksum_address
import datetime
import secrets
from typing import Optional, List, Tuple


def build_eip4361_message(
    domain: str,
    address: str,
    uri: str,
    version: str = "1",
    chain_id: int = 1,
    nonce: Optional[str] = None,
    issued_at: Optional[str] = None,
    statement: Optional[str] = None,
    expiration_time: Optional[str] = None,
    not_before: Optional[str] = None,
    request_id: Optional[str] = None,
    resources: Optional[List[str]] = None
) -> str:
    """
    构造符合 EIP-4361 (Sign-In with Ethereum) 规范的结构化签名消息
    完整格式参考: https://eips.ethereum.org/EIPS/eip-4361
    """
    # 生成默认随机 nonce
    if nonce is None:
        nonce = secrets.token_hex(8)
    
    # 生成默认签发时间 (ISO 8601 UTC 格式)
    if issued_at is None:
        issued_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # 统一转为 EIP-55 校验和地址
    address = to_checksum_address(address)
    
    # 按规范拼接消息主体
    message = f"{domain} wants you to sign in with your Ethereum account:\n{address}\n\n"
    
    if statement:
        message += f"{statement}\n\n"
    
    message += f"URI: {uri}\n"
    message += f"Version: {version}\n"
    message += f"Chain ID: {chain_id}\n"
    message += f"Nonce: {nonce}\n"
    message += f"Issued At: {issued_at}"
    
    if expiration_time:
        message += f"\nExpiration Time: {expiration_time}"
    if not_before:
        message += f"\nNot Before: {not_before}"
    if request_id:
        message += f"\nRequest ID: {request_id}"
    if resources:
        message += "\nResources:"
        for res in resources:
            message += f"\n- {res}"
    
    return message


def sign_eip4361_message(
    private_key: str,
    domain: str,
    uri: str,
    version: str = "1",
    chain_id: int = 1,
    statement: Optional[str] = None,
    expiration_time: Optional[str] = None,
    not_before: Optional[str] = None,
    request_id: Optional[str] = None,
    resources: Optional[List[str]] = None
) -> Tuple[str, int, str, str, str, str]:
    """
    对 EIP-4361 结构化消息执行 EIP-191 个人签名
    返回: (签名人地址, v, r, s, 原始消息字符串, 消息哈希)
    """
    # 从私钥派生账户
    account = Account.from_key(private_key)
    signer_address = account.address
    
    # 构造标准 EIP-4361 消息
    message = build_eip4361_message(
        domain=domain,
        address=signer_address,
        uri=uri,
        version=version,
        chain_id=chain_id,
        statement=statement,
        expiration_time=expiration_time,
        not_before=not_before,
        request_id=request_id,
        resources=resources
    )
    
    # 编码为 EIP-191 个人签名消息格式（对应钱包 personal_sign 方法）
    encoded_message = encode_defunct(text=message)
    
    # 执行签名
    signed_msg = Account.sign_message(encoded_message, private_key)
    
    # 提取签名参数 v/r/s
    v = signed_msg.v
    r = hex(signed_msg.r)
    s = hex(signed_msg.s)
    
    # 消息哈希（keccak256 编码后的消息）
    message_hash = signed_msg.message_hash.hex()
    
    return signer_address, v, r, s, message, message_hash


def recover_eip4361_signer(
    message: str,
    v: int,
    r: str,
    s: str
) -> str:
    """
    根据原始 EIP-4361 消息 + vrs 签名参数，恢复签名人地址
    输入:
        message: 原始结构化消息字符串
        v: 签名恢复位 (27/28)
        r: 签名 r 值（十六进制字符串）
        s: 签名 s 值（十六进制字符串）
    返回: 签名人校验和地址
    """
    # 同样编码为 EIP-191 格式
    encoded_message = encode_defunct(text=message)
    
    # r/s 从十六进制转为整数
    r_int = int(r, 16)
    s_int = int(s, 16)
    
    # 恢复地址
    signer_address = Account.recover_message(
        encoded_message,
        vrs=(v, r_int, s_int)
    )
    
    return to_checksum_address(signer_address)


if __name__ == "__main__":
    # ========== 测试演示 ==========
    # 生成随机测试私钥（生产环境请安全存储私钥，禁止硬编码）
    test_private_key = "0x" + secrets.token_hex(32)
    print(f"测试私钥: {test_private_key}")
    print("-" * 60)
    
    # 签名参数配置
    domain = "demo.dapp.com"
    uri = "https://demo.dapp.com/login"
    chain_id = 1  # 以太坊主网
    statement = "I accept the Demo DApp Terms of Service: https://demo.dapp.com/tos"
    resources = [
        "ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/",
        "https://demo.dapp.com/verifiable-credential"
    ]
    
    # 执行签名
    signer_addr, v, r, s, message, msg_hash = sign_eip4361_message(
        private_key=test_private_key,
        domain=domain,
        uri=uri,
        chain_id=chain_id,
        statement=statement,
        resources=resources
    )
    
    # 输出签名结果
    print("=== 签名结果 ===")
    print(f"签名人地址: {signer_addr}")
    print(f"v: {v}")
    print(f"r: {r}")
    print(f"s: {s}")
    print(f"消息哈希: {msg_hash}")
    print("\n=== 原始 EIP-4361 结构化消息 ===")
    print(message)
    print("-" * 60)
    
    # 测试地址恢复
    recovered_addr = recover_eip4361_signer(message, v, r, s)
    print(f"\n恢复出的签名人地址: {recovered_addr}")
    print(f"地址一致性验证: {'通过 ✅' if recovered_addr == signer_addr else '失败 ❌'}")