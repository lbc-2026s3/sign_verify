import hashlib
import time

# ===================== 配置 =====================
# 替换为你自己的昵称
NICKNAME = "leoliiiiiiiii64"

# ===================== POW 核心函数 =====================
def proof_of_work(nickname: str, target_prefix: str) -> tuple[int, str, float]:
    """
    工作量证明：寻找 nonce 使得 sha256(nickname + str(nonce)) 以 target_prefix 开头
    返回: (nonce值, 哈希十六进制字符串, 耗时秒数)
    """
    nonce = 0
    start_time = time.time()

    while True:
        # 拼接消息并计算 SHA256
        message = f"{nickname}{nonce}".encode("utf-8")
        hash_hex = hashlib.sha256(message).hexdigest()

        # 检查是否满足目标前缀
        if hash_hex.startswith(target_prefix):
            elapsed = time.time() - start_time
            return nonce, hash_hex, elapsed

        nonce += 1

# ===================== 主程序 =====================
if __name__ == "__main__":
    print(f"当前昵称: {NICKNAME}")
    print("-" * 60)

    # 1. 4 个前导零 POW
    print("开始计算 4 个前导零的 POW...")
    nonce_4, hash_4, time_4 = proof_of_work(NICKNAME, "0000")
    print(f"✅ 4 个前导零 POW 完成")
    print(f"Nonce: {nonce_4}")
    print(f"哈希值: {hash_4}")
    print(f"耗时: {time_4:.4f} 秒")
    print("-" * 60)

    # 2. 5 个前导零 POW
    print("开始计算 5 个前导零的 POW...")
    nonce_5, hash_5, time_5 = proof_of_work(NICKNAME, "00000")
    print(f"✅ 5 个前导零 POW 完成")
    print(f"Nonce: {nonce_5}")
    print(f"哈希值: {hash_5}")
    print(f"耗时: {time_5:.4f} 秒")