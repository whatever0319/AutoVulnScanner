import json
import csv
from scanner import xss_scanner, subnet_scanner, ssh_bruteforce

def save_json(filename, data):
    """
    儲存掃描結果為 JSON 檔
    """
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"[+] 已儲存為 JSON：{filename}")

def save_csv(filename, data, fields):
    """
    儲存掃描結果為 CSV 檔
    """
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    print(f"[+] 已儲存為 CSV：{filename}")

def run_xss_scanner():
    """
    執行 XSS 掃描器
    """
    url = input("請輸入目標網址： ")
    print(f"[+] 開始對 {url} 執行 XSS 掃描...\n")
    xss_scanner.scan_xss(url)

def run_subnet_scanner():
    """
    執行子網段服務掃描器
    """
    cidr = input("請輸入子網段（例如 192.168.1.0/24）： ")
    results = subnet_scanner.scan_subnet(cidr)

    # 儲存為報告
    save_json("reports/subnet_scan.json", results)

    # 扁平化資料方便存成 csv
    flat_results = []
    for entry in results:
        ip = entry["ip"]
        for port in entry["open_ports"]:
            flat_results.append({
                "ip": ip,
                "port": port["port"],
                "banner": port["banner"]
            })

    save_csv("reports/subnet_scan.csv", flat_results, ["ip", "port", "banner"])

def run_ssh_bruteforce():
    """
    執行 SSH 弱密碼掃描器
    """
    ip = input("請輸入目標 SSH IP： ")

    # 可改成外部字典檔載入
    usernames = ["root", "admin", "user"]
    passwords = ["123456", "admin", "password", "toor"]

    results = ssh_bruteforce.ssh_brute_force(ip, usernames, passwords)

    # 儲存為報告
    save_json("reports/ssh_bruteforce.json", results)
    save_csv("reports/ssh_bruteforce.csv", results, ["ip", "username", "password", "success"])

def main():
    """
    主程式選單
    """
    print("\n=== AutoVulnScanner 資安工具集 ===")
    print("1. XSS 掃描器")
    print("2. 子網段服務掃描器")
    print("3. SSH 弱密碼爆破")
    print("0. 離開")
    choice = input("請選擇功能 (0-3)： ")

    if choice == "1":
        run_xss_scanner()
    elif choice == "2":
        run_subnet_scanner()
    elif choice == "3":
        run_ssh_bruteforce()
    elif choice == "0":
        print("離開程式")
    else:
        print("無效選項")

if __name__ == "__main__":
    main()
