import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# 定義要掃描的常見 port（可擴充）
COMMON_PORTS = [22, 80, 443]

# 設定 socket 連線 timeout（秒）
socket.setdefaulttimeout(1)

def is_host_alive(ip):
    """
    檢查該 IP 是否有回應（用 TCP 連接常見 port 簡易判活）
    """
    for port in COMMON_PORTS:
        try:
            # 建立 socket，連線到 IP + port
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                result = s.connect_ex((str(ip), port))
                if result == 0:
                    return True  # 有 port 開啟表示主機活著
        except:
            continue
    return False

def scan_ports(ip):
    """
    掃描該 IP 的常見 port 並抓 banner（若有）
    """
    open_ports = []
    for port in COMMON_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                result = s.connect_ex((str(ip), port))
                if result == 0:
                    try:
                        # 嘗試讀取 banner
                        s.sendall(b"HEAD / HTTP/1.1\r\nHost: "+bytes(str(ip), 'utf-8')+b"\r\n\r\n")
                        banner = s.recv(1024).decode(errors="ignore")
                    except:
                        banner = ""
                    open_ports.append({"port": port, "banner": banner.strip()})
        except:
            continue
    return open_ports

def scan_subnet(subnet_cidr):
    """
    掃描整個子網段，找出活著的主機與其開放服務
    """
    # 建立一個 IPv4 網段對象
    network = ipaddress.IPv4Network(subnet_cidr)

    # 建立一個結果列表
    results = []

    print(f"[+] 開始掃描子網段：{subnet_cidr} 共 {network.num_addresses} 個 IP")

    # 使用 ThreadPoolExecutor 加快多 IP 掃描速度
    with ThreadPoolExecutor(max_workers=100) as executor:
        # 提交所有 IP 的 is_host_alive 檢查任務
        future_to_ip = {executor.submit(is_host_alive, ip): ip for ip in network.hosts()}

        for future in future_to_ip:
            ip = future_to_ip[future]
            try:
                if future.result():
                    print(f"[+] 主機存活：{ip}，正在掃描服務...")
                    ports = scan_ports(ip)
                    results.append({"ip": str(ip), "open_ports": ports})
                else:
                    print(f"[-] {ip} 無回應")
            except Exception as e:
                print(f"[!] 掃描 {ip} 時發生錯誤：{e}")
    
    return results

# 直接執行此檔案時，進行測試
if __name__ == "__main__":
    subnet = input("請輸入要掃描的子網段（CIDR，例如 192.168.1.0/24）： ")
    result = scan_subnet(subnet)

    print("\n[+] 掃描完成，結果如下：")
    for entry in result:
        print(f"主機 {entry['ip']}：")
        for port_info in entry["open_ports"]:
            print(f"  - Port {port_info['port']}: {port_info['banner'][:80]}")
