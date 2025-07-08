# AutoVulnScanner

AutoVulnScanner 是一套用 Python 製作的自動化資安掃描工具集，包含三種常見弱點掃描模組：

- 反射型 XSS 漏洞掃描器
- 子網段主機與服務掃描器（含 banner 抓取）
- SSH 弱密碼爆破測試工具（教育用途）

本工具設計目的是做為資安學習與實作展示的 side project，強調實作力、自動化能力與風險意識。


---

## 安裝說明

### 1. 下載或 Clone 專案

git clone https://github.com/whatever0319/AutoVulnScanner.git
cd AutoVulnScanner

pip install -r requirements.txt

python main.py

---

##各模組介紹

### XSS 掃描器
掃描目標網址中的所有表單

自動注入 <script>alert('XSS')</script>

判斷是否為反射型 XSS

### 子網段掃描器
掃描指定 CIDR（如 192.168.1.0/24）

檢查主機是否存活（TCP 連線）

掃描 22/80/443 等常見 port

抓取 banner 作為基本服務指紋

### SSH 爆破工具
嘗試用預設帳號與密碼組合登入 SSH

可擴充為讀取帳密字典檔

顯示成功登入帳密

## 掃描報告格式
掃描結果會自動儲存在 reports/ 資料夾中，包括：

subnet_scan.json, subnet_scan.csv

ssh_bruteforce.json, ssh_bruteforce.csv





