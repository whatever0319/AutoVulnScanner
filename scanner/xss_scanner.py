# 引入 requests 套件來發送 HTTP 請求
import requests

# 引入 BeautifulSoup 套件來解析 HTML 結構
from bs4 import BeautifulSoup

# 定義一個 XSS 測試用的 payload（用來測試是否會被反射執行）
XSS_TEST_PAYLOAD = "<script>alert('XSS')</script>"

def get_forms(url):
    """
    取得指定網址中所有表單（form 標籤）
    """
    # 向該網址發送 GET 請求
    res = requests.get(url)

    # 使用 BeautifulSoup 將 HTML 內容做解析
    soup = BeautifulSoup(res.text, "html.parser")

    # 回傳所有 form 標籤（即頁面中所有表單）
    return soup.find_all("form")

def form_details(form):
    """
    解析單一表單的結構與細節（action、method、欄位名稱）
    """
    details = {}

    # 取得表單的 action 屬性（提交的目標 URL 路徑）
    action = form.attrs.get("action")

    # 取得 method 屬性（預設為 GET，如果沒寫就當作 get）
    method = form.attrs.get("method", "get").lower()

    # 建立一個空的輸入欄位列表
    inputs = []

    # 尋找表單中所有 input 標籤
    for input_tag in form.find_all("input"):
        # 取得欄位的 type，預設為 text
        input_type = input_tag.attrs.get("type", "text")

        # 取得欄位的 name（是用來提交資料的鍵）
        input_name = input_tag.attrs.get("name")

        # 將欄位資訊加入列表中
        inputs.append({"type": input_type, "name": input_name})

    # 將表單細節儲存成字典
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs

    # 回傳解析後的表單細節
    return details

def submit_form(form_details, url, payload):
    """
    對指定的表單送出測試資料，注入 XSS payload 到所有文字欄位
    """
    # 組合完整的提交目標網址
    target_url = url + form_details["action"]

    # 建立表單資料的字典
    data = {}

    # 對每個欄位根據其型態注入資料
    for input in form_details["inputs"]:
        # 如果是文字輸入欄位，注入 payload
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = payload
        else:
            # 其他類型欄位填入預設值
            data[input["name"]] = "test"

    # 根據 method 選擇 POST 或 GET 提交表單資料
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

def scan_xss(url):
    """
    掃描指定網頁的所有表單，檢查是否存在反射型 XSS 漏洞
    """
    # 取得該頁面的所有表單
    forms = get_forms(url)

    # 印出發現的表單數量
    print(f"[+] 發現 {len(forms)} 個表單")

    # 對每個表單依序檢查
    for i, form in enumerate(forms):
        # 解析表單細節（欄位、提交方式等）
        details = form_details(form)

        # 將 payload 注入後送出表單
        response = submit_form(details, url, XSS_TEST_PAYLOAD)

        # 判斷 payload 是否出現在回應中（是否被反射）
        if XSS_TEST_PAYLOAD in response.text:
            print(f"[!] 第 {i+1} 個表單可能有 XSS 漏洞")
        else:
            print(f"[-] 第 {i+1} 個表單未發現 XSS")

# 當此檔案被當作主程式執行時才會進入這個區塊
if __name__ == "__main__":
    # 要求使用者輸入要掃描的目標網址
    target = input("請輸入要掃描的網址： ")

    # 執行掃描流程
    scan_xss(target)
