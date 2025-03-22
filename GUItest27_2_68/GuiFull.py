import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import requests
import re

# ตั้งค่าธีม GUI
BG_COLOR = "#000000"
TEXT_COLOR = "#FFFFFF"

# ลิสต์ของประเภท XSS ที่จะตรวจสอบ
scan_types = [
    ("Stored Reflected XSS", "ตรวจสอบการสะท้อนของโค้ดใน URL"),
    ("Stored Event-handler XSS", "ที่เกิดจากการใช้ event handlers เช่น onload, onclick, onmouseover, onerror, ฯลฯ"),
    ("XSS with cookies", "JavaScript เพื่อเข้าถึงหรือขโมย cookies ของผู้ใช้"),
   
    
]

# Payload และแพทเทิร์นที่ใช้ตรวจจับ XSS
XSS_PATTERNS = {
    "Stored Reflected XSS": r"(<script.*?>.*?</script>|<[^>]*?javascript:.*?>)",
    "Stored Event-handler XSS": r"on\w+\s*=\s*['\"].*?['\"]",
    "XSS with cookies": r"(document\.cookie|localStorage\.getItem|sessionStorage\.getItem)",
    

}

RISK_LEVELS = {
    "Stored Reflected XSS": "MEDIUM",
    "Stored Event-handler XSS": "LOW",
    "XSS with cookies": "HIGH",
   
}


COLOR_TAGS = {
    "HIGH": "danger",
    "MEDIUM": "warning",
    "LOW": "safe",
}

# ฟังก์ชันตรวจจับ XSS
def check_xss(content):
    results = []
    for xss_type, pattern in XSS_PATTERNS.items():
        if scan_check_vars[xss_type].get() == 1:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                risk = RISK_LEVELS.get(xss_type, "ไม่ทราบ")
                
                # เพิ่มคำอธิบายสำหรับแต่ละประเภท XSS
                if xss_type == "Stored Reflected XSS":
                    description = "การสะท้อนของโค้ดจาก URL ในเว็บไซต์ หรือการฝังสคลิป, สามารถนำไปสู่การโจมตีที่ผู้โจมตีสามารถฝังโค้ดที่เป็นอันตรายได้"
                elif xss_type == "Stored Event-handler XSS":
                    description = "ประเภทนี้คือ XSS ที่เกิดจากการใช้ event handlers เช่น onload, onclick, onmouseover, onerror,"
                elif xss_type == "XSS with cookies":
                    description = "XSS with cookies คือการโจมตีที่ใช้ JavaScript เพื่อเข้าถึงหรือขโมย cookies ของผู้ใช้ ซึ่งสามารถใช้เพื่อขโมยข้อมูลสำคัญ เช่น authentication tokens และ session cookies"
                results.append([xss_type, match, risk, description])
    return results if results else [["✅ ปลอดภัย", "ไม่พบ XSS", "", ""]]

# ฟังก์ชันตรวจสอบ URL
def check_multiple_urls():
    urls = url_entry.get("1.0", "end-1c").strip().split("\n")
    if not urls or urls == [""]:
        messagebox.showwarning("ข้อผิดพลาด", "กรุณาใส่ URL อย่างน้อยหนึ่งรายการ")
        return

    results_tree.delete(*results_tree.get_children())
    
    for url in urls:
        url = url.strip()
        if not url:
            continue

        try:
            response = requests.get(url, timeout=5)
            content = response.text
            results = check_xss(content)

            for result in results:
                xss_type, match, risk, description = result
                tag = COLOR_TAGS.get(risk, "safe")
                results_tree.insert("", "end", values=(url, xss_type, match, risk, description), tags=(tag,))

        except requests.exceptions.RequestException as e:
            results_tree.insert("", "end", values=(url, "❌ ข้อผิดพลาด", str(e), "ไม่สามารถโหลด URL", ""), tags=("danger",))

# ฟังก์ชันตรวจสอบไฟล์ HTML
def check_file_content():
    file_path = filedialog.askopenfilename(filetypes=[("HTML Files", "*.html"), ("Text Files", "*.txt"), ("All Files", "*.*")])
    if not file_path:
        return

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()

        results = check_xss(content)
        results_tree.delete(*results_tree.get_children())

        for result in results:
            xss_type, match, risk, description = result
            tag = COLOR_TAGS.get(risk, "safe")
            results_tree.insert("", "end", values=(file_path, xss_type, match, risk, description), tags=(tag,))

    except Exception as e:
        messagebox.showerror("ข้อผิดพลาด", f"เกิดข้อผิดพลาดในการอ่านไฟล์:\n{str(e)}")

# ฟังก์ชันบันทึกผลลัพธ์ลงไฟล์
def save_log():
    log_results = []
    for item in results_tree.get_children():
        values = results_tree.item(item, "values")
        log_results.append(" - ".join(values))
    
    if log_results:
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as log_file:
                log_file.write("\n".join(log_results))
            messagebox.showinfo("บันทึกสำเร็จ", f"ผลการตรวจสอบถูกบันทึกลงไฟล์ {file_path}")

# Create the main window and setup layout
root = tk.Tk()
root.title("XSS Scanner")
root.geometry("1440x900")
root.configure(bg=BG_COLOR)

header = tk.Label(root, text="🔍 เครื่องมือตรวจจับ XSS", font=("Arial", 18, "bold"), bg=BG_COLOR, fg=TEXT_COLOR)
header.pack(pady=10)

frame_input = tk.LabelFrame(root, text="🔗 ใส่ URL", font=("Arial", 12), bg=BG_COLOR, fg=TEXT_COLOR)
frame_input.pack(pady=10, padx=20, fill="x")

url_entry = tk.Text(frame_input, font=("Arial", 12), width=90, height=3, bd=2, relief="solid", bg="#222222", fg=TEXT_COLOR)
url_entry.pack(pady=10, padx=20)

check_button = ttk.Button(frame_input, text="ตรวจสอบ URL", command=check_multiple_urls)
check_button.pack(pady=5)

file_button = ttk.Button(frame_input, text="เลือกไฟล์ HTML เพื่อตรวจสอบ", command=check_file_content)
file_button.pack(pady=5)

frame_scan = tk.LabelFrame(root, text="⚙️ ประเภทการตรวจสอบ", font=("Arial", 12), bg=BG_COLOR, fg=TEXT_COLOR)
frame_scan.pack(pady=10, padx=20, fill="x")

scan_check_vars = {name: tk.IntVar() for name, _ in scan_types}
for name, desc in scan_types:
    check = tk.Checkbutton(frame_scan, text=name, variable=scan_check_vars[name], font=("Arial", 10), bg=BG_COLOR, fg=TEXT_COLOR, selectcolor="#444")
    check.pack(side="left", padx=10)

frame_results = tk.LabelFrame(root, text="📊 ผลการตรวจสอบ", font=("Arial", 12), bg=BG_COLOR, fg=TEXT_COLOR)
frame_results.pack(pady=10, padx=20, fill="both", expand=True)

columns = ("URL/ไฟล์", "ประเภท", "โค้ดที่พบ", "ระดับความอันตราย", "คำอธิบาย")
results_tree = ttk.Treeview(frame_results, columns=columns, show="headings", style="Treeview")
for col in columns:
    results_tree.heading(col, text=col)
    results_tree.column(col, width=250, anchor="center")

# Define tag colors for different statuses
results_tree.tag_configure("danger", foreground="red")
results_tree.tag_configure("safe", foreground="green")
results_tree.tag_configure("warning", foreground="yellow")

results_tree.pack(pady=5, padx=5, fill="both", expand=True)

save_button = ttk.Button(root, text="บันทึกผลลัพธ์เป็นไฟล์", command=save_log)
save_button.pack(pady=10)

# Apply dark style to the ttk widgets
style = ttk.Style()
style.configure("TButton", background="#333333", foreground="#ff0000", font=("Arial", 12, "bold"), padding=6)
style.configure("Treeview", background="#000000", foreground=TEXT_COLOR, font=("Arial", 13))
style.configure("Treeview.Heading", background="#333333", foreground="red")

# Start the GUI
# ป้องกันปัญหา "lost sys.stdin" เมื่อต้องรันเป็น .exe
import sys
import os

if not sys.stdin:
    sys.stdin = open(os.devnull, 'r')
root.mainloop()
