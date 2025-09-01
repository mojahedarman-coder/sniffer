import tkinter as tk
from tkinter import messagebox
import subprocess, re, requests, ctypes, threading
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sniff, DNSQR, IP, TCP, UDP, Raw
from scapy.layers.ssl_tls import TLSClientHello, TLSExtensionServerName

# بررسی دسترسی ادمین
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# گرفتن جدول ARP
def get_arp_table():
    result = subprocess.run("arp -a", shell=True, capture_output=True, text=True)
    return result.stdout

# استخراج IPها از خروجی ARP
def extract_ips(arp_output):
    raw_ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)", arp_output)
    return list(set(ip for ip in raw_ips if not ip.startswith("255") and not ip.startswith("0")))

# گرفتن MAC از جدول ARP
def get_mac(ip, arp_output):
    match = re.search(rf"{ip}\s+([\w-]+)\s+([\w-]+)", arp_output)
    return match.group(2).replace("-", ":") if match else "Unknown"

# گرفتن Vendor از API
vendor_cache = {}
def get_vendor(mac):
    if mac in vendor_cache or mac == "Unknown":
        return vendor_cache.get(mac, "Unknown")
    url = f"https://api.macvendors.com/{mac}"
    try:
        response = requests.get(url, timeout=3)
        vendor = response.text if response.status_code == 200 else "Unknown"
    except:
        vendor = "Unknown"
    vendor_cache[mac] = vendor
    return vendor

# دیتابیس دامنه‌ها و پورت‌ها
known_domains = {
    "discord.com": " Discord", "telegram.org": " Telegram", "whatsapp.net": " WhatsApp",
    "netflix.com": " Netflix", "spotify.com": " Spotify", "steam": " Steam",
    "microsoft": " Windows", "google": " Android", "icloud.com": " iPhone/Mac",
    "youtube.com": " YouTube", "ytimg.com": " YouTube (Media)",
    "facebook.com": " Facebook", "fbcdn.net": " Facebook (Content)"
}

known_ports = {
    443: " HTTPS", 80: " HTTP", 5222: " Chat", 1935: " RTMP",
    3478: " VoIP", 8080: " Proxy", 53: " DNS"
}

def detect_app(domain):
    return next((name for key, name in known_domains.items() if key in domain), " Unknown")

def detect_port(port):
    return known_ports.get(port, f" Port {port}")

def guess_os(vendor, domain="", ua=""):
    vendor = vendor.lower()
    domain = domain.lower()
    ua = ua.lower()
    if "apple" in vendor or "icloud" in domain or "mac" in domain or "iphone" in ua:
        return " iOS/macOS"
    elif "samsung" in vendor or "android" in domain or "google" in domain or "android" in ua:
        return " Android"
    elif "microsoft" in domain or "windows" in domain or "intel" in vendor or "hp" in vendor or "dell" in vendor or "windows" in ua:
        return " Windows"
    elif "linux" in domain or "ubuntu" in domain or "linux" in ua:
        return " Linux"
    else:
        return " Unknown"

# کنترل Sniffing
sniffing_thread = None
stop_sniffing = False

def start_sniff_all(output_box, ip_list, vendor_map):
    global sniffing_thread, stop_sniffing
    stop_sniffing = False

    def process_packet(packet):
        if stop_sniffing:
            return
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            if src_ip in ip_list:
                vendor = vendor_map.get(src_ip, "Unknown")
                info = f" IP: {src_ip} |  Size: {len(packet)} bytes"
                domain = ""
                os_type = " Unknown"

                if packet.haslayer(DNSQR):
                    domain = packet[DNSQR].qname.decode("utf-8")
                    app = detect_app(domain)
                    os_type = guess_os(vendor, domain)
                    info += f" | DNS: {domain} | App: {app} | OS: {os_type}"

                elif packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode(errors="ignore")
                        host_line = re.search(r"Host:\s*(.*)", payload)
                        ua_line = re.search(r"User-Agent:\s*(.*)", payload)
                        if host_line:
                            domain = host_line.group(1).strip()
                            app = detect_app(domain)
                            ua = ua_line.group(1).strip() if ua_line else ""
                            os_type = guess_os(vendor, domain, ua)
                            info += f" | HTTP: {domain} | App: {app} | OS: {os_type}"
                    except:
                        pass

                elif packet.haslayer(TLSClientHello):
                    for ext in packet[TLSClientHello].extensions:
                        if isinstance(ext, TLSExtensionServerName):
                            domain = ext.servernames[0].servername.decode()
                            app = detect_app(domain)
                            os_type = guess_os(vendor, domain)
                            info += f" | TLS SNI: {domain} | App: {app} | OS: {os_type}"

                if packet.haslayer(TCP):
                    port = packet[TCP].dport
                    info += f" | TCP Port: {port} | Type: {detect_port(port)}"
                elif packet.haslayer(UDP):
                    port = packet[UDP].dport
                    info += f" | UDP Port: {port} | Type: {detect_port(port)}"

                output_box.insert(tk.END, info + "\n")
                output_box.see(tk.END)

    sniffing_thread = threading.Thread(target=lambda: sniff(filter="tcp or udp or port 53 or port 443", prn=process_packet, store=0))
    sniffing_thread.start()

def stop_sniff():
    global stop_sniffing
    stop_sniffing = True

def fetch_all_vendors(ip_list, arp_output):
    vendor_map = {}
    def fetch(ip):
        mac = get_mac(ip, arp_output)
        vendor = get_vendor(mac)
        vendor_map[ip] = vendor
        os_type = guess_os(vendor)
        return f" {ip} | MAC: {mac} | Vendor: {vendor} | OS: {os_type}"
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(fetch, ip_list))
    return results, vendor_map

def launch_gui():
    if not is_admin():
        messagebox.showerror("Access Denied", "You must run this tool as Administrator.")
        return

    arp_output = get_arp_table()
    ip_list = extract_ips(arp_output)

    root = tk.Tk()
    root.title(" Arman Network Sniffer")
    root.configure(bg="black")

    tk.Label(root, text=" Devices connected to modem:", fg="lime", bg="black", font=("Consolas", 12)).pack()

    ip_box = tk.Listbox(root, height=8, width=30, bg="black", fg="lime", font=("Consolas", 11), selectbackground="green")
    for ip in ip_list:
        ip_box.insert(tk.END, ip)
    ip_box.pack()

    output_box = tk.Text(root, height=25, width=90, bg="black", fg="lime", font=("Consolas", 10))
    output_box.pack()

    def on_start():
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, " Sniffing all connected devices...\n")
        results, vendor_map = fetch_all_vendors(ip_list, arp_output)
        for line in results:
            output_box.insert(tk.END, line + "\n")
        start_sniff_all(output_box, ip_list, vendor_map)

    def on_stop():
        stop_sniff()
        output_box.insert(tk.END, "\n️ Sniffing stopped.\n")

    tk.Button(root, text="Start Sniffing", command=on_start, bg="green", fg="black", font=("Consolas", 11)).pack(pady=5)
    tk.Button(root, text="Stop Sniffing", command=on_stop, bg="red", fg="white", font=("Consolas", 11)).pack(pady=5)

    root.mainloop()

