from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
from datetime import datetime

# Alert settings
KEYWORDS = ["admin", "password", "login", "secret"]
WATCHED_IPS = ["8.8.8.8", "104.18.32.47"]

# Stats tracker
protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "Other": 0}

# Log file
log_file = "packet_log.txt"

def log_to_file(entry):
    with open("sniffer_log.txt", "a", encoding="utf-8") as f:
        f.write(entry + "\n")

def packet_callback(packet):
    time_stamp = datetime.now().strftime("%H:%M:%S")
    log_entry = ""
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)
        proto = "Other"
        info = ""

        if TCP in packet:
            proto = "TCP"
            protocol_counts["TCP"] += 1
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            info = f"{src_ip}:{sport} ➜ {dst_ip}:{dport}"

        elif UDP in packet:
            proto = "UDP"
            protocol_counts["UDP"] += 1
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            info = f"{src_ip}:{sport} ➜ {dst_ip}:{dport}"

            if DNS in packet:
                proto = "DNS"
                protocol_counts["DNS"] += 1
                try:
                    qname = packet[DNS].qd.qname.decode()
                    info += f" | DNS Query: {qname}"
                except:
                    pass

        elif ICMP in packet:
            proto = "ICMP"
            protocol_counts["ICMP"] += 1
            info = f"{src_ip} ➜ {dst_ip} (ICMP)"
        else:
            protocol_counts["Other"] += 1
            info = f"{src_ip}:{sport} -> {dst_ip}:{dport}"


        # Base log and screen output
        log_entry = f"[{time_stamp}] [{proto}] {info} | {length} bytes"
        print(f"\033[92m{log_entry}\033[0m")

        # Watch for suspicious IPs
        if dst_ip in WATCHED_IPS or src_ip in WATCHED_IPS:
            alert = f" ALERT: Traffic to/from watched IP {src_ip} ➜ {dst_ip}"
            print(f"\033[91m{alert}\033[0m")
            log_entry += f"\n{alert}"

        # Payload analysis
        if Raw in packet:
            raw_data = packet[Raw].load[:80]
            try:
                decoded = raw_data.decode('utf-8', errors='ignore')
                print(f"    Payload: {decoded}")
                if any(keyword in decoded.lower() for keyword in KEYWORDS):
                    alert = f"! Keyword alert! Found keyword in payload."
                    print(f"\033[93m{alert}\033[0m")
                    log_entry += f"\n{alert}\nPayload: {decoded}"
            except:
                print(f"    Payload: (non-decodable data)")

        log_to_file(log_entry)
        print("-" * 70)

def main():
    print("=== Advanced Packet Sniffer with Alerts and Logging (Ctrl+C to stop) ===")
    try:
        sniff(filter="ip", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\nSniffer stopped.")
        print("\n--- Protocol Summary ---")
        for proto, count in protocol_counts.items():
            print(f"{proto}: {count} packets")
        print(f"\n Logged packets to: {log_file}")

if __name__ == "__main__":
    main()

