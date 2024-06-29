import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, ARP, get_if_list, conf
import netifaces as ni
import platform
import subprocess

class MITMDetector:
    def __init__(self, master):
        self.master = master
        self.master.title("Man in the Middle Attack Protection")
        
        self.frame = tk.Frame(master, padx=20, pady=20)
        self.frame.pack(padx=10, pady=10)

        self.modem_ip, self.original_mac = self.get_modem_info()

        self.ip_label = tk.Label(self.frame, text=f"Modem IP Address: {self.modem_ip}", font=("Arial", 12))
        self.ip_label.grid(row=0, column=0, sticky="w")

        self.mac_label = tk.Label(self.frame, text=f"Modem MAC Address: {self.original_mac}", font=("Arial", 12))
        self.mac_label.grid(row=1, column=0, sticky="w")

        self.ip_status_label = tk.Label(self.frame, text="IP Address: Unchanged", fg="green", font=("Arial", 12))
        self.ip_status_label.grid(row=2, column=0, sticky="w")

        self.mac_status_label = tk.Label(self.frame, text="MAC Address: Unchanged", fg="green", font=("Arial", 12))
        self.mac_status_label.grid(row=3, column=0, sticky="w")

        self.footer_label = tk.Label(self.frame, text="Made by Batuhan Turker", font=("Arial", 10, "italic"))
        self.footer_label.grid(row=4, column=0, pady=(10, 0), sticky="w")

        self.instruction_label = tk.Label(self.frame, text="You can click close button it will tray icon, or press Control+C", font=("Arial", 10))
        self.instruction_label.grid(row=5, column=0, pady=(10, 0), sticky="w")

        self.interface = self.get_network_interface()
        self.master.after(1000, self.start_sniffing)

    def get_modem_info(self):
       
        gws = ni.gateways()
        default_gateway = gws['default'][ni.AF_INET]
        modem_ip = default_gateway[0]

      
        arp_output = subprocess.check_output(["arp", "-n", modem_ip]).decode("utf-8")
        mac_address = arp_output.split()[3]
        
        return modem_ip, mac_address

    def get_network_interface(self):
        interfaces = get_if_list()
        print("Available interfaces:", interfaces)
        return ni.gateways()['default'][ni.AF_INET][1]

    def start_sniffing(self):
        sniff(prn=self.detect_mitm, filter="arp", store=0, iface=self.interface, count=0)

    def detect_mitm(self, packet):
        if packet.haslayer(ARP):
            arp = packet[ARP]
            if arp.op == 2:  
                if arp.psrc == self.modem_ip:
                    print(f"Detected ARP Response: IP={arp.psrc} MAC={arp.hwsrc}")
                    if arp.hwsrc.lower() != self.original_mac.lower():
                        self.mac_status_label.config(text="MAC Address: Changed", fg="red")
                        self.ip_status_label.config(text="IP Address: Unchanged", fg="green")
                        messagebox.showwarning("MITM Detected", f"Potential MITM attack detected! MAC address has changed.\nOriginal: {self.original_mac}\nCurrent: {arp.hwsrc}")
                    else:
                        self.mac_status_label.config(text="MAC Address: Unchanged", fg="green")
                        self.ip_status_label.config(text="IP Address: Unchanged", fg="green")
                else:
                    self.ip_status_label.config(text="IP Address: Changed", fg="red")
                    self.mac_status_label.config(text="MAC Address: Unchanged", fg="green")
                    messagebox.showwarning("MITM Detected", f"Potential MITM attack detected! IP address has changed.\nOriginal: {self.modem_ip}\nCurrent: {arp.psrc}")

if __name__ == "__main__":
    if platform.system() == "Darwin":  # This part is for mac users
        conf.use_pcap = True
    root = tk.Tk()
    app = MITMDetector(root)
    root.mainloop()


