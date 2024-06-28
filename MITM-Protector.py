import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, ARP, get_if_list, conf

class MITMDetector:
    def __init__(self, master):
        self.master = master
        self.master.title("Man in the Middle Attack Protection")
        
        self.frame = tk.Frame(master, padx=20, pady=20)
        self.frame.pack(padx=10, pady=10)

        self.ip_label = tk.Label(self.frame, text="Modem IP Address: 192.168.1.1", font=("Arial", 12))
        self.ip_label.grid(row=0, column=0, sticky="w")

        self.mac_label = tk.Label(self.frame, text="Modem MAC Address: 08-26-97-09-d4-a2", font=("Arial", 12))
        self.mac_label.grid(row=1, column=0, sticky="w")

        self.ip_status_label = tk.Label(self.frame, text="IP Address: Unchanged", fg="green", font=("Arial", 12))
        self.ip_status_label.grid(row=2, column=0, sticky="w")

        self.mac_status_label = tk.Label(self.frame, text="MAC Address: Unchanged", fg="green", font=("Arial", 12))
        self.mac_status_label.grid(row=3, column=0, sticky="w")

        self.footer_label = tk.Label(self.frame, text="Made by Batuhan Turker", font=("Arial", 10, "italic"))
        self.footer_label.grid(row=4, column=0, pady=(10, 0), sticky="w")

        self.instruction_label = tk.Label(self.frame, text="You can click close button it will tray icon, or press Control+C", font=("Arial", 10))
        self.instruction_label.grid(row=5, column=0, pady=(10, 0), sticky="w")

        self.original_mac = "08:26:97:09:d4:a2"  

        self.interface = self.get_network_interface()
        self.master.after(1000, self.start_sniffing)

    def get_network_interface(self):
        interfaces = get_if_list()
        print("Available interfaces:", interfaces)
        return 'en0'  

    def start_sniffing(self):
        sniff(prn=self.detect_mitm, filter="arp", store=0, iface=self.interface, count=0)

    def detect_mitm(self, packet):
        if packet.haslayer(ARP):
            arp = packet[ARP]
            if arp.op == 2:  
                if arp.psrc == "192.168.1.1" and arp.hwsrc != self.original_mac:
                    self.mac_status_label.config(text="MAC Address: Changed", fg="red")
                    messagebox.showwarning("MITM Detected", "Potential MITM attack detected! MAC address has changed.")
                else:
                    self.mac_status_label.config(text="MAC Address: Unchanged", fg="green")

if __name__ == "__main__":
    conf.use_pcap = True  
    root = tk.Tk()
    app = MITMDetector(root)
    root.mainloop()
