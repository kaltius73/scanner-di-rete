import socket
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from threading import Thread
from scapy.all import ARP, Ether, srp


class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner di Rete ver. 1.0")

        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.ip_label = ttk.Label(left_frame, text="Intervallo IP (es. 192.168.1.1-192.168.1.10):")
        self.ip_label.pack(pady=5)

        self.ip_entry = ttk.Entry(left_frame)
        self.ip_entry.pack(pady=5)

        self.port_label = ttk.Label(left_frame, text="Porte (es. 22,80,443 o 1-1024):")
        self.port_label.pack(pady=5)

        self.port_entry = ttk.Entry(left_frame)
        self.port_entry.pack(pady=5)

        self.scan_mode_label = ttk.Label(left_frame, text="Modalità di Scansione:")
        self.scan_mode_label.pack(pady=5)

        self.scan_mode = ttk.Combobox(left_frame, values=["TCP", "UDP"])
        self.scan_mode.current(0)
        self.scan_mode.pack(pady=5)

        self.start_button = ttk.Button(left_frame, text="Avvia Scansione", command=self.start_scan)
        self.start_button.pack(pady=10)

        self.stop_button = ttk.Button(left_frame, text="Ferma Scansione", command=self.stop_scan)
        self.stop_button.pack(pady=10)

        self.save_button = ttk.Button(left_frame, text="Salva Risultati", command=self.save_results)
        self.save_button.pack(pady=10)

        self.progress = ttk.Progressbar(left_frame, orient="horizontal", length=200, mode="determinate")
        self.progress.pack(pady=10)

        self.output_text = tk.Text(right_frame, height=25, width=80)
        self.output_text.pack(pady=10)

        self.scanning = False
        self.results = []

    def start_scan(self):
        ip_range = self.ip_entry.get()
        ports = self.port_entry.get()
        mode = self.scan_mode.get()

        ip_list = self.parse_ip_range(ip_range)
        port_list = self.parse_ports(ports)

        if not ip_list or not port_list:
            self.output_text.insert(tk.END, "Indirizzo IP o Porta non validi.\n")
            return

        self.output_text.insert(tk.END, f"Inizio scansione...\n")
        self.scanning = True
        self.progress["maximum"] = len(ip_list) * len(port_list)

        self.scan_thread = Thread(target=self.scan_network, args=(ip_list, port_list, mode))
        self.scan_thread.start()

    def stop_scan(self):
        self.scanning = False
        self.output_text.insert(tk.END, "Scansione fermata.\n")

    def scan_network(self, ip_list, port_list, mode):
        count = 0
        for ip in ip_list:
            for port in port_list:
                if not self.scanning:
                    return
                self.scan_port(ip, port, mode)
                count += 1
                self.progress["value"] = count
        self.output_text.insert(tk.END, "Scansione completata.\n")

    def scan_port(self, ip, port, mode):
        s = socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET,
                          socket.SOCK_DGRAM if mode == "UDP" else socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        if result == 0:
            service = self.get_service(port)
            mac_address = self.get_mac_address(ip)
            self.output_text.insert(tk.END, f"{mode} Porta {port} aperta su {ip} ({service}), MAC: {mac_address}\n")
            self.results.append(f"{mode} Porta {port} aperta su {ip} ({service}), MAC: {mac_address}\n")
        else:
            self.output_text.insert(tk.END, f"{mode} Porta {port} chiusa su {ip}\n")
        s.close()

    def get_service(self, port):
        try:
            return socket.getservbyport(port)
        except:
            return "Sconosciuto"

    def get_mac_address(self, ip):
        try:
            arp_request = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp_request
            result = srp(packet, timeout=2, verbose=False)[0]
            return result[0][1].hwsrc
        except IndexError:
            return "Sconosciuto"

    def parse_ip_range(self, ip_range):
        try:
            start_ip, end_ip = ip_range.split('-')
            start_octets = start_ip.split('.')
            end_octets = end_ip.split('.')
            ip_list = []
            for i in range(int(start_octets[3]), int(end_octets[3]) + 1):
                ip_list.append(f"{start_octets[0]}.{start_octets[1]}.{start_octets[2]}.{i}")
            return ip_list
        except ValueError:
            return []

    def parse_ports(self, ports):
        try:
            if '-' in ports:
                start_port, end_port = map(int, ports.split('-'))
                return list(range(start_port, end_port + 1))
            else:
                return [int(port) for port in ports.split(',')]
        except ValueError:
            return []

    def save_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as file:
                for result in self.results:
                    file.write(result)
            self.output_text.insert(tk.END, "Risultati salvati con successo.\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
