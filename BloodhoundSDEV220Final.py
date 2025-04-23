import ipaddress
import os
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox, filedialog
from tkinter import ttk
from playsound import playsound
from scapy.all import sniff

class PacketSniffer:
    @staticmethod
    def start_sniffing(packet_callback, is_sniffing):
        def stop_filter(_):
            return not is_sniffing()

        try:
            sniff(prn=packet_callback, store=False, stop_filter=stop_filter)
        except PermissionError:
            packet_callback("[ERROR] Permission denied. Run as administrator.")
        except Exception as sniff_error:
            packet_callback(f"[ERROR] {sniff_error}")


class PortScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip

    def scan_port(self, port, open_ports):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if not sock.connect_ex((self.target_ip, port)):
                open_ports.append(port)

    def scan_ports(self, start_port, end_port):
        open_ports = []
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port, open_ports))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
        return open_ports

class CyberGUI:
    def __init__(self, root):
        self.exit_app = None
        self.status = None
        self.text_area = None
        self.root = root
        self.root.title("Bloodhound")

        self.packet_log = {}
        self.target_ip = None
        self.start_port = 20
        self.end_port = 100
        self.sniffing = False
        self.sniff_thread = None
        self.packet_sniffer = PacketSniffer()

        self.theme_var = tk.StringVar(value="dark")
        self.sound_enabled = tk.BooleanVar(value=True)

        self.suspicious_ports = {
            23: "Telnet",
            3389: "Remote Desktop (RDP)",
            4444: "Metasploit handler",
            5900: "VNC",
            135: "RPC",
            139: "NetBIOS",
            445: "SMB",
            3306: "MySQL (exposed)",
        }

        self.setup_style()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        theme = self.theme_var.get()

        if theme == "dark":
            bg = "#111"
            fg = "#0f0"
        else:
            bg = "#f0f0f0"
            fg = "#000"

        style.configure("TButton", padding=6, relief="flat", background=bg, foreground=fg, font=('Consolas', 10))
        style.configure("TLabel", background=bg, foreground=fg, font=('Consolas', 10))

    def create_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True)

        sidebar = ttk.Frame(main_frame, width=200)
        sidebar.pack(side="left", fill="y", padx=5, pady=5)

        ttk.Label(sidebar, text="Settings").pack(anchor="w", pady=(0, 10))
        ttk.Checkbutton(sidebar, text="Enable Sound", variable=self.sound_enabled).pack(anchor="w", pady=2)
        ttk.Label(sidebar, text="Theme:").pack(anchor="w", pady=(10, 0))
        ttk.Radiobutton(sidebar, text="Dark", variable=self.theme_var, value="dark", command=self.refresh_theme).pack(anchor="w")
        ttk.Radiobutton(sidebar, text="Light", variable=self.theme_var, value="light", command=self.refresh_theme).pack(anchor="w")

        console_frame = ttk.Frame(main_frame)
        console_frame.pack(side="right", fill="both", expand=True)

        self.text_area = scrolledtext.ScrolledText(console_frame, width=90, height=25, bg="#111", fg="#0f0")
        self.text_area.pack(fill="both", expand=True, padx=10, pady=10)
        self.text_area.tag_config("alert", foreground="red", font=("Courier", 10, "bold"))
        self.text_area.tag_config("success", foreground="lime", font=("Courier", 10, "bold"))

        button_frame = ttk.Frame(console_frame)
        button_frame.pack(fill="x", pady=5)

        ttk.Button(button_frame, text="Enter Target IP", command=self.enter_ip).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Scan Ports", command=self.scan_ports).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_text_area).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Save As", command=self.save_summary_as).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Exit", command=self.on_close).pack(side="left", padx=5)

        self.status = ttk.Label(console_frame, text="Ready", anchor="w")
        self.status.pack(fill="x", padx=10, pady=(0, 10))

    def refresh_theme(self):
        self.setup_style()
        self.text_area.config(bg="#111" if self.theme_var.get() == "dark" else "#fff",
                              fg="#0f0" if self.theme_var.get() == "dark" else "#000")

    def packet_callback(self, packet):
        def update_ui():
            try:
                summary = packet.summary()
                self.text_area.insert(tk.END, f"{summary}\n")
                self.text_area.yview(tk.END)
                proto = summary.split()[0]
                self.packet_log[proto] = self.packet_log.get(proto, 0) + 1
            except Exception as e:
                self.text_area.insert(tk.END, f"[ERROR] {e}\n")

        self.root.after(0, update_ui)

    def is_sniffing(self):
        return self.sniffing

    def start_sniffing(self):
        if self.sniffing:
            self.status.config(text="Already sniffing...")
            return

        self.sniffing = True
        self.status.config(text="Sniffing started...")
        self.sniff_thread = threading.Thread(
            target=self.packet_sniffer.start_sniffing,
            args=(self.packet_callback, self.is_sniffing)
        )
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.status.config(text="Stopping sniffing...")
            self.text_area.insert(tk.END, "[*] Sniffing stopped by user.\n")

            if self.packet_log:
                summary_lines = ["\n[*] Packet Summary:"]
                for proto, count in self.packet_log.items():
                    summary_lines.append(f"   {proto}: {count} packets")
                summary_text = "\n".join(summary_lines)

                self.text_area.insert(tk.END, f"{summary_text}\n")
                self.text_area.yview(tk.END)

                try:
                    with open("packet_summary.txt", "w") as f:
                        f.write("Bloodhound Packet Summary\n")
                        f.write("==========================\n")
                        for line in summary_lines[1:]:
                            f.write(line + "\n")
                    self.status.config(text="Summary saved to 'packet_summary.txt'")
                except Exception as file_error:
                    self.text_area.insert(tk.END, f"[ERROR] Failed to write file: {file_error}\n")

                self.packet_log.clear()
        else:
            self.status.config(text="Not currently sniffing.")

    def save_summary_as(self):
        if not self.packet_log:
            messagebox.showinfo("Info", "No packet data to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")],
            title="Save Packet Summary As"
        )

        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write("Bloodhound Packet Summary\n")
                    f.write("==========================\n")
                    for proto, count in self.packet_log.items():
                        f.write(f"{proto}: {count} packets\n")
                self.status.config(text=f"Summary saved to: {file_path}")
            except Exception as save_error:
                messagebox.showerror("Error", f"Failed to save file: {save_error}")

    def scan_ports(self):
        if not self.target_ip:
            messagebox.showwarning("Warning", "Please enter a target IP first.")
            return

        try:
            start_port = int(simpledialog.askstring("Port Range", "Enter start port (default 20):") or 20)
            end_port = int(simpledialog.askstring("Port Range", "Enter end port (default 100):") or 100)
            if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535) or start_port > end_port:
                raise ValueError("Invalid port range")
        except ValueError as port_error:
            messagebox.showerror("Error", f"Port input error: {port_error}")
            return

        self.start_port, self.end_port = start_port, end_port
        self.status.config(text=f"Scanning ports {start_port}-{end_port} on {self.target_ip}...")

        scanner = PortScanner(self.target_ip)
        open_ports = scanner.scan_ports(start_port, end_port)

        self.text_area.insert(tk.END, f"\n[+] Open ports on {self.target_ip}: {open_ports}\n\n", "success")
        self.text_area.insert(tk.END, "[\u2713] Port scan complete.\n\n", "success")
        self.text_area.yview(tk.END)
        self.status.config(text="Port scan complete.")

        alerts = [f"Port {port} ({self.suspicious_ports[port]})" for port in open_ports if port in self.suspicious_ports]
        if alerts:
            alert_msg = "\n\u26a0\ufe0f Suspicious ports detected:\n\n" + "\n".join(alerts)
            messagebox.showwarning("Security Alert", alert_msg)

            bark_path = os.path.join(os.path.dirname(__file__), "bark.mp3")
            if self.sound_enabled.get() and os.path.exists(bark_path):
                try:
                    playsound(bark_path, block=False)
                except Exception as sound_error:
                    print(f"[Sound Error] Could not play bark.mp3: {sound_error}")

            self.text_area.insert(tk.END, "[!] ALERT: Suspicious ports found:\n", "alert")
            for line in alerts:
                self.text_area.insert(tk.END, f"{line}\n", "alert")
            self.text_area.insert(tk.END, "\n")

    def enter_ip(self):
        ip = simpledialog.askstring("Target IP", "Enter the target IP address:")
        if ip and self.validate_ip(ip):
            self.target_ip = ip
            self.text_area.insert(tk.END, f"Target IP set to: {self.target_ip}\n")
            self.text_area.yview(tk.END)
            self.status.config(text=f"Target IP set to {self.target_ip}")
        else:
            messagebox.showerror("Error", "Invalid IP address.")

    @staticmethod
    def validate_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def clear_text_area(self):
        self.text_area.delete(1.0, tk.END)
        self.status.config(text="Text area cleared.")

    def on_close(self):
        if self.sniffing:
            self.stop_sniffing()
        self.root.destroy()


if __name__ == "__main__":
    main_window = tk.Tk()

    icon_path = r"C:\\IVYTECH\\SDEV220\\M03\\bloodhound_icon.png"
    if os.path.exists(icon_path):
        try:
            icon = tk.PhotoImage(file=icon_path)
            main_window.iconphoto(True, icon)
        except Exception as icon_error:
            print(f"[Icon Error] {icon_error}")
    else:
        print(f"⚠️ Icon not found at: {icon_path}")

    blip_path = os.path.join(os.path.dirname(__file__), "power_on_blip.mp3")
    if os.path.exists(blip_path):
        try:
            playsound(blip_path, block=False)
        except Exception as startup_error:
            print(f"[Startup Sound Error] {blip_path}: {startup_error}")

    app = CyberGUI(main_window)
    main_window.mainloop()
