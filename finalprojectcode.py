# Importing necessary libraries for networking, GUI, and system operations

import ipaddress  # Handles IP address manipulation and validation
import os  # Interacts with the operating system for file operations
import socket  # Enables network communication via sockets
import threading  # Facilitates running tasks concurrently using threads
import tkinter as tk  # Provides GUI functionality for the application
from tkinter import scrolledtext, simpledialog, messagebox, filedialog  # GUI components for enhanced user interaction
from tkinter import ttk  # Themed widgets for better UI styling
from playsound import playsound  # Allows audio playback (useful for alerts)
from scapy.all import sniff  # Captures and analyzes network packets

# PacketSniffer class is responsible for sniffing network packets
class PacketSniffer:
    @staticmethod
    def start_sniffing(packet_callback, is_sniffing):
        """
        Starts sniffing network packets, calling the provided callback function for each packet.
        Stops when 'is_sniffing' returns False.
        """
        def stop_filter(_):
            return not is_sniffing()

        try:
            sniff(prn=packet_callback, store=False, stop_filter=stop_filter)
        except PermissionError:
            packet_callback("[ERROR] Permission denied. Run as administrator.")  # User needs elevated privileges
        except Exception as sniff_error:
            packet_callback(f"[ERROR] {sniff_error}")  # Catch and display unexpected errors


# PortScanner class checks for open ports on a target IP address
class PortScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip  # The IP address to be scanned

    def scan_port(self, port, open_ports):
        """
        Attempts to connect to the specified port on the target IP.
        If successful, the port is added to the list of open ports.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Avoid long waiting times
            if not sock.connect_ex((self.target_ip, port)):  # If the connection succeeds
                open_ports.append(port)

    def scan_ports(self, start_port, end_port):
        """
        Scans a range of ports in parallel using threads.
        Returns a list of open ports.
        """
        open_ports = []
        threads = []
        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port, open_ports))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()  # Wait for all threads to complete
        return open_ports


# CyberGUI class creates the graphical interface for the network tool
class CyberGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Bloodhound")  # The name of our security tool

        # Variables and settings
        self.packet_log = {}  # Stores packet counts by protocol
        self.target_ip = None
        self.start_port = 20
        self.end_port = 100
        self.sniffing = False
        self.sniff_thread = None
        self.packet_sniffer = PacketSniffer()

        # User preferences
        self.theme_var = tk.StringVar(value="dark")  # Default to dark theme
        self.sound_enabled = tk.BooleanVar(value=True)  # Whether alerts should play sound

        # List of potentially suspicious ports
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
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)  # Handle window close event

    def setup_style(self):
        """ Configures the look of the GUI based on the selected theme. """
        style = ttk.Style()
        style.theme_use("clam")
        theme = self.theme_var.get()

        # Differentiate between dark and light themes
        bg = "#111" if theme == "dark" else "#f0f0f0"
        fg = "#0f0" if theme == "dark" else "#000"

        # Apply styles to buttons and labels
        style.configure("TButton", padding=6, relief="flat", background=bg, foreground=fg, font=('Consolas', 10))
        style.configure("TLabel", background=bg, foreground=fg, font=('Consolas', 10))

    def create_widgets(self):
        """ Sets up the buttons and display elements in the GUI. """
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True)

        # Sidebar for settings
        sidebar = ttk.Frame(main_frame, width=200)
        sidebar.pack(side="left", fill="y", padx=5, pady=5)
        ttk.Label(sidebar, text="Settings").pack(anchor="w", pady=(0, 10))
        ttk.Checkbutton(sidebar, text="Enable Sound", variable=self.sound_enabled).pack(anchor="w", pady=2)

        # Theme selection
        ttk.Label(sidebar, text="Theme:").pack(anchor="w", pady=(10, 0))
        ttk.Radiobutton(sidebar, text="Dark", variable=self.theme_var, value="dark", command=self.refresh_theme).pack(anchor="w")
        ttk.Radiobutton(sidebar, text="Light", variable=self.theme_var, value="light", command=self.refresh_theme).pack(anchor="w")

        # Console where logs are displayed
        console_frame = ttk.Frame(main_frame)
        console_frame.pack(side="right", fill="both", expand=True)
        self.text_area = scrolledtext.ScrolledText(console_frame, width=90, height=25, bg="#111", fg="#0f0")
        self.text_area.pack(fill="both", expand=True, padx=10, pady=10)

        # Buttons for user actions
        button_frame = ttk.Frame(console_frame)
        button_frame.pack(fill="x", pady=5)
        ttk.Button(button_frame, text="Enter Target IP", command=self.enter_ip).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Scan Ports", command=self.scan_ports).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing).pack(side="left", padx=5)

        self.status = ttk.Label(console_frame, text="Ready", anchor="w")
        self.status.pack(fill="x", padx=10, pady=(0, 10))

    def refresh_theme(self):
        """ Updates the GUI theme dynamically. """
        self.setup_style()
        self.text_area.config(bg="#111" if self.theme_var.get() == "dark" else "#fff",
                              fg="#0f0" if self.theme_var.get() == "dark" else "#000")

    def start_sniffing(self):
        """ Begins network packet sniffing. """
        if self.sniffing:
            self.status.config(text="Already sniffing...")
            return

        self.sniffing = True
        self.status.config(text="Sniffing started...")
        self.sniff_thread = threading.Thread(target=self.packet_sniffer.start_sniffing, args=(self.packet_callback, self.is_sniffing))
        self.sniff_thread.daemon = True
        self.sniff_thread.start()


        # Attempt to get port range from user input while handling potential errors
        try:
            # Get user input for start and end ports, with default values if left blank
            start_port = int(simpledialog.askstring("Port Range", "Enter start port (default 20):") or 20)
            end_port = int(simpledialog.askstring("Port Range", "Enter end port (default 100):") or 100)

    # Ensure the given port range is valid (between 1 and 65535, and start < end)
            if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535) or start_port > end_port:
                raise ValueError("Invalid port range")  # Raise an error if input is incorrect

        except ValueError as port_error:
    # Show an error message to the user if they entered an invalid port range
            messagebox.showerror("Error", f"Port input error: {port_error}")
            return  # Exit early if there's an issue

# Store the validated ports and update the status label
        self.start_port, self.end_port = start_port, end_port
        self.status.config(text=f"Scanning ports {start_port}-{end_port} on {self.target_ip}...")

# Initialize the scanner with the target IP and perform the port scan
        scanner = PortScanner(self.target_ip)
        open_ports = scanner.scan_ports(start_port, end_port)

# Display the list of open ports found
        self.text_area.insert(tk.END, f"\n[+] Open ports on {self.target_ip}: {open_ports}\n\n", "success")
        self.text_area.insert(tk.END, "[\u2713] Port scan complete.\n\n", "success")
        self.text_area.yview(tk.END)  # Scroll the text view to the latest message
        self.status.config(text="Port scan complete.")

# Check if any open ports are potentially suspicious
        alerts = [f"Port {port} ({self.suspicious_ports[port]})" for port in open_ports if port in self.suspicious_ports]
        if alerts:
    # Build an alert message if suspicious ports are detected
            alert_msg = "\n\u26a0\ufe0f Suspicious ports detected:\n\n" + "\n".join(alerts)
        messagebox.showwarning("Security Alert", alert_msg)  # Show a warning popup to the user

    # Play an alert sound if enabled and the sound file exists
    bark_path = os.path.join(os.path.dirname(__file__), "bark.mp3")
    if self.sound_enabled.get() and os.path.exists(bark_path):
        try:
            playsound(bark_path, block=False)  # Play sound without blocking execution
        except Exception as sound_error:
            print(f"[Sound Error] Could not play bark.mp3: {sound_error}")  # Log the error

   