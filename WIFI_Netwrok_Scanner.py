import subprocess
import re
import platform
import time
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from threading import Thread
from datetime import datetime

# Check platform and dependencies
if platform.system() == "Windows":
    try:
        import comtypes
    except ImportError:
        print("This tool requires 'comtypes' on Windows. Install with: pip install comtypes")
        sys.exit(1)
elif platform.system() == "Linux" and os.geteuid() != 0:
    print("This tool requires root privileges on Linux")
    sys.exit(1)

import pywifi
from pywifi import const

class WiFiScanner:
    def __init__(self):
        self.os_type = platform.system()
        self.wifi = pywifi.PyWiFi()
        self.iface = self.wifi.interfaces()[0] if self.wifi.interfaces() else None
        self.handshake_dir = "handshakes"
        self.wordlist_dir = "wordlists"
        self.create_directories()
    def create_directories(self):
        """Create required directories if they don't exist"""
        os.makedirs(self.handshake_dir, exist_ok=True)
        os.makedirs(self.wordlist_dir, exist_ok=True)

    def check_driver_compatibility(self):
        """More robust compatibility check"""
        try:
            if not self.iface:
                return False, "No wireless interface found"
            
            # Basic check if we can access interface properties
            if not hasattr(self.iface, 'name'):
                return False, "Incompatible driver interface"
                
            # Skip monitor mode check if modes() isn't available
            if hasattr(self.iface, 'modes'):
                modes = self.iface.modes()
                if const.IFACE_MODE_MONITOR not in modes:
                    return False, "Driver doesn't support monitor mode"
            
            return True, "Driver detected (basic scanning supported)"
        except Exception as e:
            return False, f"Driver check failed: {str(e)}"
            
    def get_chipset_info(self):
        """Get WiFi chipset information"""
        try:
            if self.os_type == "Linux":
                result = subprocess.run(['lspci'], capture_output=True, text=True)
                wifi_devices = [line for line in result.stdout.split('\n') if 'Network controller' in line or 'Wireless' in line]
                return "\n".join(wifi_devices) if wifi_devices else "No WiFi chipset info found"
            elif self.os_type == "Windows":
                result = subprocess.run(['netsh', 'wlan', 'show', 'drivers'], capture_output=True, text=True)
                return result.stdout
            else:
                return "Unsupported OS for chipset detection"
        except Exception as e:
            return f"Error getting chipset info: {str(e)}"

    def scan_networks(self):
        """Scan for available WiFi networks"""
        networks = []
        try:
            if not self.iface:
                return networks
            
            self.iface.scan()
            time.sleep(5)  # Wait for scan to complete
            
            for profile in self.iface.scan_results():
                network = {
                    'ssid': profile.ssid,
                    'bssid': profile.bssid,
                    'signal': profile.signal,
                    'frequency': profile.freq,
                    'encryption': self.get_encryption_type(profile.akm),
                    'channel': self.freq_to_channel(profile.freq)
                }
                networks.append(network)
                
        except Exception as e:
            print(f"Scan error: {str(e)}")
            
        return sorted(networks, key=lambda x: x['signal'], reverse=True)

    def get_encryption_type(self, akm_list):
        """Determine encryption type from AKM list"""
        if not akm_list:
            return "Open"
        if const.AKM_TYPE_NONE in akm_list:
            return "Open"
        elif const.AKM_TYPE_WPA in akm_list:
            return "WPA"
        elif const.AKM_TYPE_WPAPSK in akm_list:
            return "WPA-PSK"
        elif const.AKM_TYPE_WPA2 in akm_list:
            return "WPA2"
        elif const.AKM_TYPE_WPA2PSK in akm_list:
            return "WPA2-PSK"
        elif const.AKM_TYPE_WPA3 in akm_list:
            return "WPA3"
        else:
            return "Unknown"

    def freq_to_channel(self, freq):
        """Convert frequency to WiFi channel"""
        if 2412 <= freq <= 2484:    # 2.4 GHz
            return (freq - 2412) // 5 + 1
        elif 5170 <= freq <= 5925:  # 5 GHz & 6 GHz
            return (freq - 5170) // 5 + 34
        else:
            return 0

class WiFiScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced WiFi Scanner")
        self.root.geometry("1000x800")
        
        self.scanner = WiFiScanner()
        self.current_scan = []
        self.selected_network = None
        
        self.create_widgets()
        self.check_system()
        
    def check_system(self):
        """Check system compatibility at startup"""
        compat, msg = self.scanner.check_driver_compatibility()
        if not compat:
            messagebox.showwarning("Compatibility Issue", msg)
        
        chipset_info = self.scanner.get_chipset_info()
        self.chipset_text.config(state=tk.NORMAL)
        self.chipset_text.delete(1.0, tk.END)
        self.chipset_text.insert(tk.END, chipset_info)
        self.chipset_text.config(state=tk.DISABLED)
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        # Scan button
        scan_btn = ttk.Button(button_frame, text="Scan Networks", command=self.start_scan)
        scan_btn.pack(side=tk.LEFT, padx=5)
        
        # Chipset info button
        chipset_btn = ttk.Button(button_frame, text="Show Chipset Info", 
                                command=self.show_chipset_info)
        chipset_btn.pack(side=tk.RIGHT, padx=5)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Networks tab
        networks_tab = ttk.Frame(self.notebook)
        
        # Treeview with scrollbar
        tree_frame = ttk.Frame(networks_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create Treeview
        self.networks_tree = ttk.Treeview(tree_frame, columns=('SSID', 'BSSID', 'Signal', 'Channel', 'Encryption'), show='headings')
        self.networks_tree.heading('SSID', text='SSID')
        self.networks_tree.heading('BSSID', text='BSSID')
        self.networks_tree.heading('Signal', text='Signal (dBm)')
        self.networks_tree.heading('Channel', text='Channel')
        self.networks_tree.heading('Encryption', text='Encryption')
        
        # Add scrollbar
        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.networks_tree.yview)
        self.networks_tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.networks_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Network actions frame
        action_frame = ttk.Frame(networks_tab)
        action_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Crack button
        self.crack_btn = ttk.Button(action_frame, text="Crack Password", 
                                  command=self.start_cracking, state=tk.DISABLED)
        self.crack_btn.pack(side=tk.LEFT, padx=5)
        
        # Save handshake button
        self.save_btn = ttk.Button(action_frame, text="Save Handshake", 
                                command=self.save_handshake, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=5)
        
        # Bind tree selection
        self.networks_tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        
        # Chipset info tab
        chipset_tab = ttk.Frame(self.notebook)
        self.chipset_text = scrolledtext.ScrolledText(chipset_tab, wrap=tk.WORD)
        self.chipset_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.chipset_text.config(state=tk.DISABLED)
        
        # Password cracking tab
        crack_tab = ttk.Frame(self.notebook)
        self.setup_cracking_tab(crack_tab)
        
        # Add tabs to notebook
        self.notebook.add(networks_tab, text="Networks")
        self.notebook.add(chipset_tab, text="Chipset Info")
        self.notebook.add(crack_tab, text="Password Cracking")
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def setup_cracking_tab(self, tab):
        """Set up password cracking tab"""
        frame = ttk.Frame(tab, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Network info
        ttk.Label(frame, text="Target Network:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.target_ssid = ttk.Label(frame, text="None selected")
        self.target_ssid.grid(row=0, column=1, sticky=tk.W, pady=2)
        
        # Handshake file
        ttk.Label(frame, text="Handshake File:").grid(row=1, column=0, sticky=tk.W, pady=2)
        handshake_frame = ttk.Frame(frame)
        handshake_frame.grid(row=1, column=1, sticky=tk.W, pady=2)
        self.handshake_entry = ttk.Entry(handshake_frame, width=40)
        self.handshake_entry.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(handshake_frame, text="Browse", 
                 command=self.browse_handshake).pack(side=tk.LEFT)
        
        # Wordlist file
        ttk.Label(frame, text="Wordlist File:").grid(row=2, column=0, sticky=tk.W, pady=2)
        wordlist_frame = ttk.Frame(frame)
        wordlist_frame.grid(row=2, column=1, sticky=tk.W, pady=2)
        self.wordlist_entry = ttk.Entry(wordlist_frame, width=40)
        self.wordlist_entry.pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(wordlist_frame, text="Browse", 
                 command=self.browse_wordlist).pack(side=tk.LEFT)
        
        # Start button
        ttk.Button(frame, text="Start Cracking", 
                 command=self.start_cracking_thread).grid(row=3, column=1, pady=10, sticky=tk.W)
        
        # Results area
        ttk.Label(frame, text="Results:").grid(row=4, column=0, sticky=tk.NW, pady=2)
        self.results_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=10)
        self.results_text.grid(row=4, column=1, sticky=tk.W+tk.E, pady=2)
        self.results_text.config(state=tk.DISABLED)
        
    def browse_handshake(self):
        file = filedialog.askopenfilename(
            initialdir=self.scanner.handshake_dir,
            title="Select Handshake File",
            filetypes=(("Capture Files", "*.pcap *.cap"), ("All Files", "*.*"))
        )
        if file:
            self.handshake_entry.delete(0, tk.END)
            self.handshake_entry.insert(0, file)
    
    def browse_wordlist(self):
        file = filedialog.askopenfilename(
            initialdir=self.scanner.wordlist_dir,
            title="Select Wordlist File",
            filetypes=(("Text Files", "*.txt"), ("All Files", "*.*"))
        )
        if file:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, file)
    
    def start_scan(self):
        """Start network scanning in a separate thread"""
        self.status_var.set("Scanning networks...")
        self.networks_tree.delete(*self.networks_tree.get_children())
        Thread(target=self.scan_networks_thread, daemon=True).start()
        
    def scan_networks_thread(self):
        """Thread function for scanning networks"""
        networks = self.scanner.scan_networks()
        self.current_scan = networks
        
        for network in networks:
            self.root.after(0, self.add_network_to_tree, network)
        
        self.root.after(0, lambda: self.status_var.set(f"Scan complete - {len(networks)} networks found"))
        
    def add_network_to_tree(self, network):
        """Add a network to the treeview"""
        self.networks_tree.insert('', 'end', values=(
            network['ssid'],
            network['bssid'],
            network['signal'],
            network['channel'],
            network['encryption']
        ))
        
    def on_tree_select(self, event):
        """Handle network selection"""
        selected = self.networks_tree.selection()
        if not selected:
            return
            
        item = self.networks_tree.item(selected[0])
        values = item['values']
        self.selected_network = {
            'ssid': values[0],
            'bssid': values[1],
            'encryption': values[4]
        }
        
        # Enable buttons if encryption is not open
        if self.selected_network['encryption'] != "Open":
            self.crack_btn.config(state=tk.NORMAL)
            self.save_btn.config(state=tk.NORMAL)
            self.target_ssid.config(text=self.selected_network['ssid'])
        else:
            self.crack_btn.config(state=tk.DISABLED)
            self.save_btn.config(state=tk.DISABLED)
        
    def save_handshake(self):
        """Save handshake for selected network (stub functionality)"""
        if not self.selected_network:
            return
            
        filename = f"{self.selected_network['ssid']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        filepath = os.path.join(self.scanner.handshake_dir, filename)
        
        # In a real implementation, you would capture the handshake here
        with open(filepath, 'w') as f:
            f.write("Handshake capture would be saved here in a real implementation")
            
        messagebox.showinfo("Handshake Saved", 
                          f"Handshake saved as {filename}\n(Simulated for demo purposes)")
    
    def start_cracking(self):
        """Switch to cracking tab when Crack button is pressed"""
        self.notebook.select(2)  # Switch to cracking tab
    
    def start_cracking_thread(self):
        """Start password cracking process"""
        handshake = self.handshake_entry.get()
        wordlist = self.wordlist_entry.get()
        
        if not handshake or not wordlist:
            messagebox.showerror("Error", "Both handshake and wordlist files are required")
            return
            
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Starting cracking process...\n")
        self.results_text.config(state=tk.DISABLED)
        
        Thread(target=self.run_cracking, args=(handshake, wordlist), daemon=True).start()
    
    def run_cracking(self, handshake, wordlist):
        """Simulated password cracking process"""
        # In a real implementation, you would use aircrack-ng or similar here
        self.root.after(0, lambda: self.status_var.set("Cracking password..."))
        
        # Simulate cracking process
        for i in range(1, 101):
            time.sleep(0.05)
            self.root.after(0, self.update_progress, i, handshake)
            
        # Simulate result
        self.root.after(0, self.show_cracking_result, "Password found: 'securepassword123'")
    
    def update_progress(self, percent, handshake):
        """Update cracking progress in UI"""
        self.status_var.set(f"Cracking {os.path.basename(handshake)} - {percent}%")
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, f"Trying password {percent} of 100...\n")
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)
    
    def show_cracking_result(self, result):
        """Show final cracking result"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, f"\n{result}\n")
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.status_var.set("Cracking complete")
        messagebox.showinfo("Result", result)
        
    def show_chipset_info(self):
        """Show chipset information in dialog"""
        chipset_info = self.scanner.get_chipset_info()
        messagebox.showinfo("Chipset Information", chipset_info)

if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiScannerApp(root)
    root.mainloop()
