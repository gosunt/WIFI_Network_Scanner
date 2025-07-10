# WIFI_Network_Scanner

## Description
This WiFi Network Scanner is a Python GUI application that allows you to:
- Scan for nearby WiFi networks and display detailed information (SSID, BSSID, signal strength, channel, encryption type)
- View your wireless chipset/driver information
- Simulate WiFi password cracking (for educational purposes)
- Save simulated handshake captures

The tool provides a user-friendly interface to analyze wireless networks and understand WiFi security concepts. Note that actual password cracking functionality is simulated for legal/educational purposes only.

## Features
- Cross-platform support (Windows/Linux)
- Network scanning with signal strength sorting
- Encryption type detection (WPA2, WPA3, etc.)
- Chipset/driver information display
- Simulated handshake capture
- Simulated password cracking with progress tracking
- Organized file management (handshakes/wordlists directories)

## Usage

### Prerequisites
- Python 3.x
- Required packages:
  ```
  (install via `pip install -r requirements.txt`):
  ```
  ```
  pywifi
  comtypes (Windows only)

### Running the Application
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the script:
   ```bash
   python WIFI_Network_Scanner.py
   ```

   **Note for Linux users**: Run with root privileges:
   ```bash
   sudo python WIFI_Network_Scanner.py
   
   ```

## OUTPUT



### Interface Guide
1. **Main Window**:
   - **Scan Networks**: Discovers nearby WiFi access points
   - **Show Chipset Info**: Displays your wireless adapter details

2. **Networks Tab**:
   - Displays all detected networks in a sortable table
   - Select a network to enable cracking/saving options

3. **Chipset Info Tab**:
   - Shows detailed information about your wireless hardware

4. **Password Cracking Tab**:
   - Select a handshake file (simulated) and wordlist
   - Start simulated cracking process
   - View progress and results

### Important Notes
- This tool is for educational purposes only
- Actual password cracking requires additional tools (aircrack-ng, hashcat)
- Always ensure you have permission to scan networks
- Some features require root/admin privileges

## Legal Disclaimer
Unauthorized network scanning or cracking may violate laws in your jurisdiction. Use this tool only on networks you own or have permission to test. The developers assume no liability for misuse of this software.

For actual penetration testing, consider using established tools like Kali Linux with proper authorization.
