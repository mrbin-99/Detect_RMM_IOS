import os
import psutil
import requests
import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor

"""
This program is designed to detect the presence of various Remote Monitoring and Management (RMM) tools
and security-related executables on a macOS system. RMM tools are often used for legitimate remote access
but can also be abused by attackers for persistence, data exfiltration, or unauthorized remote control.

Key Features:
1. Process Detection – Scans currently running processes to identify active RMM tools.
2. File System Search – Checks common macOS installation directories (`/Applications`, `/Library`, `~/Library`) 
   to find known RMM tool executables.
3. Hash-Based Verification – 
   - Computes SHA-256 hashes of detected executables.
   - Cross-checks with known malicious hashes from Abuse.ch Malware Bazaar and other OSINT sources.
4. Multi-Threaded Execution – Uses Python’s `ThreadPoolExecutor` for faster scanning.
5. Comprehensive Reporting – Saves the results in a detailed log file on the user’s Desktop.

Purpose & Use Cases:
- Security Analysts & Incident Responders – Helps in identifying unauthorized or suspicious RMM tools that could indicate compromise.
- IT Administrators – Assists in monitoring and auditing installed remote access software to prevent abuse.
- Threat Hunting Teams – Enhances proactive defense by comparing local file hashes against threat intelligence databases.
- Red Teaming & Pentesting – Used to verify the presence of known RMM tools in controlled environments.

How It Works:
1. The script loads a list of known RMM tools (e.g., AnyDesk, TeamViewer, RemotePC, ZohoAssist).
2. It scans running processes and common directories for traces of these tools.
3. If a tool is found, it computes its hash and checks against the Abuse.ch Malware Bazaar API.
4. The results are displayed in a structured output, indicating:
   - Found (with details like file path, hash, and process information)
   - Not Found (if no traces were detected)
5. The final report is saved as a detailed log file on the Desktop.

Security Considerations:
- Limited access in macOS sandboxing – Some system directories may require root privileges to scan.
- This script does NOT modify or remove any files – It is safe for auditing purposes.
- Network access is required for hash lookups via Abuse.ch API.

Reference:
This script is inspired by the Ransomware Tool Matrix project on GitHub:  
[https://github.com/BushidoUK/Ransomware-Tool-Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix)

By using this script, security teams and administrators can enhance macOS endpoint monitoring 
and detect unauthorized use of remote access tools, which is a common attack technique.
"""


# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

TOOLS = [
    "TeamViewer", "AnyDesk", "RemotePC", "LogMeIn", "GoToAssist", "ScreenConnect", "Splashtop", "Chrome Remote Desktop",
    "Parsec", "RustDesk", "ZohoAssist"
]

SEARCH_PATHS = [
    "/Applications",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/System/Library",
    "/Library",
    os.path.expanduser("~/Library"),
    "/private/var",
    "/Library/LaunchDaemons",
    "/Library/LaunchAgents",
    "/System/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",
    os.path.expanduser("~/Library/LaunchAgents"),
    "/private/tmp",
    "/tmp",
    "/private/var/log",
    "/var/log",
    "/private/var/db/LocationServices",
    "/private/var/db/analyticsd",
    "/var/db",
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Library/Preferences"),
    os.path.expanduser("~/Library/Application Support"),
    "/private/var/db/dslocal/nodes/Default/users",
    "/Volumes",
    "/private/var/backup",
    "/.hidden",
    "/private/etc",
    "/System/Library/Extensions",
    "/Library/Extensions",
    "/usr/sbin",
    "/usr/local/sbin",
    "/private/var/tmp"
]

def get_hash_from_abuse_ch(tool):
    """Fetch known malware hashes for a given tool from Abuse.ch Malware Bazaar API using the 'tag' option."""
    logging.debug(f"Fetching hashes for {tool} from Abuse.ch")
    url = "https://mb-api.abuse.ch/api/v1/"
    payload = {"query": "get_taginfo", "tag": tool}
    
    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()
        if "data" in data and data["data"]:
            hashes = [entry["sha256_hash"] for entry in data["data"]]
            logging.info(f"Retrieved {len(hashes)} hashes for {tool} from Abuse.ch.")
            return hashes
        else:
            logging.warning(f"No hashes found for {tool} on Abuse.ch.")
            return []
    except requests.RequestException as e:
        logging.error(f"API request failed: {e}")
    return []

def get_file_hash(file_path):
    """Compute SHA-256 hash of a given file."""
    logging.debug(f"Computing hash for file: {file_path}")
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logging.error(f"Error computing hash for {file_path}: {e}")
        return None

def check_process(tool):
    """Check if the tool is running as a process."""
    logging.debug(f"Checking running processes for tool: {tool}")
    try:
        for proc in psutil.process_iter(['name', 'exe', 'cmdline']):
            if tool.lower() in proc.info['name'].lower():
                logging.info(f"Process for {tool} found: {proc.info['name']} at {proc.info['exe']}")
                logging.debug(f"Process command line: {proc.info['cmdline']}")
                return True
    except Exception as e:
        logging.error(f"Error checking process for {tool}: {e}")
    return False

def check_files(tool):
    """Check if the tool executable exists in common paths and compute its hash."""
    logging.debug(f"Checking files for tool: {tool}")
    for path in SEARCH_PATHS:
        logging.debug(f"Searching in path: {path}")
        try:
            for root, _, files in os.walk(path):
                for file in files:
                    if tool.lower() in file.lower():
                        file_path = os.path.join(root, file)
                        file_hash = get_file_hash(file_path)
                        logging.info(f"File found for {tool}: {file_path}")
                        return file_path, file_hash
        except Exception as e:
            logging.error(f"Error checking files for {tool} in {path}: {e}")
    return None, None

def check_tool(tool):
    """Check all detection methods for a given tool."""
    logging.info(f"Checking {tool}...")
    process_running = check_process(tool)
    file_path, local_hash = check_files(tool)
    abuse_ch_hashes = get_hash_from_abuse_ch(tool)

    status = f"{tool} - Not Found"
    if process_running or file_path or abuse_ch_hashes:
        status = f"{tool} - FOUND"
        if file_path:
            status += f"\n    Found Tool on System: {file_path}"
            if local_hash:
                status += f"\n    Computed SHA-256: {local_hash}"
                if local_hash in abuse_ch_hashes:
                    status += f"\n    Local file hash matches a known malicious hash!"
                else:
                    status += f"\n    No known malicious hash match"
        if process_running:
            status += f"\n    Running Process Detected"
        if abuse_ch_hashes:
            status += f"\n    Found Hashes from Abuse.ch: {', '.join(abuse_ch_hashes)}"
        else:
            status += f"\n    No known hashes from Abuse.ch"
    
    logging.info(status)
    return status

def save_report(results, save_path=None):
    """Save the results to a specified path, defaulting to the Desktop if no path is provided."""
    if not save_path:
        save_path = os.path.join(os.path.expanduser("~/Desktop"), "Tool_Detection_Report.txt")
    logging.debug(f"Saving report to: {save_path}")
    try:
        with open(save_path, "w", encoding="utf-8") as report_file:
            report_file.write("\n".join(results))
        logging.info(f"Scan complete! Results saved to: {save_path}")
    except Exception as e:
        logging.error(f"Error saving report: {e}")

def main(save_path=None):
    """Main function to scan for tools."""
    logging.info("Checking tools... Please wait.")
    results = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        for tool in TOOLS:
            results.append(executor.submit(check_tool, tool).result())

    save_report(results, save_path)

if __name__ == "__main__":
    # You can pass the save path as an argument to main() if needed
    main()
