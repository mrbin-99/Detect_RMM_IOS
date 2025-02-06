# Detect_RMM_IOS
his program is designed to detect the presence of various Remote Monitoring and Management (RMM) tools
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
https://github.com/BushidoUK/Ransomware-Tool-Matrix

By using this script, security teams and administrators can enhance macOS endpoint monitoring 
and detect unauthorized use of remote access tools, which is a common attack technique.
