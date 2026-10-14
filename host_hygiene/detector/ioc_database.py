"""Known IOC names, attack tools, dual-use binaries, and threat indicators."""

from typing import Dict, Any

IOC_DATABASE: Dict[str, Dict[str, Any]] = {
    # Post-Exploitation & Credential Theft
    "mimikatz": {
        "category": "Credential Dumping",
        "severity": "CRITICAL",
        "description": "Widely known credential extraction and Kerberos ticket manipulation tool.",
    },
    "mimi32": {
        "category": "Credential Dumping",
        "severity": "CRITICAL",
        "description": "Mimikatz 32-bit executable alias.",
    },
    "mimi64": {
        "category": "Credential Dumping",
        "severity": "CRITICAL",
        "description": "Mimikatz 64-bit executable alias.",
    },
    "safetykatz": {
        "category": "Credential Dumping",
        "severity": "CRITICAL",
        "description": "Modified Mimikatz that dumps LSASS memory using MiniDumpWriteDump and deletes dump.",
    },
    "rubeus": {
        "category": "Credential Dumping",
        "severity": "CRITICAL",
        "description": "C# toolset for raw Kerberos interaction and abuses (Kerberoasting, AS-REP roasting).",
    },
    "seatbelt": {
        "category": "Post-Exploitation Recon",
        "severity": "HIGH",
        "description": "C# project for local host security status and posture enumeration.",
    },
    "bloodhound": {
        "category": "Active Directory Recon",
        "severity": "HIGH",
        "description": "Active Directory relationship mapping and attack path visualization tool.",
    },
    "sharphound": {
        "category": "Active Directory Recon",
        "severity": "HIGH",
        "description": "C# data collector component of BloodHound.",
    },
    "lazagne": {
        "category": "Credential Dumping",
        "severity": "CRITICAL",
        "description": "Open source application used to retrieve passwords stored on a local computer.",
    },
    "gsecdump": {
        "category": "Credential Dumping",
        "severity": "CRITICAL",
        "description": "Legacy Windows credential and LSA secret dumper.",
    },
    "pwdump": {
        "category": "Credential Dumping",
        "severity": "CRITICAL",
        "description": "SAM database password hash extraction utility.",
    },
    "winpeas": {
        "category": "Privilege Escalation",
        "severity": "HIGH",
        "description": "Automated Windows local privilege escalation enumeration script/binary.",
    },
    "linpeas": {
        "category": "Privilege Escalation",
        "severity": "HIGH",
        "description": "Automated Linux local privilege escalation enumeration script.",
    },

    # Command & Control (C2) / RATs
    "cobaltstrike": {
        "category": "C2 Framework",
        "severity": "CRITICAL",
        "description": "Commercial adversary simulation and command-and-control platform.",
    },
    "beacon": {
        "category": "C2 Agent",
        "severity": "CRITICAL",
        "description": "Cobalt Strike payload/agent name.",
    },
    "meterpreter": {
        "category": "C2 Agent",
        "severity": "CRITICAL",
        "description": "Metasploit in-memory interactive payload and shell.",
    },
    "metasploit": {
        "category": "Exploitation Framework",
        "severity": "CRITICAL",
        "description": "Penetration testing and exploit execution platform.",
    },
    "sliver": {
        "category": "C2 Framework",
        "severity": "CRITICAL",
        "description": "Adversary simulation and C2 framework written in Go.",
    },
    "havoc": {
        "category": "C2 Framework",
        "severity": "CRITICAL",
        "description": "Modern malleable post-exploitation C2 framework.",
    },
    "bruteratel": {
        "category": "C2 Framework",
        "severity": "CRITICAL",
        "description": "Commercial C2 and EDR evasion framework (Brute Ratel C4).",
    },
    "covenant": {
        "category": "C2 Framework",
        "severity": "CRITICAL",
        "description": ".NET command and control platform.",
    },
    "pupy": {
        "category": "Remote Access Trojan",
        "severity": "CRITICAL",
        "description": "Cross-platform open source remote administration tool.",
    },

    # Cryptominers
    "xmrig": {
        "category": "Cryptominer",
        "severity": "CRITICAL",
        "description": "High-performance Monero (XMR) CPU/GPU miner, frequently dropped by botnets.",
    },
    "minerd": {
        "category": "Cryptominer",
        "severity": "CRITICAL",
        "description": "Generic CPU miner daemon for scrypt and sha256d cryptocurrencies.",
    },
    "stratum": {
        "category": "Cryptominer Protocol",
        "severity": "HIGH",
        "description": "Cryptocurrency mining pool communication daemon/proxy.",
    },
    "nbminer": {
        "category": "Cryptominer",
        "severity": "HIGH",
        "description": "Cryptocurrency mining software.",
    },
    "cpuminer": {
        "category": "Cryptominer",
        "severity": "CRITICAL",
        "description": "Multi-threaded CPU miner commonly distributed in cryptojacking campaigns.",
    },

    # Tunneling, Proxies & Port Forwarding (Dual-Use / Lateral Movement)
    "nc.exe": {
        "category": "Netcat / Reverse Shell",
        "severity": "HIGH",
        "description": "Traditional networking utility frequently abused for interactive reverse shells.",
    },
    "ncat": {
        "category": "Netcat / Reverse Shell",
        "severity": "MEDIUM",
        "description": "Nmap project's reimagination of Netcat.",
    },
    "chisel": {
        "category": "Network Tunneling",
        "severity": "HIGH",
        "description": "Fast TCP/UDP tunnel over HTTP secured via SSH, commonly used for pivoting.",
    },
    "ligolo": {
        "category": "Network Pivoting",
        "severity": "HIGH",
        "description": "Simple, lightweight tunneling tool used to establish pivot interfaces via TUN.",
    },
    "ngrok": {
        "category": "Port Forwarding / Exfiltration",
        "severity": "MEDIUM",
        "description": "Ingress reverse proxy tunnel, often leveraged by attackers for C2 without open ports.",
    },
    "frp": {
        "category": "Reverse Proxy Tunnel",
        "severity": "HIGH",
        "description": "Fast reverse proxy to expose local servers, heavily abused in intrusion campaigns.",
    },
    "frpc": {
        "category": "Reverse Proxy Tunnel",
        "severity": "HIGH",
        "description": "FRP reverse proxy client agent.",
    },
    "fscan": {
        "category": "Internal Reconnaissance",
        "severity": "HIGH",
        "description": "Aggressive internal network vulnerability scanner frequently used by threat actors.",
    },

    # Ransomware & Destructive Malware
    "wannacry": {
        "category": "Ransomware",
        "severity": "CRITICAL",
        "description": "EternalBlue-propagated ransomware strain.",
    },
    "lockbit": {
        "category": "Ransomware",
        "severity": "CRITICAL",
        "description": "Prolific Ransomware-as-a-Service (RaaS) strain.",
    },
    "ryuk": {
        "category": "Ransomware",
        "severity": "CRITICAL",
        "description": "Targeted enterprise ransomware associated with Wizard Spider.",
    },
    "revil": {
        "category": "Ransomware",
        "severity": "CRITICAL",
        "description": "Sodinokibi / REvil ransomware payload.",
    },
    "darkside": {
        "category": "Ransomware",
        "severity": "CRITICAL",
        "description": "Targeted enterprise ransomware operation.",
    },
}
