# Lightweight Cross-Platform Host Hygiene Agent

A zero-external-binary-dependency, cross-platform host hygiene and active process triage agent in Python for **Windows**, **macOS**, and **Linux**.

---

## Key Features

1. **Pure Python Process Inspection (Zero External Binary Dependencies)**
   - **Windows**: Built on standard library `ctypes` calling `kernel32.dll` (`CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`, and `QueryFullProcessImageNameW`). No `psutil` or external compilers required.
   - **Linux**: Direct parser for the Linux kernel `/proc` filesystem (`/proc/[pid]/comm`, `/proc/[pid]/cmdline`, `/proc/[pid]/status`, and symlink `/proc/[pid]/exe`). No external binaries (`ps`, `pgrep`) required.
   - **macOS (Darwin)**: Native `libproc` invocation via `ctypes` (`proc_listpids`, `proc_name`, `proc_pidpath`) with POSIX system fallback.

2. **Noise Reduction: OS Baseline Filtering**
   - Automatically filters out legitimate core operating system components (e.g., `systemd`, `systemd-journald`, `kworker/*` on Linux; `launchd`, `WindowServer`, `cfprefsd` on macOS; `svchost.exe`, `services.exe`, `lsass.exe`, `csrss.exe` on Windows).
   - Typically achieves a **50% to 80% noise reduction**, allowing security analysis to concentrate strictly on unfamiliar candidates.
   - Supports user-defined baseline whitelists via command-line arguments and JSON configuration files.

3. **Advanced Anomaly & Typosquatting Detection Engine**
   - **Homoglyph & Deceptive Substitution**: Flags character substitutions designed to fool human reviewers (e.g., `"svch0st"` [0 -> o], `"1sass"` [1 -> l], `"expl0rer"`, `"systemcl"` [cl -> d]).
   - **Damerau-Levenshtein Distance**: Detects transpositions, deletions, and insertions targeting protected system processes (e.g., `scvhost`, `svchostt`, `lsasss`, `csrsss`, `systemdd`).
   - **Masquerading Suffixes**: Flags deceptive name appendages (e.g., `svchost32.exe`, `services64.exe`, `svchost_updater.exe`).
   - **Known Threat Indicators (IOCs)**: Built-in catalog of offensive security tools, C2 implants, credential dumpers, and cryptominers (e.g., `mimikatz`, `cobaltstrike`, `beacon`, `meterpreter`, `xmrig`, `nc.exe`, `chisel`, `ligolo`, `sliver`, `havoc`, `linpeas`, `winpeas`, `lockbit`, etc.).
   - **Unicode & Bidirectional Homoglyph Injection**: Detects non-ASCII Cyrillic homoglyphs (e.g., Cyrillic `о` masquerading as Latin `o`) and invisible/zero-width characters (`U+200B`, `U+202E`).
   - **Suspicious Naming Patterns**: Identifies double extensions (e.g., `invoice.pdf.exe`), trailing delimiter evasion (`"svchost.exe "`), and cross-platform binary anomalies (e.g., `.exe` binaries running natively on Linux/macOS).

4. **AI Triage Interface (Gemini LLM)**
   - Formulates a structured prompt delivering context, parentage, path, and anomaly flags to the LLM.
   - Evaluates:
     - **Process Purpose**: Technical summary of what the software normally does.
     - **Risk Rating**: `Benign`, `Suspicious`, or `Malicious`.
     - **Daily Hygiene Score (0-100)**: Quantitative health rating of the host (100 = pristine, 0 = active intrusion).
     - **Actionable Recommendations**: Clear, prioritized remediation checklist for endpoint responders.
   - Communicates via pure standard library `urllib` (no SDK or package installation needed).

5. **Deterministic Offline Fallback Mode**
   - Seamlessly activates when no `GEMINI_API_KEY` is present or when `--offline` is specified.
   - Evaluates processes against an embedded software catalog (browsers, IDEs, interpreters, shells, productivity apps, cloud agents).
   - Generates an mathematically grounded **Daily Hygiene Score** and tactical incident response guidance.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |       Host Process Collection         |
                      | (Windows ctypes | Linux /proc | macOS)|
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |         OS Baseline Filter            |
                      |  (Noise reduction: 50% - 80% filtered)|
                      +---------------------------------------+
                                          |
                                          v [Candidate Processes]
                      +---------------------------------------+
                      |       Anomaly Detection Engine        |
                      | - Typosquatting (svch0st, Damerau)    |
                      | - IOC Matching (mimikatz, xmrig, etc.)|
                      | - Unicode / Homoglyphs / Double Exts  |
                      +---------------------------------------+
                                          |
                                          v
                         +---------------------------------+
                         |      Is API Key Available?      |
                         +---------------------------------+
                                /                   \
                         Yes   /                     \  No / --offline
                              v                       v
               +-----------------------+   +-----------------------+
               |    AI Triage Engine   |   | Offline Triage Engine |
               | (Gemini REST Prompt)  |   | (Rule-based Fallback) |
               +-----------------------+   +-----------------------+
                              \                       /
                               \                     /
                                v                   v
                      +---------------------------------------+
                      |        Triage Report & Scoring        |
                      | - Daily Hygiene Score (0-100)         |
                      | - Purpose & Risk Rating               |
                      | - Actionable Recommendations          |
                      | - Terminal Dashboard & JSON Export    |
                      +---------------------------------------+
```

---

## Directory Structure

```
host_hygiene/
├── __init__.py
├── agent.py                 # Core agent orchestrator & CLI entrypoint
├── collector/
│   ├── __init__.py
│   ├── base.py              # BaseProcessCollector and ProcessInfo model
│   ├── windows.py           # Pure ctypes Toolhelp32Snapshot collector
│   ├── linux.py             # Pure /proc filesystem collector
│   ├── darwin.py            # macOS libproc ctypes and POSIX collector
│   └── factory.py           # OS detection & collector factory
├── baseline/
│   ├── __init__.py
│   ├── os_filter.py         # OSBaselineFilter noise reduction engine
│   └── signatures.py        # Baseline signatures & protected core binaries
├── detector/
│   ├── __init__.py
│   ├── anomaly_engine.py    # Detection engine (typosquatting, homoglyphs, IOCs)
│   ├── ioc_database.py      # Known malware, C2, miner, and hacking tool database
│   └── similarity.py        # Homoglyph normalization & Damerau-Levenshtein metrics
├── triage/
│   ├── __init__.py
│   ├── base.py              # TriageReport and ProcessTriageEvaluation models
│   ├── ai_triage.py         # Gemini LLM triage client (zero external packages)
│   └── offline_triage.py    # Fallback offline heuristic triage engine
└── reporter/
    ├── __init__.py
    ├── console.py           # Terminal dashboard with color badges & tables
    └── json_exporter.py     # JSON export utility

tests/
├── test_collector.py        # Collector tests & mocked Linux /proc test
├── test_baseline.py         # OS baseline noise filtering tests
├── test_anomaly.py          # Typosquatting, homoglyphs, and IOC detection tests
├── test_triage.py           # Offline scoring & AI prompt parsing tests
└── test_agent_integration.py# Full end-to-end integration tests

run_agent.py                 # Root CLI script
simulate_triage.py           # Simulated test battery across OSs
```

---

## Installation & Requirements

- **Python**: 3.8+ (Tested on Python 3.12)
- **Dependencies**: **None** (100% Python Standard Library)

---

## Quick Start & Usage

### 1. Run Live Host Audit (Offline Fallback Mode)
```bash
python run_agent.py --offline
```

### 2. Run Live Host Audit with AI Triage
Set your Gemini API key:
```bash
# On Windows (PowerShell)
$env:GEMINI_API_KEY = "your-api-key-here"

# On Linux / macOS
export GEMINI_API_KEY="your-api-key-here"

# Run Agent
python run_agent.py
```
Or pass it explicitly:
```bash
python run_agent.py --api-key "your-api-key-here" --model gemini-2.5-flash
```

### 3. Export Audit Results to JSON
```bash
python run_agent.py --offline --json-out host_hygiene_report.json
```

### 4. Custom Whitelisting
Add custom internal software to the baseline:
```bash
python run_agent.py --whitelist my_internal_daemon.exe custom_agent
```
Or specify a JSON whitelist file:
```bash
python run_agent.py --whitelist-file enterprise_baseline.json
```

### 5. Automated Host Compliance Verification
Enforce a minimum Daily Hygiene Score (e.g., fail if score is below 80):
```bash
python run_agent.py --offline --min-score-fail 80
```

---

## Testing & Verification

### Running the Test Suite
All 26 unit and integration tests execute with zero external packages:
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

### Running Simulated Attack Batteries
Verify detection of typosquatting (`svch0st.exe`), IOCs (`mimikatz`, `xmrig`), and evasion patterns on simulated hosts:
```bash
# Simulate Windows attack battery
python simulate_triage.py --platform windows

# Simulate Linux attack battery
python simulate_triage.py --platform linux

# Simulate macOS attack battery
python simulate_triage.py --platform darwin
```

---

## Sample Console Output

```
================================================================================
          HOST HYGIENE & ACTIVE PROCESS TRIAGE AGENT
================================================================================

--- HOST HYGIENE SUMMARY ---
  Operating System:        WINDOWS
  Triage Mode:             OFFLINE_FALLBACK 
  Total Processes Seen:    24
  OS Baseline Noise Filter:12 processes filtered (50.0% reduction)
  Unclassified Candidates: 12
  Anomalies Flagged:       9
  Overall Host Risk:       [CRITICAL]
  Daily Hygiene Score:     0/100 (CRITICAL RISKS DETECTED)

  Summary: High-priority threat indicators detected! Found 4 malicious or heavily disguised process(es). Immediate host remediation required.

--- DETECTED ANOMALIES & SUSPICIOUS NAMING PATTERNS (9) ---
  PID     PROCESS                SEVERITY     TYPE                      DESCRIPTION
  ------ -------------------- ---------- ----------------------- ------------------------------
  9001    svch0st.exe            [CRITICAL]   HOMOGLYPH_TYPOSQUATTING   High-confidence homoglyph typosquatting mimicking core system component 'svchost' (e.g. 0->o, 1->l).
  9002    mimikatz.exe           [CRITICAL]   IOC_MATCH                 Matches known IOC/attack tool (Credential Dumping): Widely known credential extraction and Kerberos ticket manipulation tool.
  9004    xmrig.exe              [CRITICAL]   IOC_MATCH                 Matches known IOC/attack tool (Cryptominer): High-performance Monero (XMR) CPU/GPU miner, frequently dropped by botnets.
  9006    expl\u043erer.exe      [CRITICAL]   UNICODE_HOMOGLYPH_INJEC   Process name utilizes non-ASCII unicode homoglyphs: \u043e (U+043E -> o)
  9003    Q3_Financial_Summary   [HIGH]       DOUBLE_EXTENSION          Process uses deceptive double extension disguised as document/media: '.pdf.exe'
  9005    svchost32.exe          [HIGH]       MASQUERADING_SUFFIX       Process name 'svchost32.exe' appends deceptive suffix to protected system process 'svchost'.
  9007    nc.exe                 [HIGH]       IOC_MATCH                 Matches known IOC/attack tool (Netcat / Reverse Shell): Traditional networking utility frequently abused for interactive reverse shells.

--- UNCLASSIFIED / CANDIDATE PROCESS TRIAGE (12) ---
  * PID 5012   chrome.exe -> [BENIGN]
    Purpose:   Google Chrome web browser
    Reasoning: Recognized standard user application (Google Chrome web browser) with zero anomaly indicators.

  * PID 9001   svch0st.exe -> [MALICIOUS]
    Purpose:   Likely hostile artifact or masquerading payload: High-confidence homoglyph typosquatting mimicking core system component 'svchost' (e.g. 0->o, 1->l).
    Reasoning: Process 'svch0st.exe' triggered critical anomaly detection: HOMOGLYPH_TYPOSQUATTING.
    -> Rec:     Terminate PID 9001 (svch0st.exe) and audit parent process tree.
    -> Rec:     Inspect disk binary at executable location for hash and digital signature.
    -> Rec:     Check for active outbound network sockets using netstat / ss.

--- ACTIONABLE HOST RECOMMENDATIONS ---
  1. Isolate this endpoint from the local network segment immediately.
  2. Collect volatile memory dumps before terminating suspicious processes.
  3. Review authentication logs and outbound network connections.
================================================================================
```
