# Threat Hunt Case Study: Identifying Internal PowerShell-Based Port Scanning via Microsoft Defender

## Executive Summary

A performance degradation was reported across legacy devices within the internal `10.0.0.0/16` network. Initial triage ruled out external denial-of-service activity, prompting an internal threat hunt. Using Microsoft Defender for Endpoint (MDE) Advanced Hunting telemetry, investigation revealed an internal host executing a PowerShell script that performed extensive TCP port scanning against another internal device. Correlation across network, file, and process events confirmed the download and execution of a PowerShell script (`portscan.ps1`) using `ExecutionPolicy Bypass`. The activity was assessed as internal reconnaissance and mapped to relevant MITRE ATT&CK techniques.

---

## Environment & Tools

* **Microsoft Defender for Endpoint (Advanced Hunting)**
* **Windows 10 VM** (internal lab network)
* **KQL (Kusto Query Language)**
* **PowerShell**

---

## Hunt Objective

Determine the root cause of reported internal network slowdowns and assess whether the activity represented malicious or suspicious behavior requiring escalation.

---

## Initial Detection: Network Anomaly

Analysis of network telemetry identified:

* Excessive **failed TCP connection attempts** within the internal network
* A **single internal source** initiating connections
* **Numerous destination ports** targeted on a single internal IP
* A pattern consistent with **internal port scanning** rather than application failure or external attack

These indicators suggested reconnaissance activity originating from within the network.

---

## Investigation & Correlation

### Network Evidence (DeviceNetworkEvents)

* High volume of `ConnectionFailed` events
* Repeated connection attempts across many TCP destination ports
* Targeted internal host (`10.0.0.5`)

This behavior explained the observed performance degradation on legacy systems.

### File Activity (DeviceFileEvents)

Endpoint file telemetry revealed:

* Download of a PowerShell script named `portscan.ps1`
* File written shortly **before** the onset of network scanning
* Download method consistent with scripted or automated execution

### Process Activity (DeviceProcessEvents)

Process telemetry confirmed:

* Execution of the script via **PowerShell**
* Use of `ExecutionPolicy Bypass`, allowing non-interactive execution
* Script execution without user prompts

No evidence of lateral movement or additional compromised hosts was identified beyond the originating device.

---

## MITRE ATT&CK Mapping

The observed activity aligns with the following MITRE ATT&CK techniques:

* **Network Service Scanning** – Extensive connection attempts across many TCP ports
* **Command and Scripting Interpreter: PowerShell** – Script execution via PowerShell
* **Ingress Tool Transfer** – Script downloaded from an external source prior to execution
* **Impair Defenses** – Use of `ExecutionPolicy Bypass` to allow script execution

---

## Impact Assessment

Although most connection attempts failed, the volume and frequency of scanning activity consumed network and system resources on older devices, contributing to the reported network performance degradation.

---

## Response & Recommendations

* Restrict PowerShell usage via **Constrained Language Mode** or **application control**
* Monitor for excessive internal connection failures as an indicator of reconnaissance
* Implement **internal network segmentation** or host-based firewall rules for legacy systems
* Create a **custom MDE detection rule** for PowerShell-initiated port scanning behavior

---

## Key Takeaways

* Internal reconnaissance can manifest as performance issues rather than overt alerts
* Correlating **network, file, and process telemetry** is critical for accurate attribution
* Defender Advanced Hunting enables effective investigation of stealthy, non-malware activity

---

## Appendix A: Supporting Queries

> The following queries were used to validate findings and correlate evidence.

### Identify Excessive Failed Connections

```kql
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize FailedAttempts = count() by DeviceName, LocalIP, RemoteIP
| order by FailedAttempts desc
```

### Identify Targeted Ports

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName == "powershell.exe"
| where InitiatingProcessAccountDomain == "nickscenario1"
| where RemoteIP == "10.0.0.5"
| project ActionType, RemotePort
```

### Identify Script Download

```kql
DeviceFileEvents
| where FileName == "portscan.ps1"
| order by Timestamp desc
```

### Identify Script Execution

```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "ExecutionPolicy"
| order by Timestamp desc
```

---

## Disclaimer

This investigation was conducted in a controlled lab environment for educational and portfolio purposes. No production systems were affected.

## What I Learned
- How to correlate network, file, and process telemetry in Microsoft Defender
- How internal reconnaissance can present as performance degradation
- How to structure a threat hunt narrative using MITRE ATT&CK

