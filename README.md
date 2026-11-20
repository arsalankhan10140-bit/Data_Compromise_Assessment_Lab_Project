LSASS Credential Dumping Detection & Threat Hunting Lab
Overview

This repository demonstrates an end-to-end detection engineering and incident response use case focused on credential dumping from the Local Security Authority Subsystem Service (LSASS) using PowerShell enumeration techniques.

The project simulates an attacker attempting to enumerate and access sensitive LSASS process information to identify potential credential theft activity. The attack simulation is conducted using Atomic Red Team, while multiple security tools are integrated to detect, collect, investigate, and visualize the attack activity.

The primary objective is to demonstrate how security monitoring, endpoint telemetry collection, threat hunting, and forensic analysis can work together to identify suspicious behavior and reconstruct an attack timeline.

Objectives
Develop and validate detection use cases in Wazuh.
Simulate adversary techniques using Atomic Red Team.
Detect suspicious PowerShell activity associated with LSASS enumeration and credential dumping.
Collect endpoint forensic artifacts using Velociraptor.
Perform threat hunting and event analysis using Hayabusa.
Implement and evaluate Sigma detection rules.
Correlate security events and visualize the attacker's timeline.
Demonstrate an end-to-end detection, investigation, and response workflow.
Tools & Technologies
Tool	Purpose
Wazuh	SIEM, endpoint monitoring, security event collection, and detection use cases
Atomic Red Team	Adversary emulation and attack simulation
Velociraptor	Digital forensics and endpoint artifact collection
Hayabusa	Windows event log analysis and threat hunting
Sigma	Detection rule creation and threat detection logic
PowerShell	Attack simulation and enumeration activity
Windows Event Logs	Telemetry source for investigating suspicious activity
Attack Scenario

Attack: Credential Dumping from LSASS through PowerShell Enumeration

MITRE ATT&CK Mapping:

Technique	ID	Description
OS Credential Dumping	T1003	Credential dumping from operating system components
LSASS Memory	T1003.001	Attempt to access credentials stored in LSASS memory
PowerShell	T1059.001	PowerShell execution for enumeration and suspicious activity
Attack Workflow

The lab follows this investigation workflow:

Attack Simulation: Atomic Red Team is used to emulate the LSASS credential access scenario.
Security Monitoring: Wazuh collects endpoint telemetry and evaluates events against configured detection use cases.
Artifact Collection: Velociraptor is used to acquire relevant forensic artifacts from the affected endpoint.
Threat Hunting: Hayabusa analyzes Windows Event Logs to identify suspicious PowerShell execution and related activities.
Detection Engineering: Sigma rules are used to identify suspicious behaviors and support detection logic.
Timeline Analysis: Relevant events are correlated and visualized to reconstruct the sequence of attacker activities.
Investigation & Detection Methodology
1. Attack Simulation – Atomic Red Team

Atomic Red Team is used to simulate adversary behavior associated with LSASS credential dumping.

The objective is to generate realistic endpoint telemetry that can be used to validate detection capabilities and evaluate the effectiveness of security monitoring controls.

2. Detection & Monitoring – Wazuh

Wazuh serves as the centralized security monitoring platform.

The investigation focuses on:

Suspicious PowerShell execution.
Potential LSASS process access.
Unusual process activity.
Security events associated with credential access.
Detection and alert generation through customized use cases.
3. Digital Forensics – Velociraptor

Velociraptor is used to collect endpoint artifacts that support forensic investigation.

Collected artifacts can include:

Windows Event Logs.
PowerShell-related logs.
Process execution information.
Relevant system activity.
Other forensic evidence associated with the simulated attack.
4. Threat Hunting – Hayabusa

Hayabusa is used to analyze Windows Event Logs and identify suspicious activity.

The hunting process focuses on:

PowerShell execution patterns.
Suspicious process activity.
LSASS-related events.
Potential indicators of credential access.
Correlation of events across the attack lifecycle.
5. Detection Rules – Sigma

Sigma rules are incorporated to identify suspicious activity and support reusable detection logic.

The rules help translate observed attacker behavior into detection opportunities that can be adapted to different security monitoring platforms.

6. Attack Timeline Visualization

A timeline is constructed by correlating collected logs and security events from the investigation.

The timeline aims to illustrate:

Initial PowerShell activity.
Enumeration of system processes.
Suspicious interaction with LSASS.
Credential access-related activity.
Detection and investigation events.

This provides a chronological view of the simulated attack and helps demonstrate how different security tools contribute to incident reconstruction.

End-to-End Architecture

The following represents the overall workflow implemented in this project:

text
             ATTACK SIMULATION
             Atomic Red Team
                    |
                    v
          LSASS Credential Dumping
          PowerShell Enumeration
                    |
          +---------+---------+
          |                   |
          v                   v
      Wazuh SIEM        Windows Telemetry
          |                   |
          v                   v
    Detection Alerts    Velociraptor
          |              Artifact Collection
          |                   |
          +---------+---------+
                    |
                    v
              Hayabusa
             Threat Hunting
                    |
                    v
               Sigma Rules
             Detection Logic
                    |
                    v
          Timeline Reconstruction
                    |
                    v
          Attack Visualization

Repository Structure
text
.
├── README.md
├── Atomic-Red-Team/
│   └── Attack-Simulation/
├── Wazuh/
│   ├── Detection-Rules/
│   └── Alerts/
├── Velociraptor/
│   └── Collected-Artifacts/
├── Hayabusa/
│   └── Threat-Hunting-Results/
├── Sigma/
│   └── Detection-Rules/
├── Timeline/
│   └── Attack-Timeline/
└── Screenshots/
    ├── Wazuh-Alerts/
    ├── Velociraptor-Artifacts/
    ├── Hayabusa-Results/
    └── Timeline-Visualization/


Note: The directory structure is a suggested organization. Adjust it to match the actual repository contents.

Key Learning Outcomes

Through this project, the following practical skills are demonstrated:

Adversary emulation and attack simulation.
SIEM configuration and detection engineering.
Windows endpoint monitoring.
PowerShell threat analysis.
LSASS credential access detection.
Digital forensic artifact acquisition.
Windows Event Log analysis.
Sigma-based detection development.
Threat hunting and event correlation.
Attack timeline reconstruction.
Integration of multiple security tools into an investigation workflow.
Project Disclaimer

This project was developed for educational, research, and defensive cybersecurity purposes in a controlled lab environment.

Atomic Red Team was used to simulate adversary techniques for detection validation. The LSASS credential dumping scenario is intended to demonstrate defensive monitoring, forensic investigation, and threat hunting capabilities.

Do not execute attack simulations on systems without proper authorization.

Conclusion

This project demonstrates how multiple open-source security tools can be leveraged together to detect, investigate, and analyze LSASS credential dumping activity.

By combining Wazuh for security monitoring, Atomic Red Team for adversary emulation, Velociraptor for forensic artifact collection, Hayabusa for threat hunting, and Sigma for detection engineering, the lab provides a practical example of an integrated blue team investigation workflow.

The ultimate goal is to strengthen detection capabilities, improve investigation workflows, and develop a better understanding of attacker behavior through hands-on defensive security research.

Technologies: Wazuh | Atomic Red Team | Velociraptor | Hayabusa | Sigma | PowerShell | Windows Event Logs

Focus Areas: Detection Engineering | Threat Hunting | Digital Forensics | Incident Response | MITRE ATT&CK
