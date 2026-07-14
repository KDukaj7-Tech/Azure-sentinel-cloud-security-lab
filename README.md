<img width="2172" height="724" alt="GitHub read me banner" src="https://github.com/user-attachments/assets/5feae5f4-d732-44eb-90b6-d85b34ddc472" />

# Azure Cloud Security Lab

> **End-to-end Azure Cloud Security Lab demonstrating Microsoft Sentinel, Log Analytics, Kusto Query Language (KQL), Windows event monitoring, custom analytics rules, and security alert investigation.**

---

# Project Overview

I built this project to gain hands-on experience with Microsoft Azure security technologies and to better understand how a modern Security Operations Centre (SOC) monitors, detects and investigates security events.

Rather than following individual Azure tutorials, I wanted to complete a full end-to-end project that mirrored a realistic security monitoring workflow. Starting with an empty Azure subscription, I deployed the infrastructure, configured monitoring, collected Windows security logs, created custom Microsoft Sentinel detections and validated alerts using simulated authentication activity.

The goal wasn't simply to learn how to click through Azure, but to understand how security data flows through the platform and how that data can be transformed into useful detections for security analysts.

---

# Key Outcomes

By completing this project I was able to:

* Build an Azure cloud security lab from scratch.
* Deploy and configure a Windows Virtual Machine.
* Configure Azure Monitor and Log Analytics.
* Collect Windows Security Event Logs.
* Write and troubleshoot Kusto Query Language (KQL) queries.
* Investigate Windows authentication events.
* Create custom Microsoft Sentinel Analytics Rules.
* Generate and validate security alerts.
* Document the entire project using GitHub.

---

# Skills Demonstrated

**Azure • Microsoft Sentinel • Azure Monitor • Log Analytics • Windows Server • Kusto Query Language (KQL) • Detection Engineering • Security Monitoring • Windows Event Logs • Microsoft Defender Portal • Technical Documentation • Troubleshooting**

---

# Project Statistics

* 1 Azure Resource Group
* 1 Virtual Network
* 1 Windows Virtual Machine
* 1 Log Analytics Workspace
* 1 Data Collection Rule
* 1 Azure Monitor Agent
* 2 Custom Analytics Rules
* 15 Supporting Screenshots
* Multiple KQL Queries
* Windows Event IDs Investigated:

  * 4624 (Successful Logons)
  * 4625 (Failed Logons)

---

# Technologies Used

* Microsoft Azure
* Microsoft Sentinel
* Azure Monitor
* Log Analytics Workspace
* Azure Monitor Agent
* Data Collection Rules (DCR)
* Windows Server
* Microsoft Defender Portal
* Remote Desktop Protocol (RDP)
* Kusto Query Language (KQL)

---

# Lab Architecture

The following diagram illustrates the flow of security telemetry throughout the environment.

<img width="1672" height="941" alt="Azure lab architecture" src="https://github.com/user-attachments/assets/2c873d65-abd4-4b84-bf17-b1078d60271d" />

---

# Environment Deployment

## Resource Group

I began by creating a dedicated Azure Resource Group to contain every resource used throughout the project. Keeping all resources within a single Resource Group simplified management, deployment and eventual clean-up.

<img width="1919" height="912" alt="01 Resource Group Created" src="https://github.com/user-attachments/assets/9b92357e-92a7-48b1-b4c9-3056f7b9bbdd" />


---

## Virtual Network

Next, I deployed a Virtual Network (VNet) to provide secure networking for the Windows Virtual Machine. This isolated the environment while allowing Remote Desktop access for administration.

<img width="1919" height="914" alt="02-Virtual network created" src="https://github.com/user-attachments/assets/b438c0a1-c7cf-4d35-ae09-a3020d85e937" />


---

## Windows Virtual Machine

The Windows Virtual Machine acted as the monitored endpoint throughout the project.

It was responsible for generating Windows Security Events which were later collected, analysed and used to create Microsoft Sentinel detections.

Tasks completed included:

* Virtual Machine deployment
* Network configuration
* Remote Desktop configuration
* Windows configuration
* Event generation

<img width="1917" height="910" alt="03 VM Networking" src="https://github.com/user-attachments/assets/97edd84e-3dd0-4430-a115-215c0420986f" />


<img width="1919" height="909" alt="04 VM overview" src="https://github.com/user-attachments/assets/530fe057-dd3c-4d44-a28e-cd50bc3c4948" />


---

# Configuring Monitoring

## Log Analytics Workspace

A Log Analytics Workspace was created to act as the central repository for all telemetry collected from the virtual machine.

This became the foundation for querying Windows Security Events using KQL.

<img width="1917" height="916" alt="05-Log analytics workspace overview" src="https://github.com/user-attachments/assets/bbd4d09d-cd55-4e1b-967b-5684f73385cd" />


---

## Data Collection Rule

A Data Collection Rule (DCR) was configured to determine exactly which Windows Event Logs should be collected and forwarded into the Log Analytics Workspace.

This ensured only the required telemetry was ingested.

<img width="1917" height="913" alt="06-Data collection rule overview" src="https://github.com/user-attachments/assets/b5deb074-374d-45c8-8eef-1f913bbd3a37" />


---

## Azure Monitor Agent

The Azure Monitor Agent was installed on the Windows Virtual Machine.

After installation, connectivity was verified before continuing with the investigation phase.

<img width="1919" height="912" alt="07-Azure monitor agent extension" src="https://github.com/user-attachments/assets/6d591825-ba48-41d3-b65d-df8262146001" />


---

# Verifying Telemetry

Before investigating security events, I first confirmed that telemetry was reaching the Log Analytics Workspace correctly.

The Heartbeat table was queried to verify communication between the virtual machine and Azure Monitor.

```kusto
Heartbeat
| take 10
```

The returned results confirmed successful agent communication.

<img width="1919" height="911" alt="08-Heartbeat query results" src="https://github.com/user-attachments/assets/fd539b29-4c0b-47f9-b674-d1383f04cde3" />


---

# Investigating Authentication Events

The first investigation focused on Windows Event ID **4624**, representing successful logons.

```kusto
Event
| where EventLog == "Security"
| where EventID == 4624
| where TimeGenerated > ago(24h)
| project TimeGenerated, Computer, EventID, RenderedDescription
```

Using this query, I reviewed successful authentication events together with their rendered descriptions.

This helped distinguish normal Windows activity from potentially suspicious authentication behaviour.

<img width="1919" height="912" alt="09-Security event 4624 query result" src="https://github.com/user-attachments/assets/3a4a6e15-adc4-463b-8611-9bba4aeec7b1" />


---

## Event Investigation

During the investigation I analysed several Windows Logon Types including:

* Interactive Logons
* Network Logons
* Service Logons
* Workstation Unlocks

The **RenderedDescription** field provided useful information including:

* Account Name
* Process Name
* Logon Type
* Authentication Details

The majority of observed events originated from expected Windows services, demonstrating how important it is to understand normal operating system behaviour before investigating potential threats.

<img width="1919" height="914" alt="10-Event investigation-rendered description" src="https://github.com/user-attachments/assets/ad46ce07-8791-4a52-b29a-88d43b530378" />


---

# Microsoft Sentinel

After validating telemetry collection, I onboarded the Log Analytics Workspace into Microsoft Sentinel.

This transformed the collected Windows Event Logs into a SIEM environment capable of generating detections, alerts and incidents.

---

## Analytics Rule — Successful Logons

My first custom analytics rule monitored Windows Event ID **4624**.

The purpose of this rule was to demonstrate how successful authentication events could be converted into actionable detections.

Configuration included:

* Scheduled Rule
* Medium Severity
* Alert Threshold
* Event Grouping
* Custom KQL Query

<img width="1917" height="912" alt="012-Sentinel analytics rule details" src="https://github.com/user-attachments/assets/e10e3644-c034-403b-b9ab-fd1719b90eb4" />


---

## Analytics Rule — Failed Logons

The second analytics rule focused on Windows Event ID **4625**.

This rule counted failed authentication attempts over a defined time window before generating an alert once the configured threshold had been exceeded.

Building this rule required troubleshooting KQL syntax and adapting the query to match the event schema available within the lab.

<img width="1919" height="910" alt="014-Sentinel rule list and details" src="https://github.com/user-attachments/assets/bd106ea3-493f-441d-b5e8-98fb1adb0073" />


---

# Alert Validation

To confirm the detection worked correctly, I intentionally generated multiple failed logon attempts against the virtual machine.

Once the threshold was exceeded, Microsoft Sentinel successfully generated an alert.

This validated the complete monitoring pipeline from Windows Event generation through Azure Monitor and Log Analytics into Microsoft Sentinel.

<img width="1919" height="911" alt="013-Sentinel incident generated" src="https://github.com/user-attachments/assets/7c8f417d-e7d7-46bb-8f0e-fdcc3b2277f9" />
<img width="1917" height="908" alt="015-sentinel failed logon alert" src="https://github.com/user-attachments/assets/4bc5aa01-af28-426a-971a-b27d72847bf8" />



---

# Challenges Encountered

Like any real-world project, this lab involved several technical challenges.

During development I had to:

* Troubleshoot KQL syntax errors.
* Adapt queries to the available event schema.
* Validate Azure Monitor telemetry before writing detections.
* Navigate changes introduced by the Microsoft Defender portal replacing parts of the Sentinel interface.
* Test and refine analytics rules until alerts were generated successfully.

Working through these issues provided a much better understanding of how Microsoft Sentinel operates in practice than simply following a tutorial.

---

# Lessons Learned

The biggest lesson from this project is that effective security monitoring is far more than collecting logs.

The real value comes from understanding how telemetry moves through Azure services, writing meaningful KQL queries, validating detections and investigating the resulting alerts.

I also gained a much deeper appreciation for troubleshooting. Several parts of the project required refining queries, validating data sources and adapting to changes in Microsoft's interfaces. Solving those problems helped build confidence with the platform and reinforced the importance of methodical testing.

---

# Personal Reflection

This project was the first time I built an end-to-end cloud security monitoring environment entirely myself.

Looking back, the biggest improvement wasn't simply learning Azure services—it was becoming more comfortable troubleshooting problems and understanding why each component exists within the monitoring pipeline.

Instead of seeing Azure Monitor, Log Analytics and Microsoft Sentinel as separate products, I now understand how they work together to provide visibility, detection and investigation capabilities.

This project has given me a much stronger foundation for future cloud security and SOC-focused projects.

---

# Conclusion

This project represents a complete Azure cloud security monitoring implementation built from the ground up.

From deploying Azure infrastructure to configuring monitoring, analysing Windows Security Events, developing KQL queries, creating Microsoft Sentinel analytics rules and validating alerts, every stage was completed and documented as part of a single end-to-end workflow.

More importantly, it demonstrates not only familiarity with Azure security technologies but also the ability to troubleshoot issues, understand security telemetry and communicate technical work through clear documentation.

I intend to build on this foundation with additional cloud security projects as I continue developing my skills in Microsoft Azure and security operations.
