# Wazuh-OpenCTI Integration Overview

## Introduction

The **wazuh-opencti** integration enhances the capabilities of Wazuh by connecting it to OpenCTI (Open Cyber Threat Intelligence). OpenCTI is a platform designed to manage and share cyber threat intelligence. By integrating it with Wazuh, we can improve the detection and response to potential threats. This integration enables Wazuh to pull metadata from OpenCTI’s threat intelligence database, enriching alerts with more context and actionable intelligence.

When a security event is triggered, the integration searches for related **indicators** and **observables** (e.g., file hashes, IP addresses, domain names, and URLs) in OpenCTI. If matches are found, Wazuh generates enriched alerts, providing more insight into the nature of the threat.

### Key Data Types Inspected
- **SHA256 Hashes**: Identifies files by comparing their hashes to known threat data in OpenCTI.
- **IP Addresses (IPv4/IPv6)**: Detects malicious network activity by matching source and destination IPs with threat data.
- **Domain Names**: Flags domains involved in malicious activities such as phishing or malware distribution.
- **Hostnames**: Monitors devices connecting to known malicious servers.
- **URLs**: Identifies harmful URLs linked to phishing or malware attacks.

The integration inspects events from multiple Wazuh modules, including **Sysmon**, **Syscheck**, **Suricata**, and **Osquery**, and can be extended to support additional event types.

---

## Overview
By integrating Wazuh with OpenCTI, you gain the following benefits:

- **Enhanced Contextual Alerts**: Alerts are enriched with threat intelligence, enabling better decision-making.
- **Automated Threat Correlation**: Matches events with threat indicators, saving time.
- **Improved Detection Accuracy**: Increases visibility into malicious activities.

---

## Matching Events Logic

### Indicators and Observables Matching

#### **Indicators**
- Indicators follow the **STIX** pattern format and include single-value patterns (e.g., file hashes or domain names).
- If an event matches an indicator, Wazuh generates an alert with the type **indicator_pattern_match**.
- Maximum alerts per event: **3** (configurable with the **max_ind_alerts** variable).
- Alerts are prioritized based on confidence, detection score, and relevance.
- Partial matches generate the alert type **indicator_partial_pattern_match**.

#### **Observables**
- Observables represent specific data like IP addresses or file hashes.
- Matches create alerts with the type **observable_with_indicator**.
- Maximum alerts per event: **2** (configurable with the **max_obs_alerts** variable).
- Related indicators are included if applicable, generating the event type **observable_with_related_indicator**.

---

## Integration Requirements

### Prerequisites
1. **OpenCTI Instance**:
   - Version **5.12.24** or higher.
   - Obtain an **OpenCTI API token** for querying data.

2. **OpenCTI API**:
   - Generate or copy your API token:

     ![OpenCTI](images/wazuh-opencti-dashboard.png)

     ![OpenCTI API Token](images/wazuh-opencti-api.png)

---

## Installation

### Step 1: Copy Files

1. Copy the **custom-opencti** files to your Wazuh manager's integrations directory:
   - For standard setups: `/var/ossec/integrations/`
   - For Docker setups: Place them in the root directory within the `wazuh_integrations` volume.

### Step 2: Modify Configuration

2. Modify your **Wazuh manager configuration file**:
   - Path: `/var/ossec/etc/ossec.conf` (standard setups) or `config/wazuh_cluster/wazuh_manager.conf` (Docker setups).

```xml
<integration>
  <name>custom-opencti</name>
  <group>sysmon_eid1_detections,sysmon_eid3_detections,sysmon_eid7_detections,sysmon_eid22_detections,syscheck_file,osquery_file,ids,sysmon_process-anomalies,audit_command</group>
  <alert_format>json</alert_format>
  <api_key>REPLACE-ME-WITH-A-VALID-TOKEN</api_key>
  <hook_url>https://my.opencti.location/graphql</hook_url>
</integration>
```

Replace:
- **api_key** with a valid OpenCTI API key.
- **hook_url** with the OpenCTI instance's GraphQL endpoint.
- Adjust **group** to match the `rule.groups` you want the integration to inspect.
# Wazuh Rules for Threat Intel and IoC Detection

In order for Wazuh to create alerts when an Indicator of Compromise (IoC) is found, the following rule set is required. This also includes rules for when the integration fails to operate. Be sure to replace the rule IDs to avoid conflicts in your setup.

```xml
<group name="threat_intel,">
   <rule id="100210" level="10">
      <field name="integration">opencti</field>
      <description>OpenCTI</description>
      <group>opencti,</group>
   </rule>

   <rule id="100211" level="5">
      <if_sid>100210</if_sid>
      <field name="opencti.error">\.+</field>
      <description>OpenCTI: Failed to connect to API</description>
      <options>no_full_log</options>
      <group>opencti,opencti_error,</group>
   </rule>

   <rule id="100212" level="12">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">indicator_pattern_match</field>
      <description>OpenCTI: IoC found in threat intel: $(opencti.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>

   <rule id="100213" level="12">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">observable_with_indicator</field>
      <description>OpenCTI: IoC found in threat intel: $(opencti.observable_value)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>

   <rule id="100214" level="10">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">observable_with_related_indicator</field>
      <description>OpenCTI: IoC possibly found in threat intel (related): $(opencti.related.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>

   <rule id="100215" level="10">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">indicator_partial_pattern_match</field>
      <description>OpenCTI: IoC possibly found in threat intel: $(opencti.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>
</group>
```
---
### Step 3: Restart Wazuh Manager

- Standard setups:
  ```bash
  systemctl restart wazuh-manager
  ```
- Docker setups:
  ```bash
  docker restart <your-wazuh-manager-instance-id>
  ```

---

## Customization

Feel free to customize the `custom-opencti.py` script to match additional events or groups relevant to your setup. Share enhancements with the community via pull requests.

---

## Example Output

<details>
  <summary>View example output</summary>

| Field              | Value                                                                                   |
|--------------------|-----------------------------------------------------------------------------------------|
| **Index**          | wazuh-alerts-4.x-2025.01.18                                                            |
| **Alert ID**       | xxxxxxxxx                                                                              |
| **Input Type**     | log                                                                                     |
| **Agent ID**       | xxxx                                                                                   |
| **Manager Name**   | xxxx                                                                                   |
| **Integration**    | opencti                                                                                 |
| **Event Type**     | indicator_pattern_match                                                                 |
| **Indicator Link** | [View Indicator]                                                  |
| **Source Rule ID** | 100002                                                                                  |
| **Source IP**      | xxxxxx                                                                                  |
| **Destination IP** | xxxx                                                                                   |
| **Rule Description** | OpenCTI: IoC found in threat intel: xxxxx                                            |

</details>

---

## Conclusion

The Wazuh-OpenCTI integration significantly enhances detection and response capabilities by enriching alerts with threat intelligence. This automation improves visibility, speeds up response times, and enables more accurate threat identification.

### Explore Further
- [Wazuh Documentation](https://documentation.wazuh.com)
- [OpenCTI Documentation](https://www.opencti.io/documentation)
---

## Shoutout

The Wazuh-OpenCTI integration is based on the work by [misje](https://github.com/misje). A big thank to him for his contributions to the community. You can explore his GitHub for more of their projects and contributions!

---
# Wazuh-OpenCTI
