# Wazuh-OpenCTI Integration Overview

## Introduction

The **wazuh-opencti** integration enhances the capabilities of Wazuh by connecting it to OpenCTI (Open Cyber Threat Intelligence). OpenCTI is a platform designed to manage and share cyber threat intelligence. By integrating it with Wazuh, we can improve the detection and response to potential threats. This integration enables Wazuh to pull metadata from OpenCTI’s threat intelligence database, enriching alerts with more context and actionable intelligence.

When a security event is triggered, the integration searches for related **indicators** and **observables** (e.g., file hashes, IP addresses, domain names, and URLs) in OpenCTI. If matches are found, Wazuh generates enriched alerts, providing more insight into the nature of the threat.

### Key Data Types Inspected
- **SHA256 Hashes**: Identifies files by comparing their hashes to known threat data in OpenCTI (from file integrity monitoring).
- **IP Addresses (IPv4/IPv6)**: Detects malicious network activity by matching source and destination IPs with threat data (from IDS alerts and firewall logs).
- **Domain Names**: Flags domains involved in malicious activities such as phishing or malware distribution (from DNS queries).
- **URLs**: Identifies harmful URLs linked to phishing or malware attacks (from command line arguments).

The integration inspects events from multiple Wazuh modules, including **Syscheck** (file integrity monitoring), **Suricata** (IDS), **audit commands**, and **firewall events** (SonicWall, Fortigate), and can be extended to support additional event types.

---

## Overview
By integrating Wazuh with OpenCTI, you gain the following benefits:

- **Enhanced Contextual Alerts**: Alerts are enriched with threat intelligence, enabling better decision-making.
- **Automated Threat Correlation**: Matches events with threat indicators, saving time.
- **Improved Detection Accuracy**: Increases visibility into malicious activities.

---

## Supported Event Sources

The integration supports threat intelligence enrichment for the following event types:

### 1. **File Integrity Monitoring** (`syscheck_file` group)
- **Data Source**: Wazuh Syscheck module
- **Threat Intel Lookup**: SHA256 file hashes
- **Use Case**: Detect known malicious files when they are created or modified on monitored systems

### 2. **Intrusion Detection System** (`ids` group) 
- **Data Source**: Suricata IDS alerts
- **Threat Intel Lookup**: Source/destination IP addresses, DNS queries and responses
- **Use Case**: Identify communication with known malicious IPs or domains

### 3. **System Commands** (`audit_command` group)
- **Data Source**: Linux audit subsystem via Wazuh
- **Threat Intel Lookup**: URLs extracted from command line arguments  
- **Use Case**: Detect when users or processes access known malicious URLs

### 4. **SonicWall Firewall** (`sonicwall` group)
- **Data Source**: SonicWall firewall syslog events
- **Threat Intel Lookup**: Source/destination IP addresses (public IPs only)
- **Use Case**: Identify firewall-allowed traffic to/from known malicious IPs

### 5. **Fortigate Firewall** (`fortigate` group)
- **Data Source**: Fortigate firewall syslog events  
- **Threat Intel Lookup**: Source/destination IP addresses (public IPs only)
- **Use Case**: Identify firewall traffic patterns involving known malicious IPs
- **Filtering**: Skips internal administrative actions (login/logout/config changes)

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
1. **Wazuh Manager**:
   - Version **4.x** or higher
   - Running on Linux (tested on Ubuntu, CentOS, RHEL)

2. **OpenCTI Instance**:
   - Version **5.12.24** or higher
   - Accessible via HTTP/HTTPS from Wazuh manager

3. **Python Environment**:
   - Python 3.6+ with required libraries: `requests`, `json`, `ipaddress`
   - Standard libraries: `socket`, `sys`, `os`, `datetime`

4. **OpenCTI API Token**:
   Generate or copy your API token from OpenCTI platform


---

## Installation

### Step 1: Copy Integration Files

1. **Copy the integration script**:
   ```bash
   sudo cp custom-opencti /var/ossec/integrations/
   sudo cp custom-opencti.py /var/ossec/integrations/
   sudo chmod 750 /var/ossec/integrations/custom-opencti*
   sudo chown root:wazuh /var/ossec/integrations/custom-opencti*
   ```

2. **Add custom decoder**:
   ```bash
   sudo cp opencti_decoder.xml /var/ossec/etc/decoders/
   ```

3. **Add custom rules**:
   ```bash
   sudo cp opencti_rules.xml /var/ossec/etc/rules/
   ```

### Step 2: Configure Wazuh Integration

4. **Edit Wazuh configuration**:
   ```bash
   sudo vim /var/ossec/etc/ossec.conf
   ```

   Add the integration block:

```xml
<!-- custom OpenCTI -->
<ossec_config>
  <integration>
    <name>custom-opencti</name>
    <group>syscheck_file,ids,audit_command,sonicwall,fortigate</group>
    <level>5</level>
    <alert_format>json</alert_format>
    <api_key>API-KEY</api_key>
    <hook_url>http://YOUR-OPENCTI-SERVER/graphql</hook_url>
  </integration>
</ossec_config>
```

**Configuration Notes**:
- Replace `API-KEY` with your actual OpenCTI API token
- Replace `YOUR-OPENCTI-SERVER` with your OpenCTI server IP/hostname  
- The `group` parameter specifies which alert types trigger the integration
- Adjust `level` if you want to change the minimum alert severity for integration triggers

### Step 3: Verify Rules and Decoders

The provided rules and decoders handle OpenCTI integration events. **Important**: Verify the rule IDs don't conflict with your existing rules:

```xml
<group name="threat_intel,">
   <rule id="110200" level="10">
      <field name="integration">opencti</field>
      <description>OpenCTI</description>
      <group>opencti,</group>
   </rule>

   <rule id="110201" level="5">
      <if_sid>110200</if_sid>
      <field name="opencti.error">\.+</field>
      <description>OpenCTI: Failed to connect to API</description>
      <options>no_full_log</options>
      <group>opencti,opencti_error,</group>
   </rule>

   <rule id="110202" level="12">
      <if_sid>110200</if_sid>
      <field name="opencti.event_type">indicator_pattern_match</field>
      <description>OpenCTI: IoC found in threat intel: $(opencti.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>

   <rule id="110203" level="12">
      <if_sid>110200</if_sid>
      <field name="opencti.event_type">observable_with_indicator</field>
      <description>OpenCTI: IoC found in threat intel: $(opencti.observable_value)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>

   <rule id="110204" level="10">
      <if_sid>110200</if_sid>
      <field name="opencti.event_type">observable_with_related_indicator</field>
      <description>OpenCTI: IoC possibly found in threat intel (related): $(opencti.related.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>

   <rule id="110205" level="10">
      <if_sid>110200</if_sid>
      <field name="opencti.event_type">indicator_partial_pattern_match</field>
      <description>OpenCTI: IoC possibly found in threat intel: $(opencti.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>
</group>
```
### Step 4: Test Configuration and Restart

5. **Test configuration syntax**:
   ```bash
   sudo /var/ossec/bin/wazuh-logtest
   ```

6. **Restart Wazuh Manager**:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

7. **Verify integration is loaded**:
   ```bash
   sudo tail -f /var/ossec/logs/ossec.log | grep -i opencti
   ```

### Step 5: Testing Integration

8. **Monitor integration logs**:
   ```bash
   sudo tail -f /var/ossec/logs/integrations.log
   ```

9. **Generate test events** by triggering alerts in the configured groups (`ids`, `syscheck_file`, etc.)

10. **Check for OpenCTI alerts** in your Wazuh dashboard or alerts log

---

## Debugging and Troubleshooting

### Enable Debug Mode

For troubleshooting integration issues, you can enable debug logging in two ways:

#### Method 1: Manual Script Execution
Run the integration script manually with debug argument:

```bash
# Navigate to integrations directory
cd /var/ossec/integrations/

# Run script manually with sample alert and debug flag
# You can change src/dst IP with known malicious IP
echo '{"rule":{"groups":["ids"],"id":"31103"},"data":{"srcip":"1.2.3.4","dstip":"5.6.7.8"},"id":"test"}' > tmp/test.json

python3 custom-opencti.py /tmp/test.json YOUR_API_TOKEN http://YOUR_OPENCTI_HOST:8080/graphql debug
```

#### Method 2: Enable Debug in Script
Modify the debug variable in the script temporarily:

```bash
sudo vim /var/ossec/integrations/custom-opencti.py
```

Change line with `DEBUG_ENABLED = False` to `DEBUG_ENABLED = True`:
```python
# Debug can be enabled by setting the internal configuration setting
# integration.debug to 1 or higher:
DEBUG_ENABLED = True  # Change this from False to True
```

**Remember to set it back to `False` in production to avoid excessive logging.**

### Debug Output Information

When debug mode is enabled, you'll see detailed information including:
- Alert group processing steps
- IP address extraction and filtering
- OpenCTI API query construction
- GraphQL response data
- Event generation process
- Socket communication details

### Common Issues and Solutions

1. **No alerts generated**:
   - Verify alert groups match integration configuration
   - Check if IPs are public (private IPs are skipped)
   - Ensure OpenCTI has threat intelligence data for the indicators

2. **Connection errors**:
   - Verify OpenCTI endpoint URL and API token
   - Check network connectivity: `curl -X POST http://YOUR_OPENCTI_HOST:8080/graphql`
   - Validate API token permissions in OpenCTI

3. **Permission errors**:
   - Ensure integration script has correct permissions: `chmod 750 /var/ossec/integrations/custom-opencti*`
   - Verify ownership: `chown root:wazuh /var/ossec/integrations/custom-opencti*`

4. **Integration not triggering**:
   - Check if alerts meet minimum level threshold (default: level 5)
   - Verify rule groups match configuration (`ids`, `syscheck_file`, etc.)
   - Review Wazuh logs: `tail -f /var/ossec/logs/ossec.log | grep integration`

### Log Files

Monitor these log files for troubleshooting:
- **Integration logs**: `/var/ossec/logs/integrations.log`
- **Wazuh manager logs**: `/var/ossec/logs/ossec.log`
- **Wazuh alerts**: `/var/ossec/logs/alerts/alerts.log`

---

## Customization

Feel free to customize the `custom-opencti.py` script to match additional events or groups relevant to your setup. Share enhancements with the community via pull requests.

---

## Example Output

<details>
  <summary>View example output</summary>

| Field              | Value                                                                                   |
|--------------------|-----------------------------------------------------------------------------------------|
| **Index**          | wazuh-alerts-4.x-2025.09.18                                                            |
| **Alert ID**       | xxxxxxxxx                                                                              |
| **Input Type**     | log                                                                                     |
| **Agent ID**       | xxxx                                                                                   |
| **Manager Name**   | xxxx                                                                                   |
| **Integration**    | opencti                                                                                 |
| **Event Type**     | indicator_pattern_match                                                                 |
| **Indicator Link** | [View Indicator]                                                  |
| **Source Rule ID** | 110202                                                                                  |
| **Source IP**      | xxxxxx                                                                                  |
| **Destination IP** | xxxx                                                                                   |
| **Rule Description** | OpenCTI: IoC found in threat intel: xxxxx                                            |

</details>

---

## Conclusion

The Wazuh-OpenCTI integration significantly enhances detection and response capabilities by enriching alerts with threat intelligence. This automation improves visibility, speeds up response times, and enables more accurate threat identification.


