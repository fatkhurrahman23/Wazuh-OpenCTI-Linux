#!/usr/bin/env python

# Based on: https://github.com/aminemoussa/Wazuh-OpenCTI by Amine Moussa
# Original inspiration: https://github.com/misje/wazuh-opencti by Andreas Misje
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import re
import traceback

# Maximum number of alerts to create for indicators found per query:
max_ind_alerts = 3
# Maximum number of alerts to create for observables found per query:
max_obs_alerts = 3
# Debug can be enabled by setting the internal configuration setting
# integration.debug to 1 or higher:
DEBUG_ENABLED = False

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
url = ''
# Match SHA256:
regex_file_hash = re.compile('[A-Fa-f0-9]{64}')
# Location of source events file:
log_file = '{0}/logs/integrations.log'.format(pwd)
# UNIX socket to send detections events to:
socket_addr = '{0}/queue/sockets/queue'.format(pwd)

def main(args):
    global url
    debug('# Starting')
    alert_path = args[1]
    # Documentation says to do args[2].split(':')[1], but this is incorrect:
    token = args[2]
    url = args[3]

    debug('# API key: {}'.format(token))
    debug('# Alert file location: {}'.format(alert_path))

    with open(alert_path, errors='ignore') as alert_file:
        alert = json.load(alert_file)

    rule_id = alert.get('rule', {}).get('id', 'unknown')
    rule_level = alert.get('rule', {}).get('level', 'unknown')
    agent_name = alert.get('agent', {}).get('name', 'unknown')
    debug(f'# Processing alert - Rule: {rule_id}, Level: {rule_level}, Agent: {agent_name}', do_log=True)

    new_alerts = list(query_opencti(alert, url, token))

    if new_alerts:
        debug(f'# Sending {len(new_alerts)} events to Wazuh queue', do_log=True)
        for i, new_alert in enumerate(new_alerts):
            send_event(new_alert, alert['agent'])
            debug(f'# Event {i+1} sent successfully', do_log=True)
    else:
        debug('# No events generated, nothing to send', do_log=True)
    
    debug('# OpenCTI integration completed successfully', do_log=True)


def debug(msg, do_log = False):
    do_log |= DEBUG_ENABLED
    if not do_log:
        return

    now = time.strftime('%Y-%m-%d %H:%M:%S')
    msg = '{0}: {1}\n'.format(now, msg)
    f = open(log_file,'a')
    f.write(msg)
    f.close()

def log(msg):
    debug(msg, do_log=True)

# Recursively remove all empty nulls, strings, empty arrays and empty dicts
# from a dict:
def remove_empties(value):
    # Keep booleans, but remove '', [] and {}:
    def empty(value):
        return False if isinstance(value, bool) else not bool(value)
    if isinstance(value, list):
        return [x for x in (remove_empties(x) for x in value) if not empty(x)]
    elif isinstance(value, dict):
        return {key: val for key, val in ((key, remove_empties(val)) for key, val in value.items()) if not empty(val)}
    else:
        return value

# Given an object 'output' with a list of objects (edges and nodes) at key
# 'listKey', create a new list at key 'newKey' with just values from the
# original list's objects at key 'valueKey'. Example: 
# {'objectLabel': {'edges': [{'node': {'value': 'cryptbot'}}, {'node': {'value': 'exe'}}]}}
# →
# {'labels:': ['cryptbot', 'exe']}
# {'objectLabel': [{'value': 'cryptbot'}, {'value': 'exe'}]}
# →
# {'labels:': ['cryptbot', 'exe']}
def simplify_objectlist(output, listKey, valueKey, newKey):
    if 'edges' in output[listKey]:
        edges = output[listKey]['edges']
        output[newKey] = [key[valueKey] for edge in edges for _, key in edge.items()]
    else:
        output[newKey] = [key[valueKey] for key in output[listKey]]

    if newKey != listKey:
        # Delete objectLabels (array of objects) now that we have just the names:
        del output[listKey]

# Determine whether alert contains a packetbeat DNS query:
def packetbeat_dns(alert):
    return all(key in alert['data'] for key in ('method', 'dns')) and alert['data']['method'] == 'QUERY'

# For every object in dns.answers, retrieve "data", but only if "type" is
# A/AAAA and the resulting address is a global IP address:
def filter_packetbeat_dns(results):
    return [r['data'] for r in results if (r['type'] == 'A' or r['type'] == 'AAAA') and ipaddress.ip_address(r['data']).is_global]

# Sort indicators based on
#  - Whether it is not revoked
#  - Whether the indicator has "detection"
#  - Score (the higher the better)
#  - Confidence (the higher the better)
#  - valid_until is before now():
def indicator_sort_func(x):
    return (x['revoked'], not x['x_opencti_detection'], -x['x_opencti_score'], -x['confidence'], datetime.strptime(x['valid_until'], '%Y-%m-%dT%H:%M:%S.%fZ') <= datetime.now())

def sort_indicators(indicators):
    # In case there are several indicators, and since we will only extract
    # one, sort them based on !revoked, detection, score, confidence and
    # lastly expiry:
    return sorted(indicators, key=indicator_sort_func)

# Modify the indicator object so that it is more fit for opensearch (simplify
# deeply-nested lists etc.):
def modify_indicator(indicator):
    if indicator:
        # Simplify object lists for indicator labels and kill chain phases:
        simplify_objectlist(indicator, listKey = 'objectLabel', valueKey = 'value', newKey = 'labels')
        simplify_objectlist(indicator, listKey = 'killChainPhases', valueKey = 'kill_chain_name', newKey = 'killChainPhases')
        if 'externalReferences' in indicator:
            # Extract URIs from external references:
            simplify_objectlist(indicator, listKey = 'externalReferences', valueKey = 'url', newKey = 'externalReferences')

    return indicator

def indicator_link(indicator):
    return url.removesuffix('graphql') + 'dashboard/observations/indicators/{0}'.format(indicator['id'])

# Modify the observable object so that it is more fit for opensearch (simplify
# deeply-nested lists etc.):
def modify_observable(observable, indicators):
    # Generate a link to the observable:
    observable['observable_link'] = url.removesuffix('graphql') + 'dashboard/observations/observables/{0}'.format(observable['id'])

    # Extract URIs from external references:
    simplify_objectlist(observable, listKey = 'externalReferences', valueKey = 'url', newKey = 'externalReferences')
    # Convert list of file objects to list of file names:
    # simplify_objectlist(observable, listKey = 'importFiles', valueKey = 'name', newKey = 'importFiles')
    # Convert list of label objects to list of label names:
    simplify_objectlist(observable, listKey = 'objectLabel', valueKey = 'value', newKey = 'labels')

    # Grab the first indicator (already sorted to get the most relevant one):
    observable['indicator'] = next(iter(indicators), None)
    # Indicate in the alert that there were multiple indicators:
    observable['multipleIndicators'] = len(indicators) > 1
    # Generate a link to the indicator:
    if observable['indicator']:
        observable['indicator_link'] = indicator_link(observable['indicator'])

    modify_indicator(observable['indicator'])
    # Remove the original list of objects:
    del observable['indicators']
    # Remove the original list of relationships:
    del observable['stixCoreRelationships']

# Domain name–IP address releationships are not always up to date in a CTI
# database (naturally). If a DNS enrichment connector is used to create
# "resolves-to" relationship (or "related-to"), it may be worth looking up
# relationships to the observable, and if these objects have indicators, create
# an alert:
def relationship_with_indicators(node):
    related = []
    try:
        for relationship in node['stixCoreRelationships']['edges']:
            if relationship['node']['related']['indicators']['edges']:
                related.append(dict(
                    id=relationship['node']['related']['id'],
                    type=relationship['node']['type'],
                    relationship=relationship['node']['relationship_type'],
                    value=relationship['node']['related']['value'],
                    # Create a list of the individual node objects in indicator edges:
                    indicator = modify_indicator(next(iter(sort_indicators(list(map(lambda x:x['node'], relationship['node']['related']['indicators']['edges'])))), None)),
                    multipleIndicators = len(relationship['node']['related']['indicators']['edges']) > 1,
                    ))
                if related[-1]['indicator']:
                    related[-1]['indicator_link'] = indicator_link(related[-1]['indicator'])
    except KeyError:
        pass

    return next(iter(sorted(related, key=lambda x:indicator_sort_func(x['indicator']))), None)

def add_context(source_event, event):
    # Add source information (opencti.source) to the original alert
    # (naming convention from official VirusTotal integration):
    event['opencti']['source'] = {}
    event['opencti']['source']['alert_id'] = source_event['id']
    event['opencti']['source']['rule_id'] = source_event['rule']['id']
    
    if 'agent' in source_event:
        if 'name' in source_event['agent']:
            event['opencti']['source']['agent_name'] = source_event['agent']['name']
        if 'ip' in source_event['agent']:
            event['opencti']['source']['agent_ip'] = source_event['agent']['ip']
        if 'id' in source_event['agent']:
            event['opencti']['source']['agent_id'] = source_event['agent']['id']
    if 'GeoLocation' in source_event:
        event['opencti']['source']['GeoLocation'] = source_event['GeoLocation']
    if 'syscheck' in source_event:
        event['opencti']['source']['file'] = source_event['syscheck']['path']
        event['opencti']['source']['md5'] = source_event['syscheck']['md5_after']
        event['opencti']['source']['sha1'] = source_event['syscheck']['sha1_after']
        event['opencti']['source']['sha256'] = source_event['syscheck']['sha256_after']
    if 'data' in source_event:
        for key in ['in_iface', 'srcintf', 'src_ip', 'srcip', 'src_mac', 'srcmac', 'src_port', 'srcport', 'dest_ip', 'dstip', 'dst_mac', 'dstmac', 'dest_port', 'dstport', 'dstintf', 'proto', 'app_proto']:
            if key in source_event['data']:
                event['opencti']['source'][key] = source_event['data'][key]
        if packetbeat_dns(source_event):
            event['opencti']['source']['queryName'] = source_event['data']['dns']['question']['name']
            if 'answers' in source_event['data']['dns']:
                event['opencti']['source']['queryResults'] = ';'.join(map(lambda x:x['data'], source_event['data']['dns']['answers']))
        if 'alert' in source_event['data']:
            event['opencti']['source']['source_event'] = {}
            for key in ['action', 'category', 'signature', 'signature_id']:
                if key in source_event['data']['alert']:
                    event['opencti']['source']['alert'][key] = source_event['data']['alert'][key]
        if 'audit' in source_event['data'] and 'execve' in source_event['data']['audit']:
            event['opencti']['source']['execve'] = ' '.join(source_event['data']['audit']['execve'][key] for key in sorted(source_event['data']['audit']['execve'].keys()))
            for key in ['success', 'key', 'uid', 'gid', 'euid', 'egid', 'exe', 'exit', 'pid']:
                if key in source_event['data']['audit']:
                    event['opencti']['source'][key] = source_event['data']['audit'][key]
        #  sonicwall specific context information:
        if 'rule' in source_event and 'groups' in source_event['rule'] and 'sonicwall' in source_event['rule']['groups']:
            for key in ['action', 'note', 'protocol', 'status', 'srcport', 'dstport']:
                if key in source_event['data']:
                    event['opencti']['source'][key] = source_event['data'][key]
        #  fortigate specific context information:
        if 'rule' in source_event and 'groups' in source_event['rule'] and 'fortigate' in source_event['rule']['groups']:
            for key in ['action', 'status', 'logdesc', 'devname', 'logid', 'subtype', 'level', 'vd', 'dstuser', 'ui', 'duration', 'reason']:
                if key in source_event['data']:
                    event['opencti']['source'][key] = source_event['data'][key]

def send_event(msg, agent = None):
    if not agent or agent['id'] == '000':
        string = '1:opencti:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->opencti:{3}'.format(agent['id'], agent['name'], agent['ip'] if 'ip' in agent else 'any', json.dumps(msg))

    debug('# Event:')
    debug(string)
    debug(f'# Event length: {len(string)} bytes')
    debug(f'# Socket path: {socket_addr}')
    
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(socket_addr)
        sock.send(string.encode())
        sock.close()
        debug('# Event sent to Wazuh queue successfully')
    except Exception as e:
        log(f'# Error sending event to socket: {str(e)}')
        raise e

def send_error_event(msg, agent = None):
    send_event({'integration': 'opencti', 'opencti': {
        'error': msg,
        'event_type': 'error',
        }}, agent)

# Construct a stix pattern for a single IP address, either IPv4 or IPv6:
def ind_ip_pattern(string):
    if ipaddress.ip_address(string).version == 6:
        return f"[ipv6-addr:value = '{string}']"
    else:
        return f"[ipv4-addr:value = '{string}']"

# Return the value of the first key argument that exists in within:
def oneof(*keys, within):
    return next((within[key] for key in keys if key in within), None)

def query_opencti(alert, url, token):
    # The OpenCTI graphql query is filtering on a key and a list of values. By
    # default, this key is "value", unless set to "hashes.SHA256":
    filter_key='value'
    groups = alert['rule']['groups']

    # TODO: Look up registry keys/values? No such observables in OpenCTI yet from any sources
    
    log('# Alert groups: {}'.format(groups))

    # In case a key or index lookup fails, catch this and gracefully exit. Wrap
    # logic in a try–catch:
    try:
        # Group 'ids' may contain IP addresses.
        # This may be tailored for suricata, but we'll match against the "ids"
        # group. These keys are probably used by other decoders as well:
        if 'ids' in groups:
            # If data contains dns, it may contain a DNS query from packetbeat:
            if packetbeat_dns(alert):
                addrs = filter_packetbeat_dns(alert['data']['dns']['answers']) if 'answers' in alert['data']['dns'] else []
                filter_values = [alert['data']['dns']['question']['name']] + addrs
                ind_filter = [f"[domain-name:value = '{filter_values[0]}']", f"[hostname:value = '{filter_values[0]}']"] + list(map(lambda a: ind_ip_pattern(a), addrs))
                debug('# packetbeat DNS query: {}'.format(filter_values), do_log=True)
            else:
                # Look up either dest or source IP, whichever is public:
                filter_values = [next(filter(lambda x: x and ipaddress.ip_address(x).is_global, [oneof('dest_ip', 'dstip', within=alert['data']), oneof('src_ip', 'srcip', within=alert['data'])]), None)]
                ind_filter = [ind_ip_pattern(filter_values[0])] if filter_values else None
                debug('# IDS event - IPs found: {}'.format(filter_values), do_log=True)
            if not all(filter_values):
                debug('# IDS event - no valid IPs found, exiting', do_log=True)
                sys.exit()
        # Look up sha256 hashes for files added to the system or files that have been modified:
        elif 'syscheck_file' in groups and any(x in groups for x in ['syscheck_entry_added', 'syscheck_entry_modified']):
            filter_key = 'value'
            filter_values = [alert['syscheck']['sha256_after']]
            ind_filter = [f"[file:hashes.'SHA-256' = '{filter_values[0]}']"]
            debug(f'# Syscheck file hash: {filter_values[0]}', do_log=True)
            
        elif 'audit_command' in groups:
            # Extract any command line arguments that looks vaguely like a URL (starts with 'http'):
            filter_values = [val for val in alert['data']['audit']['execve'].values() if val.startswith('http')]
            ind_filter = list(map(lambda x: f"[url:value = '{x}']", filter_values))
            debug(f'# Audit command URLs found: {filter_values}', do_log=True)
            if not filter_values:
                debug('# Audit command - no URLs found, exiting', do_log=True)
                sys.exit()
        # SonicWall events contain source and destination IP addresses for threat intelligence lookup:
        elif 'sonicwall' in groups:
            # Skip SonicWall events that contain 'drop' in full_log (dropped packets)
            if 'full_log' in alert and 'drop' in alert['full_log'].lower():
                debug('# SonicWall - dropped packet detected, exiting', do_log=True)
                sys.exit()
            
            # Extract source and destination IPs from SonicWall data
            potential_ips = []
            if 'srcip' in alert['data'] and alert['data']['srcip']:
                potential_ips.append(alert['data']['srcip'])
            if 'dstip' in alert['data'] and alert['data']['dstip']:
                potential_ips.append(alert['data']['dstip'])
            
            # Filter for global (public) IP addresses only
            filter_values = [ip for ip in potential_ips if ip and ipaddress.ip_address(ip).is_global]
            log(f'# SonicWall - potential IPs: {potential_ips}, global IPs: {filter_values}')
            if filter_values:
                ind_filter = [ind_ip_pattern(ip) for ip in filter_values]
            else:
                log('# SonicWall - no global IPs found, exiting')
                sys.exit()
        # Fortigate events contain source and destination IP addresses for threat intelligence lookup:
        elif 'fortigate' in groups:
            # Skip events with private/internal actions (logout, config changes, etc.)
            skip_actions = ['logout', 'login', 'config']
            if 'action' in alert['data'] and alert['data']['action'].lower() in skip_actions:
                debug('# Fortigate - internal action detected, exiting', do_log=True)
                sys.exit()
            
            # Extract source and destination IPs from Fortigate data
            potential_ips = []
            if 'srcip' in alert['data'] and alert['data']['srcip']:
                potential_ips.append(alert['data']['srcip'])
            if 'dstip' in alert['data'] and alert['data']['dstip']:
                potential_ips.append(alert['data']['dstip'])
            
            # Filter for global (public) IP addresses only
            filter_values = [ip for ip in potential_ips if ip and ipaddress.ip_address(ip).is_global]
            log(f'# Fortigate - potential IPs: {potential_ips}, global IPs: {filter_values}')
            if filter_values:
                ind_filter = [ind_ip_pattern(ip) for ip in filter_values]
            else:
                log('# Fortigate - no global IPs found, exiting')
                sys.exit()
        # Nothing to do:
        else:
            log(f'# No matching rule groups found in {groups}, exiting')
            sys.exit()

    # Don't treat a non-existent index or key as an error. If they don't exist,
    # there is certainly no alert to make. Just quit:
    except IndexError:
        debug(f'# IndexError occurred: {str(e)}, exiting')
        sys.exit()
    except KeyError as e:
        debug(f'# KeyError occurred: {str(e)}, exiting')
        sys.exit()
    except Exception as e:
        log(f'# Unexpected error in query preparation: {str(e)}, exiting')
        sys.exit()
        
    debug(f'# Query filter_key: {filter_key}, filter_values: {filter_values}')
    debug(f'# Indicator filters: {ind_filter}')

    query_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}',
        'Accept': '*/*'
    }
    # Look for hashes, addresses and domain names is as many places as
    # possible, and return as much information as possible.
    api_json_body={'query':
            '''
            fragment Labels on StixCoreObject {
              objectLabel {
                value
              }
            }

            fragment Object on StixCoreObject {
              id
              type: entity_type
              created_at
              updated_at
              createdBy {
                ... on Identity {
                  id
                  standard_id
                  identity_class
                  name
                }
                ... on Organization {
                  x_opencti_organization_type
                  x_opencti_reliability
                }
                ... on Individual {
                  x_opencti_firstname
                  x_opencti_lastname
                }
              }
              ...Labels
              externalReferences {
                edges {
                  node {
                    url
                  }
                }
              }
            }

            fragment IndShort on Indicator {
              id
              name
              valid_until
              revoked
              confidence
              x_opencti_score
              x_opencti_detection
              indicator_types
              x_mitre_platforms
              pattern_type
              pattern
              ...Labels
              killChainPhases {
                kill_chain_name
              }
            }

            fragment IndLong on Indicator {
              ...Object
              ...IndShort
            }

            fragment Indicators on StixCyberObservable {
              indicators {
                edges {
                  node {
                    ...IndShort
                  }
                }
              }
            }

            fragment PageInfo on PageInfo {
              startCursor
              endCursor
              hasNextPage
              hasPreviousPage
              globalCount
            }

            fragment NameRelation on StixObjectOrStixRelationshipOrCreator {
              ... on DomainName {
                id
                value
                ...Indicators
              }
              ... on Hostname {
                id
                value
                ...Indicators
              }
            }

            fragment AddrRelation on StixObjectOrStixRelationshipOrCreator {
              ... on IPv4Addr {
                id
                value
                ...Indicators
              }
              ... on IPv6Addr {
                id
                value
                ...Indicators
              }
            }

            query IoCs($obs: FilterGroup, $ind: FilterGroup) {
              indicators(filters: $ind, first: 10) {
                edges {
                  node {
                    ...IndLong
                  }
                }
                pageInfo {
                  ...PageInfo
                }
              }
              stixCyberObservables(filters: $obs, first: 10) {
                edges {
                  node {
                    ...Object
                    observable_value
                    x_opencti_description
                    x_opencti_score
                    ...Indicators
                    ... on DomainName {
                      value
                      stixCoreRelationships(
                        toTypes: ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname"]
                      ) {
                        edges {
                          node {
                            type: toType
                            relationship_type
                            related: to {
                              ...AddrRelation
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on Hostname {
                      value
                      stixCoreRelationships(
                        toTypes: ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname"]
                      ) {
                        edges {
                          node {
                            type: toType
                            relationship_type
                            related: to {
                              ...AddrRelation
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on Url {
                      value
                      stixCoreRelationships(
                        toTypes: ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname"]
                      ) {
                        edges {
                          node {
                            type: toType
                            relationship_type
                            related: to {
                              ...AddrRelation
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on IPv4Addr {
                      value
                      stixCoreRelationships(fromTypes: ["Domain-Name", "Hostname"]) {
                        edges {
                          node {
                            type: fromType
                            relationship_type
                            related: from {
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on IPv6Addr {
                      value
                      stixCoreRelationships(fromTypes: ["Domain-Name", "Hostname"]) {
                        edges {
                          node {
                            type: fromType
                            relationship_type
                            related: from {
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on StixFile {
                      extensions
                      size
                      name
                      hashes {
                        algorithm
                        hash
                      }
                      x_opencti_additional_names
                    }
                  }
                }
                pageInfo {
                  ...PageInfo
                }
              }
            }
            ''' , 'variables': {
                    'obs': {
                        "mode": "or",
                        "filterGroups": [],
                        "filters": [{"key": filter_key, "values": filter_values}]
                    },
                    'ind': {
                        "mode": "and",
                        "filterGroups": [],
                        "filters": [
                            {"key": "pattern_type", "values": ["stix"]},
                            {"mode": "or", "key": "pattern", "values": ind_filter},
                        ]
                    }
                    }}
    #debug('# Query:')
    #debug(api_json_body)

    new_alerts = []
    try:
        debug(f'# Sending request to OpenCTI: {url}')
        response = requests.post(url, headers=query_headers, json=api_json_body)
        debug(f'# OpenCTI response status: {response.status_code}')
        
        # VALIDATE HTTP STATUS CODE
        if response.status_code != 200:
            debug(f'# HTTP error {response.status_code}: {response.text[:500]}')
            send_error_event(f'HTTP error {response.status_code} from OpenCTI API', alert['agent'])
            sys.exit(1)
        
    # Create an alert if the OpenCTI service cannot be reached:
    except ConnectionError as e:  
        log(f'# Connection error to OpenCTI: {str(e)}')
        log('Failed to connect to {}'.format(url))
        send_error_event('Failed to connect to the OpenCTI API', alert['agent'])
        sys.exit(1)
    except requests.exceptions.Timeout as e: 
        log(f'# Timeout connecting to OpenCTI: {str(e)}')
        send_error_event('Timeout connecting to the OpenCTI API', alert['agent'])
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        log(f'# Request error to OpenCTI: {str(e)}')
        send_error_event('Request error to OpenCTI API', alert['agent'])
        sys.exit(1)

    try:
        response = response.json()
        debug('# OpenCTI API request successful')
    except json.decoder.JSONDecodeError as e: 
        # If the API returns data, but not valid JSON, it is typically an error code.
        log(f'# JSON decode error: {str(e)}')
        log(f'# Response content: {response.text[:500]}')
        log('# Failed to parse response from API')
        send_error_event('Failed to parse response from OpenCTI API', alert['agent'])
        sys.exit(1)

    debug('# Response:')
    debug(response)

    # Check for GraphQL errors in response
    if 'errors' in response:
        log('# GraphQL errors in response: {}'.format(response['errors']))
        send_error_event('GraphQL errors from OpenCTI API: {}'.format(response['errors']), alert['agent'])
        sys.exit(1)

    # Check if response data is valid
    if not response.get('data'):
        log('# No data in response from OpenCTI API')
        send_error_event('No data in response from OpenCTI API', alert['agent'])
        sys.exit(1)

    indicators_count = len(response.get('data', {}).get('indicators', {}).get('edges', []))
    observables_count = len(response.get('data', {}).get('stixCyberObservables', {}).get('edges', []))
    log(f'# Response summary - Indicators: {indicators_count}, Observables: {observables_count}')

    if indicators_count == 0 and observables_count == 0:
        log('# No indicators or observables found in OpenCTI, no alerts generated')
        return []

    # Sort indicators based on a number of factors in order to prioritise them
    # in case many are returned:
    indicators_data = response.get('data', {}).get('indicators')
    if indicators_data and indicators_data.get('edges'):
        direct_indicators = sorted(
                # Extract the indicator objects (nodes) from the indicator list in
                # the response:
                list(map(lambda x:x['node'], indicators_data['edges'])),
                key=indicator_sort_func)
    else:
        direct_indicators = []
    # As opposed to indicators for observables, create an alert for every
    # indicator (limited by max_ind_alerts and the fixed limit in the query
    # (see "first: X")):
    for indicator in direct_indicators[:max_ind_alerts]:
        new_alert = {'integration': 'opencti', 'opencti': {
            'indicator': modify_indicator(indicator),
            'indicator_link': indicator_link(indicator),
            'query_key': filter_key,
            'query_values': ';'.join(ind_filter),
            'event_type': 'indicator_pattern_match' if indicator['pattern'] in ind_filter else 'indicator_partial_pattern_match',
            }}
        add_context(alert, new_alert)
        new_alerts.append(remove_empties(new_alert))

    # Safe processing of observables
    observables_data = response.get('data', {}).get('stixCyberObservables')
    if observables_data and observables_data.get('edges'):
        debug(f'# Processing {len(observables_data["edges"])} observables')  
        
        for i, edge in enumerate(observables_data['edges']):
            node = edge['node']
            debug(f'# Processing observable {i+1}: {node.get("observable_value", node.get("value", "unknown"))}')  

            # Create a list of the individual node objects in indicator edges:
            indicators = sort_indicators(list(map(lambda x:x['node'], node['indicators']['edges'])))
            # Get related obsverables (typically between IP addresses and domain
            # names) if they have indicators (retrieve only one indicator):
            related_obs_w_ind = relationship_with_indicators(node)

            # Remove indicators already found directly in the indicator query:
            if indicators:
                indicators = [i for i in indicators if i['id'] not in [di['id'] for di in direct_indicators]]
            if related_obs_w_ind and related_obs_w_ind['indicator']['id'] in [di['id'] for di in direct_indicators]:
                related_obs_w_ind = None

            # If the observable has no indicators, ignore it:
            if not indicators and not related_obs_w_ind:
                debug(f'# Observable {node["id"]} has no indicators, skipping')  
                debug(f'# Observable found ({node["id"]}), but it has no indicators')
                continue

            debug(f'# Observable {node["id"]} has {len(indicators)} indicators') 
            
            new_alert = {'integration': 'opencti', 'opencti': edge['node']}
            new_alert['opencti']['related'] = related_obs_w_ind
            new_alert['opencti']['query_key'] = filter_key
            new_alert['opencti']['query_values'] = ';'.join(filter_values)
            new_alert['opencti']['event_type'] = 'observable_with_indicator' if indicators else 'observable_with_related_indicator'

            modify_observable(new_alert['opencti'], indicators)

            add_context(alert, new_alert)
            # Remove all nulls, empty lists and objects, and empty strings:
            new_alerts.append(remove_empties(new_alert))
    else:
        debug('# No observables found in response') 
        
    debug(f'# Generated {len(new_alerts)} total alerts')  
    for i, alert_item in enumerate(new_alerts):
        event_type = alert_item['opencti'].get('event_type', 'unknown')
        debug(f'# Alert {i+1}: {event_type}')  

    return new_alerts


if __name__ == '__main__':
    try:
        if len(sys.argv) >= 4:
            debug('{0} {1} {2} {3}'.format(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else ''), do_log = True)
        else:
            log('Incorrect arguments: {0}'.format(' '.join(sys.argv)))
            sys.exit(1)

        DEBUG_ENABLED = len(sys.argv) > 4 and sys.argv[4] == 'debug'

        main(sys.argv)
    except Exception as e:
        debug(str(e), do_log = True)
        debug(traceback.format_exc(), do_log = True)
        raise
