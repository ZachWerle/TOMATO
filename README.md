# TOMATO
Cyberobservability Project

This program is used to analyze the observability of sensors/data collection tools in a network.
This version of TOMATO is specifically adapted for Wazuh alerts/logs.
The code in this project is adapted from https://github.com/TorNATO-PRO/TOMATO by Nathan Waltz which is a continuation of the research at https://ieeexplore.ieee.org/abstract/document/8788508.

INSTRUCTIONS:
Please see definitions.py for the input of your file and the creation of an adjacency graph for 
your network. Then while in the directory of the TOMATO project, type python main.py -h into your 
command prompt/terminal.

Python Version: 3.11.1

## Data Format Samples

### Netflow
```json
{
   "@timestamp":"2018-09-21T22:46:41.000Z",
   "netflow":{
      "version":9,
      "flow_seq_num":2864393,
      "flowset_id":1024,
      "ipv4_src_addr":"192.168.2.10",
      "ipv4_dst_addr":"192.168.2.101",
      "last_switched":"2018-09-21T22:46:37.999Z",
      "first_switched":"2018-09-21T22:03:42.999Z",
      "in_bytes":9248,
      "in_pkts":188,
      "input_snmp":0,
      "output_snmp":0,
      "l4_src_port":49172,
      "l4_dst_port":102,
      "protocol":6,
      "tcp_flags":24,
      "ip_protocol_version":4
   },
   "@version":"1",
   "host":"192.168.0.91"
}
```

### Security
```json
{
  "agent": {
    "ip": "10.0.2.9",
    "name": "DESKTOP-CKP652S",
    "id": "004"
  },
  "manager": {
    "name": "zachary-VirtualBox"
  },
  "data": {
    "win": {
      "eventdata": {
        "subjectLogonId": "0x3e7",
        "subjectDomainName": "WORKGROUP",
        "targetLinkedLogonId": "0xfe8a7",
        "impersonationLevel": "%%1833",
        "ipAddress": "127.0.0.1",
        "authenticationPackageName": "Negotiate",
        "workstationName": "DESKTOP-CKP652S",
        "targetLogonId": "0xfe8ef",
        "logonProcessName": "User32",
        "logonGuid": "{00000000-0000-0000-0000-000000000000}",
        "targetUserName": "mr.polite101@gmail.com",
        "keyLength": "0",
        "elevatedToken": "%%1843",
        "subjectUserSid": "S-1-5-18",
        "processId": "0x1a4",
        "processName": "C:\\\\Windows\\\\System32\\\\svchost.exe",
        "ipPort": "0",
        "targetDomainName": "MicrosoftAccount",
        "targetUserSid": "S-1-5-21-1031314314-1681699775-55260578-1002",
        "virtualAccount": "%%1843",
        "logonType": "11",
        "subjectUserName": "DESKTOP-CKP652S$"
      },
      "system": {
        "eventID": "4624",
        "keywords": "0x8020000000000000",
        "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        "level": "0",
        "channel": "Security",
        "opcode": "0",
        "message": "\"An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-5-18\r\n\tAccount Name:\t\tDESKTOP-CKP652S$\r\n\tAccount Domain:\t\tWORKGROUP\r\n\tLogon ID:\t\t0x3E7\r\n\r\nLogon Information:\r\n\tLogon Type:\t\t11\r\n\tRestricted Admin Mode:\t-\r\n\tVirtual Account:\t\tNo\r\n\tElevated Token:\t\tNo\r\n\r\nImpersonation Level:\t\tImpersonation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-21-1031314314-1681699775-55260578-1002\r\n\tAccount Name:\t\tmr.polite101@gmail.com\r\n\tAccount Domain:\t\tMicrosoftAccount\r\n\tLogon ID:\t\t0xFE8EF\r\n\tLinked Logon ID:\t\t0xFE8A7\r\n\tNetwork Account Name:\t-\r\n\tNetwork Account Domain:\t-\r\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x1a4\r\n\tProcess Name:\t\tC:\\Windows\\System32\\svchost.exe\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\tDESKTOP-CKP652S\r\n\tSource Network Address:\t127.0.0.1\r\n\tSource Port:\t\t0\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tUser32 \r\n\tAuthentication Package:\tNegotiate\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\"",
        "version": "2",
        "systemTime": "2022-12-27T22:57:20.6791696Z",
        "eventRecordID": "36349",
        "threadID": "796",
        "computer": "DESKTOP-CKP652S",
        "task": "12544",
        "processID": "696",
        "severityValue": "AUDIT_SUCCESS",
        "providerName": "Microsoft-Windows-Security-Auditing"
      }
    }
  },
  "rule": {
    "firedtimes": 10,
    "mail": true,
    "level": 15,
    "description": "User: WORKGROUP\\mr.polite101@gmail.com logged using Remote Desktop Connection (RDP) from loopback address, possible exploit over reverse tunneling using stolen credentials.",
    "groups": [
      "win_evt_channel"
    ],
    "mitre": {
      "technique": [
        "Remote Desktop Protocol",
        "Domain Accounts"
      ],
      "id": [
        "T1021.001",
        "T1078.002"
      ],
      "tactic": [
        "Lateral Movement",
        "Defense Evasion",
        "Persistence",
        "Privilege Escalation",
        "Initial Access"
      ]
    },
    "id": "92656"
  },
  "decoder": {
    "name": "windows_eventchannel"
  },
  "full_log": "{\"win\":{\"system\":{\"providerName\":\"Microsoft-Windows-Security-Auditing\",\"providerGuid\":\"{54849625-5478-4994-a5ba-3e3b0328c30d}\",\"eventID\":\"4624\",\"version\":\"2\",\"level\":\"0\",\"task\":\"12544\",\"opcode\":\"0\",\"keywords\":\"0x8020000000000000\",\"systemTime\":\"2022-12-27T22:57:20.6791696Z\",\"eventRecordID\":\"36349\",\"processID\":\"696\",\"threadID\":\"796\",\"channel\":\"Security\",\"computer\":\"DESKTOP-CKP652S\",\"severityValue\":\"AUDIT_SUCCESS\",\"message\":\"\\\"An account was successfully logged on.\\r\\n\\r\\nSubject:\\r\\n\\tSecurity ID:\\t\\tS-1-5-18\\r\\n\\tAccount Name:\\t\\tDESKTOP-CKP652S$\\r\\n\\tAccount Domain:\\t\\tWORKGROUP\\r\\n\\tLogon ID:\\t\\t0x3E7\\r\\n\\r\\nLogon Information:\\r\\n\\tLogon Type:\\t\\t11\\r\\n\\tRestricted Admin Mode:\\t-\\r\\n\\tVirtual Account:\\t\\tNo\\r\\n\\tElevated Token:\\t\\tNo\\r\\n\\r\\nImpersonation Level:\\t\\tImpersonation\\r\\n\\r\\nNew Logon:\\r\\n\\tSecurity ID:\\t\\tS-1-5-21-1031314314-1681699775-55260578-1002\\r\\n\\tAccount Name:\\t\\tmr.polite101@gmail.com\\r\\n\\tAccount Domain:\\t\\tMicrosoftAccount\\r\\n\\tLogon ID:\\t\\t0xFE8EF\\r\\n\\tLinked Logon ID:\\t\\t0xFE8A7\\r\\n\\tNetwork Account Name:\\t-\\r\\n\\tNetwork Account Domain:\\t-\\r\\n\\tLogon GUID:\\t\\t{00000000-0000-0000-0000-000000000000}\\r\\n\\r\\nProcess Information:\\r\\n\\tProcess ID:\\t\\t0x1a4\\r\\n\\tProcess Name:\\t\\tC:\\\\Windows\\\\System32\\\\svchost.exe\\r\\n\\r\\nNetwork Information:\\r\\n\\tWorkstation Name:\\tDESKTOP-CKP652S\\r\\n\\tSource Network Address:\\t127.0.0.1\\r\\n\\tSource Port:\\t\\t0\\r\\n\\r\\nDetailed Authentication Information:\\r\\n\\tLogon Process:\\t\\tUser32 \\r\\n\\tAuthentication Package:\\tNegotiate\\r\\n\\tTransited Services:\\t-\\r\\n\\tPackage Name (NTLM only):\\t-\\r\\n\\tKey Length:\\t\\t0\\r\\n\\r\\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\\r\\n\\r\\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\\r\\n\\r\\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\\r\\n\\r\\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\\r\\n\\r\\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\\r\\n\\r\\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\\r\\n\\r\\nThe authentication information fields provide detailed information about this specific logon request.\\r\\n\\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\\r\\n\\t- Transited services indicate which intermediate services have participated in this logon request.\\r\\n\\t- Package name indicates which sub-protocol was used among the NTLM protocols.\\r\\n\\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.\\\"\"},\"eventdata\":{\"subjectUserSid\":\"S-1-5-18\",\"subjectUserName\":\"DESKTOP-CKP652S$\",\"subjectDomainName\":\"WORKGROUP\",\"subjectLogonId\":\"0x3e7\",\"targetUserSid\":\"S-1-5-21-1031314314-1681699775-55260578-1002\",\"targetUserName\":\"mr.polite101@gmail.com\",\"targetDomainName\":\"MicrosoftAccount\",\"targetLogonId\":\"0xfe8ef\",\"logonType\":\"11\",\"logonProcessName\":\"User32\",\"authenticationPackageName\":\"Negotiate\",\"workstationName\":\"DESKTOP-CKP652S\",\"logonGuid\":\"{00000000-0000-0000-0000-000000000000}\",\"keyLength\":\"0\",\"processId\":\"0x1a4\",\"processName\":\"C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\svchost.exe\",\"ipAddress\":\"127.0.0.1\",\"ipPort\":\"0\",\"impersonationLevel\":\"%%1833\",\"virtualAccount\":\"%%1843\",\"targetLinkedLogonId\":\"0xfe8a7\",\"elevatedToken\":\"%%1843\"}}}",
  "input": {
    "type": "log"
  },
  "@timestamp": "2022-12-27T22:57:22.221Z",
  "location": "EventChannel",
  "id": "1672181842.597751",
  "timestamp": "2022-12-27T14:57:22.221-0800",
  "_id": "3yjOVYUBP2FetjEtLC-e"
}
```

### Sysmon
```json
{
  "agent": {
    "ip": "10.0.2.6",
    "name": "DESKTOP-9LO9B7Q",
    "id": "007"
  },
  "manager": {
    "name": "zachary-VirtualBox"
  },
  "data": {
    "win": {
      "eventdata": {
        "originalFileName": "svchost.exe",
        "image": "C:\\\\Windows\\\\System32\\\\svchost.exe",
        "product": "Microsoft® Windows® Operating System",
        "parentProcessGuid": "{00000000-0000-0000-0000-000000000000}",
        "description": "Host Process for Windows Services",
        "logonGuid": "{32fb43f2-7780-63ab-e703-000000000000}",
        "processGuid": "{32fb43f2-9d53-63ab-8414-000000001b00}",
        "logonId": "0x3e7",
        "parentProcessId": "660",
        "processId": "4644",
        "currentDirectory": "C:\\\\Windows\\\\system32\\\\",
        "utcTime": "2022-12-28 01:35:15.998",
        "hashes": "SHA256=643EC58E82E0272C97C2A59F6020970D881AF19C0AD5029DB9C958C13B6558C7",
        "company": "Microsoft Corporation",
        "commandLine": "C:\\\\Windows\\\\system32\\\\svchost.exe -k LocalSystemNetworkRestricted",
        "integrityLevel": "System",
        "fileVersion": "10.0.19041.546 (WinBuild.160101.0800)",
        "user": "NT AUTHORITY\\\\SYSTEM",
        "terminalSessionId": "0"
      },
      "system": {
        "eventID": "1",
        "keywords": "0x8000000000000000",
        "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
        "level": "4",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "opcode": "0",
        "message": "\"Process Create:\r\nRuleName: -\r\nUtcTime: 2022-12-28 01:35:15.998\r\nProcessGuid: {32fb43f2-9d53-63ab-8414-000000001b00}\r\nProcessId: 4644\r\nImage: C:\\Windows\\System32\\svchost.exe\r\nFileVersion: 10.0.19041.546 (WinBuild.160101.0800)\r\nDescription: Host Process for Windows Services\r\nProduct: Microsoft® Windows® Operating System\r\nCompany: Microsoft Corporation\r\nOriginalFileName: svchost.exe\r\nCommandLine: C:\\Windows\\system32\\svchost.exe -k LocalSystemNetworkRestricted\r\nCurrentDirectory: C:\\Windows\\system32\\\r\nUser: NT AUTHORITY\\SYSTEM\r\nLogonGuid: {32fb43f2-7780-63ab-e703-000000000000}\r\nLogonId: 0x3E7\r\nTerminalSessionId: 0\r\nIntegrityLevel: System\r\nHashes: SHA256=643EC58E82E0272C97C2A59F6020970D881AF19C0AD5029DB9C958C13B6558C7\r\nParentProcessGuid: {00000000-0000-0000-0000-000000000000}\r\nParentProcessId: 660\r\nParentImage: -\r\nParentCommandLine: -\r\nParentUser: -\"",
        "version": "5",
        "systemTime": "2022-12-28T01:35:16.0024910Z",
        "eventRecordID": "59112",
        "threadID": "2748",
        "computer": "DESKTOP-9LO9B7Q",
        "task": "1",
        "processID": "2128",
        "severityValue": "INFORMATION",
        "providerName": "Microsoft-Windows-Sysmon"
      }
    }
  },
  "rule": {
    "firedtimes": 27,
    "mail": true,
    "level": 12,
    "pci_dss": [
      "10.6.1",
      "11.4"
    ],
    "hipaa": [
      "164.312.b"
    ],
    "tsc": [
      "CC7.2",
      "CC7.3",
      "CC6.1",
      "CC6.8"
    ],
    "description": "Sysmon - Suspicious Process - svchost.exe",
    "groups": [
      "windows",
      "sysmon",
      "sysmon_process-anomalies"
    ],
    "mitre": {
      "technique": [
        "Process Injection"
      ],
      "id": [
        "T1055"
      ],
      "tactic": [
        "Defense Evasion",
        "Privilege Escalation"
      ]
    },
    "id": "61618",
    "nist_800_53": [
      "AU.6",
      "SI.4"
    ],
    "gdpr": [
      "IV_35.7.d"
    ]
  },
  "decoder": {
    "name": "windows_eventchannel"
  },
  "full_log": "{\"win\":{\"system\":{\"providerName\":\"Microsoft-Windows-Sysmon\",\"providerGuid\":\"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}\",\"eventID\":\"1\",\"version\":\"5\",\"level\":\"4\",\"task\":\"1\",\"opcode\":\"0\",\"keywords\":\"0x8000000000000000\",\"systemTime\":\"2022-12-28T01:35:16.0024910Z\",\"eventRecordID\":\"59112\",\"processID\":\"2128\",\"threadID\":\"2748\",\"channel\":\"Microsoft-Windows-Sysmon/Operational\",\"computer\":\"DESKTOP-9LO9B7Q\",\"severityValue\":\"INFORMATION\",\"message\":\"\\\"Process Create:\\r\\nRuleName: -\\r\\nUtcTime: 2022-12-28 01:35:15.998\\r\\nProcessGuid: {32fb43f2-9d53-63ab-8414-000000001b00}\\r\\nProcessId: 4644\\r\\nImage: C:\\\\Windows\\\\System32\\\\svchost.exe\\r\\nFileVersion: 10.0.19041.546 (WinBuild.160101.0800)\\r\\nDescription: Host Process for Windows Services\\r\\nProduct: Microsoft® Windows® Operating System\\r\\nCompany: Microsoft Corporation\\r\\nOriginalFileName: svchost.exe\\r\\nCommandLine: C:\\\\Windows\\\\system32\\\\svchost.exe -k LocalSystemNetworkRestricted\\r\\nCurrentDirectory: C:\\\\Windows\\\\system32\\\\\\r\\nUser: NT AUTHORITY\\\\SYSTEM\\r\\nLogonGuid: {32fb43f2-7780-63ab-e703-000000000000}\\r\\nLogonId: 0x3E7\\r\\nTerminalSessionId: 0\\r\\nIntegrityLevel: System\\r\\nHashes: SHA256=643EC58E82E0272C97C2A59F6020970D881AF19C0AD5029DB9C958C13B6558C7\\r\\nParentProcessGuid: {00000000-0000-0000-0000-000000000000}\\r\\nParentProcessId: 660\\r\\nParentImage: -\\r\\nParentCommandLine: -\\r\\nParentUser: -\\\"\"},\"eventdata\":{\"utcTime\":\"2022-12-28 01:35:15.998\",\"processGuid\":\"{32fb43f2-9d53-63ab-8414-000000001b00}\",\"processId\":\"4644\",\"image\":\"C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\svchost.exe\",\"fileVersion\":\"10.0.19041.546 (WinBuild.160101.0800)\",\"description\":\"Host Process for Windows Services\",\"product\":\"Microsoft® Windows® Operating System\",\"company\":\"Microsoft Corporation\",\"originalFileName\":\"svchost.exe\",\"commandLine\":\"C:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\svchost.exe -k LocalSystemNetworkRestricted\",\"currentDirectory\":\"C:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\\",\"user\":\"NT AUTHORITY\\\\\\\\SYSTEM\",\"logonGuid\":\"{32fb43f2-7780-63ab-e703-000000000000}\",\"logonId\":\"0x3e7\",\"terminalSessionId\":\"0\",\"integrityLevel\":\"System\",\"hashes\":\"SHA256=643EC58E82E0272C97C2A59F6020970D881AF19C0AD5029DB9C958C13B6558C7\",\"parentProcessGuid\":\"{00000000-0000-0000-0000-000000000000}\",\"parentProcessId\":\"660\"}}}",
  "input": {
    "type": "log"
  },
  "@timestamp": "2022-12-28T01:35:16.614Z",
  "location": "EventChannel",
  "id": "1672191316.26025597",
  "timestamp": "2022-12-27T17:35:16.614-0800",
  "_id": "lSleVoUBP2FetjEtpLNr"
}
```
### Suricata
```json
{
  "agent": {
    "ip": "10.0.2.6",
    "name": "DESKTOP-9LO9B7Q",
    "id": "007"
  },
  "manager": {
    "name": "zachary-VirtualBox"
  },
  "data": {
    "in_iface": "\\Device\\NPF_{AA371BF3-1C48-40C2-9559-328769FC414F}",
    "src_ip": "10.0.2.8",
    "src_port": "52664",
    "event_type": "alert",
    "alert": {
      "severity": "2",
      "signature_id": "2003068",
      "rev": "7",
      "metadata": {
        "updated_at": [
          "2010_07_30"
        ],
        "created_at": [
          "2010_07_30"
        ]
      },
      "gid": "1",
      "signature": "ET SCAN Potential SSH Scan OUTBOUND",
      "action": "allowed",
      "category": "Attempted Information Leak"
    },
    "flow_id": "1267808264914164.000000",
    "dest_ip": "10.0.2.6",
    "proto": "TCP",
    "dest_port": "22",
    "flow": {
      "pkts_toserver": "1",
      "start": "2022-12-27T17:35:02.918772-0900",
      "bytes_toclient": "0",
      "bytes_toserver": "66",
      "pkts_toclient": "0"
    },
    "timestamp": "2022-12-27T17:35:02.918772-0900"
  },
  "rule": {
    "firedtimes": 107,
    "mail": false,
    "level": 3,
    "description": "Suricata: Alert - ET SCAN Potential SSH Scan OUTBOUND",
    "groups": [
      "ids",
      "suricata"
    ],
    "id": "86601"
  },
  "decoder": {
    "name": "json"
  },
  "input": {
    "type": "log"
  },
  "@timestamp": "2022-12-28T01:35:04.971Z",
  "location": "\\Program Files\\Suricata\\log\\eve.json",
  "id": "1672191304.26000539",
  "timestamp": "2022-12-27T17:35:04.971-0800",
  "_id": "iyleVoUBP2FetjEtbbO1"
}
```