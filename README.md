# TorNATO
Cyberobservability Project

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
   "@timestamp":"2017-11-05T07:00:00.113Z",
   "beat":{
      "hostname":"HP-B53-01",
      "name":"HP-B53-01"
   },
   "category":"Logon",
   "computer_name":"HP-B53-01",
   "count":1,
   "event_id":4624,
   "level":"Information",
   "log_name":"Security",
   "message":"An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tHP-B53-01$\n\tAccount Domain:\t\tEME006\n\tLogon ID:\t\t0x3e7\n\nLogon Type:\t\t\t5\n\nNew Logon:\n\tSecurity ID:\t\tS-1-5-18\n\tAccount Name:\t\tSYSTEM\n\tAccount Domain:\t\tNT AUTHORITY\n\tLogon ID:\t\t0x3e7\n\tLogon GUID:\t\t{00000000-0000-0000-0000-000000000000}\n\nProcess Information:\n\tProcess ID:\t\t0x2d4\n\tProcess Name:\t\tC:\\Windows\\System32\\services.exe\n\nNetwork Information:\n\tWorkstation Name:\t\n\tSource Network Address:\t-\n\tSource Port:\t\t-\n\nDetailed Authentication Information:\n\tLogon Process:\t\tAdvapi  \n\tAuthentication Package:\tNegotiate\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\n\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\n\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\n\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.",
   "record_number":"74784",
   "source_name":"Microsoft-Windows-Security-Auditing",
   "type":"wineventlog"
}
```

### Sysmon
```json
{
   "@timestamp":"2018-10-09T04:26:40.523Z",
   "beat":{
      "hostname":"COM600-PC",
      "name":"COM600-PC",
      "version":"5.4.0"
   },
   "computer_name":"COM600-PC",
   "event_data":{
      "CommandLine":"C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding",
      "Company":"?",
      "CurrentDirectory":"C:\\Windows\\system32\\",
      "Description":"?",
      "FileVersion":"?",
      "Hashes":"SHA256=CBE2392792D209E15E44AC29E906FFDD5FBF6EED8BAB0D97D66E109AB2C5C56E",
      "Image":"C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
      "IntegrityLevel":"System",
      "LogonGuid":"{A2FC6897-EA0A-5B98-0000-0020E4030000}",
      "LogonId":"0x3e4",
      "ParentCommandLine":"C:\\Windows\\system32\\svchost.exe -k DcomLaunch",
      "ParentImage":"C:\\Windows\\System32\\svchost.exe",
      "ParentProcessGuid":"{A2FC6897-EA0A-5B98-0000-00100ACA0000}",
      "ParentProcessId":"612",
      "ProcessGuid":"{A2FC6897-2E00-5BBC-0000-00106DF3F78F}",
      "ProcessId":"5848",
      "Product":"?",
      "TerminalSessionId":"0",
      "User":"NT AUTHORITY\\NETWORK SERVICE",
      "UtcTime":"2018-10-09 04:26:40.522"
   },
   "event_id":1,
   "level":"Information",
   "log_name":"Microsoft-Windows-Sysmon/Operational",
   "message":"Process Create:\nRuleName: \nUtcTime: 2018-10-09 04:26:40.522\nProcessGuid: {A2FC6897-2E00-5BBC-0000-00106DF3F78F}\nProcessId: 5848\nImage: C:\\Windows\\System32\\wbem\\WmiPrvSE.exe\nFileVersion: ?\nDescription: ?\nProduct: ?\nCompany: ?\nCommandLine: C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding\nCurrentDirectory: C:\\Windows\\system32\\\nUser: NT AUTHORITY\\NETWORK SERVICE\nLogonGuid: {A2FC6897-EA0A-5B98-0000-0020E4030000}\nLogonId: 0x3e4\nTerminalSessionId: 0\nIntegrityLevel: System\nHashes: SHA256=CBE2392792D209E15E44AC29E906FFDD5FBF6EED8BAB0D97D66E109AB2C5C56E\nParentProcessGuid: {A2FC6897-EA0A-5B98-0000-00100ACA0000}\nParentProcessId: 612\nParentImage: C:\\Windows\\System32\\svchost.exe\nParentCommandLine: C:\\Windows\\system32\\svchost.exe -k DcomLaunch",
   "opcode":"Info",
   "process_id":940,
   "provider_guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
   "record_number":"109671",
   "source_name":"Microsoft-Windows-Sysmon",
   "task":"Process Create (rule: ProcessCreate)",
   "thread_id":2500,
   "type":"wineventlog",
   "user":{
      "domain":"NT AUTHORITY",
      "identifier":"S-1-5-18",
      "name":"SYSTEM",
      "type":"User"
   },
   "version":5
}
```