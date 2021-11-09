"""
Attack observables that might be observed.
"""

PROCESS_ATTACK_FEATURES = {
    # Lateral Movement
    'remote_desktop_protocol': [
        {'exe': 'tscon.exe'},
        {'exe': 'cmd.exe', 'params': ['/c']},
        {'exe': 'cmd.exe', 'params': ['/k']}
    ],
    'remote_file_copy': [{'exe': 'ftp.exe'}],
    'windows_admin_shares': [{'exe': 'net.exe', 'params': ['use']}],
    # Discovery
    'account_discovery': [{'exe': 'net.exe', 'params': ['user']}],
    'network_service_scanning': [{'exe': 'tcping.exe'}],
    'network_share_discovery': [
        {'exe': 'net.exe', 'params': ['view', '\\remotesystem']},
        {'exe': 'net.exe', 'params': ['share']}
    ],
    'password_policy_discovery': [{'exe': 'net.exe', 'params': ['accounts']}],
    'permission_groups_discovery': [
        {'exe': 'net.exe', 'params': ['group']},
        {'exe': 'net.exe', 'params': ['localgroup']}
    ],
    'process_discovery': [{'exe': 'tasklist.exe'}],
    'query_registry': [{'exe': 'reg.exe', 'params': ['query']}],
    'remote_system_discovery': [{'exe': 'net.exe', 'params': ['view']}],
    'security_software_discovery': [
        {'exe': 'netsh.exe'},
        {'exe': 'reg.exe', 'params': ['query']}
    ],
    'system_information_discovery': [{'exe': 'systeminfo.exe'}],
    'system_network_config_discovery': [
        {'exe': 'ipconfig.exe'},
        {'exe': 'nbtstat.exe'},
        {'exe': 'route.exe'}
    ],
    'system_network_conn_discovery': [
        {'exe': 'net.exe', 'params': ['use']},
        {'exe': 'net.exe', 'params': ['session']}
    ],
    'system_owner_discovery': [{'exe': 'whoami.exe'}],
    'system_service_discovery': [
        {'exe': 'net.exe', 'params': ['start']},
        {'exe': 'tasklist.exe', 'params': ['/svc']}
    ],
    'system_time_discovery': [{'exe': 'net.exe', 'params': ['time']}],
    # Execution
    'cmstp': [{'exe': 'cmstp.exe'}],
    'command_line_interface': [{'exe': 'cmd.exe'}],
    'control_panel_items': [
        {'exe': 'control.exe'},
        {'exe': 'rundll32.exe', 'params': ['shell32.dll,Control_RunDLL']}
    ],
    'dynamic_data_exchange': [
        {'parent_exe': 'winword.exe'},
        {'parent_exe': 'excel.exe'}
    ],
    'installutil': [{'exe': 'installutil.exe'}],
    'mshta': [{'exe': 'mshta.exe'}],
    'powershell': [{'exe': 'powershell.exe'}],
    'regsvc_regasm': [
        {'exe': 'regsvcs.exe'},
        {'exe': 'regasm.exe'}
    ],
    'regsvr32': [{'exe': 'regsvr32.exe'}],
    'rundll32': [{'exe': 'rundll32.exe'}],
    'scheduled_task': [
        {'exe': 'schtasks.exe'},
        {'parent_exe': 'taskeng.exe'}
    ],
    'scripting': [
        {'parent_exe': 'winword.exe'},
        {'parent_exe': 'excel.exe'}
    ],
    'service_execution': [
        {'exe': 'net.exe', 'params': ['start']},
        {'exe': 'net.exe', 'params': ['stop']}
    ],
    'signed_binary_proxy_exec': [
        {'exe': 'mavinject.exe'},
        {'exe': 'syncappvpublishingserver.exe'}
    ],
    'trusted_deverloper_utilities': [
        {'exe': 'MSBuild.exe'},
        {'exe': 'dnx.exe'},
        {'exe': 'rcsi.exe'},
        {'exe': 'WinDbg.exe'},
        {'exe': 'cdb.exe'},
        {'exe': 'tracker.exe'}
    ],
    'user_execution': [
        {'parent_exe': 'winword.exe'},
        {'parent_exe': 'excel.exe'}
    ],
    'windows_mgmt_instrumentation': [{'exe': 'wmic.exe'}],
    # Privilege Escalation
    'access_token_manipulation': [{'exe': 'runas.exe'}],
    'application_shimming': [{'exe': 'sdbinst.exe'}],
    'service_registry_perms_weakness': [
        {'exe': 'sc.exe'},
        {'exe': 'reg.exe'}
    ]
}

WINLOG_ATTACK_FEATURES = {
    'dcom': [528, 552, 4648],
    'logon_scripts': [528, 552],
    'pass_the_hash': [4624],
    'remote_desktop_protocol': [1149],
    'remote_file_copy': [1149],
    'windows_admin_shares': [528, 552, 4648],
    'windows_remote_management': [528, 552, 4648],
    'query_registry': [4656],
    'security_software_discovery': [4656],
    'accessibility_features': [4657],
    'appcert_dlls': [4657],
    'appinit_dlls': [4657],
    'application_shimming': [4657],
    'bypass_uac': [4657],
    'image_file_execution_options_injection': [4657],
    'port_monitors': [4657],
    'sid_history_injection': [4765, 4766],
    'service_registry_perms_weakness': [4657],
    'valid_accounts': [528, 552, 4648]
}

NETFLOW_ATTACK_FEATURES = {
    'application_deployment_software': [80, 443, 8443, 8082],
    'dcom': [135, 138, 139, 445],
    'logon_scripts': [445, 139],
    'pass_the_hash': [445, 139],
    'pass_the_ticket': [464, 389],
    'remote_desktop_protocol': [3389],
    'remote_file_copy': [20, 21, 22, 3389, 445],
    'ssh_hijacking': [22],
    'shared_webroot': [80, 443],
    'taint_shared_content': [135, 138, 139, 445],
    'third_party_software': [80, 443, 1433, 5900],
    'windows_admin_shares': [445, 139],
    'windows_remote_management': [445, 139]
}

TACTICS = {
    'lateral_movement': set(
        'application_deployment_software', 'dcom', 'logon_scripts', 'pass_the_hash',
        'pass_the_ticket', 'remote_desktop_protocol', 'remote_file_copy',
        'ssh_hijacking', 'shared_webroot', 'taint_shared_content',
        'third_party_software', 'windows_admin_shares', 'windows_remote_management'
    ),
    'discovery': set(
        'account_discovery', 'network_service_scanning', 'network_share_discovery',
        'password_policy_discovery', 'permission_groups_discovery',
        'process_discovery', 'query_registry', 'remote_system_discovery',
        'security_software_discovery', 'system_information_discovery',
        'system_network_config_discovery', 'system_network_conn_discovery',
        'system_owner_discovery', 'system_service_discovery', 'system_time_discovery'
    ),
    'execution': set(
        'cmstp', 'command_line_interface', 'control_panel_items',
        'dynamic_data_exchange', 'installutil', 'mshta', 'powershell', 'regsvc_regasm',
        'regsvr32', 'rundll32', 'scheduled_task', 'scripting', 'service_execution',
        'signed_binary_proxy_exec', 'trusted_deverloper_utilities', 'user_execution',
        'windows_mgmt_instrumentation'
    ),
    'privilege_escalation': set(
        'access_token_manipulation', 'accessibility_features', 'appcert_dlls',
        'appinit_dlls', 'application_shimming', 'bypass_uac',
        'image_file_execution_options_injection', 'port_monitors',
        'sid_history_injection', 'service_registry_perms_weakness', 'valid_accounts'
    )
}
