"""
This file is for functions related to processing the different kinds of events in data.txt
"""
from observables import NETWORK_ATTACK_FEATURES, PROCESS_ATTACK_FEATURES, WINLOG_ATTACK_FEATURES
from definitions import HOST_IPS, WAZUH
from util import split_filepath, command_param_list
from stats import evaluate_machine
from typing import Dict


def print_evaluation(stats) -> None:
    for key, value in stats['tactics'].items():
        f = value['frequency']
        a = value['anomalous']
        print(f'tactic: {key}, freq: {f}, anomalous freq: {a}')

    print('Total anomalous logs: {0}'.format(stats['total_anomalous']))
    print('Total logs: {0}'.format(stats['total_logs']))
    print('P(Features | Events) = {0}'.format(stats['prob']))
    print('Start time: {0}'.format(stats['start_time']))
    print('End time: {0}'.format(stats['finish_time']))
    print('Time difference: {0} days'.format(stats['time_diff']))
    print('Frequency: {0} logs / day'.format(stats['log_freq']))
    print('Anomalous Freq: {0} logs / day'.format(stats['anomalous']))


def reduce_event(meta_event) -> Dict[str, str]:
    if WAZUH:
        event = meta_event['data']['win']['eventdata']
        path, file = "N/A", "N/A"
        ppath, pfile = "N/A", "N/A"
        params = "N/A"
        if 'image' in event:
            path, file = split_filepath(event['image'])
        if 'parentImage' in event:
            ppath, pfile = split_filepath(event['parentImage'])
        if 'commandLine' in event:
            params = command_param_list(event["commandLine"])
        event_dict = {
            'exe': file,
            'parent_exe': pfile,
            'path': path,
            'parent_path': ppath,
            'params': params,
            '@timestamp': meta_event['@timestamp']
        }
    else:
        event = meta_event['event_data']
        path, file = split_filepath(event['Image'])
        ppath, pfile = split_filepath(event['ParentImage'])
        event_dict = {
            'exe': file,
            'parent_exe': pfile,
            'path': path,
            'parent_path': ppath,
            'params': command_param_list(event["CommandLine"]),
            '@timestamp': meta_event['@timestamp']
        }
    return event_dict


def generate_network_pairs(network_events) -> Dict:
    network_pairs = dict()
    if WAZUH:
        for event in network_events:
            if 'data' in event:
                suricata = event['data']
                src = "N/A"
                dst = "N/A"
                if 'src_ip' in suricata:
                    src = suricata['src_ip']
                if 'dest_ip' in suricata:
                    dst = suricata['dest_ip']
                if src in HOST_IPS and dst in HOST_IPS and 'dest_port' in suricata:
                    host_pair = (src, dst)
                    payload = {
                        'dest_port': suricata['dest_port'],
                        '@timestamp': event['@timestamp']
                    }
                    if host_pair in network_pairs:
                        network_pairs[host_pair] = network_pairs[host_pair] + [payload]
                    else:
                        network_pairs[host_pair] = [payload]
    else:
        for event in network_events:
            netflow = event['netflow']
            src = netflow['ipv4_src_addr']
            dst = netflow['ipv4_dst_addr']
            if src in HOST_IPS and dst in HOST_IPS:
                host_pair = (src, dst)
                payload = {
                    'destination_port': netflow['l4_dst_port'],
                    '@timestamp': event['@timestamp']
                }
                if host_pair in network_pairs:
                    network_pairs[host_pair] = network_pairs[host_pair] + [payload]
                else:
                    network_pairs[host_pair] = [payload]
    return network_pairs


def process_sysmon(hostname, process_create_events, sysmon_counter) -> Dict:
    message = 'STATISTICS FOR SYSMON LOGS Host: ' + hostname
    banner = '0' * len(message)
    print(banner)
    print(message)
    print(banner)
    if WAZUH:
        reduced_events = filter(lambda x: x['agent']['name'] == hostname, process_create_events)
    else:
        reduced_events = filter(lambda x: x['computer_name'] == hostname, process_create_events)
    reduced_events = [reduce_event(event) for event in reduced_events]
    sdata = evaluate_machine(reduced_events, PROCESS_ATTACK_FEATURES, sysmon_counter)
    print_evaluation(sdata)
    return sdata


def process_winlogs(hostname, security_events, winlog_counter) -> Dict:
    message = 'STATISTICS FOR WINDOWS SECURITY LOGS Host: ' + hostname
    banner = '0' * len(message)
    print(banner)
    print(message)
    print(banner)
    if WAZUH:
        reduced_events = filter(lambda x: x['agent']['name'] == hostname, security_events)
    else:
        reduced_events = filter(lambda x: x['computer_name'] == hostname, security_events)
    reduced_events = list(reduced_events)
    cdata = evaluate_machine(reduced_events, WINLOG_ATTACK_FEATURES, winlog_counter)
    print_evaluation(cdata)
    return cdata


def process_suricata(src, dst, logs, suricata_counter) -> Dict:
    message = f'SURICATA STATISTICS FOR SRC: {src}, DST: {dst}'
    banner = '0' * len(message)
    print(banner)
    print(message)
    print(banner)
    ndata = evaluate_machine(logs, NETWORK_ATTACK_FEATURES, suricata_counter)
    print_evaluation(ndata)
    return ndata


def process_netflow(src, dst, logs, netflow_counter) -> Dict:
    message = f'NETFLOW STATISTICS FOR SRC: {src}, DST: {dst}'
    banner = '0' * len(message)
    print(banner)
    print(message)
    print(banner)
    ndata = evaluate_machine(logs, NETWORK_ATTACK_FEATURES, netflow_counter)
    print_evaluation(ndata)
    return ndata
