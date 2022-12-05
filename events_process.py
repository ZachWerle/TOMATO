"""
This file is for functions related to processing the different kinds of events in data.txt
"""
from observables import NETFLOW_ATTACK_FEATURES, PROCESS_ATTACK_FEATURES, WINLOG_ATTACK_FEATURES
from definitions import HOST_IPS
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


def generate_netflow_pairs(netflow_events) -> Dict:
    netflow_pairs = dict()
    for event in netflow_events:
        netflow = event['netflow']
        src = netflow['ipv4_src_addr']
        dst = netflow['ipv4_dst_addr']
        if src in HOST_IPS and dst in HOST_IPS:
            host_pair = (src, dst)
            payload = {
                'destination_port': netflow['l4_dst_port'],
                '@timestamp': event['@timestamp']
            }
            netflow_pairs[host_pair] = payload
    return netflow_pairs


def process_sysmon(hostname, process_create_events, sysmon_counter) -> Dict:
    message = 'STATISTICS FOR SYSMON LOGS Host: ' + hostname
    banner = '0' * len(message)
    print(banner)
    print(message)
    print(banner)
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
    com600 = list(filter(lambda event: event['computer_name'] == hostname, security_events))
    cdata = evaluate_machine(com600, WINLOG_ATTACK_FEATURES, winlog_counter)
    print_evaluation(cdata)
    return cdata


def process_netflow(src, dst, logs, netflow_counter):
    message = f'NETFLOW STATISTICS FOR SRC: {src}, DST: {dst}'
    banner = '0' * len(message)
    print(banner)
    print(message)
    print(banner)
    ndata = evaluate_machine(logs, NETFLOW_ATTACK_FEATURES, netflow_counter)
    print_evaluation(ndata)
