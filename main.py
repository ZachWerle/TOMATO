import json
import argparse
from json import encoder
from functools import reduce
import numpy as np
import os
import pandas as pd

from pandas import json_normalize
from definitions import HOST_IPS, HOST_TO_IP, HOSTNAMES
from ftactic import get_tactic_matrix
from observables import NETFLOW_ATTACK_FEATURES, PROCESS_ATTACK_FEATURES, TACTICS, WINLOG_ATTACK_FEATURES
from util import aggregate_matrix, safe_divide, split_filepath, command_param_list
from stats import evaluate_machine, process_event_counts, generate_event_counter
from typing import Dict, List

np.set_printoptions(precision=2, suppress=True)

# parse the command line arguments
# use -h or --help to display more information on the command line
parser = argparse.ArgumentParser(description='Configure the execution of the TOMATO script!',
                                 epilog='Thanks for using our program!')
parser.add_argument('-l',
                    '--logging',
                    action='store_true',
                    default=False,
                    help='Output the log data.')
parser.add_argument('-n',
                    '--netflow',
                    action='store_true',
                    default=False,
                    help='Use the netflow data and features.')
parser.add_argument('-s',
                    '--sysmon',
                    action='store_true',
                    default=False,
                    help='Use the sysmon data and features.')
parser.add_argument('-w',
                    '--winlog',
                    action='store_true',
                    default=False,
                    help='Use the winlog data and features.')

args = parser.parse_args()

OUTPUT_LOGDATA = args.logging
USE_SYSMON = args.sysmon
USE_WINLOG = args.winlog
USE_NETFLOW = args.netflow

message_builder = 'Initializing a full stats run with ' if OUTPUT_LOGDATA else 'Normal run with '
message_data = {
    'sysmon': USE_SYSMON,
    'winlog': USE_WINLOG,
    'netflow': USE_NETFLOW
}

usable_parameters = list(map(lambda x: x[0], filter(lambda x: x[1] is True, message_data.items())))

# why doesn't Python have case statements, ruby++
if len(usable_parameters) == 0:
    message_builder += 'nothing!'
elif len(usable_parameters) == 1:
    message_builder += 'just ' + usable_parameters[0]
elif len(usable_parameters) == 2:
    message_builder += ' and '.join(usable_parameters)
else:
    message_builder += ', '.join(usable_parameters[0:-1]) + ', and ' + usable_parameters[-1]

message_banner = '#' * len(message_builder)
print(message_banner)
print(message_builder)
print(message_banner)


def print_evaluation(stats) -> None:
    if not OUTPUT_LOGDATA:
        return None
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


def print_matrix(matrix_table: Dict[str, np.ndarray]) -> None:
    if isinstance(matrix_table, dict):
        for attack_tactic, attack_matrix in matrix_table.items():
            print(f'{attack_tactic}:')
            print(attack_matrix)
    else:
        print(matrix_table)


def print_sparse_matrix(matrix_table: Dict[str, np.ndarray]) -> None:
    entries_per_line = 3
    for _, attack_matrix in matrix_table.items():
        entries = 0
        for row_index in range(attack_matrix.shape[0]):
            for col_index in range(attack_matrix.shape[1]):
                if attack_matrix[row_index, col_index] != 0:
                    print(f'(i: {row_index}, j: {col_index}, val: {attack_matrix[row_index, col_index]}) ', end='')
                    entries += 1
                    if entries == entries_per_line:
                        print()
                        entries = 0
        print()


print("Loading dump files...")

with open(os.path.join('data', 'sysmon-10k.txt')) as sysmon:
    lines = map(lambda line: eval(line.strip()), sysmon.readlines())
    process_create_events = list(map(lambda line: json.loads(json.dumps(line)), lines))

with open(os.path.join('data', 'security-10k.txt')) as security:
    lines = map(lambda line: eval(line.strip()), security.readlines())
    security_events = list(map(lambda line: json.loads(json.dumps(line)), lines))

with open(os.path.join('data', 'netflow-v9-10k-relay.txt')) as netflow:
    lines = map(lambda line: eval(line.strip()), netflow.readlines())
    netflow_events = list(map(lambda line: json.loads(json.dumps(line)), lines))

print('Loading complete')

sysmon_counter = process_event_counts
winlog_counter = generate_event_counter('event_id')
netflow_counter = generate_event_counter('destination_port')

if OUTPUT_LOGDATA:
    message = 'STATISTICS FOR SYSMON LOGS (HOST: COM600-PC)'
    banner = '0' * len(message)
    print(banner)
    print(message)
    print(banner)


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


process_events = json_normalize(process_create_events)
process_events = process_events[process_events.computer_name == 'COM600-PC']

reduced_events = filter(lambda x: x['computer_name'] == 'COM600-PC', process_create_events)
reduced_events = [reduce_event(event) for event in reduced_events]
# temp = json_normalize(reduced_events)
# print(temp)

# pd.set_option('display.max_columns', None)
# test_one = json_normalize(security_events)
# print(test_one.columns)
# test_two = json_normalize(process_create_events)
# print(test_two.columns)
# test_three = json_normalize(netflow_events)
# print(test_three.columns)

sdata = evaluate_machine(reduced_events, PROCESS_ATTACK_FEATURES, sysmon_counter)
print_evaluation(sdata)

if OUTPUT_LOGDATA:
    message = 'STATISTICS FOR WINDOWS SECURITY LOGS (HOST: COM600-PC)'
    banner = '0' * len(message)
    print(banner)
    print(message)
    print(banner)

com600 = list(filter(lambda event: event['computer_name'] == 'COM600-PC', security_events))
cdata = evaluate_machine(com600, WINLOG_ATTACK_FEATURES, winlog_counter)
print_evaluation(cdata)

if OUTPUT_LOGDATA:
    message = 'STATISTICS FOR WINDOWS SECURITY LOGS (HOST: HP-B53-01)'
    banner = '0' * len(message)
    print(banner)
    print(message)
    print(banner)

hp_b53 = list(filter(lambda event: event['computer_name'] == 'HP-B53-01', security_events))
hdata = evaluate_machine(hp_b53, WINLOG_ATTACK_FEATURES, winlog_counter)
print_evaluation(hdata)

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

        netflow_pairs[host_pair] = netflow_pairs.get(host_pair, []) + [payload]

host_indices = {}
hostname_indices = {}
host_index = len(HOSTNAMES)

for index, elem in enumerate(HOSTNAMES):
    hostname_indices[elem] = index

for index, elem in enumerate(HOST_IPS):
    host_indices[elem] = index

src_log_counts = np.zeros(host_index)
dst_log_counts = np.zeros(host_index)
total_log_count = 0

f_tactic_matrix = get_tactic_matrix('data/tactic_matrix.npy', hostname_indices)
print(f_tactic_matrix)

p_cpd = {}
for tactic in TACTICS.keys():
    matrix = np.reshape(np.zeros(host_index * host_index), (host_index, host_index))
    i = host_indices[HOST_TO_IP['COM600-PC']]
    com600_total = 0
    com600_anomalous = 0
    if USE_SYSMON:
        com600_total += sdata['total_logs']
        com600_anomalous += sdata['tactics'][tactic]['count']
    if USE_WINLOG:
        com600_total += cdata['total_logs']
        com600_anomalous += cdata['tactics'][tactic]['count']

    matrix[i, i] = safe_divide(com600_total - com600_anomalous, com600_total)
    src_log_counts[i] += com600_total
    dst_log_counts[i] += com600_total
    total_log_count += com600_total

    if USE_WINLOG:
        j = host_indices[HOST_TO_IP['HP-B53-01']]
        hp_b53_total = hdata['total_logs']
        matrix[j, j] = 1 - hdata['tactics'][tactic]['frequency']
        src_log_counts[j] += hp_b53_total
        dst_log_counts[j] += hp_b53_total
        total_log_count += hp_b53_total

    p_cpd[tactic] = matrix

for keys, logs in netflow_pairs.items():
    src, dst = keys
    if OUTPUT_LOGDATA:
        message = f'NETFLOW STATISTICS FOR SRC: {src}, DST: {dst}'
        banner = '0' * len(message)
        print(banner)
        print(message)
        print(banner)

        i = host_indices[src]
        j = host_indices[dst]
        ndata = evaluate_machine(logs, NETFLOW_ATTACK_FEATURES, netflow_counter)
        if USE_NETFLOW:
            tactic = 'lateral_movement'
            p_cpd[tactic][i][j] = 1 - ndata['tactics'][tactic]['frequency']
            src_log_counts[i] += ndata['total_logs']
            dst_log_counts[i] += ndata['total_logs']
            total_log_count += ndata['total_logs']
        print_evaluation(ndata)

e_obsrv = {}
for index, (tactic, p_matrix) in enumerate(p_cpd.items()):
    e_obsrv[tactic] = p_matrix * f_tactic_matrix[tactic]

message = 'P_cpd Matrix'
banner = '0' * len(message)
print(banner)
print(message)
print(banner)
print_sparse_matrix(p_cpd)

message = 'F_tactic Matrix'
banner = '0' * len(message)
print(banner)
print(message)
print(banner)
print_matrix(f_tactic_matrix)

message = 'E_obsrv Matrix'
banner = '0' * len(message)
print(banner)
print(message)
print(banner)
print_sparse_matrix(e_obsrv)

message = 'Host Indices'
banner = '0' * len(message)
print(banner)
print(message)
print(banner)
for src, index in hostname_indices.items():
    print(f'{src} -> {index}')

message = 'Aggregated Host Scores'
banner = '0' * len(message)
print(banner)
print(message)
print(banner)
src_observ, dst_observ = aggregate_matrix(e_obsrv)

print(f'Destination Observability: {src_observ}')
print(f'Source Observability: {dst_observ}')

message = 'Aggregated Host Efficiency'
banner = '0' * len(message)
print(banner)
print(message)
print(banner)

src_host_efficiency = [safe_divide(src_observ[index], c) for index, c in enumerate(src_log_counts)]
dst_host_efficiency = [safe_divide(dst_observ[index], c) for index, c in enumerate(dst_log_counts)]

total_efficiency = safe_divide(reduce(lambda x, y: x + np.sum(y[1], axis=None, dtype=np.float32), e_obsrv.items(), 0),
                               total_log_count)

print(f'Destination Efficiency: {dst_host_efficiency}')
print(f'Source Host Efficiency: {dst_host_efficiency}')
print(f'Total Efficiency: {total_efficiency}')
