import json
import numpy.matlib
import argparse
import numpy as np
import os

from util import split_filepath, command_param_list
from stats import process_event_counts, generate_event_counter
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


# kill me now, this is painful
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


def print_matrix(matrix_table: Dict[str, np.matlib.matrix]) -> None:
    for tactic, matrix in matrix_table.items():
        print(f'{tactic}:')
        print(matrix)


def print_sparse_matrix(matrix_table: Dict[str, np.matlib.matrix]) -> None:
    entries_per_line = 3
    for tactic, matrix in matrix_table.items():
        entries = 0
        for row_index in range(matrix.shape[0]):
            for col_index in range(matrix.shape[1]):
                if matrix[row_index, col_index] != 0:
                    print(f'(i: {row_index}, j: {col_index}, val: {matrix[row_index, col_index]}) ', end='')
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
netflow_counter = generate_event_counter('dport')

if OUTPUT_LOGDATA:
    output = 'STATISTICS FOR SYSMON LOGS (HOST: COM600-PC):'
    banner = '-' * len(output)
    print(banner)
    print(output)
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


reduced_events = filter(lambda x: x['computer_name'] == 'COM600-PC', process_create_events)
reduced_events = [reduce_event(event) for event in reduced_events]
