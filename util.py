"""The code in this file is adapted from https://github.com/TorNATO-PRO/TOMATO by Nathan Waltz"""
import numpy as np
from typing import Dict, List
from definitions import HOST_TO_IP
from observables import TACTICS


def split_filepath(path):
    dirs = path.split('\\')
    return '\\'.join(dirs[0:-1]), dirs[-1]


def command_param_list(command):
    return [command.strip('\"').strip() for command in command.split(' ')]


def safe_divide(a: float, b: float):
    if b == 0:
        return 0
    
    return a / b


def aggregate_matrix(matrix):
    src_observ = [0] * len(HOST_TO_IP)
    dst_observ = [0] * len(HOST_TO_IP)
    for tactic in TACTICS:
        src_sum = np.sum(matrix[tactic], axis=1)
        dst_sum = np.sum(matrix[tactic], axis=0)
        for host_indx in range(len(HOST_TO_IP)):
            src_observ[host_indx] += src_sum[host_indx]
            dst_observ[host_indx] += dst_sum[host_indx]

    return src_observ, dst_observ


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


# Filter the logs from the file at file_path using a provided keyword that should appear somewhere in the log/event.
# Return a list of these logs/events.
def filter_events(file_path: str, keyword: str) -> List[Dict[str, any]]:
    """
    :param file_path: a string of the file path to your input file/dataset
    :param keyword: a string that identifies the type of event that you want. A signature of the event that appears
    somewhere in it
    :return: a list of filtered logs/events from the file
    """
    events = list()
    with open(file_path, encoding="utf8") as file:
        for line in file.readlines():
            new_line = line.replace(":true", ":True")
            new_line = new_line.replace(":false", ":False")
            new_line = new_line.replace("timestamp", "@timestamp")
            event = eval(new_line.strip())
            if 'full_log' in event and keyword.casefold() in event['full_log'].casefold():
                events += [event]
            elif 'location' in event and keyword.casefold() in event['location'].casefold():
                events += [event]
            elif 'data' in event and 'win' in event['data'] \
                    and keyword.casefold() in event['data']['win']['system']['providerName'].casefold():
                events += [event]
            elif 'rule' in event:
                for group in event['rule']['groups']:
                    if keyword.casefold() in group.casefold():
                        events += [event]
    return events
