"""The code in this file is adapted from https://github.com/TorNATO-PRO/TOMATO by Nathan Waltz"""
import numpy as np
import json
from typing import Dict


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
    src_observ = np.sum(matrix['execution'], axis=0)
    dst_observ = np.sum(matrix['execution'], axis=1)

    return src_observ, dst_observ


def formalize_file(file_path):
    infile = open(file_path, "r", encoding="utf8")
    outfile = open("data/data.txt", "w", encoding="utf8")
    for line in infile.readlines():
        new_line = line.replace(":true", ":True")
        new_line = new_line.replace(":false", ":False")
        new_line = new_line.replace("timestamp", "@timestamp")
        outfile.write(new_line)
    infile.close()
    outfile.close()


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


def filter_events(filepath_keyword) -> list:
    events = list()
    with open("data/data.txt", encoding="utf8") as file:
        lines = map(lambda line: eval(line.strip()), file.readlines())
        all_events = list(map(lambda line: json.loads(json.dumps(line)), lines))
        for event in all_events:
            if 'full_log' in event and filepath_keyword.casefold() in event['full_log'].casefold():
                events += [event]
            elif 'location' in event and filepath_keyword.casefold() in event['location'].casefold():
                events += [event]
            elif 'data' in event and 'win' in event['data'] \
                    and filepath_keyword.casefold() in event['data']['win']['system']['providerName'].casefold():
                events += [event]
            elif 'rule' in event:
                for group in event['rule']['groups']:
                    if filepath_keyword.casefold() in group.casefold():
                        events += [event]
    return events
