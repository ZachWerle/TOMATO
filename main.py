"""
This program is used to analyze the observability of sensors/data collection tools in a network.
The code in this file is adapted from https://github.com/TorNATO-PRO/TOMATO by Nathan Waltz
"""
import argparse
from functools import reduce
import numpy as np

from definitions import HOST_IPS, HOST_TO_IP, HOSTNAMES, DATA_FILE
from ftactic import get_tactic_matrix
from observables import TACTICS
from util import aggregate_matrix, safe_divide, print_matrix, print_sparse_matrix, filter_events
from stats import process_event_counts, generate_event_counter
from events_process import process_sysmon, process_winevent, process_suricata, generate_network_pairs

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
parser.add_argument('-su',
                    '--suricata',
                    action='store_true',
                    default=False,
                    help='Use the suricata data and features.')
parser.add_argument('-s',
                    '--sysmon',
                    action='store_true',
                    default=False,
                    help='Use the sysmon data and features.')
parser.add_argument('-w',
                    '--winevent',
                    action='store_true',
                    default=False,
                    help='Use the windows event channel data and features.')

args = parser.parse_args()

OUTPUT_LOGDATA = args.logging
USE_SYSMON = args.sysmon
USE_WINEVENT = args.winevent
USE_SURICATA = args.suricata

message_builder = 'Initializing a full stats run with ' if OUTPUT_LOGDATA else 'Normal run with '
message_data = {
    'sysmon': USE_SYSMON,
    'winevent': USE_WINEVENT,
    'suricata': USE_SURICATA
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

print("Loading {} file...".format(DATA_FILE))

process_create_events = list()
security_events = list()
suricata_events = list()

# Filter the DATA_FILE file for specific events based on a provided keyword
if USE_SYSMON:
    process_create_events = filter_events(DATA_FILE, 'Microsoft-Windows-Sysmon')
if USE_WINEVENT:
    security_events = filter_events(DATA_FILE, 'Microsoft-Windows-Security')
if USE_SURICATA:
    suricata_events = filter_events(DATA_FILE, 'Suricata')

print('Loading complete')

# Create counter functions that can properly count the number of anomalous logs. See stats.py file
sysmon_counter = process_event_counts
winevent_counter = generate_event_counter('eventID')
suricata_counter = generate_event_counter('dest_port')

# Process Sysmon
sdata = dict()
if USE_SYSMON:
    for hostname in HOSTNAMES:
        sdata[hostname] = process_sysmon(hostname, process_create_events, sysmon_counter, OUTPUT_LOGDATA)

# Process Windows Event Channel
cdata = dict()
if USE_WINEVENT:
    for hostname in HOSTNAMES:
        cdata[hostname] = process_winevent(hostname, security_events, winevent_counter, OUTPUT_LOGDATA)

# Establish lists to keep count of logs on and between hosts
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

# Process Suricata
ndata = dict()
suricata_pairs = generate_network_pairs(suricata_events, USE_SURICATA)
if USE_SURICATA:
    for keys, logs in suricata_pairs.items():
        src, dst = keys
        ndata[src, dst] = process_suricata(src, dst, logs, suricata_counter, OUTPUT_LOGDATA)

# Get the frequency matrices for each tactic. See ftactic.py
f_tactic_matrix = get_tactic_matrix('data/tactic_matrix.npy', hostname_indices)

# Generate the cumulative probability distribution matrix
# based on the processed logs/frequency stats for each tactic for each host from above.
p_cpd = {}
for tactic in TACTICS.keys():
    matrix = np.reshape(np.zeros(host_index * host_index), (host_index, host_index))
    for hostname in HOSTNAMES:
        i = host_indices[HOST_TO_IP[hostname]]
        total = 0
        anomalous = 0
        if USE_SYSMON:
            total += sdata[hostname]['total_logs']
            anomalous += sdata[hostname]['tactics'][tactic]['count']
            if tactic == 'discovery':
                for keys, counts in sdata[hostname]['discovery_host_pairs'].items():
                    src, dst = keys
                    t = counts['total']
                    a = counts['anomalous']
                    src = host_indices[src]
                    dst = host_indices[dst]
                    matrix[src][dst] = safe_divide(t - a, t)
                    dst_log_counts[dst] += a
        if USE_WINEVENT:
            total += cdata[hostname]['total_logs']
            anomalous += cdata[hostname]['tactics'][tactic]['count']

        matrix[i, i] = safe_divide(total - anomalous, total)
        src_log_counts[i] += total
        dst_log_counts[i] += total
        total_log_count += total

    p_cpd[tactic] = matrix

if USE_SURICATA:
    for keys, logs in suricata_pairs.items():
        src, dst = keys
        i = host_indices[src]
        j = host_indices[dst]
        tactic = 'lateral_movement'
        p_cpd[tactic][i][j] = 1 - ndata[src, dst]['tactics'][tactic]['frequency']
        src_log_counts[i] += ndata[src, dst]['total_logs']
        dst_log_counts[j] += ndata[src, dst]['total_logs']
        total_log_count += ndata[src, dst]['total_logs']

# Generate the Observability Matrix
e_obsrv = {}
for index, (tactic, p_matrix) in enumerate(p_cpd.items()):
    shape = f_tactic_matrix[tactic].shape
    matrix = np.zeros(shape)
    for i in range(shape[0]):
        for j in range(shape[1]):
            matrix[i][j] = p_matrix[i][j] * f_tactic_matrix[tactic][i][j]
    e_obsrv[tactic] = matrix


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
