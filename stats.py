import observables
import datetime

from typing import List, Dict, Set

from util import safe_divide


def equal_or_empty(feature, event, element):
    return element not in feature.keys() or feature[element].casefold() == event[element].casefold()


def process_event_counts(events: List[object],
                         features: Dict[str, object],
                         tactics: Dict[str, object]) -> Dict[str, int]:
    counts = dict()
    for event in events:
        anomalous = False
        found_tactics = dict(map(lambda x: (x, False), tactics))
        for key, feature_dicts in features.items():
            found = False
            for feature_dict in feature_dicts:
                execmp = equal_or_empty(feature_dict, event, 'exe')
                pexecmp = equal_or_empty(feature_dict, event, 'parent_exe')
                pathcmp = equal_or_empty(feature_dict, event, 'path')
                ppathcmp = equal_or_empty(feature_dict, event, 'parent_path')
                paramcmp = False
                if 'params' in feature_dict.keys():
                    temp = [False] * len(feature_dict['params'])
                    temp_index = 0
                    for p_one in feature_dict['params']:
                        k_index = 0
                        k = [False] * len(event['params'])
                        for p_two in event['params']:
                            if p_one.casefold() == p_two.casefold():
                                k[k_index] = True
                                if p_two.endswith('c'):
                                    break
                            k_index += 1
                        temp[temp_index] = any(k)
                        temp_index += 1
                    paramcmp = all(temp)
                else:
                    paramcmp = True
                if execmp and pexecmp and pathcmp and ppathcmp and paramcmp:
                    found = True

            if found:
                anomalous = True
                for tactic_k, tactic_v in tactics.items():
                    if not found_tactics[tactic_k] and key in tactic_v:
                        counts[tactic_k] = counts.get(tactic_k, 0) + 1
                        found_tactics[tactic_k] = True
        counts['num_anomalous'] = counts.get('num_anomalous', 0) + (1 if anomalous else 0)
    return counts


def generate_event_counter(event_key: str):
    def local_closure(events: List[object],
                      features: Dict[str, object],
                      tactics: Dict[str, object]) -> Dict[str, int]:
        counts = dict()
        for event in events:
            id = event[event_key]
            anomalous = False
            found_tactics = dict(map(lambda x: (x, False), tactics))
            for key, value in features.items():
                if id in value:
                    anomalous = True
                    for tactic_key, tactic_value in tactics.items():
                        if not found_tactics[tactic_key] and key in tactic_value:
                            counts[tactic_key] = counts.get(tactic_key, 0) + 1
                            found_tactics[tactic_key] = True

            counts['num_anomalous'] = counts.get('num_anomalous', 0) + (1 if anomalous else 0)

        return counts

    return local_closure


def evaluate_machine(events, features, count_function):
    results = dict()
    counts = count_function(events, features, observables.TACTICS)
    total_logs = len(events)
    total_anomalous = counts['num_anomalous']
    results['tactics'] = {}
    results['total_anomalous'] = total_anomalous
    results['total_logs'] = total_logs

    for tactic in observables.TACTICS.keys():
        c = counts.get(tactic, 0)
        f = safe_divide(c, total_logs)
        a = safe_divide(c, total_anomalous)

        tactic_dict = dict()
        tactic_dict['count'] = c
        tactic_dict['frequency'] = f
        tactic_dict['anomalous'] = a
        results['tactics'][tactic] = tactic_dict

    results['prob'] = safe_divide(total_anomalous, total_logs)
    timestamps = []
    timestamp_string = '%Y-%m-%dT%H:%M:%S.%fZ'
    for event in events:
        timestamps.append(datetime.datetime.strptime(event['@timestamp'], timestamp_string))

    timestamps.sort()
    start = timestamps[0]
    finish = timestamps[-1]
    days = (finish - start).total_seconds() / 86400

    results['start_time'] = start
    results['finish_time'] = finish
    results['time_diff'] = days
    results['log_freq'] = safe_divide(total_logs, days)
    results['anomalous'] = safe_divide(total_anomalous, days)

    return results
