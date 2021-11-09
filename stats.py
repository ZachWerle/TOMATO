import observables

from typing import List, Dict, Set


def equal_or_empty(feature, event, element):
    return feature[element] is None or feature[element].casefold() == event[element].casefold()


def process_event_counts(events: List[object],
                         features: Dict[str, object],
                         tactics: Dict[str, object]) -> Dict[str, int]:
    pass


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
                            counts[tactic_key] += 1
                            found_tactics[tactic_key] = True

            counts['num_anomalous'] += 1 if anomalous else 0

        return counts
    return local_closure
