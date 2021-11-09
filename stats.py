import observables

from typing import List, Dict, Set


def equal_or_empty(feature, event, element):
    return feature[element] is None or feature[element].casefold() == event[element].casefold()


def process_event_counts(events: List[object],
                         features: Dict[str, object],
                         tactics: Set[str]) -> Dict[str, int]:
    counts = dict()
    for event in events:
        anomalous = False
        found_tactics = dict(map(lambda x: (x, False), tactics))
        for key, value in features:
            pass
