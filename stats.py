import observables

from typing import List, Dict, Set


def equal_or_empty(feature, event, element):
    return feature[element] is None or feature[element].casefold() == event[element].casefold()


def process_event_counts(events: List[object],
                         features: Dict[str, object],
                         tactics: Set[str]) -> Dict[str, int]:
    pass


def generate_event_counter(key: str):
    def local_closure(events: List[object],
                      features: Dict[str, object],
                      tactics: Set[str]) -> Dict[str, int]:
        pass
    pass
