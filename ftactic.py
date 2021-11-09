import numpy.matlib
import numpy as np
import networkx
import copy

from typing import List, Dict
from random import sample
from os.path import exists
from definitions import GRAPHICAL_SYSTEM


def markov_analysis(state: str) -> List[str]:
    tactics = set('discovery', 'privilege_escalation', 'lateral_movement', 'execution')
    tactics -= set(state)
    return list(tactics)


def random_walk(graph: networkx.Graph) -> List[Dict[str, object]]:
    previous_state = 'discovery'
    current_state = 'discovery'
    discovery_count = 0
    walk = []
    limit = 50
    update = False
    privileges = False

    current = sample(graph.nodes, 1)
    available = []
    attack_path = [current]

    for _ in range(limit):
        if current_state == 'discovery':
            discovery_count += 1
            update = discovery_count < 3
        elif current_state == 'privilege_escalation':
            update = not privileges
            privileges = True
        elif current_state == 'lateral_movement':
            available = set(available + graph.neighbors(current))
            available -= set(attack_path)
            available = list(available)

            if not available:
                update = False
            else:
                current = sample(available, 1)
                attack_path += current
                discovery_count = 0
                privileges = False
                update = True
        elif current_state == 'execution':
            update = True

        if update:
            step = {
                'tactic': current_state,
                'host': current,
                'attack_path': copy.deepcopy(attack_path)
            }

            walk += step

            if current_state != 'execution':
                previous_state = current_state
                current_state = markov_analysis(current_state)
        else:
            current_state = markov_analysis(previous_state)

    return walk


def build_n_walks(graph: networkx.Graph, n: int) -> List[Dict[str, object]]:
    return [random_walk(graph) for _ in range(n)]


def build_matrix_from_walks(walks: List[Dict[str, object]], host_indices: Dict[str, int]):
    tactics = ['discovery', 'privilege_escalation', 'lateral_movement', 'execution']
    m = {}
    for tactic in tactics:
        m[tactic] = np.matlib.zeros((len(host_indices), len(host_indices)))

    for walk in walks:
        for index, step in enumerate(walk):
            host = step['host']
            tactic = step['tactic']
            host_i = host_indices[host]

            if tactic == 'discovery' or tactic == 'privilege_escalation' or tactic == 'execution':
                m[tactic][host_i, host_i] += 1.0
            elif tactic == 'lateral_movement':
                assert (index > 0)
                previous = walk[index - 1]
                source_i = host_indices[previous['host']]
                m[tactic][source_i, host_i] += 1.0
                m[tactic][source_i, source_i] += 1.0

    return m


def get_tactic_matrix(filename: str, hostname_indices: Dict[str, int]):
    if exists(filename):
        with open(filename, 'rb') as input_file:
            return np.load(input_file)
    else:
        walks = build_n_walks(GRAPHICAL_SYSTEM, 1000)
        ftactic = build_matrix_from_walks(walks, hostname_indices)
        with open(filename, 'wb') as output_file:
            np.save(output_file, ftactic)
        return ftactic
