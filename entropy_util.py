"""
Author: Nathan Waltz

Entropy utilities for computing the new TOMATO metric.
"""

import networkx
import numpy as np

from typing import Dict
from networkx import Graph

from definitions import GRAPHICAL_SYSTEM, HOSTNAMES
from observables import TACTICS

# important for this dataset
node_at_index = {index:value for index, value in enumerate(HOSTNAMES)}

NUM_FEATURES = len(TACTICS.keys())

def compute_node_degrees(graph: Graph) -> Dict[int, int]:
    return dict(graph.degree())


def get_adjacency_matrix(graph: Graph) -> np.matrix:
    """
    Gets a dense represenation of a networkx graph.
    """
    adjacency_matrix = networkx.linalg.graphmatrix.adjacency_matrix(graph)
    return adjacency_matrix.todense()


def create_lateral_movement_matrix(graph: Graph) -> np.matrix:
    """
    Creates a probability matrix using
    Random Walker Shannon Entropy. Used to construct the lateral
    movement probability matrix.

    p_{ij} = {1 / k_i if Aij = 1 else 0}
    (A is the adjacency matrix, and k is the degree of a node)
    """
    node_degrees = compute_node_degrees(graph)
    adjacency_matrix = get_adjacency_matrix(graph)
    probability_matrix = np.empty((adjacency_matrix.shape[0], adjacency_matrix.shape[1]))
    for i in range(adjacency_matrix.shape[0]):
        current_node = node_at_index[i]
        for j in range(adjacency_matrix.shape[1]):
            if adjacency_matrix[i, j] > 1 or adjacency_matrix[i, j] < 0:
                raise ValueError('You passed an invalid adjacency matrix,  \
                                  please make sure it only contains 0s and 1s')
            probability_matrix[i, j] = \
                adjacency_matrix[i, j] / node_degrees[current_node]
   
    return probability_matrix


def create_on_host_tactic_matrix(graph: Graph) -> np.matrix:
    """
    Creates an on-host tactic matrix.    
    """
    probability_matrix = np.zeros((graph.number_of_nodes(), graph.number_of_nodes()))
    for i, j in zip(range(0, 10), range(0, 10)):
        probability_matrix[i, j] = 1
    
    return probability_matrix


def create_probability_matrix(graph: Graph) -> np.matrix:
    """
    Creates the probability matrix. This computes the probability of
    attacks occuring on a given host. 
    """
    # each of these is being treated as having an equal likelihood of occuring,
    # so we have to do this to lateral movement matrix as well.
    lateral_movement_matrix = create_lateral_movement_matrix(graph) * (1 / NUM_FEATURES)
    discovery_matrix = create_on_host_tactic_matrix(graph) * (1 / NUM_FEATURES)
    execution_matrix = create_on_host_tactic_matrix(graph) * (1 / NUM_FEATURES)
    privilege_escalation_matrix = create_on_host_tactic_matrix(graph) * (1 / NUM_FEATURES)
    return np.array([lateral_movement_matrix, discovery_matrix, execution_matrix, privilege_escalation_matrix])

np.set_printoptions(precision=3, suppress=True)
probability_matrix = create_probability_matrix(GRAPHICAL_SYSTEM)
