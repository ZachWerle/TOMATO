from numpy import reshape, repeat, ndarray, vectorize, sum
import numpy as np

from math import log

probability_matrix = reshape(repeat(0.25, 16), (4, 4))


def compute_joint_entropy(joint_prob_matrix: ndarray) -> float:
    """
    Entropy: - \sum_x \sum_y P(x, y) * log_2 (P(x, y))
    """    
    return -sum(vectorize(lambda elem: elem * log(elem, 2))(joint_prob_matrix))


print(f'The entropy of the node is: {compute_joint_entropy(probability_matrix)}')
