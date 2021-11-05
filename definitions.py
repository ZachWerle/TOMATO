"""
Global Constants that will be used throughout the project.
"""
from itertools import product
from typing import KeysView

from networkx import Graph

SECURITY_LOG = 'Microsoft-Windows-Security-Auditing'

# COM600-PC is the Gateway (GW)
COM600_PC_IP = '192.168.2.10'

# HP-B53-01 is the Human Machine Interface (HMI)
HP_B53_01_IP = '192.168.0.11'

HOST_TO_IP = {
    'COM600-PC': '192.168.0.11',
    'HP-B53-01': '192.168.2.11',
    'Relay1': '192.168.2.101',
    'Relay2': '192.168.2.102',
    'Relay3': '192.168.2.103',
    'Relay4': '192.168.2.104',
    'Relay5': '192.168.2.104',
    'Relay6': '192.168.2.105',
    'Relay7': '192.168.2.106',
    'Relay8': '192.168.2.107'
}

# the host names and host IPs
HOSTNAMES = HOST_TO_IP.keys()
HOST_IPS = HOST_TO_IP.values()


def generate_graphical_system(hostnames: KeysView[str]) -> Graph:
    """
    Generates a gsystem for the hostnames.

    :param hostnames: A set of hostnames.
    :return: An adjacency graph of the gsystem.
    """
    adjacency_graph = Graph()
    adjacency_graph.add_nodes_from(hostnames)
    sorted_hostnames = sorted(list(hostnames))
    for u, v in product(sorted_hostnames[:2], sorted_hostnames[2:]):
        adjacency_graph.add_edge(u, v)

    adjacency_graph.add_edge(sorted_hostnames[0], sorted_hostnames[1])

    return adjacency_graph


# store the generated graphical system
GRAPHICAL_SYSTEM = generate_graphical_system(HOSTNAMES)
