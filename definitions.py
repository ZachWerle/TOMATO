"""
Global Constants that will be used throughout the project.
"""
from itertools import product
from typing import KeysView

from networkx import Graph

SECURITY_LOG = 'Microsoft-Windows-Security-Auditing'

# This is where you input the file path to the data file you want to load into TOMATO
DATA_FILE = "data/ossec-alerts-15.json"

# This is where you input the key/name of the server that hosts your SIEM and associated event dataset
SERVER = "zachary-VirtualBox"

HOST_TO_IP = {
    'zachary-VirtualBox': '192.168.1.18',
    'DESKTOP-9LO9B7Q': '192.168.1.115',
    'DESKTOP-D403BQC': '192.168.1.112',
    'DESKTOP-0H8GJPO': '192.168.1.13',
    'DESKTOP-CKP652S': '192.168.1.27'
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

    # Attach edges between the hosts and the server
    for host in hostnames:
        if host != SERVER:
            adjacency_graph.add_edge(host, SERVER)

    # Manually attach edges for individual services
    adjacency_graph.add_edge("DESKTOP-D403BQC", "DESKTOP-CKP652S")
    adjacency_graph.add_edge("DESKTOP-0H8GJPO", "DESKTOP-9LO9B7Q")
    adjacency_graph.add_edge("DESKTOP-CKP652S", "DESKTOP-0H8GJPO")

    return adjacency_graph


# store the generated graphical system
GRAPHICAL_SYSTEM = generate_graphical_system(HOSTNAMES)
