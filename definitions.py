"""
Global Constants that will be used throughout the project.
The code in this file is adapted from https://github.com/TorNATO-PRO/TOMATO by Nathan Waltz
"""
from typing import KeysView
from networkx import Graph

SECURITY_LOG = 'Microsoft-Windows-Security-Auditing'

# This is where you input the file path to the data file you want to load into TOMATO
DATA_FILE = "data/alerts-final.json"
# This is where you check if the file is a Wazuh file
WAZUH = 1

# This is where you input the key/name of the server that hosts your SIEM and associated event dataset
SERVER = "zachary-VirtualBox"

HOST_TO_IP = {
    'zachary-VirtualBox': '10.0.2.5',
    'DESKTOP-9LO9B7Q': '10.0.2.6',
    'DESKTOP-D403BQC': '10.0.2.7',
    'DESKTOP-0H8GJPO': '10.0.2.8',
    'DESKTOP-CKP652S': '10.0.2.9'
}

# the host names and host IPs
HOSTNAMES = HOST_TO_IP.keys()
HOST_IPS = HOST_TO_IP.values()


# This function is used to generate the adjacency graph needed to produce the appropriate ftactic matrix
# for your network.
# Please read the instructions below and build your graph.
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

    # Manually attach edges for individual services.
    adjacency_graph.add_edge("DESKTOP-D403BQC", "DESKTOP-CKP652S")
    adjacency_graph.add_edge("DESKTOP-0H8GJPO", "DESKTOP-9LO9B7Q")
    adjacency_graph.add_edge("DESKTOP-CKP652S", "DESKTOP-0H8GJPO")

    return adjacency_graph


# store the generated graphical system
GRAPHICAL_SYSTEM = generate_graphical_system(HOSTNAMES)
