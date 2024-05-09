import json
import copy
import networkx as nx
from pyvis.network import Network
from ryu.lib.packet import ether_types

# relable graph nodes
def relabel_graph(graph):
    """
    This function changes the names of the nodes in the graph to human fridly names
    :type graph: networkx.classes.digraph.DiGraph
    :return: None
    :rtype: None
    """
    mapping = {}
    for node in graph.nodes():
        if isinstance(node, str) and ":" in node:
            mapping[node] = f"h{int(node.split(':')[-1])}"
        else:
            mapping[node] = f"s{node}"
    return nx.relabel_nodes(graph, mapping)

# create default topology graph
def create_default_graph(graph):
    graph_copied = copy.deepcopy(graph)
    # reset link attributes
    for edge in graph_copied.edges():
        graph_copied[edge[0]][edge[1]]["free_bandwidth"] = graph[edge[0]][edge[1]][
            "bandwidth"
        ]
    # return default topology graph
    return graph_copied
    
# draw networkx graph
def draw_graph(graph):
    graph = relabel_graph(graph)
    # set position of nodes
    pos = nx.spring_layout(graph)
    # draw nodes
    nx.draw_networkx_nodes(graph, pos)
    # draw edges
    nx.draw_networkx_edges(graph, pos)
    # node labels
    nx.draw_networkx_labels(graph, pos)
    # edge labels
    edge_labels = nx.get_edge_attributes(graph, "label")
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_labels)
    # customize pyvis graph
    nt = Network("800", "100%")
    nt.from_nx(graph)
    # color nodes
    for node in nt.nodes:
        if node["id"].startswith("h"):
            node["color"] = "#cdb4db"
            node["shape"] = "box"
        else:
            node["color"] = "#e9edc9"
            node["shape"] = "circle"
    # weight edges
    for edge in nt.edges:
        edge["width"] = 1 + graph[edge["from"]][edge["to"]]["bandwidth"] / 10
        edge["color"] = "#bde0fe"
    # save pyvis graph as html
    nt.save_graph("./graph.html")


# load json config file
def load_json_config(filename):
    with open(filename, "r") as f:
        config_options = json.load(f)
    return config_options


# convert Bytes per second to Megabits per second
def bps_to_mbps(bps):
    return bps * 8e-6


# get ether type friendly name
def get_ethertype(ethertype):
    if ethertype == ether_types.ETH_TYPE_IP:
        return "IPv4"
    elif ethertype == ether_types.ETH_TYPE_ARP:
        return "ARP"
    else:
        return ethertype


# widest path algorithm
# modified Dijkstra's algorithm based on https://en.wikipedia.org/wiki/Dijkstra%27s_algorithm
def widest_path(graph, src, dst, weight="bandwidth"):
    dist = {}
    prev = {}
    Q = list(graph.nodes())
    for node in graph.nodes():
        dist[node] = 0
        prev[node] = None
    dist[src] = float("inf")
    while Q:
        u = max(Q, key=lambda x: dist[x])
        if u == dst: # early stopping
            break
        Q.remove(u)
        for v in graph.neighbors(u):
            alt = min(dist[u], graph[u][v][weight])
            if alt > dist[v]:
                dist[v] = alt
                prev[v] = u
    # return path sequence and minimum bandwidth
    S = []
    minBandwidth = float("inf")
    if prev[dst] or src == dst:
        while dst:
            S.insert(0, dst)
            # self.logger.debug(f"dst: {dst}, {weight}: {dist[dst]}")
            minBandwidth = min(minBandwidth, dist[dst])
            dst = prev[dst]
    return S, minBandwidth
