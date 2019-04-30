import csv
from scapy.all import *
import matplotlib as mpl
import matplotlib.pyplot as plt
import networkx as nx
import argparse
from random import randint


def main(file, mode):
    connections = dict()
    nodes = set()
    nodes_weight = dict()
    cantidad_de_aristas = 0
    if mode == 'wh':
        mode = 1
    elif mode == 'ia':
        mode = 2
    else:
        print('Not recognized mode: ' + mode)
        exit(1)
    packets = rdpcap(file)
    for packet in packets[ARP]:
        if packet.op == mode:
            source = packet.psrc
            destination = packet.pdst
            nodes.add(source)
            nodes.add(destination)
            if source not in connections.keys():
                connections[source] = dict()
                connections[source][destination] = 1
            else:
                if destination not in connections[source].keys():
                    connections[source][destination] = 0
                connections[source][destination] += 1
            cantidad_de_aristas += 1
            if source not in nodes_weight.keys(): nodes_weight[source] = 0
            if destination not in nodes_weight.keys(): nodes_weight[destination] = 0
            nodes_weight[source] += 1
    # print(connections)
    colors = []
    for i in range(len(nodes) + 1):
        colors.append("#%06X" % randint(0, 0xFFFFFF))

    G = nx.DiGraph()

    edges_tuples = []
    edges_tuples_values = []

    min = 0
    max = 0
    for source in connections.keys():
        for destination in connections[source].keys():
            # G.add_edge(source, destination)
            edges_tuples.append((source, destination))
            cant = connections[source][destination]
            edges_tuples_values.append(cant)
            if min > cant:
                min = cant
            if max < cant:
                max = cant
    print(min)
    print(max)
    variant = max - min
    # node_sizes = [3 + 10 * i for i in range(len(G))]
    real_nodes_weigth = dict()
    print(nodes_weight)
    for node in nodes_weight.keys():
        print(node + ': ' + str(nodes_weight[node]))
        if max == min:
            G.add_node(node, weight=1)
        else:
            real_nodes_weigth[node] = (max - nodes_weight[node]) / (max - min)
            G.add_node(node, weight=real_nodes_weigth[node])

    G.add_edges_from(edges_tuples)
    pos = nx.spring_layout(G)
    if max == min:
        values = [1 for node in G.nodes()]
    else:
        values = [(max - nodes_weight[node]) / (max - min) for node in G.nodes()]

    # nx.draw_networkx_edges(G, pos=pos, edgelist=edges_tuples, style='dashed', alpha=0.1)
    nx.draw(G, pos=pos, cmap=plt.get_cmap('autumn'), node_color=values,
            arrowsize=10, width=0.1,
            with_labels=False)
    labels = {}
    ordered_nodes = sorted(real_nodes_weigth.items(), key=lambda n: n[1])
    for node in ordered_nodes[:cant_labels]:
        labels[node[0]] = node[0]
    labels['0.0.0.0'] = '0.0.0.0'

    nx.draw_networkx_labels(G, pos, labels)
    plt.show()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Para generar el grafo de la fuente s2')
    parser.add_argument('-f', '--file_name', default='', help='Nombre del file donde estan guardados los paquetes.'
                                                                 ' Sin extension!!')
    parser.add_argument('-m', '--mode', default='wh', help='Si se quiere modelar el grafo who-has (wh) o el is-at (ia)')
    parser.add_argument('-l', '--cant_labels', default='5', help='Para decidir cuantos labels usar')

    args = parser.parse_args()
    cant_labels = int(args.cant_labels)
    file_name = args.file_name
    path_to_file = 'packets/'
    file = file_name + '.pcap'
    main(path_to_file + file, args.mode)
