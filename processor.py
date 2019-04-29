from scapy.all import *
import argparse
from math import log as LOG

multicast_hexa_bit = ['1', '3', '5', '7', '9', 'b', 'd', 'f']
type_to_name = {
    2054: 'ARP',
    34525: 'IPv6',
    2048: 'IP',
    34958: 'EAPOL',
    35020: 'Raw',
    35130: 'Raw',
}


def main(filename, s1=True, s2=False):
    path_to_file = 'packets/'
    file = filename + '.pcap'
    packets = rdpcap(path_to_file + file)
    if s1:
        process_packets_to_s1(packets)
    if s2:
        process_packets_to_s2(packets[ARP])


def calcular_info_promedio_entropia(source):
    H = 0
    N = sum(source.values())

    nodes = []
    for a, c in source.items():
        p = c / float(N)
        i = -LOG(p, 2)
        H += p * i
        nodes.append((a, p, i))

    nodes.sort(key=lambda n: n[1])
    return nodes, H, N


def process_packets_to_s2(packets):
    wh_src = {}
    wh_dst = {}
    ia_src = {}
    ia_dst = {}
    for packet in packets:
        if packet.op == 1:  # who-has (request)
            if packet.psrc not in wh_src:
                wh_src[packet.psrc] = 0
            wh_src[packet.psrc] += 1
            if packet.pdst not in wh_dst: wh_dst[packet.pdst] = 0
            wh_dst[packet.pdst] += 1

        if packet.op == 2:  # is-at (response)
            if packet.psrc not in ia_src: ia_src[packet.psrc] = 0
            ia_src[packet.psrc] += 1
            if packet.pdst not in ia_dst: ia_dst[packet.pdst] = 0
            ia_dst[packet.pdst] += 1
    wh_src_count, H_wh_src, cantidad_wh_src = calcular_info_promedio_entropia(wh_src)
    wh_dst_count, H_wh_dst, cantidad_wh_dst = calcular_info_promedio_entropia(wh_dst)
    ia_src_count, H_ia_src, cantidad_ia_src = calcular_info_promedio_entropia(ia_src)
    ia_dst_count, H_ia_dst, cantidad_ia_dst = calcular_info_promedio_entropia(ia_dst)
    ips_dict = {
        'wh_src': (wh_src_count, H_wh_src, cantidad_wh_src),
        'wh_dst': (wh_dst_count, H_wh_dst, cantidad_wh_dst),
        'ia_src': (ia_src_count, H_ia_src, cantidad_ia_src),
        'ia_dst': (ia_dst_count, H_ia_dst, cantidad_ia_dst),
    }
    out_file = 's2_' + file_name + '.csv'
    with open(out_file, 'w+') as f:
        for nombre_fuente in ips_dict.keys():
            f.write('Fuente ' + nombre_fuente + '\n')
            f.write('simbolo,probabilidad,informacion\n')
            fuente = ips_dict[nombre_fuente][0]
            entropia = ips_dict[nombre_fuente][1]
            cantidad = ips_dict[nombre_fuente][2]
            for ip_prom_info in fuente:
                ip = ip_prom_info[0]
                promedio = ip_prom_info[1]
                informacion = ip_prom_info[2]
                f.write(ip + ',' + str(promedio) + ',' + str(informacion) + '\n')
            f.write('\n')
            f.write('entropia,entropia maxima\n')
            f.write(str(entropia) + ',' + str(LOG(cantidad, 2)))
            f.write('\n')
            f.write('Cantidad de simbolos: ' + str(len(fuente)))
            f.write('\n')
            f.write('\n')
            f.write('\n')
    print(out_file)


def process_packets_to_s1(packets):
    broadcast_packets_by_type = dict()
    unicast_packets_by_type = dict()
    multicast_packets_by_type = dict()
    types = set()

    for packet in packets:
        try:
            packet_type = type_to_name[packet.type]
            types.add(packet_type)
            if packet.dst == 'ff:ff:ff:ff:ff:ff':
                if packet_type not in broadcast_packets_by_type.keys():
                    broadcast_packets_by_type[packet_type] = 0
                broadcast_packets_by_type[packet_type] += 1
            elif packet.dst[4] in multicast_hexa_bit:
                if packet_type not in multicast_packets_by_type.keys():
                    multicast_packets_by_type[packet_type] = 0
                multicast_packets_by_type[packet_type] += 1
            else:
                if packet_type not in unicast_packets_by_type.keys():
                    unicast_packets_by_type[packet_type] = 0
                unicast_packets_by_type[packet_type] += 1
        except Exception as e:
            #packet.show()
            #print()
            print()
            #print()

    all_packets_by_tram = {
        'broadcast': broadcast_packets_by_type,
        'unicast': unicast_packets_by_type,
        'multicast': multicast_packets_by_type,
    }

    H = 0
    nodes = []
    all_simbols_count = dict()
    for tipo_de_destino, dict_by_type in all_packets_by_tram.items():
        for protocolo, c in dict_by_type.items():
            all_simbols_count[(tipo_de_destino, protocolo)] = c
#            p = c / float(len(packets))
#            i = -LOG(p, 2)
#            H += p * i
#            nodes.append(((tipo_de_destino, protocolo), p, i))

    nodes, H, N = calcular_info_promedio_entropia(all_simbols_count)

    cant_broadcast = 0
    cant_unicast = 0
    cant_multicast = 0
    total_broadcast = 0
    total_unicast = 0
    total_multicast = 0
    out_file = 's1_' + file_name + '.csv'
    with open(out_file, 'w+') as f:
        f.write('type,broadcast,unicast,multicast\n')
        for protocol_type in types:

            if protocol_type in broadcast_packets_by_type.keys():
                cant_broadcast = broadcast_packets_by_type[protocol_type]
                total_broadcast += cant_broadcast
            if protocol_type in unicast_packets_by_type.keys():
                cant_unicast = unicast_packets_by_type[protocol_type]
                total_unicast += cant_unicast
            if protocol_type in multicast_packets_by_type.keys():
                cant_multicast = multicast_packets_by_type[protocol_type]
                total_multicast += cant_multicast
            f.write(str(protocol_type) + ',' + str(cant_broadcast) + ',' + str(cant_unicast) + ',' + str(cant_multicast) + '\n')

            cant_broadcast = 0
            cant_unicast = 0
            cant_multicast = 0
        f.write('\n')
        f.write('type,broadcast,unicast,multicast\n')
        f.write('total,' + str(total_broadcast) + ',' + str(total_unicast) + ',' + str(total_multicast))
        f.write('\n')
        f.write('\n')
        f.write('simbolo,probabilidad,informacion\n')
        for node in nodes:
            f.write(node[0][0] + ';' + str(node[0][1]) + ',' + str(node[1]) + ',' + str(node[2]) + '\n')
        f.write('\n')
        f.write('entropia,entropia maxima\n')
        f.write(str(H) + ',' + str(LOG(N, 2)))

    print(out_file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Para procesar las fuentes s1 y s2, con el paquete que se pase como '
                                                 'parametro. Los paquetes tienen que estar en el folder packets.')
    parser.add_argument('-f', '--file_name', default='', help='Nombre del file donde estan guardados los paquetes.'
                                                                 ' Sin extension!!')
    parser.add_argument('-s1', '--fuente_1', action='store_true', help='Para que procese la fuente 1 con los paquetes '
                                                                       'dados')
    parser.add_argument('-s2', '--fuente_2', action='store_true', help='Para que procese la fuente 2 con los paquetes '
                                                                       'dados')
    parser.set_defaults(fuente_1=False)
    parser.set_defaults(fuente_2=False)
    args = parser.parse_args()
    file_name = args.file_name
    path_to_file = 'packets/'
    file = file_name + '.pcap'
    main(file_name, args.fuente_1, args.fuente_2)
