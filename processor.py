from scapy.all import *
import argparse

multicast_hexa_bit = ['1', '3', '5', '7', '9', 'b', 'd', 'f']


def main(filename):
    path_to_file = 'packets/'
    file = filename + '.pcap'
    packets = rdpcap(path_to_file + file)

    broadcast_packets_by_type = dict()
    unicast_packets_by_type = dict()
    multicast_packets_by_type = dict()
    types = set()

    for packet in packets:
        try:
            packet_type = packet.type
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
            packet.show()
            print()
    cant_broadcast = 0
    cant_unicast = 0
    cant_multicast = 0
    total_broadcast = 0
    total_unicast = 0
    total_multicast = 0
    out_file = 's1_' + filename + '.csv'
    with open(out_file, 'w+') as f:
        f.write('type broadcast unicast multicast\n')
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
            f.write(str(protocol_type) + ' ' + str(cant_broadcast) + ' ' + str(cant_unicast) + ' ' + str(cant_multicast) + '\n')

            cant_broadcast = 0
            cant_unicast = 0
            cant_multicast = 0
        f.write('\n')
        f.write('type broadcast unicast multicast\n')
        f.write('total ' + str(total_broadcast) + ' ' + str(total_unicast) + ' ' + str(total_multicast))

    print(out_file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Para procesar la fuente s1, con el paquete que se pase como '
                                                 'parametro. Los paquetes tienen que estar en el folder packets.')
    parser.add_argument('-f', '--file_name', default='', help='Nombre del file donde estan guardados los paquetes.'
                                                              ' Sin extension!!')
    args = parser.parse_args()
    main(args.file_name)
