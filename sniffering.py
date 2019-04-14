from scapy.all import *
import argparse
import os
import sys


def main(cant, tiempo, file_name):
    # Chequeo parametros de entrada
    if int(cant) == 0 and int(tiempo) == 0:
        sys.exit('Te olvidaste de poner algun parametro obligatorio, ya sea cantidad de paquetes o el tiempo a sniffear')
    ext = '.pcap'

    # os.makedirs('packets/', exist_ok=True)
    # Genero el filename default
    if len(file_name) == 0:
        file_name = 'sniff_'
        index = 0
        while True:
            files = os.listdir('packets/')
            if file_name + str(index) + ext  not in files:
                file_name = file_name + str(index) + ext
                break
            index += 1
    else:
        file_name = file_name + ext
    print('cant = ' + str(int(cant)) + ' ; tiempo = ' + str(int(tiempo)))
    if int(cant) > 0 and int(tiempo) > 0:
        print('cantidad y tiempo')
        pkts = sniff(count=int(cant), timeout=int(tiempo)*60)
    elif int(cant) > 0:
        print('solo cantidad')
        pkts = sniff(count=int(cant))
    else:
        print('solo tiempo')
        pkts = sniff(timeout=int(tiempo)*60)
    
    str(pkts)
    wrpcap('packets/' + file_name, pkts)
    print('Guardado con nombre ' + file_name)
    print('Cantidad de paquetes obtenidos ' + str(len(pkts)))
    exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Chicos corran con alguno de los siguientes parametros y no se'
                                                 ' olviden de poner el nombre del file, sino lo saca por contexto '
                                                 'con un nombre default. IMPORTANTE: se van a guardar los paquetes '
                                                 'en la carpeta packets, si no existe, la crea. '
                                                 '(preferentemente correr desde el repo.)')
    parser.add_argument('-c', '--cant_packets', default='0', help='Cantidad de paquetes a capturar')
    parser.add_argument('-t', '--tiempo', default='0', help='Cantidad de minutos que estara sniffeando.')
    parser.add_argument('-f', '--file_name', default='', help='Nombre del file donde se va a guardar. Sin extension!!')
    args = parser.parse_args()
    main(args.cant_packets, args.tiempo, args.file_name)