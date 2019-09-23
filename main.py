import os
from scapy.all import *
from socket import *
import argparse
import sys
import select
import time
from datetime import datetime
import logging
import yaml

def send_flow(byte_payload, src_ip, collector_ip, config):
    # This function uses Scapy to make sure the original source IP address is maintained.
    # This function spoofs the source in order to report the right source on the netflow collector
    payload = IP(src=src_ip, dst=collector_ip) / UDP(sport=10011, dport=int(config['collector_port'])) / Raw(load=byte_payload)

    if config['debug'] != False:
        ipLoad = len(payload.getlayer(IP))
        udpLoad = len(payload.getlayer(UDP))
        rawLoad = len(payload.getlayer(Raw))

        logging.debug("send_flow(): ipload size: {}".format(str(ipLoad)))
        logging.debug("send_flow(): udp load size: {}".format(str(udpLoad)))
        logging.debug("send_flow(): raw load size: {}".format(str(rawLoad)))

    # Try for 4 times to send the packet, otherwise move on to the next packet
    for i in range(4):
        try:
            output = send(payload, verbose=False)
        except Exception as e:
            print("Exception occured on send_flow() attempt %s:%s" % (str(i+1), str(e)))
            logging.error("Exception occured on send_flow() attempt", exc_info=True)
            continue
        break
    else:
        output = send(payload, verbose=False)


def main(config):
    # Open up the server socket
    address = (config['bind_ip'], int(config['bind_port']))
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.bind(address)

    # stats tracking variables
    stats_sources    = {}
    stats_collectors = {}
    stats_time_last  = time.time()

    #collectors_list = config.collectors.split(",")
    logging.info("Started Roneo - listening on %s:%s - sending to: %s on port %s" % (config['bind_ip'], config['bind_port'], config['collectors'], config['collector_port']))

    while True:
        # Report stats every 60 seconds
        if (time.time() - stats_time_last) > 60:
            logging.info(str("Statistics since: {}".format(datetime.fromtimestamp(stats_time_last))))

            logging.info("Sources:")
            for src in stats_sources:
                logging.info("%s\t : %d packets" % (src, stats_sources[src]))
                # Reset stat to 0
                stats_sources[src] = 0

            logging.info("Collectors:")
            for collector in stats_collectors:
                logging.info("%s\t : %d packets" % (collector, stats_collectors[collector]))
                # Reset stat to 0
                stats_collectors[collector] = 0

            stats_time_last = time.time()

        # Pull packet from socket
        recv_data, addr = server_socket.recvfrom(1500)
        source_ip = addr[0]

        if config['debug'] != False:
            logging.debug("Got a packet from source IP: %s" % source_ip)

        # Source stats tracking
        if source_ip in stats_sources:
            stats_sources[source_ip] += 1
        else:
            stats_sources[source_ip] = 1

        # Go through the list of collectors and send the flow
        for ip in config['collectors']:
            send_flow(recv_data, source_ip, ip, config)

            # Stats tracking
            if ip in stats_collectors:
                stats_collectors[ip] += 1
            else:
                stats_collectors[ip] = 1

def parse_arguments():
    parser = argparse.ArgumentParser(description='Configure Roneo - IP NetFlow Multiplexer')
    parser.add_argument('--configfile', action='store', required=True, help='Configuration file')
    args = parser.parse_args()
    return args

def parse_config(args):
    with open(args.configfile, 'r') as ymlfile:
        cfg = yaml.load(ymlfile)
    return cfg

if __name__ == "__main__":
    args   = parse_arguments()
    config = parse_config(args)

    if config['debug'] != False:
        logging.basicConfig(filename=config['log_file'], format='%(asctime)s - %(message)s', level=logging.DEBUG)
    else:
        logging.basicConfig(filename=config['log_file'], format='%(asctime)s - %(message)s', level=logging.INFO)

    main(config)