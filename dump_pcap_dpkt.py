#!/usr/bin/env python3

from argparse import ArgumentParser
import datetime
import sys
from traceback import print_exc

import dpkt
import pdb

class PacketsProcessing:
    MULTICAST_IP = '239.192.1.17'
    DPORT = 49297
    NODE_1 = '10.0.6.22'
    NODE_2 = '10.0.6.23'
    NODE_3 = '10.0.8.22'
    NODE_4 = '10.0.8.23'
    IGMP_MULTICAST = '224.0.0.1'

    def __init__(self):
        self.current_timezone = datetime.datetime.now(datetime.timezone.utc)\
            .astimezone().tzname()
        self.first_round_finished = False
        self.igmp_query_number = None
        self.igmp_query_time = None
        self.igmp_query_timestamp = 0.0
        self.request_id_src = None
        self.last_request_number = None
        self.pre_timestamp = None
        self.last_request_time = None
        self.timestamp = None
        self.request_time_from_payload = None
        self.last_packet_time = None
        self.igmp_dict = {}
        self.all_nodes = [self. NODE_1, self.NODE_2, self.NODE_3,
                          self.NODE_4]
        self.nodes_state = {self.NODE_1: False, self.NODE_2: False,
                            self.NODE_3: False, self.NODE_4: False}
        self.missing_nodes = []
        self.missing_node_detected = False
        self.missing_node_appears_again = False
        self.next_igmp_report_found = False

    def extract_data_from_udp_request(self, pack_number, udp_packet):
        data = udp_packet.data
        self.request_id_src = data[-1]
        hex_data = data.hex()
        self.request_time_from_payload = hex_data[6:10] + '-' + \
            hex_data[10:12] + '-' + hex_data[12:14] + ' ' + \
            hex_data[14:16] + ':' + \
            hex_data[16:18] + ':' + hex_data[18:20]
        self.last_request_number = pack_number

    def timestamp_to_timetrace(self):
        self.last_packet_time = datetime.datetime\
            .fromtimestamp(self.timestamp)\
            .strftime('%Y-%m-%d %H:%M:%S.%f')

    def output_unanswered_request(self, node):
        print(
            f'{node} is not responding. Unanswered request is '
            f'#{self.last_request_number}/ {self.last_request_time} '
            f'({self.current_timezone})/ '
            f'{self.request_time_from_payload} (payload)'
            f'/ request ID {hex(self.request_id_src)}'
        )

    def udp_processing(self, pack_number, ip, udp_packet):
        if isinstance(ip, dpkt.ip.IP):
            src = dpkt.utils.inet_to_str(ip.src)
            dst = dpkt.utils.inet_to_str(ip.dst)
        else:
            return
        dport = udp_packet.dport
        if dst == self.MULTICAST_IP and dport == self.DPORT:
            self.udp_server_processing(pack_number, udp_packet)
            self.first_round_finished = True
            self.pre_timestamp = self.timestamp
            self.last_request_time = self.last_packet_time
            return
        if self.first_round_finished:
            for node in self.all_nodes:
                if src == node:
                    if not self.missing_node_appears_again:
                        self.udp_nodes_processing(udp_packet, src)

    def udp_server_processing(self, pack_number, udp_packet):
        if not self.first_round_finished or all(self.nodes_state.values()):
            # if it is the first round or a request is answered
            if self.missing_node_detected and not \
                self.missing_node_appears_again:
                for missing_node in self.missing_nodes:
                    print(
                        f'Next request packet to which {missing_node} '
                        f'responds is #{self.last_request_number}/ '
                        f'{self.last_packet_time} ({self.current_timezone})/ '
                        f'{self.request_time_from_payload} (payload)/ '
                        f'request ID {hex(self.request_id_src)}\n'
                    )
                self.missing_node_appears_again = True
        else:
        # if a request is not answered and it is not the first round
            if not self.missing_node_detected:
                for node, state in self.nodes_state.items():
                    if not state:
                        self.output_unanswered_request(node)
                        if node in self.igmp_dict:
                            print(
                                f'Latest membership report from '
                                f'{node} is #{self.igmp_dict[node][0]}/ '
                                f'{self.igmp_dict[node][1]} '
                                f'({self.current_timezone})'
                            )
                        else:
                            print(
                                f'No previous membership reports from'
                                f' {node}\n'
                            )
                        self.missing_nodes.append(node)
                self.missing_node_detected = True

        if hasattr(udp_packet, 'data'):
            self.extract_data_from_udp_request(pack_number, udp_packet)
        else:
            print(f'Packet #{pack_number} has no data')

        if self.first_round_finished:
            self.nodes_state = {node: False for node in self.nodes_state} # reset response states of all nodes to False
            delay = round(self.timestamp - self.pre_timestamp, 1)
            if delay - 0.2 > 0.1:
                print(
                    f'Missing request(s) detected - no requests for {delay}s'
                    f' up to #{pack_number}/ {self.last_packet_time} '
                    f'({self.current_timezone})/ '
                    f'{self.request_time_from_payload} (payload)/ '
                    f'request ID {hex(self.request_id_src)}'
                )
        else:
            print(
                f'First request packet is #{self.last_request_number}'
                f'/ {self.last_packet_time} ({self.current_timezone})/ '
                f'{self.request_time_from_payload} (payload)/ '
                f'request ID {hex(self.request_id_src)}'
            )

    def udp_nodes_processing(self, udp_packet, src):
        if hasattr(udp_packet, 'data'):
            data = udp_packet.data
            request_id_dest = data[-1]
            if request_id_dest == self.request_id_src:
                self.nodes_state[src] = True

    def igmp_processing(self, pack_number, ip):

        if not self.missing_node_appears_again:
            if isinstance(ip, dpkt.ip.IP):
                src = dpkt.utils.inet_to_str(ip.src)
                dst = dpkt.utils.inet_to_str(ip.dst)
            if src in self.all_nodes:
                igmp_packet_time = self.last_packet_time
                igmp_packet_number = pack_number
                self.igmp_dict[src] = [igmp_packet_number, igmp_packet_time]
            if dst == self.IGMP_MULTICAST:
                if not self.igmp_query_number:
                    print(
                        f'First membership query is #{pack_number}/ '
                        f'{self.last_packet_time} ({self.current_timezone})\n'
                    )
                    self.igmp_query_number = pack_number
                    self.igmp_query_timestamp = self.timestamp
                else:
                    self.igmp_query_number = pack_number
                    self.igmp_query_time = self.last_packet_time
                    queries_interval = round(
                        self.timestamp - self.igmp_query_timestamp, 1)
                    if queries_interval > 12.1:
                        print(
                            'Membership query(s) missing - '
                            f'no queries for {queries_interval}s up to '
                            f'#{pack_number}/ {self.last_packet_time} '
                            f'({self.current_timezone})')
                    self.igmp_query_timestamp = self.timestamp
            if self.missing_node_detected:
                for missing_node in self.missing_nodes:
                    if src == missing_node:
                        print(
                            f'Next membership report from {missing_node} is '
                            f'#{self.igmp_dict[missing_node][0]}/ '
                            f'{self.igmp_dict[missing_node][1]} '
                            f'({self.current_timezone})'
                        )
                        self.next_igmp_report_found = True

    def find_unanswered_requests(self, pcap_file, hanging_nodes):
        print(f'Hanging nodes: {hanging_nodes}\n')
        self.first_round_finished = False
        unanswered_requests = []
        pack_number = 0
        with open(pcap_file, 'rb') as f:
            packets = dpkt.pcapng.Reader(f)
            for self.timestamp, pack in packets:
                pack_number += 1
                self.timestamp_to_timetrace()
                eth = dpkt.ethernet.Ethernet(pack)
                ip = eth.data
                if not hasattr(ip, 'data'):
                    continue
                packet_type = ip.data
                if isinstance(packet_type, dpkt.udp.UDP):
                    if isinstance(ip, dpkt.ip.IP):
                        src = dpkt.utils.inet_to_str(ip.src)
                        dst = dpkt.utils.inet_to_str(ip.dst)
                    else:
                        continue
                    dport = packet_type.dport
                    if dst == self.MULTICAST_IP and dport == self.DPORT:
                        if self.first_round_finished and not \
                            all(self.nodes_state.values()):
                            for node in hanging_nodes:
                                if not self.nodes_state[node]:
                                    self.output_unanswered_request(node)
                                    unanswered_requests.append(
                                        self.last_packet_time) # improve for multiple hanging_nodes, not only 1
                        if hasattr(packet_type, 'data'):
                            self.extract_data_from_udp_request(
                                pack_number, packet_type)
                        if self.first_round_finished:
                            self.nodes_state = {
                                node: False for node in self.nodes_state}
                        self.first_round_finished = True
                        self.pre_timestamp = self.timestamp
                        self.last_request_time = self.last_packet_time
                        continue
                    if self.first_round_finished:
                        for node in self.all_nodes:
                            if src == node:
                                self.udp_nodes_processing(packet_type, src)
        print(
            f'\n{hanging_nodes[0]} ({self.current_timezone}):'
            f'\n{unanswered_requests}'
        )

    def udp_dump_pcap(self, pcap_file):
        pack_number = 0
        with open(pcap_file, 'rb') as f:
            packets = dpkt.pcapng.Reader(f)
            for self.timestamp, pack in packets:
                pack_number += 1
                self.timestamp_to_timetrace()
                eth = dpkt.ethernet.Ethernet(pack)
                ip = eth.data
                if not hasattr(ip, 'data'):
                    continue
                packet_type = ip.data
                if isinstance(packet_type, dpkt.udp.UDP):
                    self.udp_processing(pack_number, ip, packet_type)
                    continue
                if isinstance(packet_type, dpkt.igmp.IGMP):
                    self.igmp_processing(pack_number, ip)
            
        hanging_nodes = self.output_results()
        self.find_unanswered_requests(pcap_file, hanging_nodes)

    def output_results(self):
        if not self.next_igmp_report_found:
            for missing_node in self.missing_nodes:
                print(f'\nNo next membership reports from {missing_node}')
        if not self.missing_node_appears_again:
            for missing_node in self.missing_nodes:
                print(
                    f'\nNo next responses from {missing_node}'
                )
                hanging_nodes = [node for node in self.all_nodes \
                    if node not in self.missing_nodes] # nodes that respond, but not always

        print(
            f'\nLatest request is #{self.last_request_number}'
            f'/ {self.last_packet_time} ({self.current_timezone})/ '
            f'{self.request_time_from_payload} (payload)/ '
            f'request ID {hex(self.request_id_src)}\n'
        )
        print(
            f'Latest membership query is #{self.igmp_query_number}/ '
            f'{self.igmp_query_time} ({self.current_timezone})\n'
        )
        for src in self.all_nodes:
            if src in self.igmp_dict:
                print(
                    f'Latest membership report from {src} is '
                    f'#{self.igmp_dict[src][0]}/ '
                    f'{self.igmp_dict[src][1]} ({self.current_timezone})\n'
                )
            else:
                print(f'No membership reports from {src}\n')
        
        return hanging_nodes

def main():
    parser = ArgumentParser(
        description='Analysis of UDP and IGMP packets in PCAP files')
    parser.add_argument('pcap_file', help='Path to the pcap file')
    parser.add_argument('--csv', action="store_true",
                        help='Enable csv generation')
    args = parser.parse_args()
    try:
        pcap_object = PacketsProcessing()
        pcap_object.udp_dump_pcap(args.pcap_file)
        sys.exit(0)
    except FileNotFoundError as fe:
        print(fe)
    except Exception:
        print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
