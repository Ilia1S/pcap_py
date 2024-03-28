#!/usr/bin/env python3

import argparse
import datetime
import sys
from traceback import print_exc

import dpkt

class PacketsProcessing:
    MULTICAST_IP = '239.192.1.17'
    DPORT = 49297
    NODE_1 = '10.0.6.22'
    NODE_2 = '10.0.6.23'
    NODE_3 = '10.0.8.22'
    NODE_4 = '10.0.8.23'
    IGMP_MULTICAST = '224.0.0.1'
    NUMBER_OF_DIVISIONS = 17
    VALUE_OF_DIVISION = 254 # in minutes

    def __init__(self):
        self.delta = 0
        self.first_udp_round_finished = False
        self.first_igmp_round_finished = False
        self.igmp_query_number = None
        self.igmp_query_time = None
        self.igmp_query_timestamp = 0.0
        self.request_id_src = None
        self.last_request_number = None
        self.pre_timestamp = None
        self.last_request_time = None
        self.timestamp = None
        self.request_time_from_payload = None
        self.payload_time_object = None
        self.last_packet_time = None
        self.igmp_dict = {}
        self.all_nodes = [self. NODE_1, self.NODE_2, self.NODE_3,
                          self.NODE_4]
        self.nodes_state_udp = {self.NODE_1: False, self.NODE_2: False,
                                self.NODE_3: False, self.NODE_4: False}
        self.nodes_state_igmp = {self.NODE_1: False, self.NODE_2: False,
                                 self.NODE_3: False, self.NODE_4: False}
        self.missing_nodes = []
        self.missing_requests = {}
        self.missing_queries = {}
        self.unanswered_requests = {self. NODE_1: [], self.NODE_2: [], \
            self. NODE_3: [], self.NODE_4: []}
        self.unanswered_queries = {self. NODE_1: [], self.NODE_2: [], \
            self. NODE_3: [], self.NODE_4: []}
        self.missing_node_detected = False
        self.missing_node_appears_again = False
        self.next_igmp_report_found = False
        self.number_of_division = 0

    def extract_data_from_udp_request(self, pack_number, udp_packet):
        data = udp_packet.data
        self.request_id_src = data[-1]
        hex_data = data.hex()
        self.request_time_from_payload = hex_data[6:10] + '-' + \
            hex_data[10:12] + '-' + hex_data[12:14] + ' ' + \
            hex_data[14:16] + ':' + \
            hex_data[16:18] + ':' + hex_data[18:20]
        self.last_request_number = pack_number

    def unix_timestamp_to_timetrace(self):
        if not self.payload_time_object:
            self.last_packet_time = datetime.datetime\
                .utcfromtimestamp(self.timestamp)\
                .strftime('%Y-%m-%d %H:%M:%S.%f')
        else:
            self.last_packet_time = (datetime.datetime\
                .utcfromtimestamp(self.timestamp) + \
                    self.delta).strftime('%Y-%m-%d %H:%M:%S.%f')

    def calculate_delta_from_payload_time(self):
        self.payload_time_object = datetime.datetime.strptime(
            self.request_time_from_payload, "%Y-%m-%d %H:%M:%S")
        last_packet_time_object = datetime.datetime\
            .strptime(self.last_packet_time, "%Y-%m-%d %H:%M:%S.%f")
        self.delta = self.payload_time_object - last_packet_time_object

    def output_unanswered_request_or_query(self, node, prot):
        if prot == 'udp':
            print(
                f"{node} isn't responding for UDP request. Unanswered request"
                f' is #{self.last_request_number}/ {self.last_request_time}/'
                f' request ID {hex(self.request_id_src)}'
            )
        elif prot == 'igmp':
            print(
                f"{node} isn't responding for membership query. "
                f'Unanswered query is #{self.igmp_query_number}/ '
                f'{self.igmp_query_time}'
            )

    def draw_csv_table(self, scale_timestamps_objects,
                       scale_timestamps_strings):

        def print_missing(data_dict, data_type):
            if data_dict:
                print(
                    '\nDivision number; Timestamp; '
                    f'Number of {data_type}:\n'
                )
                iterator = iter(data_dict.items())
                next(iterator)
                for i, (key, value) in enumerate(iterator, 1):
                    print(f'{i}; {key}; {value}')

        def print_unanswered(data_dict, data_type):
            for key, time_list in data_dict.items():
                if time_list:
                    print(
                        f'\n{key}:\nDivision number; '
                        f'Timestamp; Number of {data_type}:\n'
                    )
                    self.process_time_list(time_list, scale_timestamps_objects,
                                           scale_timestamps_strings)

        print_missing(self.missing_requests, 'missing requests')
        print_missing(self.missing_queries, 'missing queries')

        print_unanswered(self.unanswered_requests, 'unanswered requests')

        print_unanswered(self.unanswered_queries, 'unanswered queries')

    def process_time_list(self, time_list, scale_timestamps_objects,
                          scale_timestamps_strings):
        points_per_division = 0
        for i in range(self.NUMBER_OF_DIVISIONS):
            for time in time_list:
                if scale_timestamps_objects[i] < time \
                    <= scale_timestamps_objects[i+1]:
                    points_per_division += 1
            print(
                f'{i+1}; {scale_timestamps_strings[i+1]}; '
                f'{points_per_division}'
            )
            points_per_division = 0

    def udp_dump_pcap(self, pcap_file, start_of_scale):
        pack_number = 0
        one_minute = datetime.timedelta(minutes=1)
        division_delta = self.VALUE_OF_DIVISION * one_minute
        scale_timestamps_objects = [
            start_of_scale + i * division_delta \
                for i in range(self.NUMBER_OF_DIVISIONS + 1)
        ]
        scale_timestamps_strings = [
            ts.strftime('%Y-%m-%d %H:%M:%S.%f') \
                for ts in scale_timestamps_objects
        ]
        missing_data = {division: 0 for division in scale_timestamps_strings}
        self.missing_requests = missing_data.copy()
        self.missing_queries = missing_data.copy()

        with open(pcap_file, 'rb') as f:
            packets = dpkt.pcapng.Reader(f)
            for self.timestamp, pack in packets:
                pack_number += 1
                self.unix_timestamp_to_timetrace()
                eth = dpkt.ethernet.Ethernet(pack)
                ip = eth.data
                if not hasattr(ip, 'data'):
                    continue
                packet_type = ip.data
                last_packet_time_object = datetime.datetime\
                    .strptime(self.last_packet_time, "%Y-%m-%d %H:%M:%S.%f")
                if last_packet_time_object > \
                    scale_timestamps_objects[self.number_of_division+1]:
                    self.pre_timestamp = self.timestamp
                    self.number_of_division += 1
                if isinstance(packet_type, dpkt.udp.UDP):
                    self.udp_processing(pack_number, ip, packet_type,
                                        scale_timestamps_strings)
                    continue
                if isinstance(packet_type, dpkt.igmp.IGMP):
                    self.igmp_processing(pack_number, ip,
                                         scale_timestamps_strings)

        hanging_nodes_udp, hanging_nodes_igmp = self.output_results()
        self.find_unanswered_requests_and_queries(pcap_file,
            hanging_nodes_udp, hanging_nodes_igmp)

        return scale_timestamps_objects, scale_timestamps_strings

    def udp_processing(self, pack_number, ip, udp_packet,
                       scale_timestamps_strings):
        if not isinstance(ip, dpkt.ip.IP):
            return
        src = dpkt.utils.inet_to_str(ip.src)
        dst = dpkt.utils.inet_to_str(ip.dst)
        dport = udp_packet.dport
        if dst == self.MULTICAST_IP and dport == self.DPORT:
            self.udp_server_processing(
                pack_number, udp_packet, scale_timestamps_strings)
            self.first_udp_round_finished = True
            self.pre_timestamp = self.timestamp
            self.last_request_time = self.last_packet_time
        elif self.first_udp_round_finished and src in self.all_nodes:
            if not self.missing_node_appears_again:
                self.udp_nodes_processing(udp_packet, src)

    def udp_server_processing(self, pack_number, udp_packet,
                              scale_timestamps_strings):
        if not self.first_udp_round_finished or \
            all(self.nodes_state_udp.values()):
            # if it is the first round or a request is answered
            if self.missing_node_detected and not \
                self.missing_node_appears_again:
                for missing_node in self.missing_nodes:
                    print(
                        f'Next request packet to which {missing_node} '
                        f'responds is #{self.last_request_number}/ '
                        f'{self.last_packet_time}/ '
                        f'request ID {hex(self.request_id_src)}\n'
                    )
                self.missing_node_appears_again = True
        else:
        # if a request is not answered and it is not the first round
            if not self.missing_node_detected:
                for node, state in self.nodes_state_udp.items():
                    if not state:
                        self.output_unanswered_request_or_query(
                            node, 'udp')
                        if node in self.igmp_dict:
                            print(
                                'Latest membership report from '
                                f'{node} is #{self.igmp_dict[node][0]}/ '
                                f'{self.igmp_dict[node][1]}'
                            )
                        else:
                            print(
                                'No previous membership reports from'
                                f' {node}\n'
                            )
                        self.missing_nodes.append(node)
                self.missing_node_detected = True

        if hasattr(udp_packet, 'data'):
            self.extract_data_from_udp_request(pack_number, udp_packet)
            if not self.payload_time_object:
                self.calculate_delta_from_payload_time()
                self.unix_timestamp_to_timetrace()

        else:
            print(f'Packet #{pack_number} has no data')

        if self.first_udp_round_finished:
            self.nodes_state_udp = {
                node: False for node in self.nodes_state_udp} # reset response states of all nodes to False
            delay = round(self.timestamp - self.pre_timestamp, 1)
            if delay - 0.2 > 0.1:
                print(
                    f'Missing request(s) detected - no requests for {delay}s'
                    f' up to #{pack_number}/ {self.last_packet_time}/ '
                    f'request ID {hex(self.request_id_src)}'
                )
                missing_requests = round(delay / 0.2)
                self.missing_requests[scale_timestamps_strings[
                    self.number_of_division+1]] += missing_requests
        else:
            print(
                f'First request packet is #{self.last_request_number}'
                f'/ {self.last_packet_time}/ '
                f'request ID {hex(self.request_id_src)}'
            )

    def udp_nodes_processing(self, udp_packet, src):
        if hasattr(udp_packet, 'data'):
            data = udp_packet.data
            request_id_dest = data[-1]
            if request_id_dest == self.request_id_src:
                self.nodes_state_udp[src] = True

    def igmp_processing(self, pack_number, ip, scale_timestamps_strings):
        if self.missing_node_appears_again:
            return
        if not isinstance(ip, dpkt.ip.IP):
            return
        src = dpkt.utils.inet_to_str(ip.src)
        dst = dpkt.utils.inet_to_str(ip.dst)
        if src in self.all_nodes:
            self.igmp_dict[src] = [pack_number, self.last_packet_time]
        if dst == self.IGMP_MULTICAST:
            self.igmp_query_time = self.last_packet_time
            if not self.igmp_query_number:
                print(
                    f'First membership query is #{pack_number}/ '
                    f'{self.last_packet_time}\n'
                )
                self.igmp_query_number = pack_number
                self.igmp_query_timestamp = self.timestamp
            else:
                self.igmp_query_number = pack_number
                queries_interval = round(
                    self.timestamp - self.igmp_query_timestamp, 1)
                if queries_interval > 12.1:
                    print(
                        'Membership query(s) missing - no queries for '
                        f'{queries_interval}s up to '
                        f'#{pack_number}/ {self.last_packet_time}'
                    )
                    missing_queries = round(queries_interval / 12)
                    self.missing_queries[scale_timestamps_strings[
                        self.number_of_division+1]] += missing_queries
                self.igmp_query_timestamp = self.timestamp
        if self.missing_node_detected and src in self.missing_nodes:
            for missing_node in self.missing_nodes:
                print(
                    f'Next membership report from {missing_node} is '
                    f'#{self.igmp_dict[missing_node][0]}/ '
                    f'{self.igmp_dict[missing_node][1]}'
                )
                self.next_igmp_report_found = True

    def find_unanswered_requests_and_queries(
        self, pcap_file,hanging_nodes_udp, hanging_nodes_igmp):
        pack_number = 0
        self.first_udp_round_finished = False
        print(f'Hanging nodes (udp): {hanging_nodes_udp}\n')
        print(f'Hanging nodes (igmp): {hanging_nodes_igmp}\n')
        with open(pcap_file, 'rb') as f:
            packets = dpkt.pcapng.Reader(f)
            for self.timestamp, pack in packets:
                pack_number += 1
                self.unix_timestamp_to_timetrace()
                eth = dpkt.ethernet.Ethernet(pack)
                ip = eth.data
                if not hasattr(ip, 'data'):
                    continue
                packet_type = ip.data
                if isinstance(packet_type, dpkt.udp.UDP):
                    self.find_unanswered_requests(
                        pack_number, packet_type, ip, hanging_nodes_udp)
                    continue
                if isinstance(packet_type, dpkt.igmp.IGMP):
                    self.find_unanswered_queries(
                        pack_number, ip, hanging_nodes_igmp)

    def find_unanswered_requests(
        self, pack_number, packet_type, ip, hanging_nodes_udp):
        if isinstance(ip, dpkt.ip.IP):
            src = dpkt.utils.inet_to_str(ip.src)
            dst = dpkt.utils.inet_to_str(ip.dst)
        else:
            return
        dport = packet_type.dport
        if dst == self.MULTICAST_IP and dport == self.DPORT:
            if self.first_udp_round_finished:
                for node in hanging_nodes_udp:
                    if not self.nodes_state_udp[node]:
                        self.output_unanswered_request_or_query(
                            node, 'udp')
                        unanswered_req_timestamp = datetime\
                            .datetime.strptime(
                                self.last_request_time,
                                "%Y-%m-%d %H:%M:%S.%f")
                        self.unanswered_requests[node].append(
                            unanswered_req_timestamp)

            if hasattr(packet_type, 'data'):
                self.extract_data_from_udp_request(
                    pack_number, packet_type)
            if self.first_udp_round_finished:
                self.nodes_state_udp = {
                    node: False for node in self.nodes_state_udp}
            self.first_udp_round_finished = True
            self.pre_timestamp = self.timestamp
            self.last_request_time = self.last_packet_time
            return
        if self.first_udp_round_finished:
            for node in hanging_nodes_udp:
                if src == node:
                    self.udp_nodes_processing(packet_type, src)

    def find_unanswered_queries(self, pack_number, ip, hanging_nodes_igmp):
        if isinstance(ip, dpkt.ip.IP):
            src = dpkt.utils.inet_to_str(ip.src)
            dst = dpkt.utils.inet_to_str(ip.dst)
        else:
            return
        if dst == self.IGMP_MULTICAST:
            if self.first_igmp_round_finished:
                for node in hanging_nodes_igmp:
                    if not self.nodes_state_igmp[node]:
                        self.output_unanswered_request_or_query(
                            node, 'igmp')
                        unanswered_query_timestamp = datetime\
                            .datetime.strptime(
                                self.igmp_query_time,
                                "%Y-%m-%d %H:%M:%S.%f")
                        self.unanswered_queries[node].append(
                            unanswered_query_timestamp)

                self.nodes_state_igmp = {
                    node: False for node in self.nodes_state_igmp}
            self.first_igmp_round_finished = True
            self.igmp_query_time = self.last_packet_time
            self.igmp_query_number = pack_number
            return
        if self.first_igmp_round_finished:
            for node in hanging_nodes_igmp:
                if src == node:
                    self.nodes_state_igmp[node] = True

    def output_results(self):
        if not self.next_igmp_report_found:
            for missing_node in self.missing_nodes:
                print(f'\nNo next membership reports from {missing_node}')
        if not self.missing_node_appears_again:
            for missing_node in self.missing_nodes:
                print(
                    f'\nNo next responses from {missing_node}'
                )
                hanging_nodes_udp = [node for node in self.all_nodes \
                    if node not in self.missing_nodes] # nodes that are alive, but sometimes hang
        print(
            f'\nLatest request is #{self.last_request_number}'
            f'/ {self.last_packet_time}/ '
            f'request ID {hex(self.request_id_src)}\n'
        )
        print(
            f'Latest membership query is #{self.igmp_query_number}/ '
            f'{self.igmp_query_time}\n'
        )
        for src in self.all_nodes:
            if src in self.igmp_dict:
                print(
                    f'Latest membership report from {src} is '
                    f'#{self.igmp_dict[src][0]}/ '
                    f'{self.igmp_dict[src][1]}\n'
                )
            else:
                print(f'No membership reports from {src}\n')
                hanging_nodes_igmp = list(self.igmp_dict.keys()) # nodes that are alive, but sometimes hang

        return hanging_nodes_udp, hanging_nodes_igmp

def valid_date(s):
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError as exc:
        msg = f"Invalid format for --csv: '{s}'. \
Format must be YYYY-MM-DD HH:MM:SS.ssssss"
        raise argparse.ArgumentTypeError(msg) from exc

def main():
    parser = argparse.ArgumentParser(
        description='Analysis of UDP and IGMP packets in PCAP files')
    parser.add_argument('pcap_file', help='Path to the pcap file')
    parser.add_argument('--csv',
        help='Enable csv generation with specified start scale value',
        type=valid_date, required=True
    )
    args = parser.parse_args()
    try:
        pcap_object = PacketsProcessing()
        scale_timestamps_objects, scale_timestamps_strings = \
            pcap_object.udp_dump_pcap(args.pcap_file, args.csv)
        pcap_object.draw_csv_table(scale_timestamps_objects,
                                   scale_timestamps_strings)
        sys.exit(0)
    except FileNotFoundError as fe:
        print(fe)
    except Exception:
        print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
