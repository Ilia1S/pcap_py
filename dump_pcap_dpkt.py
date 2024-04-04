#!/usr/bin/env python3

import argparse
import datetime
import sys
from traceback import print_exc

import dpkt


NODE_1 = '10.0.6.22'
NODE_2 = '10.0.6.23'
NODE_3 = '10.0.8.22'
NODE_4 = '10.0.8.23'
ALL_NODES = [NODE_1, NODE_2, NODE_3, NODE_4]


class PacketsProcessing:
    MULTICAST_IP = '239.192.1.17'
    DPORT = 49297
    IGMP_MULTICAST = '224.0.0.1'
    NUMBER_OF_DIVISIONS = 17
    VALUE_OF_DIVISION = 254 # in minutes

    def __init__(self):
        self.first_udp_round_finished = False
        self.igmp_query_number = None
        self.igmp_query_time = None
        self.igmp_query_timestamp = 0.0
        self.request_id_src = None
        self.last_request_number = None
        self.pre_request_timestamp = None
        self.last_request_time = None
        self.timestamp = None
        self.last_packet_time = None
        self.igmp_dict = {}
        self.scale_timestamps_objects = []
        self.scale_timestamps_strings = []
        self.nodes_state_udp = {NODE_1: False, NODE_2: False,
                                NODE_3: False, NODE_4: False}
        self.nodes_state_igmp = {NODE_1: False, NODE_2: False,
                                 NODE_3: False, NODE_4: False}
        self.missing_nodes = []
        self.missing_requests = {}
        self.missing_queries = {}
        self.unanswered_requests = {NODE_1: [], NODE_2: [], \
            NODE_3: [], NODE_4: []}
        self.unanswered_queries = {NODE_1: [], NODE_2: [], \
            NODE_3: [], NODE_4: []}
        self.missing_node_detected = False
        self.missing_node_appears_again = False
        self.next_igmp_report_found = False
        self.number_of_division = 0

    def extract_data_from_udp_request(self, pack_number, udp_packet):
        data = udp_packet.data
        self.request_id_src = data[-1]
        self.last_request_number = pack_number

    def unix_timestamp_to_string(self, delta):
        last_packet_time_object = datetime.datetime\
            .utcfromtimestamp(self.timestamp)
        self.last_packet_time = (last_packet_time_object + delta).strftime('%Y-%m-%d %H:%M:%S.%f')

    def read_time_from_hex_data(self, packet_type):
        data = packet_type.data
        hex_data = data.hex()
        request_time_from_payload = hex_data[6:10] + '-' + \
            hex_data[10:12] + '-' + hex_data[12:14] + ' ' + \
            hex_data[14:16] + ':' + \
            hex_data[16:18] + ':' + hex_data[18:20]
        return request_time_from_payload

    def mark_scale(self, start_of_scale):
        one_minute = datetime.timedelta(minutes=1)
        division_delta = self.VALUE_OF_DIVISION * one_minute
        self.scale_timestamps_objects = [
            start_of_scale + i * division_delta \
                for i in range(self.NUMBER_OF_DIVISIONS + 1)
        ]
        self.scale_timestamps_strings = [
            ts.strftime('%Y-%m-%d %H:%M:%S') \
                for ts in self.scale_timestamps_objects
        ]

    def create_missing_data_dict(self):
        missing_data = \
            {division: 0 for division in self.scale_timestamps_strings}
        self.missing_requests = missing_data.copy()
        self.missing_queries = missing_data.copy()

    def calculate_delta_from_payload_time(self, pcap_file, payload_time):
        if not payload_time:
            delta = datetime.timedelta()
        else:
            delta = 0
            pack_number = 0
            with open(pcap_file, 'rb') as f:
                packets = dpkt.pcapng.Reader(f)
                for timestamp, pack in packets:
                    pack_number += 1
                    eth = dpkt.ethernet.Ethernet(pack)
                    ip = eth.data
                    if not hasattr(ip, 'data'):
                        continue
                    packet_type = ip.data
                    if isinstance(packet_type, dpkt.udp.UDP):
                        if not isinstance(ip, dpkt.ip.IP):
                            continue
                        dst = dpkt.utils.inet_to_str(ip.dst)
                        dport = packet_type.dport
                        if dst == self.MULTICAST_IP and dport == self.DPORT:
                            last_packet_time = datetime.datetime\
                                .utcfromtimestamp(timestamp)\
                                .strftime('%Y-%m-%d %H:%M:%S.%f')
                            request_time_from_payload = \
                                self.read_time_from_hex_data(packet_type)
                            payload_time_object = datetime.datetime.strptime(
                                request_time_from_payload,
                                "%Y-%m-%d %H:%M:%S")
                            last_packet_time_object = datetime.datetime\
                                .strptime(last_packet_time,
                                          "%Y-%m-%d %H:%M:%S.%f")

                            delta = payload_time_object - \
                                last_packet_time_object
                            break

        print(f'\nDELTA = {delta}\n')
        return delta

    def check_last_request_before_division(self, pack_number):
        requests_interval = round(
            self.timestamp - self.pre_request_timestamp, 1)
        if requests_interval - 0.2 > 0.1:
            missing_requests = round(requests_interval / 0.2)
            self.missing_requests[self.scale_timestamps_strings[
                self.number_of_division]] += missing_requests
            print(
                f'Missing request(s) - no requests for {requests_interval}s'
                f' up to #{pack_number}/ {self.last_packet_time}\n'
                f'The previous request was #{self.last_request_number}/ '
                f'{self.last_request_time}'
            )

    def check_last_query_before_division(self, pack_number):
        queries_interval = round(
            self.timestamp - self.igmp_query_timestamp, 1)
        if queries_interval > 12.1:
            print(
                'Missing membership query(s) - no queries for '
                f'{queries_interval}s up to '
                f'#{pack_number}/ {self.last_packet_time}\n'
                f'The previous query was #{self.igmp_query_number}/ '
                f'{self.igmp_query_time}'
            )
            missing_queries = round(queries_interval / 12)
            self.missing_queries[self.scale_timestamps_strings[
                self.number_of_division]] += missing_queries
        self.igmp_query_timestamp = self.timestamp

    def check_for_range(self, pack_number, start_of_scale):
        last_packet_time_object = datetime.datetime\
            .strptime(self.last_packet_time, "%Y-%m-%d %H:%M:%S.%f")
        if start_of_scale > last_packet_time_object:
            return 1
        if last_packet_time_object > self.scale_timestamps_objects[-1]:
            return -1
        if self.last_request_number and \
            last_packet_time_object > \
                self.scale_timestamps_objects[self.number_of_division+1]:
            self.check_last_request_before_division(pack_number)
            if self.igmp_query_number:
                self.check_last_query_before_division(pack_number)
            self.pre_request_timestamp = self.timestamp
            self.number_of_division += 1

    def output_unanswered_request_or_query(self, node, prot):
        if prot == 'udp':
            print(
                f'{node} not responding for UDP request. Unanswered request'
                f' is #{self.last_request_number}/ {self.last_request_time}/'
                f' request ID {hex(self.request_id_src)}'
            )
        elif prot == 'igmp':
            print(
                f'{node} not responding for membership query. '
                f'Unanswered query is #{self.igmp_query_number}/ '
                f'{self.igmp_query_time}'
            )

    def draw_csv_table(self):
        def format_unanswered(data_dict):
            unanswered_per_node = {}
            for key, time_list in data_dict.items():
                if time_list:
                    unanswered_per_node = self.process_time_list(time_list)

            return unanswered_per_node

        unanswered_req_per_node = format_unanswered(self.unanswered_requests)
        unanswered_que_per_node = format_unanswered(self.unanswered_queries)

        combined_dict = {
            key: [self.missing_requests.get(key),
                  self.missing_queries.get(key),
                  unanswered_req_per_node.get(key),
                  unanswered_que_per_node.get(key)
            ] for key in self.missing_requests
        }
        print(
            '\nDivision number; Timestamp; '
            'Missing requests; Missing queries; Unanswered requests; '
            'Unanswered queries:\n'
        )
        for i, (key, value) in enumerate(combined_dict.items(), 1):
            value_str = '; '.join(map(str, value))
            print(f'{i}; {key}; {value_str}')

    def process_time_list(self, time_list):
        unanswered_per_node = {}
        points_per_division = 0
        for i in range(self.NUMBER_OF_DIVISIONS+1):
            for time in time_list:
                if self.scale_timestamps_objects[i] < time \
                    <= self.scale_timestamps_objects[i+1]:
                    points_per_division += 1
            unanswered_per_node[self.scale_timestamps_strings[i]] = \
                points_per_division
            points_per_division = 0
        return unanswered_per_node

    def udp_dump_pcap(self, pcap_file, start_of_scale, payload_time,
                      hanging_nodes):
        delta = self.calculate_delta_from_payload_time(pcap_file,
                                                       payload_time)
        self.mark_scale(start_of_scale)
        self.create_missing_data_dict()

        pack_number = 0
        with open(pcap_file, 'rb') as f:
            packets = dpkt.pcapng.Reader(f)
            for self.timestamp, pack in packets:
                pack_number += 1
                self.unix_timestamp_to_string(delta)
                r = self.check_for_range(pack_number, start_of_scale)
                if r == 1:
                    continue
                if r == -1:
                    break
                eth = dpkt.ethernet.Ethernet(pack)
                ip = eth.data
                if not hasattr(ip, 'data'):
                    continue
                packet_type = ip.data
                if isinstance(packet_type, dpkt.udp.UDP):
                    self.udp_processing(
                        pack_number, ip, packet_type, hanging_nodes)
                    continue
                if isinstance(packet_type, dpkt.igmp.IGMP):
                    self.igmp_processing(pack_number, ip, hanging_nodes)

        self.output_results()

    def udp_processing(self, pack_number, ip, udp_packet, hanging_nodes):
        if not isinstance(ip, dpkt.ip.IP):
            return
        src = dpkt.utils.inet_to_str(ip.src)
        dst = dpkt.utils.inet_to_str(ip.dst)
        dport = udp_packet.dport
        if dst == self.MULTICAST_IP and dport == self.DPORT:
            self.udp_server_processing(
                pack_number, udp_packet, hanging_nodes)
            self.first_udp_round_finished = True
            self.pre_request_timestamp = self.timestamp
            self.last_request_time = self.last_packet_time
        elif self.first_udp_round_finished and src in ALL_NODES:
            if not self.missing_node_appears_again:
                self.udp_nodes_processing(udp_packet, src)

    def udp_server_processing(self, pack_number, udp_packet, hanging_nodes):
        if not self.first_udp_round_finished or \
            all(self.nodes_state_udp.values()):
            self.udp_when_all_respond()
        else:
            self.request_not_answered(hanging_nodes)

        if self.first_udp_round_finished:
            self.nodes_state_udp = {
                node: False for node in self.nodes_state_udp} # reset response states of all nodes to False
            self.check_last_request_before_division(pack_number)

        if hasattr(udp_packet, 'data'):
            self.extract_data_from_udp_request(pack_number, udp_packet)
        else:
            print(f'Packet #{pack_number} has no data')

        if not self.first_udp_round_finished:
            print(
                f'First request packet is #{self.last_request_number}'
                f'/ {self.last_packet_time}/ '
                f'request ID {hex(self.request_id_src)}\n'
            )

    # if it is the first round or all requests are answered
    def udp_when_all_respond(self):
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

    # if a request is not answered and it is not the first round
    def request_not_answered(self, hanging_nodes):
        for node in hanging_nodes:
            if self.nodes_state_udp.get(node, True):
                continue
            self.output_unanswered_request_or_query(
                node, 'udp')
            unanswered_req_timestamp = datetime\
                .datetime.strptime(
                    self.last_request_time,
                    "%Y-%m-%d %H:%M:%S.%f")
            self.unanswered_requests[node].append(
                        unanswered_req_timestamp)

        if not self.missing_node_detected:
            self.missing_not_detected()

    def missing_not_detected(self):
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
                        'No previous membership reports from '
                        f'{node}'
                    )
                self.missing_nodes.append(node)
        print('\n')
        self.missing_node_detected = True

    def udp_nodes_processing(self, udp_packet, src):
        if hasattr(udp_packet, 'data'):
            data = udp_packet.data
            request_id_dest = data[-1]
            if request_id_dest == self.request_id_src:
                self.nodes_state_udp[src] = True

    def igmp_processing(self, pack_number, ip, hanging_nodes):
        if self.missing_node_appears_again:
            return
        if not isinstance(ip, dpkt.ip.IP):
            return
        src = dpkt.utils.inet_to_str(ip.src)
        dst = dpkt.utils.inet_to_str(ip.dst)
        if src in ALL_NODES:
            self.igmp_dict[src] = [pack_number, self.last_packet_time]

        if dst == self.IGMP_MULTICAST:
            self.igmp_query_processing(pack_number, hanging_nodes)

        self.igmp_nodes_processing(src, hanging_nodes)

    def igmp_query_processing(self, pack_number, hanging_nodes):
        if not self.igmp_query_number:
            print(
                f'First membership query is #{pack_number}/ '
                f'{self.last_packet_time}\n'
            )
            self.igmp_query_timestamp = self.timestamp
        else:
            for node in hanging_nodes:
                if self.nodes_state_igmp.get(node, True):
                    continue
                self.output_unanswered_request_or_query(
                    node, 'igmp')
                unanswered_query_timestamp = datetime\
                    .datetime.strptime(
                        self.igmp_query_time,
                        "%Y-%m-%d %H:%M:%S.%f")
                self.unanswered_queries[node].append(
                    unanswered_query_timestamp)

            self.check_last_query_before_division(pack_number)

        self.igmp_query_number = pack_number
        self.igmp_query_time = self.last_packet_time
        self.nodes_state_igmp = {
            node: False for node in self.nodes_state_igmp}

    def igmp_nodes_processing(self, src, hanging_nodes):
        if self.igmp_query_number and src in hanging_nodes:
            self.nodes_state_igmp[src] = True

        if self.missing_node_detected and src in self.missing_nodes:
            for missing_node in self.missing_nodes:
                print(
                    f'Next membership report from {missing_node} is '
                    f'#{self.igmp_dict[missing_node][0]}/ '
                    f'{self.igmp_dict[missing_node][1]}'
                )
                self.next_igmp_report_found = True

    def output_results(self):
        print('\n')
        if not self.missing_node_appears_again:
            for missing_node in self.missing_nodes:
                print(f'No next responses from {missing_node}')
        print(
            f'\nLatest request is #{self.last_request_number}'
            f'/ {self.last_packet_time}/ '
            f'request ID {hex(self.request_id_src)}\n'
        )
        if not self.next_igmp_report_found:
            for missing_node in self.missing_nodes:
                print(f'No next membership reports from {missing_node}')
        print(
            f'\nLatest membership query is #{self.igmp_query_number}/ '
            f'{self.igmp_query_time}\n'
        )
        for src in ALL_NODES:
            if src in self.igmp_dict:
                print(
                    f'Latest membership report from {src} is '
                    f'#{self.igmp_dict[src][0]}/ '
                    f'{self.igmp_dict[src][1]}'
                )
            else:
                print(f'No membership reports from {src} at all')

def valid_csv(s):
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError as exc:
        msg = f"Invalid format for --csv: '{s}'. \
Format must be YYYY-MM-DD HH:MM:SS.ssssss"
        raise argparse.ArgumentTypeError(msg) from exc

def valid_nodes(s):
    if s in ALL_NODES:
        return s
    raise argparse.ArgumentTypeError(
        f'Invalid node IP. It can be one or more values from: {ALL_NODES}'
    )

def main():
    parser = argparse.ArgumentParser(
        description='Analysis of UDP and IGMP packets in PCAP files')
    parser.add_argument('pcap_file', help='path to the pcap file')
    parser.add_argument('--csv', metavar='start_of_scale',
        help='enable csv generation with specified start scale value',
        type=valid_csv, required=True
    )
    parser.add_argument('-H', '--hanging', type=valid_nodes, nargs='+',
        metavar='ip_address', help='specify the hanging nodes')
    parser.add_argument('-P', '--payload', action='store_true',
        help='convert time to payload time')
    args = parser.parse_args()
    try:
        pcap_object = PacketsProcessing()
        pcap_object.udp_dump_pcap(args.pcap_file, args.csv,
                                  args.payload, args.hanging)
        pcap_object.draw_csv_table()
        sys.exit(0)
    except FileNotFoundError as fe:
        print(fe)
    except Exception:
        print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
