from argparse import ArgumentParser
from datetime import datetime
import sys
from traceback import print_exc

from scapy.contrib.igmpv3 import IGMPv3
from scapy.layers.inet import UDP, IP
from scapy.packet import Raw
from scapy.utils import rdpcap


class PacketsProcessing:
    MULTICAST_IP = '239.192.1.17'
    DPORT = 49297
    NODE_1 = '10.0.6.22'
    NODE_2 = '10.0.6.23'
    NODE_3 = '10.0.8.22'
    NODE_4 = '10.0.8.23'

    def __init__(self):
        self.first_round_finished = False
        self.request_id_src = None
        self.last_request_number = None
        self.last_epoch_time = None
        self.last_request_time = None
        self.igmp_dict = {}
        self.nodes_state = {self.NODE_1: False, self.NODE_2: False,
                            self.NODE_3: False, self.NODE_4: False}
        self.missing_nodes = []
        self.is_missing_found = False
        self.missing_appears_again = False
        self.is_the_next_igmp_report_found = False

    def udp_processing(self, pack, pack_number):
        if pack.haslayer(IP):
            src = pack[IP].src
            dst = pack[IP].dst
        else:
            return
        udp_packet = pack[UDP]
        dport = udp_packet.dport

        if dst == self.MULTICAST_IP and dport == self.DPORT:
            self.udp_server_processing(pack, pack_number, udp_packet)
            self.first_round_finished = True
            return
        if self.first_round_finished:
            for node in [self.NODE_1, self.NODE_2, self.NODE_3, self.NODE_4]:
                if src == node and self.first_round_finished:
                    self.udp_nodes_processing(pack_number, udp_packet, src)

    def udp_server_processing(self, pack, pack_number, udp_packet):
        if not self.first_round_finished or all(self.nodes_state.values()):
            # if the first round or a packet is answered
            if self.is_missing_found and not self.missing_appears_again:
                for missing_node in self.missing_nodes:
                    print(
                        f"The next request's packet to which "
                        f'{missing_node} responds is '
                        f'#{self.last_request_number} - '
                        f'{self.last_request_time}\n'
                    )
                self.missing_appears_again = True
        else:
        # if a packet is not answered and not the first round
            if not self.is_missing_found:
                for node, state in self.nodes_state.items():
                    if not state:
                        print(
                            f'{node} is not responding ...\n'
                            f"The first request's packet to which "
                            f"{node} didn't respond is "
                            f'#{self.last_request_number} - '
                            f'{self.last_request_time}'
                        )
                        if node in self.igmp_dict:
                            print(
                                f'The latest membership report from '
                                f'{node} is '
                                f'#{self.igmp_dict[node][0]} - '
                                f'{self.igmp_dict[node][1]}'
                            )
                        else:
                            print(
                                f'No previous membership reports from {node}\n'
                            )
                        self.missing_nodes.append(node)
                self.is_missing_found = True

        if hasattr(udp_packet, 'payload'):
            data = udp_packet.payload
            self.request_id_src = data[Raw].load[-1]
            self.last_request_number = pack_number
            pre_last_epoch_time = self.last_epoch_time
            last_epoch_time = pack.time
            self.last_epoch_time = float(last_epoch_time)
            self.last_request_time = datetime\
                .fromtimestamp(self.last_epoch_time)\
                .strftime('%Y-%m-%d %H:%M:%S.%f')
        else:
            print(f'Packet #{pack_number} has no data')

        if self.first_round_finished:
            for node in self.nodes_state:
                self.nodes_state[node] = False
            deviation = round(
                self.last_epoch_time - pre_last_epoch_time - 0.2, 6)
            if deviation > 0.1:
                print(
                    f'Missing request detected: #{pack_number} - '
                    f'{self.last_request_time}, request ID - '
                    f'{hex(self.request_id_src)}, '
                    f'deviation - {deviation}s'
                )
        else:
            print(
                f"The first request's packet is #{self.last_request_number}"
                f' - {self.last_request_time}, '
                f'request ID - {hex(self.request_id_src)}\n'
            )

    def udp_nodes_processing(self, pack_number, udp_packet, src):
        if not self.missing_appears_again:
            if hasattr(udp_packet, 'payload'):
                data = udp_packet.payload
                request_id_dest = data[Raw].load[-1]
                if request_id_dest == self.request_id_src:
                    self.nodes_state[src] = True
            else:
                print(f'Packet #{pack_number} has no data')

    def igmp_processing(self, pack, pack_number):
        if not self.missing_appears_again:
            if pack.haslayer(IP):
                src = pack[IP].src
            if src in [self.NODE_1, self.NODE_2, self.NODE_3, self.NODE_4]:
                igmp_packet_number = pack_number
                epoch_time = pack.time
                epoch_time = float(epoch_time)
                igmp_packet_time = datetime.fromtimestamp(epoch_time)\
                    .strftime('%Y-%m-%d %H:%M:%S.%f')
                self.igmp_dict[src] = [igmp_packet_number, igmp_packet_time]
            if self.is_missing_found:
                for missing_node in self.missing_nodes:
                    if src == missing_node:
                        print(
                            f'The next membership report from '
                            f'{missing_node} is '
                            f'#{self.igmp_dict[missing_node][0]} - '
                            f'{self.igmp_dict[missing_node][1]} '
                        )
                        self.is_the_next_igmp_report_found = True

    def udp_dump_pcap(self, pcap_file):
        packets = rdpcap(pcap_file)
        pack_number = 0
        for pack in packets:
            pack_number += 1
            if IGMPv3 in pack:
                self.igmp_processing(pack, pack_number)
                continue
            elif UDP in pack:
                self.udp_processing(pack, pack_number)

        if not self.is_the_next_igmp_report_found:
            for missing_node in self.missing_nodes:
                print(f'No next membership reports from {missing_node}\n')
        if not self.missing_appears_again:
            for missing_node in self.missing_nodes:
                print(
                    f"No next request's packet to which {missing_node} "
                    f'responds again\n'
                )
        print(
            f"The latest request's packet is #{self.last_request_number}"
            f' - {self.last_request_time}, '
            f'request ID - {hex(self.request_id_src)}'
        )


def main():
    parser = ArgumentParser(
        description='Analysis of UDP and IGMP packets in PCAP files')
    parser.add_argument('pcap_file', help='Path to the pcap file')
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
