from PacketProbe.protocols.segment.icmp import ICMP
from PacketProbe.protocols.segment.tcp import TCP
from PacketProbe.protocols.segment.udp import UDP


class L3NetworkLayer:
    def __init__(self, protocol, network_payload):
        self.protocol = protocol
        self.network_payload = network_payload

        if protocol == 'TCP':
            tcp = TCP(network_payload)
            self.tcp_info = {
                'source_port': tcp.source_port,
                'destination_port': tcp.destination_port,
                'sequence_number': tcp.sequence_number,
                'acknowledgment_number': tcp.acknowledgment_number,
                'data_offset': tcp.data_offset,
                'flags': tcp.flags,
                'window_size': tcp.window_size,
                'check_sum': tcp.checksum,
                'urgent_pointer': tcp.urgent_pointer,
            }
            self.tcp_data = tcp.data

        elif protocol == 'UDP':
            udp = UDP(network_payload)
            self.udp_info = {
                'source_port': udp.source_port,
                'destination_port': udp.destination_port,
                'length': udp.length,
                'checksum': udp.checksum,
                'data': udp.data,
            }
            self.udp_data = udp.data

        elif protocol == 'ICMP':
            icmp = ICMP(network_payload)
            self.icmp_info = {
                'type': icmp.type,
                'code': icmp.code,
                'checksum': icmp.checksum,
                'identifier': icmp.identifier,
                'sequence_number': icmp.sequence_number,
            }

    def __str__(self):
        if self.protocol == 'TCP':
            return (
                "TCP Packet Information:\n"
                f"  Source Port: {self.tcp_info['source_port']}\n"
                f"  Destination Port: {self.tcp_info['destination_port']}\n"
                f"  Sequence Number: {self.tcp_info['sequence_number']}\n"
                f"  Acknowledgment Number: {self.tcp_info['acknowledgment_number']}\n"
                f"  Data Offset: {self.tcp_info['data_offset']}\n"
                f"  Flags: {self.tcp_info['flags']}\n"
                f"  Window Size: {self.tcp_info['window_size']}\n"
                f"  Checksum: {self.tcp_info['check_sum']}\n"
                f"  Urgent Pointer: {self.tcp_info['urgent_pointer']}\n"
                f"  Data: {self.tcp_data}"
            )

        elif self.protocol == 'UDP':
            return (
                "UDP Packet Information:\n"
                f"  Source Port: {self.udp_info['source_port']}\n"
                f"  Destination Port: {self.udp_info['destination_port']}\n"
                f"  Length: {self.udp_info['length']}\n"
                f"  Checksum: {self.udp_info['checksum']}\n"
                f"  Data: {self.udp_data}"
            )

        elif self.protocol == 'ICMP':
            return (
                "ICMP Packet Information:\n"
                f"  Type: {self.icmp_info['type']}\n"
                f"  Code: {self.icmp_info['code']}\n"
                f"  Checksum: {self.icmp_info['checksum']}\n"
                f"  Identifier: {self.icmp_info['identifier']}\n"
                f"  Sequence Number: {self.icmp_info['sequence_number']}"
            )

        else:
            return "Unknown Protocol"
