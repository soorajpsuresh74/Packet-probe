from PacketProbe.protocols.packet.arp import ARP
from PacketProbe.protocols.packet.ipv4 import IPV4
from PacketProbe.protocols.packet.ipv6 import IPV6
from PacketProbe.rawsegment import L3NetworkLayer
from PacketProbe.utils.packet_info import Info
from PacketProbe.utils.segmentType import determine_protocol_type


class PacketHandler:
    def _handle_ipv4_packet(self, payload: bytes):
        """Handles parsing of IPv4 packets and their Layer 3 details."""
        print("IPv4 packet captured")
        ipv4 = IPV4(payload)
        protocol = determine_protocol_type(payload)
        layer3 = L3NetworkLayer(protocol=protocol, network_payload=ipv4.data)

        print("\tIPv4 Info:")
        ipv4_info = Info.get_ipv4_info(ipv4)
        for key, value in ipv4_info.items():
            print(f"\t\t{key}: {value}")

        tcp_info = {}
        udp_info = {}

        if protocol == 'TCP':
            print("\tTCP Segment")
            tcp_info = layer3.tcp_info or {}
            for key, value in tcp_info.items():
                print(f"\t\t{key}: {value}")
        elif protocol == 'UDP':
            print("\tUDP Segment")
            udp_info = layer3.udp_info or {}
            for key, value in udp_info.items():
                print(f"\t\t{key}: {value}")

        # Merge the packet data appropriately
        packet_data = {
            "protocol": protocol,
            **ipv4_info,
            **tcp_info,
            **udp_info
        }

        return packet_data

    def _handle_ipv6_packet(self, payload: bytes):
        """Handles parsing of IPv6 packets and their Layer 3 details."""
        print("IPv6 packet captured")
        tcp_info = {}
        udp_info = {}
        ipv6 = IPV6(payload)
        protocol = determine_protocol_type(payload)
        layer3 = L3NetworkLayer(protocol=protocol, network_payload=ipv6.data)

        print("\tIPv6 Info:")
        ipv6_info = Info.get_ipv6_info(ipv6)
        for key, value in ipv6_info.items():
            print(f"\t\t{key}: {value}")

        if protocol == 'TCP':
            print("\tTCP Segment")
            tcp_info = layer3.tcp_info or {}
            for key, value in tcp_info.items():
                print(f"\t\t{key}: {value}")

        elif protocol == 'UDP':
            print("\tUDP Segment")
            udp_info = layer3.udp_info or {}
            for key, value in udp_info.items():
                print(f"\t\t{key}: {value}")

        # Merge the packet data appropriately
        packet_data = {
            "protocol": protocol,
            **ipv6_info,
            **tcp_info,
            **udp_info
        }

        return packet_data

    def _handle_arp_packet(self, payload: bytes):
        print("ARP packet captured")
        print("___________________")
        self.arp = ARP(payload)
        data = Info.get_arp_info(self.arp)
        return data
