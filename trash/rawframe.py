from datetime import datetime

from PacketProbe.rawsegment import L3NetworkLayer
from PacketProbe.protocols.packet.arp import ARP
from PacketProbe.protocols.packet.eapol import EAPOL
from PacketProbe.protocols.packet.ipv4 import IPV4
from PacketProbe.protocols.packet.ipv6 import IPV6
from PacketProbe.protocols.packet.lldp import LLDP
from PacketProbe.protocols.packet.multicast import MPLSMulticast
from PacketProbe.protocols.packet.ppp import PPP
from PacketProbe.protocols.packet.rarp import RARP
from PacketProbe.protocols.packet.unicast import MPLSUnicast
from PacketProbe.protocols.packet.vlan import VLAN
from PacketProbe.utils.packetType import determine_packet_type
from PacketProbe.utils.packet_info import Info
from PacketProbe.utils.segmentType import determine_protocol_type, determine_protocol_type_ipv6


class RawFrame:
    """Class for parsing and handling raw network packets."""
    __slots__ = (
        'ipv4', 'name', 'Bytes', 'Bytes_length', 'destination_mac', 'source_mac',
        'frame_type', 'payload', 'arp', 'vlan', 'rarp', 'ipv6', 'ppp', 'unicast',
        'multicast', 'lldp', 'eapol','packet_type',
    )

    def __init__(self, _bytes: bytes, filter_type=None):
        self.name = self.__class__.__name__
        self.Bytes = _bytes
        self.Bytes_length = len(_bytes)
        self.destination_mac = self._format_mac(_bytes[:6])
        self.source_mac = self._format_mac(_bytes[6:12])
        self.packet_type = determine_packet_type(_bytes)
        self.payload = _bytes[14:]

        if filter_type:
            print(f"Filtering for packet type: {filter_type}")
        if filter_type and filter_type.lower() != self.packet_type.lower():
            return  # Stop processing if the packet type doesn't match the filter

        self.handle_packets()

    def _format_mac(self, mac_bytes):
        """Formats a MAC address from bytes."""
        return ':'.join(mac_bytes.hex()[i:i + 2] for i in range(0, 12, 2))

    def handle_packets(self):
        """Handles packet processing based on its frame type."""
        if self.packet_type == '802.1Q VLAN':
            self._handle_vlan_packet()
        elif self.packet_type == 'IPv4':
            self._handle_ipv4_packet()
        elif self.packet_type == 'ARP':
            self._handle_arp_packet()
        elif self.packet_type == 'IPv6':
            self._handle_ipv6_packet()
        elif self.packet_type == 'PPP':
            self._handle_ppp_packet()
        elif self.packet_type == 'LLDP':
            self._handle_lldp_packet()
        elif self.packet_type == 'EAPOL':
            self._handle_eapol_packet()
        elif self.packet_type == 'MPLS Unicast':
            self._handle_unicast_packet()
        elif self.packet_type == 'MPLS Multicast':
            self._handle_multicast_packet()
        elif self.packet_type == 'RARP':
            self._handle_rarp_packet()

    def _handle_vlan_packet(self):
        """Handles parsing of VLAN packets."""
        print("VLAN packet captured")
        print("____________________")
        self.vlan = VLAN(self.payload)
        print(Info.get_vlan_info(self.vlan))

    def _handle_ipv4_packet(self):
        """Handles parsing of IPv4 packets and their Layer 3 details."""
        print("IPv4 packet captured")
        print("____________________")
        self.ipv4 = IPV4(self.payload)
        protocol = determine_protocol_type(self.payload)
        layer3 = L3NetworkLayer(protocol=protocol, network_payload=self.ipv4.data)
        print("\tIPv4 Info:")
        ipv4_info = Info.get_ipv4_info(self.ipv4)
        for key, value in ipv4_info.items():
            print(f"\t\t{key}: {value}")

        if protocol == 'TCP':
            print("\tTCP Segment")
            tcp_info = layer3.tcp_info
            for key, value in tcp_info.items():
                print(f"\t\t{key}: {value}")
        elif protocol == 'UDP':
            print("\tUDP Segment")
            udp_info = layer3.udp_info
            for key, value in udp_info.items():
                print(f"\t\t{key}: {value}")
        packet_data = {
            "timestamp": datetime.now().isoformat(),
            "source_mac": self.source_mac,
            "destination_mac": self.destination_mac,
            "protocol": protocol,
            **ipv4_info
        }

    def _handle_arp_packet(self):
        """Handles parsing of ARP packets."""
        print("ARP packet captured")
        print("___________________")
        self.arp = ARP(self.payload)
        print(Info.get_arp_info(self.arp))

    def _handle_ipv6_packet(self):
        """Handles parsing of IPv6 packets."""
        print("IPv6 packet captured")
        print("____________________")
        self.ipv6 = IPV6(self.payload)
        protocol = determine_protocol_type_ipv6(self.payload)
        layer3 = L3NetworkLayer(protocol=protocol, network_payload=self.ipv6.data)
        print("\tIPv6 Info:")
        ipv6_info = Info.get_ipv6_info(self.ipv6)
        for key, value in ipv6_info.items():
            print(f"\t\t{key}: {value}")

        if protocol == 'TCP':
            print("\tTCP Segment")
            tcp_info = layer3.tcp_info
            for key, value in tcp_info.items():
                print(f"\t\t{key}: {value}")
        elif protocol == 'UDP':
            print("\tUDP Segment")
            udp_info = layer3.udp_info
            for key, value in udp_info.items():
                print(f"\t\t{key}: {value}")

        packet_data = {
            "timestamp": datetime.now().isoformat(),
            "source_mac": self.source_mac,
            "destination_mac": self.destination_mac,
            "protocol": protocol,
            **ipv6_info
        }

    def _handle_ppp_packet(self):
        """Handles parsing of PPP packets."""
        print("PPP packet captured")
        print("___________________")
        self.ppp = PPP(self.payload)
        print(Info.get_ppp_info(self.ppp))

    def _handle_lldp_packet(self):
        """Handles parsing of LLDP packets."""
        print("LLDP packet captured")
        print("____________________")
        self.lldp = LLDP(self.payload)
        print(Info.get_lldp_info(self.lldp))

    def _handle_eapol_packet(self):
        """Handles parsing of EAPOL packets."""
        print("EAPOL packet captured")
        print("_____________________")
        self.eapol = EAPOL(self.payload)
        print(Info.get_eapol_info(self.eapol))

    def _handle_unicast_packet(self):
        """Handles parsing of MPLS Unicast packets."""
        print("MPLS Unicast packet captured")
        print("____________________________")
        self.unicast = MPLSUnicast(self.payload)
        print(Info.get_unicast_info(self.unicast))

    def _handle_multicast_packet(self):
        """Handles parsing of MPLS Multicast packets."""
        print("MPLS Multicast packet captured")
        print("______________________________")
        self.multicast = MPLSMulticast(self.payload)
        print(Info.get_multicast_info(self.multicast))

    def _handle_rarp_packet(self):
        """Handles parsing of RARP packets."""
        print("RARP packet captured")
        print("____________________")
        self.rarp = RARP(self.payload)
        print(Info.get_rarp_info(self.rarp))
