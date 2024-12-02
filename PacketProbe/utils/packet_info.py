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
from PacketProbe.protocols.segment.icmp import ICMP
from PacketProbe.protocols.segment.tcp import TCP
from PacketProbe.utils.packetDataCSV import save_packet_to_csv


class Info:
    @staticmethod
    def format_mac(mac_bytes):
        """Format MAC address from bytes to human-readable string."""
        return ':'.join(f"{byte:02x}" for byte in mac_bytes)

    @staticmethod
    def format_ip(ip_bytes):
        """Format IPv4 address from bytes to human-readable string."""
        return '.'.join(str(byte) for byte in ip_bytes)

    @staticmethod
    def format_ipv6(ipv6_bytes):
        """Format IPv6 address from bytes to human-readable string."""
        return ':'.join(
            f"{(ipv6_bytes[i] << 8) + ipv6_bytes[i + 1]:x}" for i in range(0, len(ipv6_bytes), 2)
        )

    @staticmethod
    def get_arp_info(arp):
        """Returns a dictionary with extracted ARP information."""
        if arp and isinstance(arp, ARP):
            packet_data = {
                "Hardware Type": arp.hardware_type,
                "Protocol Type": arp.protocol_type,
                "Hardware Length": arp.hardware_length,
                "Protocol Length": arp.protocol_length,
                "Opcode": arp.opcode,
                "Sender MAC": Info.format_mac(arp.sender_mac),
                "Receiver MAC": Info.format_mac(arp.receiver_mac),
                "Sender IP": Info.format_ip(arp.sender_ip),
                "Receiver IP": Info.format_ip(arp.receiver_ip)
            }
            save_packet_to_csv(packet_data, 'arp.csv')
            return packet_data

    @staticmethod
    def get_ipv4_info(ipv4):
        """Returns a dictionary with extracted IPv4 information."""
        if ipv4 and isinstance(ipv4, IPV4):
            packet_data = {
                "Version": ipv4.version,
                "IHL": ipv4.ihl,
                "TOS": ipv4.tos,
                "Total Length": ipv4.total_length,
                "Identification": ipv4.identification,
                "Flags": ipv4.flags,
                "Fragment Offset": ipv4.fragment_offset,
                "TTL": ipv4.ttl,
                "Protocol": ipv4.protocol,
                "Header Checksum": ipv4.header_checksum,
                "Source IP": Info.format_ip(ipv4.source_ip),
                "Destination IP": Info.format_ip(ipv4.destination_ip)
            }
            save_packet_to_csv(packet_data, 'ipv4.csv')
            return packet_data

    @staticmethod
    def get_rarp_info(rarp):
        """Returns a dictionary with extracted RARP information."""
        if rarp and isinstance(rarp, RARP):
            packet_data = {
                "Hardware Address Type": rarp.hardware_address_type,
                "Protocol Type": rarp.protocol_type,
                "Hardware Address Length": rarp.hardware_length,
                "Protocol Address Length": rarp.protocol_length,
                "Opcode": rarp.opcode,
                "Sender Hardware Address": Info.format_mac(rarp.sender_hardware_address),
                "Sender Protocol Address": Info.format_ip(rarp.sender_protocol_address),
                "Target Hardware Address": Info.format_mac(rarp.target_hardware_address),
                "Target Protocol Address": Info.format_ip(rarp.target_protocol_address)
            }
            save_packet_to_csv(packet_data, 'rarp.csv')
            return packet_data

    @staticmethod
    def get_ipv6_info(ipv6):
        """Returns a dictionary with extracted IPv6 information."""
        if ipv6 and isinstance(ipv6, IPV6):
            packet_data = {
                "Version": ipv6.version,
                "Traffic Class": ipv6.traffic_class,
                "Flow Label": ipv6.flow_label,
                "Payload Length": ipv6.payload_length,
                "Next Header": ipv6.next_header,
                "Hop Limit": ipv6.hop_limit,
                "Source IP": Info.format_ipv6(ipv6.source_ip),
                "Destination IP": Info.format_ipv6(ipv6.destination_ip)
            }
            save_packet_to_csv(packet_data, 'ipv6.csv')
            return packet_data

    @staticmethod
    def get_ppp_info(ppp):
        """Returns a dictionary with extracted PPP information."""
        if ppp and isinstance(ppp, PPP):
            packet_data = {
                "Flag": hex(ppp.flag),
                "Address": hex(ppp.address),
                "Control": hex(ppp.control),
                "Protocol": hex(ppp.protocol),
                "Data Length": ppp.length,
                "FCS": ppp.FCS.hex()
            }
            save_packet_to_csv(packet_data, 'ppp.csv')
            return packet_data

    @staticmethod
    def get_unicast_info(unicast):
        """Returns a dictionary with extracted MPLS Unicast information."""
        if unicast and isinstance(unicast, MPLSUnicast):
            packet_data = {
                "MPLS Unicast Packet": {
                    "Label": unicast.label,
                    "Experimental": unicast.experimental,
                    "Bottom of Stack": unicast.bottom_of_stack,
                    "TTL": unicast.ttl
                }
            }
            save_packet_to_csv(packet_data, 'unicast.csv')
            return packet_data

    @staticmethod
    def get_multicast_info(multicast):
        """Returns a dictionary with extracted MPLS Multicast information."""
        if multicast and isinstance(multicast, MPLSMulticast):
            packet_data = {
                "MPLS Multicast Packet": {
                    "Label": multicast.label,
                    "Experimental": multicast.experimental,
                    "Bottom of Stack": multicast.bottom_of_stack,
                    "TTL": multicast.ttl
                }
            }
            save_packet_to_csv(packet_data, 'multicast.csv')
            return packet_data

    @staticmethod
    def get_lldp_info(lldp):
        """Returns a dictionary with extracted LLDP information."""
        if lldp and isinstance(lldp, LLDP):
            lldp_info = {
                "Chassis ID": lldp.get_chassis_id(),
                "Port ID": lldp.get_port_id(),
                "TTL": lldp.get_ttl()
            }
            if hasattr(lldp, 'system_name'):
                lldp_info["System Name"] = lldp.system_name
            if hasattr(lldp, 'system_description'):
                lldp_info["System Description"] = lldp.system_description
            if hasattr(lldp, 'port_description'):
                lldp_info["Port Description"] = lldp.port_description

            return lldp_info

    @staticmethod
    def get_eapol_info(eapol):
        """Returns a dictionary with extracted EAPOL information."""
        if eapol and isinstance(eapol, EAPOL):
            packet_data = {
                "Version": eapol.version,
                "Packet Type": eapol.packet_type_str(),
                "Body Length": eapol.body_length,
                "Body": eapol.body.hex() if eapol.body else 'N/A'
            }
            save_packet_to_csv(packet_data, 'eapol.csv')
            return packet_data

    @staticmethod
    def get_vlan_info(vlan):
        """Returns a dictionary with extracted VLAN information."""
        if vlan and isinstance(vlan, VLAN):
            packet_data = {
                "VLAN Packet": {
                    "VLAN ID": vlan.vlan_id,
                    "Vlan de": vlan.de,
                    "Priority": vlan.priority,
                    "Ethertype": hex(vlan.ethertype),
                    "Payload": vlan.payload
                }
            }
            save_packet_to_csv(packet_data, 'vlan.csv')
            return packet_data

    @staticmethod
    def get_tcp_info(tcp):
        """Returns a dictionary with extracted TCP information."""
        if tcp and isinstance(tcp, TCP):
            packet_data = {
                "TCP Segment": {
                    "Source Port": tcp.source_port,
                    "Destination Port": tcp.destination_port,
                    "Sequence Number": tcp.sequence_number,
                    "Acknowledgment Number": tcp.acknowledgment_number,
                    "Data Offset": tcp.data_offset,
                    "Flags": tcp.flags,
                    "Window Size": tcp.window_size,
                    "Checksum": tcp.checksum,
                    "Urgent Pointer": tcp.urgent_pointer,
                    "Payload": tcp.data.hex() if tcp.data else 'N/A'
                }
            }
            save_packet_to_csv(packet_data, 'tcp.csv')
            return packet_data

    @staticmethod
    def get_icmp_info(icmp):
        if icmp and isinstance(icmp, ICMP):
            packet_data = {
                "ICMP Segment": {
                    "Type": icmp.type,
                    "Code": icmp.code,
                    "Checksum": icmp.checksum,
                    "Identifier": icmp.identifier,
                    "Sequence Number": icmp.sequence_number,
                    "data": None
                }
            }
            save_packet_to_csv(packet_data, 'icmp.csv')
            return packet_data
