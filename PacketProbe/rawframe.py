import json
import datetime

from PacketProbe.handlepackets import PacketHandler
from PacketProbe.utils.packetType import determine_packet_type


def save_data(data):
    """Saves packet data to a JSON file, handling serialization."""
    try:
        def convert_bytes(obj):
            """Converts bytes to a hex string for JSON serialization."""
            if isinstance(obj, bytes):
                return obj.hex()
            raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

        with open('packet_data.json', 'a') as file:
            json.dump(data, file, default=convert_bytes)
            file.write('\n')
    except IOError as e:
        print(f"Failed to save packet data: {e}")


class RawFrame:
    def __init__(self, _bytes: bytes, filter_type=None):
        self.name = self.__class__.__name__
        self.bytes = _bytes
        self.bytes_length = len(_bytes)
        self.destination_mac = self.format_mac(_bytes[:6])
        self.source_mac = self.format_mac(_bytes[6:12])
        self.packet_type = determine_packet_type(_bytes)
        self.payload = _bytes[14:]

        # Timestamp for data collection
        self.time_stamps = datetime.datetime.now().isoformat()

        self.packet_handler = PacketHandler()
        packet_data = self.handle_packets()

        if filter_type:
            print(f"Filtering for packet type: {filter_type}")

        if filter_type and filter_type.lower() != self.filter_type.lower():
            return  # Stop processing if the packet type doesn't match the filter

        if packet_data:
            packet_data.update({
                'time_stamps': self.time_stamps,
                'bytes_length': self.bytes_length,
                'source_mac': self.source_mac,
                'destination_mac': self.destination_mac
            })
            save_data(packet_data)

    def format_mac(self, mac_bytes):
        """Formats a MAC address in a human-readable format."""
        return ':'.join(f'{b:02x}' for b in mac_bytes)

    def handle_packets(self):
        """Handles packet processing based on its frame type."""
        if self.packet_type == 'IPv4':
            data = self.packet_handler._handle_ipv4_packet(self.payload)
            return data
        elif self.packet_type == 'IPv6':
            data = self.packet_handler._handle_ipv6_packet(self.payload)
            return data
        elif self.packet_type == 'ARP':
            data = self.packet_handler._handle_arp_packet(self.payload)
            return data
        return None
