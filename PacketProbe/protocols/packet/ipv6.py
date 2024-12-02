import ipaddress

class IPV6:
    def __init__(self, frame_payload):
        """
        Initialize an IPV6 object with the provided raw data.

        :param frame_payload: bytes representing the raw IPv6 packet data.
        """
        if len(frame_payload) < 40:
            raise ValueError("Incomplete IPv6 header: must be at least 40 bytes.")

        # The first byte contains version and traffic class
        self.version = (frame_payload[0] >> 4) & 0x0F  # Extract version (4 bits)
        self.traffic_class = ((frame_payload[0] & 0x0F) << 4) | (frame_payload[1] >> 4)  # Extract traffic class (8 bits)

        # Flow label (20 bits)
        self.flow_label = ((frame_payload[1] & 0x0F) << 16) | (frame_payload[2] << 8) | frame_payload[3]

        # Payload length (16 bits)
        self.payload_length = (frame_payload[4] << 8) | frame_payload[5]

        # Next header and hop limit
        self.next_header = frame_payload[6]  # 8 bits for next header
        self.hop_limit = frame_payload[7]  # 8 bits for hop limit

        # Source and destination IPs are 128 bits each (16 bytes)
        self.source_ip = ipaddress.IPv6Address(frame_payload[8:24])  # Source IP (16 bytes)
        self.destination_ip = ipaddress.IPv6Address(frame_payload[24:40])  # Destination IP (16 bytes)

        # The remaining data is the payload of the IPv6 packet
        self.data = frame_payload[40:]  # Data starts after the 40-byte IPv6 header

    def to_dict(self):
        """Return a dictionary representation of the IPV6 object."""
        return {
            "version": self.version,
            "traffic_class": self.traffic_class,
            "flow_label": self.flow_label,
            "payload_length": self.payload_length,
            "next_header": self.next_header,
            "hop_limit": self.hop_limit,
            "source_ip": str(self.source_ip),
            "destination_ip": str(self.destination_ip),
            "data": self.data.hex()
        }

    def __repr__(self):
        """Return a string representation of the IPV6 object."""
        return (
            f"IPV6(version={self.version}, traffic_class={self.traffic_class}, "
            f"flow_label={self.flow_label}, payload_length={self.payload_length}, "
            f"next_header={self.next_header}, hop_limit={self.hop_limit}, "
            f"source_ip={self.source_ip}, destination_ip={self.destination_ip})"
        )
