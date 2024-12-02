class IPV4:
    """
      A class for parsing and representing an IPv4 packet header.

      This class extracts fields from an IPv4 header based on the provided
      packet payload. It provides methods to access various attributes of the
      IPv4 header and represents the information in a readable format.

      Attributes:
      ----------
      version : int
          The version of the IP protocol (typically 4 for IPv4).
      ihl : int
          Internet Header Length, indicating the length of the header in 32-bit words.
      tos : int
          Type of Service, used to specify the priority of the packet.
      total_length : int
          The total length of the IPv4 packet, including header and data.
      identification : int
          An identifier for the packet, used for fragment reassembly.
      flags : int
          Flags that control or identify fragments.
      fragment_offset : int
          The offset of this fragment in the original data.
      ttl : int
          Time to Live, indicating the maximum number of hops the packet can take.
      protocol : int
          The protocol used in the data portion of the IPv4 packet (e.g., TCP, UDP).
      header_checksum : int
          A checksum for the header to detect errors.
      source_ip : bytes
          The source IP address of the packet.
      destination_ip : bytes
          The destination IP address of the packet.
      payload_length : int
          The length of the payload (the entire packet payload).

      Parameters:
      ----------
      frame_payload : bytes
          The raw bytes representing the entire packet containing the IPv4 packet.

      Raises:
      ------
      ValueError
          If the provided packet payload is shorter than the minimum length required
          for an IPv4 header (20 bytes).

      Methods:
      -------
      __str__():
          Returns a string representation of the parsed IPv4 header fields.
    """
    __slots__ = (
        'version',
        'ihl',
        'tos',
        'total_length',
        'identification',
        'flags',
        'fragment_offset',
        'ttl',
        'protocol',
        'header_checksum',
        'source_ip',
        'destination_ip',
        'payload_length',
        'data'
    )

    def __init__(self, frame_payload):
        self.payload_length = len(frame_payload)

        # Check if the payload length is sufficient for an IPv4 header
        if self.payload_length < 20:
            raise ValueError("Payload does not have the minimum required length for an IPv4 header.")

        # Parse the IPv4 header
        self.version = (frame_payload[0] >> 4) & 0x0F  # Extracting the version (first 4 bits)
        self.ihl = frame_payload[0] & 0x0F  # Extracting the Internet Header Length (last 4 bits)
        self.tos = frame_payload[1]  # Type of Service
        self.total_length = int.from_bytes(frame_payload[2:4], 'big')  # Total Length
        self.identification = int.from_bytes(frame_payload[4:6], 'big')  # Identification
        self.flags = (frame_payload[6] >> 5) & 0x07  # Flags (first 3 bits)
        self.fragment_offset = ((frame_payload[6] & 0x1F) << 8) | frame_payload[7]  # Fragment Offset
        self.ttl = frame_payload[8]  # Time to Live
        self.protocol = frame_payload[9]  # Protocol
        self.header_checksum = int.from_bytes(frame_payload[10:12], 'big')  # Header Checksum
        self.source_ip = frame_payload[12:16]  # Source IP (bytes)
        self.destination_ip = frame_payload[16:20]  # Destination IP (bytes)

        header_length = self.ihl * 4
        self.data = frame_payload[header_length:] if self.version == 4 else None

    def __str__(self) -> str:
        source_ip = ".".join(str(byte) for byte in self.source_ip)
        destination_ip = ".".join(str(byte) for byte in self.destination_ip)
        return (f"IPV4("
                f"version={self.version}, "
                f"ihl={self.ihl}, "
                f"tos={self.tos}, "
                f"total_length={self.total_length}, "
                f"identification={self.identification}, "
                f"flags={self.flags}, "
                f"fragment_offset={self.fragment_offset}, "
                f"ttl={self.ttl}, "
                f"protocol={self.protocol}, "
                f"header_checksum={self.header_checksum}, "
                f"source_ip={source_ip}, "
                f"destination_ip={destination_ip}),"
                f"data_length={len(self.data) if self.data else 0})")


