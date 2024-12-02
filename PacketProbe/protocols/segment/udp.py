class UDP:
    def __init__(self, transport_payload):
        # Ensure packet_payload is in byte form, and its length is sufficient for UDP header.
        self.payload_length = len(transport_payload)

        # Extract the source port (2 bytes)
        self.source_port = int.from_bytes(transport_payload[0:2], byteorder='big')

        # Extract the destination port (2 bytes)
        self.destination_port = int.from_bytes(transport_payload[2:4], byteorder='big')

        # Extract the length (2 bytes) and convert it to an integer
        self.length = int.from_bytes(transport_payload[4:6], byteorder='big')

        # Extract the checksum (2 bytes)
        self.checksum = int.from_bytes(transport_payload[6:8], byteorder='big')

        # The remaining bytes are the data
        self.data = transport_payload[8:]

    def __repr__(self):
        # Optional: Provide a string representation of the UDP object for easier inspection.
        return f"UDP(Source Port: {self.source_port}, Destination Port: {self.destination_port}, " \
               f"Length: {self.length}, Checksum: {self.checksum}, Data: {self.data})"
