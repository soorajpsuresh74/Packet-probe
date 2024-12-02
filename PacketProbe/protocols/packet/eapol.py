class EAPOL:
    def __init__(self, payload):
        """
        Initialize an EAPOL object with the provided raw payload data.

        :param payload: bytes representing the raw EAPOL packet data.
        """
        self.version = payload[0]              # 1 byte for version
        self.packet_type = payload[1]          # 1 byte for packet type
        self.body_length = int.from_bytes(payload[2:4], byteorder='big')  # 2 bytes for body length
        self.body = payload[4:] if len(payload) > 4 else b''

    def packet_type_str(self):
        """Return the string representation of the packet type."""
        types = {
            0: "EAP Packet",
            1: "EAPOL-Start",
            2: "EAPOL-Logoff",
            3: "EAPOL-Key",
            4: "EAPOL-Encapsulated-ASF-Alert"
        }
        return types.get(self.packet_type, "Unknown Type")

    def __str__(self):
        """Return a string representation of the EAPOL packet."""
        eapol_info = (
            f"EAPOL Packet:\n"
            f"  Version: {self.version}\n"
            f"  Packet Type: {self.packet_type_str()} ({self.packet_type})\n"
            f"  Body Length: {self.body_length}\n"
            f"  Body: {self.body.hex() if self.body else 'N/A'}\n"
        )
        return eapol_info

