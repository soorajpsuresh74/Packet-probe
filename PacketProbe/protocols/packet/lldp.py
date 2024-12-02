class LLDP:
    def __init__(self, payload):
        """
        Initialize an LLDP object with the provided raw payload data.

        :param payload: bytes representing the raw LLDP packet data.
        """
        self.payload = payload
        self.tlvs = self.parse_tlvs(payload)

    def parse_tlvs(self, payload):
        """Parse TLVs from the payload."""
        tlvs = []
        index = 0

        while index < len(payload):
            if len(payload) - index < 2:
                break  # Ensure at least 2 bytes for type and length

            # The first two bytes represent Type and Length
            tlv_header = int.from_bytes(payload[index:index + 2], byteorder='big')
            tlv_type = (tlv_header >> 9) & 0x7F  # 7 bits for Type
            tlv_length = tlv_header & 0x1FF  # 9 bits for Length
            index += 2

            # Get the TLV value
            if len(payload) - index < tlv_length:
                break  # Ensure the payload has the expected TLV length

            tlv_value = payload[index:index + tlv_length]
            tlvs.append({'type': tlv_type, 'length': tlv_length, 'value': tlv_value})
            index += tlv_length

            # End of LLDPDU TLV is type 0, break if we reach it
            if tlv_type == 0:
                break

        return tlvs

    def get_chassis_id(self):
        """Extract the Chassis ID from the TLVs."""
        for tlv in self.tlvs:
            if tlv['type'] == 1:  # Chassis ID TLV has type 1
                return tlv['value']
        return None

    def get_port_id(self):
        """Extract the Port ID from the TLVs."""
        for tlv in self.tlvs:
            if tlv['type'] == 2:  # Port ID TLV has type 2
                return tlv['value']
        return None

    def get_ttl(self):
        """Extract the TTL from the TLVs."""
        for tlv in self.tlvs:
            if tlv['type'] == 3:  # TTL TLV has type 3
                return int.from_bytes(tlv['value'], byteorder='big')
        return None

    def __str__(self):
        """Return a string representation of the LLDP packet."""
        chassis_id = self.get_chassis_id()
        port_id = self.get_port_id()
        ttl = self.get_ttl()

        lldp_info = (
            f"LLDP Packet:\n"
            f"  Chassis ID: {chassis_id.hex() if chassis_id else 'N/A'}\n"
            f"  Port ID: {port_id.hex() if port_id else 'N/A'}\n"
            f"  TTL: {ttl if ttl is not None else 'N/A'}\n"
        )
        return lldp_info

