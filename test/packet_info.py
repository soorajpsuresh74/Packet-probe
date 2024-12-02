import unittest
from io import StringIO
from unittest.mock import patch
from PacketProbe.protocols.arp import ARP
from PacketProbe.protocols.ipv4 import IPV4
from PacketProbe.protocols.vlan import VLAN
from PacketProbe.protocols.eapol import EAPOL
from PacketProbe.utils.packet_info import Info

class TestPacketInfoPrinter(unittest.TestCase):
    @patch('sys.stdout', new_callable=StringIO)
    def test_print_arp_info(self, mock_stdout):
        arp_payload = bytes.fromhex(
            '0001080006040001'
            '001122334455'
            'C0A80101'
            '66778899AABB'
            'C0A80102'
        )
        arp_packet = ARP(arp_payload)
        Info.print_arp_info(arp_packet)

        expected_output = (
            "Hardware Type: 1, Protocol Type: 2048, Hardware Length: 6, Protocol Length: 4, "
            "Opcode: 1, Sender MAC: 00:11:22:33:44:55, Receiver MAC: 66:77:88:99:aa:bb, "
            "Sender IP: 192.168.1.1, Receiver IP: 192.168.1.2\n"
        )

        self.assertEqual(mock_stdout.getvalue(), expected_output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_print_ipv4_info(self, mock_stdout):
        ipv4_payload = bytes.fromhex("45000054ABCD40004011B1E6C0A80101C0A80102")
        ipv4_packet = IPV4(ipv4_payload)
        Info.print_ipv4_info(ipv4_packet)

        expected_output = (
            "Version: 4, IHL: 5, TOS: 0, Total Length: 84, Identification: 43981, "
            "Flags: 2, Fragment Offset: 0, TTL: 64, Protocol: 17, Header Checksum: 45542, "
            "Source IP: 192.168.1.1, Destination IP: 192.168.1.2\n"
        )

        self.assertEqual(mock_stdout.getvalue(), expected_output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_print_vlan_info(self, mock_stdout):
        vlan_payload = bytes.fromhex(
            '8100000000000000'
        )
        vlan_packet = VLAN(vlan_payload)
        Info.print_vlan_info(vlan_packet)

        expected_output = (
            "VLAN ID: 0, Priority: 0, CFI: 0\n"
        )

        self.assertEqual(mock_stdout.getvalue(), expected_output)

    @patch('sys.stdout', new_callable=StringIO)
    def test_print_eapol_info(self, mock_stdout):
        eapol_payload = bytes.fromhex(
            '888E00000000000100'
        )
        eapol_packet = EAPOL(eapol_payload)
        Info.print_epl_info(eapol_packet)

        expected_output = (
            'EAPOL Packet:\n'
            'Version: 136\n'
            'Packet Type: Unknown Type\n'
            'Body Length: 0\n'
            'Body: 0000000100'
        )

        self.assertEqual(mock_stdout.getvalue(), expected_output)

if __name__ == '__main__':
    unittest.main()
