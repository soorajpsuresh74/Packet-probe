import argparse

from packetprobe import PacketProbe


def main():
    parser = argparse.ArgumentParser(description="PacketProbe - A network packet analysis tool.")
    parser.add_argument(
        '-i', '--interface',
        type=str,
        help='The network interface to capture packets from. If not specified, the default interface is used.'
    )
    parser.add_argument(
        '-f', '--frame_type',
        type=str,
        choices=['ipv4', 'ipv6', 'arp', 'rarp', 'vlan'],
        help='The type of packet to capture. If not specified, all packet types are captured.'
    )
    args = parser.parse_args()
    PacketProbe(interface=args.interface)


if __name__ == "__main__":
    main()
