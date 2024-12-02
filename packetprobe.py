import argparse

from PacketProbe.bindsocket import BindSocketPCAP, BindSocket
from PacketProbe.rawframe import RawFrame
from PacketProbe.utils.osRecognition import find_os
from PacketProbe.Interfaces.networkinterfaces import NetworkInterfaces


class PacketProbe:
    """
    PacketProbe - A network packet analysis tool

    This script provides functionality for capturing and analyzing network packets
    from a specified network interface. It uses different modules to bind to sockets
    and capture packets based on the operating system. The tool supports multiple
    packet types and can be run with specified interfaces for packet capture.

    Modules:
        argparse: For parsing command-line arguments.
        PacketProbe.bindsocket: Contains classes for binding to sockets and packet capture.
        PacketProbe.rawpacket: Provides packet processing capabilities.
        PacketProbe.utils.osRecognition: Contains utilities for recognizing the operating system.
        PacketProbe.Interfaces.networkinterfaces: Manages and lists available network interfaces.

    Classes:
        PacketProbe: Captures and processes network packets based on the OS and user specifications.

    Functions:
        main(): Entry point for parsing arguments and initializing PacketProbe.

    Usage:
        Run the script from the command line with optional arguments for interface and packet type:
            python packetprobe.py -i <interface_name> -p <packet_type>

"""

    def __init__(self, interface=None, filter_type=None):

        self.os_name = find_os()
        if self.os_name == 'nt':
            self.bind_socket_pcap = BindSocketPCAP()
            self.bind_socket_pcap.start_packet_capture()

        elif self.os_name == 'posix':
            interfaces = NetworkInterfaces()
            if not interface:
                self.interface = interfaces.interface
            else:
                self.interface = interface
            print("Current interface:", self.interface)
            self.bind_socket = BindSocket(self.interface)
            self.bind_socket.start_capturing()

        else:
            self._ni = NetworkInterfaces()
            self.interface = self._ni.interface
            print("Current interface:", self.interface)
            self.bind_socket = BindSocket(self.interface)
            self.bind_socket.start_capturing()

        self.filter_type = filter_type
        self.process_frames()

    def process_frames(self):
        # Check if the platform is Windows (nt)
        if self.os_name == 'nt' and hasattr(self, 'bind_socket_pcap'):
            # Process packets from BindSocketPCAP on Windows
            if self.bind_socket_pcap.raw_data:
                try:
                    while True:
                        frame = self.bind_socket_pcap.raw_data.get()
                        RawFrame(frame, self.filter_type)
                except KeyboardInterrupt:
                    print("\n Packet capturing stopped")
                finally:
                    pass
        elif hasattr(self, 'bind_socket'):
            # Process packets from BindSocket on non-Windows platforms
            print(self.bind_socket.raw_packets)
            if self.bind_socket.raw_packets:
                try:
                    while True:
                        frame = self.bind_socket.raw_packets.get()
                        RawFrame(frame, self.filter_type)
                except KeyboardInterrupt:
                    print("\n Packet capturing stopped")
                finally:
                    pass

