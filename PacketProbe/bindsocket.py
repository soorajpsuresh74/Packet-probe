import ctypes
import threading
import socket as _socket
from abc import ABC
from time import sleep

from PacketProbe.Interfaces.pcapnetworkinterface import PCAP
from queue import Queue

"""
    BindSocket and BindSocketPCAP - Network Socket Binding and Packet Capture
    
    This module provides classes for creating network sockets and capturing raw packets
    from specified network interfaces. It supports both standard socket-based packet capture
    and PCAP-based capture for more advanced packet handling.
    
    Classes:
        BindSocket: Captures raw packets using native socket binding on Linux/Unix systems.
        BindSocketPCAP: Uses PCAP for packet capturing, providing more control and flexibility 
                        for capturing packets across different operating systems.
    
    Dependencies:
        ctypes: For handling C-style data structures and library calls.
        threading: For running capture loops in separate threads.
        socket: For creating network sockets and handling low-level network operations.
        abc: For creating abstract base classes.
        time: For sleep intervals to control capture pacing.
        queue: For thread-safe data handling with queues.

"""


class BindSocket:
    def __init__(self, interface: str):
        self.interface = interface
        self.raw_packets = Queue()
        self.is_capturing = False

    def start_capturing(self):
        self.is_capturing = True
        capture_thread = threading.Thread(target=self.capture_packets)
        capture_thread.daemon = True
        capture_thread.start()

    def capture_packets(self) -> None:
        try:
            sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.ntohs(0x0003))
            sock.bind((self.interface, 0))
        except OSError as e:
            print(f"Error binding to interface {self.interface}: {e}")
            return  # Exit gracefully if binding fails

        print(f"Listening on {self.interface}")

        while self.is_capturing:
            sleep(2)
            try:
                data = sock.recv(4096)
                self.raw_packets.put(data)
            except KeyboardInterrupt:
                print("Stopping packet capture...")
                self.is_capturing = False
                break
            except OSError as e:
                print(f"Error receiving data: {e}")
                continue

    def stop_capturing(self) -> None:
        """Stops the packet capturing."""
        self.is_capturing = False
        print("Stopped capturing packets.")

    def __str__(self):
        """Returns a string representation of the BindSocket instance."""
        return f"BindSocket(interface={self.interface}, is_capturing={self.is_capturing})"


class BindSocketPCAP(PCAP, ABC):
    def __init__(self):
        super().__init__()
        self.current_interface = super().interfaces_selection()
        self.raw_data = Queue()

    def start_packet_capture(self):
        errbuf = ctypes.create_string_buffer(self.PCAP_ERRBUF_SIZE)
        handle = self.pcap_open_live(self.current_interface.encode(), 65536, self.PCAP_OPENFLAG_PROMISCUOUS, 1000,
                                     errbuf)
        if not handle:
            print("Failed to open interface:", errbuf.value.decode())
            return

        print(f"Listening on {self.current_interface} ... Press Ctrl+C to stop.")

        def capture_loop():
            packet_header = ctypes.POINTER(self.PcapPkthdr)()
            packet_data = ctypes.POINTER(ctypes.c_ubyte)()
            try:
                while True:
                    sleep(2)
                    result = self.pcap_next_ex(handle, ctypes.byref(packet_header), ctypes.byref(packet_data))
                    if result == 1:  # Successful capture
                        raw_data = ctypes.string_at(packet_data, packet_header.contents.caplen)
                        self.raw_data.put(raw_data)
                    elif result == 0:  # Timeout
                        continue
                    elif result == -1:  # Error
                        print("Error capturing packet")
                        break
            except KeyboardInterrupt:
                print("\nStopping packet capture.")

        capture_thread = threading.Thread(target=capture_loop, daemon=True)
        capture_thread.start()

    def __str__(self):
        """Returns a string representation of the BindSocketPCAP instance."""
        return f"BindSocketPCAP(current_interface={self.current_interface})"
