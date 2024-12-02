__all__ = ['_timestamp', '_struct']


def _timestamp():
    import time

    return time.time()


def _struct():
    from struct import Struct

    tcp_header_unpack = Struct('!2H2LB').unpack_from
    udp_header_unpack = Struct('!4H').unpack_from

    return tcp_header_unpack, udp_header_unpack
