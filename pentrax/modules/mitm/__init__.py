"""PENTRA-X MITM & Network Attacks Module"""

from .arp_spoof import arp_spoof, dns_spoof

__all__ = [
    'arp_spoof',
    'dns_spoof',
]
