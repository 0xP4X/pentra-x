"""PENTRA-X Password Attacks Module"""

from .hash_cracker import crack_hash
from .hydra_attack import hydra_attack

__all__ = [
    'crack_hash',
    'hydra_attack',
]
