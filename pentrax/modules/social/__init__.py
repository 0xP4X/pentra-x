"""PENTRA-X Social Engineering Module"""

from .phishing_gen import phishing_page_generator
from .social_tools import setoolkit, email_spoof, site_cloner

__all__ = [
    'phishing_page_generator',
    'setoolkit',
    'email_spoof',
    'site_cloner',
]
