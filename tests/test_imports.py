
import pytest
import sys
import os

# Add project root to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pentrax.cli

def test_imports():
    """Verify that the main modules allow importing."""
    assert pentrax.cli.MAIN_CATEGORIES
    assert len(pentrax.cli.MAIN_CATEGORIES) > 0

def test_menu_structure():
    """Verify that menu categories are populated."""
    assert "Network Reconnaissance" in pentrax.cli.CATEGORIZED_MENUS
    assert "Web Testing & Exploitation" in pentrax.cli.CATEGORIZED_MENUS
