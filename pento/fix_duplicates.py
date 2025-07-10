#!/usr/bin/env python3
"""
Remove duplicate BANNER and DISCLAIMER from pentrax.py

This script removes the duplicate logo and disclaimer sections from around line 3200
in the npentrax.py file to fix the issue of seeing the logo twice.
"""
import sys

FILENAME = "npentrax.py"

try:
    # Read the entire file into memory
    with open(FILENAME, 'r', encoding='utf-8') as f:
        content = f.read()

    # Find where we need to make cuts - look for the second definition
    logo_section_to_remove = 'BANNER = f"""\n{Colors.OKCYAN}\n██████╗'
    
    start_pos = content.find(logo_section_to_remove, 3000)  # Start looking after line 3000
    if start_pos == -1:
        print("Could not find the duplicate logo. It may have already been removed.")
        sys.exit(1)
        
    # Find the end marker (after the disclaimer is printed)
    end_marker = 'typewriter(DISCLAIMER, delay=0.01)\nprint()\n'
    end_pos = content.find(end_marker, start_pos) + len(end_marker)
    
    if end_pos > len(end_marker):  # Make sure we found it
        # Create new content
        new_content = content[:start_pos] + content[end_pos:]
        
        # Write back
        with open(FILENAME, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"Success! Removed duplicate logo and disclaimer in {FILENAME}")
    else:
        print("Could not find the end of the section to remove.")
        sys.exit(1)
        
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
