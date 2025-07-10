#!/usr/bin/env python3
"""
Utility to remove duplicate ASCII logos in npentrax.py
"""
import re

# Read the input file
file_path = "npentrax.py"
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Find and remove the second BANNER and DISCLAIMER definitions (around line 3200)
banner_pattern = r'def animated_print\(text, delay=0\.03\):\s+for line in text\.splitlines\(\):\s+print\(line\)\s+time\.sleep\(delay\)\s+BANNER = f"""[\s\S]+?"""\s+DISCLAIMER = f"""[\s\S]+?"""\s+# Show logo and disclaimer for all users\s+animated_print\(BANNER, delay=0\.03\)\s+print\(\)\s+typewriter\(DISCLAIMER, delay=0\.01\)\s+print\(\)'

# Keep only the first occurrence and replace the duplicate with just the function
fixed_content = re.sub(banner_pattern, 'def animated_print(text, delay=0.03):\n    for line in text.splitlines():\n        print(line)\n        time.sleep(delay)', content, count=1)

# Write the fixed content
with open(file_path + '.fixed', 'w', encoding='utf-8') as f:
    f.write(fixed_content)

print(f"Fixed file saved as {file_path}.fixed")
print("Review the changes and if they look correct, rename the fixed file to replace the original.")
