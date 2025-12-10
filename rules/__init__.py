"""
Custom malicious package detection rules.

This module automatically discovers and loads all rule functions
from Python files in this directory.

Convention: Each rule file should have a function with the same name as the file.
Example: typosquat_reatc.py should contain a function named typosquat_reatc()
"""

import importlib
from pathlib import Path

# Automatically discover and load all rules
ALL_RULES = []
_rules_dir = Path(__file__).parent

# Iterate through all Python files in the rules directory
for rule_file in _rules_dir.glob("*.py"):
    # Skip __init__.py and private files
    if rule_file.name.startswith("_"):
        continue
    
    # Import the module and get the function with the same name
    module_name = rule_file.stem
    try:
        module = importlib.import_module(f".{module_name}", package=__package__)
        
        # Convention: function name matches file name
        if hasattr(module, module_name):
            rule_func = getattr(module, module_name)
            ALL_RULES.append(rule_func)
        else:
            print(f"Warning: {rule_file.name} does not contain a function named '{module_name}'")
    except Exception as e:
        print(f"Warning: Failed to load rule from {rule_file.name}: {e}")

__all__ = ['ALL_RULES']

