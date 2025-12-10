"""
Typosquatting detection rule for 'reatc' (typosquat of 'react').
"""


def typosquat_reatc(package: dict) -> bool:
    """
    Simple rule: flag packages named "reatc" (typosquat of react).
    
    Args:
        package: Dictionary containing package metadata with 'name' and 'version' keys.
    
    Returns:
        True if the package is malicious, False otherwise.
    """
    package_name = package.get("name", "")
    return package_name.lower() == "reatc"

