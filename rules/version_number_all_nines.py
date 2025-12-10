"""
Version number detection rule that flags versions consisting entirely of 9s.
"""
import re


def version_number_all_nines(package: dict) -> bool:
    """
    Check if the package version number consists entirely of 9s.
    
    This detects suspicious version numbers like "9.9.9" or "9.9.9.9"
    which are sometimes used by malicious packages.
    
    Args:
        package: Dictionary containing package metadata with 'name' and 'version' keys.
    
    Returns:
        True if the package is malicious, False otherwise.
    """
    package_version = package.get("version", "")
    # Match version that consists only of 9s and dots (e.g., "9.9.9")
    return bool(re.match(r'^[9\.]+$', package_version))

