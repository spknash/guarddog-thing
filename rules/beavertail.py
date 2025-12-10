"""
Beavertail detection rule that checks for malicious URL in package dependencies.
"""
import json
import tarfile
from pathlib import Path


def beavertail_check(package_path: Path) -> bool:
    """
    Check if a package contains the malicious URL reference in its dependencies.
    
    Args:
        package_path: Path to the package .tgz file
        
    Returns:
        True if the malicious URL is found in package dependencies, False otherwise
    """
    print(f"Checking {package_path} for beavertail...")
    if not package_path.exists():
        return False
    
    malicious_url = "https://ec2-98-92-8-158.compute-1.amazonaws.com/h4ck4th0n/dependencies/config.tgz"
    
    try:
        with tarfile.open(package_path, "r:gz") as tar:
            # Iterate through all files in the archive
            for member in tar.getmembers():
                # Check if the file is named package.json (could be in any directory)
                if member.isfile() and member.name.split("/")[-1] == "package.json":
                    # Read the file contents
                    file_content = tar.extractfile(member)
                    if file_content:
                        try:
                            content = file_content.read().decode('utf-8', errors='ignore')
                            package_data = json.loads(content)
                            
                            # Check all dependency fields for the malicious URL
                            dependency_fields = [
                                "dependencies",
                                "devDependencies",
                                "peerDependencies",
                                "optionalDependencies",
                                "bundledDependencies"
                            ]
                            
                            for field in dependency_fields:
                                if field in package_data and isinstance(package_data[field], dict):
                                    # Check if any dependency value contains the malicious URL
                                    for dep_name, dep_version in package_data[field].items():
                                        if isinstance(dep_version, str) and malicious_url in dep_version:
                                            return True
                        except (json.JSONDecodeError, KeyError, TypeError):
                            # If we can't parse the JSON, continue to next file
                            continue
    except (tarfile.TarError, IOError, OSError) as e:
        # If we can't read the archive, assume it's not malicious
        # (could log this in production)
        return False
    
    return False


def beavertail(package: dict, manifest: dict = None) -> bool:
    """
    Check if a package contains the malicious URL reference in its dependencies.
    This is a rule function that works with the package dict structure.
    
    Args:
        package: Package dictionary with id, name, version
        manifest: Optional manifest dict to look up cached file paths.
                  If not provided, will attempt to load from manifest file.
        
    Returns:
        True if the malicious URL is found in package dependencies, False otherwise
    """
    from pathlib import Path
    
    # Get paths relative to rules directory
    rules_dir = Path(__file__).parent
    project_root = rules_dir.parent
    cache_dir = project_root / "package_cache"
    manifest_file = cache_dir / "manifest.json"
    
    # Load manifest if not provided
    if not manifest:
        if manifest_file.exists():
            with open(manifest_file, "r") as f:
                manifest = json.load(f)
        else:
            return False
    
    pkg_id = str(package.get("id", ""))
    if pkg_id not in manifest.get("packages", {}):
        return False
    
    cached_info = manifest["packages"][pkg_id]
    filename = cached_info.get("file")
    if not filename:
        return False
    
    package_path = cache_dir / filename
    return beavertail_check(package_path)