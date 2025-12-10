#!/usr/bin/env python3
"""
Hackathon Package Scanner

Downloads packages from the hackathon API with caching,
runs GuardDog rules against them, and submits predictions.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

import requests
import urllib3

# Add parent directory to path to import rules module
sys.path.insert(0, str(Path(__file__).parent.parent))
from rules import ALL_RULES

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
BASE_URL = "https://98.92.8.158/h4ck4th0n"
CACHE_DIR = Path(__file__).parent.parent / "package_cache"
MANIFEST_FILE = CACHE_DIR / "manifest.json"


def load_auth_token() -> str:
    """Load AUTH_TOKEN from .env file."""
    env_path = Path(__file__).parent.parent / ".env"
    
    if not env_path.exists():
        print(f"Error: .env file not found at {env_path}")
        sys.exit(1)
    
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("AUTH_TOKEN="):
                token = line.split("=", 1)[1].strip()
                # Remove quotes if present
                if token.startswith('"') and token.endswith('"'):
                    token = token[1:-1]
                elif token.startswith("'") and token.endswith("'"):
                    token = token[1:-1]
                return token
    
    print("Error: AUTH_TOKEN not found in .env file")
    sys.exit(1)


def get_packages(token: str) -> list:
    """Fetch list of all available packages from the API."""
    response = requests.get(
        f"{BASE_URL}/packages/user",
        headers={"Authorization": f"Bearer {token}"},
        verify=False
    )
    
    if response.status_code != 200:
        print(f"Error fetching packages: {response.status_code}")
        print(response.text)
        sys.exit(1)
    
    return response.json()


def download_package(token: str, package_id: int, output_path: Path) -> bool:
    """Download a single package by ID."""
    response = requests.get(
        f"{BASE_URL}/packages/{package_id}/download",
        headers={"Authorization": f"Bearer {token}"},
        verify=False
    )
    
    if response.status_code != 200:
        print(f"  Warning: Failed to download package {package_id}: {response.status_code}")
        return False
    
    with open(output_path, "wb") as f:
        f.write(response.content)
    
    return True


def submit_predictions(token: str, submissions: list) -> dict:
    """Submit bulk predictions to the API."""
    response = requests.post(
        f"{BASE_URL}/submissions/bulk",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={"submissions": submissions},
        verify=False
    )
    
    if response.status_code != 200:
        print(f"Error submitting predictions: {response.status_code}")
        print(response.text)
        return {"error": response.text}
    
    return response.json()


def load_manifest() -> dict:
    """Load the cache manifest file."""
    if MANIFEST_FILE.exists():
        with open(MANIFEST_FILE, "r") as f:
            return json.load(f)
    return {"packages": {}, "last_updated": None}


def save_manifest(manifest: dict):
    """Save the cache manifest file."""
    manifest["last_updated"] = datetime.now().isoformat()
    with open(MANIFEST_FILE, "w") as f:
        json.dump(manifest, f, indent=2)

def is_malicious(package: dict) -> bool:
    """
    Check if the package matches any of the malicious rules.
    """
    return any(check(package) for check in ALL_RULES)


def sync_cache(token: str, force_download: bool = False) -> dict:
    """
    Sync package cache with the API.
    Returns dict mapping package_id -> package info.
    """
    # Ensure cache directory exists
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    # Load current manifest
    manifest = load_manifest()
    
    # Fetch package list from API
    print("Fetching package list from API...")
    packages = get_packages(token)
    print(f"Found {len(packages)} packages")
    
    # Determine which packages need to be downloaded
    packages_to_download = []
    for pkg in packages:
        pkg_id = str(pkg.get("id"))
        pkg_name = pkg.get("name", "unknown")
        pkg_version = pkg.get("version", "unknown")
        
        # Check if already in cache
        if not force_download and pkg_id in manifest["packages"]:
            cached = manifest["packages"][pkg_id]
            if cached.get("name") == pkg_name and cached.get("version") == pkg_version:
                continue
        
        packages_to_download.append(pkg)
    
    if packages_to_download:
        print(f"Downloading {len(packages_to_download)} new/updated packages...")
        for pkg in packages_to_download:
            pkg_id = pkg.get("id")
            pkg_name = pkg.get("name", "unknown")
            pkg_version = pkg.get("version", "unknown")
            
            # Create safe filename
            safe_name = pkg_name.replace("/", "-").replace("@", "")
            filename = f"{pkg_id}_{safe_name}_{pkg_version}.tgz"
            output_path = CACHE_DIR / filename
            
            print(f"  Downloading {pkg_name}@{pkg_version} (ID: {pkg_id})...")
            if download_package(token, pkg_id, output_path):
                manifest["packages"][str(pkg_id)] = {
                    "name": pkg_name,
                    "version": pkg_version,
                    "file": filename
                }
        
        # Save updated manifest
        save_manifest(manifest)
    else:
        print("All packages already cached.")
    
    # Return full package info for scanning
    return {str(pkg["id"]): pkg for pkg in packages}


def main():
    parser = argparse.ArgumentParser(description="Hackathon Package Scanner")
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Force re-download all packages"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't submit predictions, just print them"
    )
    args = parser.parse_args()
    
    # Load auth token
    print("Loading auth token from .env...")
    token = load_auth_token()
    print("Auth token loaded successfully")
    
    # Sync cache
    packages = sync_cache(token, force_download=args.force_download)
    
    # Generate predictions
    print("\nGenerating predictions...")
    submissions = []
    malicious_count = 0
    
    for pkg_id, pkg in packages.items():
        pkg_name = pkg.get("name", "")
        predicted_malicious = is_malicious(pkg)
        
        if predicted_malicious:
            malicious_count += 1
            pkg_version = pkg.get("version", "")
            print(f"  MALICIOUS: {pkg_name}@{pkg_version} (ID: {pkg_id})")
        
        submissions.append({
            "package_id": int(pkg_id),
            "predicted_malicious": predicted_malicious
        })
    
    print(f"\nTotal packages: {len(submissions)}")
    print(f"Predicted malicious: {malicious_count}")
    print(f"Predicted safe: {len(submissions) - malicious_count}")
    
    # Submit predictions
    if args.dry_run:
        print("\n[DRY RUN] Predictions not submitted")
        print("Submissions would be:")
        for sub in submissions[:10]:  # Show first 10
            print(f"  {sub}")
        if len(submissions) > 10:
            print(f"  ... and {len(submissions) - 10} more")
    else:
        print("\nSubmitting predictions...")
        result = submit_predictions(token, submissions)
        print(f"Result: {result}")


if __name__ == "__main__":
    main()

