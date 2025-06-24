import hashlib
import os
import json
import argparse

# Define the file to store the baseline hashes
HASH_DB_FILE = 'file_hashes.json'

def calculate_file_hash(filepath, hash_algorithm='sha256'):
    """
    Calculates the hash of a given file.

    Args:
        filepath (str): The path to the file.
        hash_algorithm (str): The hashing algorithm to use (e.g., 'md5', 'sha1', 'sha256').

    Returns:
        str: The hexadecimal representation of the file's hash, or None if the file is not found.
    """
    if not os.path.exists(filepath):
        print(f"Error: File not found - {filepath}")
        return None

    try:
        hasher = hashlib.new(hash_algorithm)
        with open(filepath, 'rb') as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {filepath}: {e}")
        return None

def save_hashes_to_db(hashes_data):
    """
    Saves the dictionary of file hashes to a JSON file.

    Args:
        hashes_data (dict): A dictionary where keys are file paths and values are their hashes.
    """
    try:
        with open(HASH_DB_FILE, 'w') as f:
            json.dump(hashes_data, f, indent=4)
        print(f"File hashes saved to {HASH_DB_FILE}")
    except Exception as e:
        print(f"Error saving hashes to database: {e}")

def load_hashes_from_db():
    """
    Loads the dictionary of file hashes from a JSON file.

    Returns:
        dict: A dictionary of file hashes, or an empty dictionary if the file doesn't exist or is invalid.
    """
    if not os.path.exists(HASH_DB_FILE):
        return {}
    try:
        with open(HASH_DB_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"Warning: {HASH_DB_FILE} is corrupted or empty. Starting with an empty database.")
        return {}
    except Exception as e:
        print(f"Error loading hashes from database: {e}")
        return {}

def create_baseline(directory):
    """
    Creates a new baseline of file hashes for all files in the specified directory.

    Args:
        directory (str): The path to the directory to monitor.
    """
    if not os.path.isdir(directory):
        print(f"Error: Directory not found - {directory}")
        return

    print(f"\n--- Creating Baseline for '{directory}' ---")
    current_hashes = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            # Use relative path for storage to make the database portable
            relative_filepath = os.path.relpath(filepath, directory)
            file_hash = calculate_file_hash(filepath)
            if file_hash:
                current_hashes[relative_filepath] = file_hash
                print(f"Hashed: {relative_filepath}")
    save_hashes_to_db(current_hashes)
    print("Baseline creation complete.")

def check_integrity(directory):
    """
    Checks the integrity of files in the specified directory against the stored baseline.

    Args:
        directory (str): The path to the directory to monitor.
    """
    if not os.path.isdir(directory):
        print(f"Error: Directory not found - {directory}")
        return

    print(f"\n--- Checking Integrity for '{directory}' ---")
    baseline_hashes = load_hashes_from_db()
    if not baseline_hashes:
        print("No baseline found. Please create a baseline first using the 'init' command.")
        return

    current_hashes = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            relative_filepath = os.path.relpath(filepath, directory)
            current_hashes[relative_filepath] = calculate_file_hash(filepath)

    modified_files = []
    new_files = []
    deleted_files = []

    # Check for modified or deleted files
    for filepath, baseline_hash in baseline_hashes.items():
        if filepath not in current_hashes:
            deleted_files.append(filepath)
        elif current_hashes[filepath] is None: # Hash calculation failed for current file
            print(f"Warning: Could not calculate hash for '{filepath}' (possibly inaccessible). Skipping integrity check for this file.")
        elif current_hashes[filepath] != baseline_hash:
            modified_files.append(filepath)

    # Check for new files
    for filepath in current_hashes:
        if filepath not in baseline_hashes:
            new_files.append(filepath)

    print("\n--- Integrity Check Results ---")
    if not modified_files and not new_files and not deleted_files:
        print("All files are intact. No changes detected.")
    else:
        if modified_files:
            print("\nModified Files:")
            for f in modified_files:
                print(f"  - {f}")
        if new_files:
            print("\nNew Files Detected:")
            for f in new_files:
                print(f"  - {f}")
        if deleted_files:
            print("\nDeleted Files Detected:")
            for f in deleted_files:
                print(f"  - {f}")
    print("Integrity check complete.")

def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Checker: Monitors changes in files using hash values."
    )
    parser.add_argument(
        "command",
        choices=['init', 'check'],
        help="Command to execute: 'init' to create a baseline, 'check' to verify integrity."
    )
    parser.add_argument(
        "directory",
        help="The directory to monitor for file changes."
    )

    args = parser.parse_args()

    if args.command == 'init':
        create_baseline(args.directory)
    elif args.command == 'check':
        check_integrity(args.directory)

if __name__ == "__main__":
    main()
