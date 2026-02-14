import os
import hashlib
import shutil
import argparse
from datetime import datetime


# ---------------------------
# Calculate SHA-256 Hash
# ---------------------------
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[ERROR] Could not read file: {file_path} | {e}")
        return None


# ---------------------------
# Load Malware Signatures
# ---------------------------
def load_signatures(signature_file):
    try:
        with open(signature_file, "r") as f:
            return set(line.strip() for line in f)
    except Exception as e:
        print(f"[ERROR] Could not load signatures file: {e}")
        return set()


# ---------------------------
# Scan Directory
# ---------------------------
def scan_directory(directory, signatures):
    infected_files = []

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_hash(file_path)

            if file_hash in signatures:
                print(f"[MALICIOUS] {file_path}")
                infected_files.append(file_path)
            else:
                print(f"[CLEAN] {file_path}")

    return infected_files


# ---------------------------
# Quarantine Files
# ---------------------------
def quarantine_files(files, quarantine_folder):
    if not os.path.exists(quarantine_folder):
        os.makedirs(quarantine_folder)

    for file in files:
        try:
            filename = os.path.basename(file)
            destination = os.path.join(quarantine_folder, filename)
            shutil.move(file, destination)
            print(f"[QUARANTINED] {filename}")
        except Exception as e:
            print(f"[ERROR] Could not quarantine {file}: {e}")


# ---------------------------
# Logging Function
# ---------------------------
def log_results(infected_files):
    with open("scan_log.txt", "a") as log:
        log.write(f"\nScan Time: {datetime.now()}\n")
        if infected_files:
            for file in infected_files:
                log.write(f"Malicious: {file}\n")
        else:
            log.write("No malicious files detected.\n")


# ---------------------------
# Main Function
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="Basic Antivirus Signature Scanner")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--signatures", default="malware_signatures.txt",
                        help="Path to malware signatures file")
    parser.add_argument("--quarantine", default="quarantine",
                        help="Quarantine folder path")

    args = parser.parse_args()

    print("\n=== Basic Antivirus Simulation Started ===\n")

    signatures = load_signatures(args.signatures)
    infected = scan_directory(args.directory, signatures)

    if infected:
        quarantine_files(infected, args.quarantine)
    else:
        print("\nNo malicious files found.")

    log_results(infected)

    print("\n=== Scan Completed ===\n")


if __name__ == "__main__":
    main()
