Basic Antivirus Simulation (Signature-Based Scanner)

Overview:
This project simulates a basic antivirus engine using signature-based detection.
It scans files in a directory, calculates SHA-256 hashes, and compares them against a database of known malware signatures.

Features:
SHA-256 file hashing
Directory scanning
Malware signature comparison
Automatic quarantine of infected files
Logging system

How It Works:
Reads files from a target directory
Generates SHA-256 hash
Compares hash with known malicious signatures
Flags and quarantines matching files

Usage:
python antivirus_simulator.py <directory_to_scan>


Example:
python antivirus_simulator.py test_folder


Optional parameters:
--signatures malware_signatures.txt
--quarantine quarantine_folder

Educational Purpose:
This project demonstrates how signature-based antivirus engines operate.
It is intended for ethical and educational use only.
