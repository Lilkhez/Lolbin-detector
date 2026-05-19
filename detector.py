# This is the main detection engine.
# It reads Windows event logs, applies LOLBIN rules from rules.py,
# and outputs any suspicious findings.

import os
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
from rules import LOLBIN_RULES
from colorama import Fore, Style, init
from report_maker import save_to_csv, print_summary

# Initialize colorama so colors work on all platforms including Windows
init(autoreset=True)


def extract_event_data(xml_str):
    """
    Takes a raw XML string of a single Windows event
    and extracts the fields we care about.
    Returns a dictionary of field names and values.
    """
    try:
        # Parse the XML string into a tree we can navigate
        root = ET.fromstring(xml_str)

        # Windows event XML uses a namespace prefix on every tag
        # We need to include it when searching for fields
        namespace = "{http://schemas.microsoft.com/win/2004/08/events/event}"

        # Extract the Event ID — tells us what type of event this is
        # We only want Event ID 1 which is process creation
        event_id_element = root.find(f".//{namespace}EventID")
        event_id = event_id_element.text if event_id_element is not None else ""

        # Only process Event ID 1 (Process Creation)
        # This is the Sysmon event that tells us a new process started
        if event_id != "1":
            return None

        # Extract all EventData fields into a dictionary
        # These contain the actual process details we care about
        event_data = {}
        for data in root.findall(f".//{namespace}Data"):
            name = data.get("Name")
            value = data.text if data.text else ""
            event_data[name] = value

        return event_data

    except ET.ParseError:
        # If the XML is malformed, skip this event silently
        return None


def check_lolbin(event_data):
    """
    Checks a single event against all LOLBIN rules.
    Returns a detection result if suspicious activity is found.
    Returns None if nothing suspicious is detected.
    """

    # Get the process name from the event
    # The Image field contains the full path e.g. C:\Windows\System32\regsvr32.exe
    # We use os.path.basename to extract just the filename
    # So we can match it against our rules
    image = event_data.get("Image", "")

    # os.path.basename fails on Windows paths when running on Mac/Linux
    # because it expects forward slashes not backslashes
    # So we split on backslash manually and take the last part
    process_name = image.replace("\\", "/")
    process_name = os.path.basename(process_name).lower()
    command_line = event_data.get("CommandLine", "").lower()

    # Check if this process name matches any of our LOLBIN rules
    if process_name not in LOLBIN_RULES:
        return None

    # Get the rules for this specific LOLBIN
    rule = LOLBIN_RULES[process_name]
    matched_patterns = []

    # Check each suspicious pattern against the command line
    for pattern in rule["suspicious_patterns"]:
        if pattern.lower() in command_line:
            matched_patterns.append(pattern)

    # Special case for regsvr32 — /s alone is not suspicious
    # It only becomes suspicious combined with other patterns
    if process_name == "regsvr32.exe":
        if matched_patterns == ["/s"]:
            return None

    # If we found at least one suspicious pattern, return a detection
    if matched_patterns:
        return {
            "process": process_name,
            "command_line": event_data.get("CommandLine", ""),
            "parent_process": os.path.basename(
                event_data.get("ParentImage", "Unknown")
            ),
            "user": event_data.get("User", "Unknown"),
            "technique_id": rule["technique_id"],
            "technique_name": rule["technique_name"],
            "severity": rule["severity"],
            "matched_patterns": matched_patterns
        }

    return None


def scan_log_file(filepath):
    """
    Opens a single .evtx file and scans every event in it.
    Loops through chunks and records using the updated python-evtx API.
    Returns a list of all detections found.
    """
    detections = []

    print(Fore.GREEN + f"\n[*] Scanning: {os.path.basename(filepath)}")

    try:
        with Evtx(filepath) as log:
            # The .evtx file is divided into chunks
            # Each chunk contains multiple individual event records
            # We loop through chunks first, then records inside each chunk
            for chunk in log.chunks():
                for record in chunk.records():
                    try:
                        # Convert the binary record into an XML string
                        # This is what we can actually parse and read
                        xml_str = record.xml()

                        # Parse the XML and extract the fields we care about
                        # Returns None if the event is not ID 1 or XML is malformed
                        event_data = extract_event_data(xml_str)

                        # Skip anything that is not a process creation event
                        if event_data is None:
                            continue

                        # Check the event against all LOLBIN rules
                        detection = check_lolbin(event_data)

                        # If a detection was found, record it and print an alert
                        if detection:
                            detection["source_file"] = os.path.basename(filepath)
                            detections.append(detection)
                            print_alert(detection)

                    except Exception:
                        # If a single record is corrupt or unreadable
                        # skip it silently and move to the next one
                        # We never want one bad record to kill the entire scan
                        continue

    except Exception as e:
        print(Fore.RED + f"[!] Error reading {filepath}: {e}")

    # Always print how many detections this file produced
    print(Fore.GREEN + f"[*] Detections in this file: {len(detections)}")

    return detections


def print_alert(detection):
    """
    Prints a color coded alert to the terminal.
    Red for High severity, Yellow for Medium.
    """
    color = Fore.RED if detection["severity"] == "High" else Fore.YELLOW

    print(color + f"""
    ╔══════════════════════════════════════════════════════╗
    ║  🚨 LOLBIN DETECTED                                  
    ║  Severity       : {detection['severity']}
    ║  Process        : {detection['process']}
    ║  Technique      : {detection['technique_id']} - {detection['technique_name']}
    ║  Matched        : {', '.join(detection['matched_patterns'])}
    ║  Command Line   : {detection['command_line'][:80]}
    ║  Parent Process : {detection['parent_process']}
    ║  User           : {detection['user']}
    ╚══════════════════════════════════════════════════════╝
    """)


def main():
    """
    Entry point. Scans all .evtx files in the logs/ folder.
    """
    logs_folder = "logs"
    all_detections = []

    # Check the logs folder exists
    if not os.path.exists(logs_folder):
        print(Fore.RED + "[!] logs/ folder not found. Please create it and add .evtx files.")
        return

    # Get all .evtx files in the logs folder
    evtx_files = [
        f for f in os.listdir(logs_folder)
        if f.endswith(".evtx")
    ]

    if not evtx_files:
        print(Fore.RED + "[!] No .evtx files found in logs/ folder.")
        return

    print(Fore.GREEN + f"[*] Found {len(evtx_files)} log file(s) to scan")

    # Scan each file
    for filename in evtx_files:
        filepath = os.path.join(logs_folder, filename)
        detections = scan_log_file(filepath)
        all_detections.extend(detections)

    # Print summary and save report
    print(Fore.GREEN + f"\n[*] Scan complete.")
    print(Fore.GREEN + f"[*] Total detections: {len(all_detections)}")

    if all_detections:
        print_summary(all_detections)
        save_to_csv(all_detections)

    return all_detections


if __name__ == "__main__":
    main()

