# Handles saving detection results to a CSV report
# and printing a clean summary to the terminal.

import csv
import os
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


def save_to_csv(detections, output_folder="output"):
    """
    Saves all detections to a timestamped CSV file.
    Each detection becomes one row in the file.
    Returns the path of the saved file.
    """

    # Create the output folder if it doesn't exist yet
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Build a timestamped filename so every scan
    # produces a unique file and nothing gets overwritten
    # Format: lolbin_detections_2024-01-15_14-30-00.csv
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"lolbin_detections_{timestamp}.csv"
    filepath = os.path.join(output_folder, filename)

    # Define the column headers for the CSV
    # These match exactly the keys in our detection dictionary
    fieldnames = [
        "severity",
        "process",
        "technique_id",
        "technique_name",
        "matched_patterns",
        "command_line",
        "parent_process",
        "user",
        "source_file"
    ]

    # Write all detections to the CSV file
    # newline="" is required on Windows to prevent
    # blank rows appearing between each entry
    with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write the header row first
        writer.writeheader()

        # Write each detection as a row
        for detection in detections:
            # matched_patterns is a list — convert it to a
            # comma separated string so it fits in one CSV cell
            row = detection.copy()
            row["matched_patterns"] = ", ".join(detection["matched_patterns"])
            writer.writerow(row)

    print(Fore.GREEN + f"\n[*] Report saved to: {filepath}")
    return filepath


def print_summary(detections):
    """
    Prints a clean summary table to the terminal
    showing totals broken down by severity and technique.
    This gives a quick overview without reading the full CSV.
    """

    if not detections:
        print(Fore.YELLOW + "\n[*] No detections to summarise.")
        return

    # Count detections by severity
    high = [d for d in detections if d["severity"] == "High"]
    medium = [d for d in detections if d["severity"] == "Medium"]

    # Count detections by technique
    technique_counts = {}
    for d in detections:
        technique = f"{d['technique_id']} - {d['technique_name']}"
        technique_counts[technique] = technique_counts.get(technique, 0) + 1

    # Count detections by source file
    file_counts = {}
    for d in detections:
        source = d["source_file"]
        file_counts[source] = file_counts.get(source, 0) + 1

    # Print the summary
    print(Fore.CYAN + """
╔══════════════════════════════════════════════════════════════╗
║                    DETECTION SUMMARY                         
╠══════════════════════════════════════════════════════════════╣""")

    print(Fore.CYAN + f"║  Total Detections : {len(detections)}")
    print(Fore.RED   + f"║  High Severity    : {len(high)}")
    print(Fore.YELLOW + f"║  Medium Severity  : {len(medium)}")

    print(Fore.CYAN + "║")
    print(Fore.CYAN + "║  BY TECHNIQUE:")
    for technique, count in sorted(technique_counts.items()):
        print(Fore.CYAN + f"║    {count}x  {technique}")

    print(Fore.CYAN + "║")
    print(Fore.CYAN + "║  BY SOURCE FILE:")
    for source_file, count in sorted(file_counts.items()):
        print(Fore.CYAN + f"║    {count}x  {source_file}")

    print(Fore.CYAN + "╚══════════════════════════════════════════════════════════════╝")