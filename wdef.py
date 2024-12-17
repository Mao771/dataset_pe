import os
import time
import subprocess
import json
from sklearn.metrics import classification_report
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration
WATCH_DIR = r"C:\Users\max\Downloads\dataset_pe-main\dataset_pe-main\tmp"  # Directory to monitor
LOG_FILE = r"scan_results.log"  # Path to log file
DEFENDER_CMD = r"c:\Program Files\Windows Defender\MpCmdRun.exe"  # Path to MpCmdRun.exe

# Metrics tracking
true_labels = []
predicted_labels = []
processing_times = []

# Helper function to log messages
def log_message(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    print(message)

# Function to scan file with Windows Defender
def scan_file_with_defender(file_path):
    try:
        command = [DEFENDER_CMD, "-Scan", "-ScanType", "3", "-File", file_path]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if "found" in result.stdout.lower():
            return "virus"
        elif "no threats" in result.stdout.lower():
            return "clean"
        else:
            return "unknown"
    except Exception as e:
        log_message(f"Error scanning file {file_path}: {e}")
        return "unknown"

# Function to process a file
def process_file(file_path):
    global true_labels, predicted_labels, processing_times

    try:
        filename = os.path.basename(file_path)
        log_message(f"Processing file: {filename}")

        # Extract the expected result from the filename
        expected_result = filename.split("_")[-1].replace(".txt", "").strip()

        # Start timing
        start_time = time.time()

        # Scan file with Windows Defender
        detected_result = scan_file_with_defender(file_path)

        # End timing
        end_time = time.time()
        processing_time = end_time - start_time
        processing_times.append(processing_time)

        # Log results
        log_message(f"File: {filename}, Expected: {expected_result}, Detected: {detected_result}, Time: {processing_time:.2f}s")

        # Append results for metrics calculation
        true_labels.append(expected_result)
        predicted_labels.append(detected_result)

    except Exception as e:
        log_message(f"Error processing file {file_path}: {e}")

# Watchdog event handler
class FileEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(".txt"):
            process_file(event.src_path)

# Main function
def main():
    # Ensure the log file exists
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            f.write("Windows Defender Scan Analysis Log\n")

    log_message("Starting directory monitor...")
    event_handler = FileEventHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
            if true_labels and predicted_labels:
                # Calculate and log metrics
                metrics = classification_report(true_labels, predicted_labels, output_dict=True)
                avg_time = sum(processing_times) / len(processing_times) if processing_times else 0

                log_message(f"Metrics:\n{json.dumps(metrics, indent=4)}")
                log_message(f"Average Request Time: {avg_time:.2f}s")
    except KeyboardInterrupt:
        observer.stop()
        log_message("Stopping directory monitor...")
    observer.join()

if __name__ == "__main__":
    main()
