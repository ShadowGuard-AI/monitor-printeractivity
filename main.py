import psutil
import argparse
import logging
import os
import time
import platform

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Monitors print jobs and detects unusual printing patterns.")
    parser.add_argument("--interval", type=int, default=60, help="Interval in seconds to check for print jobs (default: 60).  Must be a positive integer.")
    parser.add_argument("--log_file", type=str, default="printer_monitor.log", help="Path to the log file (default: printer_monitor.log).")
    parser.add_argument("--sensitive_keywords", type=str, nargs='+', default=["confidential", "secret"], help="List of keywords that indicate a sensitive document (default: ['confidential', 'secret']).")
    parser.add_argument("--suspicious_user", type=str, nargs='+', default=[], help="List of users to monitor for suspicious activity.")
    parser.add_argument("--max_pages", type=int, default=100, help="Maximum number of pages considered normal. Trigger alerts for jobs exceeding this value. Must be a positive integer.")
    parser.add_argument("--output_format", type=str, default="console", choices=["console", "json"], help="Output format: console or json (default: console)")
    return parser.parse_args()


def is_windows():
    """
    Checks if the operating system is Windows.
    """
    return platform.system() == "Windows"


def get_print_jobs_windows():
    """
    Retrieves print jobs on Windows systems.
    """
    try:
        import win32print
        import win32api
        jobs = []
        printer_name = win32print.GetDefaultPrinter()
        handle = win32print.OpenPrinter(printer_name)
        job_info = win32print.GetPrinter(handle, 2)  # Level 2 retrieves detailed job info
        jobs_available = job_info['cJobs']

        for job_id in range(1, jobs_available + 1): # Start from 1, not 0
             try:
                job = win32print.GetJob(handle, job_id, 2)

                document_name = job['pDocument']
                user_name = job['pUserName']
                pages_printed = job['PagesPrinted']
                total_pages = job['TotalPages'] if 'TotalPages' in job else -1
                submitted_time = job['Submitted']

                jobs.append({
                    "document_name": document_name,
                    "user_name": user_name,
                    "pages_printed": pages_printed,
                    "total_pages": total_pages,
                    "submitted_time": submitted_time,
                    "printer_name": printer_name
                })
             except Exception as e:
                logging.warning(f"Error retrieving job {job_id}: {e}")
        win32print.ClosePrinter(handle)
        return jobs

    except ImportError:
        logging.error("pywin32 library is required on Windows.  Please install it: pip install pywin32")
        return []
    except Exception as e:
        logging.error(f"Error retrieving print jobs on Windows: {e}")
        return []


def get_print_jobs_linux():
    """
    Retrieves print jobs on Linux systems using the 'lpstat' command.
    """
    try:
        import subprocess
        result = subprocess.run(['lpstat', '-W', 'complete', '-o'], capture_output=True, text=True, check=True)
        output_lines = result.stdout.strip().split('\n')
        jobs = []

        for line in output_lines:
            parts = line.split()
            if len(parts) > 4:
                job_id = parts[0]
                user_name = parts[1]
                document_name = parts[2]
                pages_str = parts[-1]
                pages = int(pages_str) if pages_str.isdigit() else -1  # Handle cases where page count might be missing/invalid
                printer_name = parts[3] if len(parts) > 3 else "Unknown" # Get printer name from output

                jobs.append({
                    "document_name": document_name,
                    "user_name": user_name,
                    "pages_printed": 0,  # Not available directly from lpstat -o
                    "total_pages": pages,
                    "submitted_time": "N/A",  # Not directly available from lpstat -o
                    "printer_name": printer_name
                })

        return jobs
    except FileNotFoundError:
        logging.error("lpstat command not found. Ensure CUPS is installed and configured correctly.")
        return []
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running lpstat command: {e}")
        return []
    except Exception as e:
        logging.error(f"Error retrieving print jobs on Linux: {e}")
        return []

def get_print_jobs():
    """
    Retrieves print jobs based on the operating system.
    """
    if is_windows():
        return get_print_jobs_windows()
    else:  # Assume Linux or other Unix-like
        return get_print_jobs_linux()

def analyze_print_job(job, sensitive_keywords, suspicious_user, max_pages):
    """
    Analyzes a print job for suspicious activity.
    """
    document_name = job["document_name"]
    user_name = job["user_name"]
    total_pages = job["total_pages"]

    if any(keyword in document_name.lower() for keyword in sensitive_keywords):
        logging.warning(f"Sensitive document '{document_name}' printed by user '{user_name}' on printer '{job['printer_name']}'.")
    if user_name in suspicious_user:
        logging.warning(f"Suspicious user '{user_name}' printed document '{document_name}' on printer '{job['printer_name']}'.")
    if total_pages > max_pages:
        logging.warning(f"Unusually large print job: '{document_name}' ({total_pages} pages) printed by user '{user_name}' on printer '{job['printer_name']}'.")

def main():
    """
    Main function to monitor print jobs.
    """
    args = setup_argparse()

    # Validate input
    if args.interval <= 0:
        logging.error("Interval must be a positive integer.")
        return
    if args.max_pages <= 0:
        logging.error("Max pages must be a positive integer.")
        return

    # Configure logging to file
    file_handler = logging.FileHandler(args.log_file)
    file_handler.setLevel(logging.INFO)  # Log to file at INFO level
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logging.getLogger('').addHandler(file_handler)

    logging.info("Starting printer activity monitor...")

    try:
        while True:
            try:
                print_jobs = get_print_jobs()

                if print_jobs:
                    for job in print_jobs:
                        analyze_print_job(job, args.sensitive_keywords, args.suspicious_user, args.max_pages)
                else:
                    logging.info("No print jobs found.")
            except Exception as e:
                logging.error(f"Error during print job monitoring: {e}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        logging.info("Stopping printer activity monitor.")
    finally:
        logging.getLogger('').removeHandler(file_handler) # Remove the handler to avoid duplicate log entries.


if __name__ == "__main__":
    main()