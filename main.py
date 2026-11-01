import argparse
import logging
import os
import sys
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
        jobs = []
        # Only the default printer is opened. Jobs sent to any other
        # printer on the machine are never enumerated, however
        # sensitive the document or however large the job, and the
        # log gives no sign that the coverage is one queue deep.
        printer_name = win32print.GetDefaultPrinter()
        handle = win32print.OpenPrinter(printer_name)
        job_info = win32print.GetPrinter(handle, 2)  # Level 2 retrieves detailed job info
        jobs_available = job_info['cJobs']

        if jobs_available:
            # EnumJobs sees the live queue. A job that prints and leaves
            # the queue between my polls is never seen on this path,
            # while the Linux path below asks lpstat for completed jobs
            # and sees history. The same monitor therefore has a memory
            # on one platform and none on the other.
            for job in win32print.EnumJobs(handle, 0, jobs_available, 2):
                try:
                    jobs.append({
                        "job_id": job['JobId'] if 'JobId' in job else None,
                        "document_name": job['pDocument'],
                        "user_name": job['pUserName'],
                        "pages_printed": job['PagesPrinted'],
                        "total_pages": job['TotalPages'] if 'TotalPages' in job else -1,
                        "submitted_time": job['Submitted'],
                        "printer_name": printer_name
                    })
                except Exception as e:
                    logging.warning(f"Error reading enumerated print job: {e}")
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
            if len(parts) >= 4:
                # lpstat -o provides only the queue and job id, the user, the
                # job size in bytes, and the date. It provides no document
                # name and no page count, so none is recorded on this path.
                job_id = parts[0]
                user_name = parts[1]
                size_str = parts[2]
                size_bytes = int(size_str) if size_str.isdigit() else -1
                printer_name = job_id.rsplit('-', 1)[0] if '-' in job_id else job_id
                submitted_time = ' '.join(parts[3:])

                jobs.append({
                    "job_id": job_id,
                    "document_name": None,
                    "user_name": user_name,
                    "pages_printed": 0,
                    "total_pages": None,
                    "size_bytes": size_bytes,
                    "submitted_time": submitted_time,
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
    document_name = job.get("document_name")
    user_name = job["user_name"]
    total_pages = job.get("total_pages")
    job_label = document_name if document_name else f"job {job.get('job_id')}"

    # The sensitive keyword check needs a document name, which only the
    # Windows path provides; the Linux path has no document name to check.
    if document_name and any(keyword.lower() in document_name.lower() for keyword in sensitive_keywords):
        logging.warning(f"Sensitive document '{document_name}' printed by user '{user_name}' on printer '{job['printer_name']}'.")
    # The user comparison is exact, case included, and the Linux
    # job's user comes from splitting the lpstat line on
    # whitespace, so it is whatever token sat in that column.
    # A name written differently in the suspicious list, in
    # case or in form, never matches.
    if user_name in suspicious_user:
        logging.warning(f"Suspicious user '{user_name}' printed '{job_label}' on printer '{job['printer_name']}'.")
    if total_pages is not None and total_pages > max_pages:
        logging.warning(f"Unusually large print job: '{job_label}' ({total_pages} pages) printed by user '{user_name}' on printer '{job['printer_name']}'.")

def main():
    """
    Main function to monitor print jobs.
    """
    args = setup_argparse()

    # Validate input
    if args.interval <= 0:
        logging.error("Interval must be a positive integer.")
        sys.exit(1)
    if args.max_pages <= 0:
        logging.error("Max pages must be a positive integer.")
        sys.exit(1)

    # Configure logging to file
    file_handler = logging.FileHandler(args.log_file)
    file_handler.setLevel(logging.INFO)  # Log to file at INFO level
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logging.getLogger('').addHandler(file_handler)

    logging.info("Starting printer activity monitor...")

    seen_jobs = set()

    try:
        while True:
            try:
                print_jobs = get_print_jobs()

                if print_jobs:
                    for job in print_jobs:
                        # This set is the only thing standing between a job and a
                        # repeat alert, and it grows for as long as the monitor
                        # runs: nothing is ever pruned from it. A monitor left up
                        # for months carries every job key it has ever seen in
                        # memory, and a restarted monitor forgets them all and
                        # re-alerts on whatever history the Linux path shows it.
                        job_key = (job.get("job_id"), job.get("submitted_time"))
                        if job_key in seen_jobs:
                            continue
                        seen_jobs.add(job_key)
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