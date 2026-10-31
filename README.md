![Banner](banner.png)

# monitor-printeractivity
Monitors print jobs and detects unusual printing patterns. What is recorded depends on the platform. On Windows, jobs are read from the print spooler with pywin32, which is required on Windows, and carry document names, user accounts, printer destinations, and page counts. On Linux, jobs are read with lpstat -o, which provides only the user, the queue, the job size in bytes, and the date: the Linux path records no document name and no page count. - Focused on System monitoring and alerts

The sensitive keyword check applies where a document name exists, which is the Windows path only. Each job is analyzed once, keyed by its job id and submission time. An interval or max pages value that is not positive is refused at startup with exit 1.

## Install
`git clone https://github.com/ShadowGuardAI/monitor-printeractivity`

## Usage
`python main.py [params]`

## Parameters
- `-h`: Show help message and exit
- `--interval`: Interval in seconds to check for print jobs (default: 60). Must be a positive integer.
- `--log_file`: Path to the log file (default: printer_monitor.log).
- `--sensitive_keywords`: List of keywords that indicate a sensitive document (default: ['confidential', 'secret']).
- `--suspicious_user`: List of users to monitor for suspicious activity.
- `--max_pages`: Maximum number of pages considered normal. Trigger alerts for jobs exceeding this value. Must be a positive integer.

## License
Copyright (c) ShadowGuardAI
