# monitor-printeractivity
Monitors print jobs, including document names, user accounts, and printer destinations. Detects unauthorized printing of sensitive documents or unusual printing patterns. - Focused on System monitoring and alerts

## Install
`git clone https://github.com/ShadowGuardAI/monitor-printeractivity`

## Usage
`./monitor-printeractivity [params]`

## Parameters
- `-h`: Show help message and exit
- `--interval`: No description provided
- `--log_file`: No description provided
- `--sensitive_keywords`: List of keywords that indicate a sensitive document (default: [
- `--suspicious_user`: List of users to monitor for suspicious activity.
- `--max_pages`: Maximum number of pages considered normal. Trigger alerts for jobs exceeding this value. Must be a positive integer.
- `--output_format`: No description provided

## License
Copyright (c) ShadowGuardAI
