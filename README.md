# FortiDig

FortiDig is a Python-based log analysis tool designed for parsing and analyzing Fortigate firewall logs. It offers functionalities to perform intrusion checks based on predefined patterns associated with known CVEs.

## Version

1.0.2

## Features

- **Intrusion Check**: Scans the logs for patterns that may indicate a potential intrusion, focusing on specific CVEs.

## Requirements

- Python 3.x

## Usage

To use FortiDig, clone this repository or download the `fortidig.py` file. Then, run the script from the command line, passing the path to your Fortigate log file as an argument:

python fortidig.py <path_to_log_file>

Replace `<path_to_log_file>` with the actual path to your log file.

## Supported CVEs

FortiDig currently checks for intrusions based on the following CVEs:

- CVE-2022-40684
- CVE-2022-41328
- CVE-2022-42475
- CVE-2024-55591

## Contributing

Contributions to FortiDig are welcome. If you have a suggestion for improving the tool or adding new features, feel free to fork the repository and submit a pull request.

## License

[MIT License](LICENSE)

## Disclaimer

FortiDig is provided "as is" without warranty of any kind, either express or implied. Use it at your own risk.

