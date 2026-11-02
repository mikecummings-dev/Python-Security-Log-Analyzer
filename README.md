# Python Security Log Analyzer

A Python-based security log analysis tool that parses authentication logs, tracks failed login attempts, identifies suspicious IP activity, and generates automated security reports.

## Features
- Counts successful login attempts
- Counts failed login attempts
- Extracts and tracks unique IP addresses
- Tracks failed login attempts by source IP address
- Identifies suspicious activity using a configurable alert threshold
- Generates a formatted security report and saves it to a file
## Technologies Used
- Python
- File Handling
- Dictionaries
- Sets
- Basic Security Analytics
## Example Log Entry
2026-11-02 08:05:11 ERROR Failed login from 192.168.1.50
## Example Report Output
<img width="375" height="621" alt="image" src="https://github.com/user-attachments/assets/093f3a74-9918-429c-8a3b-7e9d03d00aa1" />

## How to Run
1. Clone or download the repository.
2. Open a terminal in the project directory.
3. Run: python3 scripting101.py
4. Enter the path to the log file you wish to analyze.
5. Enter a filename for the generated report.
6. Review the generated security report.
## Project Structure
python-security-log-analyzer/
- scripting101.py.py
- serverlog2.txt
- pracreport2.txt
- README.md
- .gitignore
## Future Improvements
 - Parse a wider variety of log formats
- Use regular expressions for more robust IP extraction
- Add username tracking and analysis
- Add timestamp-based activity analysis
- Export reports in CSV format
- Support JSON report generation
## Author
Michael Cummings

GitHub: https://github.com/mikecummings-dev
