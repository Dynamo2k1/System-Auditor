# System Auditor Overview

## Overview

This System Auditor is a comprehensive script designed to perform various security and system integrity checks on Windows systems. Its primary functions include:

- **Command Execution**: Runs a series of system and PowerShell commands to gather system information, user details, and other relevant data.
- **File Integrity Monitoring**: Computes and verifies file hashes to detect any unauthorized changes.
- **Rootkit Detection**: Executes a PowerShell command to identify potential rootkits by examining hidden processes.
- **Active Response**: Monitors system performance and triggers responses based on certain conditions, such as high CPU usage.

## Features

- Collects detailed system information, including hardware, software, and security settings.
- Monitors and verifies the integrity of critical files.
- Detects potential rootkits by analyzing system processes.
- Responds to high CPU usage conditions with predefined actions.

## Installation Instructions

### Prerequisites

1. **Windows Operating System**: This script is designed to run on Windows systems.
2. **PowerShell**: Ensure PowerShell is installed and accessible from the command line.
3. **Permissions**: The script requires administrative privileges to execute certain commands and access system information.

### Steps to Install

1. **Download the Script**:
   - Save the provided C code as `system_auditor.c`.

2. **Compile the Code**:
   - Open a Command Prompt or PowerShell window.
   - Navigate to the directory containing `system_auditor.c`.
   - Compile the code using a suitable compiler like MinGW or Microsoft Visual Studio:
     ```sh
     gcc -o system_auditor system_auditor.c -lbcrypt -lshlwapi
     ```
   - This command will generate an executable file named `system_auditor.exe`.

3. **Prepare the Output Directory**:
   - The script saves its output and logs to `C:\Data`. Ensure this directory exists or modify the script to use a different path.

4. **Run the Auditor**:
   - Open Command Prompt or PowerShell with administrative privileges.
   - Execute the compiled auditor:
     ```sh
     system_auditor.exe
     ```

5. **Review Results**:
   - After execution, review the generated files in the `C:\Data` directory for the collected system information, logs, and any detected issues.

## Usage Notes

- The script generates various JSON and text files containing system data and logs. Review these files to understand the system's status and any potential security concerns.
- Regularly update and review the script and its outputs to maintain an up-to-date understanding of your system's integrity and security.
