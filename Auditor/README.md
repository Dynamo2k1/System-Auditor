## Overview

This document provides detailed explanations of the code sections in the System Auditor script. The code is designed to gather system information, verify file integrity, detect rootkits, and perform active responses.

## Code Sections

### 1. `ExecuteCommand(const char* command, const char* outputFile)`

```c
void ExecuteCommand(const char* command, const char* outputFile) {
    char fullCommand[2048];
    snprintf(fullCommand, sizeof(fullCommand), "%s > \"%s\" 2>&1", command, outputFile);

    int result = system(fullCommand);
    if (result != 0) {
        FILE* logFile;
        if (fopen_s(&logFile, "C:\\Data\\error_log.txt", "a") == 0) {
            fprintf(logFile, "Failed to execute command: %s\n", command);
            fclose(logFile);
        }
    }
}
```

- **Purpose**: Executes a command and redirects both standard output and error to a specified log file.
- **Parameters**:
  - `command`: The command to be executed.
  - `outputFile`: The path where output and errors are logged.
- **Details**: Uses `snprintf` to build a command string that redirects output. Calls `system()` to execute the command and logs errors if execution fails.

### 2. `CreateOutputDirectory(const char* dirPath)`

```c
void CreateOutputDirectory(const char* dirPath) {
    if (!CreateDirectoryA(dirPath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        printf("Failed to create directory %s. Exiting...\n", dirPath);
        exit(1);
    }
}
```

- **Purpose**: Creates a directory for storing audit results if it does not already exist.
- **Parameters**:
  - `dirPath`: The path of the directory to be created.
- **Details**: Calls `CreateDirectoryA()` and checks for errors. If directory creation fails and the error is not that the directory already exists, it prints an error message and exits.

### 3. `HashFile(const char* filePath, unsigned char* hashOutput)`

```c
void HashFile(const char* filePath, unsigned char* hashOutput) {
    FILE* file;
    if (fopen_s(&file, filePath, "rb") != 0) {
        printf("Failed to open file %s\n", filePath);
        return;
    }

    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_HASH_HANDLE hHash;
    unsigned char buffer[1024];
    unsigned char hash[32]; // SHA-256 hash size
    DWORD bytesRead = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) {
        printf("Failed to open algorithm provider\n");
        fclose(file);
        return;
    }

    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) {
        printf("Failed to create hash\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        fclose(file);
        return;
    }

    while ((bytesRead = (DWORD)fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (BCryptHashData(hHash, buffer, bytesRead, 0) != 0) {
            printf("Failed to hash data\n");
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            fclose(file);
            return;
        }
    }

    if (BCryptFinishHash(hHash, hash, sizeof(hash), 0) != 0) {
        printf("Failed to finish hash\n");
    }
    else {
        memcpy(hashOutput, hash, sizeof(hash));
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    fclose(file);
}
```

- **Purpose**: Computes the SHA-256 hash of a file.
- **Parameters**:
  - `filePath`: The path of the file to be hashed.
  - `hashOutput`: Buffer to store the resulting hash.
- **Details**: Uses Windows Cryptographic API (`bcrypt`) to open an algorithm provider, create a hash, process file data, and finish the hash. Handles errors at each stage and cleans up resources.

### 4. `PerformFileIntegrityCheck(const char* filePath, const char* hashFile)`

```c
void PerformFileIntegrityCheck(const char* filePath, const char* hashFile) {
    unsigned char currentHash[32];
    unsigned char savedHash[32];

    HashFile(filePath, currentHash);

    FILE* hashFilePtr;
    if (fopen_s(&hashFilePtr, hashFile, "rb") == 0) {
        fread(savedHash, (DWORD)sizeof(savedHash), 1, hashFilePtr);
        fclose(hashFilePtr);

        if (memcmp(currentHash, savedHash, sizeof(savedHash)) == 0) {
            printf("File integrity verified for %s\n", filePath);
        }
        else {
            printf("File integrity compromised for %s\n", filePath);
        }
    }
    else {
        printf("No previous hash found for %s. Saving current hash.\n", filePath);
    }

    // Save the current hash for future comparison
    if (fopen_s(&hashFilePtr, hashFile, "wb") == 0) {
        fwrite(currentHash, (DWORD)sizeof(currentHash), 1, hashFilePtr);
        fclose(hashFilePtr);
    }
}
```

- **Purpose**: Checks the integrity of a file by comparing its current hash with a previously saved hash.
- **Parameters**:
  - `filePath`: The path of the file to check.
  - `hashFile`: The path of the file containing the previously saved hash.
- **Details**: Computes the current hash of the file, reads the saved hash, compares the two, and updates the saved hash if necessary.

### 5. `DetectRootkits()`

```c
void DetectRootkits() {
    ExecuteCommand("powershell -Command \"Get-WmiObject Win32_Process | Where-Object { $_.ParentProcessId -eq 0 } | ConvertTo-Json\"", "C:\\Data\\rootkit_detection.json");
}
```

- **Purpose**: Detects potential rootkits by checking for processes with a parent process ID of 0.
- **Details**: Uses PowerShell to list processes and saves the output to a JSON file. This simple method identifies processes that may be indicative of rootkits.

### 6. `ActiveResponse()`

```c
void ActiveResponse() {
    FILE* cpuUsageFile;
    if (fopen_s(&cpuUsage

File, "C:\\Data\\cpu_usage.json", "r") != 0) return;

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), cpuUsageFile)) {
        if (strstr(buffer, "90")) { // Assuming 90% is a threshold for high CPU usage
            // Trigger some active response (e.g., kill a process or restart a service)
            ExecuteCommand("powershell -Command \"Stop-Process -Name process_to_kill\"", "C:\\Data\\active_response_log.txt");
            printf("Active response triggered due to high CPU usage\n");
        }
    }
    fclose(cpuUsageFile);
}
```

- **Purpose**: Triggers an active response if CPU usage exceeds a specified threshold.
- **Details**: Reads the CPU usage data from a JSON file, checks for high usage, and performs a predefined action if the threshold is met.

### 7. `ExecuteCommands()`

```c
void ExecuteCommands() {
    // Commands array, optimized and cleaned up
    struct {
        const char* command;
        const char* outputFile;
    } commands[] = {
        {"powershell -Command \"Get-ComputerInfo | ConvertTo-Json\"", "C:\\Data\\system_info.json"},
        // Additional commands...
    };

    // Execute each command
    for (int i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        ExecuteCommand(commands[i].command, commands[i].outputFile);
    }
}
```

- **Purpose**: Executes a series of system and PowerShell commands to collect various types of system data.
- **Details**: Iterates through a list of commands, executing each and saving the output to a specified file.

### 8. `main()`

```c
int main() {
    // Ensure output directory exists
    CreateOutputDirectory("C:\\Data");

    // Execute all commands
    ExecuteCommands();

    // Perform File Integrity Monitoring
    PerformFileIntegrityCheck("C:\\Data\\system_info.txt", "C:\\Data\\system_info.hash");

    // Detect rootkits
    DetectRootkits();

    // Trigger Active Response
    ActiveResponse();

    printf("Audit completed. Check C:\\Data\\ for results.\n");

    return 0;
}
```

- **Purpose**: The main function of the program that orchestrates the execution of the auditor.
- **Details**: Ensures the output directory exists, runs commands to gather system data, performs file integrity checks, detects rootkits, and triggers active responses.
