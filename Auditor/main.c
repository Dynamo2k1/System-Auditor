#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcrypt.h> 
#include <shlwapi.h> 

// Function to execute a command and log output and errors
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

// Function to create directory if it doesn't exist
void CreateOutputDirectory(const char* dirPath) {
    if (!CreateDirectoryA(dirPath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        printf("Failed to create directory %s. Exiting...\n", dirPath);
        exit(1);
    }
}

// Function to compare file hashes for File Integrity Monitoring
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

// Function to perform file integrity check by comparing current and previous hashes
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

// Function to detect rootkits (basic approach via checking hidden processes or abnormal services)
void DetectRootkits() {
    ExecuteCommand("powershell -Command \"Get-WmiObject Win32_Process | Where-Object { $_.ParentProcessId -eq 0 } | ConvertTo-Json\"", "C:\\Data\\rootkit_detection.json");
}

// Function to execute active response based on a condition (example: high CPU usage)
void ActiveResponse() {
    FILE* cpuUsageFile;
    if (fopen_s(&cpuUsageFile, "C:\\Data\\cpu_usage.json", "r") != 0) return;

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

// Function to execute all commands and handle log collection
void ExecuteCommands() {
    // Commands array, optimized and cleaned up
    struct {
        const char* command;
        const char* outputFile;
    } commands[] = {
        {"powershell -Command \"Get-ComputerInfo | ConvertTo-Json\"", "C:\\Data\\system_info.json"},
        {"powershell -Command \"(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime\"", "C:\\Data\\last_boot.txt"},
        {"powershell -Command \"Get-LocalUser | ConvertTo-Json\"", "C:\\Data\\local_users.json"},
        {"powershell -Command \"Get-LocalGroup | ConvertTo-Json\"", "C:\\Data\\group_memberships.json"},
        {"powershell -Command \"secedit /export /cfg C:\\Data\\local_security_policies.cfg\"", "C:\\Data\\local_security_policies.cfg"},
        {"powershell -Command \"Get-WinEvent -LogName Security -FilterXPath \"*[System[(EventID=4740)]]\" | ConvertTo-Json\"", "C:\\Data\\account_lockouts.json"},
        {"powershell -Command \"Get-MpComputerStatus | ConvertTo-Json\"", "C:\\Data\\windows_defender_status.json"},
        {"powershell -Command \"Get-Counter -Counter \\\"\\Processor(_Total)\\% Processor Time\\\" -SampleInterval 5 -MaxSamples 10 | ConvertTo-Json\"", "C:\\Data\\cpu_usage.json"},
        {"powershell -Command \"Get-Counter -Counter \\\"\\Memory\\Available MBytes\\\" -SampleInterval 5 -MaxSamples 10 | ConvertTo-Json\"", "C:\\Data\\memory_usage.json"},
        {"powershell -Command \"Get-ChildItem -Path HKLM:\\Software | ConvertTo-Json\"", "C:\\Data\\registry_software_keys.json"},
        {"powershell -Command \"Get-NetAdapter | ConvertTo-Json\"", "C:\\Data\\network_adapters.json"},
        {"powershell -Command \"Get-NetTCPConnection | ConvertTo-Json\"", "C:\\Data\\net_tcp_connections.json"},
        {"powershell -Command \"Get-Service | ConvertTo-Json\"", "C:\\Data\\all_services.json"},
        {"powershell -Command \"Get-NetFirewallProfile | ConvertTo-Json\"", "C:\\Data\\firewall_status.json"},
        {"systeminfo > C:\\Data\\system_info.txt", "C:\\Data\\system_info.txt"}, // System info as TXT
        {"net user > C:\\Data\\net_user_list.txt", "C:\\Data\\net_user_list.txt"},
        {"net share > C:\\Data\\net_share.txt", "C:\\Data\\net_share.txt"}
    };

    // Execute each command
    for (int i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        ExecuteCommand(commands[i].command, commands[i].outputFile);
    }
}

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
