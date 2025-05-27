# C/C++ SAST Scanner

Simple Static Application Security Testing (SAST) tool for C/C++ code. Detects common security vulnerabilities including:

* **Hardcoded credentials** (passwords, API keys)
* **SQL injection** vulnerabilities
* **Unsafe C functions** (strcpy, gets, sprintf)
* **Memory leaks** (unmatched new/delete)
* **Dangerous OS calls** (system, exec, popen)

## Usage

```bash
# Scan single file
./SAST-Cpp --file example.cpp

# Scan directory
./SAST-Cpp --dir /path/to/project

# With output directory
./SAST-Cpp --dir ./src --output-dir reports
```

## Example

Given this vulnerable C++ code:
```cpp
#include <iostream>
#include <cstring>

int main() {
    char buffer[100];
    char* password = "secret123";        // hardcoded credential
    char* input = getInput();
    
    strcpy(buffer, input);               // unsafe function
    system("ls -la");                    // dangerous OS call
    
    int* ptr = new int[100];            // memory leak
    return 0;
}
```

**Output:**
```
Scan Results for example.cpp:
  Hardcoded Credentials: 1
  OS Command Execution: 1
  Unsafe Function Use: 1
  Potential Memory Leak: 1

Total issues: 4
```

## Options

* `--file <path>` - Scan single file
* `--dir <path>` - Scan directory recursively  
* `--output-dir <path>` - Output directory for reports
* `--format <json|text>` - Report format (default: json)
* `--verbose` - Detailed output
* `--help` - Show all options

## Building

```bash
g++ -std=c++17 -O2 main.cpp -o SAST-Cpp
```
