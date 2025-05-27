// SAST CLI Tool
// Author: Sarthak
// Description: Scans C/C++ code for vulnerabilities like hardcoded creds, SQLi, unsafe functions.
#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include <unordered_map>
#include <vector>
#include <filesystem>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <mutex>

namespace fs = std::filesystem;

const std::string VERSION = "1.0.0";
const std::string PROGRAM_NAME = "SAST-Cpp";

// Simple JSON-like structure for reports
class SimpleJSON {
private:
    std::unordered_map<std::string, std::string> data;
    std::unordered_map<std::string, std::vector<std::unordered_map<std::string, std::string>>> arrays;
    
public:
    void set(const std::string& key, const std::string& value) {
        data[key] = value;
    }
    
    void set(const std::string& key, int value) {
        data[key] = std::to_string(value);
    }
    
    void addToArray(const std::string& key, const std::unordered_map<std::string, std::string>& item) {
        arrays[key].push_back(item);
    }
    
    size_t getArraySize(const std::string& key) const {
        auto it = arrays.find(key);
        return (it != arrays.end()) ? it->second.size() : 0;
    }
    
    std::string get(const std::string& key) const {
        auto it = data.find(key);
        return (it != data.end()) ? it->second : "";
    }
    
    int getInt(const std::string& key) const {
        auto it = data.find(key);
        return (it != data.end()) ? std::stoi(it->second) : 0;
    }
    
    std::string toJSON() const {
        std::ostringstream json;
        json << "{\n";
        
        bool first = true;
        for (const auto& [key, value] : data) {
            if (!first) json << ",\n";
            json << "  \"" << key << "\": \"" << value << "\"";
            first = false;
        }
        
        for (const auto& [key, arr] : arrays) {
            if (!first) json << ",\n";
            json << "  \"" << key << "\": [\n";
            
            for (size_t i = 0; i < arr.size(); ++i) {
                json << "    {\n";
                bool firstItem = true;
                for (const auto& [itemKey, itemValue] : arr[i]) {
                    if (!firstItem) json << ",\n";
                    json << "      \"" << itemKey << "\": \"" << itemValue << "\"";
                    firstItem = false;
                }
                json << "\n    }";
                if (i < arr.size() - 1) json << ",";
                json << "\n";
            }
            json << "  ]";
            first = false;
        }
        
        json << "\n}";
        return json.str();
    }
    
    std::vector<std::string> getArrayKeys() const {
        std::vector<std::string> keys;
        for (const auto& [key, _] : arrays) {
            keys.push_back(key);
        }
        return keys;
    }
    
    const std::vector<std::unordered_map<std::string, std::string>>& getArray(const std::string& key) const {
        static const std::vector<std::unordered_map<std::string, std::string>> empty;
        auto it = arrays.find(key);
        return (it != arrays.end()) ? it->second : empty;
    }
};

struct GlobalConfig {
    bool verbose = false;
    bool quiet = false;
    std::string outputFormat = "json";
    std::vector<std::string> enabledChecks;
    std::vector<std::string> disabledChecks;
    bool noColor = false;
} globalConfig;

namespace Color {
    const std::string reset = "\033[0m";
    const std::string red = "\033[31m";
    const std::string green = "\033[32m";
    const std::string yellow = "\033[33m";
    const std::string blue = "\033[34m";
    const std::string magenta = "\033[35m";
    const std::string cyan = "\033[36m";
    const std::string bold = "\033[1m";

    std::string colorize(const std::string& text, const std::string& color) {
        if (globalConfig.noColor) return text;
        return color + text + reset;
    }
}

class Logger {
private:
    std::mutex logMutex;
    
public:
    enum Level { DEBUG, INFO, WARNING, ERROR, CRITICAL };
    
    void log(Level level, const std::string& message) {
        if (globalConfig.quiet && level < ERROR) return;
        if (!globalConfig.verbose && level == DEBUG) return;
        
        std::lock_guard<std::mutex> lock(logMutex);
        
        std::string prefix, color;
        switch (level) {
            case DEBUG: prefix = "[DEBUG] "; color = Color::blue; break;
            case INFO: prefix = "[INFO] "; color = Color::green; break;
            case WARNING: prefix = "[WARNING] "; color = Color::yellow; break;
            case ERROR: prefix = "[ERROR] "; color = Color::red; break;
            case CRITICAL: prefix = "[CRITICAL] "; color = Color::magenta; break;
        }
        
        std::cout << Color::colorize(prefix, color) << message << std::endl;
    }
    
    void debug(const std::string& msg) { log(DEBUG, msg); }
    void info(const std::string& msg) { log(INFO, msg); }
    void warning(const std::string& msg) { log(WARNING, msg); }
    void error(const std::string& msg) { log(ERROR, msg); }
    void critical(const std::string& msg) { log(CRITICAL, msg); }
};

Logger logger;

class SecurityScanner {
    std::string filepath;
    std::vector<std::string> lines;
    SimpleJSON report;
    std::unordered_map<std::string, bool> enabledChecksMap;

public:
    SecurityScanner(const std::string& path) : filepath(path) {
        setupEnabledChecks();
    }

    void setupEnabledChecks() {
        const std::vector<std::string> allChecks = {
            "HardcodedCredentials", "SQLInjection", "DangerousOSFunctions",
            "UnsafeFunctions", "MemoryLeaks", "HardcodedPaths",
            "LogForging", "WeakCryptography", "UseAfterFree", 
            "InsecureFilePermissions", "UnvalidatedInput"
        };
        
        for (const auto& check : allChecks) {
            enabledChecksMap[check] = true;
        }
        
        if (!globalConfig.enabledChecks.empty()) {
            for (const auto& check : allChecks) {
                enabledChecksMap[check] = false;
            }
            for (const auto& check : globalConfig.enabledChecks) {
                enabledChecksMap[check] = true;
            }
        }
        
        for (const auto& check : globalConfig.disabledChecks) {
            enabledChecksMap[check] = false;
        }
    }

    bool isCheckEnabled(const std::string& checkName) const {
        auto it = enabledChecksMap.find(checkName);
        return (it != enabledChecksMap.end()) ? it->second : false;
    }

    bool loadFile() {
        std::ifstream file(filepath);
        if (!file.is_open()) {
            logger.error("Failed to open file: " + filepath);
            return false;
        }

        std::string line;
        while (getline(file, line)) {
            lines.push_back(line);
        }
        
        logger.debug("Loaded " + std::to_string(lines.size()) + " lines from " + filepath);
        return true;
    }

    void checkHardcodedCredentials() {
        if (!isCheckEnabled("HardcodedCredentials")) return;
        
        std::regex credPattern(R"((?:password|passwd|pwd|token|apikey|secret|key|pass|auth|credentials)\s*=\s*["'](?![\s{}$%])[^"']*["'])", std::regex::icase);
        for (size_t i = 0; i < lines.size(); i++) {
            if (std::regex_search(lines[i], credPattern)) {
                if (lines[i].find("//") != std::string::npos && lines[i].find("//") < lines[i].find("=")) {
                    continue;
                }
                std::unordered_map<std::string, std::string> issue;
                issue["line"] = std::to_string(i + 1);
                issue["content"] = lines[i];
                report.addToArray("Hardcoded Credentials", issue);
            }
        }
    }

    void checkSQLInjections() {
        if (!isCheckEnabled("SQLInjection")) return;
        
        std::regex sqlPattern(R"((SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP).*?(?:["']\s*\+\s*\w+|\w+\s*\+\s*["']|'\s*\+|\+\s*'|"\s*\+|\+\s*"))", std::regex::icase);
        for (size_t i = 0; i < lines.size(); i++) {
            if (std::regex_search(lines[i], sqlPattern)) {
                if (lines[i].find("//") != std::string::npos && lines[i].find("//") < lines[i].find("+")) {
                    continue;
                }
                std::unordered_map<std::string, std::string> issue;
                issue["line"] = std::to_string(i + 1);
                issue["content"] = lines[i];
                report.addToArray("Potential SQL Injection", issue);
            }
        }
    }

    void checkDangerousOSFunctions() {
        if (!isCheckEnabled("DangerousOSFunctions")) return;
        
        std::regex dangerousFunctions(R"(\b(system|popen|exec[lv][ep]?|fork|spawn|shellexec)\s*\([^)]*\))", std::regex::icase);
        for (size_t i = 0; i < lines.size(); i++) {
            if (std::regex_search(lines[i], dangerousFunctions)) {
                if (lines[i].find("//") != std::string::npos && lines[i].find("//") < lines[i].find("(")) {
                    continue;
                }
                std::unordered_map<std::string, std::string> issue;
                issue["line"] = std::to_string(i + 1);
                issue["content"] = lines[i];
                report.addToArray("OS Command Execution", issue);
            }
        }
    }

    void checkUnsafeFunctions() {
        if (!isCheckEnabled("UnsafeFunctions")) return;
        
        std::regex unsafePattern(R"(\b(gets|strcpy|strcat|sprintf|scanf|printf|vsprintf|memcpy|memmove|malloc|realloc|free|alloca)\s*\([^)]*\))", std::regex::icase);
        for (size_t i = 0; i < lines.size(); i++) {
            if (std::regex_search(lines[i], unsafePattern)) {
                if (lines[i].find("//") != std::string::npos && lines[i].find("//") < lines[i].find("(")) {
                    continue;
                }
                std::unordered_map<std::string, std::string> issue;
                issue["line"] = std::to_string(i + 1);
                issue["content"] = lines[i];
                report.addToArray("Unsafe Function Use", issue);
            }
        }
    }

    void checkMemoryLeaks() {
        if (!isCheckEnabled("MemoryLeaks")) return;
        
        std::regex newPattern(R"(\b(\w+)\s*=\s*new\b\s+(?:\w+|[a-zA-Z0-9_:]+\s*\[))");
        std::regex deletePattern(R"(\bdelete\b\s+(\w+))");
        
        std::unordered_map<std::string, std::vector<size_t>> allocatedVars;
        std::unordered_map<std::string, std::vector<size_t>> deallocatedVars;
        
        for (size_t i = 0; i < lines.size(); i++) {
            std::string codeLine = lines[i];
            if (codeLine.find("//") != std::string::npos) {
                codeLine = codeLine.substr(0, codeLine.find("//"));
            }
            
            std::smatch match;
            if (std::regex_search(codeLine, match, newPattern)) {
                std::string varName = match[1].str();
                allocatedVars[varName].push_back(i + 1);
            }
            
            if (std::regex_search(codeLine, match, deletePattern)) {
                std::string varName = match[1].str();
                deallocatedVars[varName].push_back(i + 1);
            }
        }
        
        for (const auto& [varName, allocLines] : allocatedVars) {
            auto it = deallocatedVars.find(varName);
            if (it == deallocatedVars.end() || it->second.size() < allocLines.size()) {
                size_t allocCount = allocLines.size();
                size_t deallocCount = (it != deallocatedVars.end()) ? it->second.size() : 0;
                
                if (allocCount > deallocCount) {
                    std::unordered_map<std::string, std::string> issue;
                    issue["variable"] = varName;
                    issue["allocations"] = std::to_string(allocCount);
                    issue["deallocations"] = std::to_string(deallocCount);
                    issue["leak_count"] = std::to_string(allocCount - deallocCount);
                    
                    std::ostringstream allocLinesStr;
                    for (size_t i = 0; i < allocLines.size(); ++i) {
                        if (i > 0) allocLinesStr << ",";
                        allocLinesStr << allocLines[i];
                    }
                    issue["allocation_lines"] = allocLinesStr.str();
                    
                    report.addToArray("Potential Memory Leak", issue);
                }
            }
        }
    }

    void runAllChecks() {
        checkHardcodedCredentials();
        checkSQLInjections();
        checkDangerousOSFunctions();
        checkUnsafeFunctions();
        checkMemoryLeaks();
        
        report.set("filename", filepath);
        report.set("scan_time", getCurrentTimestamp());
        report.set("lines_of_code", static_cast<int>(lines.size()));
        report.set("scanner_version", VERSION);
    }
    
    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    bool exportReport(const std::string& outputPath) {
        std::ofstream outFile(outputPath);
        if (!outFile.is_open()) {
            logger.error("Failed to create report file: " + outputPath);
            return false;
        }
        
        if (globalConfig.outputFormat == "json") {
            outFile << report.toJSON();
        } else if (globalConfig.outputFormat == "text") {
            outFile << "Security Scan Report for " << filepath << std::endl;
            outFile << "Generated on " << report.get("scan_time") << std::endl;
            outFile << "Scanner Version: " << VERSION << std::endl;
            outFile << "Lines of Code: " << report.get("lines_of_code") << std::endl;
            outFile << std::string(80, '-') << std::endl << std::endl;
            
            bool issuesFound = false;
            auto arrayKeys = report.getArrayKeys();
            
            for (const auto& category : arrayKeys) {
                if (report.getArraySize(category) > 0) {
                    issuesFound = true;
                    outFile << category << ":" << std::endl;
                    outFile << std::string(category.length() + 1, '-') << std::endl;
                    
                    auto issues = report.getArray(category);
                    for (const auto& issue : issues) {
                        for (const auto& [key, value] : issue) {
                            outFile << key << ": " << value << std::endl;
                        }
                        outFile << std::endl;
                    }
                    outFile << std::endl;
                }
            }
            
            if (!issuesFound) {
                outFile << "No issues found." << std::endl;
            }
        }
        
        outFile.close();
        return fs::exists(outputPath) && fs::file_size(outputPath) > 0;
    }
    
    SimpleJSON getReportSummary() {
        SimpleJSON summary;
        int totalIssues = 0;
        
        auto arrayKeys = report.getArrayKeys();
        for (const auto& category : arrayKeys) {
            int count = static_cast<int>(report.getArraySize(category));
            summary.set(category, count);
            totalIssues += count;
        }
        
        summary.set("total_issues", totalIssues);
        return summary;
    }
    
    void printConsoleReport() {
        auto summary = getReportSummary();
        
        if (!globalConfig.quiet) {
            std::cout << Color::colorize("\nScan Results for " + fs::path(filepath).filename().string() + ":", Color::bold) << std::endl;
            
            if (summary.getInt("total_issues") == 0) {
                std::cout << Color::colorize("No issues found.", Color::green) << std::endl;
                return;
            }
            
            auto arrayKeys = report.getArrayKeys();
            for (const auto& category : arrayKeys) {
                int count = static_cast<int>(report.getArraySize(category));
                if (count > 0) {
                    std::string color = Color::red;
                    std::cout << "  " << Color::colorize(category + ": ", Color::bold) 
                              << Color::colorize(std::to_string(count), color) << std::endl;
                }
            }
            
            std::cout << Color::colorize("\nTotal issues: " + std::to_string(summary.getInt("total_issues")), Color::bold) << std::endl;
        }
    }
};

// Simple command line parser
class CommandLineParser {
private:
    std::vector<std::string> args;
    
public:
    CommandLineParser(int argc, char* argv[]) {
        for (int i = 1; i < argc; ++i) {
            args.push_back(std::string(argv[i]));
        }
    }
    
    bool hasFlag(const std::string& flag) const {
        return std::find(args.begin(), args.end(), flag) != args.end();
    }
    
    std::string getValue(const std::string& flag) const {
        auto it = std::find(args.begin(), args.end(), flag);
        if (it != args.end() && (it + 1) != args.end()) {
            return *(it + 1);
        }
        return "";
    }
    
    std::vector<std::string> getValues(const std::string& flag) const {
        std::vector<std::string> values;
        auto it = std::find(args.begin(), args.end(), flag);
        if (it != args.end() && (it + 1) != args.end()) {
            std::string valueStr = *(it + 1);
            std::istringstream iss(valueStr);
            std::string item;
            while (std::getline(iss, item, ',')) {
                values.push_back(item);
            }
        }
        return values;
    }
};

void scanDirectory(const std::string& directory, const std::string& outputDir = "") {
    int totalFiles = 0;
    int processedFiles = 0;
    int issueFiles = 0;
    SimpleJSON globalSummary;
    globalSummary.set("total_issues", 0);
    
    try {
        for (const auto& entry : fs::recursive_directory_iterator(directory)) {
            if (entry.is_regular_file() && 
                (entry.path().extension() == ".cpp" || 
                 entry.path().extension() == ".h" || 
                 entry.path().extension() == ".hpp" || 
                 entry.path().extension() == ".cc" ||
                 entry.path().extension() == ".c")) {
                totalFiles++;
            }
        }
    } catch (const std::exception& e) {
        logger.error("Error counting files: " + std::string(e.what()));
        return;
    }
    
    if (totalFiles == 0) {
        logger.warning("No C/C++ files found in directory: " + directory);
        return;
    }
    
    logger.info("Found " + std::to_string(totalFiles) + " files to scan");
    
    fs::path outputPath;
    if (!outputDir.empty()) {
        outputPath = fs::path(outputDir);
        if (!fs::exists(outputPath)) {
            try {
                fs::create_directories(outputPath);
            } catch (const std::exception& e) {
                logger.error("Failed to create output directory: " + std::string(e.what()));
                return;
            }
        }
    }
    
    try {
        for (const auto& entry : fs::recursive_directory_iterator(directory)) {
            if (entry.is_regular_file() && 
                (entry.path().extension() == ".cpp" || 
                 entry.path().extension() == ".h" || 
                 entry.path().extension() == ".hpp" || 
                 entry.path().extension() == ".cc" ||
                 entry.path().extension() == ".c")) {
                
                if (globalConfig.verbose) {
                    logger.info("Scanning: " + entry.path().filename().string());
                }
                
                SecurityScanner scanner(entry.path().string());
                if (scanner.loadFile()) {
                    scanner.runAllChecks();
                    
                    std::string reportPath;
                    if (!outputDir.empty()) {
                        reportPath = (outputPath / entry.path().filename()).string() + ".sast." + globalConfig.outputFormat;
                    } else {
                        reportPath = entry.path().string() + ".sast." + globalConfig.outputFormat;
                    }
                    
                    if (scanner.exportReport(reportPath)) {
                        processedFiles++;
                        
                        auto summary = scanner.getReportSummary();
                        globalSummary.set("total_issues", globalSummary.getInt("total_issues") + summary.getInt("total_issues"));
                        
                        if (summary.getInt("total_issues") > 0) {
                            issueFiles++;
                        }
                        
                        if (globalConfig.verbose) {
                            scanner.printConsoleReport();
                        }
                    }
                }
            }
        }
        
        logger.info("Scan complete: " + std::to_string(processedFiles) + "/" + std::to_string(totalFiles) + " files processed");
        logger.info("Files with issues: " + std::to_string(issueFiles) + "/" + std::to_string(totalFiles));
        logger.info("Total issues found: " + std::to_string(globalSummary.getInt("total_issues")));
        
    } catch (const std::exception& e) {
        logger.error("Error scanning directory: " + std::string(e.what()));
    }
}

void printUsage() {
    std::cout << PROGRAM_NAME << " v" << VERSION << " - Static Application Security Testing Scanner\n\n";
    
    std::cout << "Usage:\n";
    std::cout << "  " << PROGRAM_NAME << " [OPTIONS] --file <path>\n";
    std::cout << "  " << PROGRAM_NAME << " [OPTIONS] --dir <path>\n\n";
    
    std::cout << "Options:\n";
    std::cout << "  -h, --help              Show this help message\n";
    std::cout << "  -v, --version           Show version information\n";
    std::cout << "  -f, --file <path>       Scan a single file\n";
    std::cout << "  -d, --dir <path>        Scan directory recursively\n";
    std::cout << "  -o, --output-dir <path> Output directory for reports\n";
    std::cout << "  --format <type>         Output format (json|text) [default: json]\n";
    std::cout << "  --verbose               Enable verbose output\n";
    std::cout << "  --quiet                 Quiet mode (errors only)\n";
    std::cout << "  --no-color              Disable colored output\n";
    std::cout << "  --enable-checks <list>  Enable only specific checks (comma-separated)\n";
    std::cout << "  --disable-checks <list> Disable specific checks (comma-separated)\n";
    std::cout << "  --list-checks           List available security checks\n\n";
    
    std::cout << "Examples:\n";
    std::cout << "  " << PROGRAM_NAME << " --file mycode.cpp\n";
    std::cout << "  " << PROGRAM_NAME << " --dir /path/to/src --output-dir reports\n";
    std::cout << "  " << PROGRAM_NAME << " --dir /path/to/src --format text --verbose\n";
}

void printAvailableChecks() {
    std::cout << "Available security checks:\n";
    std::cout << "  HardcodedCredentials     - Detects credentials like passwords hard-coded in source\n";
    std::cout << "  SQLInjection             - Identifies potential SQL injection vulnerabilities\n";
    std::cout << "  DangerousOSFunctions     - Finds calls to dangerous OS functions (system, exec)\n";
    std::cout << "  UnsafeFunctions          - Detects unsafe C/C++ functions (strcpy, gets)\n"; 
    std::cout << "  MemoryLeaks              - Identifies potential memory leaks\n";
    std::cout << "  HardcodedPaths           - Finds hardcoded absolute file paths\n";
    std::cout << "  LogForging               - Identifies potential log forging vulnerabilities\n";
    std::cout << "  WeakCryptography         - Detects use of weak cryptographic algorithms\n";
    std::cout << "  UseAfterFree             - Detects use of a pointer after being freed\n";
    std::cout << "  InsecureFilePermissions  - Identifies insecure file permission settings\n";
    std::cout << "  UnvalidatedInput         - Reports input with insufficient validation\n";
}

int main(int argc, char* argv[]) {
    CommandLineParser parser(argc, argv);
    
    if (parser.hasFlag("-h") || parser.hasFlag("--help")) {
        printUsage();
        return 0;
    }
    
    if (parser.hasFlag("-v") || parser.hasFlag("--version")) {
        std::cout << PROGRAM_NAME << " v" << VERSION << std::endl;
        return 0;
    }
    
    if (parser.hasFlag("--list-checks")) {
        printAvailableChecks();
        return 0;
    }
    
    if (parser.hasFlag("--verbose")) {
        globalConfig.verbose = true;
    }
    
    if (parser.hasFlag("--quiet")) {
        globalConfig.quiet = true;
    }
    
    if (parser.hasFlag("--no-color")) {
        globalConfig.noColor = true;
    }
    
    std::string format = parser.getValue("--format");
    if (!format.empty()) {
        if (format == "json" || format == "text") {
            globalConfig.outputFormat = format;
        } else {
            logger.error("Invalid output format. Supported formats: json, text");
            return 1;
        }
    }
    
    globalConfig.enabledChecks = parser.getValues("--enable-checks");
    globalConfig.disabledChecks = parser.getValues("--disable-checks");
    
    std::cout << Color::colorize(PROGRAM_NAME + " v" + VERSION, Color::cyan) << std::endl;
    
    std::string filePath = parser.getValue("-f");
    if (filePath.empty()) {
        filePath = parser.getValue("--file");
    }
    
    std::string dirPath = parser.getValue("-d");
    if (dirPath.empty()) {
        dirPath = parser.getValue("--dir");
    }
    
    if (!filePath.empty()) {
        if (!fs::exists(filePath)) {
            logger.error("File not found: " + filePath);
            return 1;
        }
        
        if (!fs::is_regular_file(filePath)) {
            logger.error("Not a file: " + filePath);
            return 1;
        }
        
        fs::path path(filePath);
        std::string ext = path.extension().string();
        if (ext != ".cpp" && ext != ".h" && ext != ".hpp" && ext != ".cc" && ext != ".c") {
            logger.warning("File does not have a C/C++ extension. Continuing anyway...");
        }
        
        logger.info("Scanning file: " + filePath);
        
        SecurityScanner scanner(filePath);
        if (scanner.loadFile()) {
            scanner.runAllChecks();
            
            std::string outputPath;
            std::string outputDir = parser.getValue("-o");
            if (outputDir.empty()) {
                outputDir = parser.getValue("--output-dir");
            }
            
            if (!outputDir.empty()) {
                fs::path outDir(outputDir);
                if (!fs::exists(outDir)) {
                    try {
                        fs::create_directories(outDir);
                    } catch (const std::exception& e) {
                        logger.error("Failed to create output directory: " + std::string(e.what()));
                        return 1;
                    }
                }
                outputPath = (outDir / (path.filename().string() + ".sast." + globalConfig.outputFormat)).string();
            } else {
                outputPath = filePath + ".sast." + globalConfig.outputFormat;
            }
            
            if (scanner.exportReport(outputPath)) {
                logger.info("Report saved to: " + outputPath);
                scanner.printConsoleReport();
            } else {
                logger.error("Failed to save report.");
                return 1;
            }
        } else {
            logger.error("Failed to load file.");
            return 1;
        }
    } else if (!dirPath.empty()) {
        if (!fs::exists(dirPath)) {
            logger.error("Directory not found: " + dirPath);
            return 1;
        }
        
        if (!fs::is_directory(dirPath)) {
            logger.error("Not a directory: " + dirPath);
            return 1;
        }
        
        logger.info("Scanning directory: " + dirPath);
        std::string outputDir = parser.getValue("-o");
        if (outputDir.empty()) {
            outputDir = parser.getValue("--output-dir");
        }
        scanDirectory(dirPath, outputDir);
    } else {
        logger.error("Please specify either --file or --dir option.");
        printUsage();
        return 1;
    }
    
    return 0;
}