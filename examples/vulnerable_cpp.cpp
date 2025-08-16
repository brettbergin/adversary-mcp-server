#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <fstream>

// 1. Buffer Overflow vulnerability
void bufferOverflow(const char* input) {
    char buffer[10];  // Small buffer
    strcpy(buffer, input);  // No bounds checking - vulnerable to overflow
    std::cout << "Buffer content: " << buffer << std::endl;
}

// 2. Use after free vulnerability
void useAfterFree() {
    char* ptr = (char*)malloc(100);
    free(ptr);
    strcpy(ptr, "dangerous");  // Using freed memory
    std::cout << ptr << std::endl;
}

// 3. Format string vulnerability
void formatString(const char* userInput) {
    printf(userInput);  // Direct use of user input as format string
}

// 4. Integer overflow
void integerOverflow(int size) {
    // No validation of size parameter
    char* buffer = (char*)malloc(size * sizeof(char));
    if (buffer) {
        // Use buffer without checking if allocation succeeded properly
        strcpy(buffer, "data");
        free(buffer);
    }
}

// 5. Null pointer dereference
void nullPointerDeref(char* ptr) {
    // No null check before dereferencing
    *ptr = 'A';
    std::cout << "Value: " << *ptr << std::endl;
}

// 6. Command injection
void commandInjection(const std::string& filename) {
    std::string command = "cat " + filename;  // Direct concatenation
    system(command.c_str());  // Executing user-controlled command
}

// 7. Path traversal
void pathTraversal(const std::string& filename) {
    std::string path = "/uploads/" + filename;  // No validation
    std::ifstream file(path);
    if (file.is_open()) {
        std::string line;
        while (getline(file, line)) {
            std::cout << line << std::endl;
        }
        file.close();
    }
}

// 8. Double free vulnerability
void doubleFree() {
    char* ptr = (char*)malloc(100);
    free(ptr);
    free(ptr);  // Freeing already freed memory
}

// 9. Memory leak
void memoryLeak() {
    for (int i = 0; i < 1000; i++) {
        char* leak = (char*)malloc(1024);
        // Not freeing allocated memory
    }
}

// 10. Uninitialized variable usage
void uninitializedVar() {
    int x;  // Uninitialized
    int y = x + 10;  // Using uninitialized variable
    std::cout << "Result: " << y << std::endl;
}

// 11. Race condition (basic example)
#include <thread>
int shared_counter = 0;

void raceCondition() {
    // Multiple threads accessing shared resource without synchronization
    for (int i = 0; i < 1000; ++i) {
        shared_counter++;  // Not thread-safe
    }
}

// 12. Hardcoded credentials
const char* API_KEY = "sk-1234567890abcdef";
const char* DB_PASSWORD = "admin123";

int main() {
    // Example usage (commented to prevent actual execution)
    // bufferOverflow("This is a very long string that will overflow the buffer");
    // commandInjection("file.txt; rm -rf /");

    std::cout << "Vulnerable C++ examples compiled successfully" << std::endl;
    return 0;
}
