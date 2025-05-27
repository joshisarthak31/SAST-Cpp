#include <iostream>
#include <cstring>
#include <cstdlib>

int main() {
    char buffer[100];
    char* password = "secret123";        // hardcoded credential
    char* input = "user_input_data";
    
    strcpy(buffer, input);               // unsafe function
    system("ls -la");                    // dangerous OS call
    
    int* ptr = new int[100];            // memory leak
    return 0;
}