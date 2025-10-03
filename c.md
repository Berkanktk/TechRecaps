# C Programming Learning Guide

## Table of Contents

1. [C Basics](#c-basics)
   1. [What is C](#what-is-c)
   2. [Hello World](#hello-world)
   3. [Data Types and Variables](#data-types-and-variables)
   4. [Constants](#constants)
2. [Operators](#operators)
   1. [Arithmetic Operators](#arithmetic-operators)
   2. [Comparison Operators](#comparison-operators)
   3. [Logical Operators](#logical-operators)
   4. [Bitwise Operators](#bitwise-operators)
3. [Control Flow](#control-flow)
   1. [Conditional Statements](#conditional-statements)
   2. [Loops](#loops)
   3. [Switch Statement](#switch-statement)
   4. [Break and Continue](#break-and-continue)
4. [Input and Output](#input-and-output)
   1. [printf and scanf](#printf-and-scanf)
   2. [Character I/O](#character-io)
   3. [Formatted Output](#formatted-output)
   4. [Input Validation](#input-validation)
5. [Arrays and Strings](#arrays-and-strings)
   1. [Arrays](#arrays)
   2. [Multidimensional Arrays](#multidimensional-arrays)
   3. [Strings](#strings)
   4. [String Functions](#string-functions)
6. [Functions](#functions)
   1. [Function Declaration](#function-declaration)
   2. [Parameters and Arguments](#parameters-and-arguments)
   3. [Return Values](#return-values)
   4. [Scope and Storage Classes](#scope-and-storage-classes)
7. [Pointers](#pointers)
   1. [Pointer Basics](#pointer-basics)
   2. [Pointer Arithmetic](#pointer-arithmetic)
   3. [Pointers and Arrays](#pointers-and-arrays)
   4. [Pointers and Functions](#pointers-and-functions)
8. [Memory Management](#memory-management)
   1. [Static vs Dynamic Allocation](#static-vs-dynamic-allocation)
   2. [malloc and free](#malloc-and-free)
   3. [Memory Leaks](#memory-leaks)
   4. [Common Memory Errors](#common-memory-errors)

---

## C Basics

### What is C

**C** is a general-purpose, procedural programming language developed by Dennis Ritchie at Bell Labs in 1972.

**Key Features:**
- Low-level access to memory
- Efficient and fast execution
- Portable across platforms
- Foundation for many other languages
- Manual memory management
- Minimal runtime overhead

**C Program Structure:**
```c
#include <stdio.h>    // Preprocessor directive

int main() {          // Main function
    // Program code
    return 0;         // Return status
}
```

### Hello World

```c
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```

**Compilation Process:**
```bash
gcc hello.c -o hello    # Compile
./hello                 # Run (Linux/Mac)
hello.exe              # Run (Windows)
```

**Program Breakdown:**
- `#include <stdio.h>` - Include standard I/O library
- `int main()` - Entry point, returns integer
- `printf()` - Print formatted output
- `return 0` - Indicate successful execution
- `\n` - Newline character

### Data Types and Variables

```c
#include <stdio.h>

int main() {
    // Integer types
    char c = 'A';              // 1 byte (-128 to 127)
    unsigned char uc = 255;     // 1 byte (0 to 255)
    short s = 32767;           // 2 bytes (-32,768 to 32,767)
    unsigned short us = 65535;  // 2 bytes (0 to 65,535)
    int i = 2147483647;        // 4 bytes (-2^31 to 2^31-1)
    unsigned int ui = 4294967295U; // 4 bytes (0 to 2^32-1)
    long l = 9223372036854775807L; // 8 bytes
    unsigned long ul = 18446744073709551615UL; // 8 bytes
    
    // Floating point types
    float f = 3.14f;           // 4 bytes (6-7 decimal digits)
    double d = 3.141592653589793; // 8 bytes (15-17 decimal digits)
    long double ld = 3.141592653589793238L; // 16 bytes
    
    // Boolean (C99 and later)
    _Bool flag = 1;            // 0 or 1
    
    // Display sizes and values
    printf("char: %d bytes, value: %c (%d)\n", sizeof(char), c, c);
    printf("int: %d bytes, value: %d\n", sizeof(int), i);
    printf("float: %d bytes, value: %.2f\n", sizeof(float), f);
    printf("double: %d bytes, value: %.15f\n", sizeof(double), d);
    
    // Variable declaration and initialization
    int x;          // Declaration
    x = 10;         // Assignment
    int y = 20;     // Declaration + initialization
    int a = 5, b = 3, c = 8; // Multiple variables
    
    // Type conversion
    int num1 = 10;
    int num2 = 3;
    float result = (float)num1 / num2; // Explicit casting
    printf("10 / 3 = %.2f\n", result);
    
    // Automatic type promotion
    char ch = 100;
    int sum = ch + 1; // char promoted to int
    printf("char + int = %d\n", sum);
    
    return 0;
}
```

### Constants

```c
#include <stdio.h>

// Preprocessor constants
#define PI 3.14159
#define MAX_SIZE 100
#define GREETING "Hello"

int main() {
    // const keyword
    const int MAX_STUDENTS = 50;
    const float GRAVITY = 9.81f;
    const char GRADE = 'A';
    
    // Literal constants
    int decimal = 42;          // Decimal
    int octal = 052;           // Octal (starts with 0)
    int hex = 0x2A;            // Hexadecimal (starts with 0x)
    int binary = 0b101010;     // Binary (GCC extension)
    
    float pi = 3.14f;          // Float literal
    double e = 2.718281828;    // Double literal
    char newline = '\n';       // Character literal
    char* message = "Hello";   // String literal
    
    // Escape sequences
    printf("Common escape sequences:\n");
    printf("Newline: \\n\n");
    printf("Tab: \\t\tTabbed text\n");
    printf("Backslash: \\\\\n");
    printf("Quote: \"Hello\"\n");
    printf("Single quote: \'A\'\n");
    printf("Null character: \\0 (ASCII value: %d)\n", '\0');
    
    // Using constants
    printf("PI = %.5f\n", PI);
    printf("Circle area (r=5): %.2f\n", PI * 5 * 5);
    printf("Max students: %d\n", MAX_STUDENTS);
    
    // Enumeration constants
    enum weekday {
        MONDAY = 1,    // Explicitly set to 1
        TUESDAY,       // 2
        WEDNESDAY,     // 3
        THURSDAY,      // 4
        FRIDAY,        // 5
        SATURDAY,      // 6
        SUNDAY         // 7
    };
    
    enum weekday today = FRIDAY;
    printf("Today is day %d of the week\n", today);
    
    return 0;
}
```

---

## Operators

### Arithmetic Operators

```c
#include <stdio.h>

int main() {
    int a = 15, b = 4;
    float x = 15.0, y = 4.0;
    
    // Basic arithmetic
    printf("a = %d, b = %d\n", a, b);
    printf("Addition: %d + %d = %d\n", a, b, a + b);
    printf("Subtraction: %d - %d = %d\n", a, b, a - b);
    printf("Multiplication: %d * %d = %d\n", a, b, a * b);
    printf("Division (int): %d / %d = %d\n", a, b, a / b);
    printf("Division (float): %.1f / %.1f = %.2f\n", x, y, x / y);
    printf("Modulo: %d %% %d = %d\n", a, b, a % b);
    
    // Increment and decrement
    int count = 5;
    printf("\nIncrement/Decrement:\n");
    printf("count = %d\n", count);
    printf("++count = %d (pre-increment)\n", ++count);   // count becomes 6, returns 6
    printf("count++ = %d (post-increment)\n", count++);  // returns 6, count becomes 7
    printf("count = %d\n", count);
    printf("--count = %d (pre-decrement)\n", --count);   // count becomes 6, returns 6
    printf("count-- = %d (post-decrement)\n", count--);  // returns 6, count becomes 5
    printf("count = %d\n", count);
    
    // Compound assignment operators
    int num = 10;
    printf("\nCompound assignment:\n");
    printf("num = %d\n", num);
    num += 5;  // num = num + 5
    printf("After num += 5: %d\n", num);
    num -= 3;  // num = num - 3
    printf("After num -= 3: %d\n", num);
    num *= 2;  // num = num * 2
    printf("After num *= 2: %d\n", num);
    num /= 4;  // num = num / 4
    printf("After num /= 4: %d\n", num);
    num %= 3;  // num = num % 3
    printf("After num %%= 3: %d\n", num);
    
    // Operator precedence
    int result = 2 + 3 * 4;  // Multiplication first
    printf("\n2 + 3 * 4 = %d (not 20)\n", result);
    result = (2 + 3) * 4;    // Parentheses override precedence
    printf("(2 + 3) * 4 = %d\n", result);
    
    return 0;
}
```

### Comparison Operators

```c
#include <stdio.h>

int main() {
    int a = 10, b = 20, c = 10;
    
    printf("a = %d, b = %d, c = %d\n", a, b, c);
    
    // Comparison operators (return 1 for true, 0 for false)
    printf("\nComparison operators:\n");
    printf("a == b: %d\n", a == b);  // Equal to
    printf("a != b: %d\n", a != b);  // Not equal to
    printf("a < b: %d\n", a < b);    // Less than
    printf("a > b: %d\n", a > b);    // Greater than
    printf("a <= c: %d\n", a <= c);  // Less than or equal to
    printf("a >= c: %d\n", a >= c);  // Greater than or equal to
    
    // Comparing different types
    float f = 10.0;
    printf("\nComparing int and float:\n");
    printf("a == f: %d\n", a == f);  // 10 == 10.0 is true
    
    // Character comparisons (ASCII values)
    char ch1 = 'A', ch2 = 'B';
    printf("\nCharacter comparisons:\n");
    printf("'A' < 'B': %d\n", ch1 < ch2);  // 65 < 66
    printf("'A' == 65: %d\n", ch1 == 65);  // ASCII value of 'A'
    
    // String comparison (pointer comparison, not content!)
    char* str1 = "hello";
    char* str2 = "hello";
    char* str3 = "world";
    printf("\nString pointer comparison:\n");
    printf("str1 == str2: %d (may be optimized)\n", str1 == str2);
    printf("str1 == str3: %d\n", str1 == str3);
    
    // Chained comparisons (be careful!)
    int x = 5;
    // This is NOT like math: 1 < x < 10
    // It's evaluated as: (1 < x) < 10, which becomes 1 < 10 = 1
    printf("\nChained comparison gotcha:\n");
    printf("1 < %d < 10 evaluates as: %d\n", x, 1 < x < 10);
    printf("Correct way: %d\n", (1 < x) && (x < 10));
    
    return 0;
}
```

### Logical Operators

```c
#include <stdio.h>

int main() {
    int a = 1, b = 0, c = 5;
    
    printf("a = %d (true), b = %d (false), c = %d\n", a, b, c);
    
    // Logical AND (&&)
    printf("\nLogical AND (&&):\n");
    printf("a && b: %d\n", a && b);     // 1 && 0 = 0
    printf("a && c: %d\n", a && c);     // 1 && 5 = 1 (any non-zero is true)
    printf("b && c: %d\n", b && c);     // 0 && 5 = 0
    
    // Logical OR (||)
    printf("\nLogical OR (||):\n");
    printf("a || b: %d\n", a || b);     // 1 || 0 = 1
    printf("a || c: %d\n", a || c);     // 1 || 5 = 1
    printf("b || b: %d\n", b || b);     // 0 || 0 = 0
    
    // Logical NOT (!)
    printf("\nLogical NOT (!):\n");
    printf("!a: %d\n", !a);             // !1 = 0
    printf("!b: %d\n", !b);             // !0 = 1
    printf("!c: %d\n", !c);             // !5 = 0 (any non-zero becomes 0)
    printf("!!c: %d\n", !!c);           // !!5 = 1 (double negation)
    
    // Short-circuit evaluation
    printf("\nShort-circuit evaluation:\n");
    int x = 0, y = 0;
    
    // In AND, if first is false, second is not evaluated
    if (x && ++y) {
        printf("This won't print\n");
    }
    printf("After x && ++y: x = %d, y = %d\n", x, y);  // y is still 0
    
    // In OR, if first is true, second is not evaluated
    x = 1;
    if (x || ++y) {
        printf("This will print\n");
    }
    printf("After x || ++y: x = %d, y = %d\n", x, y);  // y is still 0
    
    // Practical examples
    printf("\nPractical examples:\n");
    int age = 20;
    int hasLicense = 1;
    
    if (age >= 18 && hasLicense) {
        printf("Can drive\n");
    }
    
    int temperature = 25;
    if (temperature < 0 || temperature > 40) {
        printf("Extreme weather!\n");
    } else {
        printf("Normal weather\n");
    }
    
    // Converting to boolean
    int num = 42;
    int is_positive = num > 0;  // 1 if true, 0 if false
    printf("Is %d positive? %d\n", num, is_positive);
    
    return 0;
}
```

### Bitwise Operators

```c
#include <stdio.h>

// Function to print binary representation
void print_binary(unsigned int n) {
    for (int i = 7; i >= 0; i--) {
        printf("%d", (n >> i) & 1);
    }
}

int main() {
    unsigned int a = 60;   // 00111100 in binary
    unsigned int b = 13;   // 00001101 in binary
    
    printf("a = %u (", a);
    print_binary(a);
    printf(")\n");
    
    printf("b = %u (", b);
    print_binary(b);
    printf(")\n\n");
    
    // Bitwise AND (&)
    unsigned int and_result = a & b;  // 00001100 = 12
    printf("a & b = %u (", and_result);
    print_binary(and_result);
    printf(")\n");
    
    // Bitwise OR (|)
    unsigned int or_result = a | b;   // 00111101 = 61
    printf("a | b = %u (", or_result);
    print_binary(or_result);
    printf(")\n");
    
    // Bitwise XOR (^)
    unsigned int xor_result = a ^ b;  // 00110001 = 49
    printf("a ^ b = %u (", xor_result);
    print_binary(xor_result);
    printf(")\n");
    
    // Bitwise NOT (~)
    unsigned int not_a = ~a;  // Flips all bits
    printf("~a = %u (", not_a & 0xFF);  // Show only 8 bits
    print_binary(not_a & 0xFF);
    printf(")\n");
    
    // Left shift (<<)
    unsigned int left_shift = a << 2;  // Multiply by 2^2 = 4
    printf("a << 2 = %u (", left_shift);
    print_binary(left_shift & 0xFF);
    printf(")\n");
    
    // Right shift (>>)
    unsigned int right_shift = a >> 2; // Divide by 2^2 = 4
    printf("a >> 2 = %u (", right_shift);
    print_binary(right_shift);
    printf(")\n");
    
    // Practical applications
    printf("\nPractical applications:\n");
    
    // Check if number is even or odd
    int num = 15;
    if (num & 1) {
        printf("%d is odd\n", num);
    } else {
        printf("%d is even\n", num);
    }
    
    // Set a specific bit (set 3rd bit)
    int value = 8;  // 1000
    value |= (1 << 2);  // Set bit at position 2
    printf("After setting bit 2: %d\n", value);  // 1100 = 12
    
    // Clear a specific bit (clear 3rd bit)
    value &= ~(1 << 3);  // Clear bit at position 3
    printf("After clearing bit 3: %d\n", value);  // 0100 = 4
    
    // Toggle a specific bit
    value ^= (1 << 1);  // Toggle bit at position 1
    printf("After toggling bit 1: %d\n", value);  // 0110 = 6
    
    // Check if a bit is set
    int bit_position = 2;
    if (value & (1 << bit_position)) {
        printf("Bit %d is set\n", bit_position);
    } else {
        printf("Bit %d is not set\n", bit_position);
    }
    
    // Multiply/divide by powers of 2
    int n = 10;
    printf("%d * 8 = %d (using << 3)\n", n, n << 3);
    printf("%d / 4 = %d (using >> 2)\n", n, n >> 2);
    
    return 0;
}
```

---

## Control Flow

### Conditional Statements

```c
#include <stdio.h>

int main() {
    // Simple if statement
    int score = 85;
    
    if (score >= 90) {
        printf("Excellent! Grade A\n");
    }
    
    // if-else statement
    if (score >= 60) {
        printf("You passed!\n");
    } else {
        printf("You failed. Study harder!\n");
    }
    
    // if-else-if ladder
    printf("Grade: ");
    if (score >= 90) {
        printf("A\n");
    } else if (score >= 80) {
        printf("B\n");
    } else if (score >= 70) {
        printf("C\n");
    } else if (score >= 60) {
        printf("D\n");
    } else {
        printf("F\n");
    }
    
    // Nested if statements
    int age = 20;
    int hasLicense = 1;
    
    if (age >= 18) {
        if (hasLicense) {
            printf("You can drive!\n");
        } else {
            printf("You need a license to drive.\n");
        }
    } else {
        printf("You're too young to drive.\n");
    }
    
    // Logical operators in conditions
    int temperature = 25;
    int isSunny = 1;
    
    if (temperature > 20 && isSunny) {
        printf("Perfect weather for a picnic!\n");
    }
    
    if (temperature < 0 || temperature > 40) {
        printf("Extreme weather conditions!\n");
    }
    
    // Ternary operator (conditional operator)
    int a = 10, b = 20;
    int max = (a > b) ? a : b;
    printf("Maximum of %d and %d is %d\n", a, b, max);
    
    char* status = (score >= 60) ? "Pass" : "Fail";
    printf("Status: %s\n", status);
    
    // Multiple conditions with ternary
    char grade = (score >= 90) ? 'A' : 
                 (score >= 80) ? 'B' :
                 (score >= 70) ? 'C' :
                 (score >= 60) ? 'D' : 'F';
    printf("Grade using ternary: %c\n", grade);
    
    // Common mistakes and gotchas
    int x = 5;
    
    // Assignment vs comparison
    if (x = 10) {  // This assigns 10 to x, then evaluates to true!
        printf("This will always execute (x is now %d)\n", x);
    }
    
    // Correct comparison
    x = 5;  // Reset x
    if (x == 10) {
        printf("This won't execute\n");
    } else {
        printf("x is %d, not 10\n", x);
    }
    
    // Floating point comparison
    float f1 = 0.1 + 0.2;
    float f2 = 0.3;
    if (f1 == f2) {
        printf("Equal\n");
    } else {
        printf("Not equal due to floating point precision\n");
        printf("f1 = %.15f\n", f1);
        printf("f2 = %.15f\n", f2);
    }
    
    // Better floating point comparison
    #include <math.h>
    const float EPSILON = 0.00001f;
    if (fabs(f1 - f2) < EPSILON) {
        printf("Close enough to be considered equal\n");
    }
    
    return 0;
}
```

### Loops

```c
#include <stdio.h>

int main() {
    // for loop
    printf("for loop (0 to 4):\n");
    for (int i = 0; i < 5; i++) {
        printf("%d ", i);
    }
    printf("\n");
    
    // for loop with different increment
    printf("Counting down from 10 to 0 by 2:\n");
    for (int i = 10; i >= 0; i -= 2) {
        printf("%d ", i);
    }
    printf("\n");
    
    // Multiple variables in for loop
    printf("Multiple variables:\n");
    for (int i = 0, j = 10; i < 5; i++, j--) {
        printf("i=%d, j=%d  ", i, j);
    }
    printf("\n");
    
    // while loop
    printf("\nwhile loop (factorial of 5):\n");
    int n = 5;
    int factorial = 1;
    int temp = n;
    while (temp > 0) {
        factorial *= temp;
        temp--;
    }
    printf("%d! = %d\n", n, factorial);
    
    // do-while loop (executes at least once)
    printf("\ndo-while loop:\n");
    int count = 0;
    do {
        printf("Count: %d\n", count);
        count++;
    } while (count < 3);
    
    // do-while with user input simulation
    printf("\nPassword checker simulation:\n");
    char password[] = "secret";
    char input[] = "wrong";
    int attempts = 0;
    
    do {
        attempts++;
        printf("Attempt %d: Checking password '%s'\n", attempts, input);
        if (attempts == 2) {
            strcpy(input, "secret");  // Simulate correct password on 2nd try
        }
    } while (strcmp(input, password) != 0 && attempts < 3);
    
    if (strcmp(input, password) == 0) {
        printf("Access granted!\n");
    } else {
        printf("Access denied!\n");
    }
    
    // Nested loops - multiplication table
    printf("\nMultiplication table (5x5):\n");
    for (int i = 1; i <= 5; i++) {
        for (int j = 1; j <= 5; j++) {
            printf("%2d ", i * j);
        }
        printf("\n");
    }
    
    // Infinite loop with break
    printf("\nFinding first perfect square > 50:\n");
    int num = 1;
    while (1) {  // Infinite loop
        int square = num * num;
        if (square > 50) {
            printf("First perfect square > 50 is %d (%d^2)\n", square, num);
            break;
        }
        num++;
    }
    
    // continue statement
    printf("\nPrinting odd numbers from 1 to 10:\n");
    for (int i = 1; i <= 10; i++) {
        if (i % 2 == 0) {
            continue;  // Skip even numbers
        }
        printf("%d ", i);
    }
    printf("\n");
    
    return 0;
}
```

### Switch Statement

```c
#include <stdio.h>

int main() {
    // Basic switch statement
    int dayOfWeek = 3;
    
    printf("Day %d is: ", dayOfWeek);
    switch (dayOfWeek) {
        case 1:
            printf("Monday");
            break;
        case 2:
            printf("Tuesday");
            break;
        case 3:
            printf("Wednesday");
            break;
        case 4:
            printf("Thursday");
            break;
        case 5:
            printf("Friday");
            break;
        case 6:
            printf("Saturday");
            break;
        case 7:
            printf("Sunday");
            break;
        default:
            printf("Invalid day");
            break;
    }
    printf("\n");
    
    // Switch with character
    char grade = 'B';
    printf("Grade %c: ", grade);
    switch (grade) {
        case 'A':
        case 'a':
            printf("Excellent!");
            break;
        case 'B':
        case 'b':
            printf("Good job!");
            break;
        case 'C':
        case 'c':
            printf("Satisfactory");
            break;
        case 'D':
        case 'd':
            printf("Needs improvement");
            break;
        case 'F':
        case 'f':
            printf("Failed");
            break;
        default:
            printf("Invalid grade");
    }
    printf("\n");
    
    // Fall-through behavior (missing breaks)
    int month = 2;
    int days;
    
    printf("Month %d has ", month);
    switch (month) {
        case 1: case 3: case 5: case 7: case 8: case 10: case 12:
            days = 31;
            break;
        case 4: case 6: case 9: case 11:
            days = 30;
            break;
        case 2:
            days = 28;  // Simplified, not considering leap years
            break;
        default:
            days = 0;
            printf("Invalid month\n");
            return 1;
    }
    printf("%d days\n", days);
    
    // Switch for simple calculator
    printf("\nSimple calculator:\n");
    float num1 = 10.0, num2 = 3.0;
    char operator = '/';
    float result;
    
    printf("%.1f %c %.1f = ", num1, operator, num2);
    switch (operator) {
        case '+':
            result = num1 + num2;
            printf("%.1f\n", result);
            break;
        case '-':
            result = num1 - num2;
            printf("%.1f\n", result);
            break;
        case '*':
            result = num1 * num2;
            printf("%.1f\n", result);
            break;
        case '/':
            if (num2 != 0) {
                result = num1 / num2;
                printf("%.2f\n", result);
            } else {
                printf("Error: Division by zero\n");
            }
            break;
        case '%':
            if (num2 != 0) {
                result = (int)num1 % (int)num2;
                printf("%.0f\n", result);
            } else {
                printf("Error: Division by zero\n");
            }
            break;
        default:
            printf("Error: Unknown operator\n");
    }
    
    // Nested switch (not recommended, but possible)
    int category = 1;
    int subcategory = 2;
    
    switch (category) {
        case 1:
            printf("Electronics - ");
            switch (subcategory) {
                case 1: printf("Computers"); break;
                case 2: printf("Phones"); break;
                case 3: printf("Tablets"); break;
                default: printf("Other electronics");
            }
            break;
        case 2:
            printf("Books - ");
            switch (subcategory) {
                case 1: printf("Fiction"); break;
                case 2: printf("Non-fiction"); break;
                case 3: printf("Technical"); break;
                default: printf("Other books");
            }
            break;
        default:
            printf("Unknown category");
    }
    printf("\n");
    
    return 0;
}
```

### Break and Continue

```c
#include <stdio.h>

int main() {
    // break in loops
    printf("Break example - finding first number divisible by 7:\n");
    for (int i = 1; i <= 100; i++) {
        if (i % 7 == 0) {
            printf("First number divisible by 7: %d\n", i);
            break;  // Exit the loop immediately
        }
    }
    
    // continue in loops
    printf("\nContinue example - odd numbers from 1 to 10:\n");
    for (int i = 1; i <= 10; i++) {
        if (i % 2 == 0) {
            continue;  // Skip the rest of this iteration
        }
        printf("%d ", i);
    }
    printf("\n");
    
    // break in nested loops (only breaks innermost loop)
    printf("\nBreak in nested loops:\n");
    for (int i = 1; i <= 3; i++) {
        printf("Outer loop i = %d\n", i);
        for (int j = 1; j <= 5; j++) {
            if (j == 3) {
                printf("  Breaking inner loop at j = %d\n", j);
                break;  // Only breaks inner loop
            }
            printf("  Inner loop j = %d\n", j);
        }
    }
    
    // Using goto for breaking out of nested loops
    printf("\nUsing goto to break out of nested loops:\n");
    for (int i = 1; i <= 3; i++) {
        for (int j = 1; j <= 3; j++) {
            if (i == 2 && j == 2) {
                printf("Breaking out of both loops at i=%d, j=%d\n", i, j);
                goto end_loops;  // Jump out of both loops
            }
            printf("i=%d, j=%d\n", i, j);
        }
    }
    end_loops:
    printf("After nested loops\n");
    
    // Alternative to goto: using flag variable
    printf("\nUsing flag to break out of nested loops:\n");
    int should_break = 0;
    for (int i = 1; i <= 3 && !should_break; i++) {
        for (int j = 1; j <= 3; j++) {
            if (i == 2 && j == 2) {
                printf("Setting flag at i=%d, j=%d\n", i, j);
                should_break = 1;
                break;
            }
            printf("i=%d, j=%d\n", i, j);
        }
    }
    
    // continue with nested loops
    printf("\nContinue in nested loops:\n");
    for (int i = 1; i <= 3; i++) {
        printf("Outer loop i = %d:\n", i);
        for (int j = 1; j <= 5; j++) {
            if (j == 3) {
                continue;  // Skip j=3, continue with j=4
            }
            printf("  j = %d\n", j);
        }
    }
    
    // Practical example: Input validation
    printf("\nInput validation example (simulated):\n");
    int numbers[] = {5, -2, 0, 8, -1, 3, 0, 7};  // Simulated input
    int size = sizeof(numbers) / sizeof(numbers[0]);
    int sum = 0;
    int count = 0;
    
    for (int i = 0; i < size; i++) {
        int num = numbers[i];
        printf("Processing number: %d\n", num);
        
        if (num == 0) {
            printf("  Zero encountered, stopping processing\n");
            break;  // Stop processing when we hit zero
        }
        
        if (num < 0) {
            printf("  Negative number, skipping\n");
            continue;  // Skip negative numbers
        }
        
        sum += num;
        count++;
        printf("  Added to sum. Current sum: %d\n", sum);
    }
    
    if (count > 0) {
        printf("Average of positive numbers: %.2f\n", (float)sum / count);
    } else {
        printf("No positive numbers found\n");
    }
    
    return 0;
}
```

---

## Input and Output

### printf and scanf

```c
#include <stdio.h>

int main() {
    // Basic printf
    printf("Hello, World!\n");
    
    // Format specifiers
    int age = 25;
    float height = 5.9f;
    char grade = 'A';
    char name[] = "Alice";
    
    printf("Name: %s\n", name);
    printf("Age: %d years\n", age);
    printf("Height: %.1f feet\n", height);
    printf("Grade: %c\n", grade);
    
    // Different integer formats
    int num = 255;
    printf("Decimal: %d\n", num);
    printf("Octal: %o\n", num);
    printf("Hexadecimal: %x\n", num);
    printf("Hexadecimal (uppercase): %X\n", num);
    
    // Different float formats
    float pi = 3.141592653589793f;
    printf("Default: %f\n", pi);
    printf("2 decimals: %.2f\n", pi);
    printf("Scientific: %e\n", pi);
    printf("Scientific (uppercase): %E\n", pi);
    printf("Shorter of %f or %e: %g\n", pi);
    
    // Field width and alignment
    printf("Field width examples:\n");
    printf("|%10d|\n", 123);        // Right-aligned in 10 chars
    printf("|%-10d|\n", 123);       // Left-aligned in 10 chars
    printf("|%010d|\n", 123);       // Zero-padded
    printf("|%10.2f|\n", 3.14);     // Float with field width
    printf("|%-10.2f|\n", 3.14);    // Left-aligned float
    
    // Basic scanf
    printf("\nInput examples (simulated):\n");
    
    // Simulating user input for demonstration
    // In real programs, these would read from keyboard
    int user_age;
    float user_height;
    char user_grade;
    char user_name[50];
    
    // scanf("%d", &user_age);         // Read integer
    // scanf("%f", &user_height);      // Read float
    // scanf(" %c", &user_grade);      // Read character (note the space)
    // scanf("%s", user_name);         // Read string (no & needed for arrays)
    
    // For demonstration, let's assign values
    user_age = 30;
    user_height = 6.2f;
    user_grade = 'B';
    strcpy(user_name, "Bob");
    
    printf("You entered:\n");
    printf("Name: %s\n", user_name);
    printf("Age: %d\n", user_age);
    printf("Height: %.1f\n", user_height);
    printf("Grade: %c\n", user_grade);
    
    // scanf return value
    printf("\nscanf return value example:\n");
    char input_string[] = "42 3.14 hello";
    int items_read;
    int int_val;
    float float_val;
    char str_val[20];
    
    // Simulate scanf with sscanf (string scanf)
    items_read = sscanf(input_string, "%d %f %s", &int_val, &float_val, str_val);
    printf("Items successfully read: %d\n", items_read);
    printf("Integer: %d, Float: %.2f, String: %s\n", int_val, float_val, str_val);
    
    // Common scanf pitfalls
    printf("\nCommon scanf issues:\n");
    
    // 1. Leftover newlines
    printf("When mixing scanf with getchar, watch for newlines\n");
    
    // 2. Buffer overflow with %s
    printf("Use field width to prevent overflow: scanf(\"%%49s\", str)\n");
    
    // 3. No error checking
    printf("Always check scanf return value\n");
    
    return 0;
}
```

### Character I/O

```c
#include <stdio.h>
#include <ctype.h>

int main() {
    // Character input/output functions
    printf("Character I/O examples:\n");
    
    // getchar() and putchar()
    printf("Using putchar to display characters:\n");
    putchar('H');
    putchar('e');
    putchar('l');
    putchar('l');
    putchar('o');
    putchar('\n');
    
    // Reading and echoing characters (simulated)
    printf("\nSimulating character input:\n");
    char input_string[] = "Hello World!\n";
    int i = 0;
    char ch;
    
    printf("Input: %s", input_string);
    printf("Character by character processing:\n");
    
    while (input_string[i] != '\0') {
        ch = input_string[i];
        printf("Read: ");
        
        if (ch == '\n') {
            printf("'\\n' (newline)");
        } else if (ch == ' ') {
            printf("' ' (space)");
        } else {
            printf("'%c'", ch);
        }
        
        printf(" -> ");
        
        // Process the character
        if (isalpha(ch)) {
            printf("Letter ");
            if (islower(ch)) {
                printf("(lowercase) -> uppercase: %c", toupper(ch));
            } else {
                printf("(uppercase) -> lowercase: %c", tolower(ch));
            }
        } else if (isdigit(ch)) {
            printf("Digit");
        } else if (isspace(ch)) {
            printf("Whitespace");
        } else if (ispunct(ch)) {
            printf("Punctuation");
        } else {
            printf("Other");
        }
        
        printf("\n");
        i++;
    }
    
    // Character classification functions
    printf("\nCharacter classification:\n");
    char test_chars[] = "A1a! \t\n";
    
    for (int j = 0; test_chars[j] != '\0'; j++) {
        char c = test_chars[j];
        printf("'%c': ", c);
        
        if (c == ' ') printf("' ': ");
        else if (c == '\t') printf("'\\t': ");
        else if (c == '\n') printf("'\\n': ");
        
        printf("alpha:%d digit:%d lower:%d upper:%d space:%d punct:%d\n",
               isalpha(c), isdigit(c), islower(c), isupper(c), isspace(c), ispunct(c));
    }
    
    // Simple text processing example
    printf("\nText processing example:\n");
    char text[] = "Hello, World! 123";
    int letters = 0, digits = 0, spaces = 0, others = 0;
    
    printf("Processing: \"%s\"\n", text);
    
    for (int k = 0; text[k] != '\0'; k++) {
        if (isalpha(text[k])) {
            letters++;
        } else if (isdigit(text[k])) {
            digits++;
        } else if (isspace(text[k])) {
            spaces++;
        } else {
            others++;
        }
    }
    
    printf("Letters: %d, Digits: %d, Spaces: %d, Others: %d\n",
           letters, digits, spaces, others);
    
    // Case conversion
    printf("\nCase conversion:\n");
    char sentence[] = "ThIs Is A MiXeD cAsE sEnTeNcE";
    printf("Original: %s\n", sentence);
    
    // Convert to uppercase
    printf("Uppercase: ");
    for (int m = 0; sentence[m] != '\0'; m++) {
        putchar(toupper(sentence[m]));
    }
    printf("\n");
    
    // Convert to lowercase
    printf("Lowercase: ");
    for (int n = 0; sentence[n] != '\0'; n++) {
        putchar(tolower(sentence[n]));
    }
    printf("\n");
    
    // Toggle case
    printf("Toggled: ");
    for (int o = 0; sentence[o] != '\0'; o++) {
        if (islower(sentence[o])) {
            putchar(toupper(sentence[o]));
        } else if (isupper(sentence[o])) {
            putchar(tolower(sentence[o]));
        } else {
            putchar(sentence[o]);
        }
    }
    printf("\n");
    
    return 0;
}
```

### Formatted Output

```c
#include <stdio.h>

int main() {
    // Advanced printf formatting
    
    // Width and precision
    printf("=== Width and Precision ===\n");
    int num = 42;
    float pi = 3.141592653589793f;
    
    printf("Default: %d\n", num);
    printf("Width 10: '%10d'\n", num);
    printf("Width 10, left-aligned: '%-10d'\n", num);
    printf("Width 10, zero-padded: '%010d'\n", num);
    
    printf("\nFloat formatting:\n");
    printf("Default: %f\n", pi);
    printf("Precision 2: %.2f\n", pi);
    printf("Width 10, precision 2: '%10.2f'\n", pi);
    printf("Width 10, precision 2, left: '%-10.2f'\n", pi);
    printf("Scientific: %e\n", pi);
    printf("Scientific precision 3: %.3e\n", pi);
    printf("Auto format: %g\n", pi);
    
    // String formatting
    printf("\n=== String Formatting ===\n");
    char name[] = "Alice";
    printf("Default: '%s'\n", name);
    printf("Width 10: '%10s'\n", name);
    printf("Width 10, left-aligned: '%-10s'\n", name);
    printf("Precision 3: '%.3s'\n", name);
    printf("Width 10, precision 3: '%10.3s'\n", name);
    
    // Numeric bases
    printf("\n=== Numeric Bases ===\n");
    int value = 255;
    printf("Decimal: %d\n", value);
    printf("Octal: %o\n", value);
    printf("Octal with prefix: %#o\n", value);
    printf("Hex lowercase: %x\n", value);
    printf("Hex uppercase: %X\n", value);
    printf("Hex with prefix: %#x\n", value);
    printf("Hex uppercase with prefix: %#X\n", value);
    
    // Character and ASCII
    printf("\n=== Characters ===\n");
    char ch = 'A';
    printf("Character: %c\n", ch);
    printf("ASCII value: %d\n", ch);
    printf("Character from ASCII 66: %c\n", 66);
    
    // Pointers
    printf("\n=== Pointers ===\n");
    int var = 42;
    int* ptr = &var;
    printf("Variable value: %d\n", var);
    printf("Variable address: %p\n", (void*)ptr);
    printf("Pointer value: %p\n", (void*)ptr);
    printf("Pointer address: %p\n", (void*)&ptr);
    
    // Dynamic width and precision
    printf("\n=== Dynamic Width/Precision ===\n");
    int width = 15;
    int precision = 3;
    printf("Dynamic width %d: '%*d'\n", width, width, num);
    printf("Dynamic precision %d: '%.*f'\n", precision, precision, pi);
    printf("Both dynamic: '%*.*f'\n", width, precision, pi);
    
    // Flags
    printf("\n=== Flags ===\n");
    int pos = 42;
    int neg = -42;
    printf("Default: %d %d\n", pos, neg);
    printf("Always show sign: %+d %+d\n", pos, neg);
    printf("Space for positive: % d % d\n", pos, neg);
    printf("Left-align: '%-10d' '%-10d'\n", pos, neg);
    printf("Zero-pad: '%010d' '%010d'\n", pos, neg);
    
    // Special cases
    printf("\n=== Special Cases ===\n");
    printf("Percent sign: %%\n");
    printf("Zero: %d\n", 0);
    printf("Zero with + flag: %+d\n", 0);
    printf("Zero with space flag: % d\n", 0);
    
    // Large numbers
    printf("\n=== Large Numbers ===\n");
    long long big = 1234567890123456789LL;
    printf("Long long: %lld\n", big);
    printf("Long long hex: %llx\n", big);
    
    unsigned long long ubig = 18446744073709551615ULL;
    printf("Unsigned long long: %llu\n", ubig);
    
    // Practical formatting examples
    printf("\n=== Practical Examples ===\n");
    
    // Table formatting
    printf("%-10s %8s %8s %8s\n", "Name", "Age", "Height", "Weight");
    printf("%-10s %8s %8s %8s\n", "----", "---", "------", "------");
    printf("%-10s %8d %8.1f %8.1f\n", "Alice", 25, 5.6f, 120.5f);
    printf("%-10s %8d %8.1f %8.1f\n", "Bob", 30, 6.0f, 180.0f);
    printf("%-10s %8d %8.1f %8.1f\n", "Charlie", 28, 5.9f, 165.2f);
    
    // Money formatting
    printf("\nMoney formatting:\n");
    float price1 = 19.99f;
    float price2 = 5.5f;
    float price3 = 100.0f;
    printf("Price 1: $%6.2f\n", price1);
    printf("Price 2: $%6.2f\n", price2);
    printf("Price 3: $%6.2f\n", price3);
    
    // Progress bar simulation
    printf("\nProgress bars:\n");
    for (int progress = 0; progress <= 100; progress += 25) {
        printf("Progress: [");
        for (int i = 0; i < 20; i++) {
            if (i < progress / 5) {
                printf("=");
            } else {
                printf(" ");
            }
        }
        printf("] %3d%%\n", progress);
    }
    
    return 0;
}
```

### Input Validation

```c
#include <stdio.h>
#include <string.h>
#include <ctype.h>

// Function to clear input buffer
void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

// Function to get integer with validation
int get_integer(const char* prompt, int min, int max) {
    int value;
    int result;
    
    while (1) {
        printf("%s", prompt);
        result = scanf("%d", &value);
        
        if (result == 1) {  // Successfully read one integer
            if (value >= min && value <= max) {
                clear_input_buffer();  // Clear any remaining input
                return value;
            } else {
                printf("Error: Please enter a number between %d and %d.\n", min, max);
                clear_input_buffer();
            }
        } else {
            printf("Error: Please enter a valid integer.\n");
            clear_input_buffer();
        }
    }
}

// Function to get float with validation
float get_float(const char* prompt, float min, float max) {
    float value;
    int result;
    
    while (1) {
        printf("%s", prompt);
        result = scanf("%f", &value);
        
        if (result == 1) {
            if (value >= min && value <= max) {
                clear_input_buffer();
                return value;
            } else {
                printf("Error: Please enter a number between %.2f and %.2f.\n", min, max);
                clear_input_buffer();
            }
        } else {
            printf("Error: Please enter a valid number.\n");
            clear_input_buffer();
        }
    }
}

// Function to get string with validation
void get_string(const char* prompt, char* buffer, int max_length) {
    while (1) {
        printf("%s", prompt);
        
        if (fgets(buffer, max_length, stdin) != NULL) {
            // Remove newline if present
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len - 1] == '\n') {
                buffer[len - 1] = '\0';
            }
            
            // Check if string is not empty
            if (strlen(buffer) > 0) {
                return;
            } else {
                printf("Error: Please enter a non-empty string.\n");
            }
        } else {
            printf("Error: Failed to read input.\n");
            clear_input_buffer();
        }
    }
}

// Function to validate email (simple validation)
int is_valid_email(const char* email) {
    int at_count = 0;
    int dot_after_at = 0;
    int at_position = -1;
    
    // Basic checks
    if (strlen(email) < 5) return 0;  // Minimum: a@b.c
    
    for (int i = 0; email[i] != '\0'; i++) {
        if (email[i] == '@') {
            if (at_count > 0) return 0;  // Multiple @ symbols
            if (i == 0) return 0;        // @ at beginning
            at_count++;
            at_position = i;
        } else if (email[i] == '.' && at_position != -1 && i > at_position + 1) {
            dot_after_at = 1;
        }
    }
    
    return (at_count == 1 && dot_after_at && 
            email[strlen(email) - 1] != '.' && 
            email[strlen(email) - 1] != '@');
}

// Function to get validated email
void get_email(const char* prompt, char* email, int max_length) {
    while (1) {
        get_string(prompt, email, max_length);
        
        if (is_valid_email(email)) {
            return;
        } else {
            printf("Error: Please enter a valid email address.\n");
        }
    }
}

// Function to get yes/no answer
int get_yes_no(const char* prompt) {
    char answer[10];
    
    while (1) {
        printf("%s (y/n): ", prompt);
        
        if (fgets(answer, sizeof(answer), stdin) != NULL) {
            // Convert to lowercase
            for (int i = 0; answer[i]; i++) {
                answer[i] = tolower(answer[i]);
            }
            
            if (strncmp(answer, "y", 1) == 0 || strncmp(answer, "yes", 3) == 0) {
                return 1;
            } else if (strncmp(answer, "n", 1) == 0 || strncmp(answer, "no", 2) == 0) {
                return 0;
            } else {
                printf("Error: Please enter 'y' for yes or 'n' for no.\n");
            }
        } else {
            printf("Error: Failed to read input.\n");
            clear_input_buffer();
        }
    }
}

int main() {
    printf("=== Input Validation Examples ===\n\n");
    
    // For demonstration, we'll simulate the validation functions
    // In a real program, these would interact with actual user input
    
    printf("1. Integer validation:\n");
    printf("Simulating: get_integer(\"Enter age (1-120): \", 1, 120)\n");
    printf("Valid input '25' -> Age: 25\n");
    printf("Invalid input 'abc' -> Error: Please enter a valid integer.\n");
    printf("Invalid input '150' -> Error: Please enter a number between 1 and 120.\n\n");
    
    printf("2. Float validation:\n");
    printf("Simulating: get_float(\"Enter height (0.5-3.0): \", 0.5, 3.0)\n");
    printf("Valid input '1.75' -> Height: 1.75\n");
    printf("Invalid input '5.0' -> Error: Please enter a number between 0.50 and 3.00.\n\n");
    
    printf("3. String validation:\n");
    printf("Simulating: get_string(\"Enter name: \", buffer, 50)\n");
    printf("Valid input 'John Doe' -> Name: John Doe\n");
    printf("Invalid input '' -> Error: Please enter a non-empty string.\n\n");
    
    printf("4. Email validation:\n");
    char test_emails[][50] = {
        "user@example.com",
        "invalid.email",
        "@invalid.com",
        "user@",
        "user@domain.",
        "user@domain.c"
    };
    
    int num_emails = sizeof(test_emails) / sizeof(test_emails[0]);
    
    for (int i = 0; i < num_emails; i++) {
        printf("Email '%s' is %s\n", test_emails[i], 
               is_valid_email(test_emails[i]) ? "valid" : "invalid");
    }
    
    printf("\n5. Yes/No validation:\n");
    printf("Simulating: get_yes_no(\"Continue?\")\n");
    printf("Valid inputs: 'y', 'yes', 'Y', 'YES' -> 1 (true)\n");
    printf("Valid inputs: 'n', 'no', 'N', 'NO' -> 0 (false)\n");
    printf("Invalid input 'maybe' -> Error: Please enter 'y' for yes or 'n' for no.\n\n");
    
    // Demonstration of robust input handling
    printf("6. Common input problems and solutions:\n\n");
    
    printf("Problem: scanf leaves newline in buffer\n");
    printf("Solution: Use clear_input_buffer() after scanf\n\n");
    
    printf("Problem: Buffer overflow with gets()\n");
    printf("Solution: Use fgets() with size limit\n\n");
    
    printf("Problem: No validation of input range\n");
    printf("Solution: Check values after input and re-prompt if invalid\n\n");
    
    printf("Problem: Mixed data types causing issues\n");
    printf("Solution: Read everything as strings first, then parse\n\n");
    
    // Example of parsing approach
    printf("7. Safe parsing approach:\n");
    char input[] = "123";
    int parsed_value;
    char* endptr;
    
    parsed_value = strtol(input, &endptr, 10);
    
    if (*endptr == '\0' && endptr != input) {
        printf("Successfully parsed '%s' as integer: %d\n", input, parsed_value);
    } else {
        printf("Failed to parse '%s' as integer\n", input);
    }
    
    return 0;
}
```

## 5. Arrays

Arrays store multiple values of the same type in contiguous memory locations.

### Declaration and Initialization

```c
#include <stdio.h>

int main() {
    // Different ways to declare arrays
    int numbers[5];  // Uninitialized array of 5 integers
    int values[5] = {1, 2, 3, 4, 5};  // Initialized array
    int partial[5] = {1, 2};  // Partially initialized (rest are 0)
    int auto_size[] = {1, 2, 3, 4, 5};  // Size determined by initializer
    
    // Character arrays (strings)
    char name[20];  // Can hold up to 19 characters + null terminator
    char greeting[] = "Hello";  // Automatically sized
    char letters[] = {'H', 'i', '\0'};  // Manual character array
    
    // Printing array contents
    printf("values array: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", values[i]);
    }
    printf("\n");
    
    printf("greeting: %s\n", greeting);
    
    return 0;
}
```

### Array Operations

```c
#include <stdio.h>

int main() {
    int numbers[10] = {64, 34, 25, 12, 22, 11, 90, 5, 77, 30};
    int size = 10;
    
    // 1. Finding maximum and minimum
    int max = numbers[0], min = numbers[0];
    for (int i = 1; i < size; i++) {
        if (numbers[i] > max) max = numbers[i];
        if (numbers[i] < min) min = numbers[i];
    }
    printf("Max: %d, Min: %d\n", max, min);
    
    // 2. Sum and average
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += numbers[i];
    }
    printf("Sum: %d, Average: %.2f\n", sum, (float)sum / size);
    
    // 3. Reversing array
    printf("Original: ");
    for (int i = 0; i < size; i++) printf("%d ", numbers[i]);
    printf("\n");
    
    for (int i = 0; i < size / 2; i++) {
        int temp = numbers[i];
        numbers[i] = numbers[size - 1 - i];
        numbers[size - 1 - i] = temp;
    }
    
    printf("Reversed: ");
    for (int i = 0; i < size; i++) printf("%d ", numbers[i]);
    printf("\n");
    
    return 0;
}
```

### Searching Arrays

```c
#include <stdio.h>

// Linear search
int linear_search(int arr[], int size, int target) {
    for (int i = 0; i < size; i++) {
        if (arr[i] == target) {
            return i;  // Return index if found
        }
    }
    return -1;  // Return -1 if not found
}

// Binary search (requires sorted array)
int binary_search(int arr[], int size, int target) {
    int left = 0, right = size - 1;
    
    while (left <= right) {
        int mid = left + (right - left) / 2;
        
        if (arr[mid] == target) {
            return mid;
        } else if (arr[mid] < target) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return -1;
}

int main() {
    int numbers[] = {2, 5, 8, 12, 16, 23, 38, 45, 56, 67, 78};
    int size = 11;
    int target = 23;
    
    // Linear search
    int pos = linear_search(numbers, size, target);
    if (pos != -1) {
        printf("Linear search: Found %d at index %d\n", target, pos);
    } else {
        printf("Linear search: %d not found\n", target);
    }
    
    // Binary search (array is already sorted)
    pos = binary_search(numbers, size, target);
    if (pos != -1) {
        printf("Binary search: Found %d at index %d\n", target, pos);
    } else {
        printf("Binary search: %d not found\n", target);
    }
    
    return 0;
}
```

### Sorting Arrays

```c
#include <stdio.h>

// Bubble sort
void bubble_sort(int arr[], int size) {
    for (int i = 0; i < size - 1; i++) {
        for (int j = 0; j < size - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                // Swap elements
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

// Selection sort
void selection_sort(int arr[], int size) {
    for (int i = 0; i < size - 1; i++) {
        int min_idx = i;
        for (int j = i + 1; j < size; j++) {
            if (arr[j] < arr[min_idx]) {
                min_idx = j;
            }
        }
        // Swap minimum element with first element
        int temp = arr[min_idx];
        arr[min_idx] = arr[i];
        arr[i] = temp;
    }
}

void print_array(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
}

int main() {
    int numbers1[] = {64, 34, 25, 12, 22, 11, 90};
    int numbers2[] = {64, 34, 25, 12, 22, 11, 90};
    int size = 7;
    
    printf("Original array: ");
    print_array(numbers1, size);
    
    bubble_sort(numbers1, size);
    printf("After bubble sort: ");
    print_array(numbers1, size);
    
    printf("Original array: ");
    print_array(numbers2, size);
    
    selection_sort(numbers2, size);
    printf("After selection sort: ");
    print_array(numbers2, size);
    
    return 0;
}
```

## 6. Multidimensional Arrays

Arrays can have multiple dimensions for representing matrices, tables, etc.

### 2D Arrays

```c
#include <stdio.h>

int main() {
    // Declaration and initialization
    int matrix[3][4] = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12}
    };
    
    // Alternative initialization
    int grid[2][3] = {{1, 2, 3}, {4, 5, 6}};
    
    // Accessing elements
    printf("Element at [1][2]: %d\n", matrix[1][2]);
    
    // Printing entire matrix
    printf("Matrix:\n");
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%3d ", matrix[i][j]);
        }
        printf("\n");
    }
    
    // Modifying elements
    matrix[0][0] = 99;
    printf("After modification [0][0] = %d\n", matrix[0][0]);
    
    return 0;
}
```

### Matrix Operations

```c
#include <stdio.h>

void print_matrix(int rows, int cols, int matrix[rows][cols]) {
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            printf("%4d ", matrix[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

void matrix_add(int rows, int cols, int a[rows][cols], int b[rows][cols], int result[rows][cols]) {
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            result[i][j] = a[i][j] + b[i][j];
        }
    }
}

void matrix_multiply(int r1, int c1, int a[r1][c1], int r2, int c2, int b[r2][c2], int result[r1][c2]) {
    // Initialize result matrix
    for (int i = 0; i < r1; i++) {
        for (int j = 0; j < c2; j++) {
            result[i][j] = 0;
        }
    }
    
    // Multiply matrices
    for (int i = 0; i < r1; i++) {
        for (int j = 0; j < c2; j++) {
            for (int k = 0; k < c1; k++) {
                result[i][j] += a[i][k] * b[k][j];
            }
        }
    }
}

int main() {
    int a[2][3] = {{1, 2, 3}, {4, 5, 6}};
    int b[2][3] = {{7, 8, 9}, {10, 11, 12}};
    int sum[2][3];
    
    printf("Matrix A:\n");
    print_matrix(2, 3, a);
    
    printf("Matrix B:\n");
    print_matrix(2, 3, b);
    
    matrix_add(2, 3, a, b, sum);
    printf("A + B:\n");
    print_matrix(2, 3, sum);
    
    // Matrix multiplication example
    int c[3][2] = {{1, 2}, {3, 4}, {5, 6}};
    int product[2][2];
    
    printf("Matrix C:\n");
    print_matrix(3, 2, c);
    
    matrix_multiply(2, 3, a, 3, 2, c, product);
    printf("A * C:\n");
    print_matrix(2, 2, product);
    
    return 0;
}
```

### 3D Arrays and Beyond

```c
#include <stdio.h>

int main() {
    // 3D array: [depth][rows][columns]
    int cube[2][3][4] = {
        {
            {1, 2, 3, 4},
            {5, 6, 7, 8},
            {9, 10, 11, 12}
        },
        {
            {13, 14, 15, 16},
            {17, 18, 19, 20},
            {21, 22, 23, 24}
        }
    };
    
    printf("3D Array contents:\n");
    for (int d = 0; d < 2; d++) {
        printf("Layer %d:\n", d);
        for (int r = 0; r < 3; r++) {
            for (int c = 0; c < 4; c++) {
                printf("%3d ", cube[d][r][c]);
            }
            printf("\n");
        }
        printf("\n");
    }
    
    // Accessing specific element
    printf("Element at [1][2][3]: %d\n", cube[1][2][3]);
    
    // Practical example: RGB image representation
    // image[height][width][channels] where channels = 3 (R,G,B)
    unsigned char image[2][2][3] = {
        {{255, 0, 0}, {0, 255, 0}},      // Red pixel, Green pixel
        {{0, 0, 255}, {255, 255, 255}}   // Blue pixel, White pixel
    };
    
    printf("Image pixel colors (R,G,B):\n");
    for (int y = 0; y < 2; y++) {
        for (int x = 0; x < 2; x++) {
            printf("(%d,%d,%d) ", image[y][x][0], image[y][x][1], image[y][x][2]);
        }
        printf("\n");
    }
    
    return 0;
}
```

## 7. Strings

Strings in C are arrays of characters terminated by a null character '\0'.

### String Basics

```c
#include <stdio.h>

int main() {
    // Different ways to declare strings
    char str1[20] = "Hello";           // String literal
    char str2[] = "World";             // Auto-sized
    char str3[20];                     // Uninitialized
    char str4[] = {'H', 'i', '\0'};    // Character array
    
    // Getting string input
    printf("Enter a string: ");
    fgets(str3, sizeof(str3), stdin);  // Safe string input
    
    // Remove newline from fgets if present
    int len = 0;
    while (str3[len] != '\0') len++;   // Find length
    if (len > 0 && str3[len-1] == '\n') {
        str3[len-1] = '\0';
    }
    
    printf("str1: %s\n", str1);
    printf("str2: %s\n", str2);
    printf("str3: %s\n", str3);
    printf("str4: %s\n", str4);
    
    return 0;
}
```

### Character Access and Modification

```c
#include <stdio.h>
#include <ctype.h>

int main() {
    char text[] = "Hello World";
    
    printf("Original: %s\n", text);
    
    // Access individual characters
    printf("First character: %c\n", text[0]);
    printf("Last character: %c\n", text[10]);  // 'W' is at index 10
    
    // Modify characters
    text[0] = 'h';  // Change 'H' to 'h'
    printf("After modification: %s\n", text);
    
    // Convert to uppercase
    for (int i = 0; text[i] != '\0'; i++) {
        text[i] = toupper(text[i]);
    }
    printf("Uppercase: %s\n", text);
    
    // Convert to lowercase
    for (int i = 0; text[i] != '\0'; i++) {
        text[i] = tolower(text[i]);
    }
    printf("Lowercase: %s\n", text);
    
    // Count characters
    int count = 0;
    for (int i = 0; text[i] != '\0'; i++) {
        count++;
    }
    printf("Length: %d characters\n", count);
    
    return 0;
}
```

### String Comparison

```c
#include <stdio.h>

// Manual string comparison
int string_compare(const char* str1, const char* str2) {
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

// Manual string copy
void string_copy(char* dest, const char* src) {
    while ((*dest++ = *src++));
}

int main() {
    char name1[] = "Alice";
    char name2[] = "Bob";
    char name3[] = "Alice";
    char buffer[20];
    
    // Compare strings manually
    int result1 = string_compare(name1, name2);
    int result2 = string_compare(name1, name3);
    
    if (result1 == 0) {
        printf("%s and %s are equal\n", name1, name2);
    } else if (result1 < 0) {
        printf("%s comes before %s\n", name1, name2);
    } else {
        printf("%s comes after %s\n", name1, name2);
    }
    
    if (result2 == 0) {
        printf("%s and %s are equal\n", name1, name3);
    }
    
    // Copy string
    string_copy(buffer, name1);
    printf("Copied string: %s\n", buffer);
    
    return 0;
}
```

## 8. String Functions

C provides standard library functions for string manipulation.

### Standard String Functions

```c
#include <stdio.h>
#include <string.h>

int main() {
    char str1[50] = "Hello";
    char str2[50] = "World";
    char str3[50];
    char text[] = "Programming in C is fun";
    
    // strlen() - get string length
    printf("Length of '%s': %zu\n", str1, strlen(str1));
    
    // strcpy() - copy string
    strcpy(str3, str1);
    printf("Copied string: %s\n", str3);
    
    // strcat() - concatenate strings
    strcat(str1, " ");
    strcat(str1, str2);
    printf("Concatenated: %s\n", str1);
    
    // strcmp() - compare strings
    int cmp = strcmp("apple", "banana");
    printf("Comparing 'apple' and 'banana': %d\n", cmp);
    
    if (strcmp("test", "test") == 0) {
        printf("Strings are equal\n");
    }
    
    // strchr() - find character
    char* pos = strchr(text, 'g');
    if (pos) {
        printf("Found 'g' at position: %ld\n", pos - text);
    }
    
    // strstr() - find substring
    char* substr = strstr(text, "in C");
    if (substr) {
        printf("Found 'in C' at position: %ld\n", substr - text);
        printf("Substring: %s\n", substr);
    }
    
    return 0;
}
```

### String Tokenization

```c
#include <stdio.h>
#include <string.h>

int main() {
    // Using strtok() to split strings
    char sentence[] = "apple,banana,orange,grape";
    char data[] = "John:25:Engineer:New York";
    
    printf("Original: %s\n", sentence);
    printf("Tokens:\n");
    
    // Split by comma
    char* token = strtok(sentence, ",");
    while (token != NULL) {
        printf("- %s\n", token);
        token = strtok(NULL, ",");
    }
    
    printf("\nParsing person data: %s\n", data);
    token = strtok(data, ":");
    int field = 0;
    while (token != NULL) {
        switch (field) {
            case 0: printf("Name: %s\n", token); break;
            case 1: printf("Age: %s\n", token); break;
            case 2: printf("Job: %s\n", token); break;
            case 3: printf("City: %s\n", token); break;
        }
        field++;
        token = strtok(NULL, ":");
    }
    
    // Manual tokenization (safer approach)
    char csv[] = "red,green,blue,yellow";
    char* start = csv;
    char* end;
    
    printf("\nManual tokenization:\n");
    while ((end = strchr(start, ',')) != NULL) {
        *end = '\0';  // Temporarily null-terminate
        printf("Token: %s\n", start);
        *end = ',';   // Restore comma
        start = end + 1;
    }
    printf("Token: %s\n", start);  // Last token
    
    return 0;
}
```

### String Conversion

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Custom string to integer conversion
int string_to_int(const char* str) {
    int result = 0;
    int sign = 1;
    int i = 0;
    
    // Handle negative sign
    if (str[0] == '-') {
        sign = -1;
        i = 1;
    } else if (str[0] == '+') {
        i = 1;
    }
    
    // Convert digits
    while (str[i] != '\0' && isdigit(str[i])) {
        result = result * 10 + (str[i] - '0');
        i++;
    }
    
    return result * sign;
}

// Custom integer to string conversion
void int_to_string(int num, char* str) {
    sprintf(str, "%d", num);
}

int main() {
    // Using standard library functions
    char num_str[] = "12345";
    char float_str[] = "3.14159";
    char negative[] = "-789";
    
    // String to number conversions
    int num = atoi(num_str);
    float f = atof(float_str);
    long l = strtol(negative, NULL, 10);
    
    printf("String to number conversions:\n");
    printf("'%s' -> %d\n", num_str, num);
    printf("'%s' -> %.2f\n", float_str, f);
    printf("'%s' -> %ld\n", negative, l);
    
    // Number to string conversions
    char buffer[20];
    int value = 42;
    float pi = 3.14159;
    
    sprintf(buffer, "%d", value);
    printf("Number to string: %d -> '%s'\n", value, buffer);
    
    sprintf(buffer, "%.2f", pi);
    printf("Float to string: %.2f -> '%s'\n", pi, buffer);
    
    // Custom conversion functions
    int custom_num = string_to_int("-456");
    printf("Custom string_to_int('-456'): %d\n", custom_num);
    
    int_to_string(789, buffer);
    printf("Custom int_to_string(789): '%s'\n", buffer);
    
    // Safe string to number with error checking
    char input[] = "123abc";
    char* endptr;
    long safe_num = strtol(input, &endptr, 10);
    
    if (*endptr == '\0') {
        printf("'%s' is a valid number: %ld\n", input, safe_num);
    } else {
        printf("'%s' contains invalid characters after: %ld\n", input, safe_num);
        printf("Invalid part: '%s'\n", endptr);
    }
    
    return 0;
}
```

## 9. Functions

Functions allow code reuse and modular programming.

### Function Declaration and Definition

```c
#include <stdio.h>

// Function declarations (prototypes)
int add(int a, int b);
void greet(char* name);
double calculate_area(double radius);
int factorial(int n);

// Function definitions
int add(int a, int b) {
    return a + b;
}

void greet(char* name) {
    printf("Hello, %s!\n", name);
}

double calculate_area(double radius) {
    return 3.14159 * radius * radius;
}

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

int main() {
    // Function calls
    int sum = add(5, 3);
    printf("5 + 3 = %d\n", sum);
    
    greet("Alice");
    
    double area = calculate_area(5.0);
    printf("Area of circle (radius=5): %.2f\n", area);
    
    int fact = factorial(5);
    printf("5! = %d\n", fact);
    
    return 0;
}
```

### Function Parameters

```c
#include <stdio.h>

// Pass by value
void modify_value(int x) {
    x = 100;  // This doesn't affect the original variable
    printf("Inside function: x = %d\n", x);
}

// Pass by reference (using pointers)
void modify_reference(int* x) {
    *x = 100;  // This modifies the original variable
    printf("Inside function: *x = %d\n", *x);
}

// Array parameter (always passed by reference)
void modify_array(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        arr[i] *= 2;  // This modifies the original array
    }
}

// Multiple return values using pointers
void divide_and_remainder(int dividend, int divisor, int* quotient, int* remainder) {
    *quotient = dividend / divisor;
    *remainder = dividend % divisor;
}

// Const parameters (read-only)
void print_array(const int arr[], int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
        // arr[i] = 0;  // Error: cannot modify const parameter
    }
    printf("\n");
}

int main() {
    // Pass by value example
    int num = 50;
    printf("Before function call: num = %d\n", num);
    modify_value(num);
    printf("After function call: num = %d\n", num);
    
    // Pass by reference example
    printf("\nBefore function call: num = %d\n", num);
    modify_reference(&num);
    printf("After function call: num = %d\n", num);
    
    // Array modification
    int numbers[] = {1, 2, 3, 4, 5};
    printf("\nBefore array modification: ");
    print_array(numbers, 5);
    
    modify_array(numbers, 5);
    printf("After array modification: ");
    print_array(numbers, 5);
    
    // Multiple return values
    int quotient, remainder;
    divide_and_remainder(17, 5, &quotient, &remainder);
    printf("\n17 ÷ 5 = %d remainder %d\n", quotient, remainder);
    
    return 0;
}
```

### Return Values and Types

```c
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

// Function returning different types
int get_max(int a, int b) {
    return (a > b) ? a : b;
}

float calculate_average(int arr[], int size) {
    int sum = 0;
    for (int i = 0; i < size; i++) {
        sum += arr[i];
    }
    return (float)sum / size;
}

bool is_even(int num) {
    return num % 2 == 0;
}

// Function returning pointer
char* find_substring(char* text, char* pattern) {
    return strstr(text, pattern);
}

// Function with multiple exit points
int validate_age(int age) {
    if (age < 0) {
        printf("Error: Age cannot be negative\n");
        return -1;  // Error code
    }
    
    if (age > 150) {
        printf("Error: Age seems unrealistic\n");
        return -1;  // Error code
    }
    
    return 0;  // Success
}

// Void function (no return value)
void print_grade(int score) {
    if (score >= 90) {
        printf("Grade: A\n");
    } else if (score >= 80) {
        printf("Grade: B\n");
    } else if (score >= 70) {
        printf("Grade: C\n");
    } else if (score >= 60) {
        printf("Grade: D\n");
    } else {
        printf("Grade: F\n");
    }
}

int main() {
    // Integer return
    int max = get_max(15, 23);
    printf("Maximum: %d\n", max);
    
    // Float return
    int scores[] = {85, 92, 78, 96, 88};
    float avg = calculate_average(scores, 5);
    printf("Average: %.2f\n", avg);
    
    // Boolean return
    int num = 42;
    if (is_even(num)) {
        printf("%d is even\n", num);
    } else {
        printf("%d is odd\n", num);
    }
    
    // Pointer return
    char text[] = "Programming in C";
    char* found = find_substring(text, "in");
    if (found) {
        printf("Found substring: %s\n", found);
    }
    
    // Function with error handling
    int ages[] = {25, -5, 200, 30};
    for (int i = 0; i < 4; i++) {
        printf("Validating age %d: ", ages[i]);
        if (validate_age(ages[i]) == 0) {
            printf("Valid\n");
        }
    }
    
    // Void function
    print_grade(87);
    
    return 0;
}
```

## 10. Scope and Storage Classes

Understanding variable scope and storage classes is crucial for proper memory management.

### Variable Scope

```c
#include <stdio.h>

int global_var = 100;  // Global scope

void function_scope_demo() {
    int local_var = 200;  // Local to this function
    printf("Inside function - local_var: %d\n", local_var);
    printf("Inside function - global_var: %d\n", global_var);
    
    // Block scope
    {
        int block_var = 300;  // Local to this block
        int local_var = 400;  // Shadows the function's local_var
        printf("Inside block - block_var: %d\n", block_var);
        printf("Inside block - local_var (shadowed): %d\n", local_var);
        printf("Inside block - global_var: %d\n", global_var);
    }
    // block_var is not accessible here
    
    printf("After block - local_var: %d\n", local_var);  // Back to 200
}

int main() {
    printf("In main - global_var: %d\n", global_var);
    
    function_scope_demo();
    
    // Demonstrating for loop scope
    for (int i = 0; i < 3; i++) {
        printf("Loop iteration: %d\n", i);
    }
    // i is not accessible here
    
    return 0;
}
```

### Storage Classes

```c
#include <stdio.h>

// Global variables (external storage)
int global_count = 0;

// Function to demonstrate static variables
void counter_function() {
    static int static_count = 0;  // Retains value between calls
    int auto_count = 0;           // Reset on each call
    
    static_count++;
    auto_count++;
    
    printf("Static count: %d, Auto count: %d\n", static_count, auto_count);
}

// Function with register variable
void register_demo() {
    register int fast_var = 100;  // Suggest storing in CPU register
    
    // Note: Cannot take address of register variable
    // int* ptr = &fast_var;  // This would cause an error
    
    printf("Register variable: %d\n", fast_var);
}

// External declaration (variable defined in another file)
extern int external_var;  // Assuming this is defined elsewhere

int main() {
    // Auto storage class (default for local variables)
    auto int local_var = 10;  // 'auto' keyword is optional
    
    printf("Local variable: %d\n", local_var);
    
    // Demonstrate static variable behavior
    printf("Calling counter_function multiple times:\n");
    for (int i = 0; i < 5; i++) {
        counter_function();
    }
    
    register_demo();
    
    // Global variable access
    global_count = 42;
    printf("Global count: %d\n", global_count);
    
    return 0;
}

// Static function (internal linkage)
static void internal_function() {
    printf("This function is only visible in this file\n");
}
```

### Variable Lifetime Examples

```c
#include <stdio.h>
#include <stdlib.h>

// Global variable - exists for entire program duration
int global_lifetime = 1;

void demonstrate_lifetimes() {
    // Automatic variable - exists only during function execution
    int automatic = 2;
    
    // Static variable - exists for entire program duration
    static int static_var = 3;
    
    // Dynamic allocation - exists until explicitly freed
    int* dynamic = (int*)malloc(sizeof(int));
    *dynamic = 4;
    
    printf("Automatic: %d\n", automatic);
    printf("Static: %d\n", static_var);
    printf("Dynamic: %d\n", *dynamic);
    
    // Modify static variable
    static_var += 10;
    
    // Free dynamic memory
    free(dynamic);
    // dynamic pointer is now invalid
}

// Function returning pointer to static variable (safe)
int* get_static_counter() {
    static int counter = 0;
    counter++;
    return &counter;  // Safe because static variable persists
}

// Dangerous function - returning pointer to local variable
int* dangerous_function() {
    int local = 100;
    return &local;  // Dangerous! local variable is destroyed
}

int main() {
    printf("Global lifetime: %d\n", global_lifetime);
    
    printf("\nFirst call to demonstrate_lifetimes:\n");
    demonstrate_lifetimes();
    
    printf("\nSecond call to demonstrate_lifetimes:\n");
    demonstrate_lifetimes();
    
    // Safe use of static variable pointer
    int* safe_ptr = get_static_counter();
    printf("\nStatic counter: %d\n", *safe_ptr);
    
    safe_ptr = get_static_counter();
    printf("Static counter: %d\n", *safe_ptr);
    
    // Demonstrate the danger of returning local variable address
    // int* danger = dangerous_function();
    // printf("Dangerous value: %d\n", *danger);  // Undefined behavior!
    
    return 0;
}
```

## 11. Pointers

Pointers are variables that store memory addresses of other variables.

### Pointer Basics

```c
#include <stdio.h>

int main() {
    int num = 42;
    int* ptr;  // Declare pointer to integer
    
    ptr = &num;  // Store address of num in ptr
    
    printf("Value of num: %d\n", num);
    printf("Address of num: %p\n", (void*)&num);
    printf("Value of ptr (address): %p\n", (void*)ptr);
    printf("Value pointed to by ptr: %d\n", *ptr);
    
    // Modify value through pointer
    *ptr = 100;
    printf("After *ptr = 100, num = %d\n", num);
    
    // Pointer arithmetic with addresses
    printf("Size of int: %zu bytes\n", sizeof(int));
    printf("Address of ptr itself: %p\n", (void*)&ptr);
    
    return 0;
}
```

### Pointer Declaration and Initialization

```c
#include <stdio.h>

int main() {
    // Different ways to declare pointers
    int* ptr1;           // Uninitialized pointer (dangerous)
    int* ptr2 = NULL;    // Null pointer (safe initialization)
    
    int value = 25;
    int* ptr3 = &value;  // Initialize with address
    
    // Multiple pointers of same type
    int *a, *b, *c;      // All are pointers to int
    int *x, y, *z;       // x and z are pointers, y is int
    
    // Const pointers
    int num1 = 10, num2 = 20;
    const int* ptr_to_const = &num1;     // Pointer to constant int
    int* const const_ptr = &num1;        // Constant pointer to int
    const int* const const_ptr_const = &num1;  // Constant pointer to constant int
    
    printf("value = %d\n", value);
    printf("*ptr3 = %d\n", *ptr3);
    
    // Checking for null pointer
    if (ptr2 == NULL) {
        printf("ptr2 is null\n");
    }
    
    // Working with const pointers
    printf("*ptr_to_const = %d\n", *ptr_to_const);
    // *ptr_to_const = 30;  // Error: cannot modify value
    ptr_to_const = &num2;   // OK: can change what it points to
    
    printf("*const_ptr = %d\n", *const_ptr);
    *const_ptr = 30;        // OK: can modify value
    // const_ptr = &num2;   // Error: cannot change what it points to
    
    return 0;
}
```

### Pointer Arithmetic

```c
#include <stdio.h>

int main() {
    int arr[] = {10, 20, 30, 40, 50};
    int* ptr = arr;  // Points to first element
    
    printf("Array elements using pointer arithmetic:\n");
    
    // Access array elements using pointer arithmetic
    for (int i = 0; i < 5; i++) {
        printf("arr[%d] = %d, *(ptr + %d) = %d\n", 
               i, arr[i], i, *(ptr + i));
    }
    
    printf("\nPointer incrementing:\n");
    ptr = arr;  // Reset pointer
    for (int i = 0; i < 5; i++) {
        printf("Address: %p, Value: %d\n", (void*)ptr, *ptr);
        ptr++;  // Move to next element
    }
    
    // Pointer subtraction
    int* start = &arr[0];
    int* end = &arr[4];
    ptrdiff_t difference = end - start;
    printf("\nDifference between pointers: %td elements\n", difference);
    
    // Comparing pointers
    ptr = arr;
    if (ptr == &arr[0]) {
        printf("ptr points to first element\n");
    }
    
    // Different data types and pointer arithmetic
    char char_arr[] = "Hello";
    char* char_ptr = char_arr;
    
    printf("\nCharacter array with pointer arithmetic:\n");
    while (*char_ptr != '\0') {
        printf("Character: %c, Address: %p\n", *char_ptr, (void*)char_ptr);
        char_ptr++;
    }
    
    return 0;
}
```

### Pointers and Arrays

```c
#include <stdio.h>

void print_array_with_pointer(int* arr, int size) {
    printf("Array elements: ");
    for (int i = 0; i < size; i++) {
        printf("%d ", *(arr + i));  // Same as arr[i]
    }
    printf("\n");
}

void modify_array(int* arr, int size) {
    for (int i = 0; i < size; i++) {
        *(arr + i) *= 2;  // Double each element
    }
}

int main() {
    int numbers[] = {1, 2, 3, 4, 5};
    int size = 5;
    
    // Array name is a pointer to first element
    printf("Array name as pointer: %p\n", (void*)numbers);
    printf("Address of first element: %p\n", (void*)&numbers[0]);
    
    // Different ways to access array elements
    printf("\nDifferent ways to access elements:\n");
    for (int i = 0; i < size; i++) {
        printf("numbers[%d] = %d\n", i, numbers[i]);
        printf("*(numbers + %d) = %d\n", i, *(numbers + i));
        printf("&numbers[%d] = %p\n", i, (void*)&numbers[i]);
        printf("(numbers + %d) = %p\n\n", i, (void*)(numbers + i));
    }
    
    print_array_with_pointer(numbers, size);
    
    modify_array(numbers, size);
    printf("After modification: ");
    print_array_with_pointer(numbers, size);
    
    // 2D array and pointers
    int matrix[3][4] = {
        {1, 2, 3, 4},
        {5, 6, 7, 8},
        {9, 10, 11, 12}
    };
    
    printf("\n2D array with pointers:\n");
    int* flat_ptr = (int*)matrix;  // Treat as 1D array
    for (int i = 0; i < 12; i++) {
        printf("%d ", *(flat_ptr + i));
        if ((i + 1) % 4 == 0) printf("\n");
    }
    
    return 0;
}
```

### Double Pointers

```c
#include <stdio.h>

void swap_pointers(int** ptr1, int** ptr2) {
    int* temp = *ptr1;
    *ptr1 = *ptr2;
    *ptr2 = temp;
}

void allocate_and_assign(int** ptr, int value) {
    static int storage;  // Static storage for demonstration
    storage = value;
    *ptr = &storage;
}

int main() {
    int a = 10, b = 20;
    int* ptr1 = &a;
    int* ptr2 = &b;
    int** double_ptr = &ptr1;  // Pointer to pointer
    
    printf("Initial values:\n");
    printf("a = %d, b = %d\n", a, b);
    printf("*ptr1 = %d, *ptr2 = %d\n", *ptr1, *ptr2);
    printf("**double_ptr = %d\n", **double_ptr);
    
    // Accessing value through double pointer
    **double_ptr = 100;  // Changes value of 'a'
    printf("After **double_ptr = 100: a = %d\n", a);
    
    // Changing what double_ptr points to
    double_ptr = &ptr2;
    printf("After double_ptr = &ptr2: **double_ptr = %d\n", **double_ptr);
    
    // Swapping pointers
    ptr1 = &a;
    ptr2 = &b;
    printf("\nBefore swap: *ptr1 = %d, *ptr2 = %d\n", *ptr1, *ptr2);
    swap_pointers(&ptr1, &ptr2);
    printf("After swap: *ptr1 = %d, *ptr2 = %d\n", *ptr1, *ptr2);
    
    // Dynamic pointer assignment
    int* new_ptr;
    allocate_and_assign(&new_ptr, 42);
    printf("Dynamically assigned: *new_ptr = %d\n", *new_ptr);
    
    // Array of pointers
    int x = 1, y = 2, z = 3;
    int* ptr_array[] = {&x, &y, &z};
    
    printf("\nArray of pointers:\n");
    for (int i = 0; i < 3; i++) {
        printf("ptr_array[%d] points to value: %d\n", i, *ptr_array[i]);
    }
    
    return 0;
}
```

## 12. Dynamic Memory Allocation

Dynamic memory allocation allows programs to request memory at runtime.

### malloc, calloc, realloc, free

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // malloc - allocates uninitialized memory
    int* numbers = (int*)malloc(5 * sizeof(int));
    if (numbers == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }
    
    // Initialize allocated memory
    for (int i = 0; i < 5; i++) {
        numbers[i] = (i + 1) * 10;
    }
    
    printf("malloc allocated array: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", numbers[i]);
    }
    printf("\n");
    
    // realloc - resize allocated memory
    numbers = (int*)realloc(numbers, 8 * sizeof(int));
    if (numbers == NULL) {
        printf("Memory reallocation failed\n");
        return 1;
    }
    
    // Initialize new elements
    for (int i = 5; i < 8; i++) {
        numbers[i] = (i + 1) * 10;
    }
    
    printf("After realloc: ");
    for (int i = 0; i < 8; i++) {
        printf("%d ", numbers[i]);
    }
    printf("\n");
    
    // calloc - allocates zero-initialized memory
    int* zeros = (int*)calloc(5, sizeof(int));
    if (zeros == NULL) {
        printf("Memory allocation failed\n");
        free(numbers);
        return 1;
    }
    
    printf("calloc allocated array (zero-initialized): ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", zeros[i]);
    }
    printf("\n");
    
    // Dynamic string allocation
    char* str = (char*)malloc(20 * sizeof(char));
    if (str != NULL) {
        strcpy(str, "Dynamic string");
        printf("Dynamic string: %s\n", str);
        free(str);
    }
    
    // Free allocated memory
    free(numbers);
    free(zeros);
    
    return 0;
}
```

### Memory Management Best Practices

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to create a dynamic array
int* create_array(int size, int initial_value) {
    int* arr = (int*)malloc(size * sizeof(int));
    if (arr == NULL) {
        printf("Memory allocation failed\n");
        return NULL;
    }
    
    for (int i = 0; i < size; i++) {
        arr[i] = initial_value;
    }
    
    return arr;
}

// Function to resize array safely
int* resize_array(int* arr, int old_size, int new_size) {
    int* new_arr = (int*)realloc(arr, new_size * sizeof(int));
    if (new_arr == NULL) {
        printf("Memory reallocation failed\n");
        return arr;  // Return original array
    }
    
    // Initialize new elements if array grew
    if (new_size > old_size) {
        for (int i = old_size; i < new_size; i++) {
            new_arr[i] = 0;
        }
    }
    
    return new_arr;
}

// Safe string duplication
char* safe_strdup(const char* src) {
    if (src == NULL) return NULL;
    
    size_t len = strlen(src) + 1;
    char* copy = (char*)malloc(len);
    if (copy == NULL) {
        printf("Memory allocation failed\n");
        return NULL;
    }
    
    strcpy(copy, src);
    return copy;
}

int main() {
    // Create dynamic array
    int* arr = create_array(5, 10);
    if (arr == NULL) return 1;
    
    printf("Created array: ");
    for (int i = 0; i < 5; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
    
    // Resize array
    arr = resize_array(arr, 5, 8);
    printf("Resized array: ");
    for (int i = 0; i < 8; i++) {
        printf("%d ", arr[i]);
    }
    printf("\n");
    
    // Safe string operations
    char* original = "Hello, World!";
    char* copy = safe_strdup(original);
    if (copy != NULL) {
        printf("Original: %s\n", original);
        printf("Copy: %s\n", copy);
        free(copy);
    }
    
    // Common memory errors (commented out)
    /*
    // 1. Memory leak - forgetting to free
    int* leak = malloc(100 * sizeof(int));
    // free(leak);  // Forgot to free!
    
    // 2. Double free
    free(arr);
    // free(arr);  // Error: double free!
    
    // 3. Use after free
    free(arr);
    // arr[0] = 10;  // Error: use after free!
    
    // 4. Buffer overflow
    char* buffer = malloc(10);
    // strcpy(buffer, "This string is too long!");  // Buffer overflow!
    free(buffer);
    */
    
    // Proper cleanup
    free(arr);
    arr = NULL;  // Prevent accidental use
    
    printf("Memory management completed successfully\n");
    return 0;
}
```

### Memory Leaks and Debugging

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simple memory leak detector (for demonstration)
static int allocations = 0;
static int deallocations = 0;

void* debug_malloc(size_t size) {
    void* ptr = malloc(size);
    if (ptr != NULL) {
        allocations++;
        printf("ALLOC: %p (%zu bytes) - Total allocations: %d\n", 
               ptr, size, allocations);
    }
    return ptr;
}

void debug_free(void* ptr) {
    if (ptr != NULL) {
        deallocations++;
        printf("FREE:  %p - Total deallocations: %d\n", ptr, deallocations);
        free(ptr);
    }
}

void memory_report() {
    printf("\n=== Memory Report ===\n");
    printf("Total allocations: %d\n", allocations);
    printf("Total deallocations: %d\n", deallocations);
    printf("Potential leaks: %d\n", allocations - deallocations);
    printf("=====================\n\n");
}

// Example functions with memory management
char* create_string(const char* text) {
    char* str = (char*)debug_malloc(strlen(text) + 1);
    if (str != NULL) {
        strcpy(str, text);
    }
    return str;
}

void process_strings() {
    char* str1 = create_string("First string");
    char* str2 = create_string("Second string");
    char* str3 = create_string("Third string");
    
    printf("Created strings: %s, %s, %s\n", str1, str2, str3);
    
    // Free some but not all (demonstrating leak)
    debug_free(str1);
    debug_free(str2);
    // str3 not freed - this is a leak!
}

// Proper memory management example
void proper_memory_usage() {
    int* numbers = (int*)debug_malloc(10 * sizeof(int));
    if (numbers == NULL) return;
    
    // Use the memory
    for (int i = 0; i < 10; i++) {
        numbers[i] = i * i;
    }
    
    // Always free when done
    debug_free(numbers);
}

int main() {
    printf("Starting memory debugging example\n\n");
    
    process_strings();
    memory_report();
    
    proper_memory_usage();
    memory_report();
    
    // Valgrind-style tips for debugging
    printf("Memory debugging tips:\n");
    printf("1. Always pair malloc/calloc with free\n");
    printf("2. Set pointers to NULL after freeing\n");
    printf("3. Use tools like Valgrind or AddressSanitizer\n");
    printf("4. Initialize pointers to NULL\n");
    printf("5. Check return values of allocation functions\n");
    
    return 0;
}
```

## 13. Structures

Structures allow grouping related data of different types.

### Structure Declaration and Initialization

```c
#include <stdio.h>
#include <string.h>

// Basic structure definition
struct Point {
    int x;
    int y;
};

// Structure with different data types
struct Student {
    int id;
    char name[50];
    float gpa;
    char grade;
};

// Nested structures
struct Address {
    char street[100];
    char city[50];
    int zip_code;
};

struct Person {
    char name[50];
    int age;
    struct Address address;
};

int main() {
    // Different ways to initialize structures
    struct Point p1 = {10, 20};           // Positional initialization
    struct Point p2 = {.x = 5, .y = 15};  // Designated initialization
    struct Point p3;                       // Uninitialized
    
    // Manual initialization
    p3.x = 30;
    p3.y = 40;
    
    printf("Points: p1(%d,%d), p2(%d,%d), p3(%d,%d)\n", 
           p1.x, p1.y, p2.x, p2.y, p3.x, p3.y);
    
    // Student structure
    struct Student student1 = {12345, "John Doe", 3.75, 'A'};
    struct Student student2;
    
    // Initialize student2 manually
    student2.id = 67890;
    strcpy(student2.name, "Jane Smith");
    student2.gpa = 3.90;
    student2.grade = 'A';
    
    printf("\nStudents:\n");
    printf("ID: %d, Name: %s, GPA: %.2f, Grade: %c\n", 
           student1.id, student1.name, student1.gpa, student1.grade);
    printf("ID: %d, Name: %s, GPA: %.2f, Grade: %c\n", 
           student2.id, student2.name, student2.gpa, student2.grade);
    
    // Nested structure
    struct Person person = {
        "Alice Johnson",
        25,
        {"123 Main St", "New York", 10001}
    };
    
    printf("\nPerson:\n");
    printf("Name: %s\n", person.name);
    printf("Age: %d\n", person.age);
    printf("Address: %s, %s %d\n", 
           person.address.street, person.address.city, person.address.zip_code);
    
    return 0;
}
```

### Structure Operations

```c
#include <stdio.h>
#include <string.h>
#include <math.h>

struct Point {
    double x, y;
};

struct Rectangle {
    struct Point top_left;
    struct Point bottom_right;
};

struct Circle {
    struct Point center;
    double radius;
};

// Function to calculate distance between two points
double distance(struct Point p1, struct Point p2) {
    double dx = p2.x - p1.x;
    double dy = p2.y - p1.y;
    return sqrt(dx * dx + dy * dy);
}

// Function to calculate rectangle area
double rectangle_area(struct Rectangle rect) {
    double width = rect.bottom_right.x - rect.top_left.x;
    double height = rect.top_left.y - rect.bottom_right.y;
    return width * height;
}

// Function to calculate circle area
double circle_area(struct Circle circle) {
    return 3.14159 * circle.radius * circle.radius;
}

// Function to check if point is inside rectangle
int point_in_rectangle(struct Point point, struct Rectangle rect) {
    return (point.x >= rect.top_left.x && 
            point.x <= rect.bottom_right.x &&
            point.y <= rect.top_left.y && 
            point.y >= rect.bottom_right.y);
}

// Function to print point
void print_point(struct Point p) {
    printf("(%.2f, %.2f)", p.x, p.y);
}

int main() {
    struct Point p1 = {0, 0};
    struct Point p2 = {3, 4};
    struct Point p3 = {1, 2};
    
    printf("Point 1: ");
    print_point(p1);
    printf("\nPoint 2: ");
    print_point(p2);
    printf("\n");
    
    double dist = distance(p1, p2);
    printf("Distance between points: %.2f\n", dist);
    
    // Rectangle operations
    struct Rectangle rect = {{0, 5}, {10, 0}};
    double rect_area = rectangle_area(rect);
    printf("Rectangle area: %.2f\n", rect_area);
    
    if (point_in_rectangle(p3, rect)) {
        printf("Point 3 is inside the rectangle\n");
    } else {
        printf("Point 3 is outside the rectangle\n");
    }
    
    // Circle operations
    struct Circle circle = {{0, 0}, 5.0};
    double circ_area = circle_area(circle);
    printf("Circle area: %.2f\n", circ_area);
    
    // Structure assignment
    struct Point p4 = p2;  // Copy entire structure
    printf("Copied point: ");
    print_point(p4);
    printf("\n");
    
    // Array of structures
    struct Point points[] = {
        {1, 1}, {2, 2}, {3, 3}, {4, 4}, {5, 5}
    };
    
    printf("Array of points:\n");
    for (int i = 0; i < 5; i++) {
        printf("Point %d: ", i);
        print_point(points[i]);
        printf("\n");
    }
    
    return 0;
}
```

### Structures and Pointers

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Book {
    int id;
    char title[100];
    char author[50];
    double price;
};

// Function to create a book
struct Book* create_book(int id, const char* title, const char* author, double price) {
    struct Book* book = (struct Book*)malloc(sizeof(struct Book));
    if (book == NULL) {
        printf("Memory allocation failed\n");
        return NULL;
    }
    
    book->id = id;
    strcpy(book->title, title);
    strcpy(book->author, author);
    book->price = price;
    
    return book;
}

// Function to print book details
void print_book(const struct Book* book) {
    if (book == NULL) {
        printf("Book is NULL\n");
        return;
    }
    
    printf("Book ID: %d\n", book->id);
    printf("Title: %s\n", book->title);
    printf("Author: %s\n", book->author);
    printf("Price: $%.2f\n", book->price);
    printf("------------------------\n");
}

// Function to modify book price
void update_price(struct Book* book, double new_price) {
    if (book != NULL) {
        book->price = new_price;
    }
}

// Function to compare books by price
int compare_books_by_price(const void* a, const void* b) {
    const struct Book* book1 = (const struct Book*)a;
    const struct Book* book2 = (const struct Book*)b;
    
    if (book1->price < book2->price) return -1;
    if (book1->price > book2->price) return 1;
    return 0;
}

int main() {
    // Using pointers to structures
    struct Book* book1 = create_book(1, "The C Programming Language", "Kernighan & Ritchie", 45.99);
    struct Book* book2 = create_book(2, "C: The Complete Reference", "Herbert Schildt", 39.99);
    
    if (book1 && book2) {
        printf("Original books:\n");
        print_book(book1);
        print_book(book2);
        
        // Update price using pointer
        update_price(book1, 49.99);
        printf("After price update:\n");
        print_book(book1);
        
        // Array of structure pointers
        struct Book* library[2] = {book1, book2};
        
        printf("Library contents:\n");
        for (int i = 0; i < 2; i++) {
            printf("Book %d:\n", i + 1);
            print_book(library[i]);
        }
        
        // Free allocated memory
        free(book1);
        free(book2);
    }
    
    // Array of structures (not pointers)
    struct Book books[] = {
        {3, "Advanced C", "Peter van der Linden", 55.00},
        {4, "C Traps and Pitfalls", "Andrew Koenig", 35.00},
        {5, "Expert C Programming", "Peter van der Linden", 50.00}
    };
    
    int num_books = sizeof(books) / sizeof(books[0]);
    
    printf("Before sorting:\n");
    for (int i = 0; i < num_books; i++) {
        print_book(&books[i]);
    }
    
    // Sort books by price
    qsort(books, num_books, sizeof(struct Book), compare_books_by_price);
    
    printf("After sorting by price:\n");
    for (int i = 0; i < num_books; i++) {
        print_book(&books[i]);
    }
    
    return 0;
}
```

### Typedef and Structure Aliases

```c
#include <stdio.h>
#include <string.h>

// Using typedef to create type aliases
typedef struct {
    int x, y;
} Point;

typedef struct {
    Point center;
    int radius;
} Circle;

// Typedef with named structure
typedef struct Node {
    int data;
    struct Node* next;  // Self-reference requires named struct
} Node;

// Enum inside structure
typedef enum {
    FRESHMAN, SOPHOMORE, JUNIOR, SENIOR
} Year;

typedef struct {
    char name[50];
    int age;
    Year year;
    double gpa;
} Student;

// Function pointer in structure
typedef struct {
    double (*operation)(double, double);
    char name[20];
} Calculator;

double add(double a, double b) { return a + b; }
double multiply(double a, double b) { return a * b; }

int main() {
    // Using typedef'ed structures
    Point p1 = {10, 20};
    Point p2 = {30, 40};
    
    printf("Point 1: (%d, %d)\n", p1.x, p1.y);
    printf("Point 2: (%d, %d)\n", p2.x, p2.y);
    
    Circle circle = {{0, 0}, 5};
    printf("Circle: center(%d, %d), radius=%d\n", 
           circle.center.x, circle.center.y, circle.radius);
    
    // Linked list node
    Node node1 = {10, NULL};
    Node node2 = {20, NULL};
    Node node3 = {30, NULL};
    
    // Connect nodes
    node1.next = &node2;
    node2.next = &node3;
    
    printf("\nLinked list: ");
    Node* current = &node1;
    while (current != NULL) {
        printf("%d -> ", current->data);
        current = current->next;
    }
    printf("NULL\n");
    
    // Student with enum
    Student student = {"Alice", 20, SOPHOMORE, 3.75};
    printf("\nStudent: %s, Age: %d, Year: %d, GPA: %.2f\n",
           student.name, student.age, student.year, student.gpa);
    
    // Structure with function pointer
    Calculator calc1 = {add, "Addition"};
    Calculator calc2 = {multiply, "Multiplication"};
    
    double result1 = calc1.operation(5.0, 3.0);
    double result2 = calc2.operation(5.0, 3.0);
    
    printf("\n%s: 5.0 + 3.0 = %.2f\n", calc1.name, result1);
    printf("%s: 5.0 * 3.0 = %.2f\n", calc2.name, result2);
    
    // Array of different calculator operations
    Calculator calculators[] = {
        {add, "Add"},
        {multiply, "Multiply"}
    };
    
    printf("\nCalculator operations:\n");
    for (int i = 0; i < 2; i++) {
        double result = calculators[i].operation(10.0, 2.0);
        printf("%s: 10.0 op 2.0 = %.2f\n", calculators[i].name, result);
    }
    
    return 0;
}
```

## 14. File Input/Output

File I/O operations allow programs to read from and write to files.

### Basic File Operations

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE* file;
    char buffer[100];
    
    // Writing to a file
    file = fopen("example.txt", "w");
    if (file == NULL) {
        printf("Error opening file for writing\n");
        return 1;
    }
    
    fprintf(file, "Hello, World!\n");
    fprintf(file, "This is line 2\n");
    fprintf(file, "Number: %d\n", 42);
    
    fclose(file);
    printf("Data written to file successfully\n");
    
    // Reading from a file
    file = fopen("example.txt", "r");
    if (file == NULL) {
        printf("Error opening file for reading\n");
        return 1;
    }
    
    printf("\nFile contents:\n");
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        printf("%s", buffer);
    }
    
    fclose(file);
    
    // Appending to a file
    file = fopen("example.txt", "a");
    if (file != NULL) {
        fprintf(file, "Appended line\n");
        fclose(file);
    }
    
    return 0;
}
```

### File Modes and Operations

```c
#include <stdio.h>
#include <string.h>

void demonstrate_file_modes() {
    FILE* file;
    char data[] = "Sample text for file operations";
    char buffer[100];
    
    // "w" - Write mode (creates new file or overwrites existing)
    file = fopen("test.txt", "w");
    if (file != NULL) {
        fputs("Initial content\n", file);
        fclose(file);
        printf("Write mode: File created/overwritten\n");
    }
    
    // "a" - Append mode (adds to end of file)
    file = fopen("test.txt", "a");
    if (file != NULL) {
        fputs("Appended content\n", file);
        fclose(file);
        printf("Append mode: Content added\n");
    }
    
    // "r" - Read mode
    file = fopen("test.txt", "r");
    if (file != NULL) {
        printf("Read mode contents:\n");
        while (fgets(buffer, sizeof(buffer), file) != NULL) {
            printf("  %s", buffer);
        }
        fclose(file);
    }
    
    // "r+" - Read/Write mode (file must exist)
    file = fopen("test.txt", "r+");
    if (file != NULL) {
        fseek(file, 0, SEEK_END);  // Go to end
        fputs("Read/Write addition\n", file);
        fclose(file);
        printf("Read/Write mode: Content modified\n");
    }
    
    // Binary file operations
    int numbers[] = {1, 2, 3, 4, 5};
    
    // Write binary data
    file = fopen("numbers.bin", "wb");
    if (file != NULL) {
        fwrite(numbers, sizeof(int), 5, file);
        fclose(file);
        printf("Binary write: Numbers saved\n");
    }
    
    // Read binary data
    int read_numbers[5];
    file = fopen("numbers.bin", "rb");
    if (file != NULL) {
        size_t items_read = fread(read_numbers, sizeof(int), 5, file);
        fclose(file);
        
        printf("Binary read: ");
        for (size_t i = 0; i < items_read; i++) {
            printf("%d ", read_numbers[i]);
        }
        printf("\n");
    }
}

int main() {
    demonstrate_file_modes();
    return 0;
}
```

### File Positioning and Random Access

```c
#include <stdio.h>
#include <string.h>

typedef struct {
    int id;
    char name[20];
    float salary;
} Employee;

void create_employee_file() {
    FILE* file = fopen("employees.dat", "wb");
    if (file == NULL) {
        printf("Error creating file\n");
        return;
    }
    
    Employee employees[] = {
        {101, "Alice Johnson", 50000.0},
        {102, "Bob Smith", 55000.0},
        {103, "Carol Davis", 60000.0},
        {104, "David Wilson", 52000.0},
        {105, "Eve Brown", 58000.0}
    };
    
    fwrite(employees, sizeof(Employee), 5, file);
    fclose(file);
    printf("Employee file created with 5 records\n");
}

void read_employee_by_position(int position) {
    FILE* file = fopen("employees.dat", "rb");
    if (file == NULL) {
        printf("Error opening file\n");
        return;
    }
    
    Employee emp;
    
    // Seek to specific position
    if (fseek(file, position * sizeof(Employee), SEEK_SET) == 0) {
        if (fread(&emp, sizeof(Employee), 1, file) == 1) {
            printf("Employee at position %d:\n", position);
            printf("ID: %d, Name: %s, Salary: %.2f\n", 
                   emp.id, emp.name, emp.salary);
        } else {
            printf("Error reading employee at position %d\n", position);
        }
    } else {
        printf("Error seeking to position %d\n", position);
    }
    
    fclose(file);
}

void update_employee_salary(int position, float new_salary) {
    FILE* file = fopen("employees.dat", "r+b");
    if (file == NULL) {
        printf("Error opening file for update\n");
        return;
    }
    
    Employee emp;
    
    // Read current data
    fseek(file, position * sizeof(Employee), SEEK_SET);
    if (fread(&emp, sizeof(Employee), 1, file) == 1) {
        // Update salary
        emp.salary = new_salary;
        
        // Write back to same position
        fseek(file, position * sizeof(Employee), SEEK_SET);
        fwrite(&emp, sizeof(Employee), 1, file);
        
        printf("Updated employee %s salary to %.2f\n", emp.name, new_salary);
    }
    
    fclose(file);
}

void display_file_info() {
    FILE* file = fopen("employees.dat", "rb");
    if (file == NULL) {
        printf("Error opening file\n");
        return;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    int num_records = file_size / sizeof(Employee);
    
    printf("\nFile information:\n");
    printf("File size: %ld bytes\n", file_size);
    printf("Record size: %zu bytes\n", sizeof(Employee));
    printf("Number of records: %d\n", num_records);
    
    // Display all records
    rewind(file);  // Go back to beginning
    Employee emp;
    int position = 0;
    
    printf("\nAll employees:\n");
    while (fread(&emp, sizeof(Employee), 1, file) == 1) {
        printf("Position %d: ID=%d, Name=%s, Salary=%.2f\n", 
               position++, emp.id, emp.name, emp.salary);
    }
    
    fclose(file);
}

int main() {
    create_employee_file();
    display_file_info();
    
    printf("\nReading specific employees:\n");
    read_employee_by_position(0);  // First employee
    read_employee_by_position(2);  // Third employee
    
    printf("\nUpdating salary:\n");
    update_employee_salary(1, 57000.0);  // Update second employee
    
    display_file_info();
    
    return 0;
}
```

### Error Handling and File Utilities

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Safe file copy function
int copy_file(const char* source, const char* destination) {
    FILE* src = fopen(source, "rb");
    if (src == NULL) {
        printf("Error opening source file '%s': %s\n", source, strerror(errno));
        return -1;
    }
    
    FILE* dest = fopen(destination, "wb");
    if (dest == NULL) {
        printf("Error creating destination file '%s': %s\n", destination, strerror(errno));
        fclose(src);
        return -1;
    }
    
    char buffer[1024];
    size_t bytes;
    size_t total_bytes = 0;
    
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, 1, bytes, dest) != bytes) {
            printf("Error writing to destination file\n");
            fclose(src);
            fclose(dest);
            return -1;
        }
        total_bytes += bytes;
    }
    
    if (ferror(src)) {
        printf("Error reading from source file\n");
        fclose(src);
        fclose(dest);
        return -1;
    }
    
    fclose(src);
    fclose(dest);
    
    printf("Successfully copied %zu bytes from '%s' to '%s'\n", 
           total_bytes, source, destination);
    return 0;
}

// Count lines in a text file
int count_lines(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error opening file '%s': %s\n", filename, strerror(errno));
        return -1;
    }
    
    int lines = 0;
    int ch;
    
    while ((ch = fgetc(file)) != EOF) {
        if (ch == '\n') {
            lines++;
        }
    }
    
    // If file doesn't end with newline but has content, count last line
    if (ftell(file) > 0) {
        fseek(file, -1, SEEK_END);
        if (fgetc(file) != '\n') {
            lines++;
        }
    }
    
    fclose(file);
    return lines;
}

// Search for text in file
void search_in_file(const char* filename, const char* search_text) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error opening file '%s': %s\n", filename, strerror(errno));
        return;
    }
    
    char line[256];
    int line_number = 1;
    int matches = 0;
    
    printf("Searching for '%s' in '%s':\n", search_text, filename);
    
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, search_text) != NULL) {
            printf("Line %d: %s", line_number, line);
            matches++;
        }
        line_number++;
    }
    
    if (matches == 0) {
        printf("No matches found\n");
    } else {
        printf("Found %d matches\n", matches);
    }
    
    fclose(file);
}

// Create a sample text file for testing
void create_sample_file() {
    FILE* file = fopen("sample.txt", "w");
    if (file == NULL) {
        printf("Error creating sample file\n");
        return;
    }
    
    fprintf(file, "This is the first line of text\n");
    fprintf(file, "The second line contains numbers: 123\n");
    fprintf(file, "Third line has special characters: !@#$%%\n");
    fprintf(file, "Fourth line with more text\n");
    fprintf(file, "Final line without newline");
    
    fclose(file);
    printf("Sample file created\n");
}

int main() {
    // Create sample file
    create_sample_file();
    
    // Test file utilities
    int lines = count_lines("sample.txt");
    if (lines >= 0) {
        printf("Line count: %d\n", lines);
    }
    
    // Search for text
    search_in_file("sample.txt", "line");
    search_in_file("sample.txt", "123");
    
    // Copy file
    if (copy_file("sample.txt", "copy_of_sample.txt") == 0) {
        printf("File copied successfully\n");
        
        // Verify copy
        int original_lines = count_lines("sample.txt");
        int copy_lines = count_lines("copy_of_sample.txt");
        
        if (original_lines == copy_lines) {
            printf("Copy verification: SUCCESS (%d lines)\n", copy_lines);
        } else {
            printf("Copy verification: FAILED\n");
        }
    }
    
    // Demonstrate error handling
    printf("\nError handling examples:\n");
    count_lines("nonexistent.txt");  // Should show error
    copy_file("nonexistent.txt", "output.txt");  // Should show error
    
    return 0;
}
```

## 15. Preprocessor Directives

The preprocessor processes directives before compilation.

### Include and Define

```c
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// Simple macros
#define PI 3.14159
#define MAX_SIZE 100
#define SQUARE(x) ((x) * (x))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

// Multi-line macro
#define SWAP(a, b) do { \
    typeof(a) temp = (a); \
    (a) = (b); \
    (b) = temp; \
} while(0)

// Conditional compilation
#define DEBUG 1
#define VERSION_MAJOR 2
#define VERSION_MINOR 1

#if DEBUG
    #define DEBUG_PRINT(fmt, ...) printf("DEBUG: " fmt, ##__VA_ARGS__)
#else
    #define DEBUG_PRINT(fmt, ...) // No operation
#endif

// Stringification
#define STRINGIFY(x) #x
#define TO_STRING(x) STRINGIFY(x)

// Token pasting
#define CONCAT(a, b) a##b

int main() {
    // Using simple macros
    double radius = 5.0;
    double area = PI * SQUARE(radius);
    printf("Circle area (radius=%.1f): %.2f\n", radius, area);
    
    // Using function-like macros
    int a = 10, b = 20;
    printf("MAX(%d, %d) = %d\n", a, b, MAX(a, b));
    printf("MIN(%d, %d) = %d\n", a, b, MIN(a, b));
    
    // Array with macro-defined size
    int numbers[MAX_SIZE];
    printf("Array size: %d\n", MAX_SIZE);
    
    // Swap macro
    printf("Before swap: a=%d, b=%d\n", a, b);
    SWAP(a, b);
    printf("After swap: a=%d, b=%d\n", a, b);
    
    // Debug printing
    DEBUG_PRINT("This is a debug message with value: %d\n", 42);
    
    // Stringification
    printf("PI as string: %s\n", TO_STRING(PI));
    printf("MAX_SIZE as string: %s\n", TO_STRING(MAX_SIZE));
    
    // Token pasting
    int var1 = 100, var2 = 200;
    printf("CONCAT(var, 1) = %d\n", CONCAT(var, 1));
    printf("CONCAT(var, 2) = %d\n", CONCAT(var, 2));
    
    // Predefined macros
    printf("\nPredefined macros:\n");
    printf("File: %s\n", __FILE__);
    printf("Line: %d\n", __LINE__);
    printf("Date: %s\n", __DATE__);
    printf("Time: %s\n", __TIME__);
    printf("Function: %s\n", __func__);
    
    return 0;
}
```

### Conditional Compilation

```c
#include <stdio.h>

// Version control
#define VERSION_MAJOR 1
#define VERSION_MINOR 5
#define VERSION_PATCH 2

// Feature flags
#define FEATURE_LOGGING 1
#define FEATURE_GRAPHICS 0
#define FEATURE_NETWORK 1

// Platform detection
#ifdef _WIN32
    #define PLATFORM "Windows"
#elif defined(__linux__)
    #define PLATFORM "Linux"
#elif defined(__APPLE__)
    #define PLATFORM "macOS"
#else
    #define PLATFORM "Unknown"
#endif

// Debug levels
#define DEBUG_LEVEL_NONE 0
#define DEBUG_LEVEL_ERROR 1
#define DEBUG_LEVEL_WARNING 2
#define DEBUG_LEVEL_INFO 3

#ifndef DEBUG_LEVEL
    #define DEBUG_LEVEL DEBUG_LEVEL_WARNING
#endif

// Conditional logging macros
#if DEBUG_LEVEL >= DEBUG_LEVEL_ERROR
    #define LOG_ERROR(msg) printf("ERROR: %s\n", msg)
#else
    #define LOG_ERROR(msg)
#endif

#if DEBUG_LEVEL >= DEBUG_LEVEL_WARNING
    #define LOG_WARNING(msg) printf("WARNING: %s\n", msg)
#else
    #define LOG_WARNING(msg)
#endif

#if DEBUG_LEVEL >= DEBUG_LEVEL_INFO
    #define LOG_INFO(msg) printf("INFO: %s\n", msg)
#else
    #define LOG_INFO(msg)
#endif

// Feature-dependent functions
#if FEATURE_LOGGING
void initialize_logging() {
    printf("Logging system initialized\n");
}
#endif

#if FEATURE_GRAPHICS
void initialize_graphics() {
    printf("Graphics system initialized\n");
}
#endif

#if FEATURE_NETWORK
void initialize_network() {
    printf("Network system initialized\n");
}
#endif

// Version checking
#if VERSION_MAJOR >= 2
    #define USE_NEW_API 1
#else
    #define USE_NEW_API 0
#endif

void show_version() {
    printf("Version: %d.%d.%d\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);
    printf("Platform: %s\n", PLATFORM);
    
    #if USE_NEW_API
        printf("Using new API\n");
    #else
        printf("Using legacy API\n");
    #endif
}

int main() {
    show_version();
    
    printf("\nInitializing systems:\n");
    
    #if FEATURE_LOGGING
        initialize_logging();
    #endif
    
    #if FEATURE_GRAPHICS
        initialize_graphics();
    #else
        printf("Graphics disabled\n");
    #endif
    
    #if FEATURE_NETWORK
        initialize_network();
    #endif
    
    printf("\nTesting logging levels:\n");
    LOG_ERROR("This is an error message");
    LOG_WARNING("This is a warning message");
    LOG_INFO("This is an info message");
    
    // Compile-time assertions
    #if VERSION_MAJOR < 1
        #error "Version major must be at least 1"
    #endif
    
    #if MAX_SIZE > 1000
        #warning "MAX_SIZE is very large"
    #endif
    
    return 0;
}
```

### Header Guards and Include Management

```c
// utils.h - Example header file
#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>

// Prevent multiple includes
#ifdef __cplusplus
extern "C" {
#endif

// Constants
#define BUFFER_SIZE 256
#define MAX_ITEMS 100

// Type definitions
typedef struct {
    int id;
    char name[50];
} Item;

// Function declarations
void print_item(const Item* item);
int compare_items(const Item* a, const Item* b);
void sort_items(Item items[], int count);

// Inline function (C99)
static inline int is_valid_id(int id) {
    return id > 0 && id <= 9999;
}

// Macro utilities
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define SAFE_FREE(ptr) do { \
    if (ptr) { \
        free(ptr); \
        ptr = NULL; \
    } \
} while(0)

#ifdef __cplusplus
}
#endif

#endif // UTILS_H

// main.c - Using the header
#include <stdio.h>
// #include "utils.h"  // Would include our header

// Demonstrate header guard simulation
int main() {
    printf("Header guard and include management example\n");
    
    // Simulating utils.h functionality
    typedef struct {
        int id;
        char name[50];
    } Item;
    
    Item items[] = {
        {3, "Item C"},
        {1, "Item A"},
        {2, "Item B"}
    };
    
    int count = sizeof(items) / sizeof(items[0]);
    printf("Number of items: %d\n", count);
    
    // Print items
    for (int i = 0; i < count; i++) {
        printf("ID: %d, Name: %s\n", items[i].id, items[i].name);
    }
    
    // Simulate include guard working
    printf("\nInclude guard prevents multiple inclusions\n");
    printf("Header constants and functions available\n");
    
    return 0;
}
```

## 16. Advanced Topics

### Function Pointers

```c
#include <stdio.h>
#include <stdlib.h>

// Different function signatures for demonstration
int add(int a, int b) { return a + b; }
int subtract(int a, int b) { return a - b; }
int multiply(int a, int b) { return a * b; }
int divide(int a, int b) { return b != 0 ? a / b : 0; }

// Function that takes function pointer as parameter
int calculate(int a, int b, int (*operation)(int, int)) {
    return operation(a, b);
}

// Array of function pointers
typedef int (*MathOperation)(int, int);

// Function pointer in structure
typedef struct {
    char name[20];
    MathOperation func;
} Calculator;

// Higher-order function example
void apply_to_array(int arr[], int size, int (*transform)(int)) {
    for (int i = 0; i < size; i++) {
        arr[i] = transform(arr[i]);
    }
}

int square(int x) { return x * x; }
int double_value(int x) { return x * 2; }

// Callback function example
void process_data(int data[], int size, void (*callback)(int, int)) {
    for (int i = 0; i < size; i++) {
        callback(i, data[i]);
    }
}

void print_element(int index, int value) {
    printf("Element[%d] = %d\n", index, value);
}

int main() {
    // Basic function pointer usage
    int (*math_func)(int, int);
    
    math_func = add;
    printf("Using function pointer for addition: %d\n", math_func(5, 3));
    
    math_func = multiply;
    printf("Using function pointer for multiplication: %d\n", math_func(5, 3));
    
    // Function pointer as parameter
    printf("\nUsing calculate function:\n");
    printf("Add: %d\n", calculate(10, 5, add));
    printf("Subtract: %d\n", calculate(10, 5, subtract));
    printf("Multiply: %d\n", calculate(10, 5, multiply));
    printf("Divide: %d\n", calculate(10, 5, divide));
    
    // Array of function pointers
    MathOperation operations[] = {add, subtract, multiply, divide};
    char* operation_names[] = {"Add", "Subtract", "Multiply", "Divide"};
    
    printf("\nArray of function pointers:\n");
    for (int i = 0; i < 4; i++) {
        printf("%s: %d\n", operation_names[i], operations[i](12, 4));
    }
    
    // Function pointers in structures
    Calculator calculators[] = {
        {"Addition", add},
        {"Subtraction", subtract},
        {"Multiplication", multiply},
        {"Division", divide}
    };
    
    printf("\nCalculators with function pointers:\n");
    for (int i = 0; i < 4; i++) {
        printf("%s: 8 op 2 = %d\n", 
               calculators[i].name, 
               calculators[i].func(8, 2));
    }
    
    // Higher-order functions
    int numbers[] = {1, 2, 3, 4, 5};
    int size = 5;
    
    printf("\nOriginal array: ");
    for (int i = 0; i < size; i++) printf("%d ", numbers[i]);
    printf("\n");
    
    apply_to_array(numbers, size, square);
    printf("After squaring: ");
    for (int i = 0; i < size; i++) printf("%d ", numbers[i]);
    printf("\n");
    
    apply_to_array(numbers, size, double_value);
    printf("After doubling: ");
    for (int i = 0; i < size; i++) printf("%d ", numbers[i]);
    printf("\n");
    
    // Callback functions
    int data[] = {10, 20, 30, 40, 50};
    printf("\nUsing callback function:\n");
    process_data(data, 5, print_element);
    
    return 0;
}
```

### Enums and Unions

```c
#include <stdio.h>
#include <string.h>

// Basic enum
enum Status {
    STATUS_PENDING,
    STATUS_PROCESSING,
    STATUS_COMPLETED,
    STATUS_FAILED
};

// Enum with explicit values
enum ErrorCode {
    ERR_NONE = 0,
    ERR_FILE_NOT_FOUND = 404,
    ERR_PERMISSION_DENIED = 403,
    ERR_OUT_OF_MEMORY = 500,
    ERR_INVALID_INPUT = 400
};

// Enum in typedef
typedef enum {
    MONDAY, TUESDAY, WEDNESDAY, THURSDAY, FRIDAY, SATURDAY, SUNDAY
} Day;

// Union examples
union Data {
    int integer;
    float floating;
    char string[20];
};

// Union with discriminator (tagged union)
typedef enum {
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_STRING
} DataType;

typedef struct {
    DataType type;
    union {
        int int_value;
        float float_value;
        char string_value[50];
    } data;
} TypedData;

// Function to print status
const char* status_to_string(enum Status status) {
    switch (status) {
        case STATUS_PENDING: return "Pending";
        case STATUS_PROCESSING: return "Processing";
        case STATUS_COMPLETED: return "Completed";
        case STATUS_FAILED: return "Failed";
        default: return "Unknown";
    }
}

// Function to print day
const char* day_to_string(Day day) {
    static const char* day_names[] = {
        "Monday", "Tuesday", "Wednesday", "Thursday",
        "Friday", "Saturday", "Sunday"
    };
    
    if (day >= MONDAY && day <= SUNDAY) {
        return day_names[day];
    }
    return "Invalid Day";
}

// Function to print typed data
void print_typed_data(const TypedData* data) {
    printf("Data type: ");
    switch (data->type) {
        case TYPE_INT:
            printf("Integer, value: %d\n", data->data.int_value);
            break;
        case TYPE_FLOAT:
            printf("Float, value: %.2f\n", data->data.float_value);
            break;
        case TYPE_STRING:
            printf("String, value: %s\n", data->data.string_value);
            break;
        default:
            printf("Unknown\n");
    }
}

int main() {
    // Using basic enums
    enum Status current_status = STATUS_PENDING;
    printf("Current status: %s\n", status_to_string(current_status));
    
    current_status = STATUS_COMPLETED;
    printf("Updated status: %s\n", status_to_string(current_status));
    
    // Using enum with explicit values
    enum ErrorCode error = ERR_FILE_NOT_FOUND;
    printf("Error code: %d\n", error);
    
    // Using typedef enum
    Day today = FRIDAY;
    printf("Today is: %s\n", day_to_string(today));
    
    // Loop through days
    printf("\nDays of the week:\n");
    for (Day d = MONDAY; d <= SUNDAY; d++) {
        printf("%d: %s\n", d, day_to_string(d));
    }
    
    // Basic union usage
    union Data data;
    
    data.integer = 42;
    printf("\nUnion as integer: %d\n", data.integer);
    
    data.floating = 3.14f;
    printf("Union as float: %.2f\n", data.floating);
    printf("Union integer after float assignment: %d (corrupted)\n", data.integer);
    
    strcpy(data.string, "Hello");
    printf("Union as string: %s\n", data.string);
    printf("Union integer after string assignment: %d (corrupted)\n", data.integer);
    
    // Tagged union (safe union usage)
    printf("\nTagged union examples:\n");
    
    TypedData typed_data1 = {TYPE_INT, .data.int_value = 100};
    print_typed_data(&typed_data1);
    
    TypedData typed_data2 = {TYPE_FLOAT, .data.float_value = 3.14159f};
    print_typed_data(&typed_data2);
    
    TypedData typed_data3 = {TYPE_STRING};
    strcpy(typed_data3.data.string_value, "Hello, World!");
    print_typed_data(&typed_data3);
    
    // Demonstrate union memory sharing
    printf("\nUnion memory layout:\n");
    printf("Union size: %zu bytes\n", sizeof(union Data));
    printf("Integer size: %zu bytes\n", sizeof(int));
    printf("Float size: %zu bytes\n", sizeof(float));
    printf("String size: %zu bytes\n", sizeof(char[20]));
    
    return 0;
}
```

### Bit Manipulation

```c
#include <stdio.h>
#include <stdint.h>

// Bit manipulation macros
#define SET_BIT(x, n) ((x) |= (1 << (n)))
#define CLEAR_BIT(x, n) ((x) &= ~(1 << (n)))
#define TOGGLE_BIT(x, n) ((x) ^= (1 << (n)))
#define CHECK_BIT(x, n) ((x) & (1 << (n)))

// Print binary representation
void print_binary(unsigned int num, int bits) {
    for (int i = bits - 1; i >= 0; i--) {
        printf("%d", (num >> i) & 1);
        if (i % 4 == 0 && i > 0) printf(" ");
    }
}

// Count set bits (Hamming weight)
int count_set_bits(unsigned int num) {
    int count = 0;
    while (num) {
        count += num & 1;
        num >>= 1;
    }
    return count;
}

// Check if number is power of 2
int is_power_of_2(unsigned int num) {
    return num > 0 && (num & (num - 1)) == 0;
}

// Swap two numbers using XOR
void xor_swap(int* a, int* b) {
    if (a != b) {  // Avoid XOR of same memory location
        *a ^= *b;
        *b ^= *a;
        *a ^= *b;
    }
}

// Find rightmost set bit
int rightmost_set_bit(unsigned int num) {
    return num & -num;
}

// Bitfield example
typedef struct {
    unsigned int flag1 : 1;
    unsigned int flag2 : 1;
    unsigned int flag3 : 1;
    unsigned int value : 5;
    unsigned int unused : 24;
} BitField;

// Permissions system using bits
typedef enum {
    PERM_READ = 1 << 0,     // 001
    PERM_WRITE = 1 << 1,    // 010
    PERM_EXECUTE = 1 << 2   // 100
} Permission;

void print_permissions(unsigned int perms) {
    printf("Permissions: ");
    if (perms & PERM_READ) printf("R");
    if (perms & PERM_WRITE) printf("W");
    if (perms & PERM_EXECUTE) printf("X");
    if (perms == 0) printf("None");
    printf("\n");
}

int main() {
    unsigned int num = 42;  // Binary: 101010
    
    printf("Original number: %u\n", num);
    printf("Binary: ");
    print_binary(num, 8);
    printf("\n\n");
    
    // Basic bit operations
    printf("Bit manipulation operations:\n");
    
    printf("Setting bit 1: ");
    SET_BIT(num, 1);
    print_binary(num, 8);
    printf(" (%u)\n", num);
    
    printf("Clearing bit 3: ");
    CLEAR_BIT(num, 3);
    print_binary(num, 8);
    printf(" (%u)\n", num);
    
    printf("Toggling bit 7: ");
    TOGGLE_BIT(num, 7);
    print_binary(num, 8);
    printf(" (%u)\n", num);
    
    printf("Checking bit 5: %s\n", CHECK_BIT(num, 5) ? "Set" : "Clear");
    
    // Count set bits
    printf("\nSet bits in %u: %d\n", num, count_set_bits(num));
    
    // Power of 2 check
    printf("\nPower of 2 tests:\n");
    int test_nums[] = {1, 2, 3, 4, 8, 15, 16, 32};
    for (int i = 0; i < 8; i++) {
        printf("%d is %sa power of 2\n", 
               test_nums[i], 
               is_power_of_2(test_nums[i]) ? "" : "not ");
    }
    
    // XOR swap
    int a = 15, b = 27;
    printf("\nBefore XOR swap: a=%d, b=%d\n", a, b);
    xor_swap(&a, &b);
    printf("After XOR swap: a=%d, b=%d\n", a, b);
    
    // Rightmost set bit
    printf("\nRightmost set bit examples:\n");
    int numbers[] = {12, 18, 20, 24};
    for (int i = 0; i < 4; i++) {
        printf("%d (", numbers[i]);
        print_binary(numbers[i], 8);
        printf(") -> rightmost set bit: %d\n", rightmost_set_bit(numbers[i]));
    }
    
    // Bitfields
    printf("\nBitfield example:\n");
    BitField bf = {0};
    bf.flag1 = 1;
    bf.flag3 = 1;
    bf.value = 15;
    
    printf("BitField size: %zu bytes\n", sizeof(BitField));
    printf("flag1: %u, flag2: %u, flag3: %u, value: %u\n",
           bf.flag1, bf.flag2, bf.flag3, bf.value);
    
    // Permissions system
    printf("\nPermissions system:\n");
    unsigned int user_perms = PERM_READ | PERM_WRITE;
    unsigned int admin_perms = PERM_READ | PERM_WRITE | PERM_EXECUTE;
    
    printf("User ");
    print_permissions(user_perms);
    printf("Admin ");
    print_permissions(admin_perms);
    
    // Grant execute permission to user
    user_perms |= PERM_EXECUTE;
    printf("User (after granting execute) ");
    print_permissions(user_perms);
    
    // Revoke write permission from user
    user_perms &= ~PERM_WRITE;
    printf("User (after revoking write) ");
    print_permissions(user_perms);
    
    return 0;
}
```

## 17. Data Structures

### Linked Lists

```c
#include <stdio.h>
#include <stdlib.h>

// Node structure for singly linked list
typedef struct Node {
    int data;
    struct Node* next;
} Node;

// Linked list structure
typedef struct {
    Node* head;
    int size;
} LinkedList;

// Initialize linked list
void list_init(LinkedList* list) {
    list->head = NULL;
    list->size = 0;
}

// Create new node
Node* create_node(int data) {
    Node* new_node = (Node*)malloc(sizeof(Node));
    if (new_node == NULL) {
        printf("Memory allocation failed\n");
        return NULL;
    }
    new_node->data = data;
    new_node->next = NULL;
    return new_node;
}

// Insert at beginning
void list_insert_front(LinkedList* list, int data) {
    Node* new_node = create_node(data);
    if (new_node == NULL) return;
    
    new_node->next = list->head;
    list->head = new_node;
    list->size++;
}

// Insert at end
void list_insert_back(LinkedList* list, int data) {
    Node* new_node = create_node(data);
    if (new_node == NULL) return;
    
    if (list->head == NULL) {
        list->head = new_node;
    } else {
        Node* current = list->head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_node;
    }
    list->size++;
}

// Insert at specific position
void list_insert_at(LinkedList* list, int position, int data) {
    if (position < 0 || position > list->size) {
        printf("Invalid position\n");
        return;
    }
    
    if (position == 0) {
        list_insert_front(list, data);
        return;
    }
    
    Node* new_node = create_node(data);
    if (new_node == NULL) return;
    
    Node* current = list->head;
    for (int i = 0; i < position - 1; i++) {
        current = current->next;
    }
    
    new_node->next = current->next;
    current->next = new_node;
    list->size++;
}

// Delete by value
int list_delete(LinkedList* list, int data) {
    if (list->head == NULL) return 0;
    
    // Delete from front
    if (list->head->data == data) {
        Node* temp = list->head;
        list->head = list->head->next;
        free(temp);
        list->size--;
        return 1;
    }
    
    // Delete from middle or end
    Node* current = list->head;
    while (current->next != NULL && current->next->data != data) {
        current = current->next;
    }
    
    if (current->next != NULL) {
        Node* temp = current->next;
        current->next = current->next->next;
        free(temp);
        list->size--;
        return 1;
    }
    
    return 0;  // Not found
}

// Search for value
Node* list_find(LinkedList* list, int data) {
    Node* current = list->head;
    while (current != NULL) {
        if (current->data == data) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// Print list
void list_print(LinkedList* list) {
    printf("List (%d elements): ", list->size);
    Node* current = list->head;
    while (current != NULL) {
        printf("%d", current->data);
        if (current->next != NULL) printf(" -> ");
        current = current->next;
    }
    printf(" -> NULL\n");
}

// Reverse list
void list_reverse(LinkedList* list) {
    Node* prev = NULL;
    Node* current = list->head;
    Node* next = NULL;
    
    while (current != NULL) {
        next = current->next;
        current->next = prev;
        prev = current;
        current = next;
    }
    
    list->head = prev;
}

// Free all nodes
void list_destroy(LinkedList* list) {
    Node* current = list->head;
    while (current != NULL) {
        Node* temp = current;
        current = current->next;
        free(temp);
    }
    list->head = NULL;
    list->size = 0;
}

int main() {
    LinkedList list;
    list_init(&list);
    
    // Insert elements
    printf("Inserting elements:\n");
    list_insert_front(&list, 10);
    list_insert_front(&list, 20);
    list_insert_back(&list, 5);
    list_insert_back(&list, 15);
    list_print(&list);
    
    // Insert at specific position
    list_insert_at(&list, 2, 25);
    printf("After inserting 25 at position 2:\n");
    list_print(&list);
    
    // Search for elements
    printf("\nSearching:\n");
    Node* found = list_find(&list, 15);
    printf("Search for 15: %s\n", found ? "Found" : "Not found");
    
    found = list_find(&list, 100);
    printf("Search for 100: %s\n", found ? "Found" : "Not found");
    
    // Delete elements
    printf("\nDeleting elements:\n");
    if (list_delete(&list, 20)) {
        printf("Deleted 20\n");
    }
    list_print(&list);
    
    if (list_delete(&list, 5)) {
        printf("Deleted 5\n");
    }
    list_print(&list);
    
    // Reverse list
    printf("\nReversing list:\n");
    list_reverse(&list);
    list_print(&list);
    
    // Clean up
    list_destroy(&list);
    printf("List destroyed\n");
    
    return 0;
}
```

### Stacks and Queues

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

// Stack implementation using array
#define STACK_MAX_SIZE 100

typedef struct {
    int data[STACK_MAX_SIZE];
    int top;
} Stack;

// Stack operations
void stack_init(Stack* stack) {
    stack->top = -1;
}

bool stack_is_empty(Stack* stack) {
    return stack->top == -1;
}

bool stack_is_full(Stack* stack) {
    return stack->top == STACK_MAX_SIZE - 1;
}

bool stack_push(Stack* stack, int value) {
    if (stack_is_full(stack)) {
        printf("Stack overflow\n");
        return false;
    }
    stack->data[++stack->top] = value;
    return true;
}

bool stack_pop(Stack* stack, int* value) {
    if (stack_is_empty(stack)) {
        printf("Stack underflow\n");
        return false;
    }
    *value = stack->data[stack->top--];
    return true;
}

bool stack_peek(Stack* stack, int* value) {
    if (stack_is_empty(stack)) {
        printf("Stack is empty\n");
        return false;
    }
    *value = stack->data[stack->top];
    return true;
}

void stack_print(Stack* stack) {
    printf("Stack: ");
    if (stack_is_empty(stack)) {
        printf("Empty\n");
        return;
    }
    
    for (int i = stack->top; i >= 0; i--) {
        printf("%d ", stack->data[i]);
    }
    printf("(top to bottom)\n");
}

// Queue implementation using circular array
#define QUEUE_MAX_SIZE 100

typedef struct {
    int data[QUEUE_MAX_SIZE];
    int front;
    int rear;
    int size;
} Queue;

// Queue operations
void queue_init(Queue* queue) {
    queue->front = 0;
    queue->rear = -1;
    queue->size = 0;
}

bool queue_is_empty(Queue* queue) {
    return queue->size == 0;
}

bool queue_is_full(Queue* queue) {
    return queue->size == QUEUE_MAX_SIZE;
}

bool queue_enqueue(Queue* queue, int value) {
    if (queue_is_full(queue)) {
        printf("Queue overflow\n");
        return false;
    }
    
    queue->rear = (queue->rear + 1) % QUEUE_MAX_SIZE;
    queue->data[queue->rear] = value;
    queue->size++;
    return true;
}

bool queue_dequeue(Queue* queue, int* value) {
    if (queue_is_empty(queue)) {
        printf("Queue underflow\n");
        return false;
    }
    
    *value = queue->data[queue->front];
    queue->front = (queue->front + 1) % QUEUE_MAX_SIZE;
    queue->size--;
    return true;
}

bool queue_front(Queue* queue, int* value) {
    if (queue_is_empty(queue)) {
        printf("Queue is empty\n");
        return false;
    }
    *value = queue->data[queue->front];
    return true;
}

void queue_print(Queue* queue) {
    printf("Queue: ");
    if (queue_is_empty(queue)) {
        printf("Empty\n");
        return;
    }
    
    int index = queue->front;
    for (int i = 0; i < queue->size; i++) {
        printf("%d ", queue->data[index]);
        index = (index + 1) % QUEUE_MAX_SIZE;
    }
    printf("(front to rear)\n");
}

// Practical examples
bool check_balanced_parentheses(const char* expression) {
    Stack stack;
    stack_init(&stack);
    
    for (int i = 0; expression[i] != '\0'; i++) {
        char ch = expression[i];
        
        if (ch == '(' || ch == '[' || ch == '{') {
            stack_push(&stack, ch);
        } else if (ch == ')' || ch == ']' || ch == '}') {
            if (stack_is_empty(&stack)) {
                return false;
            }
            
            int top;
            stack_pop(&stack, &top);
            
            if ((ch == ')' && top != '(') ||
                (ch == ']' && top != '[') ||
                (ch == '}' && top != '{')) {
                return false;
            }
        }
    }
    
    return stack_is_empty(&stack);
}

void simulate_printer_queue() {
    Queue print_queue;
    queue_init(&print_queue);
    
    printf("Printer queue simulation:\n");
    
    // Add print jobs
    printf("Adding print jobs: ");
    for (int i = 1; i <= 5; i++) {
        queue_enqueue(&print_queue, i);
        printf("Job%d ", i);
    }
    printf("\n");
    queue_print(&print_queue);
    
    // Process print jobs
    printf("\nProcessing jobs:\n");
    int job;
    while (!queue_is_empty(&print_queue)) {
        if (queue_dequeue(&print_queue, &job)) {
            printf("Printing Job%d\n", job);
        }
        queue_print(&print_queue);
    }
}

int main() {
    // Stack demonstration
    printf("=== Stack Demonstration ===\n");
    Stack stack;
    stack_init(&stack);
    
    printf("Pushing elements: 10, 20, 30, 40\n");
    stack_push(&stack, 10);
    stack_push(&stack, 20);
    stack_push(&stack, 30);
    stack_push(&stack, 40);
    stack_print(&stack);
    
    int value;
    printf("\nPopping elements:\n");
    while (!stack_is_empty(&stack)) {
        if (stack_pop(&stack, &value)) {
            printf("Popped: %d\n", value);
        }
        stack_print(&stack);
    }
    
    // Queue demonstration
    printf("\n=== Queue Demonstration ===\n");
    Queue queue;
    queue_init(&queue);
    
    printf("Enqueuing elements: 1, 2, 3, 4, 5\n");
    for (int i = 1; i <= 5; i++) {
        queue_enqueue(&queue, i);
    }
    queue_print(&queue);
    
    printf("\nDequeuing elements:\n");
    while (!queue_is_empty(&queue)) {
        if (queue_dequeue(&queue, &value)) {
            printf("Dequeued: %d\n", value);
        }
        queue_print(&queue);
    }
    
    // Practical examples
    printf("\n=== Practical Examples ===\n");
    
    // Balanced parentheses
    const char* expressions[] = {
        "()",
        "(())",
        "([{}])",
        "(()",
        "([)]",
        "{[()()]}"
    };
    
    printf("Balanced parentheses check:\n");
    for (int i = 0; i < 6; i++) {
        bool balanced = check_balanced_parentheses(expressions[i]);
        printf("'%s': %s\n", expressions[i], balanced ? "Balanced" : "Not balanced");
    }
    
    printf("\n");
    simulate_printer_queue();
    
    return 0;
}
```