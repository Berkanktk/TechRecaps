# Java Learning Guide

## Table of Contents
1. [Java Basics](#java-basics)  
   1. [What is Java](#what-is-java)  
   2. [Data Types and Variables](#data-types-and-variables)  
   3. [Operators](#operators)  
   4. [Input and Output](#input-and-output)  
2. [Control Flow](#control-flow)  
   1. [Conditional Statements](#conditional-statements)  
   2. [Loops](#loops)  
   3. [Switch Statement](#switch-statement)  
   4. [Break and Continue](#break-and-continue)  
3. [Methods](#methods)  
   1. [Method Declaration](#method-declaration)  
   2. [Method Overloading](#method-overloading)  
   3. [Variable Arguments](#variable-arguments)  
   4. [Recursion](#recursion)  
4. [Arrays and Strings](#arrays-and-strings)  
   1. [Arrays](#arrays)  
   2. [Multidimensional Arrays](#multidimensional-arrays)  
   3. [String Basics](#string-basics)  
   4. [StringBuilder](#stringbuilder)  
5. [Object-Oriented Programming](#object-oriented-programming)  
   1. [Classes and Objects](#classes-and-objects)  
   2. [Constructors](#constructors)  
   3. [Encapsulation](#encapsulation)  
   4. [Static Members](#static-members)  
6. [Inheritance and Polymorphism](#inheritance-and-polymorphism)  
   1. [Inheritance](#inheritance)  
   2. [Method Overriding](#method-overriding)  
   3. [Abstract Classes](#abstract-classes)  
   4. [Interfaces](#interfaces)  
7. [Collections Framework](#collections-framework)  
   1. [Lists](#lists)  
   2. [Sets](#sets)  
   3. [Maps](#maps)  
   4. [Collections Utility](#collections-utility)  
8. [Exception Handling](#exception-handling)  
   1. [Try-Catch-Finally](#try-catch-finally)  
   2. [Custom Exceptions](#custom-exceptions)  
   3. [Checked vs Unchecked](#checked-vs-unchecked)  
   4. [Best Practices](#best-practices)  
9. [File I/O](#file-io)  
   1. [File Operations](#file-operations)  
   2. [Readers and Writers](#readers-and-writers)  
   3. [Streams](#streams)  
   4. [NIO](#nio)  
10. [Generics](#generics)  
    1. [Generic Classes](#generic-classes)  
    2. [Generic Methods](#generic-methods)  
    3. [Bounded Types](#bounded-types)  
    4. [Wildcards](#wildcards)  
11. [Lambda Expressions and Functional Programming](#lambda-expressions-and-functional-programming)  
    1. [Lambda Syntax](#lambda-syntax)  
    2. [Functional Interfaces](#functional-interfaces)  
    3. [Method References](#method-references)  
    4. [Built-in Functional Interfaces](#built-in-functional-interfaces)  
12. [Stream API](#stream-api)  
    1. [Creating Streams](#creating-streams)  
    2. [Intermediate Operations](#intermediate-operations)  
    3. [Terminal Operations](#terminal-operations)  
    4. [Collectors](#collectors)  
13. [Concurrency and Multithreading](#concurrency-and-multithreading)  
    1. [Thread Basics](#thread-basics)  
    2. [Synchronization](#synchronization)  
    3. [Executor Framework](#executor-framework)  
    4. [Concurrent Collections](#concurrent-collections)  
14. [Annotations and Reflection](#annotations-and-reflection)  
    1. [Built-in Annotations](#built-in-annotations)  
    2. [Custom Annotations](#custom-annotations)  
    3. [Reflection Basics](#reflection-basics)  
    4. [Dynamic Programming](#dynamic-programming)  
15. [Modern Java Features](#modern-java-features)  
    1. [Records](#records)  
    2. [Sealed Classes](#sealed-classes)  
    3. [Pattern Matching](#pattern-matching)  
    4. [Text Blocks](#text-blocks)  


---

## Java Basics

### What is Java

**Java** is a high-level, object-oriented programming language known for platform independence ("Write Once, Run Anywhere").

**Key Features:**
- Platform independent (JVM)
- Object-oriented
- Strongly typed
- Memory management (Garbage Collection)
- Multithreaded
- Secure

**Java Ecosystem:**
- JDK (Java Development Kit)
- JRE (Java Runtime Environment)
- JVM (Java Virtual Machine)

### Data Types and Variables

```java
// Primitive data types
byte smallNumber = 127;           // 8-bit (-128 to 127)
short mediumNumber = 32767;       // 16-bit (-32,768 to 32,767)
int number = 2147483647;          // 32-bit (-2^31 to 2^31-1)
long bigNumber = 9223372036854775807L; // 64-bit

float decimal = 3.14f;            // 32-bit floating point
double precision = 3.14159265359; // 64-bit floating point

char character = 'A';             // 16-bit Unicode character
boolean flag = true;              // true or false

// Reference types
String text = "Hello World";
int[] numbers = {1, 2, 3, 4, 5};

// Variable declaration and initialization
int x;                // Declaration
x = 10;              // Initialization
int y = 20;          // Declaration + initialization

// Constants
final int MAX_SIZE = 100;
final String APP_NAME = "MyApp";

// Type conversion
int intValue = 42;
double doubleValue = intValue;    // Implicit (widening)
int backToInt = (int) doubleValue; // Explicit (narrowing)

// Wrapper classes
Integer wrappedInt = 42;          // Autoboxing
int primitiveInt = wrappedInt;    // Unboxing
```

### Operators

```java
// Arithmetic operators
int a = 10, b = 3;
System.out.println(a + b);  // 13 (addition)
System.out.println(a - b);  // 7 (subtraction)
System.out.println(a * b);  // 30 (multiplication)
System.out.println(a / b);  // 3 (integer division)
System.out.println(a % b);  // 1 (modulo)

// Increment/decrement
int count = 5;
count++;     // Post-increment: count = 6
++count;     // Pre-increment: count = 7
count--;     // Post-decrement: count = 6
--count;     // Pre-decrement: count = 5

// Assignment operators
int x = 10;
x += 5;      // x = x + 5 (15)
x -= 3;      // x = x - 3 (12)
x *= 2;      // x = x * 2 (24)
x /= 4;      // x = x / 4 (6)
x %= 3;      // x = x % 3 (0)

// Comparison operators
System.out.println(a > b);   // true
System.out.println(a < b);   // false
System.out.println(a >= b);  // true
System.out.println(a <= b);  // false
System.out.println(a == b);  // false
System.out.println(a != b);  // true

// Logical operators
boolean p = true, q = false;
System.out.println(p && q);  // false (AND)
System.out.println(p || q);  // true (OR)
System.out.println(!p);      // false (NOT)
System.out.println(p ^ q);   // true (XOR)

// Bitwise operators
int num1 = 5;  // 101 in binary
int num2 = 3;  // 011 in binary
System.out.println(num1 & num2);  // 1 (AND: 001)
System.out.println(num1 | num2);  // 7 (OR: 111)
System.out.println(num1 ^ num2);  // 6 (XOR: 110)
System.out.println(~num1);        // -6 (NOT)
System.out.println(num1 << 1);    // 10 (left shift)
System.out.println(num1 >> 1);    // 2 (right shift)

// Ternary operator
int max = (a > b) ? a : b;
String result = (count > 0) ? "positive" : "zero or negative";
```

### Input and Output

```java
import java.util.Scanner;

public class InputOutput {
    public static void main(String[] args) {
        // Output
        System.out.println("Hello World");           // Print with newline
        System.out.print("Hello ");                  // Print without newline
        System.out.print("World\n");
        
        // Formatted output
        String name = "Alice";
        int age = 25;
        double salary = 50000.50;
        
        System.out.printf("Name: %s, Age: %d%n", name, age);
        System.out.printf("Salary: $%.2f%n", salary);
        System.out.format("Formatted: %s is %d years old%n", name, age);
        
        // Input with Scanner
        Scanner scanner = new Scanner(System.in);
        
        System.out.print("Enter your name: ");
        String userName = scanner.nextLine();
        
        System.out.print("Enter your age: ");
        int userAge = scanner.nextInt();
        
        System.out.print("Enter your height: ");
        double height = scanner.nextDouble();
        
        // Display input
        System.out.printf("Hello %s! You are %d years old and %.2f cm tall.%n", 
                         userName, userAge, height);
        
        scanner.close(); // Always close scanner
    }
}
```

---

## Control Flow

### Conditional Statements

```java
// Simple if statement
int score = 85;
if (score >= 90) {
    System.out.println("Excellent!");
}

// if-else
if (score >= 60) {
    System.out.println("Pass");
} else {
    System.out.println("Fail");
}

// if-else-if ladder
if (score >= 90) {
    System.out.println("Grade: A");
} else if (score >= 80) {
    System.out.println("Grade: B");
} else if (score >= 70) {
    System.out.println("Grade: C");
} else if (score >= 60) {
    System.out.println("Grade: D");
} else {
    System.out.println("Grade: F");
}

// Nested if statements
int age = 20;
boolean hasLicense = true;

if (age >= 18) {
    if (hasLicense) {
        System.out.println("Can drive");
    } else {
        System.out.println("Need license");
    }
} else {
    System.out.println("Too young to drive");
}

// Logical operators in conditions
int temperature = 25;
boolean isSunny = true;

if (temperature > 20 && isSunny) {
    System.out.println("Perfect weather!");
}

if (temperature < 0 || temperature > 40) {
    System.out.println("Extreme weather!");
}

// Ternary operator
String weather = (temperature > 20) ? "warm" : "cold";
int max = (a > b) ? a : b;

// Short-circuit evaluation
boolean result = (x != 0) && (y / x > 2); // Safe division
```

### Loops

```java
// for loop
for (int i = 0; i < 5; i++) {
    System.out.println("Count: " + i);
}

// for loop with different increments
for (int i = 10; i >= 0; i -= 2) {
    System.out.println(i);
}

// Enhanced for loop (for-each)
int[] numbers = {1, 2, 3, 4, 5};
for (int num : numbers) {
    System.out.println(num);
}

String[] fruits = {"apple", "banana", "orange"};
for (String fruit : fruits) {
    System.out.println(fruit);
}

// while loop
int count = 0;
while (count < 3) {
    System.out.println("Count: " + count);
    count++;
}

// do-while loop
int num = 1;
do {
    System.out.println("Number: " + num);
    num++;
} while (num <= 3);

// Infinite loop with break
while (true) {
    String input = scanner.nextLine();
    if (input.equals("quit")) {
        break;
    }
    System.out.println("You entered: " + input);
}

// Nested loops
for (int i = 1; i <= 3; i++) {
    for (int j = 1; j <= 3; j++) {
        System.out.print(i + "," + j + " ");
    }
    System.out.println();
}

// Loop through 2D array
int[][] matrix = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
for (int[] row : matrix) {
    for (int element : row) {
        System.out.print(element + " ");
    }
    System.out.println();
}
```

### Switch Statement

```java
// Traditional switch
int dayOfWeek = 3;
switch (dayOfWeek) {
    case 1:
        System.out.println("Monday");
        break;
    case 2:
        System.out.println("Tuesday");
        break;
    case 3:
        System.out.println("Wednesday");
        break;
    case 4:
        System.out.println("Thursday");
        break;
    case 5:
        System.out.println("Friday");
        break;
    case 6:
    case 7:
        System.out.println("Weekend");
        break;
    default:
        System.out.println("Invalid day");
}

// Switch with String
String grade = "B";
switch (grade) {
    case "A":
        System.out.println("Excellent");
        break;
    case "B":
        System.out.println("Good");
        break;
    case "C":
        System.out.println("Average");
        break;
    case "D":
        System.out.println("Below Average");
        break;
    case "F":
        System.out.println("Fail");
        break;
    default:
        System.out.println("Invalid grade");
}

// Switch expression (Java 14+)
String dayName = switch (dayOfWeek) {
    case 1 -> "Monday";
    case 2 -> "Tuesday";
    case 3 -> "Wednesday";
    case 4 -> "Thursday";
    case 5 -> "Friday";
    case 6, 7 -> "Weekend";
    default -> "Invalid day";
};

// Switch with yield (Java 14+)
String result = switch (grade) {
    case "A" -> {
        System.out.println("Outstanding performance!");
        yield "Excellent";
    }
    case "B" -> "Good";
    case "C" -> "Average";
    default -> "Needs improvement";
};
```

### Break and Continue

```java
// break in loops
for (int i = 0; i < 10; i++) {
    if (i == 5) {
        break; // Exit loop when i equals 5
    }
    System.out.println(i); // Prints 0, 1, 2, 3, 4
}

// continue in loops
for (int i = 0; i < 10; i++) {
    if (i % 2 == 0) {
        continue; // Skip even numbers
    }
    System.out.println(i); // Prints 1, 3, 5, 7, 9
}

// Labeled break and continue
outer: for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (i == 1 && j == 1) {
            break outer; // Break out of both loops
        }
        System.out.println(i + "," + j);
    }
}

// continue with label
outer: for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (j == 1) {
            continue outer; // Continue outer loop
        }
        System.out.println(i + "," + j);
    }
}

// Practical example: finding prime numbers
public static boolean isPrime(int n) {
    if (n <= 1) return false;
    
    for (int i = 2; i <= Math.sqrt(n); i++) {
        if (n % i == 0) {
            return false; // Found divisor, not prime
        }
    }
    return true;
}

// Print first 10 prime numbers
int count = 0;
int num = 2;
while (count < 10) {
    if (isPrime(num)) {
        System.out.println(num);
        count++;
    }
    num++;
}
```

---

## Methods

### Method Declaration

```java
// Basic method syntax
public static returnType methodName(parameters) {
    // method body
    return value; // if not void
}

// Method without parameters
public static void greet() {
    System.out.println("Hello World!");
}

// Method with parameters
public static void greetUser(String name) {
    System.out.println("Hello, " + name + "!");
}

// Method with return value
public static int add(int a, int b) {
    return a + b;
}

// Method with multiple parameters
public static double calculateArea(double length, double width) {
    return length * width;
}

// Method returning multiple values using array
public static int[] getMinMax(int[] numbers) {
    int min = numbers[0];
    int max = numbers[0];
    
    for (int num : numbers) {
        if (num < min) min = num;
        if (num > max) max = num;
    }
    
    return new int[]{min, max};
}

// Using methods
public static void main(String[] args) {
    greet();                           // Hello World!
    greetUser("Alice");               // Hello, Alice!
    
    int sum = add(5, 3);              // 8
    double area = calculateArea(5.0, 3.0); // 15.0
    
    int[] numbers = {3, 7, 1, 9, 4};
    int[] minMax = getMinMax(numbers);
    System.out.println("Min: " + minMax[0] + ", Max: " + minMax[1]);
}

// Method with boolean return
public static boolean isEven(int number) {
    return number % 2 == 0;
}

// Method with String return
public static String getGrade(int score) {
    if (score >= 90) return "A";
    if (score >= 80) return "B";
    if (score >= 70) return "C";
    if (score >= 60) return "D";
    return "F";
}
```

### Method Overloading

```java
// Method overloading - same name, different parameters
public class Calculator {
    
    // Add two integers
    public static int add(int a, int b) {
        return a + b;
    }
    
    // Add three integers
    public static int add(int a, int b, int c) {
        return a + b + c;
    }
    
    // Add two doubles
    public static double add(double a, double b) {
        return a + b;
    }
    
    // Add array of integers
    public static int add(int[] numbers) {
        int sum = 0;
        for (int num : numbers) {
            sum += num;
        }
        return sum;
    }
    
    // Multiply methods
    public static int multiply(int a, int b) {
        return a * b;
    }
    
    public static double multiply(double a, double b) {
        return a * b;
    }
    
    public static int multiply(int a, int b, int c) {
        return a * b * c;
    }
    
    // Print methods with different parameters
    public static void print(String message) {
        System.out.println(message);
    }
    
    public static void print(int number) {
        System.out.println("Number: " + number);
    }
    
    public static void print(String message, int times) {
        for (int i = 0; i < times; i++) {
            System.out.println(message);
        }
    }
    
    public static void main(String[] args) {
        // Calling overloaded methods
        System.out.println(add(5, 3));           // 8
        System.out.println(add(5, 3, 2));        // 10
        System.out.println(add(5.5, 3.2));       // 8.7
        System.out.println(add(new int[]{1, 2, 3, 4})); // 10
        
        print("Hello");                          // Hello
        print(42);                              // Number: 42
        print("Hi", 3);                         // Hi (printed 3 times)
    }
}
```

### Variable Arguments

```java
// Varargs (variable arguments)
public static int sum(int... numbers) {
    int total = 0;
    for (int num : numbers) {
        total += num;
    }
    return total;
}

// Varargs with other parameters (varargs must be last)
public static void printInfo(String name, int... scores) {
    System.out.println("Student: " + name);
    System.out.print("Scores: ");
    for (int score : scores) {
        System.out.print(score + " ");
    }
    System.out.println();
}

// Generic varargs
public static void printItems(String... items) {
    for (String item : items) {
        System.out.println("- " + item);
    }
}

// Finding maximum with varargs
public static int max(int first, int... rest) {
    int maximum = first;
    for (int num : rest) {
        if (num > maximum) {
            maximum = num;
        }
    }
    return maximum;
}

// Using varargs
public static void main(String[] args) {
    // Different ways to call varargs methods
    System.out.println(sum());                    // 0
    System.out.println(sum(5));                   // 5
    System.out.println(sum(1, 2, 3));            // 6
    System.out.println(sum(1, 2, 3, 4, 5));      // 15
    
    // Passing array to varargs
    int[] numbers = {10, 20, 30};
    System.out.println(sum(numbers));            // 60
    
    printInfo("Alice", 85, 92, 78);
    printInfo("Bob", 90);
    printInfo("Charlie"); // No scores
    
    printItems("apple", "banana", "orange");
    
    System.out.println(max(5, 3, 9, 1, 7));     // 9
}
```

### Recursion

```java
// Factorial calculation
public static long factorial(int n) {
    // Base case
    if (n <= 1) {
        return 1;
    }
    // Recursive case
    return n * factorial(n - 1);
}

// Fibonacci sequence
public static int fibonacci(int n) {
    if (n <= 1) {
        return n;
    }
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// Power calculation
public static double power(double base, int exponent) {
    if (exponent == 0) {
        return 1;
    }
    if (exponent < 0) {
        return 1 / power(base, -exponent);
    }
    return base * power(base, exponent - 1);
}

// Sum of digits
public static int sumOfDigits(int number) {
    if (number == 0) {
        return 0;
    }
    return (number % 10) + sumOfDigits(number / 10);
}

// Binary search (recursive)
public static int binarySearch(int[] arr, int target, int left, int right) {
    if (left > right) {
        return -1; // Not found
    }
    
    int mid = left + (right - left) / 2;
    
    if (arr[mid] == target) {
        return mid;
    } else if (arr[mid] > target) {
        return binarySearch(arr, target, left, mid - 1);
    } else {
        return binarySearch(arr, target, mid + 1, right);
    }
}

// Tower of Hanoi
public static void hanoi(int n, char source, char destination, char auxiliary) {
    if (n == 1) {
        System.out.println("Move disk 1 from " + source + " to " + destination);
        return;
    }
    
    hanoi(n - 1, source, auxiliary, destination);
    System.out.println("Move disk " + n + " from " + source + " to " + destination);
    hanoi(n - 1, auxiliary, destination, source);
}

// Using recursive methods
public static void main(String[] args) {
    System.out.println("5! = " + factorial(5));          // 120
    System.out.println("Fibonacci(10) = " + fibonacci(10)); // 55
    System.out.println("2^8 = " + power(2, 8));          // 256.0
    System.out.println("Sum of digits of 12345 = " + sumOfDigits(12345)); // 15
    
    int[] sortedArray = {1, 3, 5, 7, 9, 11, 13, 15};
    int index = binarySearch(sortedArray, 7, 0, sortedArray.length - 1);
    System.out.println("7 found at index: " + index);    // 3
    
    System.out.println("Tower of Hanoi for 3 disks:");
    hanoi(3, 'A', 'C', 'B');
}
```

---

## Arrays and Strings

### Arrays

```java
// Array declaration and initialization
int[] numbers = new int[5];           // Array of 5 integers (default: 0)
int[] values = {1, 2, 3, 4, 5};      // Initialize with values
int[] data = new int[]{10, 20, 30};  // Alternative syntax

// Accessing array elements
numbers[0] = 100;                     // Set first element
numbers[4] = 500;                     // Set last element
int first = numbers[0];               // Get first element
int length = numbers.length;          // Array length

// Array iteration
for (int i = 0; i < numbers.length; i++) {
    System.out.println("Index " + i + ": " + numbers[i]);
}

// Enhanced for loop
for (int num : values) {
    System.out.println(num);
}

// Array operations
public static void arrayOperations() {
    int[] arr = {5, 2, 8, 1, 9, 3};
    
    // Find maximum
    int max = arr[0];
    for (int num : arr) {
        if (num > max) max = num;
    }
    System.out.println("Maximum: " + max);
    
    // Find minimum
    int min = arr[0];
    for (int num : arr) {
        if (num < min) min = num;
    }
    System.out.println("Minimum: " + min);
    
    // Calculate sum
    int sum = 0;
    for (int num : arr) {
        sum += num;
    }
    System.out.println("Sum: " + sum);
    System.out.println("Average: " + (double)sum / arr.length);
}

// Array sorting (bubble sort)
public static void bubbleSort(int[] arr) {
    int n = arr.length;
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                // Swap elements
                int temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

// Linear search
public static int linearSearch(int[] arr, int target) {
    for (int i = 0; i < arr.length; i++) {
        if (arr[i] == target) {
            return i;
        }
    }
    return -1; // Not found
}

// Array copying
int[] original = {1, 2, 3, 4, 5};
int[] copy1 = original.clone();              // Shallow copy
int[] copy2 = Arrays.copyOf(original, original.length);
int[] copy3 = new int[original.length];
System.arraycopy(original, 0, copy3, 0, original.length);
```

### Multidimensional Arrays

```java
// 2D array declaration and initialization
int[][] matrix = new int[3][4];              // 3 rows, 4 columns
int[][] grid = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};

// Jagged arrays (different row lengths)
int[][] jagged = {{1, 2}, {3, 4, 5}, {6, 7, 8, 9}};

// Accessing 2D array elements
matrix[0][0] = 10;                          // First row, first column
matrix[2][3] = 99;                          // Last row, last column
int value = grid[1][2];                     // Gets 6

// Iterating through 2D arrays
for (int i = 0; i < grid.length; i++) {
    for (int j = 0; j < grid[i].length; j++) {
        System.out.print(grid[i][j] + " ");
    }
    System.out.println();
}

// Enhanced for loop with 2D arrays
for (int[] row : grid) {
    for (int element : row) {
        System.out.print(element + " ");
    }
    System.out.println();
}

// Matrix operations
public static int[][] addMatrices(int[][] a, int[][] b) {
    int rows = a.length;
    int cols = a[0].length;
    int[][] result = new int[rows][cols];
    
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            result[i][j] = a[i][j] + b[i][j];
        }
    }
    return result;
}

// Matrix multiplication
public static int[][] multiplyMatrices(int[][] a, int[][] b) {
    int rowsA = a.length;
    int colsA = a[0].length;
    int colsB = b[0].length;
    int[][] result = new int[rowsA][colsB];
    
    for (int i = 0; i < rowsA; i++) {
        for (int j = 0; j < colsB; j++) {
            for (int k = 0; k < colsA; k++) {
                result[i][j] += a[i][k] * b[k][j];
            }
        }
    }
    return result;
}

// 3D arrays
int[][][] cube = new int[3][3][3];          // 3x3x3 cube
cube[1][2][0] = 42;

// Array of arrays with different types
String[][] students = {
    {"Alice", "Bob", "Charlie"},
    {"Diana", "Eve"},
    {"Frank", "Grace", "Henry", "Ivy"}
};
```

### String Basics

```java
// String creation
String str1 = "Hello";                      // String literal
String str2 = new String("World");          // Using constructor
String str3 = "Hello";                      // Same reference as str1

// String comparison
System.out.println(str1 == str3);           // true (same reference)
System.out.println(str1 == str2);           // false (different objects)
System.out.println(str1.equals("Hello"));   // true (content comparison)
System.out.println(str1.equalsIgnoreCase("HELLO")); // true

// String properties
String text = "Java Programming";
System.out.println(text.length());          // 16
System.out.println(text.charAt(0));         // 'J'
System.out.println(text.charAt(text.length() - 1)); // 'g'
System.out.println(text.isEmpty());         // false
System.out.println("".isEmpty());           // true

// String searching
System.out.println(text.indexOf('a'));      // 1 (first occurrence)
System.out.println(text.lastIndexOf('a'));  // 3 (last occurrence)
System.out.println(text.indexOf("Program")); // 5
System.out.println(text.contains("Java"));   // true
System.out.println(text.startsWith("Java")); // true
System.out.println(text.endsWith("ing"));    // true

// String manipulation
String name = "  Alice Smith  ";
System.out.println(name.trim());            // "Alice Smith"
System.out.println(name.toLowerCase());     // "  alice smith  "
System.out.println(name.toUpperCase());     // "  ALICE SMITH  "
System.out.println(text.replace('a', 'o')); // "Jovo Progromming"
System.out.println(text.substring(5));      // "Programming"
System.out.println(text.substring(0, 4));   // "Java"

// String splitting
String sentence = "apple,banana,orange";
String[] fruits = sentence.split(",");      // ["apple", "banana", "orange"]

String words = "Hello world java";
String[] wordArray = words.split(" ");      // ["Hello", "world", "java"]

// String joining
String joined = String.join("-", fruits);   // "apple-banana-orange"

// String formatting
String formatted = String.format("Name: %s, Age: %d, Score: %.2f", 
                                 "Alice", 25, 95.678);
System.out.println(formatted);              // Name: Alice, Age: 25, Score: 95.68

// Character operations
char[] charArray = text.toCharArray();
for (char c : charArray) {
    System.out.print(c + " ");
}

// String immutability
String original = "Hello";
String modified = original.concat(" World"); // Creates new string
System.out.println(original);               // "Hello" (unchanged)
System.out.println(modified);               // "Hello World"
```

### StringBuilder

```java
// StringBuilder for efficient string manipulation
StringBuilder sb = new StringBuilder();
sb.append("Hello");
sb.append(" ");
sb.append("World");
System.out.println(sb.toString());          // "Hello World"

// StringBuilder with initial capacity
StringBuilder buffer = new StringBuilder(100);

// StringBuilder methods
StringBuilder builder = new StringBuilder("Java");
builder.append(" Programming");              // "Java Programming"
builder.insert(4, " Language");             // "Java Language Programming"
builder.delete(4, 13);                      // "Java Programming"
builder.reverse();                          // "gnimmargorP avaJ"
builder.reverse();                          // "Java Programming"

// Replacing content
builder.replace(5, 16, "Development");      // "Java Development"
builder.setCharAt(0, 'j');                 // "java Development"

// StringBuilder vs String performance
public static void stringConcatenation() {
    // Inefficient with String
    long start = System.currentTimeMillis();
    String result = "";
    for (int i = 0; i < 10000; i++) {
        result += "a";  // Creates new string each time
    }
    long end = System.currentTimeMillis();
    System.out.println("String concatenation: " + (end - start) + "ms");
    
    // Efficient with StringBuilder
    start = System.currentTimeMillis();
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 10000; i++) {
        sb.append("a");  // Modifies existing buffer
    }
    String sbResult = sb.toString();
    end = System.currentTimeMillis();
    System.out.println("StringBuilder: " + (end - start) + "ms");
}

// Practical StringBuilder usage
public static String createCSV(String[] headers, String[][] data) {
    StringBuilder csv = new StringBuilder();
    
    // Add headers
    for (int i = 0; i < headers.length; i++) {
        csv.append(headers[i]);
        if (i < headers.length - 1) {
            csv.append(",");
        }
    }
    csv.append("\n");
    
    // Add data rows
    for (String[] row : data) {
        for (int i = 0; i < row.length; i++) {
            csv.append(row[i]);
            if (i < row.length - 1) {
                csv.append(",");
            }
        }
        csv.append("\n");
    }
    
    return csv.toString();
}

// StringBuffer (thread-safe alternative to StringBuilder)
StringBuffer threadSafeBuffer = new StringBuffer();
threadSafeBuffer.append("Thread-safe");
threadSafeBuffer.append(" string building");
```

---

## Object-Oriented Programming

### Classes and Objects

```java
// Basic class definition
public class Person {
    // Instance variables (fields)
    private String name;
    private int age;
    private String email;
    
    // Constructor
    public Person(String name, int age, String email) {
        this.name = name;
        this.age = age;
        this.email = email;
    }
    
    // Getter methods
    public String getName() {
        return name;
    }
    
    public int getAge() {
        return age;
    }
    
    public String getEmail() {
        return email;
    }
    
    // Setter methods
    public void setName(String name) {
        this.name = name;
    }
    
    public void setAge(int age) {
        if (age >= 0) {
            this.age = age;
        }
    }
    
    public void setEmail(String email) {
        this.email = email;
    }
    
    // Instance methods
    public void introduce() {
        System.out.println("Hi, I'm " + name + ", " + age + " years old.");
    }
    
    public boolean isAdult() {
        return age >= 18;
    }
    
    // toString method
    @Override
    public String toString() {
        return "Person{name='" + name + "', age=" + age + ", email='" + email + "'}";
    }
}

// Using the class
public class PersonDemo {
    public static void main(String[] args) {
        // Creating objects
        Person person1 = new Person("Alice", 25, "alice@email.com");
        Person person2 = new Person("Bob", 17, "bob@email.com");
        
        // Using methods
        person1.introduce();                     // Hi, I'm Alice, 25 years old.
        System.out.println(person1.isAdult());  // true
        System.out.println(person2.isAdult());  // false
        
        // Using getters and setters
        System.out.println(person1.getName());  // Alice
        person1.setAge(26);
        System.out.println(person1.getAge());   // 26
        
        // toString method
        System.out.println(person1);            // Person{name='Alice', age=26, email='alice@email.com'}
    }
}

// More complex class example
public class BankAccount {
    private String accountNumber;
    private String ownerName;
    private double balance;
    private static int totalAccounts = 0;    // Static variable
    
    public BankAccount(String accountNumber, String ownerName, double initialBalance) {
        this.accountNumber = accountNumber;
        this.ownerName = ownerName;
        this.balance = initialBalance;
        totalAccounts++;  // Increment static counter
    }
    
    public void deposit(double amount) {
        if (amount > 0) {
            balance += amount;
            System.out.println("Deposited $" + amount + ". New balance: $" + balance);
        } else {
            System.out.println("Invalid deposit amount.");
        }
    }
    
    public boolean withdraw(double amount) {
        if (amount > 0 && amount <= balance) {
            balance -= amount;
            System.out.println("Withdrew $" + amount + ". New balance: $" + balance);
            return true;
        } else {
            System.out.println("Invalid withdrawal amount or insufficient funds.");
            return false;
        }
    }
    
    public double getBalance() {
        return balance;
    }
    
    public static int getTotalAccounts() {
        return totalAccounts;
    }
    
    public void printAccountInfo() {
        System.out.println("Account: " + accountNumber);
        System.out.println("Owner: " + ownerName);
        System.out.println("Balance: $" + balance);
    }
}
```

### Constructors

```java
public class Student {
    private String name;
    private int id;
    private String major;
    private double gpa;
    
    // Default constructor
    public Student() {
        this.name = "Unknown";
        this.id = 0;
        this.major = "Undeclared";
        this.gpa = 0.0;
    }
    
    // Parameterized constructor
    public Student(String name, int id) {
        this.name = name;
        this.id = id;
        this.major = "Undeclared";
        this.gpa = 0.0;
    }
    
    // Constructor with all parameters
    public Student(String name, int id, String major, double gpa) {
        this.name = name;
        this.id = id;
        this.major = major;
        this.gpa = gpa;
    }
    
    // Constructor chaining
    public Student(String name, int id, String major) {
        this(name, id, major, 0.0);  // Calls the 4-parameter constructor
    }
    
    // Copy constructor
    public Student(Student other) {
        this.name = other.name;
        this.id = other.id;
        this.major = other.major;
        this.gpa = other.gpa;
    }
    
    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    
    public String getMajor() { return major; }
    public void setMajor(String major) { this.major = major; }
    
    public double getGpa() { return gpa; }
    public void setGpa(double gpa) {
        if (gpa >= 0.0 && gpa <= 4.0) {
            this.gpa = gpa;
        }
    }
    
    @Override
    public String toString() {
        return String.format("Student{name='%s', id=%d, major='%s', gpa=%.2f}", 
                           name, id, major, gpa);
    }
}

// Using different constructors
public class ConstructorDemo {
    public static void main(String[] args) {
        Student student1 = new Student();                              // Default
        Student student2 = new Student("Alice", 12345);                // Name and ID
        Student student3 = new Student("Bob", 12346, "Computer Science"); // Name, ID, major
        Student student4 = new Student("Charlie", 12347, "Mathematics", 3.8); // All parameters
        Student student5 = new Student(student4);                      // Copy constructor
        
        System.out.println(student1);  // Default values
        System.out.println(student2);  // Name and ID set
        System.out.println(student3);  // Name, ID, and major set
        System.out.println(student4);  // All values set
        System.out.println(student5);  // Copy of student4
    }
}
```

### Encapsulation

```java
// Proper encapsulation example
public class Employee {
    // Private fields (data hiding)
    private String name;
    private int employeeId;
    private double salary;
    private String department;
    
    // Constructor
    public Employee(String name, int employeeId, double salary, String department) {
        this.name = name;
        this.employeeId = employeeId;
        setSalary(salary);      // Use setter for validation
        this.department = department;
    }
    
    // Public getter methods (controlled access)
    public String getName() {
        return name;
    }
    
    public int getEmployeeId() {
        return employeeId;
    }
    
    public double getSalary() {
        return salary;
    }
    
    public String getDepartment() {
        return department;
    }
    
    // Public setter methods (controlled modification)
    public void setName(String name) {
        if (name != null && !name.trim().isEmpty()) {
            this.name = name;
        }
    }
    
    public void setSalary(double salary) {
        if (salary >= 0) {
            this.salary = salary;
        } else {
            System.out.println("Salary cannot be negative");
        }
    }
    
    public void setDepartment(String department) {
        if (department != null && !department.trim().isEmpty()) {
            this.department = department;
        }
    }
    
    // Business logic methods
    public void giveRaise(double percentage) {
        if (percentage > 0) {
            salary += salary * (percentage / 100);
            System.out.println(name + " received a " + percentage + "% raise.");
        }
    }
    
    public double getAnnualSalary() {
        return salary * 12;
    }
    
    // Read-only computed property
    public String getDisplayName() {
        return name + " (ID: " + employeeId + ")";
    }
}

// Encapsulation with validation
public class Temperature {
    private double celsius;
    
    public Temperature(double celsius) {
        setCelsius(celsius);
    }
    
    public double getCelsius() {
        return celsius;
    }
    
    public void setCelsius(double celsius) {
        if (celsius >= -273.15) {  // Absolute zero validation
            this.celsius = celsius;
        } else {
            throw new IllegalArgumentException("Temperature cannot be below absolute zero");
        }
    }
    
    // Computed properties
    public double getFahrenheit() {
        return (celsius * 9.0 / 5.0) + 32;
    }
    
    public void setFahrenheit(double fahrenheit) {
        setCelsius((fahrenheit - 32) * 5.0 / 9.0);
    }
    
    public double getKelvin() {
        return celsius + 273.15;
    }
    
    public void setKelvin(double kelvin) {
        setCelsius(kelvin - 273.15);
    }
    
    @Override
    public String toString() {
        return String.format("%.2f°C (%.2f°F, %.2f K)", 
                           celsius, getFahrenheit(), getKelvin());
    }
}

// Immutable class example
public final class Point {
    private final int x;
    private final int y;
    
    public Point(int x, int y) {
        this.x = x;
        this.y = y;
    }
    
    public int getX() {
        return x;
    }
    
    public int getY() {
        return y;
    }
    
    // Return new instance instead of modifying current
    public Point move(int deltaX, int deltaY) {
        return new Point(x + deltaX, y + deltaY);
    }
    
    public double distanceTo(Point other) {
        int dx = this.x - other.x;
        int dy = this.y - other.y;
        return Math.sqrt(dx * dx + dy * dy);
    }
    
    @Override
    public String toString() {
        return "(" + x + ", " + y + ")";
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Point point = (Point) obj;
        return x == point.x && y == point.y;
    }
}
```

### Static Members

```java
public class MathUtils {
    // Static constants
    public static final double PI = 3.14159265359;
    public static final double E = 2.71828182846;
    
    // Static variable
    private static int operationCount = 0;
    
    // Static methods
    public static int add(int a, int b) {
        operationCount++;
        return a + b;
    }
    
    public static int multiply(int a, int b) {
        operationCount++;
        return a * b;
    }
    
    public static double circleArea(double radius) {
        operationCount++;
        return PI * radius * radius;
    }
    
    public static int factorial(int n) {
        operationCount++;
        if (n <= 1) return 1;
        return n * factorial(n - 1);
    }
    
    public static int getOperationCount() {
        return operationCount;
    }
    
    public static void resetOperationCount() {
        operationCount = 0;
    }
}

// Class with static and instance members
public class Counter {
    // Static variable - shared among all instances
    private static int totalInstances = 0;
    
    // Instance variable - unique to each instance
    private int instanceCount = 0;
    private String name;
    
    // Static initializer block
    static {
        System.out.println("Counter class loaded");
        totalInstances = 0;
    }
    
    // Instance initializer block
    {
        System.out.println("Creating new Counter instance");
    }
    
    public Counter(String name) {
        this.name = name;
        totalInstances++;
    }
    
    public void increment() {
        instanceCount++;
    }
    
    public int getInstanceCount() {
        return instanceCount;
    }
    
    // Static method
    public static int getTotalInstances() {
        return totalInstances;
    }
    
    // Static method cannot access instance variables
    public static void printClassInfo() {
        System.out.println("Counter class - Total instances: " + totalInstances);
        // System.out.println(name); // Error: Cannot access instance variable
    }
    
    // Instance method can access both static and instance variables
    public void printInfo() {
        System.out.println("Counter " + name + ": count=" + instanceCount + 
                          ", total instances=" + totalInstances);
    }
}

// Singleton pattern using static
public class Database {
    private static Database instance = null;
    private String connectionString;
    
    // Private constructor prevents instantiation
    private Database() {
        connectionString = "jdbc:mysql://localhost:3306/mydb";
    }
    
    // Static method to get single instance
    public static Database getInstance() {
        if (instance == null) {
            instance = new Database();
        }
        return instance;
    }
    
    public void connect() {
        System.out.println("Connected to: " + connectionString);
    }
    
    public void disconnect() {
        System.out.println("Disconnected from database");
    }
}

// Using static members
public class StaticDemo {
    public static void main(String[] args) {
        // Using static methods without creating instance
        System.out.println(MathUtils.add(5, 3));           // 8
        System.out.println(MathUtils.circleArea(5));       // 78.54
        System.out.println(MathUtils.factorial(5));        // 120
        System.out.println("Operations: " + MathUtils.getOperationCount()); // 3
        
        // Creating Counter instances
        Counter c1 = new Counter("First");
        Counter c2 = new Counter("Second");
        
        c1.increment();
        c1.increment();
        c2.increment();
        
        c1.printInfo();  // Counter First: count=2, total instances=2
        c2.printInfo();  // Counter Second: count=1, total instances=2
        
        Counter.printClassInfo();  // Counter class - Total instances: 2
        
        // Singleton usage
        Database db1 = Database.getInstance();
        Database db2 = Database.getInstance();
        System.out.println(db1 == db2);  // true (same instance)
        
        db1.connect();
    }
}

---

## Inheritance and Polymorphism

### Inheritance

```java
// Base class (superclass)
public class Animal {
    protected String name;
    protected int age;
    
    public Animal(String name, int age) {
        this.name = name;
        this.age = age;
    }
    
    public void eat() {
        System.out.println(name + " is eating");
    }
    
    public void sleep() {
        System.out.println(name + " is sleeping");
    }
    
    public void makeSound() {
        System.out.println(name + " makes a sound");
    }
    
    public String getInfo() {
        return name + " (" + age + " years old)";
    }
}

// Derived class (subclass)
public class Dog extends Animal {
    private String breed;
    
    public Dog(String name, int age, String breed) {
        super(name, age);  // Call parent constructor
        this.breed = breed;
    }
    
    // Method specific to Dog
    public void bark() {
        System.out.println(name + " barks: Woof!");
    }
    
    public void fetch() {
        System.out.println(name + " fetches the ball");
    }
    
    public String getBreed() {
        return breed;
    }
    
    @Override
    public String getInfo() {
        return super.getInfo() + ", Breed: " + breed;
    }
}

public class Cat extends Animal {
    private boolean indoor;
    
    public Cat(String name, int age, boolean indoor) {
        super(name, age);
        this.indoor = indoor;
    }
    
    public void meow() {
        System.out.println(name + " meows: Meow!");
    }
    
    public void purr() {
        System.out.println(name + " purrs contentedly");
    }
    
    public boolean isIndoor() {
        return indoor;
    }
    
    @Override
    public String getInfo() {
        return super.getInfo() + ", Indoor: " + indoor;
    }
}

// Multi-level inheritance
public class Puppy extends Dog {
    private boolean isVaccinated;
    
    public Puppy(String name, int age, String breed, boolean isVaccinated) {
        super(name, age, breed);
        this.isVaccinated = isVaccinated;
    }
    
    public void play() {
        System.out.println(name + " is playing like a puppy");
    }
    
    public boolean isVaccinated() {
        return isVaccinated;
    }
    
    @Override
    public String getInfo() {
        return super.getInfo() + ", Vaccinated: " + isVaccinated;
    }
}

// Using inheritance
public class InheritanceDemo {
    public static void main(String[] args) {
        Animal animal = new Animal("Generic Animal", 5);
        Dog dog = new Dog("Buddy", 3, "Golden Retriever");
        Cat cat = new Cat("Whiskers", 2, true);
        Puppy puppy = new Puppy("Max", 1, "Labrador", true);
        
        // Common methods (inherited)
        animal.eat();  // Generic Animal is eating
        dog.eat();     // Buddy is eating
        cat.sleep();   // Whiskers is sleeping
        
        // Specific methods
        dog.bark();    // Buddy barks: Woof!
        cat.meow();    // Whiskers meows: Meow!
        puppy.play();  // Max is playing like a puppy
        
        // Overridden methods
        System.out.println(animal.getInfo()); // Generic Animal (5 years old)
        System.out.println(dog.getInfo());    // Buddy (3 years old), Breed: Golden Retriever
        System.out.println(puppy.getInfo());  // Max (1 years old), Breed: Labrador, Vaccinated: true
    }
}
```

### Method Overriding

```java
// Base class
public class Vehicle {
    protected String brand;
    protected int year;
    
    public Vehicle(String brand, int year) {
        this.brand = brand;
        this.year = year;
    }
    
    public void start() {
        System.out.println("Vehicle is starting");
    }
    
    public void stop() {
        System.out.println("Vehicle is stopping");
    }
    
    public double calculateFuelEfficiency() {
        return 25.0; // Default efficiency
    }
    
    public String getDetails() {
        return brand + " " + year;
    }
    
    // Final method cannot be overridden
    public final void displayLicense() {
        System.out.println("Vehicle License: ABC-123");
    }
}

public class Car extends Vehicle {
    private int doors;
    
    public Car(String brand, int year, int doors) {
        super(brand, year);
        this.doors = doors;
    }
    
    @Override
    public void start() {
        System.out.println("Car engine starts with key");
    }
    
    @Override
    public double calculateFuelEfficiency() {
        return 30.0; // Better efficiency for cars
    }
    
    @Override
    public String getDetails() {
        return super.getDetails() + ", Doors: " + doors;
    }
    
    // New method specific to Car
    public void openTrunk() {
        System.out.println("Trunk opened");
    }
}

public class Motorcycle extends Vehicle {
    private boolean hasSidecar;
    
    public Motorcycle(String brand, int year, boolean hasSidecar) {
        super(brand, year);
        this.hasSidecar = hasSidecar;
    }
    
    @Override
    public void start() {
        System.out.println("Motorcycle starts with kick/button");
    }
    
    @Override
    public double calculateFuelEfficiency() {
        return 50.0; // Better efficiency for motorcycles
    }
    
    @Override
    public String getDetails() {
        return super.getDetails() + ", Sidecar: " + hasSidecar;
    }
    
    public void wheelie() {
        System.out.println("Motorcycle does a wheelie!");
    }
}

// Runtime polymorphism
public class PolymorphismDemo {
    public static void main(String[] args) {
        Vehicle[] vehicles = {
            new Vehicle("Generic", 2020),
            new Car("Toyota", 2021, 4),
            new Motorcycle("Honda", 2019, false)
        };
        
        for (Vehicle vehicle : vehicles) {
            System.out.println("=== " + vehicle.getClass().getSimpleName() + " ===");
            vehicle.start();                    // Calls overridden method
            System.out.println("Efficiency: " + vehicle.calculateFuelEfficiency() + " mpg");
            System.out.println("Details: " + vehicle.getDetails());
            vehicle.stop();
            System.out.println();
        }
        
        // Type checking and casting
        for (Vehicle vehicle : vehicles) {
            if (vehicle instanceof Car) {
                Car car = (Car) vehicle;
                car.openTrunk();
            } else if (vehicle instanceof Motorcycle) {
                Motorcycle bike = (Motorcycle) vehicle;
                bike.wheelie();
            }
        }
    }
}
```

### Abstract Classes

```java
// Abstract class
public abstract class Shape {
    protected String color;
    protected double x, y; // Position
    
    public Shape(String color, double x, double y) {
        this.color = color;
        this.x = x;
        this.y = y;
    }
    
    // Abstract methods - must be implemented by subclasses
    public abstract double calculateArea();
    public abstract double calculatePerimeter();
    public abstract void draw();
    
    // Concrete methods - can be inherited as-is
    public void move(double deltaX, double deltaY) {
        this.x += deltaX;
        this.y += deltaY;
        System.out.println("Shape moved to (" + x + ", " + y + ")");
    }
    
    public String getColor() {
        return color;
    }
    
    public void setColor(String color) {
        this.color = color;
    }
    
    // Template method pattern
    public final void display() {
        System.out.println("=== " + getClass().getSimpleName() + " ===");
        System.out.println("Color: " + color);
        System.out.println("Position: (" + x + ", " + y + ")");
        System.out.println("Area: " + calculateArea());
        System.out.println("Perimeter: " + calculatePerimeter());
        draw();
    }
}

public class Circle extends Shape {
    private double radius;
    
    public Circle(String color, double x, double y, double radius) {
        super(color, x, y);
        this.radius = radius;
    }
    
    @Override
    public double calculateArea() {
        return Math.PI * radius * radius;
    }
    
    @Override
    public double calculatePerimeter() {
        return 2 * Math.PI * radius;
    }
    
    @Override
    public void draw() {
        System.out.println("Drawing a circle with radius " + radius);
    }
    
    public double getRadius() {
        return radius;
    }
}

public class Rectangle extends Shape {
    private double width, height;
    
    public Rectangle(String color, double x, double y, double width, double height) {
        super(color, x, y);
        this.width = width;
        this.height = height;
    }
    
    @Override
    public double calculateArea() {
        return width * height;
    }
    
    @Override
    public double calculatePerimeter() {
        return 2 * (width + height);
    }
    
    @Override
    public void draw() {
        System.out.println("Drawing a rectangle " + width + "x" + height);
    }
    
    public double getWidth() { return width; }
    public double getHeight() { return height; }
}

public class Triangle extends Shape {
    private double side1, side2, side3;
    
    public Triangle(String color, double x, double y, double side1, double side2, double side3) {
        super(color, x, y);
        this.side1 = side1;
        this.side2 = side2;
        this.side3 = side3;
    }
    
    @Override
    public double calculateArea() {
        // Using Heron's formula
        double s = calculatePerimeter() / 2;
        return Math.sqrt(s * (s - side1) * (s - side2) * (s - side3));
    }
    
    @Override
    public double calculatePerimeter() {
        return side1 + side2 + side3;
    }
    
    @Override
    public void draw() {
        System.out.println("Drawing a triangle with sides " + side1 + ", " + side2 + ", " + side3);
    }
}

// Using abstract classes
public class AbstractDemo {
    public static void main(String[] args) {
        // Cannot instantiate abstract class
        // Shape shape = new Shape("red", 0, 0); // Error
        
        Shape[] shapes = {
            new Circle("red", 0, 0, 5),
            new Rectangle("blue", 10, 10, 4, 6),
            new Triangle("green", 5, 5, 3, 4, 5)
        };
        
        for (Shape shape : shapes) {
            shape.display();
            System.out.println();
        }
        
        // Move shapes
        shapes[0].move(2, 3);
        shapes[1].setColor("yellow");
    }
}
```

### Interfaces

```java
// Interface definition
public interface Drawable {
    // Public static final by default
    String DEFAULT_COLOR = "black";
    
    // Abstract methods by default
    void draw();
    void resize(double factor);
    
    // Default method (Java 8+)
    default void highlight() {
        System.out.println("Highlighting with yellow border");
    }
    
    // Static method (Java 8+)
    static void printDrawingInfo() {
        System.out.println("Drawing interface v1.0");
    }
}

public interface Moveable {
    void move(double deltaX, double deltaY);
    double getSpeed();
    void setSpeed(double speed);
}

public interface Colorable {
    void setColor(String color);
    String getColor();
    
    default void fade() {
        System.out.println("Fading color effect");
    }
}

// Multiple interface implementation
public class GraphicsObject implements Drawable, Moveable, Colorable {
    private double x, y;
    private double speed;
    private String color;
    private double size;
    
    public GraphicsObject(double x, double y, String color, double size) {
        this.x = x;
        this.y = y;
        this.color = color;
        this.size = size;
        this.speed = 1.0;
    }
    
    @Override
    public void draw() {
        System.out.println("Drawing graphics object at (" + x + ", " + y + ") in " + color);
    }
    
    @Override
    public void resize(double factor) {
        size *= factor;
        System.out.println("Resized to " + size);
    }
    
    @Override
    public void move(double deltaX, double deltaY) {
        x += deltaX * speed;
        y += deltaY * speed;
        System.out.println("Moved to (" + x + ", " + y + ")");
    }
    
    @Override
    public double getSpeed() {
        return speed;
    }
    
    @Override
    public void setSpeed(double speed) {
        this.speed = speed;
    }
    
    @Override
    public void setColor(String color) {
        this.color = color;
    }
    
    @Override
    public String getColor() {
        return color;
    }
}

// Functional interface (Single Abstract Method)
@FunctionalInterface
public interface Calculator {
    double calculate(double a, double b);
    
    // Default and static methods allowed
    default void printResult(double result) {
        System.out.println("Result: " + result);
    }
    
    static Calculator getAdder() {
        return (a, b) -> a + b;
    }
}

// Interface inheritance
public interface AdvancedDrawable extends Drawable {
    void animate();
    void addEffect(String effect);
}

public class AdvancedShape implements AdvancedDrawable {
    private String name;
    
    public AdvancedShape(String name) {
        this.name = name;
    }
    
    @Override
    public void draw() {
        System.out.println("Drawing advanced shape: " + name);
    }
    
    @Override
    public void resize(double factor) {
        System.out.println("Resizing " + name + " by factor " + factor);
    }
    
    @Override
    public void animate() {
        System.out.println("Animating " + name);
    }
    
    @Override
    public void addEffect(String effect) {
        System.out.println("Adding " + effect + " effect to " + name);
    }
}

// Using interfaces
public class InterfaceDemo {
    public static void main(String[] args) {
        GraphicsObject obj = new GraphicsObject(0, 0, "red", 10);
        
        // Using interface methods
        obj.draw();
        obj.move(5, 3);
        obj.setColor("blue");
        obj.resize(1.5);
        obj.highlight(); // Default method
        
        Drawable.printDrawingInfo(); // Static method
        
        // Interface references
        Drawable drawable = obj;
        Moveable moveable = obj;
        Colorable colorable = obj;
        
        drawable.draw();
        moveable.move(2, 2);
        colorable.setColor("green");
        
        // Functional interface with lambda
        Calculator adder = (a, b) -> a + b;
        Calculator multiplier = (a, b) -> a * b;
        
        double result1 = adder.calculate(5, 3);
        double result2 = multiplier.calculate(4, 7);
        
        adder.printResult(result1);
        multiplier.printResult(result2);
        
        // Method reference
        Calculator staticAdder = Calculator.getAdder();
        staticAdder.printResult(staticAdder.calculate(10, 20));
        
        // Advanced interface
        AdvancedShape advShape = new AdvancedShape("Star");
        advShape.draw();
        advShape.animate();
        advShape.addEffect("glow");
    }
}
```

---

## Collections Framework

### Lists

```java
import java.util.*;

public class ListExamples {
    public static void main(String[] args) {
        // ArrayList - dynamic array
        List<String> arrayList = new ArrayList<>();
        arrayList.add("apple");
        arrayList.add("banana");
        arrayList.add("cherry");
        arrayList.add(1, "orange"); // Insert at index
        
        System.out.println("ArrayList: " + arrayList);
        System.out.println("Size: " + arrayList.size());
        System.out.println("Element at index 2: " + arrayList.get(2));
        
        // LinkedList - doubly linked list
        List<String> linkedList = new LinkedList<>();
        linkedList.add("first");
        linkedList.add("second");
        linkedList.add("third");
        
        LinkedList<String> ll = (LinkedList<String>) linkedList;
        ll.addFirst("start");
        ll.addLast("end");
        
        System.out.println("LinkedList: " + linkedList);
        
        // Vector - synchronized ArrayList
        Vector<Integer> vector = new Vector<>();
        vector.add(10);
        vector.add(20);
        vector.add(30);
        
        System.out.println("Vector: " + vector);
        
        // Common List operations
        listOperations();
        
        // List iteration
        listIteration();
        
        // Performance comparison
        performanceComparison();
    }
    
    public static void listOperations() {
        List<String> fruits = new ArrayList<>(Arrays.asList("apple", "banana", "cherry", "date"));
        
        // Searching
        System.out.println("Contains 'banana': " + fruits.contains("banana"));
        System.out.println("Index of 'cherry': " + fruits.indexOf("cherry"));
        System.out.println("Last index of 'apple': " + fruits.lastIndexOf("apple"));
        
        // Modification
        fruits.set(1, "blueberry");     // Replace element
        fruits.remove("date");          // Remove by value
        fruits.remove(0);               // Remove by index
        
        System.out.println("Modified: " + fruits);
        
        // Sublist
        List<String> subList = fruits.subList(0, 2);
        System.out.println("Sublist: " + subList);
        
        // Bulk operations
        List<String> moreFruits = Arrays.asList("grape", "kiwi");
        fruits.addAll(moreFruits);
        System.out.println("After addAll: " + fruits);
        
        fruits.removeAll(Arrays.asList("grape", "kiwi"));
        System.out.println("After removeAll: " + fruits);
        
        // Clear
        fruits.clear();
        System.out.println("After clear: " + fruits + ", isEmpty: " + fruits.isEmpty());
    }
    
    public static void listIteration() {
        List<Integer> numbers = Arrays.asList(1, 2, 3, 4, 5);
        
        // Enhanced for loop
        System.out.print("Enhanced for: ");
        for (int num : numbers) {
            System.out.print(num + " ");
        }
        System.out.println();
        
        // Iterator
        System.out.print("Iterator: ");
        Iterator<Integer> iterator = numbers.iterator();
        while (iterator.hasNext()) {
            System.out.print(iterator.next() + " ");
        }
        System.out.println();
        
        // ListIterator (bidirectional)
        System.out.print("ListIterator (reverse): ");
        ListIterator<Integer> listIterator = numbers.listIterator(numbers.size());
        while (listIterator.hasPrevious()) {
            System.out.print(listIterator.previous() + " ");
        }
        System.out.println();
        
        // Stream API (Java 8+)
        System.out.print("Stream filter: ");
        numbers.stream()
               .filter(n -> n % 2 == 0)
               .forEach(n -> System.out.print(n + " "));
        System.out.println();
    }
    
    public static void performanceComparison() {
        int size = 100000;
        
        // ArrayList vs LinkedList for random access
        List<Integer> arrayList = new ArrayList<>();
        List<Integer> linkedList = new LinkedList<>();
        
        // Fill lists
        for (int i = 0; i < size; i++) {
            arrayList.add(i);
            linkedList.add(i);
        }
        
        // Random access performance
        long start = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            arrayList.get(size / 2);
        }
        long arrayListTime = System.currentTimeMillis() - start;
        
        start = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            linkedList.get(size / 2);
        }
        long linkedListTime = System.currentTimeMillis() - start;
        
        System.out.println("Random access (1000 operations):");
        System.out.println("ArrayList: " + arrayListTime + "ms");
        System.out.println("LinkedList: " + linkedListTime + "ms");
    }
}
```

### Sets

```java
import java.util.*;

public class SetExamples {
    public static void main(String[] args) {
        // HashSet - hash table based
        Set<String> hashSet = new HashSet<>();
        hashSet.add("apple");
        hashSet.add("banana");
        hashSet.add("cherry");
        hashSet.add("apple");  // Duplicate - will be ignored
        
        System.out.println("HashSet: " + hashSet);  // Order not guaranteed
        
        // LinkedHashSet - maintains insertion order
        Set<String> linkedHashSet = new LinkedHashSet<>();
        linkedHashSet.add("first");
        linkedHashSet.add("second");
        linkedHashSet.add("third");
        linkedHashSet.add("first");  // Duplicate ignored
        
        System.out.println("LinkedHashSet: " + linkedHashSet);  // Insertion order maintained
        
        // TreeSet - sorted set
        Set<String> treeSet = new TreeSet<>();
        treeSet.add("zebra");
        treeSet.add("apple");
        treeSet.add("monkey");
        treeSet.add("banana");
        
        System.out.println("TreeSet: " + treeSet);  // Natural ordering
        
        // Set operations
        setOperations();
        
        // Custom objects in sets
        customObjectSets();
        
        // Set with custom comparator
        customComparatorSet();
    }
    
    public static void setOperations() {
        Set<Integer> set1 = new HashSet<>(Arrays.asList(1, 2, 3, 4, 5));
        Set<Integer> set2 = new HashSet<>(Arrays.asList(4, 5, 6, 7, 8));
        
        // Union
        Set<Integer> union = new HashSet<>(set1);
        union.addAll(set2);
        System.out.println("Union: " + union);
        
        // Intersection
        Set<Integer> intersection = new HashSet<>(set1);
        intersection.retainAll(set2);
        System.out.println("Intersection: " + intersection);
        
        // Difference
        Set<Integer> difference = new HashSet<>(set1);
        difference.removeAll(set2);
        System.out.println("Difference (set1 - set2): " + difference);
        
        // Symmetric difference
        Set<Integer> symmetricDiff = new HashSet<>(set1);
        symmetricDiff.addAll(set2);
        Set<Integer> temp = new HashSet<>(set1);
        temp.retainAll(set2);
        symmetricDiff.removeAll(temp);
        System.out.println("Symmetric difference: " + symmetricDiff);
        
        // Subset check
        Set<Integer> subset = new HashSet<>(Arrays.asList(2, 3));
        System.out.println("Is subset: " + set1.containsAll(subset));
    }
    
    public static void customObjectSets() {
        // Person class for demonstration
        class Person {
            private String name;
            private int age;
            
            public Person(String name, int age) {
                this.name = name;
                this.age = age;
            }
            
            @Override
            public boolean equals(Object obj) {
                if (this == obj) return true;
                if (obj == null || getClass() != obj.getClass()) return false;
                Person person = (Person) obj;
                return age == person.age && Objects.equals(name, person.name);
            }
            
            @Override
            public int hashCode() {
                return Objects.hash(name, age);
            }
            
            @Override
            public String toString() {
                return name + "(" + age + ")";
            }
        }
        
        Set<Person> people = new HashSet<>();
        people.add(new Person("Alice", 25));
        people.add(new Person("Bob", 30));
        people.add(new Person("Alice", 25));  // Duplicate based on equals()
        
        System.out.println("People set: " + people);
        
        // TreeSet with Comparable
        class ComparablePerson extends Person implements Comparable<ComparablePerson> {
            public ComparablePerson(String name, int age) {
                super(name, age);
            }
            
            @Override
            public int compareTo(ComparablePerson other) {
                int nameComparison = this.toString().compareTo(other.toString());
                return nameComparison != 0 ? nameComparison : Integer.compare(this.hashCode(), other.hashCode());
            }
        }
        
        Set<ComparablePerson> sortedPeople = new TreeSet<>();
        sortedPeople.add(new ComparablePerson("Charlie", 35));
        sortedPeople.add(new ComparablePerson("Alice", 25));
        sortedPeople.add(new ComparablePerson("Bob", 30));
        
        System.out.println("Sorted people: " + sortedPeople);
    }
    
    public static void customComparatorSet() {
        // TreeSet with custom comparator
        Set<String> lengthSortedSet = new TreeSet<>((s1, s2) -> {
            int lengthComparison = Integer.compare(s1.length(), s2.length());
            return lengthComparison != 0 ? lengthComparison : s1.compareTo(s2);
        });
        
        lengthSortedSet.add("elephant");
        lengthSortedSet.add("cat");
        lengthSortedSet.add("dog");
        lengthSortedSet.add("butterfly");
        lengthSortedSet.add("bee");
        
        System.out.println("Length sorted set: " + lengthSortedSet);
        
        // NavigableSet operations (TreeSet implements NavigableSet)
        NavigableSet<String> navigableSet = new TreeSet<>(lengthSortedSet);
        
        System.out.println("First: " + navigableSet.first());
        System.out.println("Last: " + navigableSet.last());
        System.out.println("Higher than 'dog': " + navigableSet.higher("dog"));
        System.out.println("Lower than 'dog': " + navigableSet.lower("dog"));
        System.out.println("Ceiling of 'dog': " + navigableSet.ceiling("dog"));
        System.out.println("Floor of 'dog': " + navigableSet.floor("dog"));
        
        // Subset operations
        System.out.println("Head set (before 'dog'): " + navigableSet.headSet("dog"));
        System.out.println("Tail set (from 'dog'): " + navigableSet.tailSet("dog"));
        System.out.println("Sub set: " + navigableSet.subSet("cat", "elephant"));
    }
}
```

### Maps

```java
import java.util.*;

public class MapExamples {
    public static void main(String[] args) {
        // HashMap - hash table based
        Map<String, Integer> hashMap = new HashMap<>();
        hashMap.put("apple", 5);
        hashMap.put("banana", 3);
        hashMap.put("cherry", 8);
        hashMap.put("apple", 7);  // Updates existing value
        
        System.out.println("HashMap: " + hashMap);
        
        // LinkedHashMap - maintains insertion order
        Map<String, Integer> linkedHashMap = new LinkedHashMap<>();
        linkedHashMap.put("first", 1);
        linkedHashMap.put("second", 2);
        linkedHashMap.put("third", 3);
        
        System.out.println("LinkedHashMap: " + linkedHashMap);
        
        // TreeMap - sorted by keys
        Map<String, Integer> treeMap = new TreeMap<>();
        treeMap.put("zebra", 26);
        treeMap.put("apple", 1);
        treeMap.put("monkey", 13);
        
        System.out.println("TreeMap: " + treeMap);  // Sorted by keys
        
        // Hashtable - synchronized HashMap
        Hashtable<String, String> hashtable = new Hashtable<>();
        hashtable.put("key1", "value1");
        hashtable.put("key2", "value2");
        
        System.out.println("Hashtable: " + hashtable);
        
        // Map operations
        mapOperations();
        
        // Map iteration
        mapIteration();
        
        // Nested maps
        nestedMaps();
        
        // Custom key objects
        customKeyMaps();
    }
    
    public static void mapOperations() {
        Map<String, Integer> scores = new HashMap<>();
        scores.put("Alice", 95);
        scores.put("Bob", 87);
        scores.put("Charlie", 92);
        scores.put("Diana", 78);
        
        // Basic operations
        System.out.println("Alice's score: " + scores.get("Alice"));
        System.out.println("Eve's score: " + scores.get("Eve"));  // null
        System.out.println("Eve's score with default: " + scores.getOrDefault("Eve", 0));
        
        // Check operations
        System.out.println("Contains 'Bob': " + scores.containsKey("Bob"));
        System.out.println("Contains score 87: " + scores.containsValue(87));
        System.out.println("Is empty: " + scores.isEmpty());
        System.out.println("Size: " + scores.size());
        
        // Conditional operations (Java 8+)
        scores.putIfAbsent("Eve", 85);  // Only puts if key doesn't exist
        scores.computeIfAbsent("Frank", k -> k.length() * 10);  // Compute value if absent
        scores.computeIfPresent("Alice", (k, v) -> v + 5);  // Compute if present
        scores.compute("Bob", (k, v) -> v != null ? v + 2 : 50);  // Always compute
        
        System.out.println("After conditional operations: " + scores);
        
        // Replace operations
        scores.replace("Charlie", 92, 94);  // Replace if current value matches
        scores.replace("Diana", 80);  // Replace unconditionally
        scores.replaceAll((k, v) -> v + 1);  // Replace all values
        
        System.out.println("After replacements: " + scores);
        
        // Merge operation
        Map<String, Integer> bonusPoints = new HashMap<>();
        bonusPoints.put("Alice", 5);
        bonusPoints.put("Grace", 10);
        
        bonusPoints.forEach((k, v) -> scores.merge(k, v, Integer::sum));
        System.out.println("After merge: " + scores);
        
        // Remove operations
        scores.remove("Grace");
        scores.remove("Alice", 101);  // Remove only if value matches
        System.out.println("After removals: " + scores);
    }
    
    public static void mapIteration() {
        Map<String, Integer> map = new HashMap<>();
        map.put("one", 1);
        map.put("two", 2);
        map.put("three", 3);
        
        // Iterate over keys
        System.out.print("Keys: ");
        for (String key : map.keySet()) {
            System.out.print(key + " ");
        }
        System.out.println();
        
        // Iterate over values
        System.out.print("Values: ");
        for (Integer value : map.values()) {
            System.out.print(value + " ");
        }
        System.out.println();
        
        // Iterate over entries
        System.out.println("Entries:");
        for (Map.Entry<String, Integer> entry : map.entrySet()) {
            System.out.println(entry.getKey() + " = " + entry.getValue());
        }
        
        // Java 8 forEach
        System.out.println("Using forEach:");
        map.forEach((k, v) -> System.out.println(k + " -> " + v));
        
        // Stream API
        System.out.println("Even values:");
        map.entrySet().stream()
           .filter(entry -> entry.getValue() % 2 == 0)
           .forEach(entry -> System.out.println(entry.getKey() + " = " + entry.getValue()));
    }
    
    public static void nestedMaps() {
        // Map of maps - representing a grade book
        Map<String, Map<String, Integer>> gradebook = new HashMap<>();
        
        // Alice's grades
        Map<String, Integer> aliceGrades = new HashMap<>();
        aliceGrades.put("Math", 95);
        aliceGrades.put("Science", 88);
        aliceGrades.put("English", 92);
        
        // Bob's grades
        Map<String, Integer> bobGrades = new HashMap<>();
        bobGrades.put("Math", 87);
        bobGrades.put("Science", 91);
        bobGrades.put("English", 85);
        
        gradebook.put("Alice", aliceGrades);
        gradebook.put("Bob", bobGrades);
        
        // Access nested data
        System.out.println("Alice's Math grade: " + gradebook.get("Alice").get("Math"));
        
        // Calculate averages
        gradebook.forEach((student, grades) -> {
            double average = grades.values().stream().mapToInt(Integer::intValue).average().orElse(0);
            System.out.println(student + "'s average: " + average);
        });
        
        // Add new grade
        gradebook.computeIfAbsent("Charlie", k -> new HashMap<>()).put("Math", 93);
        System.out.println("Updated gradebook: " + gradebook);
    }
    
    public static void customKeyMaps() {
        // Custom key class
        class Student {
            private String name;
            private int id;
            
            public Student(String name, int id) {
                this.name = name;
                this.id = id;
            }
            
            @Override
            public boolean equals(Object obj) {
                if (this == obj) return true;
                if (obj == null || getClass() != obj.getClass()) return false;
                Student student = (Student) obj;
                return id == student.id && Objects.equals(name, student.name);
            }
            
            @Override
            public int hashCode() {
                return Objects.hash(name, id);
            }
            
            @Override
            public String toString() {
                return name + "(" + id + ")";
            }
        }
        
        Map<Student, String> studentMajors = new HashMap<>();
        Student alice = new Student("Alice", 123);
        Student bob = new Student("Bob", 456);
        
        studentMajors.put(alice, "Computer Science");
        studentMajors.put(bob, "Mathematics");
        studentMajors.put(new Student("Alice", 123), "Physics");  // Updates existing
        
        System.out.println("Student majors: " + studentMajors);
        
        // TreeMap with custom comparator for keys
        Map<Student, String> sortedStudents = new TreeMap<>((s1, s2) -> {
            int nameComparison = s1.name.compareTo(s2.name);
            return nameComparison != 0 ? nameComparison : Integer.compare(s1.id, s2.id);
        });
        
        sortedStudents.putAll(studentMajors);
        sortedStudents.put(new Student("Charlie", 789), "Biology");
        
        System.out.println("Sorted students: " + sortedStudents);
    }
}
```

### Collections Utility

```java
import java.util.*;

public class CollectionsUtilityExamples {
    public static void main(String[] args) {
        // Sorting
        sortingExamples();
        
        // Searching
        searchingExamples();
        
        // Min/Max operations
        minMaxExamples();
        
        // Reversing and shuffling
        reverseShuffleExamples();
        
        // Frequency and disjoint
        frequencyExamples();
        
        // Immutable collections
        immutableCollections();
        
        // Synchronized collections
        synchronizedCollections();
    }
    
    public static void sortingExamples() {
        List<String> fruits = new ArrayList<>(Arrays.asList("banana", "apple", "cherry", "date"));
        
        // Natural ordering
        Collections.sort(fruits);
        System.out.println("Sorted fruits: " + fruits);
        
        // Custom comparator
        Collections.sort(fruits, (a, b) -> Integer.compare(a.length(), b.length()));
        System.out.println("Sorted by length: " + fruits);
        
        // Reverse order
        Collections.sort(fruits, Collections.reverseOrder());
        System.out.println("Reverse sorted: " + fruits);
        
        // Custom objects
        class Person {
            String name;
            int age;
            
            Person(String name, int age) {
                this.name = name;
                this.age = age;
            }
            
            @Override
            public String toString() {
                return name + "(" + age + ")";
            }
        }
        
        List<Person> people = new ArrayList<>();
        people.add(new Person("Alice", 25));
        people.add(new Person("Bob", 30));
        people.add(new Person("Charlie", 20));
        
        // Sort by age
        Collections.sort(people, Comparator.comparing(p -> p.age));
        System.out.println("People sorted by age: " + people);
        
        // Sort by name
        Collections.sort(people, Comparator.comparing(p -> p.name));
        System.out.println("People sorted by name: " + people);
    }
    
    public static void searchingExamples() {
        List<Integer> numbers = Arrays.asList(1, 3, 5, 7, 9, 11, 13);
        
        // Binary search (list must be sorted)
        int index = Collections.binarySearch(numbers, 7);
        System.out.println("Index of 7: " + index);
        
        int notFound = Collections.binarySearch(numbers, 6);
        System.out.println("Index of 6 (not found): " + notFound);  // Negative value
        
        // Binary search with comparator
        List<String> words = Arrays.asList("apple", "banana", "cherry", "date");
        int wordIndex = Collections.binarySearch(words, "cherry");
        System.out.println("Index of 'cherry': " + wordIndex);
        
        // Custom comparator search
        List<String> lengthSorted = Arrays.asList("cat", "dog", "bird", "elephant");
        Collections.sort(lengthSorted, Comparator.comparing(String::length));
        int lengthIndex = Collections.binarySearch(lengthSorted, "bird", 
                                                  Comparator.comparing(String::length));
        System.out.println("Index of 'bird' by length: " + lengthIndex);
    }
    
    public static void minMaxExamples() {
        List<Integer> numbers = Arrays.asList(5, 2, 8, 1, 9, 3);
        
        // Natural ordering
        System.out.println("Min: " + Collections.min(numbers));
        System.out.println("Max: " + Collections.max(numbers));
        
        // Custom comparator
        List<String> words = Arrays.asList("elephant", "cat", "dog", "butterfly");
        String shortest = Collections.min(words, Comparator.comparing(String::length));
        String longest = Collections.max(words, Comparator.comparing(String::length));
        
        System.out.println("Shortest word: " + shortest);
        System.out.println("Longest word: " + longest);
    }
    
    public static void reverseShuffleExamples() {
        List<Integer> numbers = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5));
        
        // Reverse
        Collections.reverse(numbers);
        System.out.println("Reversed: " + numbers);
        
        // Shuffle
        Collections.shuffle(numbers);
        System.out.println("Shuffled: " + numbers);
        
        // Shuffle with custom random
        Collections.shuffle(numbers, new Random(42));  // Deterministic shuffle
        System.out.println("Deterministic shuffle: " + numbers);
        
        // Rotate
        List<String> letters = new ArrayList<>(Arrays.asList("A", "B", "C", "D", "E"));
        Collections.rotate(letters, 2);  // Rotate right by 2
        System.out.println("Rotated right by 2: " + letters);
        
        Collections.rotate(letters, -3);  // Rotate left by 3
        System.out.println("Rotated left by 3: " + letters);
    }
    
    public static void frequencyExamples() {
        List<String> items = Arrays.asList("apple", "banana", "apple", "cherry", "banana", "apple");
        
        // Frequency count
        int appleCount = Collections.frequency(items, "apple");
        System.out.println("Frequency of 'apple': " + appleCount);
        
        // Check if collections are disjoint (no common elements)
        List<String> fruits = Arrays.asList("apple", "banana");
        List<String> vegetables = Arrays.asList("carrot", "lettuce");
        List<String> mixed = Arrays.asList("apple", "carrot");
        
        System.out.println("Fruits and vegetables disjoint: " + Collections.disjoint(fruits, vegetables));
        System.out.println("Fruits and mixed disjoint: " + Collections.disjoint(fruits, mixed));
        
        // Replace all occurrences
        List<String> mutableItems = new ArrayList<>(items);
        Collections.replaceAll(mutableItems, "apple", "orange");
        System.out.println("After replacing apples: " + mutableItems);
        
        // Swap elements
        Collections.swap(mutableItems, 0, mutableItems.size() - 1);
        System.out.println("After swapping first and last: " + mutableItems);
    }
    
    public static void immutableCollections() {
        List<String> mutableList = new ArrayList<>(Arrays.asList("a", "b", "c"));
        
        // Unmodifiable views
        List<String> unmodifiableList = Collections.unmodifiableList(mutableList);
        Set<String> unmodifiableSet = Collections.unmodifiableSet(new HashSet<>(mutableList));
        Map<String, Integer> mutableMap = new HashMap<>();
        mutableMap.put("key", 1);
        Map<String, Integer> unmodifiableMap = Collections.unmodifiableMap(mutableMap);
        
        System.out.println("Unmodifiable list: " + unmodifiableList);
        
        // Trying to modify will throw UnsupportedOperationException
        try {
            unmodifiableList.add("d");
        } catch (UnsupportedOperationException e) {
            System.out.println("Cannot modify unmodifiable list");
        }
        
        // Empty collections
        List<String> emptyList = Collections.emptyList();
        Set<String> emptySet = Collections.emptySet();
        Map<String, String> emptyMap = Collections.emptyMap();
        
        // Singleton collections
        List<String> singletonList = Collections.singletonList("only");
        Set<String> singletonSet = Collections.singleton("unique");
        Map<String, String> singletonMap = Collections.singletonMap("key", "value");
        
        System.out.println("Singleton list: " + singletonList);
        System.out.println("Singleton set: " + singletonSet);
        System.out.println("Singleton map: " + singletonMap);
        
        // Checked collections (type safety at runtime)
        List<String> checkedList = Collections.checkedList(new ArrayList<>(), String.class);
        checkedList.add("safe");
        System.out.println("Checked list: " + checkedList);
    }
    
    public static void synchronizedCollections() {
        // Thread-safe wrappers
        List<String> list = new ArrayList<>();
        List<String> syncList = Collections.synchronizedList(list);
        
        Set<String> set = new HashSet<>();
        Set<String> syncSet = Collections.synchronizedSet(set);
        
        Map<String, String> map = new HashMap<>();
        Map<String, String> syncMap = Collections.synchronizedMap(map);
        
        // Safe iteration requires manual synchronization
        synchronized (syncList) {
            Iterator<String> it = syncList.iterator();
            while (it.hasNext()) {
                System.out.println(it.next());
            }
        }
        
        // Fill collections
        List<String> fillList = new ArrayList<>(Collections.nCopies(5, "default"));
        System.out.println("Filled list: " + fillList);
        
        // Copy
        List<String> source = Arrays.asList("a", "b", "c", "d");
        List<String> dest = new ArrayList<>(Collections.nCopies(source.size(), null));
        Collections.copy(dest, source);
        System.out.println("Copied list: " + dest);
        
        // Add all
        List<String> target = new ArrayList<>();
        Collections.addAll(target, "x", "y", "z");
        System.out.println("Added all: " + target);
    }
}

---

## Exception Handling

### Try-Catch-Finally

```java
// Basic try-catch
public class ExceptionHandling {
    public static void main(String[] args) {
        // Simple exception handling
        try {
            int result = 10 / 0;  // ArithmeticException
            System.out.println(result);
        } catch (ArithmeticException e) {
            System.out.println("Cannot divide by zero!");
            System.out.println("Error: " + e.getMessage());
        }
        
        // Multiple catch blocks
        try {
            String str = null;
            System.out.println(str.length());  // NullPointerException
            
            int[] arr = new int[5];
            System.out.println(arr[10]);       // ArrayIndexOutOfBoundsException
        } catch (NullPointerException e) {
            System.out.println("Null pointer error: " + e.getMessage());
        } catch (ArrayIndexOutOfBoundsException e) {
            System.out.println("Array index error: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("General error: " + e.getMessage());
        }
        
        // try-catch-finally
        try {
            System.out.println("In try block");
            // Some risky operation
        } catch (Exception e) {
            System.out.println("In catch block");
        } finally {
            System.out.println("In finally block - always executes");
        }
        
        // try-with-resources (Java 7+)
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.print("Enter a number: ");
            int number = scanner.nextInt();
            System.out.println("You entered: " + number);
        } catch (Exception e) {
            System.out.println("Input error: " + e.getMessage());
        }
        // Scanner automatically closed
    }
    
    // Method that throws exception
    public static int divide(int a, int b) throws ArithmeticException {
        if (b == 0) {
            throw new ArithmeticException("Division by zero not allowed");
        }
        return a / b;
    }
    
    // Multiple exceptions in throws clause
    public static void riskyMethod() throws IOException, SQLException {
        // Method that might throw multiple types of exceptions
    }
    
    // Exception propagation
    public static void method1() throws Exception {
        method2();
    }
    
    public static void method2() throws Exception {
        throw new Exception("Error from method2");
    }
}
```

### Custom Exceptions

```java
// Custom checked exception
class InvalidAgeException extends Exception {
    public InvalidAgeException(String message) {
        super(message);
    }
    
    public InvalidAgeException(String message, Throwable cause) {
        super(message, cause);
    }
}

// Custom unchecked exception
class InsufficientFundsException extends RuntimeException {
    private double balance;
    private double requestedAmount;
    
    public InsufficientFundsException(double balance, double requestedAmount) {
        super(String.format("Insufficient funds. Balance: %.2f, Requested: %.2f", 
                           balance, requestedAmount));
        this.balance = balance;
        this.requestedAmount = requestedAmount;
    }
    
    public double getBalance() { return balance; }
    public double getRequestedAmount() { return requestedAmount; }
}

// Business logic with custom exceptions
class BankAccount {
    private double balance;
    private String accountNumber;
    
    public BankAccount(String accountNumber, double initialBalance) {
        this.accountNumber = accountNumber;
        this.balance = initialBalance;
    }
    
    public void withdraw(double amount) throws InsufficientFundsException {
        if (amount > balance) {
            throw new InsufficientFundsException(balance, amount);
        }
        balance -= amount;
    }
    
    public void deposit(double amount) {
        if (amount <= 0) {
            throw new IllegalArgumentException("Deposit amount must be positive");
        }
        balance += amount;
    }
    
    public double getBalance() { return balance; }
}

class Person {
    private String name;
    private int age;
    
    public Person(String name, int age) throws InvalidAgeException {
        this.name = name;
        setAge(age);
    }
    
    public void setAge(int age) throws InvalidAgeException {
        if (age < 0) {
            throw new InvalidAgeException("Age cannot be negative: " + age);
        }
        if (age > 150) {
            throw new InvalidAgeException("Age seems unrealistic: " + age);
        }
        this.age = age;
    }
    
    public int getAge() { return age; }
    public String getName() { return name; }
}

// Using custom exceptions
public class CustomExceptionDemo {
    public static void main(String[] args) {
        // Using custom checked exception
        try {
            Person person = new Person("Alice", -5);
        } catch (InvalidAgeException e) {
            System.out.println("Invalid age: " + e.getMessage());
        }
        
        // Using custom unchecked exception
        BankAccount account = new BankAccount("12345", 1000.0);
        try {
            account.withdraw(1500.0);
        } catch (InsufficientFundsException e) {
            System.out.println("Cannot withdraw: " + e.getMessage());
            System.out.println("Available balance: " + e.getBalance());
        }
        
        // Exception chaining
        try {
            processFile("nonexistent.txt");
        } catch (Exception e) {
            System.out.println("Failed to process file: " + e.getMessage());
            System.out.println("Caused by: " + e.getCause());
        }
    }
    
    public static void processFile(String filename) throws Exception {
        try {
            // Simulate file processing
            throw new IOException("File not found: " + filename);
        } catch (IOException e) {
            // Wrap in a more general exception
            throw new Exception("Processing failed", e);
        }
    }
}
```

### Checked vs Unchecked

```java
import java.io.*;
import java.sql.*;

public class ExceptionTypes {
    
    // Checked exceptions - must be handled or declared
    public static void checkedExceptions() {
        // IOException - checked
        try {
            FileReader file = new FileReader("test.txt");
            file.close();
        } catch (IOException e) {
            System.out.println("IO Error: " + e.getMessage());
        }
        
        // SQLException - checked
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        } catch (SQLException e) {
            System.out.println("Database error: " + e.getMessage());
        }
        
        // ParseException - checked
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            Date date = sdf.parse("invalid-date");
        } catch (ParseException e) {
            System.out.println("Parse error: " + e.getMessage());
        }
    }
    
    // Unchecked exceptions - runtime exceptions
    public static void uncheckedExceptions() {
        try {
            // NullPointerException
            String str = null;
            int length = str.length();
            
            // ArrayIndexOutOfBoundsException
            int[] arr = new int[5];
            int value = arr[10];
            
            // NumberFormatException
            int number = Integer.parseInt("not-a-number");
            
            // IllegalArgumentException
            Thread.sleep(-1000);
            
        } catch (RuntimeException e) {
            System.out.println("Runtime error: " + e.getClass().getSimpleName() + 
                             " - " + e.getMessage());
        } catch (InterruptedException e) {
            System.out.println("Interrupted: " + e.getMessage());
        }
    }
    
    // Error vs Exception
    public static void errorsVsExceptions() {
        try {
            // This would cause OutOfMemoryError (Error, not Exception)
            int[] hugeArray = new int[Integer.MAX_VALUE];
        } catch (OutOfMemoryError e) {
            System.out.println("Out of memory - this is an Error, not Exception");
        } catch (Exception e) {
            System.out.println("This won't catch Errors");
        }
        
        // Catching Throwable catches both Exceptions and Errors
        try {
            // Some operation
        } catch (Throwable t) {
            System.out.println("Caught: " + t.getClass().getSimpleName());
        }
    }
    
    // Exception hierarchy demonstration
    public static void exceptionHierarchy() {
        try {
            throw new FileNotFoundException("File not found");
        } catch (FileNotFoundException e) {
            System.out.println("Specific: FileNotFoundException");
        } catch (IOException e) {
            System.out.println("General: IOException");
        } catch (Exception e) {
            System.out.println("Most general: Exception");
        }
    }
    
    public static void main(String[] args) {
        checkedExceptions();
        uncheckedExceptions();
        errorsVsExceptions();
        exceptionHierarchy();
    }
}
```

### Best Practices

```java
import java.io.*;
import java.util.logging.Logger;

public class ExceptionBestPractices {
    private static final Logger logger = Logger.getLogger(ExceptionBestPractices.class.getName());
    
    // Best Practice 1: Be specific with exception types
    public void badExample() throws Exception {  // Too general
        throw new Exception("Something went wrong");
    }
    
    public void goodExample() throws FileNotFoundException {  // Specific
        throw new FileNotFoundException("Configuration file not found");
    }
    
    // Best Practice 2: Don't ignore exceptions
    public void badIgnoring() {
        try {
            riskyOperation();
        } catch (Exception e) {
            // Bad: Silent failure
        }
    }
    
    public void goodLogging() {
        try {
            riskyOperation();
        } catch (Exception e) {
            logger.severe("Operation failed: " + e.getMessage());
            // Or re-throw if can't handle
            throw new RuntimeException("Failed to complete operation", e);
        }
    }
    
    // Best Practice 3: Use try-with-resources
    public void badResourceManagement() {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream("file.txt");
            // Process file
        } catch (IOException e) {
            logger.severe("File processing failed: " + e.getMessage());
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    logger.warning("Failed to close file: " + e.getMessage());
                }
            }
        }
    }
    
    public void goodResourceManagement() {
        try (FileInputStream fis = new FileInputStream("file.txt")) {
            // Process file
        } catch (IOException e) {
            logger.severe("File processing failed: " + e.getMessage());
        }
        // File automatically closed
    }
    
    // Best Practice 4: Fail fast with validation
    public void processUser(String name, int age, String email) {
        // Validate early
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("Name cannot be null or empty");
        }
        if (age < 0 || age > 150) {
            throw new IllegalArgumentException("Invalid age: " + age);
        }
        if (email == null || !email.contains("@")) {
            throw new IllegalArgumentException("Invalid email: " + email);
        }
        
        // Process with validated data
        processValidatedUser(name, age, email);
    }
    
    // Best Practice 5: Document exceptions
    /**
     * Reads user data from file.
     * 
     * @param filename the file to read from
     * @return user data
     * @throws FileNotFoundException if file doesn't exist
     * @throws IOException if file cannot be read
     * @throws IllegalArgumentException if filename is null or empty
     */
    public String readUserData(String filename) throws IOException {
        if (filename == null || filename.trim().isEmpty()) {
            throw new IllegalArgumentException("Filename cannot be null or empty");
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            return reader.readLine();
        }
    }
    
    // Best Practice 6: Don't catch and ignore in libraries
    public void libraryMethod() throws ProcessingException {
        try {
            complexOperation();
        } catch (Exception e) {
            // Don't swallow exceptions in library code
            throw new ProcessingException("Processing failed", e);
        }
    }
    
    // Best Practice 7: Use specific catch blocks
    public void processData() {
        try {
            parseData();
            validateData();
            saveData();
        } catch (ParseException e) {
            logger.warning("Data parsing failed: " + e.getMessage());
            // Handle parse errors specifically
        } catch (ValidationException e) {
            logger.warning("Data validation failed: " + e.getMessage());
            // Handle validation errors specifically
        } catch (SQLException e) {
            logger.severe("Database error: " + e.getMessage());
            // Handle database errors specifically
        } catch (Exception e) {
            logger.severe("Unexpected error: " + e.getMessage());
            // Handle any other errors
        }
    }
    
    // Best Practice 8: Clean up in finally or use try-with-resources
    public void processWithCleanup() {
        Connection conn = null;
        PreparedStatement stmt = null;
        try {
            conn = getConnection();
            stmt = conn.prepareStatement("SELECT * FROM users");
            // Process results
        } catch (SQLException e) {
            logger.severe("Database operation failed: " + e.getMessage());
        } finally {
            // Clean up resources
            if (stmt != null) {
                try { stmt.close(); } catch (SQLException e) { /* log */ }
            }
            if (conn != null) {
                try { conn.close(); } catch (SQLException e) { /* log */ }
            }
        }
    }
    
    // Custom exception classes
    public static class ProcessingException extends Exception {
        public ProcessingException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    
    public static class ValidationException extends Exception {
        public ValidationException(String message) {
            super(message);
        }
    }
    
    // Utility methods
    private void riskyOperation() throws IOException { /* implementation */ }
    private void processValidatedUser(String name, int age, String email) { /* implementation */ }
    private void complexOperation() throws Exception { /* implementation */ }
    private void parseData() throws ParseException { /* implementation */ }
    private void validateData() throws ValidationException { /* implementation */ }
    private void saveData() throws SQLException { /* implementation */ }
    private Connection getConnection() throws SQLException { return null; }
}

---

## File I/O

### File Operations

```java
import java.io.*;
import java.nio.file.*;
import java.util.List;

public class FileOperations {
    public static void main(String[] args) {
        // Basic file operations
        basicFileOperations();
        
        // File information
        fileInformation();
        
        // Directory operations
        directoryOperations();
        
        // Path operations
        pathOperations();
    }
    
    public static void basicFileOperations() {
        // Create file
        try {
            File file = new File("example.txt");
            
            if (file.createNewFile()) {
                System.out.println("File created: " + file.getName());
            } else {
                System.out.println("File already exists.");
            }
            
            // Write to file
            try (FileWriter writer = new FileWriter(file)) {
                writer.write("Hello, World!\n");
                writer.write("This is a test file.\n");
            }
            
            // Read from file
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("Read: " + line);
                }
            }
            
            // Delete file
            if (file.delete()) {
                System.out.println("File deleted: " + file.getName());
            }
            
        } catch (IOException e) {
            System.out.println("An error occurred: " + e.getMessage());
        }
    }
    
    public static void fileInformation() {
        File file = new File("test.txt");
        
        System.out.println("File name: " + file.getName());
        System.out.println("Absolute path: " + file.getAbsolutePath());
        System.out.println("Writeable: " + file.canWrite());
        System.out.println("Readable: " + file.canRead());
        System.out.println("File size: " + file.length() + " bytes");
        System.out.println("Exists: " + file.exists());
        System.out.println("Is directory: " + file.isDirectory());
        System.out.println("Is file: " + file.isFile());
        System.out.println("Is hidden: " + file.isHidden());
        System.out.println("Last modified: " + new Date(file.lastModified()));
        
        // File permissions
        System.out.println("Can read: " + file.canRead());
        System.out.println("Can write: " + file.canWrite());
        System.out.println("Can execute: " + file.canExecute());
        
        // Set permissions
        file.setReadable(true);
        file.setWritable(true);
        file.setExecutable(false);
    }
    
    public static void directoryOperations() {
        // Create directory
        File dir = new File("testDir");
        if (dir.mkdir()) {
            System.out.println("Directory created: " + dir.getName());
        }
        
        // Create nested directories
        File nestedDir = new File("parent/child/grandchild");
        if (nestedDir.mkdirs()) {
            System.out.println("Nested directories created");
        }
        
        // List directory contents
        File currentDir = new File(".");
        String[] contents = currentDir.list();
        if (contents != null) {
            System.out.println("Directory contents:");
            for (String item : contents) {
                System.out.println("  " + item);
            }
        }
        
        // List with file objects
        File[] files = currentDir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    System.out.println("DIR:  " + file.getName());
                } else {
                    System.out.println("FILE: " + file.getName() + " (" + file.length() + " bytes)");
                }
            }
        }
        
        // Filter files
        File[] javaFiles = currentDir.listFiles((dir2, name) -> name.endsWith(".java"));
        System.out.println("Java files count: " + (javaFiles != null ? javaFiles.length : 0));
        
        // Delete directory (must be empty)
        if (dir.delete()) {
            System.out.println("Directory deleted: " + dir.getName());
        }
    }
    
    public static void pathOperations() {
        // Path manipulation
        String fileName = "document.txt";
        String directory = "/home/user/documents";
        String fullPath = directory + File.separator + fileName;
        
        System.out.println("Full path: " + fullPath);
        System.out.println("File separator: " + File.separator);
        System.out.println("Path separator: " + File.pathSeparator);
        
        // Extract path components
        File file = new File(fullPath);
        System.out.println("Parent directory: " + file.getParent());
        System.out.println("File name: " + file.getName());
        
        // Get file extension
        String extension = "";
        int lastDot = fileName.lastIndexOf('.');
        if (lastDot > 0) {
            extension = fileName.substring(lastDot + 1);
        }
        System.out.println("File extension: " + extension);
        
        // Relative vs absolute paths
        File relativeFile = new File("data.txt");
        File absoluteFile = new File("/tmp/data.txt");
        
        System.out.println("Relative path: " + relativeFile.getPath());
        System.out.println("Absolute path: " + absoluteFile.getPath());
        System.out.println("Is absolute: " + absoluteFile.isAbsolute());
        
        // Convert to absolute path
        System.out.println("Relative to absolute: " + relativeFile.getAbsolutePath());
    }
}
```

### Readers and Writers

```java
import java.io.*;
import java.util.Scanner;

public class ReadersWriters {
    public static void main(String[] args) {
        // Character-based I/O
        characterIO();
        
        // Byte-based I/O
        byteIO();
        
        // Buffered I/O
        bufferedIO();
        
        // Scanner usage
        scannerUsage();
    }
    
    public static void characterIO() {
        // FileWriter and FileReader
        try {
            // Writing characters
            try (FileWriter writer = new FileWriter("chars.txt")) {
                writer.write("Hello, World!\n");
                writer.write("Java File I/O\n");
                writer.write("Character streams\n");
            }
            
            // Reading characters
            try (FileReader reader = new FileReader("chars.txt")) {
                int ch;
                while ((ch = reader.read()) != -1) {
                    System.out.print((char) ch);
                }
            }
            
            // Reading with char array
            try (FileReader reader = new FileReader("chars.txt")) {
                char[] buffer = new char[1024];
                int charsRead = reader.read(buffer);
                System.out.println("Characters read: " + charsRead);
                System.out.println("Content: " + new String(buffer, 0, charsRead));
            }
            
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
    
    public static void byteIO() {
        // FileInputStream and FileOutputStream
        try {
            // Writing bytes
            String data = "Binary data example\nSecond line";
            try (FileOutputStream fos = new FileOutputStream("bytes.txt")) {
                fos.write(data.getBytes());
            }
            
            // Reading bytes
            try (FileInputStream fis = new FileInputStream("bytes.txt")) {
                int byteData;
                while ((byteData = fis.read()) != -1) {
                    System.out.print((char) byteData);
                }
            }
            
            // Reading with byte array
            try (FileInputStream fis = new FileInputStream("bytes.txt")) {
                byte[] buffer = new byte[1024];
                int bytesRead = fis.read(buffer);
                System.out.println("Bytes read: " + bytesRead);
                System.out.println("Content: " + new String(buffer, 0, bytesRead));
            }
            
            // File copying
            copyFile("bytes.txt", "bytes_copy.txt");
            
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
    
    public static void bufferedIO() {
        try {
            // BufferedWriter for efficient writing
            try (BufferedWriter writer = new BufferedWriter(new FileWriter("buffered.txt"))) {
                writer.write("Line 1");
                writer.newLine();
                writer.write("Line 2");
                writer.newLine();
                writer.write("Line 3");
                writer.flush(); // Force write to disk
            }
            
            // BufferedReader for efficient reading
            try (BufferedReader reader = new BufferedReader(new FileReader("buffered.txt"))) {
                String line;
                int lineNumber = 1;
                while ((line = reader.readLine()) != null) {
                    System.out.println(lineNumber + ": " + line);
                    lineNumber++;
                }
            }
            
            // PrintWriter for convenient writing
            try (PrintWriter writer = new PrintWriter(new FileWriter("formatted.txt"))) {
                writer.println("Formatted output");
                writer.printf("Number: %d, Float: %.2f%n", 42, 3.14159);
                writer.print("No newline");
            }
            
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
    
    public static void scannerUsage() {
        // Create test file with data
        try (PrintWriter writer = new PrintWriter("data.txt")) {
            writer.println("Alice 25 85.5");
            writer.println("Bob 30 92.3");
            writer.println("Charlie 28 78.9");
        } catch (IOException e) {
            System.out.println("Error creating test file: " + e.getMessage());
            return;
        }
        
        // Read structured data with Scanner
        try (Scanner scanner = new Scanner(new File("data.txt"))) {
            while (scanner.hasNextLine()) {
                String name = scanner.next();
                int age = scanner.nextInt();
                double score = scanner.nextDouble();
                
                System.out.printf("Name: %s, Age: %d, Score: %.1f%n", name, age, score);
            }
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
        }
        
        // Scanner with delimiters
        try (Scanner scanner = new Scanner("apple,banana,orange")) {
            scanner.useDelimiter(",");
            while (scanner.hasNext()) {
                System.out.println("Fruit: " + scanner.next());
            }
        }
        
        // Scanner from string
        Scanner stringScanner = new Scanner("123 45.67 true hello");
        int intValue = stringScanner.nextInt();
        double doubleValue = stringScanner.nextDouble();
        boolean boolValue = stringScanner.nextBoolean();
        String stringValue = stringScanner.next();
        
        System.out.printf("Parsed: %d, %.2f, %b, %s%n", 
                         intValue, doubleValue, boolValue, stringValue);
        stringScanner.close();
    }
    
    // Utility method for file copying
    public static void copyFile(String source, String destination) throws IOException {
        try (FileInputStream fis = new FileInputStream(source);
             FileOutputStream fos = new FileOutputStream(destination)) {
            
            byte[] buffer = new byte[1024];
            int bytesRead;
            
            while ((bytesRead = fis.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }
            
            System.out.println("File copied from " + source + " to " + destination);
        }
    }
}
```

### Streams

```java
import java.io.*;

public class StreamExamples {
    public static void main(String[] args) {
        // Data streams
        dataStreams();
        
        // Object streams (Serialization)
        objectStreams();
        
        // Filter streams
        filterStreams();
    }
    
    public static void dataStreams() {
        try {
            // Writing primitive data types
            try (DataOutputStream dos = new DataOutputStream(
                    new FileOutputStream("data.bin"))) {
                
                dos.writeInt(42);
                dos.writeDouble(3.14159);
                dos.writeBoolean(true);
                dos.writeUTF("Hello, Data Stream!");
                dos.writeLong(System.currentTimeMillis());
            }
            
            // Reading primitive data types
            try (DataInputStream dis = new DataInputStream(
                    new FileInputStream("data.bin"))) {
                
                int intValue = dis.readInt();
                double doubleValue = dis.readDouble();
                boolean boolValue = dis.readBoolean();
                String stringValue = dis.readUTF();
                long longValue = dis.readLong();
                
                System.out.println("Read values:");
                System.out.println("Int: " + intValue);
                System.out.println("Double: " + doubleValue);
                System.out.println("Boolean: " + boolValue);
                System.out.println("String: " + stringValue);
                System.out.println("Long: " + longValue);
            }
            
        } catch (IOException e) {
            System.out.println("Error with data streams: " + e.getMessage());
        }
    }
    
    public static void objectStreams() {
        // Serializable class
        class Person implements Serializable {
            private static final long serialVersionUID = 1L;
            private String name;
            private int age;
            private transient String password; // transient = not serialized
            
            public Person(String name, int age, String password) {
                this.name = name;
                this.age = age;
                this.password = password;
            }
            
            @Override
            public String toString() {
                return String.format("Person{name='%s', age=%d, password='%s'}", 
                                   name, age, password);
            }
        }
        
        try {
            Person person = new Person("Alice", 30, "secret123");
            
            // Serialize object
            try (ObjectOutputStream oos = new ObjectOutputStream(
                    new FileOutputStream("person.ser"))) {
                oos.writeObject(person);
                System.out.println("Object serialized: " + person);
            }
            
            // Deserialize object
            try (ObjectInputStream ois = new ObjectInputStream(
                    new FileInputStream("person.ser"))) {
                Person deserializedPerson = (Person) ois.readObject();
                System.out.println("Object deserialized: " + deserializedPerson);
                // Note: password is null (transient)
            }
            
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Error with object streams: " + e.getMessage());
        }
    }
    
    public static void filterStreams() {
        try {
            // Creating test file with mixed content
            try (PrintWriter writer = new PrintWriter("mixed.txt")) {
                writer.println("This is line 1");
                writer.println("IMPORTANT: This is line 2");
                writer.println("This is line 3");
                writer.println("ERROR: This is line 4");
                writer.println("This is line 5");
            }
            
            // Custom FilterInputStream to uppercase text
            class UppercaseInputStream extends FilterInputStream {
                public UppercaseInputStream(InputStream in) {
                    super(in);
                }
                
                @Override
                public int read() throws IOException {
                    int ch = super.read();
                    return (ch == -1) ? ch : Character.toUpperCase(ch);
                }
                
                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    int result = super.read(b, off, len);
                    for (int i = off; i < off + result; i++) {
                        b[i] = (byte) Character.toUpperCase(b[i]);
                    }
                    return result;
                }
            }
            
            // Reading with custom filter
            try (UppercaseInputStream uis = new UppercaseInputStream(
                    new FileInputStream("mixed.txt"));
                 BufferedReader reader = new BufferedReader(
                    new InputStreamReader(uis))) {
                
                System.out.println("Uppercase filtered content:");
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            }
            
            // LineNumberReader (built-in filter)
            try (LineNumberReader lnr = new LineNumberReader(
                    new FileReader("mixed.txt"))) {
                
                System.out.println("Content with line numbers:");
                String line;
                while ((line = lnr.readLine()) != null) {
                    System.out.printf("%3d: %s%n", lnr.getLineNumber(), line);
                }
            }
            
            // PushbackInputStream for lookahead
            try (PushbackInputStream pis = new PushbackInputStream(
                    new FileInputStream("mixed.txt"))) {
                
                int ch = pis.read();
                if (ch != -1) {
                    System.out.println("First character: " + (char) ch);
                    pis.unread(ch); // Push back the character
                    
                    // Now read again
                    ch = pis.read();
                    System.out.println("First character again: " + (char) ch);
                }
            }
            
        } catch (IOException e) {
            System.out.println("Error with filter streams: " + e.getMessage());
        }
    }
}
```

### NIO

```java
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.util.List;
import java.util.stream.Stream;

public class NIOExamples {
    public static void main(String[] args) {
        // Path operations
        pathOperations();
        
        // File operations with NIO
        fileOperations();
        
        // Directory operations
        directoryOperations();
        
        // File watching
        watchService();
    }
    
    public static void pathOperations() {
        // Creating paths
        Path path1 = Paths.get("documents", "file.txt");
        Path path2 = Paths.get("/home/user/documents/file.txt");
        Path path3 = Path.of("modern", "syntax", "file.txt"); // Java 11+
        
        System.out.println("Path 1: " + path1);
        System.out.println("Path 2: " + path2);
        System.out.println("Path 3: " + path3);
        
        // Path information
        Path filePath = Paths.get("/home/user/documents/report.pdf");
        System.out.println("File name: " + filePath.getFileName());
        System.out.println("Parent: " + filePath.getParent());
        System.out.println("Root: " + filePath.getRoot());
        System.out.println("Name count: " + filePath.getNameCount());
        
        // Path manipulation
        Path basePath = Paths.get("/home/user");
        Path fullPath = basePath.resolve("documents/file.txt");
        System.out.println("Resolved path: " + fullPath);
        
        Path relativePath = basePath.relativize(fullPath);
        System.out.println("Relative path: " + relativePath);
        
        // Path normalization
        Path messyPath = Paths.get("/home/user/../user/./documents//file.txt");
        Path normalizedPath = messyPath.normalize();
        System.out.println("Messy path: " + messyPath);
        System.out.println("Normalized: " + normalizedPath);
        
        // Convert to absolute path
        Path relativePath2 = Paths.get("file.txt");
        Path absolutePath = relativePath2.toAbsolutePath();
        System.out.println("Relative: " + relativePath2);
        System.out.println("Absolute: " + absolutePath);
    }
    
    public static void fileOperations() {
        try {
            Path testFile = Paths.get("nio_test.txt");
            
            // Write to file
            List<String> lines = List.of(
                "First line",
                "Second line", 
                "Third line"
            );
            Files.write(testFile, lines, StandardCharsets.UTF_8);
            System.out.println("File written successfully");
            
            // Read entire file
            String content = Files.readString(testFile, StandardCharsets.UTF_8);
            System.out.println("File content:\n" + content);
            
            // Read all lines
            List<String> readLines = Files.readAllLines(testFile, StandardCharsets.UTF_8);
            System.out.println("Lines read: " + readLines.size());
            readLines.forEach(line -> System.out.println("  " + line));
            
            // Read with stream (memory efficient for large files)
            try (Stream<String> lineStream = Files.lines(testFile)) {
                long lineCount = lineStream.count();
                System.out.println("Line count: " + lineCount);
            }
            
            // File attributes
            System.out.println("File exists: " + Files.exists(testFile));
            System.out.println("Is regular file: " + Files.isRegularFile(testFile));
            System.out.println("Is directory: " + Files.isDirectory(testFile));
            System.out.println("File size: " + Files.size(testFile) + " bytes");
            System.out.println("Is readable: " + Files.isReadable(testFile));
            System.out.println("Is writable: " + Files.isWritable(testFile));
            System.out.println("Is executable: " + Files.isExecutable(testFile));
            
            // Copy file
            Path copyPath = Paths.get("nio_test_copy.txt");
            Files.copy(testFile, copyPath, StandardCopyOption.REPLACE_EXISTING);
            System.out.println("File copied to: " + copyPath);
            
            // Move file
            Path movedPath = Paths.get("nio_test_moved.txt");
            Files.move(copyPath, movedPath, StandardCopyOption.REPLACE_EXISTING);
            System.out.println("File moved to: " + movedPath);
            
            // Delete files
            Files.deleteIfExists(testFile);
            Files.deleteIfExists(movedPath);
            System.out.println("Files deleted");
            
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
    
    public static void directoryOperations() {
        try {
            Path testDir = Paths.get("test_directory");
            
            // Create directory
            Files.createDirectories(testDir);
            System.out.println("Directory created: " + testDir);
            
            // Create some test files
            Files.write(testDir.resolve("file1.txt"), "Content 1".getBytes());
            Files.write(testDir.resolve("file2.java"), "Content 2".getBytes());
            Files.write(testDir.resolve("file3.txt"), "Content 3".getBytes());
            
            // List directory contents
            System.out.println("Directory contents:");
            try (Stream<Path> paths = Files.list(testDir)) {
                paths.forEach(path -> System.out.println("  " + path.getFileName()));
            }
            
            // Find files with filter
            System.out.println("Text files:");
            try (Stream<Path> paths = Files.list(testDir)) {
                paths.filter(path -> path.toString().endsWith(".txt"))
                     .forEach(path -> System.out.println("  " + path.getFileName()));
            }
            
            // Walk directory tree
            System.out.println("All files in tree:");
            try (Stream<Path> paths = Files.walk(testDir)) {
                paths.filter(Files::isRegularFile)
                     .forEach(path -> System.out.println("  " + path));
            }
            
            // Find files by name pattern
            System.out.println("Files matching pattern:");
            try (Stream<Path> paths = Files.find(testDir, 2, 
                    (path, attrs) -> path.toString().endsWith(".java"))) {
                paths.forEach(path -> System.out.println("  " + path));
            }
            
            // Clean up - delete directory and contents
            try (Stream<Path> paths = Files.walk(testDir)) {
                paths.sorted((p1, p2) -> -p1.compareTo(p2)) // Reverse order for deletion
                     .forEach(path -> {
                         try {
                             Files.delete(path);
                         } catch (IOException e) {
                             System.out.println("Failed to delete: " + path);
                         }
                     });
            }
            
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
    
    public static void watchService() {
        try {
            Path watchDir = Paths.get("watch_test");
            Files.createDirectories(watchDir);
            
            // Create watch service
            WatchService watchService = FileSystems.getDefault().newWatchService();
            
            // Register directory for watching
            watchDir.register(watchService, 
                StandardWatchEventKinds.ENTRY_CREATE,
                StandardWatchEventKinds.ENTRY_DELETE,
                StandardWatchEventKinds.ENTRY_MODIFY);
            
            System.out.println("Watching directory: " + watchDir);
            System.out.println("Create/modify/delete files in this directory...");
            
            // Watch for events (in a separate thread in real applications)
            new Thread(() -> {
                try {
                    WatchKey key;
                    while ((key = watchService.take()) != null) {
                        for (WatchEvent<?> event : key.pollEvents()) {
                            WatchEvent.Kind<?> kind = event.kind();
                            Path fileName = (Path) event.context();
                            
                            System.out.println("Event: " + kind + " - " + fileName);
                        }
                        key.reset();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }).start();
            
            // Simulate file operations
            Thread.sleep(1000);
            Files.write(watchDir.resolve("test1.txt"), "Content".getBytes());
            Thread.sleep(1000);
            Files.write(watchDir.resolve("test1.txt"), "Modified Content".getBytes());
            Thread.sleep(1000);
            Files.delete(watchDir.resolve("test1.txt"));
            
            Thread.sleep(2000); // Let watch service process events
            
            // Clean up
            watchService.close();
            Files.deleteIfExists(watchDir);
            
        } catch (IOException | InterruptedException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}

---

## Generics

### Generic Classes

```java
// Basic generic class
public class Box<T> {
    private T content;
    
    public Box(T content) {
        this.content = content;
    }
    
    public T getContent() {
        return content;
    }
    
    public void setContent(T content) {
        this.content = content;
    }
    
    @Override
    public String toString() {
        return "Box[" + content + "]";
    }
}

// Multiple type parameters
public class Pair<T, U> {
    private T first;
    private U second;
    
    public Pair(T first, U second) {
        this.first = first;
        this.second = second;
    }
    
    public T getFirst() { return first; }
    public U getSecond() { return second; }
    
    @Override
    public String toString() {
        return "(" + first + ", " + second + ")";
    }
}

// Generic class with constraints
public class NumberBox<T extends Number> {
    private T value;
    
    public NumberBox(T value) {
        this.value = value;
    }
    
    public double getDoubleValue() {
        return value.doubleValue(); // Available because T extends Number
    }
    
    public boolean isPositive() {
        return value.doubleValue() > 0;
    }
}

// Generic collection class
public class GenericList<T> {
    private Object[] array;
    private int size = 0;
    private static final int DEFAULT_CAPACITY = 10;
    
    public GenericList() {
        array = new Object[DEFAULT_CAPACITY];
    }
    
    public void add(T item) {
        if (size >= array.length) {
            resize();
        }
        array[size++] = item;
    }
    
    @SuppressWarnings("unchecked")
    public T get(int index) {
        if (index < 0 || index >= size) {
            throw new IndexOutOfBoundsException();
        }
        return (T) array[index];
    }
    
    public int size() {
        return size;
    }
    
    private void resize() {
        Object[] newArray = new Object[array.length * 2];
        System.arraycopy(array, 0, newArray, 0, size);
        array = newArray;
    }
}

// Using generic classes
public class GenericClassDemo {
    public static void main(String[] args) {
        // Basic generic usage
        Box<String> stringBox = new Box<>("Hello");
        Box<Integer> intBox = new Box<>(42);
        
        System.out.println("String box: " + stringBox.getContent());
        System.out.println("Int box: " + intBox.getContent());
        
        // Multiple type parameters
        Pair<String, Integer> nameAge = new Pair<>("Alice", 25);
        Pair<Double, Boolean> scorePass = new Pair<>(95.5, true);
        
        System.out.println("Name-Age: " + nameAge);
        System.out.println("Score-Pass: " + scorePass);
        
        // Bounded generic
        NumberBox<Integer> intNumberBox = new NumberBox<>(42);
        NumberBox<Double> doubleNumberBox = new NumberBox<>(3.14);
        
        System.out.println("Int as double: " + intNumberBox.getDoubleValue());
        System.out.println("Is positive: " + doubleNumberBox.isPositive());
        
        // Generic list
        GenericList<String> stringList = new GenericList<>();
        stringList.add("first");
        stringList.add("second");
        stringList.add("third");
        
        for (int i = 0; i < stringList.size(); i++) {
            System.out.println("Item " + i + ": " + stringList.get(i));
        }
    }
}
```

### Generic Methods

```java
public class GenericMethods {
    
    // Generic method with single type parameter
    public static <T> void swap(T[] array, int i, int j) {
        T temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
    
    // Generic method with return type
    public static <T> T getMiddleElement(T[] array) {
        if (array.length == 0) {
            return null;
        }
        return array[array.length / 2];
    }
    
    // Multiple type parameters
    public static <T, U> Pair<T, U> makePair(T first, U second) {
        return new Pair<>(first, second);
    }
    
    // Bounded type parameters
    public static <T extends Comparable<T>> T findMax(T[] array) {
        if (array.length == 0) {
            return null;
        }
        
        T max = array[0];
        for (T element : array) {
            if (element.compareTo(max) > 0) {
                max = element;
            }
        }
        return max;
    }
    
    // Generic method with wildcards
    public static double sumNumbers(List<? extends Number> numbers) {
        double sum = 0.0;
        for (Number num : numbers) {
            sum += num.doubleValue();
        }
        return sum;
    }
    
    // Generic method in generic class
    public static class GenericContainer<T> {
        private T item;
        
        public GenericContainer(T item) {
            this.item = item;
        }
        
        // Method with additional type parameter
        public <U> Pair<T, U> pairWith(U other) {
            return new Pair<>(item, other);
        }
        
        // Static generic method in generic class
        public static <V> GenericContainer<V> create(V item) {
            return new GenericContainer<>(item);
        }
    }
    
    // Generic method with complex bounds
    public static <T extends Number & Comparable<T>> T findMinPositive(List<T> numbers) {
        T min = null;
        for (T num : numbers) {
            if (num.doubleValue() > 0) {
                if (min == null || num.compareTo(min) < 0) {
                    min = num;
                }
            }
        }
        return min;
    }
    
    public static void main(String[] args) {
        // Using generic methods
        String[] strings = {"apple", "banana", "cherry"};
        System.out.println("Before swap: " + Arrays.toString(strings));
        swap(strings, 0, 2);
        System.out.println("After swap: " + Arrays.toString(strings));
        
        Integer[] numbers = {1, 5, 3, 9, 2};
        Integer middle = getMiddleElement(numbers);
        System.out.println("Middle element: " + middle);
        
        // Multiple type parameters
        Pair<String, Integer> pair = makePair("Count", 10);
        System.out.println("Pair: " + pair);
        
        // Bounded generics
        String[] words = {"zebra", "apple", "monkey"};
        String maxWord = findMax(words);
        System.out.println("Max word: " + maxWord);
        
        // Wildcards
        List<Integer> intList = Arrays.asList(1, 2, 3, 4, 5);
        List<Double> doubleList = Arrays.asList(1.1, 2.2, 3.3);
        
        System.out.println("Sum of integers: " + sumNumbers(intList));
        System.out.println("Sum of doubles: " + sumNumbers(doubleList));
        
        // Generic container
        GenericContainer<String> container = new GenericContainer<>("Hello");
        Pair<String, Integer> containerPair = container.pairWith(42);
        System.out.println("Container pair: " + containerPair);
        
        // Static factory method
        GenericContainer<Double> doubleContainer = GenericContainer.create(3.14);
        
        // Complex bounds
        List<Integer> intNumbers = Arrays.asList(-5, 3, -1, 7, 2);
        Integer minPositive = findMinPositive(intNumbers);
        System.out.println("Min positive: " + minPositive);
    }
}
```

### Bounded Types

```java
import java.util.*;

// Upper bounded wildcards
public class BoundedTypes {
    
    // Bounded type parameter - T must extend Number
    public static class NumberContainer<T extends Number> {
        private T value;
        
        public NumberContainer(T value) {
            this.value = value;
        }
        
        public double getDoubleValue() {
            return value.doubleValue();
        }
        
        public boolean isGreaterThan(NumberContainer<? extends Number> other) {
            return this.getDoubleValue() > other.getDoubleValue();
        }
    }
    
    // Multiple bounds - T must implement both Comparable and Serializable
    public static class SortableItem<T extends Comparable<T> & Serializable> {
        private T item;
        
        public SortableItem(T item) {
            this.item = item;
        }
        
        public T getItem() {
            return item;
        }
        
        public boolean isLessThan(SortableItem<T> other) {
            return item.compareTo(other.item) < 0;
        }
    }
    
    // Bounded methods with inheritance hierarchy
    public static abstract class Animal {
        protected String name;
        public Animal(String name) { this.name = name; }
        public abstract void makeSound();
    }
    
    public static class Dog extends Animal {
        public Dog(String name) { super(name); }
        public void makeSound() { System.out.println(name + " barks"); }
        public void fetch() { System.out.println(name + " fetches"); }
    }
    
    public static class Cat extends Animal {
        public Cat(String name) { super(name); }
        public void makeSound() { System.out.println(name + " meows"); }
        public void purr() { System.out.println(name + " purrs"); }
    }
    
    // Method with upper bounded wildcard
    public static void makeAllSounds(List<? extends Animal> animals) {
        for (Animal animal : animals) {
            animal.makeSound();
        }
    }
    
    // Method with lower bounded wildcard
    public static void addAnimals(List<? super Dog> animals) {
        animals.add(new Dog("Buddy"));
        animals.add(new Dog("Max"));
    }
    
    // Recursive type bound
    public static class ComparableContainer<T extends Comparable<T>> {
        private List<T> items = new ArrayList<>();
        
        public void add(T item) {
            items.add(item);
        }
        
        public T getMax() {
            if (items.isEmpty()) return null;
            return Collections.max(items);
        }
        
        public T getMin() {
            if (items.isEmpty()) return null;
            return Collections.min(items);
        }
        
        public void sort() {
            Collections.sort(items);
        }
    }
    
    // Complex bounded example - Repository pattern
    public interface Entity {
        Long getId();
    }
    
    public static class User implements Entity {
        private Long id;
        private String name;
        
        public User(Long id, String name) {
            this.id = id;
            this.name = name;
        }
        
        public Long getId() { return id; }
        public String getName() { return name; }
        
        @Override
        public String toString() {
            return "User{id=" + id + ", name='" + name + "'}";
        }
    }
    
    public static class Repository<T extends Entity> {
        private Map<Long, T> storage = new HashMap<>();
        
        public void save(T entity) {
            storage.put(entity.getId(), entity);
        }
        
        public T findById(Long id) {
            return storage.get(id);
        }
        
        public List<T> findAll() {
            return new ArrayList<>(storage.values());
        }
    }
    
    public static void main(String[] args) {
        // Number containers
        NumberContainer<Integer> intContainer = new NumberContainer<>(42);
        NumberContainer<Double> doubleContainer = new NumberContainer<>(3.14);
        
        System.out.println("Int value: " + intContainer.getDoubleValue());
        System.out.println("Is int > double: " + intContainer.isGreaterThan(doubleContainer));
        
        // Sortable items
        SortableItem<String> stringItem = new SortableItem<>("hello");
        SortableItem<String> anotherString = new SortableItem<>("world");
        
        System.out.println("Is 'hello' < 'world': " + stringItem.isLessThan(anotherString));
        
        // Animal hierarchy with wildcards
        List<Dog> dogs = Arrays.asList(new Dog("Rex"), new Dog("Fido"));
        List<Cat> cats = Arrays.asList(new Cat("Whiskers"), new Cat("Fluffy"));
        List<Animal> animals = new ArrayList<>();
        
        makeAllSounds(dogs);  // Upper bound - can read as Animal
        makeAllSounds(cats);  // Upper bound - can read as Animal
        
        addAnimals(animals);  // Lower bound - can add Dogs
        makeAllSounds(animals);
        
        // Comparable container
        ComparableContainer<Integer> numbers = new ComparableContainer<>();
        numbers.add(5);
        numbers.add(2);
        numbers.add(8);
        numbers.add(1);
        
        System.out.println("Max: " + numbers.getMax());
        System.out.println("Min: " + numbers.getMin());
        numbers.sort();
        
        // Repository pattern
        Repository<User> userRepo = new Repository<>();
        userRepo.save(new User(1L, "Alice"));
        userRepo.save(new User(2L, "Bob"));
        
        User user = userRepo.findById(1L);
        System.out.println("Found user: " + user);
        
        List<User> allUsers = userRepo.findAll();
        System.out.println("All users: " + allUsers);
    }
}
```

### Wildcards

```java
import java.util.*;

public class WildcardExamples {
    
    // Unbounded wildcard - can be any type
    public static void printList(List<?> list) {
        for (Object item : list) {
            System.out.println(item);
        }
    }
    
    // Upper bounded wildcard - PECS (Producer Extends)
    public static double calculateTotal(List<? extends Number> numbers) {
        double total = 0.0;
        for (Number num : numbers) {
            total += num.doubleValue();
        }
        return total;
    }
    
    // Lower bounded wildcard - PECS (Consumer Super)
    public static void addNumbers(List<? super Integer> list) {
        list.add(1);
        list.add(2);
        list.add(3);
    }
    
    // Complex wildcard example - copying
    public static <T> void copy(List<? extends T> source, List<? super T> destination) {
        for (T item : source) {
            destination.add(item);
        }
    }
    
    // Wildcard capture helper
    public static void reverse(List<?> list) {
        reverseHelper(list);
    }
    
    private static <T> void reverseHelper(List<T> list) {
        Collections.reverse(list);
    }
    
    // Real-world example - Event system
    public static abstract class Event {
        private final long timestamp;
        
        public Event() {
            this.timestamp = System.currentTimeMillis();
        }
        
        public long getTimestamp() { return timestamp; }
    }
    
    public static class UserEvent extends Event {
        private final String userId;
        
        public UserEvent(String userId) {
            this.userId = userId;
        }
        
        public String getUserId() { return userId; }
        
        @Override
        public String toString() {
            return "UserEvent{userId='" + userId + "'}";
        }
    }
    
    public static class SystemEvent extends Event {
        private final String message;
        
        public SystemEvent(String message) {
            this.message = message;
        }
        
        public String getMessage() { return message; }
        
        @Override
        public String toString() {
            return "SystemEvent{message='" + message + "'}";
        }
    }
    
    // Event handler with upper bounded wildcard
    public static class EventProcessor {
        public void processEvents(List<? extends Event> events) {
            for (Event event : events) {
                System.out.println("Processing event at " + event.getTimestamp() + ": " + event);
            }
        }
        
        // Event dispatcher with lower bounded wildcard
        public void dispatchToHandlers(Event event, List<? super Event> handlers) {
            handlers.add(event); // Can add event and its subtypes
        }
    }
    
    // Generic DAO pattern with wildcards
    public interface DAO<T> {
        void save(T entity);
        T findById(Long id);
        List<T> findAll();
    }
    
    public static class GenericService {
        // Method accepting any DAO
        public void backupData(DAO<?> dao) {
            List<?> allData = dao.findAll();
            System.out.println("Backing up " + allData.size() + " items");
            // Can read but not write to the list
        }
        
        // Method that can work with DAOs of specific type hierarchy
        public <T extends Event> void processEventData(DAO<? extends T> eventDao) {
            List<? extends T> events = eventDao.findAll();
            for (T event : events) {
                System.out.println("Event timestamp: " + event.getTimestamp());
            }
        }
    }
    
    // Wildcard with nested generics
    public static class Container<T> {
        private T content;
        
        public Container(T content) {
            this.content = content;
        }
        
        public T getContent() { return content; }
        
        @Override
        public String toString() {
            return "Container{" + content + "}";
        }
    }
    
    // Working with nested generics and wildcards
    public static void printContainers(List<Container<?>> containers) {
        for (Container<?> container : containers) {
            System.out.println(container);
        }
    }
    
    // Bounded wildcards with nested generics
    public static void printNumberContainers(List<Container<? extends Number>> containers) {
        for (Container<? extends Number> container : containers) {
            Number number = container.getContent();
            System.out.println("Number container: " + number.doubleValue());
        }
    }
    
    public static void main(String[] args) {
        // Unbounded wildcards
        List<String> strings = Arrays.asList("hello", "world");
        List<Integer> integers = Arrays.asList(1, 2, 3);
        
        System.out.println("String list:");
        printList(strings);
        System.out.println("Integer list:");
        printList(integers);
        
        // Upper bounded wildcards
        List<Integer> intList = Arrays.asList(1, 2, 3, 4, 5);
        List<Double> doubleList = Arrays.asList(1.1, 2.2, 3.3);
        
        System.out.println("Total of integers: " + calculateTotal(intList));
        System.out.println("Total of doubles: " + calculateTotal(doubleList));
        
        // Lower bounded wildcards
        List<Number> numberList = new ArrayList<>();
        List<Object> objectList = new ArrayList<>();
        
        addNumbers(numberList);  // Integer is subtype of Number
        addNumbers(objectList);  // Integer is subtype of Object
        
        System.out.println("Numbers: " + numberList);
        System.out.println("Objects: " + objectList);
        
        // Copy example
        List<String> source = Arrays.asList("a", "b", "c");
        List<Object> destination = new ArrayList<>();
        copy(source, destination);
        System.out.println("Copied: " + destination);
        
        // Wildcard capture
        List<String> stringList = new ArrayList<>(Arrays.asList("c", "a", "b"));
        System.out.println("Before reverse: " + stringList);
        reverse(stringList);
        System.out.println("After reverse: " + stringList);
        
        // Event system example
        List<UserEvent> userEvents = Arrays.asList(
            new UserEvent("user1"),
            new UserEvent("user2")
        );
        
        List<SystemEvent> systemEvents = Arrays.asList(
            new SystemEvent("System started"),
            new SystemEvent("System ready")
        );
        
        EventProcessor processor = new EventProcessor();
        processor.processEvents(userEvents);
        processor.processEvents(systemEvents);
        
        // Container examples
        List<Container<?>> mixedContainers = Arrays.asList(
            new Container<>("String content"),
            new Container<>(42),
            new Container<>(3.14)
        );
        
        System.out.println("Mixed containers:");
        printContainers(mixedContainers);
        
        List<Container<? extends Number>> numberContainers = Arrays.asList(
            new Container<>(42),
            new Container<>(3.14),
            new Container<>(100L)
        );
        
        System.out.println("Number containers:");
        printNumberContainers(numberContainers);
    }
}
```

---

## Lambda Expressions and Functional Programming

### Lambda Syntax

```java
import java.util.*;
import java.util.function.*;

public class LambdaSyntax {
    public static void main(String[] args) {
        // Basic lambda syntax
        
        // No parameters
        Runnable r1 = () -> System.out.println("Hello Lambda!");
        Runnable r2 = () -> {
            System.out.println("Multi-line");
            System.out.println("Lambda body");
        };
        
        // Single parameter
        Consumer<String> printer = s -> System.out.println(s);
        Consumer<String> upperPrinter = (String s) -> System.out.println(s.toUpperCase());
        
        // Multiple parameters
        BinaryOperator<Integer> add = (a, b) -> a + b;
        BinaryOperator<Integer> multiply = (Integer a, Integer b) -> {
            int result = a * b;
            System.out.println(a + " * " + b + " = " + result);
            return result;
        };
        
        // Lambda with return statement
        Function<String, Integer> stringLength = s -> s.length();
        Function<String, String> reverse = s -> {
            StringBuilder sb = new StringBuilder(s);
            return sb.reverse().toString();
        };
        
        // Using lambdas
        r1.run();
        r2.run();
        
        printer.accept("Hello World");
        upperPrinter.accept("hello world");
        
        System.out.println("5 + 3 = " + add.apply(5, 3));
        multiply.apply(4, 7);
        
        System.out.println("Length of 'hello': " + stringLength.apply("hello"));
        System.out.println("Reverse of 'hello': " + reverse.apply("hello"));
        
        // Lambdas with collections
        lambdasWithCollections();
        
        // Custom functional interfaces
        customFunctionalInterfaces();
        
        // Lambda scope and closures
        lambdaScope();
    }
    
    public static void lambdasWithCollections() {
        List<String> names = Arrays.asList("Alice", "Bob", "Charlie", "David");
        
        // forEach with lambda
        System.out.println("Names:");
        names.forEach(name -> System.out.println("  " + name));
        
        // Sorting with lambda
        List<String> sortedNames = new ArrayList<>(names);
        sortedNames.sort((a, b) -> a.compareTo(b));
        System.out.println("Sorted: " + sortedNames);
        
        // Sort by length
        List<String> byLength = new ArrayList<>(names);
        byLength.sort((a, b) -> Integer.compare(a.length(), b.length()));
        System.out.println("By length: " + byLength);
        
        // Filtering with removeIf
        List<String> filtered = new ArrayList<>(names);
        filtered.removeIf(name -> name.length() < 5);
        System.out.println("Long names: " + filtered);
        
        // Working with maps
        Map<String, Integer> nameLength = new HashMap<>();
        names.forEach(name -> nameLength.put(name, name.length()));
        
        nameLength.forEach((name, length) -> 
            System.out.println(name + " has " + length + " characters"));
    }
    
    @FunctionalInterface
    interface Calculator {
        double calculate(double a, double b);
    }
    
    @FunctionalInterface
    interface StringProcessor {
        String process(String input);
    }
    
    @FunctionalInterface
    interface Validator<T> {
        boolean isValid(T item);
    }
    
    public static void customFunctionalInterfaces() {
        // Custom functional interfaces
        Calculator add = (a, b) -> a + b;
        Calculator subtract = (a, b) -> a - b;
        Calculator multiply = (a, b) -> a * b;
        Calculator divide = (a, b) -> b != 0 ? a / b : 0;
        
        double x = 10, y = 3;
        System.out.println(x + " + " + y + " = " + add.calculate(x, y));
        System.out.println(x + " - " + y + " = " + subtract.calculate(x, y));
        System.out.println(x + " * " + y + " = " + multiply.calculate(x, y));
        System.out.println(x + " / " + y + " = " + divide.calculate(x, y));
        
        // String processing
        StringProcessor upperCase = s -> s.toUpperCase();
        StringProcessor addPrefix = s -> "Mr. " + s;
        StringProcessor reverse = s -> new StringBuilder(s).reverse().toString();
        
        String name = "john";
        System.out.println("Original: " + name);
        System.out.println("Upper: " + upperCase.process(name));
        System.out.println("Prefix: " + addPrefix.process(name));
        System.out.println("Reverse: " + reverse.process(name));
        
        // Validators
        Validator<String> emailValidator = email -> email.contains("@") && email.contains(".");
        Validator<Integer> positiveValidator = num -> num > 0;
        Validator<String> notEmptyValidator = str -> str != null && !str.trim().isEmpty();
        
        System.out.println("Valid email 'test@example.com': " + emailValidator.isValid("test@example.com"));
        System.out.println("Valid email 'invalid': " + emailValidator.isValid("invalid"));
        System.out.println("Positive 5: " + positiveValidator.isValid(5));
        System.out.println("Positive -3: " + positiveValidator.isValid(-3));
    }
    
    public static void lambdaScope() {
        // Lambda scope and variable capture
        int multiplier = 2; // Effectively final
        
        Function<Integer, Integer> doubler = x -> x * multiplier;
        System.out.println("Double 5: " + doubler.apply(5));
        
        // Local variable capture
        String prefix = "Result: ";
        List<Integer> numbers = Arrays.asList(1, 2, 3, 4, 5);
        
        numbers.forEach(n -> System.out.println(prefix + (n * multiplier)));
        
        // Instance variable access
        LambdaScope scopeExample = new LambdaScope();
        scopeExample.demonstrateScope();
    }
    
    static class LambdaScope {
        private String instanceVar = "Instance";
        private static String staticVar = "Static";
        
        public void demonstrateScope() {
            String localVar = "Local";
            
            Runnable lambda = () -> {
                System.out.println("Instance variable: " + instanceVar);
                System.out.println("Static variable: " + staticVar);
                System.out.println("Local variable: " + localVar);
                // System.out.println("This: " + this); // 'this' refers to enclosing instance
            };
            
            lambda.run();
            
            // Method reference to instance method
            List<String> strings = Arrays.asList("hello", "world");
            strings.forEach(this::processString);
        }
        
        private void processString(String s) {
            System.out.println("Processing: " + s.toUpperCase());
        }
    }
}
```

### Functional Interfaces

```java
import java.util.*;
import java.util.function.*;

public class FunctionalInterfaceExamples {
    public static void main(String[] args) {
        // Built-in functional interfaces
        builtInInterfaces();
        
        // Chaining functional interfaces
        chainingInterfaces();
        
        // Creating custom functional interfaces
        customInterfaces();
        
        // Functional interfaces with exceptions
        exceptionalInterfaces();
    }
    
    public static void builtInInterfaces() {
        // Function<T, R> - takes T, returns R
        Function<String, Integer> stringLength = String::length;
        Function<Integer, String> intToString = Object::toString;
        
        System.out.println("Length of 'hello': " + stringLength.apply("hello"));
        System.out.println("42 as string: " + intToString.apply(42));
        
        // Consumer<T> - takes T, returns void
        Consumer<String> printer = System.out::println;
        Consumer<List<String>> listPrinter = list -> list.forEach(System.out::println);
        
        printer.accept("Hello Consumer!");
        listPrinter.accept(Arrays.asList("item1", "item2", "item3"));
        
        // Supplier<T> - takes nothing, returns T
        Supplier<String> greeting = () -> "Hello World!";
        Supplier<Double> randomValue = Math::random;
        Supplier<Date> currentTime = Date::new;
        
        System.out.println("Greeting: " + greeting.get());
        System.out.println("Random: " + randomValue.get());
        System.out.println("Current time: " + currentTime.get());
        
        // Predicate<T> - takes T, returns boolean
        Predicate<String> isEmpty = String::isEmpty;
        Predicate<Integer> isPositive = n -> n > 0;
        Predicate<String> startsWithA = s -> s.startsWith("A");
        
        System.out.println("'' is empty: " + isEmpty.test(""));
        System.out.println("5 is positive: " + isPositive.test(5));
        System.out.println("'Apple' starts with A: " + startsWithA.test("Apple"));
        
        // BiFunction<T, U, R> - takes T and U, returns R
        BiFunction<String, String, String> concat = (a, b) -> a + " " + b;
        BiFunction<Integer, Integer, Integer> max = Integer::max;
        
        System.out.println("Concat: " + concat.apply("Hello", "World"));
        System.out.println("Max: " + max.apply(5, 8));
        
        // BiConsumer<T, U> - takes T and U, returns void
        BiConsumer<String, Integer> printNameAge = (name, age) -> 
            System.out.println(name + " is " + age + " years old");
        
        printNameAge.accept("Alice", 25);
        
        // BiPredicate<T, U> - takes T and U, returns boolean
        BiPredicate<String, String> startsWith = String::startsWith;
        BiPredicate<Integer, Integer> isGreater = (a, b) -> a > b;
        
        System.out.println("'hello' starts with 'he': " + startsWith.test("hello", "he"));
        System.out.println("10 > 5: " + isGreater.test(10, 5));
        
        // UnaryOperator<T> - special case of Function<T, T>
        UnaryOperator<String> toUpper = String::toUpperCase;
        UnaryOperator<Integer> square = n -> n * n;
        
        System.out.println("Upper: " + toUpper.apply("hello"));
        System.out.println("Square of 5: " + square.apply(5));
        
        // BinaryOperator<T> - special case of BiFunction<T, T, T>
        BinaryOperator<String> stringConcat = String::concat;
        BinaryOperator<Integer> add = Integer::sum;
        
        System.out.println("Binary concat: " + stringConcat.apply("Hello", "World"));
        System.out.println("Binary add: " + add.apply(3, 7));
    }
    
    public static void chainingInterfaces() {
        // Function composition
        Function<String, String> addExclamation = s -> s + "!";
        Function<String, String> toUpper = String::toUpperCase;
        
        // compose() - executes the parameter first, then this function
        Function<String, String> upperThenExclamation = addExclamation.compose(toUpper);
        System.out.println("Compose: " + upperThenExclamation.apply("hello"));
        
        // andThen() - executes this function first, then the parameter
        Function<String, String> exclamationThenUpper = addExclamation.andThen(toUpper);
        System.out.println("AndThen: " + exclamationThenUpper.apply("hello"));
        
        // Predicate chaining
        Predicate<String> isLong = s -> s.length() > 5;
        Predicate<String> startsWithA = s -> s.startsWith("A");
        
        // and() - both conditions must be true
        Predicate<String> longAndStartsWithA = isLong.and(startsWithA);
        System.out.println("'Application' long and starts with A: " + 
                          longAndStartsWithA.test("Application"));
        
        // or() - either condition can be true
        Predicate<String> longOrStartsWithA = isLong.or(startsWithA);
        System.out.println("'App' long or starts with A: " + 
                          longOrStartsWithA.test("App"));
        
        // negate() - opposite of the condition
        Predicate<String> notLong = isLong.negate();
        System.out.println("'hi' is not long: " + notLong.test("hi"));
        
        // Consumer chaining
        Consumer<String> print1 = s -> System.out.print("First: " + s);
        Consumer<String> print2 = s -> System.out.println(", Second: " + s);
        
        Consumer<String> combined = print1.andThen(print2);
        combined.accept("Hello");
    }
    
    // Custom functional interfaces
    @FunctionalInterface
    interface TriFunction<T, U, V, R> {
        R apply(T t, U u, V v);
    }
    
    @FunctionalInterface
    interface Processor<T> {
        T process(T input);
        
        // Default method
        default Processor<T> andThen(Processor<T> after) {
            return input -> after.process(this.process(input));
        }
    }
    
    @FunctionalInterface
    interface Validator<T> {
        ValidationResult validate(T item);
    }
    
    static class ValidationResult {
        private final boolean valid;
        private final String message;
        
        public ValidationResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }
        
        public boolean isValid() { return valid; }
        public String getMessage() { return message; }
        
        @Override
        public String toString() {
            return valid ? "Valid" : "Invalid: " + message;
        }
    }
    
    public static void customInterfaces() {
        // TriFunction example
        TriFunction<Integer, Integer, Integer, String> formatter = 
            (a, b, c) -> String.format("(%d, %d, %d)", a, b, c);
        
        System.out.println("TriFunction: " + formatter.apply(1, 2, 3));
        
        // Processor chaining
        Processor<String> addPrefix = s -> "Mr. " + s;
        Processor<String> addSuffix = s -> s + " Jr.";
        Processor<String> toUpper = String::toUpperCase;
        
        Processor<String> fullProcessor = addPrefix.andThen(addSuffix).andThen(toUpper);
        System.out.println("Processed: " + fullProcessor.process("john doe"));
        
        // Validator example
        Validator<String> emailValidator = email -> {
            if (email == null || email.trim().isEmpty()) {
                return new ValidationResult(false, "Email cannot be empty");
            }
            if (!email.contains("@")) {
                return new ValidationResult(false, "Email must contain @");
            }
            if (!email.contains(".")) {
                return new ValidationResult(false, "Email must contain .");
            }
            return new ValidationResult(true, "Valid email");
        };
        
        System.out.println("Validate 'test@example.com': " + 
                          emailValidator.validate("test@example.com"));
        System.out.println("Validate 'invalid': " + 
                          emailValidator.validate("invalid"));
    }
    
    // Functional interfaces with exception handling
    @FunctionalInterface
    interface ThrowingFunction<T, R> {
        R apply(T t) throws Exception;
        
        static <T, R> Function<T, R> wrap(ThrowingFunction<T, R> throwingFunction) {
            return t -> {
                try {
                    return throwingFunction.apply(t);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            };
        }
    }
    
    @FunctionalInterface
    interface ThrowingConsumer<T> {
        void accept(T t) throws Exception;
        
        static <T> Consumer<T> wrap(ThrowingConsumer<T> throwingConsumer) {
            return t -> {
                try {
                    throwingConsumer.accept(t);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            };
        }
    }
    
    public static void exceptionalInterfaces() {
        // Functions that throw exceptions
        ThrowingFunction<String, Integer> parseInteger = Integer::parseInt;
        
        // Wrap the throwing function
        Function<String, Integer> safeParseInteger = ThrowingFunction.wrap(parseInteger);
        
        try {
            System.out.println("Parse '42': " + safeParseInteger.apply("42"));
            // System.out.println("Parse 'invalid': " + safeParseInteger.apply("invalid"));
        } catch (RuntimeException e) {
            System.out.println("Parsing failed: " + e.getCause().getMessage());
        }
        
        // Consumer that throws exceptions
        ThrowingConsumer<String> writeToFile = filename -> {
            if (filename.equals("readonly")) {
                throw new IOException("Cannot write to readonly file");
            }
            System.out.println("Writing to file: " + filename);
        };
        
        Consumer<String> safeWriter = ThrowingConsumer.wrap(writeToFile);
        
        try {
            safeWriter.accept("normal.txt");
            // safeWriter.accept("readonly");
        } catch (RuntimeException e) {
            System.out.println("Write failed: " + e.getCause().getMessage());
        }
    }
}
```

### Method References

```java
import java.util.*;
import java.util.function.*;

public class MethodReferenceExamples {
    public static void main(String[] args) {
        // Static method references
        staticMethodReferences();
        
        // Instance method references
        instanceMethodReferences();
        
        // Constructor references
        constructorReferences();
        
        // Method references vs lambdas
        methodReferencesVsLambdas();
    }
    
    public static void staticMethodReferences() {
        // Static method reference - ClassName::methodName
        List<String> numbers = Arrays.asList("1", "2", "3", "4", "5");
        
        // Lambda: s -> Integer.parseInt(s)
        // Method reference: Integer::parseInt
        List<Integer> integers = numbers.stream()
                                       .map(Integer::parseInt)
                                       .collect(Collectors.toList());
        System.out.println("Parsed integers: " + integers);
        
        // Math static methods
        List<Double> values = Arrays.asList(1.1, 2.7, 3.2, 4.9);
        
        values.stream()
              .map(Math::ceil)  // Lambda: d -> Math.ceil(d)
              .forEach(System.out::println);
        
        // Custom static method
        List<String> words = Arrays.asList("hello", "world", "java");
        words.stream()
             .map(StringUtils::capitalize)  // Our static method
             .forEach(System.out::println);
        
        // Comparator static methods
        List<String> names = Arrays.asList("Alice", "bob", "Charlie");
        names.sort(String::compareToIgnoreCase);  // Static method reference
        System.out.println("Sorted names: " + names);
    }
    
    public static void instanceMethodReferences() {
        // Instance method of particular object - object::methodName
        List<String> strings = Arrays.asList("hello", "world", "java", "lambda");
        
        // Method reference to instance method of particular object
        PrintStream out = System.out;
        strings.forEach(out::println);  // Lambda: s -> out.println(s)
        
        // String instance methods
        String prefix = "-> ";
        strings.stream()
               .map(prefix::concat)  // Lambda: s -> prefix.concat(s)
               .forEach(System.out::println);
        
        // Instance method of arbitrary object - ClassName::instanceMethod
        strings.stream()
               .map(String::toUpperCase)  // Lambda: s -> s.toUpperCase()
               .forEach(System.out::println);
        
        strings.stream()
               .filter(String::isEmpty)  // Lambda: s -> s.isEmpty()
               .forEach(System.out::println);
        
        // Sorting with method reference to instance method
        List<String> sortedByLength = strings.stream()
                                            .sorted(Comparator.comparing(String::length))
                                            .collect(Collectors.toList());
        System.out.println("Sorted by length: " + sortedByLength);
        
        // Custom class example
        List<Person> people = Arrays.asList(
            new Person("Alice", 30),
            new Person("Bob", 25),
            new Person("Charlie", 35)
        );
        
        // Method reference to instance method of arbitrary object
        people.stream()
              .map(Person::getName)  // Lambda: p -> p.getName()
              .forEach(System.out::println);
        
        people.sort(Comparator.comparing(Person::getAge));  // Lambda: p -> p.getAge()
        System.out.println("People sorted by age: " + people);
    }
    
    public static void constructorReferences() {
        // Constructor reference - ClassName::new
        List<String> names = Arrays.asList("Alice", "Bob", "Charlie");
        
        // Single parameter constructor
        List<Person> people = names.stream()
                                  .map(Person::new)  // Lambda: name -> new Person(name)
                                  .collect(Collectors.toList());
        System.out.println("People from names: " + people);
        
        // Array constructor reference
        String[] nameArray = names.stream()
                                 .toArray(String[]::new);  // Lambda: size -> new String[size]
        System.out.println("Name array: " + Arrays.toString(nameArray));
        
        // Generic constructor references
        Supplier<List<String>> listSupplier = ArrayList::new;  // Lambda: () -> new ArrayList<>()
        List<String> newList = listSupplier.get();
        newList.add("Hello");
        System.out.println("New list: " + newList);
        
        // Constructor with multiple parameters
        BiFunction<String, Integer, Person> personCreator = Person::new;  // Lambda: (name, age) -> new Person(name, age)
        Person newPerson = personCreator.apply("David", 28);
        System.out.println("New person: " + newPerson);
        
        // Map constructor
        Supplier<Map<String, Integer>> mapSupplier = HashMap::new;
        Map<String, Integer> newMap = mapSupplier.get();
        newMap.put("key", 42);
        System.out.println("New map: " + newMap);
    }
    
    public static void methodReferencesVsLambdas() {
        List<String> words = Arrays.asList("hello", "world", "java");
        
        // Equivalent expressions
        System.out.println("Method references vs Lambdas:");
        
        // Static method
        words.stream().map(Integer::parseInt);              // Method reference
        words.stream().map(s -> Integer.parseInt(s));       // Lambda
        
        // Instance method of particular object
        words.forEach(System.out::println);                 // Method reference
        words.forEach(s -> System.out.println(s));          // Lambda
        
        // Instance method of arbitrary object
        words.stream().map(String::toUpperCase);            // Method reference
        words.stream().map(s -> s.toUpperCase());           // Lambda
        
        // Constructor
        words.stream().map(StringBuilder::new);             // Method reference
        words.stream().map(s -> new StringBuilder(s));      // Lambda
        
        // When to use lambdas instead of method references
        List<Integer> numbers = Arrays.asList(1, 2, 3, 4, 5);
        
        // Method reference not possible - need to modify arguments
        numbers.stream()
               .map(n -> n * 2)  // Cannot use method reference
               .forEach(System.out::println);
        
        // Method reference not possible - multiple statements
        words.stream()
             .filter(s -> {
                 System.out.println("Checking: " + s);
                 return s.length() > 4;
             })
             .forEach(System.out::println);
        
        // Method reference not possible - accessing multiple methods
        List<Person> people = Arrays.asList(new Person("Alice", 30));
        people.stream()
              .filter(p -> p.getName().startsWith("A") && p.getAge() > 25)
              .forEach(System.out::println);
    }
    
    // Utility class for examples
    static class StringUtils {
        public static String capitalize(String str) {
            if (str == null || str.isEmpty()) {
                return str;
            }
            return str.substring(0, 1).toUpperCase() + str.substring(1);
        }
    }
    
    // Person class for examples
    static class Person {
        private String name;
        private int age;
        
        public Person(String name) {
            this.name = name;
            this.age = 0;
        }
        
        public Person(String name, int age) {
            this.name = name;
            this.age = age;
        }
        
        public String getName() { return name; }
        public int getAge() { return age; }
        
        @Override
        public String toString() {
            return "Person{name='" + name + "', age=" + age + "}";
        }
    }
}
```

### Built-in Functional Interfaces

```java
import java.util.*;
import java.util.function.*;

public class BuiltInFunctionalInterfaces {
    public static void main(String[] args) {
        // Core functional interfaces
        coreFunctionalInterfaces();
        
        // Primitive specializations
        primitiveSpecializations();
        
        // Practical applications
        practicalApplications();
        
        // Advanced combinations
        advancedCombinations();
    }
    
    public static void coreFunctionalInterfaces() {
        System.out.println("=== Core Functional Interfaces ===");
        
        // Function<T, R> - transformation
        Function<String, Integer> length = String::length;
        Function<Integer, String> hex = Integer::toHexString;
        
        System.out.println("Length of 'hello': " + length.apply("hello"));
        System.out.println("Hex of 255: " + hex.apply(255));
        
        // Predicate<T> - testing
        Predicate<String> isEmpty = String::isEmpty;
        Predicate<Integer> isEven = n -> n % 2 == 0;
        Predicate<String> hasUpperCase = s -> !s.equals(s.toLowerCase());
        
        System.out.println("'' is empty: " + isEmpty.test(""));
        System.out.println("4 is even: " + isEven.test(4));
        System.out.println("'Hello' has uppercase: " + hasUpperCase.test("Hello"));
        
        // Consumer<T> - side effects
        Consumer<String> printer = System.out::println;
        Consumer<List<String>> listLogger = list -> 
            System.out.println("List size: " + list.size());
        
        printer.accept("Hello Consumer!");
        listLogger.accept(Arrays.asList("a", "b", "c"));
        
        // Supplier<T> - generation
        Supplier<String> uuid = () -> UUID.randomUUID().toString();
        Supplier<Integer> randomInt = () -> (int) (Math.random() * 100);
        Supplier<Date> now = Date::new;
        
        System.out.println("UUID: " + uuid.get());
        System.out.println("Random int: " + randomInt.get());
        System.out.println("Current time: " + now.get());
        
        // UnaryOperator<T> - same type transformation
        UnaryOperator<String> reverse = s -> new StringBuilder(s).reverse().toString();
        UnaryOperator<Integer> factorial = n -> {
            int result = 1;
            for (int i = 2; i <= n; i++) result *= i;
            return result;
        };
        
        System.out.println("Reverse 'hello': " + reverse.apply("hello"));
        System.out.println("Factorial of 5: " + factorial.apply(5));
        
        // BinaryOperator<T> - combining same types
        BinaryOperator<String> concat = String::concat;
        BinaryOperator<Integer> max = Integer::max;
        BinaryOperator<Integer> gcd = BuiltInFunctionalInterfaces::gcd;
        
        System.out.println("Concat 'Hello' + 'World': " + concat.apply("Hello", "World"));
        System.out.println("Max of 5 and 8: " + max.apply(5, 8));
        System.out.println("GCD of 12 and 18: " + gcd.apply(12, 18));
    }
    
    public static void primitiveSpecializations() {
        System.out.println("\n=== Primitive Specializations ===");
        
        // IntFunction, LongFunction, DoubleFunction
        IntFunction<String> intToString = Integer::toString;
        LongFunction<String> longToHex = Long::toHexString;
        DoubleFunction<Integer> doubleToInt = d -> (int) Math.round(d);
        
        System.out.println("Int 42 to string: " + intToString.apply(42));
        System.out.println("Long 255 to hex: " + longToHex.apply(255L));
        System.out.println("Double 3.7 to int: " + doubleToInt.apply(3.7));
        
        // ToIntFunction, ToLongFunction, ToDoubleFunction
        ToIntFunction<String> stringToInt = Integer::parseInt;
        ToLongFunction<String> stringToLong = Long::parseLong;
        ToDoubleFunction<String> stringToDouble = Double::parseDouble;
        
        System.out.println("String '42' to int: " + stringToInt.applyAsInt("42"));
        System.out.println("String '100' to long: " + stringToLong.applyAsLong("100"));
        System.out.println("String '3.14' to double: " + stringToDouble.applyAsDouble("3.14"));
        
        // IntPredicate, LongPredicate, DoublePredicate
        IntPredicate isPositive = n -> n > 0;
        LongPredicate isEven = n -> n % 2 == 0;
        DoublePredicate isWhole = d -> d == Math.floor(d);
        
        System.out.println("5 is positive: " + isPositive.test(5));
        System.out.println("4L is even: " + isEven.test(4L));
        System.out.println("3.0 is whole: " + isWhole.test(3.0));
        
        // IntConsumer, LongConsumer, DoubleConsumer
        IntConsumer intPrinter = System.out::println;
        LongConsumer longLogger = l -> System.out.println("Long value: " + l);
        DoubleConsumer doubleProcessor = d -> System.out.println("Processed: " + (d * 2));
        
        intPrinter.accept(42);
        longLogger.accept(100L);
        doubleProcessor.accept(3.14);
        
        // IntSupplier, LongSupplier, DoubleSupplier
        IntSupplier randomInt = () -> (int) (Math.random() * 100);
        LongSupplier timestamp = System::currentTimeMillis;
        DoubleSupplier randomDouble = Math::random;
        
        System.out.println("Random int: " + randomInt.getAsInt());
        System.out.println("Timestamp: " + timestamp.getAsLong());
        System.out.println("Random double: " + randomDouble.getAsDouble());
        
        // IntUnaryOperator, LongUnaryOperator, DoubleUnaryOperator
        IntUnaryOperator square = n -> n * n;
        LongUnaryOperator doubleValue = n -> n * 2;
        DoubleUnaryOperator sqrt = Math::sqrt;
        
        System.out.println("Square of 5: " + square.applyAsInt(5));
        System.out.println("Double of 10L: " + doubleValue.applyAsLong(10L));
        System.out.println("Sqrt of 16.0: " + sqrt.applyAsDouble(16.0));
        
        // IntBinaryOperator, LongBinaryOperator, DoubleBinaryOperator
        IntBinaryOperator add = Integer::sum;
        LongBinaryOperator multiply = (a, b) -> a * b;
        DoubleBinaryOperator power = Math::pow;
        
        System.out.println("Add 3 + 7: " + add.applyAsInt(3, 7));
        System.out.println("Multiply 4L * 5L: " + multiply.applyAsLong(4L, 5L));
        System.out.println("Power 2.0 ^ 3.0: " + power.applyAsDouble(2.0, 3.0));
    }
    
    public static void practicalApplications() {
        System.out.println("\n=== Practical Applications ===");
        
        // Data processing pipeline
        List<String> data = Arrays.asList("1", "2", "3", "4", "5");
        
        Function<String, Integer> parser = Integer::parseInt;
        Predicate<Integer> isEven = n -> n % 2 == 0;
        Function<Integer, Integer> square = n -> n * n;
        Consumer<Integer> printer = n -> System.out.print(n + " ");
        
        System.out.print("Even squares: ");
        data.stream()
            .map(parser)
            .filter(isEven)
            .map(square)
            .forEach(printer);
        System.out.println();
        
        // Validation chain
        List<String> emails = Arrays.asList("user@example.com", "invalid", "test@test.org");
        
        Predicate<String> notEmpty = Predicate.not(String::isEmpty);
        Predicate<String> hasAt = s -> s.contains("@");
        Predicate<String> hasDot = s -> s.contains(".");
        Predicate<String> validEmail = notEmpty.and(hasAt).and(hasDot);
        
        System.out.println("Valid emails:");
        emails.stream()
              .filter(validEmail)
              .forEach(System.out::println);
        
        // Factory pattern with Supplier
        Map<String, Supplier<List<String>>> listFactories = Map.of(
            "array", ArrayList::new,
            "linked", LinkedList::new,
            "vector", Vector::new
        );
        
        List<String> arrayList = listFactories.get("array").get();
        arrayList.add("item");
        System.out.println("Created ArrayList: " + arrayList.getClass().getSimpleName());
        
        // Configuration with Function
        Map<String, Function<String, String>> formatters = Map.of(
            "upper", String::toUpperCase,
            "lower", String::toLowerCase,
            "reverse", s -> new StringBuilder(s).reverse().toString()
        );
        
        String text = "Hello World";
        formatters.forEach((name, formatter) -> 
            System.out.println(name + ": " + formatter.apply(text)));
    }
    
    public static void advancedCombinations() {
        System.out.println("\n=== Advanced Combinations ===");
        
        // Function composition chain
        Function<String, String> removeSpaces = s -> s.replace(" ", "");
        Function<String, String> toLowerCase = String::toLowerCase;
        Function<String, Integer> getLength = String::length;
        
        Function<String, Integer> pipeline = removeSpaces
            .andThen(toLowerCase)
            .andThen(getLength);
        
        System.out.println("Pipeline result for 'Hello World': " + 
                          pipeline.apply("Hello World"));
        
        // Predicate combinations
        Predicate<Integer> isPositive = n -> n > 0;
        Predicate<Integer> isEven = n -> n % 2 == 0;
        Predicate<Integer> isSmall = n -> n < 10;
        
        Predicate<Integer> positiveEvenSmall = isPositive.and(isEven).and(isSmall);
        
        List<Integer> numbers = Arrays.asList(-2, 1, 2, 8, 15, 20);
        System.out.print("Positive even small numbers: ");
        numbers.stream()
               .filter(positiveEvenSmall)
               .forEach(n -> System.out.print(n + " "));
        System.out.println();
        
        // Consumer chaining
        Consumer<String> logger = s -> System.out.println("LOG: " + s);
        Consumer<String> uppercaser = s -> System.out.println("UPPER: " + s.toUpperCase());
        Consumer<String> counter = s -> System.out.println("LENGTH: " + s.length());
        
        Consumer<String> multiProcessor = logger.andThen(uppercaser).andThen(counter);
        multiProcessor.accept("hello");
        
        // Supplier with caching
        Supplier<String> expensiveOperation = () -> {
            System.out.println("Performing expensive operation...");
            try { Thread.sleep(1000); } catch (InterruptedException e) {}
            return "Expensive Result";
        };
        
        Supplier<String> cached = memoize(expensiveOperation);
        System.out.println("First call: " + cached.get());
        System.out.println("Second call: " + cached.get()); // Should be faster
    }
    
    // Utility method for GCD
    private static int gcd(int a, int b) {
        while (b != 0) {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }
    
    // Memoization utility
    private static <T> Supplier<T> memoize(Supplier<T> supplier) {
        return new Supplier<T>() {
            private T value;
            private boolean computed = false;
            
            @Override
            public T get() {
                if (!computed) {
                    value = supplier.get();
                    computed = true;
                }
                return value;
            }
        };
    }
}
```