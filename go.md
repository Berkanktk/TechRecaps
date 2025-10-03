# Go Programming Language

A comprehensive guide covering Go from basics to medium level with practical examples.

## Table of Contents

1. [Go Fundamentals](#1-go-fundamentals)
2. [Variables and Constants](#2-variables-and-constants)
3. [Data Types](#3-data-types)
4. [Operators](#4-operators)
5. [Control Flow](#5-control-flow)
6. [Arrays and Slices](#6-arrays-and-slices)
7. [Maps](#7-maps)
8. [Strings](#8-strings)
9. [Functions](#9-functions)
10. [Methods](#10-methods)
11. [Structs](#11-structs)
12. [Interfaces](#12-interfaces)
13. [Pointers](#13-pointers)
14. [Error Handling](#14-error-handling)
15. [Packages and Modules](#15-packages-and-modules)
16. [Concurrency](#16-concurrency)
17. [Channels](#17-channels)
18. [File I/O](#18-file-io)
19. [JSON Handling](#19-json-handling)
20. [Testing](#20-testing)

## 1. Go Fundamentals

Go is a statically typed, compiled programming language designed for simplicity and efficiency.

### Hello World

```go
package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}
```

### Basic Program Structure

```go
package main

import (
    "fmt"
    "math"
    "strings"
)

func main() {
    // Program entry point
    fmt.Println("Go basics demonstration")
    
    // Calling functions from different packages
    result := math.Sqrt(16)
    fmt.Printf("Square root of 16: %.2f\n", result)
    
    text := strings.ToUpper("hello go")
    fmt.Println("Uppercase:", text)
}
```

### Comments

```go
package main

import "fmt"

// This is a single-line comment

/*
This is a multi-line comment
spanning multiple lines
*/

func main() {
    fmt.Println("Comments example")
    
    // Inline comment
    var x int = 10 // Variable declaration with comment
    fmt.Println("Value:", x)
}
```

## 2. Variables and Constants

### Variable Declaration

```go
package main

import "fmt"

func main() {
    // Various ways to declare variables
    var name string = "Alice"
    var age int = 30
    var isActive bool = true
    
    // Type inference
    var score = 95.5
    
    // Short declaration
    city := "New York"
    population := 8_000_000
    
    // Multiple declarations
    var x, y, z int = 1, 2, 3
    a, b := "hello", "world"
    
    fmt.Printf("Name: %s, Age: %d, Active: %t\n", name, age, isActive)
    fmt.Printf("Score: %.1f, City: %s, Population: %d\n", score, city, population)
    fmt.Printf("x=%d, y=%d, z=%d\n", x, y, z)
    fmt.Printf("a=%s, b=%s\n", a, b)
}
```

### Zero Values

```go
package main

import "fmt"

func main() {
    // Zero values for different types
    var intVar int
    var floatVar float64
    var boolVar bool
    var stringVar string
    var sliceVar []int
    var mapVar map[string]int
    var funcVar func()
    
    fmt.Printf("int: %d\n", intVar)           // 0
    fmt.Printf("float64: %f\n", floatVar)     // 0.000000
    fmt.Printf("bool: %t\n", boolVar)         // false
    fmt.Printf("string: '%s'\n", stringVar)   // ''
    fmt.Printf("slice: %v\n", sliceVar)       // []
    fmt.Printf("map: %v\n", mapVar)           // map[]
    fmt.Printf("func: %v\n", funcVar)         // <nil>
}
```

### Constants

```go
package main

import "fmt"

const (
    Pi = 3.14159
    E  = 2.71828
)

const (
    StatusPending = iota // 0
    StatusProcessing     // 1
    StatusCompleted      // 2
    StatusFailed         // 3
)

func main() {
    const greeting = "Hello"
    const maxRetries = 3
    
    fmt.Printf("Pi: %.5f, E: %.5f\n", Pi, E)
    fmt.Printf("Greeting: %s, Max retries: %d\n", greeting, maxRetries)
    
    fmt.Printf("Status values: %d, %d, %d, %d\n", 
        StatusPending, StatusProcessing, StatusCompleted, StatusFailed)
    
    // Typed constants
    const typedInt int = 100
    const typedFloat float64 = 3.14
    
    fmt.Printf("Typed constants: %d, %.2f\n", typedInt, typedFloat)
}
```

## 3. Data Types

### Basic Types

```go
package main

import (
    "fmt"
    "unsafe"
)

func main() {
    // Integer types
    var int8Var int8 = 127
    var int16Var int16 = 32767
    var int32Var int32 = 2147483647
    var int64Var int64 = 9223372036854775807
    
    var uint8Var uint8 = 255
    var uint16Var uint16 = 65535
    var uint32Var uint32 = 4294967295
    var uint64Var uint64 = 18446744073709551615
    
    // Platform dependent
    var intVar int = 42
    var uintVar uint = 42
    
    // Floating point
    var float32Var float32 = 3.14
    var float64Var float64 = 3.141592653589793
    
    // Complex numbers
    var complex64Var complex64 = 1 + 2i
    var complex128Var complex128 = 1 + 2i
    
    // Boolean
    var boolVar bool = true
    
    // String
    var stringVar string = "Hello, Go!"
    
    // Byte and rune
    var byteVar byte = 'A'        // alias for uint8
    var runeVar rune = '世'        // alias for int32
    
    fmt.Printf("int8: %d, int16: %d, int32: %d, int64: %d\n", 
        int8Var, int16Var, int32Var, int64Var)
    fmt.Printf("uint8: %d, uint16: %d, uint32: %d, uint64: %d\n", 
        uint8Var, uint16Var, uint32Var, uint64Var)
    fmt.Printf("int: %d, uint: %d\n", intVar, uintVar)
    fmt.Printf("float32: %f, float64: %f\n", float32Var, float64Var)
    fmt.Printf("complex64: %v, complex128: %v\n", complex64Var, complex128Var)
    fmt.Printf("bool: %t, string: %s\n", boolVar, stringVar)
    fmt.Printf("byte: %c (%d), rune: %c (%d)\n", byteVar, byteVar, runeVar, runeVar)
    
    // Size information
    fmt.Printf("Size of int: %d bytes\n", unsafe.Sizeof(intVar))
    fmt.Printf("Size of float64: %d bytes\n", unsafe.Sizeof(float64Var))
    fmt.Printf("Size of string: %d bytes\n", unsafe.Sizeof(stringVar))
}
```

### Type Conversion

```go
package main

import (
    "fmt"
    "strconv"
)

func main() {
    // Numeric conversions
    var i int = 42
    var f float64 = float64(i)
    var u uint = uint(f)
    
    fmt.Printf("int: %d, float64: %.1f, uint: %d\n", i, f, u)
    
    // String conversions
    str := "123"
    num, err := strconv.Atoi(str)
    if err == nil {
        fmt.Printf("String to int: '%s' -> %d\n", str, num)
    }
    
    floatStr := "3.14"
    floatNum, err := strconv.ParseFloat(floatStr, 64)
    if err == nil {
        fmt.Printf("String to float: '%s' -> %.2f\n", floatStr, floatNum)
    }
    
    // Number to string
    intToStr := strconv.Itoa(42)
    floatToStr := strconv.FormatFloat(3.14159, 'f', 2, 64)
    boolToStr := strconv.FormatBool(true)
    
    fmt.Printf("Int to string: %s\n", intToStr)
    fmt.Printf("Float to string: %s\n", floatToStr)
    fmt.Printf("Bool to string: %s\n", boolToStr)
    
    // Type assertions (for interfaces)
    var x interface{} = "hello"
    str2, ok := x.(string)
    if ok {
        fmt.Printf("Type assertion: %s\n", str2)
    }
    
    // Check type
    switch v := x.(type) {
    case string:
        fmt.Printf("x is a string: %s\n", v)
    case int:
        fmt.Printf("x is an int: %d\n", v)
    default:
        fmt.Printf("x is of unknown type\n")
    }
}
```

## 4. Operators

### Arithmetic Operators

```go
package main

import "fmt"

func main() {
    a, b := 15, 4
    
    fmt.Printf("a = %d, b = %d\n", a, b)
    fmt.Printf("Addition: %d + %d = %d\n", a, b, a+b)
    fmt.Printf("Subtraction: %d - %d = %d\n", a, b, a-b)
    fmt.Printf("Multiplication: %d * %d = %d\n", a, b, a*b)
    fmt.Printf("Division: %d / %d = %d\n", a, b, a/b)
    fmt.Printf("Modulo: %d %% %d = %d\n", a, b, a%b)
    
    // Float division
    x, y := 15.0, 4.0
    fmt.Printf("Float division: %.1f / %.1f = %.2f\n", x, y, x/y)
    
    // Increment and decrement
    a++
    fmt.Printf("After a++: %d\n", a)
    b--
    fmt.Printf("After b--: %d\n", b)
    
    // Assignment operators
    a += 5
    fmt.Printf("After a += 5: %d\n", a)
    a -= 3
    fmt.Printf("After a -= 3: %d\n", a)
    a *= 2
    fmt.Printf("After a *= 2: %d\n", a)
    a /= 4
    fmt.Printf("After a /= 4: %d\n", a)
}
```

### Comparison Operators

```go
package main

import "fmt"

func main() {
    x, y := 10, 20
    
    fmt.Printf("x = %d, y = %d\n", x, y)
    fmt.Printf("x == y: %t\n", x == y)
    fmt.Printf("x != y: %t\n", x != y)
    fmt.Printf("x < y: %t\n", x < y)
    fmt.Printf("x <= y: %t\n", x <= y)
    fmt.Printf("x > y: %t\n", x > y)
    fmt.Printf("x >= y: %t\n", x >= y)
    
    // String comparison
    str1, str2 := "apple", "banana"
    fmt.Printf("'%s' < '%s': %t\n", str1, str2, str1 < str2)
    fmt.Printf("'%s' == '%s': %t\n", str1, str1, str1 == str1)
    
    // Boolean comparison
    bool1, bool2 := true, false
    fmt.Printf("%t == %t: %t\n", bool1, bool2, bool1 == bool2)
    fmt.Printf("%t != %t: %t\n", bool1, bool2, bool1 != bool2)
}
```

### Logical Operators

```go
package main

import "fmt"

func main() {
    a, b := true, false
    
    fmt.Printf("a = %t, b = %t\n", a, b)
    fmt.Printf("a && b: %t\n", a && b)  // AND
    fmt.Printf("a || b: %t\n", a || b)  // OR
    fmt.Printf("!a: %t\n", !a)          // NOT
    fmt.Printf("!b: %t\n", !b)          // NOT
    
    // Short-circuit evaluation
    x, y := 10, 0
    
    // This won't cause division by zero due to short-circuit
    if y != 0 && x/y > 5 {
        fmt.Println("Division result > 5")
    } else {
        fmt.Println("Either y is 0 or division result <= 5")
    }
    
    // Complex logical expressions
    age := 25
    hasLicense := true
    hasInsurance := true
    
    canDrive := age >= 18 && hasLicense && hasInsurance
    fmt.Printf("Can drive: %t\n", canDrive)
    
    // Logical operators with numbers (non-zero is true)
    num1, num2 := 5, 0
    fmt.Printf("Logical operations with numbers:\n")
    fmt.Printf("num1 && num2 equivalent: %t\n", num1 != 0 && num2 != 0)
    fmt.Printf("num1 || num2 equivalent: %t\n", num1 != 0 || num2 != 0)
}
```

### Bitwise Operators

```go
package main

import "fmt"

func main() {
    a, b := 12, 10  // Binary: 1100 and 1010
    
    fmt.Printf("a = %d (binary: %04b)\n", a, a)
    fmt.Printf("b = %d (binary: %04b)\n", b, b)
    
    fmt.Printf("a & b = %d (binary: %04b)\n", a&b, a&b)   // AND
    fmt.Printf("a | b = %d (binary: %04b)\n", a|b, a|b)   // OR
    fmt.Printf("a ^ b = %d (binary: %04b)\n", a^b, a^b)   // XOR
    fmt.Printf("^a = %d (binary: %08b)\n", ^a, ^a)        // NOT
    
    // Bit shifting
    fmt.Printf("a << 2 = %d (binary: %08b)\n", a<<2, a<<2) // Left shift
    fmt.Printf("a >> 2 = %d (binary: %04b)\n", a>>2, a>>2) // Right shift
    
    // Practical bit manipulation
    flags := 0
    
    // Set flags (OR operation)
    const (
        Read    = 1 << 0  // 001
        Write   = 1 << 1  // 010
        Execute = 1 << 2  // 100
    )
    
    flags |= Read | Write  // Set read and write flags
    fmt.Printf("Flags after setting Read|Write: %03b\n", flags)
    
    // Check flags (AND operation)
    fmt.Printf("Has Read permission: %t\n", flags&Read != 0)
    fmt.Printf("Has Execute permission: %t\n", flags&Execute != 0)
    
    // Clear flags (AND with NOT)
    flags &^= Write  // Clear write flag
    fmt.Printf("Flags after clearing Write: %03b\n", flags)
    
    // Toggle flags (XOR operation)
    flags ^= Execute  // Toggle execute flag
    fmt.Printf("Flags after toggling Execute: %03b\n", flags)
}
```

## 5. Control Flow

### If Statements

```go
package main

import (
    "fmt"
    "math/rand"
    "time"
)

func main() {
    // Basic if statement
    age := 18
    if age >= 18 {
        fmt.Println("You are an adult")
    }
    
    // If-else
    score := 85
    if score >= 90 {
        fmt.Println("Grade: A")
    } else if score >= 80 {
        fmt.Println("Grade: B")
    } else if score >= 70 {
        fmt.Println("Grade: C")
    } else {
        fmt.Println("Grade: F")
    }
    
    // If with initialization
    if num := rand.Intn(100); num%2 == 0 {
        fmt.Printf("%d is even\n", num)
    } else {
        fmt.Printf("%d is odd\n", num)
    }
    
    // Complex conditions
    username := "admin"
    password := "secret123"
    isActive := true
    
    if len(username) > 0 && len(password) >= 8 && isActive {
        fmt.Println("Login successful")
    } else {
        fmt.Println("Login failed")
    }
    
    // Checking for zero values
    var name string
    if name == "" {
        fmt.Println("Name is empty")
    }
    
    var numbers []int
    if numbers == nil {
        fmt.Println("Slice is nil")
    }
    
    // Error checking pattern
    value, err := time.Parse("2006-01-02", "2023-12-25")
    if err != nil {
        fmt.Printf("Error parsing date: %v\n", err)
    } else {
        fmt.Printf("Parsed date: %v\n", value)
    }
}
```

### Switch Statements

```go
package main

import (
    "fmt"
    "runtime"
    "time"
)

func main() {
    // Basic switch
    day := time.Now().Weekday()
    switch day {
    case time.Monday:
        fmt.Println("It's Monday")
    case time.Tuesday:
        fmt.Println("It's Tuesday")
    case time.Wednesday, time.Thursday, time.Friday:
        fmt.Println("It's a weekday")
    case time.Saturday, time.Sunday:
        fmt.Println("It's weekend!")
    default:
        fmt.Println("Unknown day")
    }
    
    // Switch with expressions
    score := 85
    switch {
    case score >= 90:
        fmt.Println("Excellent!")
    case score >= 80:
        fmt.Println("Good job!")
    case score >= 70:
        fmt.Println("Not bad")
    default:
        fmt.Println("Try harder")
    }
    
    // Switch with initialization
    switch os := runtime.GOOS; os {
    case "darwin":
        fmt.Println("Running on macOS")
    case "linux":
        fmt.Println("Running on Linux")
    case "windows":
        fmt.Println("Running on Windows")
    default:
        fmt.Printf("Running on %s\n", os)
    }
    
    // Type switch
    var x interface{} = 42
    switch v := x.(type) {
    case int:
        fmt.Printf("x is an integer: %d\n", v)
    case string:
        fmt.Printf("x is a string: %s\n", v)
    case bool:
        fmt.Printf("x is a boolean: %t\n", v)
    default:
        fmt.Printf("x is of type %T\n", v)
    }
    
    // Fallthrough (rarely used)
    number := 2
    switch number {
    case 1:
        fmt.Println("One")
        fallthrough
    case 2:
        fmt.Println("Two or fallthrough from One")
        fallthrough
    case 3:
        fmt.Println("Three or fallthrough from Two")
    default:
        fmt.Println("Other")
    }
}
```

### Loops

```go
package main

import "fmt"

func main() {
    // Basic for loop
    fmt.Println("Basic for loop:")
    for i := 0; i < 5; i++ {
        fmt.Printf("%d ", i)
    }
    fmt.Println()
    
    // While-like loop
    fmt.Println("While-like loop:")
    j := 0
    for j < 3 {
        fmt.Printf("j = %d ", j)
        j++
    }
    fmt.Println()
    
    // Infinite loop with break
    fmt.Println("Infinite loop with break:")
    counter := 0
    for {
        if counter >= 3 {
            break
        }
        fmt.Printf("Counter: %d ", counter)
        counter++
    }
    fmt.Println()
    
    // For with continue
    fmt.Println("Loop with continue (skip even numbers):")
    for i := 0; i < 10; i++ {
        if i%2 == 0 {
            continue
        }
        fmt.Printf("%d ", i)
    }
    fmt.Println()
    
    // For range with slice
    fmt.Println("For range with slice:")
    numbers := []int{10, 20, 30, 40, 50}
    for index, value := range numbers {
        fmt.Printf("Index: %d, Value: %d\n", index, value)
    }
    
    // For range with map
    fmt.Println("For range with map:")
    scores := map[string]int{
        "Alice": 95,
        "Bob":   87,
        "Carol": 92,
    }
    for name, score := range scores {
        fmt.Printf("%s: %d\n", name, score)
    }
    
    // For range with string (iterates over runes)
    fmt.Println("For range with string:")
    text := "Hello, 世界"
    for i, char := range text {
        fmt.Printf("Index: %d, Char: %c\n", i, char)
    }
    
    // Ignoring index or value
    fmt.Println("Sum of slice values:")
    sum := 0
    for _, value := range numbers {  // Ignore index
        sum += value
    }
    fmt.Printf("Sum: %d\n", sum)
    
    // Nested loops
    fmt.Println("Multiplication table:")
    for i := 1; i <= 3; i++ {
        for j := 1; j <= 3; j++ {
            fmt.Printf("%d*%d=%d ", i, j, i*j)
        }
        fmt.Println()
    }
    
    // Labeled break and continue
    fmt.Println("Labeled break example:")
outer:
    for i := 0; i < 3; i++ {
        for j := 0; j < 3; j++ {
            if i == 1 && j == 1 {
                break outer  // Break out of both loops
            }
            fmt.Printf("(%d,%d) ", i, j)
        }
    }
    fmt.Println()
}
```

## 6. Arrays and Slices

### Arrays

```go
package main

import "fmt"

func main() {
    // Array declaration and initialization
    var arr1 [5]int  // Zero-initialized array
    fmt.Printf("Zero array: %v\n", arr1)
    
    arr2 := [5]int{1, 2, 3, 4, 5}  // Array literal
    fmt.Printf("Initialized array: %v\n", arr2)
    
    arr3 := [...]int{10, 20, 30}  // Compiler determines size
    fmt.Printf("Auto-sized array: %v, length: %d\n", arr3, len(arr3))
    
    // Partial initialization
    arr4 := [5]int{1: 10, 3: 30}  // Index-specific initialization
    fmt.Printf("Partial array: %v\n", arr4)
    
    // Accessing elements
    fmt.Printf("First element: %d\n", arr2[0])
    fmt.Printf("Last element: %d\n", arr2[len(arr2)-1])
    
    // Modifying elements
    arr2[2] = 99
    fmt.Printf("After modification: %v\n", arr2)
    
    // Array properties
    fmt.Printf("Array length: %d\n", len(arr2))
    fmt.Printf("Array capacity: %d\n", cap(arr2))
    
    // Iterating over arrays
    fmt.Println("Array iteration:")
    for i := 0; i < len(arr2); i++ {
        fmt.Printf("arr2[%d] = %d\n", i, arr2[i])
    }
    
    // Range iteration
    fmt.Println("Range iteration:")
    for index, value := range arr2 {
        fmt.Printf("Index: %d, Value: %d\n", index, value)
    }
    
    // Multi-dimensional arrays
    var matrix [3][3]int
    matrix[0] = [3]int{1, 2, 3}
    matrix[1] = [3]int{4, 5, 6}
    matrix[2] = [3]int{7, 8, 9}
    
    fmt.Println("2D Array:")
    for i := 0; i < 3; i++ {
        for j := 0; j < 3; j++ {
            fmt.Printf("%d ", matrix[i][j])
        }
        fmt.Println()
    }
    
    // Array comparison
    arr5 := [3]int{1, 2, 3}
    arr6 := [3]int{1, 2, 3}
    arr7 := [3]int{1, 2, 4}
    
    fmt.Printf("arr5 == arr6: %t\n", arr5 == arr6)
    fmt.Printf("arr5 == arr7: %t\n", arr5 == arr7)
}
```

### Slices

```go
package main

import "fmt"

func main() {
    // Slice creation
    var slice1 []int  // nil slice
    fmt.Printf("Nil slice: %v, len: %d, cap: %d\n", slice1, len(slice1), cap(slice1))
    
    slice2 := []int{1, 2, 3, 4, 5}  // Slice literal
    fmt.Printf("Slice literal: %v, len: %d, cap: %d\n", slice2, len(slice2), cap(slice2))
    
    slice3 := make([]int, 5)  // Make with length
    fmt.Printf("Make slice: %v, len: %d, cap: %d\n", slice3, len(slice3), cap(slice3))
    
    slice4 := make([]int, 3, 10)  // Make with length and capacity
    fmt.Printf("Make with capacity: %v, len: %d, cap: %d\n", slice4, len(slice4), cap(slice4))
    
    // Slicing arrays and slices
    arr := [6]int{1, 2, 3, 4, 5, 6}
    slice5 := arr[1:4]  // Elements at index 1, 2, 3
    fmt.Printf("Array slice [1:4]: %v\n", slice5)
    
    slice6 := arr[:3]   // From beginning to index 2
    slice7 := arr[3:]   // From index 3 to end
    slice8 := arr[:]    // Entire array as slice
    
    fmt.Printf("arr[:3]: %v\n", slice6)
    fmt.Printf("arr[3:]: %v\n", slice7)
    fmt.Printf("arr[:]: %v\n", slice8)
    
    // Append operation
    nums := []int{1, 2, 3}
    fmt.Printf("Original: %v, len: %d, cap: %d\n", nums, len(nums), cap(nums))
    
    nums = append(nums, 4)
    fmt.Printf("After append(4): %v, len: %d, cap: %d\n", nums, len(nums), cap(nums))
    
    nums = append(nums, 5, 6, 7)
    fmt.Printf("After append(5,6,7): %v, len: %d, cap: %d\n", nums, len(nums), cap(nums))
    
    // Append slice to slice
    more := []int{8, 9, 10}
    nums = append(nums, more...)
    fmt.Printf("After append slice: %v, len: %d, cap: %d\n", nums, len(nums), cap(nums))
    
    // Copy operation
    src := []int{1, 2, 3, 4, 5}
    dst := make([]int, len(src))
    n := copy(dst, src)
    fmt.Printf("Copied %d elements: %v\n", n, dst)
    
    // Slice manipulation
    data := []int{10, 20, 30, 40, 50}
    
    // Insert at index 2
    index := 2
    value := 25
    data = append(data[:index], append([]int{value}, data[index:]...)...)
    fmt.Printf("After insert 25 at index 2: %v\n", data)
    
    // Remove element at index 3
    removeIndex := 3
    data = append(data[:removeIndex], data[removeIndex+1:]...)
    fmt.Printf("After remove index 3: %v\n", data)
    
    // Slice sharing underlying array
    original := []int{1, 2, 3, 4, 5}
    slice9 := original[1:4]
    slice10 := original[2:5]
    
    fmt.Printf("Original: %v\n", original)
    fmt.Printf("slice9 [1:4]: %v\n", slice9)
    fmt.Printf("slice10 [2:5]: %v\n", slice10)
    
    slice9[1] = 99  // Modifies original array
    fmt.Printf("After slice9[1] = 99:\n")
    fmt.Printf("Original: %v\n", original)
    fmt.Printf("slice9: %v\n", slice9)
    fmt.Printf("slice10: %v\n", slice10)
    
    // 2D slices
    matrix := make([][]int, 3)
    for i := range matrix {
        matrix[i] = make([]int, 4)
        for j := range matrix[i] {
            matrix[i][j] = i*4 + j
        }
    }
    
    fmt.Println("2D slice:")
    for _, row := range matrix {
        fmt.Printf("%v\n", row)
    }
}
```

## 7. Maps

### Map Basics

```go
package main

import "fmt"

func main() {
    // Map declaration and initialization
    var scores map[string]int  // nil map
    fmt.Printf("Nil map: %v\n", scores)
    
    // Initialize with make
    scores = make(map[string]int)
    scores["Alice"] = 95
    scores["Bob"] = 87
    scores["Carol"] = 92
    
    fmt.Printf("Scores map: %v\n", scores)
    
    // Map literal
    grades := map[string]string{
        "Alice": "A",
        "Bob":   "B",
        "Carol": "A",
    }
    fmt.Printf("Grades map: %v\n", grades)
    
    // Accessing values
    aliceScore := scores["Alice"]
    fmt.Printf("Alice's score: %d\n", aliceScore)
    
    // Check if key exists
    bobScore, exists := scores["Bob"]
    if exists {
        fmt.Printf("Bob's score: %d\n", bobScore)
    }
    
    // Accessing non-existent key
    davidScore, exists := scores["David"]
    fmt.Printf("David's score: %d, exists: %t\n", davidScore, exists)
    
    // Adding/updating values
    scores["David"] = 88
    scores["Alice"] = 98  // Update existing
    fmt.Printf("Updated scores: %v\n", scores)
    
    // Deleting entries
    delete(scores, "Bob")
    fmt.Printf("After deleting Bob: %v\n", scores)
    
    // Map length
    fmt.Printf("Number of entries: %d\n", len(scores))
    
    // Iterating over maps
    fmt.Println("Iterating over scores:")
    for name, score := range scores {
        fmt.Printf("%s: %d\n", name, score)
    }
    
    // Iterate over keys only
    fmt.Println("Keys only:")
    for name := range scores {
        fmt.Printf("%s ", name)
    }
    fmt.Println()
    
    // Complex map types
    studentGrades := map[string]map[string]int{
        "Alice": {"Math": 95, "Science": 92, "English": 88},
        "Bob":   {"Math": 87, "Science": 91, "English": 84},
    }
    
    fmt.Printf("Alice's Math grade: %d\n", studentGrades["Alice"]["Math"])
    
    // Map with slice values
    teamMembers := map[string][]string{
        "Engineering": {"Alice", "Bob", "Charlie"},
        "Marketing":   {"David", "Eve"},
        "Sales":       {"Frank", "Grace", "Henry", "Ivy"},
    }
    
    fmt.Printf("Engineering team: %v\n", teamMembers["Engineering"])
    
    // Map as a set (using bool values)
    uniqueNumbers := map[int]bool{
        1: true,
        2: true,
        3: true,
    }
    
    // Check if number is in set
    if uniqueNumbers[2] {
        fmt.Println("2 is in the set")
    }
    
    // Add to set
    uniqueNumbers[4] = true
    
    // Remove from set
    delete(uniqueNumbers, 1)
    
    fmt.Printf("Set contents: %v\n", uniqueNumbers)
    
    // Map comparison (maps are not comparable)
    // This would cause compile error:
    // fmt.Println(scores == grades)
    
    // Manual comparison
    map1 := map[string]int{"a": 1, "b": 2}
    map2 := map[string]int{"a": 1, "b": 2}
    
    equal := len(map1) == len(map2)
    if equal {
        for k, v := range map1 {
            if map2[k] != v {
                equal = false
                break
            }
        }
    }
    fmt.Printf("Maps are equal: %t\n", equal)
}
```

## 8. Strings

### String Basics

```go
package main

import (
    "fmt"
    "strings"
    "unicode/utf8"
)

func main() {
    // String creation
    str1 := "Hello, World!"
    str2 := `This is a
multi-line
raw string`
    
    fmt.Printf("String 1: %s\n", str1)
    fmt.Printf("String 2: %s\n", str2)
    
    // String length (bytes vs runes)
    text := "Hello, 世界"
    fmt.Printf("Text: %s\n", text)
    fmt.Printf("Byte length: %d\n", len(text))
    fmt.Printf("Rune count: %d\n", utf8.RuneCountInString(text))
    
    // String indexing (returns bytes)
    fmt.Printf("First byte: %c (%d)\n", text[0], text[0])
    fmt.Printf("Byte at index 7: %d\n", text[7])  // Part of UTF-8 encoding
    
    // String iteration
    fmt.Println("Byte iteration:")
    for i := 0; i < len(text); i++ {
        fmt.Printf("Index %d: %c (%d)\n", i, text[i], text[i])
    }
    
    fmt.Println("Rune iteration:")
    for i, r := range text {
        fmt.Printf("Index %d: %c (%d)\n", i, r, r)
    }
    
    // String concatenation
    firstName := "John"
    lastName := "Doe"
    fullName := firstName + " " + lastName
    fmt.Printf("Full name: %s\n", fullName)
    
    // String formatting
    age := 30
    formatted := fmt.Sprintf("Name: %s, Age: %d", fullName, age)
    fmt.Println(formatted)
    
    // String comparison
    str3 := "apple"
    str4 := "banana"
    fmt.Printf("'%s' < '%s': %t\n", str3, str4, str3 < str4)
    fmt.Printf("'%s' == '%s': %t\n", str3, str3, str3 == str3)
    
    // String contains
    sentence := "The quick brown fox"
    fmt.Printf("Contains 'quick': %t\n", strings.Contains(sentence, "quick"))
    fmt.Printf("Contains 'slow': %t\n", strings.Contains(sentence, "slow"))
    
    // String prefix and suffix
    filename := "document.pdf"
    fmt.Printf("Starts with 'doc': %t\n", strings.HasPrefix(filename, "doc"))
    fmt.Printf("Ends with '.pdf': %t\n", strings.HasSuffix(filename, ".pdf"))
    
    // String case conversion
    original := "Hello World"
    fmt.Printf("Original: %s\n", original)
    fmt.Printf("Upper: %s\n", strings.ToUpper(original))
    fmt.Printf("Lower: %s\n", strings.ToLower(original))
    fmt.Printf("Title: %s\n", strings.Title(original))
    
    // String trimming
    messy := "  hello world  "
    fmt.Printf("Original: '%s'\n", messy)
    fmt.Printf("Trimmed: '%s'\n", strings.TrimSpace(messy))
    fmt.Printf("Trim left: '%s'\n", strings.TrimLeft(messy, " "))
    fmt.Printf("Trim right: '%s'\n", strings.TrimRight(messy, " "))
    
    // String replacement
    text2 := "Hello World Hello Universe"
    fmt.Printf("Original: %s\n", text2)
    fmt.Printf("Replace first: %s\n", strings.Replace(text2, "Hello", "Hi", 1))
    fmt.Printf("Replace all: %s\n", strings.ReplaceAll(text2, "Hello", "Hi"))
    
    // String splitting and joining
    csv := "apple,banana,cherry,date"
    fruits := strings.Split(csv, ",")
    fmt.Printf("Split CSV: %v\n", fruits)
    
    joined := strings.Join(fruits, " | ")
    fmt.Printf("Joined: %s\n", joined)
    
    // String searching
    haystack := "The quick brown fox jumps over the lazy dog"
    fmt.Printf("Index of 'fox': %d\n", strings.Index(haystack, "fox"))
    fmt.Printf("Last index of 'the': %d\n", strings.LastIndex(haystack, "the"))
    fmt.Printf("Count of 'o': %d\n", strings.Count(haystack, "o"))
    
    // String fields (split on whitespace)
    sentence2 := "  hello   world   go   "
    words := strings.Fields(sentence2)
    fmt.Printf("Fields: %v\n", words)
    
    // String builder for efficient concatenation
    var builder strings.Builder
    for i := 0; i < 5; i++ {
        builder.WriteString(fmt.Sprintf("Line %d\n", i))
    }
    result := builder.String()
    fmt.Printf("Builder result:\n%s", result)
}
```

## 9. Functions

### Function Basics

```go
package main

import "fmt"

// Simple function
func greet() {
    fmt.Println("Hello from function!")
}

// Function with parameters
func add(a, b int) int {
    return a + b
}

// Function with multiple parameters of different types
func printInfo(name string, age int, active bool) {
    fmt.Printf("Name: %s, Age: %d, Active: %t\n", name, age, active)
}

// Function with multiple return values
func divide(a, b int) (int, int) {
    quotient := a / b
    remainder := a % b
    return quotient, remainder
}

// Function with named return values
func calculate(x, y int) (sum, product int) {
    sum = x + y
    product = x * y
    return  // naked return
}

// Function with error return
func safeDivide(a, b int) (int, error) {
    if b == 0 {
        return 0, fmt.Errorf("division by zero")
    }
    return a / b, nil
}

func main() {
    // Call simple function
    greet()
    
    // Call function with parameters
    result := add(5, 3)
    fmt.Printf("5 + 3 = %d\n", result)
    
    // Call function with multiple parameters
    printInfo("Alice", 30, true)
    
    // Call function with multiple returns
    q, r := divide(17, 5)
    fmt.Printf("17 / 5 = %d remainder %d\n", q, r)
    
    // Ignore return value with blank identifier
    sum, _ := calculate(10, 20)
    fmt.Printf("Sum only: %d\n", sum)
    
    // Function with error handling
    result2, err := safeDivide(10, 2)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
    } else {
        fmt.Printf("10 / 2 = %d\n", result2)
    }
    
    result3, err := safeDivide(10, 0)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
    } else {
        fmt.Printf("Result: %d\n", result3)
    }
}
```

### Variadic Functions

```go
package main

import "fmt"

// Variadic function
func sum(numbers ...int) int {
    total := 0
    for _, num := range numbers {
        total += num
    }
    return total
}

// Mixed parameters with variadic
func printMessage(prefix string, messages ...string) {
    for _, msg := range messages {
        fmt.Printf("%s: %s\n", prefix, msg)
    }
}

// Function that accepts any type
func printAll(items ...interface{}) {
    for i, item := range items {
        fmt.Printf("Item %d: %v (type: %T)\n", i, item, item)
    }
}

func main() {
    // Call variadic function
    fmt.Printf("Sum of no numbers: %d\n", sum())
    fmt.Printf("Sum of 1, 2, 3: %d\n", sum(1, 2, 3))
    fmt.Printf("Sum of 1, 2, 3, 4, 5: %d\n", sum(1, 2, 3, 4, 5))
    
    // Pass slice to variadic function
    numbers := []int{10, 20, 30, 40}
    fmt.Printf("Sum of slice: %d\n", sum(numbers...))
    
    // Mixed parameters
    printMessage("INFO", "Server started", "Database connected", "Ready to serve")
    
    // Variadic with different types
    printAll(42, "hello", 3.14, true, []int{1, 2, 3})
}
```

### Function Types and Variables

```go
package main

import "fmt"

// Function type definition
type Operation func(int, int) int

// Functions that match the Operation type
func add(a, b int) int { return a + b }
func multiply(a, b int) int { return a * b }
func subtract(a, b int) int { return a - b }

// Function that takes another function as parameter
func calculate(a, b int, op Operation) int {
    return op(a, b)
}

// Function that returns a function
func makeMultiplier(factor int) func(int) int {
    return func(x int) int {
        return x * factor
    }
}

// Higher-order function for slice operations
func applyToSlice(slice []int, fn func(int) int) []int {
    result := make([]int, len(slice))
    for i, v := range slice {
        result[i] = fn(v)
    }
    return result
}

func main() {
    // Function variables
    var op Operation
    
    op = add
    fmt.Printf("Add: %d\n", op(5, 3))
    
    op = multiply
    fmt.Printf("Multiply: %d\n", op(5, 3))
    
    // Function as parameter
    fmt.Printf("Calculate with add: %d\n", calculate(10, 5, add))
    fmt.Printf("Calculate with subtract: %d\n", calculate(10, 5, subtract))
    
    // Anonymous function
    fmt.Printf("Calculate with anonymous: %d\n", 
        calculate(10, 5, func(a, b int) int { return a * a + b * b }))
    
    // Function returning function
    double := makeMultiplier(2)
    triple := makeMultiplier(3)
    
    fmt.Printf("Double 7: %d\n", double(7))
    fmt.Printf("Triple 7: %d\n", triple(7))
    
    // Higher-order function example
    numbers := []int{1, 2, 3, 4, 5}
    
    // Square all numbers
    squared := applyToSlice(numbers, func(x int) int { return x * x })
    fmt.Printf("Original: %v\n", numbers)
    fmt.Printf("Squared: %v\n", squared)
    
    // Double all numbers using previously created function
    doubled := applyToSlice(numbers, double)
    fmt.Printf("Doubled: %v\n", doubled)
    
    // Array of functions
    operations := []Operation{add, subtract, multiply}
    operationNames := []string{"add", "subtract", "multiply"}
    
    for i, op := range operations {
        result := op(12, 4)
        fmt.Printf("%s(12, 4) = %d\n", operationNames[i], result)
    }
}
```

### Closures

```go
package main

import "fmt"

// Closure that captures variables
func makeCounter() func() int {
    count := 0
    return func() int {
        count++
        return count
    }
}

// Closure with parameters
func makeAdder(base int) func(int) int {
    return func(x int) int {
        return base + x
    }
}

// Multiple closures sharing state
func makeCalculator() (func(int), func() int, func()) {
    total := 0
    
    add := func(x int) {
        total += x
    }
    
    getTotal := func() int {
        return total
    }
    
    reset := func() {
        total = 0
    }
    
    return add, getTotal, reset
}

func main() {
    // Basic closure
    counter1 := makeCounter()
    counter2 := makeCounter()
    
    fmt.Printf("Counter1: %d\n", counter1())  // 1
    fmt.Printf("Counter1: %d\n", counter1())  // 2
    fmt.Printf("Counter2: %d\n", counter2())  // 1 (independent)
    fmt.Printf("Counter1: %d\n", counter1())  // 3
    
    // Closure with parameters
    add5 := makeAdder(5)
    add10 := makeAdder(10)
    
    fmt.Printf("add5(3) = %d\n", add5(3))    // 8
    fmt.Printf("add10(3) = %d\n", add10(3))  // 13
    
    // Multiple closures sharing state
    add, getTotal, reset := makeCalculator()
    
    add(10)
    add(20)
    fmt.Printf("Total: %d\n", getTotal())  // 30
    
    add(5)
    fmt.Printf("Total: %d\n", getTotal())  // 35
    
    reset()
    fmt.Printf("Total after reset: %d\n", getTotal())  // 0
    
    // Closure in loop (common pitfall)
    fmt.Println("Closure in loop (correct way):")
    funcs := make([]func(), 3)
    
    for i := 0; i < 3; i++ {
        i := i  // Create new variable in each iteration
        funcs[i] = func() {
            fmt.Printf("Function %d\n", i)
        }
    }
    
    for _, f := range funcs {
        f()
    }
    
    // Alternative: pass value to closure
    fmt.Println("Using parameter:")
    funcs2 := make([]func(), 3)
    
    for i := 0; i < 3; i++ {
        funcs2[i] = func(val int) func() {
            return func() {
                fmt.Printf("Function %d\n", val)
            }
        }(i)
    }
    
    for _, f := range funcs2 {
        f()
    }
}
```

## 10. Methods

### Method Basics

```go
package main

import (
    "fmt"
    "math"
)

// Struct types for methods
type Rectangle struct {
    Width, Height float64
}

type Circle struct {
    Radius float64
}

// Methods on Rectangle
func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}

func (r Rectangle) Perimeter() float64 {
    return 2 * (r.Width + r.Height)
}

// Method with pointer receiver (can modify the struct)
func (r *Rectangle) Scale(factor float64) {
    r.Width *= factor
    r.Height *= factor
}

// Method with value receiver (cannot modify the struct)
func (r Rectangle) String() string {
    return fmt.Sprintf("Rectangle{Width: %.2f, Height: %.2f}", r.Width, r.Height)
}

// Methods on Circle
func (c Circle) Area() float64 {
    return math.Pi * c.Radius * c.Radius
}

func (c Circle) Circumference() float64 {
    return 2 * math.Pi * c.Radius
}

func (c *Circle) Grow(factor float64) {
    c.Radius *= factor
}

func main() {
    // Create rectangles
    rect1 := Rectangle{Width: 10, Height: 5}
    rect2 := &Rectangle{Width: 8, Height: 6}
    
    // Call methods with value receiver
    fmt.Printf("Rectangle 1: %s\n", rect1.String())
    fmt.Printf("Area: %.2f\n", rect1.Area())
    fmt.Printf("Perimeter: %.2f\n", rect1.Perimeter())
    
    // Call method with pointer receiver
    fmt.Printf("Before scaling: %s\n", rect1.String())
    rect1.Scale(2.0)  // Go automatically takes address
    fmt.Printf("After scaling by 2: %s\n", rect1.String())
    
    // Method call on pointer
    fmt.Printf("Rectangle 2: %s\n", rect2.String())  // Go automatically dereferences
    rect2.Scale(0.5)
    fmt.Printf("After scaling by 0.5: %s\n", rect2.String())
    
    // Circle methods
    circle := Circle{Radius: 5}
    fmt.Printf("Circle radius: %.2f\n", circle.Radius)
    fmt.Printf("Area: %.2f\n", circle.Area())
    fmt.Printf("Circumference: %.2f\n", circle.Circumference())
    
    circle.Grow(2)
    fmt.Printf("After growing by 2: radius = %.2f\n", circle.Radius)
}
```

### Methods on Different Types

```go
package main

import (
    "fmt"
    "strings"
)

// Method on built-in type alias
type MyString string

func (s MyString) ToUpper() string {
    return strings.ToUpper(string(s))
}

func (s MyString) Reverse() string {
    runes := []rune(s)
    for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
        runes[i], runes[j] = runes[j], runes[i]
    }
    return string(runes)
}

// Method on slice type
type IntSlice []int

func (s IntSlice) Sum() int {
    total := 0
    for _, v := range s {
        total += v
    }
    return total
}

func (s IntSlice) Average() float64 {
    if len(s) == 0 {
        return 0
    }
    return float64(s.Sum()) / float64(len(s))
}

func (s *IntSlice) Append(values ...int) {
    *s = append(*s, values...)
}

// Method on map type
type Counter map[string]int

func (c Counter) Increment(key string) {
    c[key]++
}

func (c Counter) Total() int {
    total := 0
    for _, count := range c {
        total += count
    }
    return total
}

func (c Counter) Most() (string, int) {
    var maxKey string
    var maxCount int
    
    for key, count := range c {
        if count > maxCount {
            maxKey = key
            maxCount = count
        }
    }
    
    return maxKey, maxCount
}

// Method on function type
type Handler func(string) string

func (h Handler) Handle(input string) string {
    return h(input)
}

func (h Handler) Chain(other Handler) Handler {
    return func(input string) string {
        return other(h(input))
    }
}

func main() {
    // Methods on string type
    text := MyString("hello world")
    fmt.Printf("Original: %s\n", text)
    fmt.Printf("Upper: %s\n", text.ToUpper())
    fmt.Printf("Reverse: %s\n", text.Reverse())
    
    // Methods on slice type
    numbers := IntSlice{1, 2, 3, 4, 5}
    fmt.Printf("Numbers: %v\n", numbers)
    fmt.Printf("Sum: %d\n", numbers.Sum())
    fmt.Printf("Average: %.2f\n", numbers.Average())
    
    numbers.Append(6, 7, 8)
    fmt.Printf("After append: %v\n", numbers)
    fmt.Printf("New average: %.2f\n", numbers.Average())
    
    // Methods on map type
    counter := make(Counter)
    counter.Increment("apple")
    counter.Increment("banana")
    counter.Increment("apple")
    counter.Increment("cherry")
    counter.Increment("apple")
    
    fmt.Printf("Counter: %v\n", counter)
    fmt.Printf("Total: %d\n", counter.Total())
    
    most, count := counter.Most()
    fmt.Printf("Most frequent: %s (%d times)\n", most, count)
    
    // Methods on function type
    upper := Handler(strings.ToUpper)
    trim := Handler(strings.TrimSpace)
    
    input := "  hello world  "
    fmt.Printf("Original: '%s'\n", input)
    fmt.Printf("Upper: '%s'\n", upper.Handle(input))
    fmt.Printf("Trim: '%s'\n", trim.Handle(input))
    
    // Chain handlers
    combined := trim.Chain(upper)
    fmt.Printf("Trim then Upper: '%s'\n", combined.Handle(input))
}
```

### Method Sets and Receivers

```go
package main

import "fmt"

type Person struct {
    Name string
    Age  int
}

// Value receiver methods
func (p Person) GetName() string {
    return p.Name
}

func (p Person) IsAdult() bool {
    return p.Age >= 18
}

// Pointer receiver methods
func (p *Person) SetName(name string) {
    p.Name = name
}

func (p *Person) Birthday() {
    p.Age++
}

// Method that works with both value and pointer
func (p Person) String() string {
    return fmt.Sprintf("Person{Name: %s, Age: %d}", p.Name, p.Age)
}

// Demonstrate method sets
func demonstrateMethodSets() {
    fmt.Println("=== Method Sets Demo ===")
    
    // Value type can call both value and pointer receiver methods
    person1 := Person{Name: "Alice", Age: 25}
    fmt.Printf("person1: %s\n", person1.String())
    fmt.Printf("Name: %s\n", person1.GetName())
    fmt.Printf("Is adult: %t\n", person1.IsAdult())
    
    // Go automatically takes address for pointer receiver methods
    person1.SetName("Alice Smith")
    person1.Birthday()
    fmt.Printf("After updates: %s\n", person1.String())
    
    // Pointer type can call both value and pointer receiver methods
    person2 := &Person{Name: "Bob", Age: 17}
    fmt.Printf("person2: %s\n", person2.String())  // Go automatically dereferences
    fmt.Printf("Name: %s\n", person2.GetName())
    fmt.Printf("Is adult: %t\n", person2.IsAdult())
    
    person2.SetName("Robert")
    person2.Birthday()
    fmt.Printf("After updates: %s\n", person2.String())
}

// Interface to demonstrate method sets with interfaces
type Namer interface {
    GetName() string
    SetName(string)
}

type Stringer interface {
    String() string
}

func testInterfaces() {
    fmt.Println("\n=== Interface Method Sets ===")
    
    person := Person{Name: "Charlie", Age: 30}
    
    // This works because Person has GetName() method
    var s Stringer = person
    fmt.Printf("Via Stringer interface: %s\n", s.String())
    
    // This works because *Person satisfies Namer interface
    var n Namer = &person  // Must use pointer because SetName has pointer receiver
    fmt.Printf("Original name: %s\n", n.GetName())
    n.SetName("Charles")
    fmt.Printf("Updated name: %s\n", n.GetName())
    
    // This would NOT compile:
    // var n2 Namer = person  // Person doesn't satisfy Namer (missing SetName)
}

// Example of method promotion with embedded types
type Employee struct {
    Person  // Embedded type
    ID      int
    Salary  float64
}

// Method specific to Employee
func (e Employee) GetSalary() float64 {
    return e.Salary
}

// Method that overrides embedded method
func (e Employee) String() string {
    return fmt.Sprintf("Employee{ID: %d, %s, Salary: %.2f}", 
        e.ID, e.Person.String(), e.Salary)
}

func demonstrateEmbedding() {
    fmt.Println("\n=== Method Promotion ===")
    
    emp := Employee{
        Person: Person{Name: "David", Age: 28},
        ID:     12345,
        Salary: 75000.00,
    }
    
    // Can call methods from embedded Person
    fmt.Printf("Employee name: %s\n", emp.GetName())  // Promoted from Person
    fmt.Printf("Is adult: %t\n", emp.IsAdult())       // Promoted from Person
    
    // Can call Employee-specific methods
    fmt.Printf("Salary: %.2f\n", emp.GetSalary())
    
    // Employee's String method overrides Person's
    fmt.Printf("Employee: %s\n", emp.String())
    
    // Can still access embedded type's method explicitly
    fmt.Printf("Person part: %s\n", emp.Person.String())
    
    // Pointer receiver methods work too
    emp.SetName("Dave")
    emp.Birthday()
    fmt.Printf("After updates: %s\n", emp.String())
}

func main() {
    demonstrateMethodSets()
    testInterfaces()
    demonstrateEmbedding()
}
```

## 11. Structs

### Struct Basics

```go
package main

import "fmt"

// Basic struct definition
type Person struct {
    FirstName string
    LastName  string
    Age       int
    Email     string
}

// Struct with different field types
type Product struct {
    ID          int
    Name        string
    Price       float64
    InStock     bool
    Categories  []string
    Attributes  map[string]string
}

// Empty struct
type Empty struct{}

func main() {
    // Struct literal initialization
    p1 := Person{
        FirstName: "John",
        LastName:  "Doe",
        Age:       30,
        Email:     "john@example.com",
    }
    
    // Positional initialization (not recommended)
    p2 := Person{"Jane", "Smith", 25, "jane@example.com"}
    
    // Partial initialization
    p3 := Person{
        FirstName: "Bob",
        Age:       35,
        // LastName and Email will be zero values
    }
    
    // Zero value struct
    var p4 Person
    
    fmt.Printf("p1: %+v\n", p1)
    fmt.Printf("p2: %+v\n", p2)
    fmt.Printf("p3: %+v\n", p3)
    fmt.Printf("p4 (zero): %+v\n", p4)
    
    // Accessing and modifying fields
    fmt.Printf("p1 name: %s %s\n", p1.FirstName, p1.LastName)
    p1.Age = 31
    p1.Email = "john.doe@example.com"
    fmt.Printf("p1 after update: %+v\n", p1)
    
    // Struct with complex fields
    product := Product{
        ID:      101,
        Name:    "Laptop",
        Price:   999.99,
        InStock: true,
        Categories: []string{"Electronics", "Computers"},
        Attributes: map[string]string{
            "Brand":  "TechCorp",
            "Model":  "Pro-2023",
            "Color":  "Silver",
        },
    }
    
    fmt.Printf("Product: %+v\n", product)
    fmt.Printf("Product categories: %v\n", product.Categories)
    fmt.Printf("Product brand: %s\n", product.Attributes["Brand"])
    
    // Struct comparison
    p5 := Person{FirstName: "Alice", LastName: "Johnson", Age: 28, Email: "alice@example.com"}
    p6 := Person{FirstName: "Alice", LastName: "Johnson", Age: 28, Email: "alice@example.com"}
    p7 := Person{FirstName: "Alice", LastName: "Johnson", Age: 29, Email: "alice@example.com"}
    
    fmt.Printf("p5 == p6: %t\n", p5 == p6)  // true
    fmt.Printf("p5 == p7: %t\n", p5 == p7)  // false
    
    // Anonymous struct
    config := struct {
        Host string
        Port int
        SSL  bool
    }{
        Host: "localhost",
        Port: 8080,
        SSL:  false,
    }
    
    fmt.Printf("Config: %+v\n", config)
    
    // Empty struct usage (as signal or set member)
    var signal Empty
    fmt.Printf("Empty struct size: %d bytes\n", len(fmt.Sprintf("%v", signal)))
    
    // Set using empty struct
    set := make(map[string]Empty)
    set["apple"] = Empty{}
    set["banana"] = Empty{}
    
    if _, exists := set["apple"]; exists {
        fmt.Println("Apple is in set")
    }
}
```

### Nested and Embedded Structs

```go
package main

import "fmt"

// Address struct
type Address struct {
    Street   string
    City     string
    State    string
    ZipCode  string
    Country  string
}

// Person with nested Address
type Person struct {
    Name    string
    Age     int
    Address Address  // Nested struct
}

// Contact information
type ContactInfo struct {
    Email string
    Phone string
}

// Employee with embedded structs
type Employee struct {
    Person      // Embedded struct (anonymous field)
    ContactInfo // Embedded struct
    ID          int
    Department  string
    Salary      float64
}

// Method on Address
func (a Address) String() string {
    return fmt.Sprintf("%s, %s, %s %s, %s", 
        a.Street, a.City, a.State, a.ZipCode, a.Country)
}

// Method on Person
func (p Person) FullInfo() string {
    return fmt.Sprintf("%s (%d years old) - %s", 
        p.Name, p.Age, p.Address.String())
}

// Method on Employee
func (e Employee) DisplayInfo() string {
    return fmt.Sprintf("Employee ID: %d\nName: %s\nDepartment: %s\nSalary: $%.2f\nEmail: %s\nPhone: %s\nAddress: %s",
        e.ID, e.Name, e.Department, e.Salary, e.Email, e.Phone, e.Address.String())
}

func main() {
    // Nested struct
    person := Person{
        Name: "John Doe",
        Age:  30,
        Address: Address{
            Street:  "123 Main St",
            City:    "Anytown",
            State:   "CA",
            ZipCode: "12345",
            Country: "USA",
        },
    }
    
    fmt.Println("=== Nested Struct ===")
    fmt.Printf("Person: %+v\n", person)
    fmt.Printf("Address: %s\n", person.Address.String())
    fmt.Printf("Full info: %s\n", person.FullInfo())
    
    // Embedded structs
    employee := Employee{
        Person: Person{
            Name: "Alice Smith",
            Age:  28,
            Address: Address{
                Street:  "456 Oak Ave",
                City:    "Springfield",
                State:   "NY",
                ZipCode: "67890",
                Country: "USA",
            },
        },
        ContactInfo: ContactInfo{
            Email: "alice.smith@company.com",
            Phone: "+1-555-0123",
        },
        ID:         12345,
        Department: "Engineering",
        Salary:     85000.00,
    }
    
    fmt.Println("\n=== Embedded Struct ===")
    
    // Access embedded fields directly
    fmt.Printf("Employee name: %s\n", employee.Name)        // From Person
    fmt.Printf("Employee email: %s\n", employee.Email)      // From ContactInfo
    fmt.Printf("Employee city: %s\n", employee.Address.City) // From Person.Address
    
    // Access embedded fields explicitly
    fmt.Printf("Person name: %s\n", employee.Person.Name)
    fmt.Printf("Contact email: %s\n", employee.ContactInfo.Email)
    
    // Call promoted methods
    fmt.Printf("Employee full info: %s\n", employee.FullInfo()) // From Person
    
    // Call Employee method
    fmt.Println("\nEmployee Details:")
    fmt.Println(employee.DisplayInfo())
    
    // Struct initialization with embedded types
    emp2 := Employee{
        Person: Person{
            Name: "Bob Johnson",
            Age:  35,
        },
        ContactInfo: ContactInfo{
            Email: "bob@company.com",
        },
        ID:         67890,
        Department: "Marketing",
    }
    
    // Modify embedded fields
    emp2.Age = 36  // Directly access embedded field
    emp2.Address.City = "Boston"
    emp2.Phone = "+1-555-0456"
    
    fmt.Printf("\nEmployee 2: %+v\n", emp2)
}
```

### Anonymous Structs and Struct Tags

```go
package main

import (
    "encoding/json"
    "fmt"
    "reflect"
)

// Struct with tags for JSON marshaling
type User struct {
    ID       int    `json:"id"`
    Name     string `json:"name"`
    Email    string `json:"email,omitempty"`
    Password string `json:"-"`              // Never serialize
    IsActive bool   `json:"is_active"`
    Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Struct with multiple tags
type Product struct {
    ID          int     `json:"id" xml:"id" db:"product_id"`
    Name        string  `json:"name" xml:"name" db:"product_name"`
    Price       float64 `json:"price" xml:"price" db:"price"`
    Description string  `json:"description,omitempty" xml:"description,omitempty" db:"description"`
}

func main() {
    // Anonymous struct for one-time use
    config := struct {
        Host     string
        Port     int
        Debug    bool
        Features []string
    }{
        Host:     "localhost",
        Port:     8080,
        Debug:    true,
        Features: []string{"auth", "logging", "metrics"},
    }
    
    fmt.Println("=== Anonymous Struct ===")
    fmt.Printf("Config: %+v\n", config)
    
    // Array of anonymous structs
    servers := []struct {
        Name string
        URL  string
        Live bool
    }{
        {"Production", "https://api.prod.com", true},
        {"Staging", "https://api.staging.com", true},
        {"Development", "https://api.dev.com", false},
    }
    
    fmt.Println("\nServers:")
    for _, server := range servers {
        status := "offline"
        if server.Live {
            status = "online"
        }
        fmt.Printf("- %s (%s): %s\n", server.Name, server.URL, status)
    }
    
    // Working with struct tags
    user := User{
        ID:       1,
        Name:     "Alice Johnson",
        Email:    "alice@example.com",
        Password: "secret123",
        IsActive: true,
        Metadata: map[string]interface{}{
            "role":        "admin",
            "last_login":  "2023-12-01",
            "preferences": map[string]bool{"darkMode": true},
        },
    }
    
    fmt.Println("\n=== Struct Tags and JSON ===")
    
    // Marshal to JSON (Password will be omitted due to "-" tag)
    jsonData, err := json.MarshalIndent(user, "", "  ")
    if err != nil {
        fmt.Printf("Error marshaling: %v\n", err)
        return
    }
    
    fmt.Printf("User as JSON:\n%s\n", jsonData)
    
    // Unmarshal from JSON
    jsonStr := `{
        "id": 2,
        "name": "Bob Smith", 
        "email": "bob@example.com",
        "is_active": false
    }`
    
    var newUser User
    err = json.Unmarshal([]byte(jsonStr), &newUser)
    if err != nil {
        fmt.Printf("Error unmarshaling: %v\n", err)
        return
    }
    
    fmt.Printf("Unmarshaled user: %+v\n", newUser)
    
    // Inspecting struct tags using reflection
    fmt.Println("\n=== Struct Tag Inspection ===")
    userType := reflect.TypeOf(User{})
    
    for i := 0; i < userType.NumField(); i++ {
        field := userType.Field(i)
        jsonTag := field.Tag.Get("json")
        fmt.Printf("Field: %s, JSON tag: '%s'\n", field.Name, jsonTag)
    }
    
    // Anonymous struct with tags for response
    response := struct {
        Success bool        `json:"success"`
        Message string      `json:"message"`
        Data    interface{} `json:"data,omitempty"`
        Error   string      `json:"error,omitempty"`
    }{
        Success: true,
        Message: "Operation completed successfully",
        Data:    user,
    }
    
    responseJSON, _ := json.MarshalIndent(response, "", "  ")
    fmt.Printf("\nAPI Response:\n%s\n", responseJSON)
    
    // Struct with validation tags (conceptual)
    type FormData struct {
        Username string `json:"username" validate:"required,min=3,max=20"`
        Email    string `json:"email" validate:"required,email"`
        Age      int    `json:"age" validate:"required,min=18,max=120"`
    }
    
    form := FormData{
        Username: "alice",
        Email:    "alice@example.com",
        Age:      25,
    }
    
    fmt.Println("\n=== Validation Tags (Example) ===")
    formType := reflect.TypeOf(form)
    for i := 0; i < formType.NumField(); i++ {
        field := formType.Field(i)
        validateTag := field.Tag.Get("validate")
        fmt.Printf("Field: %s, Validation: '%s'\n", field.Name, validateTag)
    }
}
```

## 12. Interfaces

### Interface Basics

```go
package main

import (
    "fmt"
    "math"
)

// Shape interface
type Shape interface {
    Area() float64
    Perimeter() float64
}

// Drawable interface
type Drawable interface {
    Draw() string
}

// Combined interface
type DrawableShape interface {
    Shape
    Drawable
}

// Rectangle implements Shape and Drawable
type Rectangle struct {
    Width, Height float64
}

func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}

func (r Rectangle) Perimeter() float64 {
    return 2 * (r.Width + r.Height)
}

func (r Rectangle) Draw() string {
    return fmt.Sprintf("Drawing rectangle %.1fx%.1f", r.Width, r.Height)
}

// Circle implements Shape and Drawable
type Circle struct {
    Radius float64
}

func (c Circle) Area() float64 {
    return math.Pi * c.Radius * c.Radius
}

func (c Circle) Perimeter() float64 {
    return 2 * math.Pi * c.Radius
}

func (c Circle) Draw() string {
    return fmt.Sprintf("Drawing circle with radius %.1f", c.Radius)
}

// Triangle implements only Shape
type Triangle struct {
    Base, Height float64
}

func (t Triangle) Area() float64 {
    return 0.5 * t.Base * t.Height
}

func (t Triangle) Perimeter() float64 {
    // Simplified - assumes equilateral triangle
    return 3 * t.Base
}

// Functions that work with interfaces
func printShapeInfo(s Shape) {
    fmt.Printf("Area: %.2f, Perimeter: %.2f\n", s.Area(), s.Perimeter())
}

func drawShape(d Drawable) {
    fmt.Println(d.Draw())
}

func processDrawableShape(ds DrawableShape) {
    fmt.Printf("Processing: %s\n", ds.Draw())
    fmt.Printf("Area: %.2f\n", ds.Area())
}

func main() {
    // Create shapes
    rect := Rectangle{Width: 10, Height: 5}
    circle := Circle{Radius: 3}
    triangle := Triangle{Base: 6, Height: 4}
    
    // Use shapes through Shape interface
    shapes := []Shape{rect, circle, triangle}
    
    fmt.Println("=== Shape Interface ===")
    for i, shape := range shapes {
        fmt.Printf("Shape %d: ", i+1)
        printShapeInfo(shape)
    }
    
    // Use through Drawable interface
    fmt.Println("\n=== Drawable Interface ===")
    drawables := []Drawable{rect, circle}
    for _, drawable := range drawables {
        drawShape(drawable)
    }
    
    // Use through combined interface
    fmt.Println("\n=== DrawableShape Interface ===")
    drawableShapes := []DrawableShape{rect, circle}
    for _, ds := range drawableShapes {
        processDrawableShape(ds)
        fmt.Println()
    }
    
    // Interface variables
    fmt.Println("=== Interface Variables ===")
    var s Shape
    fmt.Printf("Zero interface: %v\n", s)
    
    s = rect
    fmt.Printf("Rectangle area: %.2f\n", s.Area())
    
    s = circle
    fmt.Printf("Circle area: %.2f\n", s.Area())
    
    // Type assertion
    fmt.Println("\n=== Type Assertions ===")
    if r, ok := s.(Rectangle); ok {
        fmt.Printf("s is a Rectangle: %+v\n", r)
    } else {
        fmt.Println("s is not a Rectangle")
    }
    
    if c, ok := s.(Circle); ok {
        fmt.Printf("s is a Circle: %+v\n", c)
    } else {
        fmt.Println("s is not a Circle")
    }
    
    // Type switch
    fmt.Println("\n=== Type Switch ===")
    for _, shape := range shapes {
        switch v := shape.(type) {
        case Rectangle:
            fmt.Printf("Rectangle with width %.1f and height %.1f\n", v.Width, v.Height)
        case Circle:
            fmt.Printf("Circle with radius %.1f\n", v.Radius)
        case Triangle:
            fmt.Printf("Triangle with base %.1f and height %.1f\n", v.Base, v.Height)
        default:
            fmt.Printf("Unknown shape type: %T\n", v)
        }
    }
}
```

### Empty Interface and Type Assertions

```go
package main

import "fmt"

// Function that accepts any type
func describe(i interface{}) {
    fmt.Printf("Value: %v, Type: %T\n", i, i)
}

// Function that processes different types
func processValue(value interface{}) {
    switch v := value.(type) {
    case nil:
        fmt.Println("Value is nil")
    case bool:
        if v {
            fmt.Println("Boolean value is true")
        } else {
            fmt.Println("Boolean value is false")
        }
    case int:
        fmt.Printf("Integer value: %d\n", v)
        if v > 0 {
            fmt.Println("  - Positive number")
        } else if v < 0 {
            fmt.Println("  - Negative number")
        } else {
            fmt.Println("  - Zero")
        }
    case float64:
        fmt.Printf("Float value: %.2f\n", v)
    case string:
        fmt.Printf("String value: '%s' (length: %d)\n", v, len(v))
    case []int:
        fmt.Printf("Integer slice: %v (length: %d)\n", v, len(v))
    case map[string]int:
        fmt.Printf("String-to-int map: %v\n", v)
    default:
        fmt.Printf("Unknown type: %T with value %v\n", v, v)
    }
}

// Container using empty interface
type Container struct {
    items []interface{}
}

func (c *Container) Add(item interface{}) {
    c.items = append(c.items, item)
}

func (c *Container) Get(index int) interface{} {
    if index >= 0 && index < len(c.items) {
        return c.items[index]
    }
    return nil
}

func (c *Container) Size() int {
    return len(c.items)
}

func (c *Container) GetAll() []interface{} {
    return c.items
}

// Generic-like function using interface{}
func findInSlice(slice []interface{}, target interface{}) int {
    for i, item := range slice {
        if item == target {
            return i
        }
    }
    return -1
}

func main() {
    fmt.Println("=== Empty Interface ===")
    
    // Empty interface can hold any value
    var anything interface{}
    
    anything = 42
    describe(anything)
    
    anything = "hello"
    describe(anything)
    
    anything = []int{1, 2, 3}
    describe(anything)
    
    anything = map[string]int{"a": 1, "b": 2}
    describe(anything)
    
    // Array of mixed types
    fmt.Println("\n=== Mixed Types ===")
    mixed := []interface{}{
        42,
        "hello",
        3.14,
        true,
        []int{1, 2, 3},
        map[string]int{"key": 100},
        nil,
    }
    
    for i, value := range mixed {
        fmt.Printf("Item %d: ", i)
        processValue(value)
    }
    
    // Type assertions
    fmt.Println("\n=== Type Assertions ===")
    var x interface{} = "hello world"
    
    // Safe type assertion
    if str, ok := x.(string); ok {
        fmt.Printf("x is a string: '%s'\n", str)
        fmt.Printf("Length: %d\n", len(str))
    } else {
        fmt.Println("x is not a string")
    }
    
    // Unsafe type assertion (would panic if wrong)
    str := x.(string)
    fmt.Printf("Direct assertion: '%s'\n", str)
    
    // This would panic:
    // num := x.(int)  // panic: interface conversion
    
    // Safe way to handle potential panic
    defer func() {
        if r := recover(); r != nil {
            fmt.Printf("Recovered from panic: %v\n", r)
        }
    }()
    
    // Container example
    fmt.Println("\n=== Container Example ===")
    container := &Container{}
    
    container.Add(42)
    container.Add("hello")
    container.Add(3.14)
    container.Add([]int{1, 2, 3})
    
    fmt.Printf("Container size: %d\n", container.Size())
    
    for i := 0; i < container.Size(); i++ {
        item := container.Get(i)
        fmt.Printf("Item %d: ", i)
        describe(item)
    }
    
    // Find in slice
    fmt.Println("\n=== Find in Slice ===")
    items := []interface{}{1, "hello", 3.14, true}
    
    index := findInSlice(items, "hello")
    fmt.Printf("Index of 'hello': %d\n", index)
    
    index = findInSlice(items, 42)
    fmt.Printf("Index of 42: %d\n", index)
    
    // Working with interfaces and methods
    fmt.Println("\n=== Interface Methods ===")
    type Stringer interface {
        String() string
    }
    
    type Person struct {
        Name string
        Age  int
    }
    
    func (p Person) String() string {
        return fmt.Sprintf("Person{Name: %s, Age: %d}", p.Name, p.Age)
    }
    
    var s Stringer = Person{Name: "Alice", Age: 30}
    fmt.Printf("Stringer: %s\n", s.String())
    
    // Check if interface{} implements Stringer
    var unknown interface{} = Person{Name: "Bob", Age: 25}
    if stringer, ok := unknown.(Stringer); ok {
        fmt.Printf("Unknown implements Stringer: %s\n", stringer.String())
    }
}
```

## 13. Pointers

### Pointer Basics

```go
package main

import "fmt"

func main() {
    // Basic pointer operations
    var x int = 42
    var p *int = &x  // p points to x
    
    fmt.Printf("Value of x: %d\n", x)
    fmt.Printf("Address of x: %p\n", &x)
    fmt.Printf("Value of p (address): %p\n", p)
    fmt.Printf("Value pointed to by p: %d\n", *p)
    
    // Modify value through pointer
    *p = 100
    fmt.Printf("After *p = 100, x = %d\n", x)
    
    // Zero value of pointer is nil
    var nilPtr *int
    fmt.Printf("Nil pointer: %v\n", nilPtr)
    
    if nilPtr == nil {
        fmt.Println("Pointer is nil")
    }
    
    // Pointer to different types
    str := "Hello"
    strPtr := &str
    fmt.Printf("String value: %s, via pointer: %s\n", str, *strPtr)
    
    // Array and pointer
    arr := [3]int{1, 2, 3}
    arrPtr := &arr
    fmt.Printf("Array: %v\n", arr)
    fmt.Printf("Array via pointer: %v\n", *arrPtr)
    fmt.Printf("First element via pointer: %d\n", (*arrPtr)[0])
    
    // Pointer arithmetic is not allowed in Go
    // p++  // This would cause a compile error
    
    // Multiple pointers
    y := 50
    p1 := &y
    p2 := &y
    
    fmt.Printf("p1 == p2: %t (same address)\n", p1 == p2)
    fmt.Printf("*p1 == *p2: %t (same value)\n", *p1 == *p2)
}
```

### Pointers with Functions

```go
package main

import "fmt"

// Function with value parameter (copy)
func modifyValue(x int) {
    x = 100
    fmt.Printf("Inside modifyValue: x = %d\n", x)
}

// Function with pointer parameter (reference)
func modifyPointer(x *int) {
    *x = 100
    fmt.Printf("Inside modifyPointer: *x = %d\n", *x)
}

// Function returning pointer
func createInt(value int) *int {
    x := value  // Local variable
    return &x   // Safe to return address of local variable in Go
}

// Function with multiple pointer parameters
func swap(a, b *int) {
    *a, *b = *b, *a
}

// Function that returns multiple pointers
func createPair(x, y int) (*int, *int) {
    return &x, &y
}

// Pointer to struct
type Person struct {
    Name string
    Age  int
}

func updatePerson(p *Person, name string, age int) {
    p.Name = name
    p.Age = age
}

func (p *Person) Birthday() {
    p.Age++
}

func main() {
    // Value vs pointer parameters
    num := 50
    fmt.Printf("Original: %d\n", num)
    
    modifyValue(num)
    fmt.Printf("After modifyValue: %d\n", num)  // Unchanged
    
    modifyPointer(&num)
    fmt.Printf("After modifyPointer: %d\n", num)  // Changed
    
    // Function returning pointer
    ptr := createInt(42)
    fmt.Printf("Created int via pointer: %d\n", *ptr)
    
    // Swap function
    a, b := 10, 20
    fmt.Printf("Before swap: a=%d, b=%d\n", a, b)
    swap(&a, &b)
    fmt.Printf("After swap: a=%d, b=%d\n", a, b)
    
    // Multiple pointers from function
    p1, p2 := createPair(100, 200)
    fmt.Printf("Pair: *p1=%d, *p2=%d\n", *p1, *p2)
    
    // Pointer to struct
    person := Person{Name: "Alice", Age: 25}
    fmt.Printf("Original person: %+v\n", person)
    
    updatePerson(&person, "Alice Smith", 26)
    fmt.Printf("After update: %+v\n", person)
    
    // Method with pointer receiver
    person.Birthday()
    fmt.Printf("After birthday: %+v\n", person)
    
    // Slice of pointers
    numbers := []int{1, 2, 3, 4, 5}
    var pointers []*int
    
    for i := range numbers {
        pointers = append(pointers, &numbers[i])
    }
    
    fmt.Printf("Original slice: %v\n", numbers)
    fmt.Print("Values via pointers: ")
    for _, ptr := range pointers {
        fmt.Printf("%d ", *ptr)
    }
    fmt.Println()
    
    // Modify through pointers
    for _, ptr := range pointers {
        *ptr *= 2
    }
    fmt.Printf("After modification: %v\n", numbers)
}
```

### Pointer to Pointer

```go
package main

import "fmt"

func modifyPointer(pp **int, newValue int) {
    **pp = newValue
}

func changePointer(pp **int, newTarget *int) {
    *pp = newTarget
}

func main() {
    // Pointer to pointer
    x := 42
    p := &x      // Pointer to int
    pp := &p     // Pointer to pointer to int
    
    fmt.Printf("Value of x: %d\n", x)
    fmt.Printf("Value via p: %d\n", *p)
    fmt.Printf("Value via pp: %d\n", **pp)
    
    fmt.Printf("Address of x: %p\n", &x)
    fmt.Printf("Value of p (address of x): %p\n", p)
    fmt.Printf("Address of p: %p\n", &p)
    fmt.Printf("Value of pp (address of p): %p\n", pp)
    
    // Modify value through double pointer
    **pp = 100
    fmt.Printf("After **pp = 100: x = %d\n", x)
    
    // Function with double pointer
    modifyPointer(&p, 200)
    fmt.Printf("After modifyPointer: x = %d\n", x)
    
    // Change what pointer points to
    y := 300
    changePointer(&p, &y)
    fmt.Printf("After changePointer: *p = %d (now points to y)\n", *p)
    fmt.Printf("x is still: %d\n", x)
    
    // Array of pointers to pointers
    a, b, c := 1, 2, 3
    pa, pb, pc := &a, &b, &c
    
    arrayOfPointers := []*int{pa, pb, pc}
    arrayOfPointerPointers := [3]**int{&pa, &pb, &pc}
    
    fmt.Printf("Values via array of pointers: ")
    for _, ptr := range arrayOfPointers {
        fmt.Printf("%d ", *ptr)
    }
    fmt.Println()
    
    fmt.Printf("Values via array of pointer pointers: ")
    for _, pp := range arrayOfPointerPointers {
        fmt.Printf("%d ", **pp)
    }
    fmt.Println()
    
    // Practical example: linked list node
    type Node struct {
        Value int
        Next  *Node
    }
    
    // Create linked list
    node1 := &Node{Value: 1}
    node2 := &Node{Value: 2}
    node3 := &Node{Value: 3}
    
    node1.Next = node2
    node2.Next = node3
    
    // Traverse linked list
    current := node1
    fmt.Print("Linked list: ")
    for current != nil {
        fmt.Printf("%d ", current.Value)
        current = current.Next
    }
    fmt.Println()
}
```

## 14. Error Handling

### Basic Error Handling

```go
package main

import (
    "errors"
    "fmt"
    "strconv"
)

// Function that returns an error
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}

// Function with formatted error
func validateAge(age int) error {
    if age < 0 {
        return fmt.Errorf("age cannot be negative: %d", age)
    }
    if age > 150 {
        return fmt.Errorf("age seems unrealistic: %d", age)
    }
    return nil
}

// Multiple return values with error
func parseAndValidate(s string) (int, error) {
    num, err := strconv.Atoi(s)
    if err != nil {
        return 0, fmt.Errorf("failed to parse '%s': %w", s, err)
    }
    
    if num < 0 {
        return 0, errors.New("number must be positive")
    }
    
    return num, nil
}

func main() {
    // Basic error handling
    result, err := divide(10, 2)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
    } else {
        fmt.Printf("10 / 2 = %.2f\n", result)
    }
    
    result, err = divide(10, 0)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
    } else {
        fmt.Printf("Result: %.2f\n", result)
    }
    
    // Formatted error
    ages := []int{25, -5, 200, 30}
    for _, age := range ages {
        if err := validateAge(age); err != nil {
            fmt.Printf("Invalid age %d: %v\n", age, err)
        } else {
            fmt.Printf("Valid age: %d\n", age)
        }
    }
    
    // Error wrapping and unwrapping
    inputs := []string{"42", "abc", "-10", "100"}
    for _, input := range inputs {
        num, err := parseAndValidate(input)
        if err != nil {
            fmt.Printf("Error processing '%s': %v\n", input, err)
            
            // Check if it's a parsing error
            var numError *strconv.NumError
            if errors.As(err, &numError) {
                fmt.Printf("  - This was a number parsing error\n")
            }
        } else {
            fmt.Printf("Successfully parsed: %d\n", num)
        }
    }
    
    // Error checking patterns
    fmt.Println("\n=== Error Checking Patterns ===")
    
    // Pattern 1: Early return
    if err := doSomething(); err != nil {
        fmt.Printf("doSomething failed: %v\n", err)
        return
    }
    
    // Pattern 2: Error accumulation
    var errs []error
    
    if err := validateAge(-1); err != nil {
        errs = append(errs, err)
    }
    
    if err := validateAge(200); err != nil {
        errs = append(errs, err)
    }
    
    if len(errs) > 0 {
        fmt.Printf("Found %d errors:\n", len(errs))
        for i, err := range errs {
            fmt.Printf("  %d: %v\n", i+1, err)
        }
    }
    
    // Pattern 3: Ignore error (be careful!)
    result, _ = divide(15, 3)  // Ignoring error
    fmt.Printf("Result (ignoring error): %.2f\n", result)
}

func doSomething() error {
    // Simulate some operation that might fail
    return nil  // Success
}
```

### Custom Error Types

```go
package main

import (
    "fmt"
    "time"
)

// Custom error type
type ValidationError struct {
    Field   string
    Value   interface{}
    Message string
}

func (e ValidationError) Error() string {
    return fmt.Sprintf("validation error on field '%s' with value '%v': %s", 
        e.Field, e.Value, e.Message)
}

// Another custom error type
type NetworkError struct {
    Operation string
    URL       string
    Retry     bool
    Timestamp time.Time
}

func (e NetworkError) Error() string {
    return fmt.Sprintf("network error during %s to %s at %s (retry: %t)", 
        e.Operation, e.URL, e.Timestamp.Format(time.RFC3339), e.Retry)
}

func (e NetworkError) Temporary() bool {
    return e.Retry
}

// Error type with multiple behaviors
type FileError struct {
    Filename string
    Op       string
    Err      error
}

func (e FileError) Error() string {
    return fmt.Sprintf("file error: %s %s: %v", e.Op, e.Filename, e.Err)
}

func (e FileError) Unwrap() error {
    return e.Err
}

// Sentinel errors
var (
    ErrNotFound     = errors.New("item not found")
    ErrUnauthorized = errors.New("unauthorized access")
    ErrInvalidInput = errors.New("invalid input")
)

// Functions that return custom errors
func validateUser(name, email string, age int) error {
    if name == "" {
        return ValidationError{
            Field:   "name",
            Value:   name,
            Message: "cannot be empty",
        }
    }
    
    if age < 0 || age > 120 {
        return ValidationError{
            Field:   "age", 
            Value:   age,
            Message: "must be between 0 and 120",
        }
    }
    
    return nil
}

func fetchData(url string) error {
    // Simulate network operation
    if url == "" {
        return NetworkError{
            Operation: "GET",
            URL:       url,
            Retry:     false,
            Timestamp: time.Now(),
        }
    }
    
    if url == "http://unreliable.com" {
        return NetworkError{
            Operation: "GET",
            URL:       url,
            Retry:     true,
            Timestamp: time.Now(),
        }
    }
    
    return nil
}

func readFile(filename string) error {
    if filename == "missing.txt" {
        return FileError{
            Filename: filename,
            Op:       "read",
            Err:      ErrNotFound,
        }
    }
    return nil
}

import "errors"

func main() {
    fmt.Println("=== Custom Error Types ===")
    
    // Validation errors
    users := []struct {
        name  string
        email string
        age   int
    }{
        {"Alice", "alice@example.com", 25},
        {"", "bob@example.com", 30},
        {"Charlie", "charlie@example.com", -5},
        {"David", "david@example.com", 150},
    }
    
    for _, user := range users {
        if err := validateUser(user.name, user.email, user.age); err != nil {
            fmt.Printf("User validation failed: %v\n", err)
            
            // Type assertion to access custom error fields
            if ve, ok := err.(ValidationError); ok {
                fmt.Printf("  Field: %s, Value: %v\n", ve.Field, ve.Value)
            }
        } else {
            fmt.Printf("User %s is valid\n", user.name)
        }
    }
    
    // Network errors
    fmt.Println("\n=== Network Errors ===")
    urls := []string{"http://example.com", "", "http://unreliable.com"}
    
    for _, url := range urls {
        if err := fetchData(url); err != nil {
            fmt.Printf("Fetch failed: %v\n", err)
            
            if ne, ok := err.(NetworkError); ok {
                if ne.Temporary() {
                    fmt.Println("  This is a temporary error, can retry")
                } else {
                    fmt.Println("  This is a permanent error, do not retry")
                }
            }
        } else {
            fmt.Printf("Successfully fetched: %s\n", url)
        }
    }
    
    // Error wrapping and unwrapping
    fmt.Println("\n=== Error Wrapping ===")
    if err := readFile("missing.txt"); err != nil {
        fmt.Printf("Read error: %v\n", err)
        
        // Check if it wraps a specific error
        if errors.Is(err, ErrNotFound) {
            fmt.Println("  This is a 'not found' error")
        }
        
        // Unwrap to get the underlying error
        if unwrapped := errors.Unwrap(err); unwrapped != nil {
            fmt.Printf("  Underlying error: %v\n", unwrapped)
        }
        
        // Use errors.As to check for specific types
        var fileErr FileError
        if errors.As(err, &fileErr) {
            fmt.Printf("  File operation: %s on %s\n", fileErr.Op, fileErr.Filename)
        }
    }
    
    // Sentinel error checking
    fmt.Println("\n=== Sentinel Errors ===")
    testErrors := []error{
        ErrNotFound,
        ErrUnauthorized,
        ValidationError{Field: "test", Value: "value", Message: "test error"},
    }
    
    for _, err := range testErrors {
        switch {
        case errors.Is(err, ErrNotFound):
            fmt.Println("Handle not found error")
        case errors.Is(err, ErrUnauthorized):
            fmt.Println("Handle unauthorized error")
        default:
            fmt.Printf("Handle other error: %v\n", err)
        }
    }
}
```

### Error Handling Patterns

```go
package main

import (
    "fmt"
    "io"
    "strings"
)

// Result type pattern (alternative to multiple returns)
type Result[T any] struct {
    Value T
    Err   error
}

func (r Result[T]) IsError() bool {
    return r.Err != nil
}

func (r Result[T]) Unwrap() (T, error) {
    return r.Value, r.Err
}

// Operation that might fail
func riskyOperation(input string) Result[int] {
    if input == "" {
        return Result[int]{Err: fmt.Errorf("empty input")}
    }
    
    if input == "fail" {
        return Result[int]{Err: fmt.Errorf("operation failed for input: %s", input)}
    }
    
    return Result[int]{Value: len(input)}
}

// Error aggregation
type MultiError []error

func (m MultiError) Error() string {
    if len(m) == 0 {
        return "no errors"
    }
    
    var builder strings.Builder
    builder.WriteString(fmt.Sprintf("%d error(s): ", len(m)))
    
    for i, err := range m {
        if i > 0 {
            builder.WriteString("; ")
        }
        builder.WriteString(err.Error())
    }
    
    return builder.String()
}

func (m MultiError) HasErrors() bool {
    return len(m) > 0
}

// Retry pattern
func retryOperation(maxRetries int, operation func() error) error {
    var lastErr error
    
    for i := 0; i < maxRetries; i++ {
        err := operation()
        if err == nil {
            return nil
        }
        
        lastErr = err
        fmt.Printf("Attempt %d failed: %v\n", i+1, err)
    }
    
    return fmt.Errorf("operation failed after %d retries, last error: %w", maxRetries, lastErr)
}

// Circuit breaker pattern (simplified)
type CircuitBreaker struct {
    failures   int
    maxFailures int
    isOpen     bool
}

func NewCircuitBreaker(maxFailures int) *CircuitBreaker {
    return &CircuitBreaker{
        maxFailures: maxFailures,
    }
}

func (cb *CircuitBreaker) Call(operation func() error) error {
    if cb.isOpen {
        return fmt.Errorf("circuit breaker is open")
    }
    
    err := operation()
    if err != nil {
        cb.failures++
        if cb.failures >= cb.maxFailures {
            cb.isOpen = true
            return fmt.Errorf("circuit breaker opened after %d failures: %w", cb.failures, err)
        }
        return err
    }
    
    cb.failures = 0  // Reset on success
    return nil
}

func (cb *CircuitBreaker) Reset() {
    cb.failures = 0
    cb.isOpen = false
}

// Panic recovery pattern
func safeOperation(operation func() error) (err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic recovered: %v", r)
        }
    }()
    
    return operation()
}

func main() {
    fmt.Println("=== Result Type Pattern ===")
    inputs := []string{"hello", "", "world", "fail"}
    
    for _, input := range inputs {
        result := riskyOperation(input)
        if result.IsError() {
            fmt.Printf("Error for '%s': %v\n", input, result.Err)
        } else {
            fmt.Printf("Success for '%s': %d\n", input, result.Value)
        }
    }
    
    // Error aggregation
    fmt.Println("\n=== Error Aggregation ===")
    var multiErr MultiError
    
    // Collect multiple errors
    for _, input := range []string{"", "fail", "test"} {
        result := riskyOperation(input)
        if result.IsError() {
            multiErr = append(multiErr, result.Err)
        }
    }
    
    if multiErr.HasErrors() {
        fmt.Printf("Multiple errors occurred: %v\n", multiErr)
    }
    
    // Retry pattern
    fmt.Println("\n=== Retry Pattern ===")
    attempts := 0
    err := retryOperation(3, func() error {
        attempts++
        if attempts < 3 {
            return fmt.Errorf("simulated failure %d", attempts)
        }
        return nil
    })
    
    if err != nil {
        fmt.Printf("Final error: %v\n", err)
    } else {
        fmt.Println("Operation succeeded after retries")
    }
    
    // Circuit breaker pattern
    fmt.Println("\n=== Circuit Breaker Pattern ===")
    cb := NewCircuitBreaker(2)
    
    // Simulate operations
    operations := []bool{false, false, true, true}  // false = failure, true = success
    
    for i, shouldSucceed := range operations {
        err := cb.Call(func() error {
            if shouldSucceed {
                return nil
            }
            return fmt.Errorf("operation %d failed", i+1)
        })
        
        if err != nil {
            fmt.Printf("Operation %d: %v\n", i+1, err)
        } else {
            fmt.Printf("Operation %d: success\n", i+1)
        }
    }
    
    // Reset circuit breaker
    cb.Reset()
    fmt.Println("Circuit breaker reset")
    
    // Panic recovery
    fmt.Println("\n=== Panic Recovery ===")
    
    err = safeOperation(func() error {
        // This would normally panic
        var slice []int
        _ = slice[10]  // Index out of bounds
        return nil
    })
    
    if err != nil {
        fmt.Printf("Recovered from panic: %v\n", err)
    }
    
    err = safeOperation(func() error {
        return fmt.Errorf("normal error")
    })
    
    if err != nil {
        fmt.Printf("Normal error: %v\n", err)
    }
    
    // Error handling with defer
    fmt.Println("\n=== Defer Error Handling ===")
    
    func() {
        defer func() {
            if err := recover(); err != nil {
                fmt.Printf("Deferred recovery: %v\n", err)
            }
        }()
        
        panic("something went wrong")
    }()
    
    // Resource cleanup pattern
    func() (err error) {
        resource := "file.txt"
        
        defer func() {
            if closeErr := closeResource(resource); closeErr != nil {
                if err == nil {
                    err = closeErr
                } else {
                    err = fmt.Errorf("multiple errors: %v; close error: %w", err, closeErr)
                }
            }
        }()
        
        // Simulate some work that might fail
        return processResource(resource)
    }()
}

func closeResource(resource string) error {
    fmt.Printf("Closing resource: %s\n", resource)
    // Simulate cleanup
    return nil
}

func processResource(resource string) error {
    fmt.Printf("Processing resource: %s\n", resource)
    // Simulate processing
    return nil
}
```

## 15. Packages and Modules

### Package Basics

```go
// File: main.go
package main

import (
    "fmt"
    "math"
    "math/rand"
    "strings"
    "time"
)

// Exported function (starts with capital letter)
func PublicFunction() {
    fmt.Println("This is a public function")
}

// Unexported function (starts with lowercase letter)
func privateFunction() {
    fmt.Println("This is a private function")
}

// Exported variable
var PublicVariable = "I am public"

// Unexported variable
var privateVariable = "I am private"

// Exported constant
const PublicConstant = 42

// Unexported constant
const privateConstant = "secret"

// Exported type
type PublicStruct struct {
    PublicField  string
    privateField int  // This field is not exported
}

// Exported method
func (p PublicStruct) PublicMethod() string {
    return fmt.Sprintf("Public: %s, Private: %d", p.PublicField, p.privateField)
}

// Unexported method
func (p PublicStruct) privateMethod() {
    fmt.Println("This is a private method")
}

func main() {
    fmt.Println("=== Package Basics ===")
    
    // Using standard library packages
    fmt.Printf("Random number: %d\n", rand.Intn(100))
    fmt.Printf("Square root of 16: %.2f\n", math.Sqrt(16))
    fmt.Printf("Uppercase: %s\n", strings.ToUpper("hello"))
    
    // Using exported items from current package
    PublicFunction()
    privateFunction()  // Can access private items within same package
    
    fmt.Printf("Public variable: %s\n", PublicVariable)
    fmt.Printf("Private variable: %s\n", privateVariable)
    
    fmt.Printf("Public constant: %d\n", PublicConstant)
    fmt.Printf("Private constant: %s\n", privateConstant)
    
    // Using exported struct
    ps := PublicStruct{
        PublicField:  "visible",
        privateField: 123,  // Can access private field within same package
    }
    
    fmt.Printf("Struct: %+v\n", ps)
    fmt.Printf("Method result: %s\n", ps.PublicMethod())
    ps.privateMethod()  // Can call private method within same package
    
    // Package alias
    t := time.Now()
    fmt.Printf("Current time: %s\n", t.Format("2006-01-02 15:04:05"))
    
    // Using packages with different import styles
    demonstrateImports()
}

func demonstrateImports() {
    fmt.Println("\n=== Import Styles ===")
    
    // Standard import (already shown above)
    fmt.Println("Standard import: fmt.Println")
    
    // Aliased import would look like:
    // import f "fmt"
    // f.Println("Aliased import")
    
    // Dot import would look like:
    // import . "fmt"
    // Println("Dot import")  // Direct access without package name
    
    // Blank import would look like:
    // import _ "some/package"  // Import for side effects only
}
```

### Creating Custom Packages

```go
// File: utils/math.go
package utils

import "math"

// Exported functions
func Add(a, b int) int {
    return a + b
}

func Multiply(a, b int) int {
    return a * b
}

func Power(base, exponent float64) float64 {
    return math.Pow(base, exponent)
}

// Exported variable
var Pi = math.Pi

// File: utils/string.go
package utils

import (
    "strings"
    "unicode"
)

// String utilities
func Reverse(s string) string {
    runes := []rune(s)
    for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
        runes[i], runes[j] = runes[j], runes[i]
    }
    return string(runes)
}

func IsPalindrome(s string) bool {
    s = strings.ToLower(s)
    cleaned := ""
    for _, r := range s {
        if unicode.IsLetter(r) || unicode.IsDigit(r) {
            cleaned += string(r)
        }
    }
    return cleaned == Reverse(cleaned)
}

func WordCount(s string) map[string]int {
    words := strings.Fields(strings.ToLower(s))
    count := make(map[string]int)
    for _, word := range words {
        count[word]++
    }
    return count
}

// File: main.go
package main

import (
    "fmt"
    // "myproject/utils"  // Import custom package
)

// Simulating utils package functionality for this example
type Utils struct{}

func (u Utils) Add(a, b int) int { return a + b }
func (u Utils) Multiply(a, b int) int { return a * b }
func (u Utils) Reverse(s string) string {
    runes := []rune(s)
    for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
        runes[i], runes[j] = runes[j], runes[i]
    }
    return string(runes)
}

var utils = Utils{}

func main() {
    fmt.Println("=== Custom Package Usage ===")
    
    // Using math utilities
    sum := utils.Add(10, 20)
    product := utils.Multiply(5, 6)
    
    fmt.Printf("Sum: %d\n", sum)
    fmt.Printf("Product: %d\n", product)
    
    // Using string utilities
    original := "hello world"
    reversed := utils.Reverse(original)
    
    fmt.Printf("Original: %s\n", original)
    fmt.Printf("Reversed: %s\n", reversed)
    
    // Package initialization demonstration
    fmt.Println("\n=== Package Initialization ===")
    demonstrateInit()
}

// Package initialization
var initialized = initializePackage()

func initializePackage() string {
    fmt.Println("Package variable initialized")
    return "initialized"
}

func init() {
    fmt.Println("init function called")
}

func demonstrateInit() {
    fmt.Printf("Initialized variable: %s\n", initialized)
}
```

### Go Modules

```go
// File: go.mod (conceptual example)
/*
module myproject

go 1.21

require (
    github.com/gorilla/mux v1.8.0
    github.com/stretchr/testify v1.8.4
)

require (
    github.com/davecgh/go-spew v1.1.1 // indirect
    github.com/pmezard/go-difflib v1.0.0 // indirect
    gopkg.in/yaml.v3 v3.0.1 // indirect
)
*/

// File: main.go
package main

import (
    "fmt"
    "log"
    "net/http"
    // In a real project, these would be:
    // "github.com/gorilla/mux"
    // "myproject/internal/handlers"
    // "myproject/pkg/utils"
)

// Simulating external package functionality
type Router struct {
    routes map[string]func(http.ResponseWriter, *http.Request)
}

func NewRouter() *Router {
    return &Router{routes: make(map[string]func(http.ResponseWriter, *http.Request))}
}

func (r *Router) HandleFunc(path string, handler func(http.ResponseWriter, *http.Request)) {
    r.routes[path] = handler
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    if handler, exists := r.routes[req.URL.Path]; exists {
        handler(w, req)
    } else {
        http.NotFound(w, req)
    }
}

func main() {
    fmt.Println("=== Go Modules Example ===")
    
    // This would normally use imported packages
    router := NewRouter()
    
    // Define routes
    router.HandleFunc("/", homeHandler)
    router.HandleFunc("/api/health", healthHandler)
    
    fmt.Println("Server would start on :8080")
    fmt.Println("Routes registered:")
    fmt.Println("  GET /")
    fmt.Println("  GET /api/health")
    
    // In a real application:
    // log.Fatal(http.ListenAndServe(":8080", router))
    
    // Demonstrate module concepts
    demonstrateModuleConcepts()
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Welcome to the home page!")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, `{"status": "healthy"}`)
}

func demonstrateModuleConcepts() {
    fmt.Println("\n=== Module Concepts ===")
    
    // Module structure concepts
    fmt.Println("Typical Go module structure:")
    fmt.Println("myproject/")
    fmt.Println("├── go.mod")
    fmt.Println("├── go.sum")
    fmt.Println("├── main.go")
    fmt.Println("├── cmd/")
    fmt.Println("│   └── server/")
    fmt.Println("│       └── main.go")
    fmt.Println("├── internal/")
    fmt.Println("│   ├── handlers/")
    fmt.Println("│   │   └── user.go")
    fmt.Println("│   └── models/")
    fmt.Println("│       └── user.go")
    fmt.Println("├── pkg/")
    fmt.Println("│   └── utils/")
    fmt.Println("│       └── helpers.go")
    fmt.Println("└── tests/")
    fmt.Println("    └── integration_test.go")
    
    fmt.Println("\nModule commands:")
    fmt.Println("  go mod init <module-name>  # Initialize new module")
    fmt.Println("  go mod tidy               # Add missing and remove unused modules")
    fmt.Println("  go mod download           # Download modules to local cache")
    fmt.Println("  go mod verify             # Verify dependencies")
    fmt.Println("  go get <package>          # Add or update dependency")
    fmt.Println("  go get -u <package>       # Update to latest version")
    
    // Version constraints
    fmt.Println("\nVersion constraints examples:")
    fmt.Println("  v1.2.3         # Exact version")
    fmt.Println("  >=v1.2.3       # Minimum version")
    fmt.Println("  v1.2.0-v1.3.0  # Version range")
    fmt.Println("  latest         # Latest available")
}

// Package documentation example
/*
Package myproject provides utilities for web application development.

This package includes:
- HTTP handlers for common endpoints
- Utility functions for data processing
- Configuration management tools

Example usage:

    router := NewRouter()
    router.HandleFunc("/", homeHandler)
    http.ListenAndServe(":8080", router)

For more information, see the documentation at https://pkg.go.dev/myproject
*/

// Function documentation
/*
NewRouter creates a new HTTP router instance.

The router handles HTTP requests and routes them to appropriate handlers
based on the URL path.

Returns:
    *Router: A new router instance ready to register handlers

Example:
    router := NewRouter()
    router.HandleFunc("/api/users", usersHandler)
*/
```

## 16. Concurrency

### Goroutines

```go
package main

import (
    "fmt"
    "math/rand"
    "runtime"
    "sync"
    "time"
)

// Simple goroutine example
func sayHello(name string) {
    for i := 0; i < 3; i++ {
        fmt.Printf("Hello %s! (%d)\n", name, i+1)
        time.Sleep(100 * time.Millisecond)
    }
}

// Goroutine with work simulation
func worker(id int, work chan int, results chan int) {
    for w := range work {
        fmt.Printf("Worker %d starting work %d\n", id, w)
        
        // Simulate work
        time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
        
        result := w * 2
        fmt.Printf("Worker %d finished work %d, result: %d\n", id, w, result)
        results <- result
    }
}

// CPU-intensive work
func computeSum(start, end int, result chan int) {
    sum := 0
    for i := start; i <= end; i++ {
        sum += i
    }
    result <- sum
}

func main() {
    fmt.Println("=== Basic Goroutines ===")
    
    // Launch goroutines
    go sayHello("Alice")
    go sayHello("Bob")
    
    // Main goroutine continues
    fmt.Println("Main function continues...")
    time.Sleep(500 * time.Millisecond)  // Wait for goroutines to finish
    
    fmt.Println("\n=== Worker Pool Pattern ===")
    
    // Create channels
    work := make(chan int, 10)
    results := make(chan int, 10)
    
    // Start workers
    numWorkers := 3
    for i := 1; i <= numWorkers; i++ {
        go worker(i, work, results)
    }
    
    // Send work
    numJobs := 5
    for i := 1; i <= numJobs; i++ {
        work <- i
    }
    close(work)  // No more work
    
    // Collect results
    for i := 1; i <= numJobs; i++ {
        result := <-results
        fmt.Printf("Result received: %d\n", result)
    }
    
    fmt.Println("\n=== Parallel Computation ===")
    
    // Parallel sum computation
    n := 1000000
    numGoroutines := runtime.NumCPU()
    chunkSize := n / numGoroutines
    
    resultChan := make(chan int, numGoroutines)
    
    start := time.Now()
    
    for i := 0; i < numGoroutines; i++ {
        startRange := i*chunkSize + 1
        endRange := (i + 1) * chunkSize
        if i == numGoroutines-1 {
            endRange = n  // Include any remainder in last chunk
        }
        
        go computeSum(startRange, endRange, resultChan)
    }
    
    // Collect partial results
    totalSum := 0
    for i := 0; i < numGoroutines; i++ {
        partialSum := <-resultChan
        totalSum += partialSum
    }
    
    elapsed := time.Since(start)
    fmt.Printf("Sum of 1 to %d: %d\n", n, totalSum)
    fmt.Printf("Computed using %d goroutines in %v\n", numGoroutines, elapsed)
    
    // Compare with single-threaded computation
    start = time.Now()
    singleSum := 0
    for i := 1; i <= n; i++ {
        singleSum += i
    }
    elapsed = time.Since(start)
    fmt.Printf("Single-threaded result: %d in %v\n", singleSum, elapsed)
    
    fmt.Printf("Number of CPUs: %d\n", runtime.NumCPU())
    fmt.Printf("Number of goroutines: %d\n", runtime.NumGoroutine())
}
```

### WaitGroups and Synchronization

```go
package main

import (
    "fmt"
    "math/rand"
    "sync"
    "time"
)

// Task that takes some time
func longRunningTask(id int, wg *sync.WaitGroup) {
    defer wg.Done()  // Signal completion when function returns
    
    duration := time.Duration(rand.Intn(1000)) * time.Millisecond
    fmt.Printf("Task %d starting (will take %v)\n", id, duration)
    
    time.Sleep(duration)
    
    fmt.Printf("Task %d completed\n", id)
}

// Counter with mutex protection
type SafeCounter struct {
    mu    sync.Mutex
    value int
}

func (c *SafeCounter) Increment() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.value++
}

func (c *SafeCounter) Value() int {
    c.mu.Lock()
    defer c.mu.Unlock()
    return c.value
}

// Read-write mutex example
type SafeMap struct {
    mu   sync.RWMutex
    data map[string]int
}

func NewSafeMap() *SafeMap {
    return &SafeMap{
        data: make(map[string]int),
    }
}

func (sm *SafeMap) Set(key string, value int) {
    sm.mu.Lock()
    defer sm.mu.Unlock()
    sm.data[key] = value
}

func (sm *SafeMap) Get(key string) (int, bool) {
    sm.mu.RLock()
    defer sm.mu.RUnlock()
    value, exists := sm.data[key]
    return value, exists
}

func (sm *SafeMap) Keys() []string {
    sm.mu.RLock()
    defer sm.mu.RUnlock()
    
    keys := make([]string, 0, len(sm.data))
    for k := range sm.data {
        keys = append(keys, k)
    }
    return keys
}

// Once example - initialization that should happen only once
var (
    instance *Database
    once     sync.Once
)

type Database struct {
    name string
}

func GetDatabase() *Database {
    once.Do(func() {
        fmt.Println("Initializing database (this should happen only once)")
        time.Sleep(100 * time.Millisecond)  // Simulate expensive initialization
        instance = &Database{name: "MyDB"}
    })
    return instance
}

func main() {
    fmt.Println("=== WaitGroup Example ===")
    
    var wg sync.WaitGroup
    numTasks := 5
    
    // Add to wait group before starting goroutines
    wg.Add(numTasks)
    
    for i := 1; i <= numTasks; i++ {
        go longRunningTask(i, &wg)
    }
    
    fmt.Println("Waiting for all tasks to complete...")
    wg.Wait()  // Block until all goroutines call Done()
    fmt.Println("All tasks completed!")
    
    fmt.Println("\n=== Mutex Example ===")
    
    counter := &SafeCounter{}
    var wg2 sync.WaitGroup
    
    // Start multiple goroutines that increment the counter
    numIncrementers := 100
    wg2.Add(numIncrementers)
    
    for i := 0; i < numIncrementers; i++ {
        go func() {
            defer wg2.Done()
            for j := 0; j < 100; j++ {
                counter.Increment()
            }
        }()
    }
    
    wg2.Wait()
    fmt.Printf("Final counter value: %d (expected: %d)\n", counter.Value(), numIncrementers*100)
    
    fmt.Println("\n=== RWMutex Example ===")
    
    safeMap := NewSafeMap()
    var wg3 sync.WaitGroup
    
    // Writers
    numWriters := 5
    wg3.Add(numWriters)
    
    for i := 0; i < numWriters; i++ {
        go func(id int) {
            defer wg3.Done()
            for j := 0; j < 10; j++ {
                key := fmt.Sprintf("key_%d_%d", id, j)
                safeMap.Set(key, id*10+j)
                time.Sleep(10 * time.Millisecond)
            }
        }(i)
    }
    
    // Readers
    numReaders := 10
    wg3.Add(numReaders)
    
    for i := 0; i < numReaders; i++ {
        go func(id int) {
            defer wg3.Done()
            for j := 0; j < 20; j++ {
                keys := safeMap.Keys()
                if len(keys) > 0 {
                    key := keys[rand.Intn(len(keys))]
                    if value, exists := safeMap.Get(key); exists {
                        fmt.Printf("Reader %d: %s = %d\n", id, key, value)
                    }
                }
                time.Sleep(5 * time.Millisecond)
            }
        }(i)
    }
    
    wg3.Wait()
    fmt.Printf("Final map size: %d\n", len(safeMap.Keys()))
    
    fmt.Println("\n=== sync.Once Example ===")
    
    var wg4 sync.WaitGroup
    numClients := 10
    wg4.Add(numClients)
    
    for i := 0; i < numClients; i++ {
        go func(id int) {
            defer wg4.Done()
            db := GetDatabase()
            fmt.Printf("Client %d got database: %s\n", id, db.name)
        }(i)
    }
    
    wg4.Wait()
    
    fmt.Println("\n=== Atomic Operations ===")
    demonstrateAtomic()
}

import "sync/atomic"

func demonstrateAtomic() {
    var counter int64
    var wg sync.WaitGroup
    
    numGoroutines := 100
    wg.Add(numGoroutines)
    
    for i := 0; i < numGoroutines; i++ {
        go func() {
            defer wg.Done()
            for j := 0; j < 1000; j++ {
                atomic.AddInt64(&counter, 1)
            }
        }()
    }
    
    wg.Wait()
    
    finalValue := atomic.LoadInt64(&counter)
    fmt.Printf("Atomic counter final value: %d (expected: %d)\n", finalValue, numGoroutines*1000)
    
    // Atomic compare and swap
    var value int64 = 10
    fmt.Printf("Initial value: %d\n", value)
    
    swapped := atomic.CompareAndSwapInt64(&value, 10, 20)
    fmt.Printf("CAS(10, 20): %t, new value: %d\n", swapped, value)
    
    swapped = atomic.CompareAndSwapInt64(&value, 10, 30)
    fmt.Printf("CAS(10, 30): %t, value unchanged: %d\n", swapped, value)
}
```

## 17. Channels

### Channel Basics

```go
package main

import (
    "fmt"
    "time"
)

func main() {
    fmt.Println("=== Basic Channel Operations ===")
    
    // Create channels
    ch := make(chan int)
    stringCh := make(chan string)
    
    // Send and receive in goroutines
    go func() {
        ch <- 42  // Send value
        stringCh <- "Hello from goroutine"
    }()
    
    // Receive values
    value := <-ch
    message := <-stringCh
    
    fmt.Printf("Received int: %d\n", value)
    fmt.Printf("Received string: %s\n", message)
    
    fmt.Println("\n=== Buffered Channels ===")
    
    // Buffered channel
    bufferedCh := make(chan int, 3)
    
    // Can send without blocking until buffer is full
    bufferedCh <- 1
    bufferedCh <- 2
    bufferedCh <- 3
    
    fmt.Printf("Sent 3 values to buffered channel\n")
    
    // Receive values
    for i := 0; i < 3; i++ {
        value := <-bufferedCh
        fmt.Printf("Received: %d\n", value)
    }
    
    fmt.Println("\n=== Channel Directions ===")
    
    // Demonstrate send-only and receive-only channels
    numbers := make(chan int)
    
    go sender(numbers)
    go receiver(numbers)
    
    time.Sleep(200 * time.Millisecond)
    
    fmt.Println("\n=== Channel Closing ===")
    
    dataCh := make(chan int, 5)
    
    // Producer goroutine
    go func() {
        for i := 1; i <= 5; i++ {
            dataCh <- i
            fmt.Printf("Sent: %d\n", i)
        }
        close(dataCh)  // Close channel when done
        fmt.Println("Channel closed")
    }()
    
    // Consumer with range
    fmt.Println("Receiving with range:")
    for value := range dataCh {
        fmt.Printf("Received: %d\n", value)
    }
    
    fmt.Println("\n=== Channel with OK Pattern ===")
    
    testCh := make(chan string, 2)
    testCh <- "first"
    testCh <- "second"
    close(testCh)
    
    for {
        value, ok := <-testCh
        if !ok {
            fmt.Println("Channel is closed and empty")
            break
        }
        fmt.Printf("Received: %s\n", value)
    }
}

// Function that only sends to channel
func sender(ch chan<- int) {
    for i := 1; i <= 3; i++ {
        ch <- i
        fmt.Printf("Sent: %d\n", i)
        time.Sleep(50 * time.Millisecond)
    }
    close(ch)
}

// Function that only receives from channel
func receiver(ch <-chan int) {
    for value := range ch {
        fmt.Printf("Received: %d\n", value)
    }
    fmt.Println("Receiver done")
}
```

### Channel Patterns

```go
package main

import (
    "fmt"
    "math/rand"
    "time"
)

// Fan-out pattern: distribute work to multiple workers
func fanOut(input <-chan int, workers int) []<-chan int {
    outputs := make([]<-chan int, workers)
    
    for i := 0; i < workers; i++ {
        output := make(chan int)
        outputs[i] = output
        
        go func(out chan<- int, workerID int) {
            defer close(out)
            for value := range input {
                // Simulate work
                time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
                result := value * value
                fmt.Printf("Worker %d: %d -> %d\n", workerID, value, result)
                out <- result
            }
        }(output, i)
    }
    
    return outputs
}

// Fan-in pattern: combine multiple channels into one
func fanIn(inputs ...<-chan int) <-chan int {
    output := make(chan int)
    
    for i, input := range inputs {
        go func(in <-chan int, id int) {
            for value := range in {
                output <- value
            }
        }(input, i)
    }
    
    // Close output channel when all inputs are done
    go func() {
        // Note: This is simplified. In practice, you'd use sync.WaitGroup
        time.Sleep(1 * time.Second)  // Wait for workers to finish
        close(output)
    }()
    
    return output
}

// Pipeline pattern
func pipeline() {
    fmt.Println("=== Pipeline Pattern ===")
    
    // Stage 1: Generate numbers
    numbers := make(chan int)
    go func() {
        defer close(numbers)
        for i := 1; i <= 10; i++ {
            numbers <- i
        }
    }()
    
    // Stage 2: Square numbers
    squares := make(chan int)
    go func() {
        defer close(squares)
        for n := range numbers {
            squares <- n * n
        }
    }()
    
    // Stage 3: Add 1 to each square
    results := make(chan int)
    go func() {
        defer close(results)
        for s := range squares {
            results <- s + 1
        }
    }()
    
    // Consume results
    for result := range results {
        fmt.Printf("Pipeline result: %d\n", result)
    }
}

// Producer-Consumer pattern
func producerConsumer() {
    fmt.Println("\n=== Producer-Consumer Pattern ===")
    
    buffer := make(chan string, 5)  // Buffered channel as queue
    
    // Producer
    go func() {
        defer close(buffer)
        items := []string{"item1", "item2", "item3", "item4", "item5", "item6"}
        
        for _, item := range items {
            fmt.Printf("Producing: %s\n", item)
            buffer <- item
            time.Sleep(100 * time.Millisecond)
        }
        fmt.Println("Producer finished")
    }()
    
    // Consumer
    go func() {
        for item := range buffer {
            fmt.Printf("Consuming: %s\n", item)
            time.Sleep(200 * time.Millisecond)  // Slower than producer
        }
        fmt.Println("Consumer finished")
    }()
    
    time.Sleep(2 * time.Second)  // Wait for completion
}

// Worker pool pattern
func workerPool() {
    fmt.Println("\n=== Worker Pool Pattern ===")
    
    jobs := make(chan int, 10)
    results := make(chan int, 10)
    
    // Start workers
    numWorkers := 3
    for w := 1; w <= numWorkers; w++ {
        go worker(w, jobs, results)
    }
    
    // Send jobs
    numJobs := 9
    for j := 1; j <= numJobs; j++ {
        jobs <- j
    }
    close(jobs)
    
    // Collect results
    for r := 1; r <= numJobs; r++ {
        result := <-results
        fmt.Printf("Result: %d\n", result)
    }
}

func worker(id int, jobs <-chan int, results chan<- int) {
    for job := range jobs {
        fmt.Printf("Worker %d processing job %d\n", id, job)
        time.Sleep(100 * time.Millisecond)  // Simulate work
        results <- job * 2
    }
}

// Request-Response pattern
type Request struct {
    ID       int
    Data     string
    Response chan string
}

func requestResponse() {
    fmt.Println("\n=== Request-Response Pattern ===")
    
    requests := make(chan Request)
    
    // Server goroutine
    go func() {
        for req := range requests {
            // Process request
            response := fmt.Sprintf("Processed: %s (ID: %d)", req.Data, req.ID)
            req.Response <- response
        }
    }()
    
    // Client requests
    for i := 1; i <= 3; i++ {
        response := make(chan string)
        request := Request{
            ID:       i,
            Data:     fmt.Sprintf("request_%d", i),
            Response: response,
        }
        
        requests <- request
        resp := <-response
        fmt.Printf("Client received: %s\n", resp)
    }
    
    close(requests)
}

func main() {
    fmt.Println("=== Fan-Out/Fan-In Pattern ===")
    
    // Create input channel
    input := make(chan int)
    
    // Start input producer
    go func() {
        defer close(input)
        for i := 1; i <= 6; i++ {
            input <- i
        }
    }()
    
    // Fan-out to workers
    outputs := fanOut(input, 3)
    
    // Fan-in results
    results := fanIn(outputs...)
    
    // Collect results
    var collected []int
    for result := range results {
        collected = append(collected, result)
        if len(collected) >= 6 {  // We know we're expecting 6 results
            break
        }
    }
    
    fmt.Printf("Collected results: %v\n", collected)
    
    // Other patterns
    pipeline()
    producerConsumer()
    workerPool()
    requestResponse()
}
```

### Select Statement

```go
package main

import (
    "fmt"
    "math/rand"
    "time"
)

func main() {
    fmt.Println("=== Basic Select ===")
    
    ch1 := make(chan string)
    ch2 := make(chan string)
    
    // Send on channels with different delays
    go func() {
        time.Sleep(100 * time.Millisecond)
        ch1 <- "from ch1"
    }()
    
    go func() {
        time.Sleep(200 * time.Millisecond)
        ch2 <- "from ch2"
    }()
    
    // Select waits for first available channel
    select {
    case msg1 := <-ch1:
        fmt.Printf("Received: %s\n", msg1)
    case msg2 := <-ch2:
        fmt.Printf("Received: %s\n", msg2)
    }
    
    fmt.Println("\n=== Select with Timeout ===")
    
    slowCh := make(chan string)
    
    go func() {
        time.Sleep(2 * time.Second)  // Slow operation
        slowCh <- "slow result"
    }()
    
    select {
    case result := <-slowCh:
        fmt.Printf("Got result: %s\n", result)
    case <-time.After(1 * time.Second):
        fmt.Println("Timeout! Operation took too long")
    }
    
    fmt.Println("\n=== Select with Default ===")
    
    nonBlockingCh := make(chan int)
    
    // Non-blocking channel operations
    select {
    case value := <-nonBlockingCh:
        fmt.Printf("Received: %d\n", value)
    default:
        fmt.Println("No data available, continuing...")
    }
    
    // Non-blocking send
    select {
    case nonBlockingCh <- 42:
        fmt.Println("Sent value successfully")
    default:
        fmt.Println("Channel not ready for sending")
    }
    
    fmt.Println("\n=== Multiplexing Multiple Channels ===")
    
    multiplex()
    
    fmt.Println("\n=== Heartbeat Pattern ===")
    
    heartbeat()
    
    fmt.Println("\n=== Rate Limiting ===")
    
    rateLimiting()
}

func multiplex() {
    ch1 := make(chan string)
    ch2 := make(chan int)
    ch3 := make(chan bool)
    done := make(chan bool)
    
    // Producer goroutines
    go func() {
        for i := 0; i < 3; i++ {
            ch1 <- fmt.Sprintf("string_%d", i)
            time.Sleep(300 * time.Millisecond)
        }
        close(ch1)
    }()
    
    go func() {
        for i := 0; i < 3; i++ {
            ch2 <- i * 10
            time.Sleep(500 * time.Millisecond)
        }
        close(ch2)
    }()
    
    go func() {
        for i := 0; i < 2; i++ {
            ch3 <- i%2 == 0
            time.Sleep(700 * time.Millisecond)
        }
        close(ch3)
    }()
    
    // Multiplexer
    go func() {
        defer func() { done <- true }()
        
        for {
            select {
            case str, ok := <-ch1:
                if !ok {
                    ch1 = nil  // Disable this case
                    continue
                }
                fmt.Printf("String: %s\n", str)
                
            case num, ok := <-ch2:
                if !ok {
                    ch2 = nil  // Disable this case
                    continue
                }
                fmt.Printf("Number: %d\n", num)
                
            case flag, ok := <-ch3:
                if !ok {
                    ch3 = nil  // Disable this case
                    continue
                }
                fmt.Printf("Boolean: %t\n", flag)
            }
            
            // Exit when all channels are closed
            if ch1 == nil && ch2 == nil && ch3 == nil {
                break
            }
        }
    }()
    
    <-done
}

func heartbeat() {
    heartbeatCh := make(chan struct{})
    workCh := make(chan string)
    
    // Worker with heartbeat
    go func() {
        defer close(heartbeatCh)
        defer close(workCh)
        
        for i := 0; i < 5; i++ {
            select {
            case heartbeatCh <- struct{}{}:
            default:
            }
            
            // Simulate work
            time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
            workCh <- fmt.Sprintf("work_result_%d", i)
        }
    }()
    
    // Monitor
    timeout := time.After(3 * time.Second)
    var heartbeatCount int
    
    for {
        select {
        case <-heartbeatCh:
            heartbeatCount++
            fmt.Printf("♥ Heartbeat %d\n", heartbeatCount)
            
        case work, ok := <-workCh:
            if !ok {
                fmt.Println("Work completed")
                return
            }
            fmt.Printf("Work: %s\n", work)
            
        case <-timeout:
            fmt.Println("❌ Timeout - worker appears to be stuck")
            return
        }
    }
}

func rateLimiting() {
    // Rate limiter using time.Tick
    rateLimiter := time.Tick(200 * time.Millisecond)
    
    // Simulate requests
    requests := make(chan string, 10)
    for i := 1; i <= 8; i++ {
        requests <- fmt.Sprintf("request_%d", i)
    }
    close(requests)
    
    // Process requests with rate limiting
    for req := range requests {
        <-rateLimiter  // Wait for rate limiter
        fmt.Printf("Processing: %s at %s\n", req, time.Now().Format("15:04:05.000"))
    }
    
    fmt.Println("\nBurst rate limiting:")
    
    // Burst rate limiter
    burstLimiter := make(chan struct{}, 3)  // Allow burst of 3
    
    // Fill the burst limiter
    for i := 0; i < 3; i++ {
        burstLimiter <- struct{}{}
    }
    
    // Refill burst limiter periodically
    go func() {
        ticker := time.NewTicker(500 * time.Millisecond)
        defer ticker.Stop()
        
        for range ticker.C {
            select {
            case burstLimiter <- struct{}{}:
            default:
                // Burst limiter is full
            }
        }
    }()
    
    // Process requests with burst limiting
    for i := 1; i <= 8; i++ {
        <-burstLimiter  // Wait for available slot
        fmt.Printf("Burst processing request_%d at %s\n", i, time.Now().Format("15:04:05.000"))
        time.Sleep(100 * time.Millisecond)  // Simulate processing time
    }
}
```

## 16. Testing

Go has built-in testing support with the `testing` package.

### Basic Testing

```go
// math.go
package main

func Add(a, b int) int {
    return a + b
}

func Multiply(a, b int) int {
    return a * b
}
```

```go
// math_test.go
package main

import "testing"

func TestAdd(t *testing.T) {
    result := Add(2, 3)
    expected := 5
    
    if result != expected {
        t.Errorf("Add(2, 3) = %d; want %d", result, expected)
    }
}

func TestMultiply(t *testing.T) {
    result := Multiply(4, 5)
    expected := 20
    
    if result != expected {
        t.Errorf("Multiply(4, 5) = %d; want %d", result, expected)
    }
}

// Table-driven tests
func TestAddTable(t *testing.T) {
    tests := []struct {
        name string
        a, b int
        want int
    }{
        {"positive numbers", 2, 3, 5},
        {"negative numbers", -2, -3, -5},
        {"mixed numbers", -2, 3, 1},
        {"zeros", 0, 0, 0},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := Add(tt.a, tt.b); got != tt.want {
                t.Errorf("Add() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Benchmarks

```go
func BenchmarkAdd(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Add(2, 3)
    }
}

func BenchmarkMultiply(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Multiply(4, 5)
    }
}
```

### Test Coverage

```bash
# Run tests
go test

# Run tests with verbose output
go test -v

# Run benchmarks
go test -bench=.

# Test coverage
go test -cover

# Generate coverage profile
go test -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## 17. File I/O

Working with files and directories in Go.

### Reading Files

```go
package main

import (
    "bufio"
    "fmt"
    "io"
    "os"
)

func main() {
    // Read entire file
    content, err := os.ReadFile("example.txt")
    if err != nil {
        fmt.Printf("Error reading file: %v\n", err)
        return
    }
    fmt.Printf("File content: %s\n", content)
    
    // Read file with os.Open
    file, err := os.Open("example.txt")
    if err != nil {
        fmt.Printf("Error opening file: %v\n", err)
        return
    }
    defer file.Close()
    
    // Read with buffer
    reader := bufio.NewReader(file)
    for {
        line, err := reader.ReadString('\n')
        if err == io.EOF {
            break
        }
        if err != nil {
            fmt.Printf("Error reading line: %v\n", err)
            break
        }
        fmt.Printf("Line: %s", line)
    }
    
    // Read line by line with Scanner
    file2, _ := os.Open("example.txt")
    defer file2.Close()
    
    scanner := bufio.NewScanner(file2)
    for scanner.Scan() {
        fmt.Printf("Scanned line: %s\n", scanner.Text())
    }
    
    if err := scanner.Err(); err != nil {
        fmt.Printf("Scanner error: %v\n", err)
    }
}
```

### Writing Files

```go
package main

import (
    "bufio"
    "fmt"
    "os"
)

func main() {
    // Write entire file
    data := []byte("Hello, World!\nThis is a test file.")
    err := os.WriteFile("output.txt", data, 0644)
    if err != nil {
        fmt.Printf("Error writing file: %v\n", err)
        return
    }
    
    // Write with os.Create
    file, err := os.Create("output2.txt")
    if err != nil {
        fmt.Printf("Error creating file: %v\n", err)
        return
    }
    defer file.Close()
    
    // Write string
    _, err = file.WriteString("Hello from WriteString\n")
    if err != nil {
        fmt.Printf("Error writing string: %v\n", err)
        return
    }
    
    // Write bytes
    _, err = file.Write([]byte("Hello from Write\n"))
    if err != nil {
        fmt.Printf("Error writing bytes: %v\n", err)
        return
    }
    
    // Buffered writing
    writer := bufio.NewWriter(file)
    writer.WriteString("Buffered line 1\n")
    writer.WriteString("Buffered line 2\n")
    writer.Flush()  // Important: flush the buffer
    
    // Append to file
    file2, err := os.OpenFile("output.txt", os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        fmt.Printf("Error opening file for append: %v\n", err)
        return
    }
    defer file2.Close()
    
    file2.WriteString("\nAppended text")
}
```

## 18. JSON and Data Serialization

Working with JSON and other data formats.

### JSON Marshaling and Unmarshaling

```go
package main

import (
    "encoding/json"
    "fmt"
    "time"
)

type Person struct {
    Name      string    `json:"name"`
    Age       int       `json:"age"`
    Email     string    `json:"email,omitempty"`  // Omit if empty
    CreatedAt time.Time `json:"created_at"`
    IsActive  bool      `json:"is_active"`
    Tags      []string  `json:"tags,omitempty"`
}

func main() {
    // Create struct instance
    person := Person{
        Name:      "John Doe",
        Age:       30,
        Email:     "john@example.com",
        CreatedAt: time.Now(),
        IsActive:  true,
        Tags:      []string{"developer", "golang"},
    }
    
    // Marshal to JSON
    jsonData, err := json.Marshal(person)
    if err != nil {
        fmt.Printf("Error marshaling: %v\n", err)
        return
    }
    fmt.Printf("JSON: %s\n", jsonData)
    
    // Marshal with indentation
    prettyJSON, err := json.MarshalIndent(person, "", "  ")
    if err != nil {
        fmt.Printf("Error marshaling with indent: %v\n", err)
        return
    }
    fmt.Printf("Pretty JSON:\n%s\n", prettyJSON)
    
    // Unmarshal from JSON
    jsonString := `{
        "name": "Jane Smith",
        "age": 25,
        "email": "jane@example.com",
        "created_at": "2023-01-01T00:00:00Z",
        "is_active": false,
        "tags": ["designer", "frontend"]
    }`
    
    var newPerson Person
    err = json.Unmarshal([]byte(jsonString), &newPerson)
    if err != nil {
        fmt.Printf("Error unmarshaling: %v\n", err)
        return
    }
    fmt.Printf("Unmarshaled: %+v\n", newPerson)
    
    // Working with maps
    var data map[string]interface{}
    err = json.Unmarshal([]byte(jsonString), &data)
    if err != nil {
        fmt.Printf("Error unmarshaling to map: %v\n", err)
        return
    }
    fmt.Printf("Map data: %v\n", data)
    
    // Access map values
    if name, ok := data["name"].(string); ok {
        fmt.Printf("Name from map: %s\n", name)
    }
    
    if age, ok := data["age"].(float64); ok {  // JSON numbers are float64
        fmt.Printf("Age from map: %.0f\n", age)
    }
}
```

## 19. HTTP and Web Programming

Building HTTP clients and servers in Go.

### HTTP Client

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

func main() {
    // Simple GET request
    resp, err := http.Get("https://jsonplaceholder.typicode.com/posts/1")
    if err != nil {
        fmt.Printf("Error making GET request: %v\n", err)
        return
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        fmt.Printf("Error reading response: %v\n", err)
        return
    }
    
    fmt.Printf("GET Response: %s\n", body)
    
    // Custom HTTP client with timeout
    client := &http.Client{
        Timeout: 10 * time.Second,
    }
    
    // POST request with JSON
    postData := map[string]interface{}{
        "title":  "Go HTTP Tutorial",
        "body":   "Learning HTTP in Go",
        "userId": 1,
    }
    
    jsonData, err := json.Marshal(postData)
    if err != nil {
        fmt.Printf("Error marshaling JSON: %v\n", err)
        return
    }
    
    resp, err = client.Post(
        "https://jsonplaceholder.typicode.com/posts",
        "application/json",
        bytes.NewBuffer(jsonData),
    )
    if err != nil {
        fmt.Printf("Error making POST request: %v\n", err)
        return
    }
    defer resp.Body.Close()
    
    body, err = io.ReadAll(resp.Body)
    if err != nil {
        fmt.Printf("Error reading POST response: %v\n", err)
        return
    }
    
    fmt.Printf("POST Response: %s\n", body)
}
```

## 20. Context and Cancellation

Using context for cancellation, timeouts, and passing values.

### Basic Context Usage

```go
package main

import (
    "context"
    "fmt"
    "time"
)

func main() {
    // Background context
    ctx := context.Background()
    fmt.Printf("Background context: %v\n", ctx)
    
    // Context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()  // Always call cancel
    
    // Simulate work
    select {
    case <-time.After(2 * time.Second):
        fmt.Println("Work completed")
    case <-ctx.Done():
        fmt.Printf("Context cancelled: %v\n", ctx.Err())
    }
    
    // Context with deadline
    deadline := time.Now().Add(5 * time.Second)
    ctx2, cancel2 := context.WithDeadline(context.Background(), deadline)
    defer cancel2()
    
    // Manual cancellation
    ctx3, cancel3 := context.WithCancel(context.Background())
    
    go func() {
        time.Sleep(1 * time.Second)
        cancel3()  // Cancel after 1 second
    }()
    
    select {
    case <-time.After(2 * time.Second):
        fmt.Println("Work completed")
    case <-ctx3.Done():
        fmt.Printf("Manually cancelled: %v\n", ctx3.Err())
    }
}
```

---
