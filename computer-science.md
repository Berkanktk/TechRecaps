# Computer Science Learning Guide

## Table of Contents

1. [Fundamentals](#fundamentals)
   1. [What is Computer Science](#what-is-computer-science)
   2. [Number Systems and Bit Operations](#number-systems-and-bit-operations)
   3. [Boolean Logic](#boolean-logic)
   4. [Basic Complexity Analysis](#basic-complexity-analysis)
   5. [Computer Hardware Fundamentals](#computer-hardware-fundamentals)
   6. [Networking Fundamentals](#networking-fundamentals)
   7. [Network Topologies and Infrastructure](#network-topologies-and-infrastructure)
2. [Algorithms](#algorithms)
   1. [Algorithm Basics](#algorithm-basics)
   2. [Searching Algorithms](#searching-algorithms)
   3. [Sorting Algorithms](#sorting-algorithms)
   4. [Recursion](#recursion)
3. [Data Structures](#data-structures)
   1. [Arrays](#arrays)
   2. [Linked Lists](#linked-lists)
   3. [Stacks](#stacks)
   4. [Queues](#queues)
   5. [Hash Tables](#hash-tables)
4. [Time and Space Complexity](#time-and-space-complexity)
   1. [Big O Notation](#big-o-notation)
   2. [Best, Average, Worst Case](#best-average-worst-case)
   3. [Space Complexity](#space-complexity)
   4. [Complexity Analysis Examples](#complexity-analysis-examples)
5. [Programming Paradigms](#programming-paradigms)
   1. [Procedural Programming](#procedural-programming)
   2. [Object-Oriented Programming](#object-oriented-programming)
   3. [Functional Programming](#functional-programming)
   4. [Declarative vs Imperative](#declarative-vs-imperative)
6. [Advanced Data Structures](#advanced-data-structures)
   1. [Trees](#trees)
   2. [Binary Search Trees](#binary-search-trees)
   3. [Heaps](#heaps)
   4. [Graphs](#graphs)
   5. [Tries](#tries)
7. [Advanced Algorithms](#advanced-algorithms)
   1. [Dynamic Programming](#dynamic-programming)
   2. [Greedy Algorithms](#greedy-algorithms)
   3. [Backtracking](#backtracking)
   4. [Graph Algorithms](#graph-algorithms)
8. [String Algorithms](#string-algorithms)
   1. [Pattern Matching](#pattern-matching)
   2. [String Processing](#string-processing)
   3. [Text Algorithms](#text-algorithms)
9. [Computer Systems](#computer-systems)
   1. [Computer Architecture](#computer-architecture)
   2. [Memory Hierarchy](#memory-hierarchy)
   3. [Operating Systems](#operating-systems)
   4. [File Systems](#file-systems)
10. [Databases](#databases)
    1. [Database Design](#database-design)
    2. [SQL and NoSQL](#sql-and-nosql)
    3. [Transactions](#transactions)
    4. [Indexing](#indexing)
11. [Networks and Distributed Systems](#networks-and-distributed-systems)
    1. [Network Protocols](#network-protocols)
    2. [Client-Server Architecture](#client-server-architecture)
    3. [Distributed Computing](#distributed-computing)
    4. [Concurrency and Parallelism](#concurrency-and-parallelism)

---

# Fundamentals

### What is Computer Science

Computer Science is the study of computational systems, algorithms, and the design of computer systems and their applications.

**Core Areas:**
- **Algorithms & Data Structures** - Efficient problem solving
- **Programming Languages** - Tools for implementation
- **Computer Systems** - Hardware and software interaction
- **Theory of Computation** - Mathematical foundations
- **Software Engineering** - Large-scale system design
- **Artificial Intelligence** - Intelligent system behavior

### Number Systems and Bit Operations

Understanding how computers represent and manipulate data at the bit level.

**Binary (Base 2):**
```
Decimal: 13
Binary:  1101
Process: 1×8 + 1×4 + 0×2 + 1×1 = 13

Binary to Decimal Conversion:
11010110₂ = 1×128 + 1×64 + 0×32 + 1×16 + 0×8 + 1×4 + 1×2 + 0×1 = 214₁₀

Decimal to Binary Conversion:
214 ÷ 2 = 107 remainder 0
107 ÷ 2 = 53  remainder 1
53  ÷ 2 = 26  remainder 1
26  ÷ 2 = 13  remainder 0
13  ÷ 2 = 6   remainder 1
6   ÷ 2 = 3   remainder 0
3   ÷ 2 = 1   remainder 1
1   ÷ 2 = 0   remainder 1
Reading upward: 11010110₂
```

**Hexadecimal (Base 16):**
```
Decimal: 255
Hex:     FF
Binary:  11111111

Hex Digits: 0-9, A-F (A=10, B=11, C=12, D=13, E=14, F=15)

Binary to Hex (group by 4 bits):
11010110₂ = 1101 0110 = D6₁₆

Hex to Decimal:
2A3₁₆ = 2×256 + 10×16 + 3×1 = 675₁₀
```

**Octal (Base 8):**
```
Binary to Octal (group by 3 bits):
11010110₂ = 011 010 110 = 326₈

Octal uses digits 0-7
```

**Binary Arithmetic:**
```
Binary Addition:
  1101  (13)
+ 1011  (11)
------
 11000  (24)

Rules:
0 + 0 = 0
0 + 1 = 1
1 + 0 = 1
1 + 1 = 10 (carry 1)

Binary Subtraction:
  1101  (13)
- 1011  (11)
------
  0010  (2)

Rules:
0 - 0 = 0
1 - 0 = 1
1 - 1 = 0
0 - 1 = 1 (borrow from next bit)

Binary Multiplication:
    1101  (13)
  × 1011  (11)
  ------
    1101
   0000
  1101
 1101
--------
10001111  (143)
```

**Two's Complement (Negative Numbers):**
```
8-bit Two's Complement Range: -128 to +127

Positive: 5 = 00000101
Negative: -5
Step 1: 00000101 (original)
Step 2: 11111010 (flip all bits)
Step 3: 11111011 (add 1) = -5

Why Two's Complement?
Addition works normally:
   5: 00000101
+ (-5): 11111011
-----------
   0: 00000000 (carry discarded)
```

**Bit Manipulation Operations:**
```python
# Bitwise AND (&)
12 & 10  # 1100 & 1010 = 1000 = 8
# Use: Check if specific bits are set, clear bits

# Bitwise OR (|)
12 | 10  # 1100 | 1010 = 1110 = 14
# Use: Set specific bits

# Bitwise XOR (^)
12 ^ 10  # 1100 ^ 1010 = 0110 = 6
# Use: Toggle bits, find differences

# Bitwise NOT (~)
~12  # ~1100 = ...11110011 (depends on word size)
# Use: Flip all bits

# Left Shift (<<)
12 << 2  # 1100 << 2 = 110000 = 48
# Use: Multiply by 2^n

# Right Shift (>>)
12 >> 2  # 1100 >> 2 = 11 = 3
# Use: Divide by 2^n (for positive numbers)

# Arithmetic Right Shift (sign extension)
-12 >> 2  # Fills with sign bit for negative numbers
```

**Common Bit Manipulation Tricks:**
```python
def check_bit(num, pos):
    """Check if bit at position is set"""
    return (num & (1 << pos)) != 0

def set_bit(num, pos):
    """Set bit at position"""
    return num | (1 << pos)

def clear_bit(num, pos):
    """Clear bit at position"""
    return num & ~(1 << pos)

def toggle_bit(num, pos):
    """Toggle bit at position"""
    return num ^ (1 << pos)

def count_set_bits(num):
    """Count number of 1s in binary representation"""
    count = 0
    while num:
        count += num & 1
        num >>= 1
    return count

def is_power_of_two(num):
    """Check if number is power of 2"""
    return num > 0 and (num & (num - 1)) == 0

def swap_without_temp(a, b):
    """Swap two numbers without temporary variable"""
    a = a ^ b
    b = a ^ b
    a = a ^ b
    return a, b

def find_single_number(arr):
    """Find number that appears once (others appear twice)"""
    result = 0
    for num in arr:
        result ^= num
    return result

def reverse_bits(num, bit_length=8):
    """Reverse bits in a number"""
    result = 0
    for i in range(bit_length):
        if num & (1 << i):
            result |= (1 << (bit_length - 1 - i))
    return result
```

**Data Representation:**
```python
# Integer Representation
import struct

# 32-bit signed integer
value = -123
binary_repr = format(value & 0xFFFFFFFF, '032b')
print(f"{value} in 32-bit binary: {binary_repr}")

# Floating Point (IEEE 754)
# 32-bit float: 1 sign bit + 8 exponent bits + 23 mantissa bits
def float_to_binary(f):
    """Convert float to IEEE 754 binary representation"""
    import struct
    packed = struct.pack('!f', f)
    integer = struct.unpack('!I', packed)[0]
    return format(integer, '032b')

print(f"3.14 in IEEE 754: {float_to_binary(3.14)}")

# Character Encoding
char = 'A'
ascii_value = ord(char)
print(f"'{char}' = {ascii_value} = {format(ascii_value, '08b')}")

# UTF-8 encoding for unicode
text = "Hello 世界"
utf8_bytes = text.encode('utf-8')
print(f"UTF-8 bytes: {[hex(b) for b in utf8_bytes]}")
```

**Endianness:**
```python
import struct

# Big-endian vs Little-endian byte order
value = 0x12345678

# Big-endian (most significant byte first)
big_endian = struct.pack('>I', value)
print(f"Big-endian bytes: {[hex(b) for b in big_endian]}")
# Output: ['0x12', '0x34', '0x56', '0x78']

# Little-endian (least significant byte first)
little_endian = struct.pack('<I', value)
print(f"Little-endian bytes: {[hex(b) for b in little_endian]}")
# Output: ['0x78', '0x56', '0x34', '0x12']

# Check system endianness
import sys
print(f"System byte order: {sys.byteorder}")

# Network byte order (always big-endian)
network_order = struct.pack('!I', value)  # '!' means network order
```

**Overflow and Underflow:**
```python
# 8-bit unsigned integer overflow
max_8bit = 255  # 11111111
overflow = max_8bit + 1  # Would be 100000000, but stored as 00000000 = 0

# 8-bit signed integer overflow (two's complement)
max_signed_8bit = 127   # 01111111
overflow_signed = max_signed_8bit + 1  # 10000000 = -128

# Example in Python (simulating 8-bit)
def add_8bit_unsigned(a, b):
    result = a + b
    return result & 0xFF  # Keep only lower 8 bits

def add_8bit_signed(a, b):
    result = a + b
    # Convert to signed 8-bit range
    if result > 127:
        result -= 256
    elif result < -128:
        result += 256
    return result

print(f"255 + 1 (8-bit unsigned): {add_8bit_unsigned(255, 1)}")  # 0
print(f"127 + 1 (8-bit signed): {add_8bit_signed(127, 1)}")    # -128
```

### Boolean Logic

Foundation of digital circuits and programming logic.

**Basic Operations:**
```
AND (∧): true ∧ true = true
OR (∨):  false ∨ true = true
NOT (¬): ¬true = false
XOR (⊕): true ⊕ true = false
```

**De Morgan's Laws:**
```
¬(A ∧ B) = ¬A ∨ ¬B
¬(A ∨ B) = ¬A ∧ ¬B
```

**Truth Tables:**
```
A | B | A∧B | A∨B | A⊕B
--|---|-----|-----|----
0 | 0 |  0  |  0  |  0
0 | 1 |  0  |  1  |  1
1 | 0 |  0  |  1  |  1
1 | 1 |  1  |  1  |  0
```

# Computer Hardware Fundamentals

Understanding the physical components that execute computer programs.

## CPU (Central Processing Unit)

**Architecture Components:**
```
Control Unit    - Fetches and decodes instructions
ALU            - Performs arithmetic and logical operations
Registers      - High-speed temporary storage
Cache          - Fast memory close to CPU cores
```

**Instruction Cycle:**
```python
def cpu_cycle():
    """Basic fetch-decode-execute cycle"""
    while True:
        instruction = fetch_from_memory(PC)  # Program Counter
        decoded = decode_instruction(instruction)
        result = execute(decoded)
        PC += 1  # Move to next instruction
```

**CPU Performance Factors:**
```
Clock Speed    - Cycles per second (GHz)
Cores          - Independent processing units
Cache Size     - L1, L2, L3 cache hierarchy
Architecture   - x86, ARM, RISC-V
```

## Memory Hierarchy

**Storage Levels (fastest to slowest):**
```
Registers      - CPU internal, ~1 cycle access
L1 Cache       - 32KB-64KB, ~1-3 cycles
L2 Cache       - 256KB-1MB, ~10-20 cycles
L3 Cache       - 8MB-32MB, ~40-75 cycles
RAM            - GBs, ~100-300 cycles
SSD            - ~10,000 cycles
HDD            - ~10,000,000 cycles
```

**Memory Management:**
```python
class MemoryHierarchy:
    def __init__(self):
        self.l1_cache = {}  # Fastest, smallest
        self.l2_cache = {}  # Medium speed/size
        self.ram = {}       # Slower, larger

    def read(self, address):
        if address in self.l1_cache:
            return self.l1_cache[address]  # Cache hit
        elif address in self.l2_cache:
            # Move to L1 for faster future access
            data = self.l2_cache[address]
            self.l1_cache[address] = data
            return data
        else:
            # Load from RAM to all cache levels
            data = self.ram[address]
            self.l2_cache[address] = data
            self.l1_cache[address] = data
            return data
```

## Storage Systems

**Storage Types:**
```
SRAM (Static)   - Cache memory, no refresh needed
DRAM (Dynamic)  - Main memory, needs refresh
SSD (Flash)     - Non-volatile, no moving parts
HDD (Magnetic)  - Non-volatile, mechanical
```

**RAID Configurations:**
```python
def raid_comparison():
    """Different RAID levels and their characteristics"""
    return {
        'RAID 0': {'redundancy': False, 'performance': 'High', 'capacity': '100%'},
        'RAID 1': {'redundancy': True, 'performance': 'Medium', 'capacity': '50%'},
        'RAID 5': {'redundancy': True, 'performance': 'Good', 'capacity': '75%'},
        'RAID 10': {'redundancy': True, 'performance': 'Very High', 'capacity': '50%'}
    }
```

## Input/Output Systems

**I/O Communication:**
```
Polling        - CPU repeatedly checks device status
Interrupts     - Device signals CPU when ready
DMA           - Direct Memory Access, bypasses CPU
```

**Bus Architecture:**
```python
class SystemBus:
    def __init__(self):
        self.address_bus = 64  # bits (determines max memory)
        self.data_bus = 64     # bits (data transfer width)
        self.control_bus = []  # control signals

    def transfer_data(self, source_addr, dest_addr, size):
        # 1. Place source address on address bus
        # 2. Send read control signal
        # 3. Data appears on data bus
        # 4. Place destination address on address bus
        # 5. Send write control signal
        pass
```

**Peripheral Interfaces:**
```
USB            - Universal Serial Bus, hot-pluggable
PCIe           - High-speed expansion slots
SATA           - Storage device interface
Ethernet       - Network connectivity
```

### Basic Complexity Analysis

Understanding how algorithms scale with input size.

**Growth Rates (fastest to slowest):**
```
O(1)        - Constant
O(log n)    - Logarithmic
O(n)        - Linear
O(n log n)  - Linearithmic
O(n²)       - Quadratic
O(2ⁿ)       - Exponential
```

**Example Analysis:**
```python
# O(1) - Constant time
def get_first(arr):
    return arr[0]

# O(n) - Linear time
def find_max(arr):
    max_val = arr[0]
    for item in arr:  # n iterations
        if item > max_val:
            max_val = item
    return max_val

# O(n²) - Quadratic time
def bubble_sort(arr):
    n = len(arr)
    for i in range(n):      # n iterations
        for j in range(n-1): # n iterations
            if arr[j] > arr[j+1]:
                arr[j], arr[j+1] = arr[j+1], arr[j]
```

---

# Algorithms

### Algorithm Basics

An algorithm is a step-by-step procedure for solving a problem.

**Properties of Good Algorithms:**
- **Correctness** - Produces correct output
- **Efficiency** - Uses minimal time/space
- **Clarity** - Easy to understand and implement
- **Generality** - Works for all valid inputs

**Algorithm Design Strategies:**
```
1. Brute Force    - Try all possibilities
2. Divide & Conquer - Break into subproblems
3. Greedy         - Make locally optimal choices
4. Dynamic Programming - Store subproblem solutions
5. Backtracking   - Try solutions, undo if needed
```

### Searching Algorithms

Finding elements in data structures.

**Linear Search:**
```python
def linear_search(arr, target):
    for i in range(len(arr)):
        if arr[i] == target:
            return i
    return -1

# Time: O(n), Space: O(1)
```

**Binary Search:**
```python
def binary_search(arr, target):
    left, right = 0, len(arr) - 1

    while left <= right:
        mid = (left + right) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            left = mid + 1
        else:
            right = mid - 1

    return -1

# Time: O(log n), Space: O(1)
# Requires sorted array
```

**Binary Search Tree Search:**
```python
class TreeNode:
    def __init__(self, val):
        self.val = val
        self.left = None
        self.right = None

def search_bst(root, target):
    if not root or root.val == target:
        return root

    if target < root.val:
        return search_bst(root.left, target)
    return search_bst(root.right, target)

# Time: O(log n) average, O(n) worst
```

### Sorting Algorithms

Arranging elements in order.

**Bubble Sort:**
```python
def bubble_sort(arr):
    n = len(arr)
    for i in range(n):
        swapped = False
        for j in range(0, n - i - 1):
            if arr[j] > arr[j + 1]:
                arr[j], arr[j + 1] = arr[j + 1], arr[j]
                swapped = True
        if not swapped:  # Optimization
            break
    return arr

# Time: O(n²), Space: O(1)
# Stable: Yes
```

**Selection Sort:**
```python
def selection_sort(arr):
    n = len(arr)
    for i in range(n):
        min_idx = i
        for j in range(i + 1, n):
            if arr[j] < arr[min_idx]:
                min_idx = j
        arr[i], arr[min_idx] = arr[min_idx], arr[i]
    return arr

# Time: O(n²), Space: O(1)
# Stable: No
```

**Insertion Sort:**
```python
def insertion_sort(arr):
    for i in range(1, len(arr)):
        key = arr[i]
        j = i - 1
        while j >= 0 and arr[j] > key:
            arr[j + 1] = arr[j]
            j -= 1
        arr[j + 1] = key
    return arr

# Time: O(n²), Space: O(1)
# Stable: Yes, Good for small arrays
```

**Merge Sort:**
```python
def merge_sort(arr):
    if len(arr) <= 1:
        return arr

    mid = len(arr) // 2
    left = merge_sort(arr[:mid])
    right = merge_sort(arr[mid:])

    return merge(left, right)

def merge(left, right):
    result = []
    i = j = 0

    while i < len(left) and j < len(right):
        if left[i] <= right[j]:
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1

    result.extend(left[i:])
    result.extend(right[j:])
    return result

# Time: O(n log n), Space: O(n)
# Stable: Yes, Divide & Conquer
```

**Quick Sort:**
```python
def quick_sort(arr, low=0, high=None):
    if high is None:
        high = len(arr) - 1

    if low < high:
        pi = partition(arr, low, high)
        quick_sort(arr, low, pi - 1)
        quick_sort(arr, pi + 1, high)

    return arr

def partition(arr, low, high):
    pivot = arr[high]  # Choose last element as pivot
    i = low - 1

    for j in range(low, high):
        if arr[j] <= pivot:
            i += 1
            arr[i], arr[j] = arr[j], arr[i]

    arr[i + 1], arr[high] = arr[high], arr[i + 1]
    return i + 1

# Time: O(n log n) average, O(n²) worst
# Space: O(log n), In-place: Yes
```

### Recursion

Function calling itself to solve smaller subproblems.

**Recursion Components:**
1. **Base Case** - Stopping condition
2. **Recursive Case** - Function calls itself

**Factorial:**
```python
def factorial(n):
    # Base case
    if n <= 1:
        return 1
    # Recursive case
    return n * factorial(n - 1)

# factorial(5) = 5 * 4 * 3 * 2 * 1 = 120
```

**Fibonacci:**
```python
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)

# Time: O(2ⁿ) - Inefficient
# Can be optimized with memoization
```

**Fibonacci with Memoization:**
```python
def fibonacci_memo(n, memo={}):
    if n in memo:
        return memo[n]

    if n <= 1:
        return n

    memo[n] = fibonacci_memo(n - 1, memo) + fibonacci_memo(n - 2, memo)
    return memo[n]

# Time: O(n), Space: O(n)
```

**Tree Traversal:**
```python
def inorder_traversal(root):
    if root:
        inorder_traversal(root.left)   # Left
        print(root.val)                # Root
        inorder_traversal(root.right)  # Right

def preorder_traversal(root):
    if root:
        print(root.val)                # Root
        preorder_traversal(root.left)  # Left
        preorder_traversal(root.right) # Right

def postorder_traversal(root):
    if root:
        postorder_traversal(root.left)  # Left
        postorder_traversal(root.right) # Right
        print(root.val)                 # Root
```

---

# Data Structures

### Arrays

Collection of elements stored in contiguous memory locations.

**Basic Operations:**
```python
# Static array (fixed size)
arr = [0] * 5  # [0, 0, 0, 0, 0]

# Dynamic array (resizable)
arr = []
arr.append(1)    # Add element - O(1) amortized
arr.insert(0, 5) # Insert at index - O(n)
arr.pop()        # Remove last - O(1)
arr.pop(0)       # Remove at index - O(n)
arr[2] = 10      # Access/Update - O(1)
```

**2D Arrays:**
```python
# Create 3x3 matrix
matrix = [[0 for _ in range(3)] for _ in range(3)]

# Access element
matrix[1][2] = 5

# Traverse
for i in range(len(matrix)):
    for j in range(len(matrix[0])):
        print(matrix[i][j])
```

**Array Algorithms:**
```python
# Reverse array
def reverse_array(arr):
    left, right = 0, len(arr) - 1
    while left < right:
        arr[left], arr[right] = arr[right], arr[left]
        left += 1
        right -= 1

# Rotate array right by k positions
def rotate_array(arr, k):
    n = len(arr)
    k %= n
    reverse_array(arr)
    reverse_array(arr[:k])
    reverse_array(arr[k:])

# Two pointers technique
def two_sum_sorted(arr, target):
    left, right = 0, len(arr) - 1
    while left < right:
        current_sum = arr[left] + arr[right]
        if current_sum == target:
            return [left, right]
        elif current_sum < target:
            left += 1
        else:
            right -= 1
    return []
```

### Linked Lists

Linear data structure where elements are stored in nodes.

**Singly Linked List:**
```python
class ListNode:
    def __init__(self, val=0):
        self.val = val
        self.next = None

class LinkedList:
    def __init__(self):
        self.head = None

    def append(self, val):
        new_node = ListNode(val)
        if not self.head:
            self.head = new_node
            return

        current = self.head
        while current.next:
            current = current.next
        current.next = new_node

    def prepend(self, val):
        new_node = ListNode(val)
        new_node.next = self.head
        self.head = new_node

    def delete(self, val):
        if not self.head:
            return

        if self.head.val == val:
            self.head = self.head.next
            return

        current = self.head
        while current.next and current.next.val != val:
            current = current.next

        if current.next:
            current.next = current.next.next

    def find(self, val):
        current = self.head
        while current:
            if current.val == val:
                return current
            current = current.next
        return None

# Time Complexities:
# Access: O(n), Search: O(n)
# Insertion: O(1) at head, O(n) at tail
# Deletion: O(1) if node given, O(n) to find
```

**Doubly Linked List:**
```python
class DoublyListNode:
    def __init__(self, val=0):
        self.val = val
        self.next = None
        self.prev = None

class DoublyLinkedList:
    def __init__(self):
        self.head = None
        self.tail = None

    def append(self, val):
        new_node = DoublyListNode(val)
        if not self.head:
            self.head = self.tail = new_node
        else:
            self.tail.next = new_node
            new_node.prev = self.tail
            self.tail = new_node

    def delete(self, node):
        if node.prev:
            node.prev.next = node.next
        else:
            self.head = node.next

        if node.next:
            node.next.prev = node.prev
        else:
            self.tail = node.prev
```

**Linked List Algorithms:**
```python
# Reverse linked list
def reverse_linked_list(head):
    prev = None
    current = head

    while current:
        next_temp = current.next
        current.next = prev
        prev = current
        current = next_temp

    return prev

# Detect cycle (Floyd's Algorithm)
def has_cycle(head):
    if not head or not head.next:
        return False

    slow = fast = head

    while fast and fast.next:
        slow = slow.next
        fast = fast.next.next
        if slow == fast:
            return True

    return False

# Find middle node
def find_middle(head):
    slow = fast = head

    while fast and fast.next:
        slow = slow.next
        fast = fast.next.next

    return slow

# Merge two sorted lists
def merge_sorted_lists(l1, l2):
    dummy = ListNode(0)
    current = dummy

    while l1 and l2:
        if l1.val <= l2.val:
            current.next = l1
            l1 = l1.next
        else:
            current.next = l2
            l2 = l2.next
        current = current.next

    current.next = l1 or l2
    return dummy.next
```

### Stacks

Last-In-First-Out (LIFO) data structure.

**Implementation:**
```python
class Stack:
    def __init__(self):
        self.items = []

    def push(self, item):
        self.items.append(item)  # O(1)

    def pop(self):
        if self.is_empty():
            raise IndexError("Stack is empty")
        return self.items.pop()  # O(1)

    def peek(self):
        if self.is_empty():
            raise IndexError("Stack is empty")
        return self.items[-1]    # O(1)

    def is_empty(self):
        return len(self.items) == 0

    def size(self):
        return len(self.items)

# Using list as stack
stack = []
stack.append(1)    # push
stack.append(2)    # push
top = stack.pop()  # pop -> 2
```

**Stack Applications:**
```python
# Balanced parentheses
def is_balanced(s):
    stack = []
    mapping = {')': '(', '}': '{', ']': '['}

    for char in s:
        if char in mapping:
            if not stack or stack.pop() != mapping[char]:
                return False
        else:
            stack.append(char)

    return not stack

# Evaluate postfix expression
def evaluate_postfix(expression):
    stack = []
    operators = {'+', '-', '*', '/'}

    for token in expression.split():
        if token in operators:
            b = stack.pop()
            a = stack.pop()
            if token == '+':
                result = a + b
            elif token == '-':
                result = a - b
            elif token == '*':
                result = a * b
            elif token == '/':
                result = a / b
            stack.append(result)
        else:
            stack.append(float(token))

    return stack[0]

# Convert infix to postfix (Shunting Yard)
def infix_to_postfix(expression):
    precedence = {'+': 1, '-': 1, '*': 2, '/': 2, '^': 3}
    output = []
    operator_stack = []

    for token in expression.split():
        if token.isdigit():
            output.append(token)
        elif token == '(':
            operator_stack.append(token)
        elif token == ')':
            while operator_stack and operator_stack[-1] != '(':
                output.append(operator_stack.pop())
            operator_stack.pop()  # Remove '('
        elif token in precedence:
            while (operator_stack and
                   operator_stack[-1] != '(' and
                   precedence.get(operator_stack[-1], 0) >= precedence[token]):
                output.append(operator_stack.pop())
            operator_stack.append(token)

    while operator_stack:
        output.append(operator_stack.pop())

    return ' '.join(output)
```

### Queues

First-In-First-Out (FIFO) data structure.

**Queue Implementation:**
```python
from collections import deque

class Queue:
    def __init__(self):
        self.items = deque()

    def enqueue(self, item):
        self.items.append(item)      # O(1)

    def dequeue(self):
        if self.is_empty():
            raise IndexError("Queue is empty")
        return self.items.popleft()  # O(1)

    def front(self):
        if self.is_empty():
            raise IndexError("Queue is empty")
        return self.items[0]

    def is_empty(self):
        return len(self.items) == 0

    def size(self):
        return len(self.items)

# Using deque as queue
queue = deque()
queue.append(1)      # enqueue
queue.append(2)      # enqueue
first = queue.popleft()  # dequeue -> 1
```

**Circular Queue:**
```python
class CircularQueue:
    def __init__(self, size):
        self.size = size
        self.queue = [None] * size
        self.front = self.rear = -1

    def enqueue(self, data):
        if self.is_full():
            return False

        if self.front == -1:  # First element
            self.front = self.rear = 0
        else:
            self.rear = (self.rear + 1) % self.size

        self.queue[self.rear] = data
        return True

    def dequeue(self):
        if self.is_empty():
            return None

        data = self.queue[self.front]

        if self.front == self.rear:  # Last element
            self.front = self.rear = -1
        else:
            self.front = (self.front + 1) % self.size

        return data

    def is_empty(self):
        return self.front == -1

    def is_full(self):
        return (self.rear + 1) % self.size == self.front
```

**Priority Queue:**
```python
import heapq

class PriorityQueue:
    def __init__(self):
        self.heap = []

    def push(self, priority, item):
        heapq.heappush(self.heap, (priority, item))

    def pop(self):
        if self.is_empty():
            raise IndexError("Priority queue is empty")
        return heapq.heappop(self.heap)[1]

    def is_empty(self):
        return len(self.heap) == 0

# For max heap, negate the priority
pq = PriorityQueue()
pq.push(3, "Low priority")
pq.push(1, "High priority")
pq.push(2, "Medium priority")

print(pq.pop())  # "High priority"
```

### Hash Tables

Data structure that maps keys to values using a hash function.

**Hash Table Implementation:**
```python
class HashTable:
    def __init__(self, size=10):
        self.size = size
        self.table = [[] for _ in range(size)]  # Chaining for collisions

    def _hash(self, key):
        return hash(key) % self.size

    def put(self, key, value):
        hash_index = self._hash(key)
        bucket = self.table[hash_index]

        # Update existing key
        for i, (k, v) in enumerate(bucket):
            if k == key:
                bucket[i] = (key, value)
                return

        # Add new key-value pair
        bucket.append((key, value))

    def get(self, key):
        hash_index = self._hash(key)
        bucket = self.table[hash_index]

        for k, v in bucket:
            if k == key:
                return v

        raise KeyError(key)

    def delete(self, key):
        hash_index = self._hash(key)
        bucket = self.table[hash_index]

        for i, (k, v) in enumerate(bucket):
            if k == key:
                del bucket[i]
                return

        raise KeyError(key)

# Time Complexity:
# Average: O(1) for all operations
# Worst: O(n) if all keys hash to same bucket
```

**Hash Function Examples:**
```python
# Simple hash functions
def simple_hash(key, table_size):
    return sum(ord(c) for c in str(key)) % table_size

def djb2_hash(key, table_size):
    hash_value = 5381
    for char in str(key):
        hash_value = ((hash_value << 5) + hash_value) + ord(char)
    return hash_value % table_size

# Handling collisions
class HashTableOpenAddressing:
    def __init__(self, size=10):
        self.size = size
        self.keys = [None] * size
        self.values = [None] * size

    def _hash(self, key):
        return hash(key) % self.size

    def _probe(self, key):
        index = self._hash(key)

        while self.keys[index] is not None:
            if self.keys[index] == key:
                return index
            index = (index + 1) % self.size  # Linear probing

        return index

    def put(self, key, value):
        index = self._probe(key)
        self.keys[index] = key
        self.values[index] = value

    def get(self, key):
        index = self._hash(key)

        while self.keys[index] is not None:
            if self.keys[index] == key:
                return self.values[index]
            index = (index + 1) % self.size

        raise KeyError(key)
```

---

# Time and Space Complexity

### Big O Notation

Mathematical notation describing algorithm efficiency.

**Common Time Complexities:**
```python
# O(1) - Constant
def get_first_element(arr):
    return arr[0]

# O(log n) - Logarithmic
def binary_search(arr, target):
    left, right = 0, len(arr) - 1
    while left <= right:
        mid = (left + right) // 2
        if arr[mid] == target:
            return mid
        elif arr[mid] < target:
            left = mid + 1
        else:
            right = mid - 1
    return -1

# O(n) - Linear
def linear_search(arr, target):
    for i, val in enumerate(arr):
        if val == target:
            return i
    return -1

# O(n log n) - Linearithmic
def merge_sort(arr):
    if len(arr) <= 1:
        return arr

    mid = len(arr) // 2
    left = merge_sort(arr[:mid])
    right = merge_sort(arr[mid:])
    return merge(left, right)

# O(n²) - Quadratic
def bubble_sort(arr):
    n = len(arr)
    for i in range(n):
        for j in range(n - 1 - i):
            if arr[j] > arr[j + 1]:
                arr[j], arr[j + 1] = arr[j + 1], arr[j]

# O(2ⁿ) - Exponential
def fibonacci_naive(n):
    if n <= 1:
        return n
    return fibonacci_naive(n - 1) + fibonacci_naive(n - 2)
```

**Complexity Comparison:**
```
Input Size (n) | O(1) | O(log n) | O(n) | O(n log n) | O(n²) | O(2ⁿ)
---------------|------|----------|------|------------|-------|-------
1              | 1    | 1        | 1    | 1          | 1     | 2
10             | 1    | 3        | 10   | 33         | 100   | 1024
100            | 1    | 7        | 100  | 664        | 10K   | 1.3×10³⁰
1000           | 1    | 10       | 1K   | 9966       | 1M    | Impossible
```

### Best, Average, Worst Case

**Example: Quick Sort Analysis**
```python
def quick_sort_analysis(arr):
    # Best Case: O(n log n)
    # - Pivot always divides array in half
    # - log n levels, n work per level

    # Average Case: O(n log n)
    # - Random pivot selection
    # - Expected balanced partitions

    # Worst Case: O(n²)
    # - Pivot is always smallest/largest
    # - Creates unbalanced partitions
    # - Happens with already sorted arrays
    pass

# Improving worst case with random pivot
import random

def quick_sort_randomized(arr, low=0, high=None):
    if high is None:
        high = len(arr) - 1

    if low < high:
        # Random pivot selection
        random_index = random.randint(low, high)
        arr[random_index], arr[high] = arr[high], arr[random_index]

        pi = partition(arr, low, high)
        quick_sort_randomized(arr, low, pi - 1)
        quick_sort_randomized(arr, pi + 1, high)
```

### Space Complexity

Amount of memory used by an algorithm.

**Space Complexity Examples:**
```python
# O(1) - Constant space
def reverse_array_inplace(arr):
    left, right = 0, len(arr) - 1
    while left < right:
        arr[left], arr[right] = arr[right], arr[left]
        left += 1
        right -= 1

# O(n) - Linear space
def reverse_array_new(arr):
    return arr[::-1]  # Creates new array

# O(log n) - Logarithmic space (recursion stack)
def binary_search_recursive(arr, target, left=0, right=None):
    if right is None:
        right = len(arr) - 1

    if left > right:
        return -1

    mid = (left + right) // 2
    if arr[mid] == target:
        return mid
    elif arr[mid] < target:
        return binary_search_recursive(arr, target, mid + 1, right)
    else:
        return binary_search_recursive(arr, target, left, mid - 1)

# O(n) - Linear space (recursion stack)
def factorial_recursive(n):
    if n <= 1:
        return 1
    return n * factorial_recursive(n - 1)
```

### Complexity Analysis Examples

**Example 1: Nested Loops**
```python
def example1(arr):
    n = len(arr)
    count = 0

    for i in range(n):        # n iterations
        for j in range(i, n): # n-i iterations
            count += 1

    return count

# Analysis:
# Outer loop: n iterations
# Inner loop: n + (n-1) + (n-2) + ... + 1 = n(n+1)/2
# Time Complexity: O(n²)
```

**Example 2: Divide and Conquer**
```python
def example2(arr):
    if len(arr) <= 1:
        return arr

    mid = len(arr) // 2
    left = example2(arr[:mid])    # T(n/2)
    right = example2(arr[mid:])   # T(n/2)

    # Linear merge operation
    result = []
    i = j = 0
    while i < len(left) and j < len(right):  # O(n)
        if left[i] <= right[j]:
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1

    result.extend(left[i:])
    result.extend(right[j:])
    return result

# Recurrence: T(n) = 2T(n/2) + O(n)
# Solution: T(n) = O(n log n)
```

**Example 3: Multiple Loops**
```python
def example3(arr):
    n = len(arr)

    # First loop: O(n)
    for i in range(n):
        print(arr[i])

    # Second loop: O(n²)
    for i in range(n):
        for j in range(n):
            print(arr[i], arr[j])

    # Third loop: O(n)
    for i in range(n):
        print(arr[i])

# Total: O(n) + O(n²) + O(n) = O(n²)
# Always dominated by the highest complexity
```

**Master Theorem for Divide & Conquer:**
```
T(n) = aT(n/b) + f(n)

Case 1: f(n) = O(n^(log_b(a) - ε)) → T(n) = O(n^log_b(a))
Case 2: f(n) = O(n^log_b(a))       → T(n) = O(n^log_b(a) * log n)
Case 3: f(n) = O(n^(log_b(a) + ε)) → T(n) = O(f(n))

Examples:
- Merge Sort: T(n) = 2T(n/2) + O(n) → Case 2 → O(n log n)
- Binary Search: T(n) = T(n/2) + O(1) → Case 2 → O(log n)
- Strassen's Matrix: T(n) = 7T(n/2) + O(n²) → Case 1 → O(n^log₂7)
```

---

# Programming Paradigms

### Procedural Programming

Programming style based on procedures/functions that operate on data.

**Key Concepts:**
- **Procedures/Functions** - Reusable code blocks
- **Sequential Execution** - Top-to-bottom flow
- **Global/Local Variables** - Data scope management
- **Modularity** - Breaking code into functions

**Example:**
```python
# Procedural approach to calculate area
def calculate_rectangle_area(length, width):
    return length * width

def calculate_circle_area(radius):
    import math
    return math.pi * radius ** 2

def calculate_triangle_area(base, height):
    return 0.5 * base * height

# Main program
shapes = [
    ('rectangle', 5, 3),
    ('circle', 4),
    ('triangle', 6, 8)
]

for shape_data in shapes:
    if shape_data[0] == 'rectangle':
        area = calculate_rectangle_area(shape_data[1], shape_data[2])
    elif shape_data[0] == 'circle':
        area = calculate_circle_area(shape_data[1])
    elif shape_data[0] == 'triangle':
        area = calculate_triangle_area(shape_data[1], shape_data[2])

    print(f"{shape_data[0]} area: {area}")
```

**Advantages:**
- Simple and straightforward
- Easy to understand for beginners
- Good for small programs

**Disadvantages:**
- Code reusability issues
- Difficult to maintain large programs
- Global variables can cause issues

### Object-Oriented Programming

Programming paradigm based on objects that contain data and methods.

**Four Pillars of OOP:**

**1. Encapsulation:**
```python
class BankAccount:
    def __init__(self, initial_balance=0):
        self._balance = initial_balance  # Protected attribute

    def deposit(self, amount):
        if amount > 0:
            self._balance += amount
            return True
        return False

    def withdraw(self, amount):
        if 0 < amount <= self._balance:
            self._balance -= amount
            return True
        return False

    def get_balance(self):
        return self._balance

# Usage
account = BankAccount(100)
account.deposit(50)
print(account.get_balance())  # 150
# account._balance = 1000000  # Bad practice, breaks encapsulation
```

**2. Inheritance:**
```python
class Animal:
    def __init__(self, name, species):
        self.name = name
        self.species = species

    def speak(self):
        pass

    def info(self):
        return f"{self.name} is a {self.species}"

class Dog(Animal):
    def __init__(self, name, breed):
        super().__init__(name, "Dog")
        self.breed = breed

    def speak(self):
        return "Woof!"

    def fetch(self):
        return f"{self.name} is fetching the ball"

class Cat(Animal):
    def __init__(self, name, color):
        super().__init__(name, "Cat")
        self.color = color

    def speak(self):
        return "Meow!"

    def climb(self):
        return f"{self.name} is climbing a tree"

# Usage
dog = Dog("Buddy", "Golden Retriever")
cat = Cat("Whiskers", "Orange")

print(dog.speak())    # "Woof!"
print(cat.speak())    # "Meow!"
print(dog.info())     # "Buddy is a Dog"
```

**3. Polymorphism:**
```python
def animal_sound(animal):
    return animal.speak()  # Works with any animal

animals = [Dog("Rex", "Labrador"), Cat("Fluffy", "Persian")]

for animal in animals:
    print(f"{animal.name}: {animal_sound(animal)}")

# Method overloading (using default parameters)
class Calculator:
    def add(self, a, b=0, c=0):
        return a + b + c

calc = Calculator()
print(calc.add(5))        # 5
print(calc.add(5, 3))     # 8
print(calc.add(5, 3, 2))  # 10
```

**4. Abstraction:**
```python
from abc import ABC, abstractmethod

class Shape(ABC):
    @abstractmethod
    def area(self):
        pass

    @abstractmethod
    def perimeter(self):
        pass

class Rectangle(Shape):
    def __init__(self, length, width):
        self.length = length
        self.width = width

    def area(self):
        return self.length * self.width

    def perimeter(self):
        return 2 * (self.length + self.width)

class Circle(Shape):
    def __init__(self, radius):
        self.radius = radius

    def area(self):
        import math
        return math.pi * self.radius ** 2

    def perimeter(self):
        import math
        return 2 * math.pi * self.radius

# Usage
shapes = [Rectangle(5, 3), Circle(4)]
for shape in shapes:
    print(f"Area: {shape.area():.2f}")
```

**Design Patterns:**
```python
# Singleton Pattern
class DatabaseConnection:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def connect(self):
        return "Connected to database"

# Factory Pattern
class ShapeFactory:
    @staticmethod
    def create_shape(shape_type, *args):
        if shape_type == "rectangle":
            return Rectangle(*args)
        elif shape_type == "circle":
            return Circle(*args)
        else:
            raise ValueError(f"Unknown shape: {shape_type}")

# Observer Pattern
class Subject:
    def __init__(self):
        self._observers = []

    def attach(self, observer):
        self._observers.append(observer)

    def detach(self, observer):
        self._observers.remove(observer)

    def notify(self, message):
        for observer in self._observers:
            observer.update(message)

class Observer:
    def __init__(self, name):
        self.name = name

    def update(self, message):
        print(f"{self.name} received: {message}")
```

### Functional Programming

Programming paradigm based on mathematical functions and avoiding state changes.

**Key Concepts:**

**1. Pure Functions:**
```python
# Pure function - same input always gives same output
def add(x, y):
    return x + y

# Impure function - depends on external state
counter = 0
def increment():
    global counter
    counter += 1
    return counter

# Pure function alternative
def pure_increment(current_value):
    return current_value + 1
```

**2. Immutability:**
```python
# Instead of modifying existing data
def add_item_mutable(lst, item):
    lst.append(item)  # Modifies original list
    return lst

# Create new data structures
def add_item_immutable(lst, item):
    return lst + [item]  # Returns new list

# Using tuple (immutable)
original = (1, 2, 3)
new_tuple = original + (4,)  # Creates new tuple
```

**3. Higher-Order Functions:**
```python
# Functions that take other functions as arguments
def apply_operation(numbers, operation):
    return [operation(num) for num in numbers]

def square(x):
    return x ** 2

def cube(x):
    return x ** 3

numbers = [1, 2, 3, 4, 5]
squared = apply_operation(numbers, square)    # [1, 4, 9, 16, 25]
cubed = apply_operation(numbers, cube)        # [1, 8, 27, 64, 125]

# Built-in higher-order functions
numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

# Map - transform each element
squared = list(map(lambda x: x**2, numbers))

# Filter - select elements that meet condition
evens = list(filter(lambda x: x % 2 == 0, numbers))

# Reduce - combine elements into single value
from functools import reduce
sum_all = reduce(lambda x, y: x + y, numbers)
product = reduce(lambda x, y: x * y, numbers)
```

**4. Function Composition:**
```python
def compose(f, g):
    return lambda x: f(g(x))

def add_one(x):
    return x + 1

def multiply_by_two(x):
    return x * 2

# Compose functions
add_then_multiply = compose(multiply_by_two, add_one)
result = add_then_multiply(5)  # (5 + 1) * 2 = 12

# Partial application
from functools import partial

def multiply(x, y):
    return x * y

double = partial(multiply, 2)
triple = partial(multiply, 3)

print(double(5))  # 10
print(triple(5))  # 15
```

**5. Recursion and Tail Recursion:**
```python
# Traditional recursion
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)

# Tail recursion (optimized)
def factorial_tail(n, accumulator=1):
    if n <= 1:
        return accumulator
    return factorial_tail(n - 1, n * accumulator)

# List processing with recursion
def sum_list(lst):
    if not lst:
        return 0
    return lst[0] + sum_list(lst[1:])

def reverse_list(lst):
    if len(lst) <= 1:
        return lst
    return [lst[-1]] + reverse_list(lst[:-1])
```

### Declarative vs Imperative

**Imperative Programming:**
- Describes HOW to do something
- Step-by-step instructions
- Focus on state changes

```python
# Imperative: How to find even numbers
numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
evens = []

for number in numbers:
    if number % 2 == 0:
        evens.append(number)

print(evens)  # [2, 4, 6, 8, 10]
```

**Declarative Programming:**
- Describes WHAT you want
- Express logic without control flow
- Focus on the result

```python
# Declarative: What we want (even numbers)
numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
evens = [num for num in numbers if num % 2 == 0]

# Or using filter
evens = list(filter(lambda x: x % 2 == 0, numbers))

print(evens)  # [2, 4, 6, 8, 10]
```

**SQL Example:**
```sql
-- Declarative: What we want
SELECT name, age
FROM users
WHERE age > 18
ORDER BY age;

-- vs Imperative (pseudocode):
-- 1. Open users table
-- 2. For each row:
--    a. Check if age > 18
--    b. If yes, add to result
-- 3. Sort result by age
-- 4. Return name and age columns
```

---

# Advanced Data Structures

### Trees

Hierarchical data structure with nodes connected by edges.

**Tree Terminology:**
```
         A       <- Root
       /   \
      B     C    <- Internal nodes
     / \   /
    D   E F      <- Leaves
```

**Binary Tree Implementation:**
```python
class TreeNode:
    def __init__(self, val=0):
        self.val = val
        self.left = None
        self.right = None

class BinaryTree:
    def __init__(self):
        self.root = None

    def insert_level_order(self, val):
        new_node = TreeNode(val)

        if not self.root:
            self.root = new_node
            return

        queue = [self.root]
        while queue:
            node = queue.pop(0)

            if not node.left:
                node.left = new_node
                return
            elif not node.right:
                node.right = new_node
                return
            else:
                queue.append(node.left)
                queue.append(node.right)

    # Tree Traversals
    def inorder(self, node, result=None):
        if result is None:
            result = []

        if node:
            self.inorder(node.left, result)
            result.append(node.val)
            self.inorder(node.right, result)

        return result

    def preorder(self, node, result=None):
        if result is None:
            result = []

        if node:
            result.append(node.val)
            self.preorder(node.left, result)
            self.preorder(node.right, result)

        return result

    def postorder(self, node, result=None):
        if result is None:
            result = []

        if node:
            self.postorder(node.left, result)
            self.postorder(node.right, result)
            result.append(node.val)

        return result

    def level_order(self):
        if not self.root:
            return []

        result = []
        queue = [self.root]

        while queue:
            level_size = len(queue)
            level = []

            for _ in range(level_size):
                node = queue.pop(0)
                level.append(node.val)

                if node.left:
                    queue.append(node.left)
                if node.right:
                    queue.append(node.right)

            result.append(level)

        return result
```

**Tree Properties:**
```python
def tree_height(node):
    if not node:
        return -1
    return 1 + max(tree_height(node.left), tree_height(node.right))

def tree_size(node):
    if not node:
        return 0
    return 1 + tree_size(node.left) + tree_size(node.right)

def is_balanced(node):
    if not node:
        return True

    left_height = tree_height(node.left)
    right_height = tree_height(node.right)

    return (abs(left_height - right_height) <= 1 and
            is_balanced(node.left) and
            is_balanced(node.right))

def lowest_common_ancestor(root, p, q):
    if not root or root == p or root == q:
        return root

    left = lowest_common_ancestor(root.left, p, q)
    right = lowest_common_ancestor(root.right, p, q)

    if left and right:
        return root

    return left or right
```

### Binary Search Trees

Binary tree where left subtree < root < right subtree.

**BST Implementation:**
```python
class BST:
    def __init__(self):
        self.root = None

    def insert(self, val):
        self.root = self._insert_recursive(self.root, val)

    def _insert_recursive(self, node, val):
        if not node:
            return TreeNode(val)

        if val < node.val:
            node.left = self._insert_recursive(node.left, val)
        elif val > node.val:
            node.right = self._insert_recursive(node.right, val)

        return node

    def search(self, val):
        return self._search_recursive(self.root, val)

    def _search_recursive(self, node, val):
        if not node or node.val == val:
            return node

        if val < node.val:
            return self._search_recursive(node.left, val)
        return self._search_recursive(node.right, val)

    def delete(self, val):
        self.root = self._delete_recursive(self.root, val)

    def _delete_recursive(self, node, val):
        if not node:
            return node

        if val < node.val:
            node.left = self._delete_recursive(node.left, val)
        elif val > node.val:
            node.right = self._delete_recursive(node.right, val)
        else:
            # Node to delete found
            if not node.left:
                return node.right
            elif not node.right:
                return node.left

            # Node with two children
            min_node = self._find_min(node.right)
            node.val = min_node.val
            node.right = self._delete_recursive(node.right, min_node.val)

        return node

    def _find_min(self, node):
        while node.left:
            node = node.left
        return node

    def find_kth_smallest(self, k):
        result = []
        self._inorder_for_kth(self.root, result, k)
        return result[k-1] if k <= len(result) else None

    def _inorder_for_kth(self, node, result, k):
        if not node or len(result) >= k:
            return

        self._inorder_for_kth(node.left, result, k)
        if len(result) < k:
            result.append(node.val)
        self._inorder_for_kth(node.right, result, k)

# Time Complexities:
# Average: O(log n) for search, insert, delete
# Worst: O(n) when tree becomes linear
```

**AVL Tree (Self-Balancing BST):**
```python
class AVLNode:
    def __init__(self, val):
        self.val = val
        self.left = None
        self.right = None
        self.height = 1

class AVLTree:
    def get_height(self, node):
        if not node:
            return 0
        return node.height

    def get_balance(self, node):
        if not node:
            return 0
        return self.get_height(node.left) - self.get_height(node.right)

    def update_height(self, node):
        if node:
            node.height = 1 + max(self.get_height(node.left),
                                  self.get_height(node.right))

    def rotate_right(self, y):
        x = y.left
        T2 = x.right

        x.right = y
        y.left = T2

        self.update_height(y)
        self.update_height(x)

        return x

    def rotate_left(self, x):
        y = x.right
        T2 = y.left

        y.left = x
        x.right = T2

        self.update_height(x)
        self.update_height(y)

        return y

    def insert(self, root, val):
        # Normal BST insertion
        if not root:
            return AVLNode(val)

        if val < root.val:
            root.left = self.insert(root.left, val)
        elif val > root.val:
            root.right = self.insert(root.right, val)
        else:
            return root

        # Update height
        self.update_height(root)

        # Get balance factor
        balance = self.get_balance(root)

        # Left Left Case
        if balance > 1 and val < root.left.val:
            return self.rotate_right(root)

        # Right Right Case
        if balance < -1 and val > root.right.val:
            return self.rotate_left(root)

        # Left Right Case
        if balance > 1 and val > root.left.val:
            root.left = self.rotate_left(root.left)
            return self.rotate_right(root)

        # Right Left Case
        if balance < -1 and val < root.right.val:
            root.right = self.rotate_right(root.right)
            return self.rotate_left(root)

        return root
```

### Heaps

Complete binary tree with heap property (parent >= children for max heap).

**Binary Heap Implementation:**
```python
class MaxHeap:
    def __init__(self):
        self.heap = []

    def parent(self, i):
        return (i - 1) // 2

    def left_child(self, i):
        return 2 * i + 1

    def right_child(self, i):
        return 2 * i + 2

    def swap(self, i, j):
        self.heap[i], self.heap[j] = self.heap[j], self.heap[i]

    def insert(self, val):
        self.heap.append(val)
        self._heapify_up(len(self.heap) - 1)

    def _heapify_up(self, i):
        while i > 0:
            parent_i = self.parent(i)
            if self.heap[i] <= self.heap[parent_i]:
                break
            self.swap(i, parent_i)
            i = parent_i

    def extract_max(self):
        if not self.heap:
            return None

        if len(self.heap) == 1:
            return self.heap.pop()

        max_val = self.heap[0]
        self.heap[0] = self.heap.pop()
        self._heapify_down(0)
        return max_val

    def _heapify_down(self, i):
        while True:
            largest = i
            left = self.left_child(i)
            right = self.right_child(i)

            if (left < len(self.heap) and
                self.heap[left] > self.heap[largest]):
                largest = left

            if (right < len(self.heap) and
                self.heap[right] > self.heap[largest]):
                largest = right

            if largest == i:
                break

            self.swap(i, largest)
            i = largest

    def peek(self):
        return self.heap[0] if self.heap else None

    def size(self):
        return len(self.heap)

# Time Complexities:
# Insert: O(log n)
# Extract max: O(log n)
# Peek: O(1)
# Build heap: O(n)
```

**Heap Sort:**
```python
def heap_sort(arr):
    # Build max heap
    n = len(arr)
    for i in range(n // 2 - 1, -1, -1):
        heapify(arr, n, i)

    # Extract elements one by one
    for i in range(n - 1, 0, -1):
        arr[0], arr[i] = arr[i], arr[0]
        heapify(arr, i, 0)

    return arr

def heapify(arr, n, i):
    largest = i
    left = 2 * i + 1
    right = 2 * i + 2

    if left < n and arr[left] > arr[largest]:
        largest = left

    if right < n and arr[right] > arr[largest]:
        largest = right

    if largest != i:
        arr[i], arr[largest] = arr[largest], arr[i]
        heapify(arr, n, largest)

# Time: O(n log n), Space: O(1)
```

**Priority Queue using Heap:**
```python
import heapq

class PriorityQueue:
    def __init__(self):
        self.heap = []

    def push(self, priority, item):
        heapq.heappush(self.heap, (priority, item))

    def pop(self):
        if self.heap:
            return heapq.heappop(self.heap)[1]
        return None

    def peek(self):
        if self.heap:
            return self.heap[0][1]
        return None

    def is_empty(self):
        return len(self.heap) == 0

# For max priority queue, negate priorities
class MaxPriorityQueue:
    def __init__(self):
        self.heap = []

    def push(self, priority, item):
        heapq.heappush(self.heap, (-priority, item))

    def pop(self):
        if self.heap:
            return heapq.heappop(self.heap)[1]
        return None
```

### Graphs

Collection of vertices connected by edges.

**Graph Representations:**

**Adjacency Matrix:**
```python
class GraphMatrix:
    def __init__(self, num_vertices):
        self.num_vertices = num_vertices
        self.matrix = [[0] * num_vertices for _ in range(num_vertices)]

    def add_edge(self, u, v, weight=1):
        self.matrix[u][v] = weight
        # For undirected graph:
        # self.matrix[v][u] = weight

    def has_edge(self, u, v):
        return self.matrix[u][v] != 0

    def get_neighbors(self, u):
        neighbors = []
        for v in range(self.num_vertices):
            if self.matrix[u][v] != 0:
                neighbors.append(v)
        return neighbors

# Space: O(V²), Edge lookup: O(1)
```

**Adjacency List:**
```python
from collections import defaultdict

class GraphList:
    def __init__(self):
        self.graph = defaultdict(list)

    def add_edge(self, u, v, weight=1):
        self.graph[u].append((v, weight))
        # For undirected graph:
        # self.graph[v].append((u, weight))

    def has_edge(self, u, v):
        return any(neighbor == v for neighbor, _ in self.graph[u])

    def get_neighbors(self, u):
        return [neighbor for neighbor, _ in self.graph[u]]

    def get_vertices(self):
        vertices = set()
        for u in self.graph:
            vertices.add(u)
            for v, _ in self.graph[u]:
                vertices.add(v)
        return list(vertices)

# Space: O(V + E), Edge lookup: O(degree(V))
```

**Graph Traversal Algorithms:**

**Depth-First Search (DFS):**
```python
def dfs_recursive(graph, start, visited=None):
    if visited is None:
        visited = set()

    visited.add(start)
    print(start, end=' ')

    for neighbor in graph.get_neighbors(start):
        if neighbor not in visited:
            dfs_recursive(graph, neighbor, visited)

def dfs_iterative(graph, start):
    visited = set()
    stack = [start]

    while stack:
        vertex = stack.pop()
        if vertex not in visited:
            visited.add(vertex)
            print(vertex, end=' ')

            # Add neighbors in reverse order for consistent traversal
            neighbors = graph.get_neighbors(vertex)
            for neighbor in reversed(neighbors):
                if neighbor not in visited:
                    stack.append(neighbor)

# Time: O(V + E), Space: O(V)
```

**Breadth-First Search (BFS):**
```python
from collections import deque

def bfs(graph, start):
    visited = set()
    queue = deque([start])
    visited.add(start)

    while queue:
        vertex = queue.popleft()
        print(vertex, end=' ')

        for neighbor in graph.get_neighbors(vertex):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)

def bfs_shortest_path(graph, start, end):
    if start == end:
        return [start]

    visited = set()
    queue = deque([(start, [start])])
    visited.add(start)

    while queue:
        vertex, path = queue.popleft()

        for neighbor in graph.get_neighbors(vertex):
            if neighbor == end:
                return path + [neighbor]

            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor]))

    return None  # No path found

# Time: O(V + E), Space: O(V)
```

### Tries

Tree-like data structure for storing strings with common prefixes.

**Trie Implementation:**
```python
class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end_of_word = False

class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, word):
        node = self.root
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end_of_word = True

    def search(self, word):
        node = self.root
        for char in word:
            if char not in node.children:
                return False
            node = node.children[char]
        return node.is_end_of_word

    def starts_with(self, prefix):
        node = self.root
        for char in prefix:
            if char not in node.children:
                return False
            node = node.children[char]
        return True

    def delete(self, word):
        def _delete_helper(node, word, index):
            if index == len(word):
                if not node.is_end_of_word:
                    return False
                node.is_end_of_word = False
                return len(node.children) == 0

            char = word[index]
            if char not in node.children:
                return False

            should_delete_child = _delete_helper(
                node.children[char], word, index + 1
            )

            if should_delete_child:
                del node.children[char]
                return not node.is_end_of_word and len(node.children) == 0

            return False

        _delete_helper(self.root, word, 0)

    def get_all_words_with_prefix(self, prefix):
        words = []
        node = self.root

        # Navigate to prefix
        for char in prefix:
            if char not in node.children:
                return words
            node = node.children[char]

        # DFS to collect all words
        def dfs(node, current_word):
            if node.is_end_of_word:
                words.append(current_word)

            for char, child_node in node.children.items():
                dfs(child_node, current_word + char)

        dfs(node, prefix)
        return words

    def longest_common_prefix(self, words):
        if not words:
            return ""

        # Insert all words
        for word in words:
            self.insert(word)

        # Find longest common prefix
        node = self.root
        prefix = ""

        while len(node.children) == 1 and not node.is_end_of_word:
            char = next(iter(node.children))
            prefix += char
            node = node.children[char]

        return prefix

# Time Complexities:
# Insert: O(m) where m is length of word
# Search: O(m)
# Prefix search: O(p) where p is length of prefix
# Space: O(ALPHABET_SIZE * N * M) worst case
```

**Trie Applications:**
```python
# Auto-complete system
class AutoComplete:
    def __init__(self):
        self.trie = Trie()

    def add_word(self, word):
        self.trie.insert(word.lower())

    def get_suggestions(self, prefix, max_suggestions=10):
        suggestions = self.trie.get_all_words_with_prefix(prefix.lower())
        return suggestions[:max_suggestions]

# Word search in 2D grid
def word_search_trie(board, words):
    if not board or not board[0]:
        return []

    trie = Trie()
    for word in words:
        trie.insert(word)

    result = []
    rows, cols = len(board), len(board[0])

    def dfs(r, c, node, path):
        if node.is_end_of_word:
            result.append(path)
            node.is_end_of_word = False  # Avoid duplicates

        if r < 0 or r >= rows or c < 0 or c >= cols:
            return

        char = board[r][c]
        if char not in node.children:
            return

        board[r][c] = '#'  # Mark as visited
        child_node = node.children[char]

        # Explore all 4 directions
        for dr, dc in [(0, 1), (1, 0), (0, -1), (-1, 0)]:
            dfs(r + dr, c + dc, child_node, path + char)

        board[r][c] = char  # Restore

    for r in range(rows):
        for c in range(cols):
            dfs(r, c, trie.root, "")

    return result
```

---

# Advanced Algorithms

## Dynamic Programming

Technique for solving problems by breaking them into subproblems and storing results.

**Key Principles:**
- **Optimal Substructure** - Optimal solution contains optimal solutions to subproblems
- **Overlapping Subproblems** - Same subproblems are solved multiple times
- **Memoization** - Store results to avoid recomputation

**Classic DP Problems:**

**Fibonacci (Memoization):**
```python
def fibonacci_memo(n, memo={}):
    if n in memo:
        return memo[n]

    if n <= 1:
        return n

    memo[n] = fibonacci_memo(n-1, memo) + fibonacci_memo(n-2, memo)
    return memo[n]

# Time: O(n), Space: O(n)
```

**Fibonacci (Tabulation):**
```python
def fibonacci_tab(n):
    if n <= 1:
        return n

    dp = [0] * (n + 1)
    dp[1] = 1

    for i in range(2, n + 1):
        dp[i] = dp[i-1] + dp[i-2]

    return dp[n]

# Space optimized
def fibonacci_optimized(n):
    if n <= 1:
        return n

    prev2, prev1 = 0, 1

    for i in range(2, n + 1):
        current = prev1 + prev2
        prev2, prev1 = prev1, current

    return prev1

# Time: O(n), Space: O(1)
```

**Longest Common Subsequence:**
```python
def lcs(text1, text2):
    m, n = len(text1), len(text2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if text1[i-1] == text2[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])

    return dp[m][n]

# To reconstruct the LCS
def lcs_string(text1, text2):
    m, n = len(text1), len(text2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    # Fill the DP table
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if text1[i-1] == text2[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])

    # Backtrack to find the LCS
    lcs = []
    i, j = m, n

    while i > 0 and j > 0:
        if text1[i-1] == text2[j-1]:
            lcs.append(text1[i-1])
            i -= 1
            j -= 1
        elif dp[i-1][j] > dp[i][j-1]:
            i -= 1
        else:
            j -= 1

    return ''.join(reversed(lcs))

# Time: O(m*n), Space: O(m*n)
```

**0/1 Knapsack:**
```python
def knapsack(weights, values, capacity):
    n = len(weights)
    dp = [[0] * (capacity + 1) for _ in range(n + 1)]

    for i in range(1, n + 1):
        for w in range(capacity + 1):
            # Don't take item i-1
            dp[i][w] = dp[i-1][w]

            # Take item i-1 if possible
            if weights[i-1] <= w:
                dp[i][w] = max(dp[i][w],
                             dp[i-1][w - weights[i-1]] + values[i-1])

    return dp[n][capacity]

# Space optimized version
def knapsack_optimized(weights, values, capacity):
    dp = [0] * (capacity + 1)

    for i in range(len(weights)):
        for w in range(capacity, weights[i] - 1, -1):
            dp[w] = max(dp[w], dp[w - weights[i]] + values[i])

    return dp[capacity]

# Time: O(n*W), Space: O(W)
```

**Edit Distance (Levenshtein):**
```python
def edit_distance(word1, word2):
    m, n = len(word1), len(word2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    # Initialize base cases
    for i in range(m + 1):
        dp[i][0] = i  # Delete all characters
    for j in range(n + 1):
        dp[0][j] = j  # Insert all characters

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if word1[i-1] == word2[j-1]:
                dp[i][j] = dp[i-1][j-1]  # No operation needed
            else:
                dp[i][j] = 1 + min(
                    dp[i-1][j],    # Delete
                    dp[i][j-1],    # Insert
                    dp[i-1][j-1]   # Replace
                )

    return dp[m][n]

# Time: O(m*n), Space: O(m*n)
```

**Coin Change:**
```python
def coin_change(coins, amount):
    dp = [float('inf')] * (amount + 1)
    dp[0] = 0

    for i in range(1, amount + 1):
        for coin in coins:
            if coin <= i:
                dp[i] = min(dp[i], dp[i - coin] + 1)

    return dp[amount] if dp[amount] != float('inf') else -1

# Number of ways to make change
def coin_change_ways(coins, amount):
    dp = [0] * (amount + 1)
    dp[0] = 1

    for coin in coins:
        for i in range(coin, amount + 1):
            dp[i] += dp[i - coin]

    return dp[amount]

# Time: O(n*amount), Space: O(amount)
```

## Greedy Algorithms

Make locally optimal choices hoping to find global optimum.

**When to Use Greedy:**
- Problem has optimal substructure
- Greedy choice property holds
- Local optimum leads to global optimum

**Activity Selection:**
```python
def activity_selection(start, finish):
    n = len(start)
    activities = list(range(n))

    # Sort by finish time
    activities.sort(key=lambda i: finish[i])

    selected = [activities[0]]
    last_finish = finish[activities[0]]

    for i in range(1, n):
        activity = activities[i]
        if start[activity] >= last_finish:
            selected.append(activity)
            last_finish = finish[activity]

    return selected

# Time: O(n log n), Space: O(n)
```

**Fractional Knapsack:**
```python
def fractional_knapsack(weights, values, capacity):
    n = len(weights)
    items = [(values[i]/weights[i], weights[i], values[i])
             for i in range(n)]

    # Sort by value-to-weight ratio
    items.sort(reverse=True)

    total_value = 0

    for ratio, weight, value in items:
        if capacity >= weight:
            # Take entire item
            total_value += value
            capacity -= weight
        else:
            # Take fraction of item
            total_value += ratio * capacity
            break

    return total_value

# Time: O(n log n), Space: O(n)
```

**Huffman Coding:**
```python
import heapq
from collections import defaultdict, Counter

class Node:
    def __init__(self, freq, symbol=None, left=None, right=None):
        self.freq = freq
        self.symbol = symbol
        self.left = left
        self.right = right

    def __lt__(self, other):
        return self.freq < other.freq

def huffman_encoding(text):
    if not text:
        return "", {}

    # Count frequencies
    freq = Counter(text)

    # Create priority queue
    heap = [Node(f, s) for s, f in freq.items()]
    heapq.heapify(heap)

    # Build Huffman tree
    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)

        merged = Node(left.freq + right.freq, left=left, right=right)
        heapq.heappush(heap, merged)

    root = heap[0]

    # Generate codes
    codes = {}

    def generate_codes(node, code=""):
        if node.symbol:  # Leaf node
            codes[node.symbol] = code or "0"  # Single char edge case
        else:
            generate_codes(node.left, code + "0")
            generate_codes(node.right, code + "1")

    generate_codes(root)

    # Encode text
    encoded = "".join(codes[char] for char in text)

    return encoded, codes

# Time: O(n log n), Space: O(n)
```

**Dijkstra's Algorithm:**
```python
import heapq

def dijkstra(graph, start):
    distances = {node: float('inf') for node in graph}
    distances[start] = 0
    pq = [(0, start)]
    visited = set()

    while pq:
        current_dist, current = heapq.heappop(pq)

        if current in visited:
            continue

        visited.add(current)

        for neighbor, weight in graph[current]:
            distance = current_dist + weight

            if distance < distances[neighbor]:
                distances[neighbor] = distance
                heapq.heappush(pq, (distance, neighbor))

    return distances

# With path reconstruction
def dijkstra_with_path(graph, start, end):
    distances = {node: float('inf') for node in graph}
    distances[start] = 0
    previous = {node: None for node in graph}
    pq = [(0, start)]
    visited = set()

    while pq:
        current_dist, current = heapq.heappop(pq)

        if current == end:
            break

        if current in visited:
            continue

        visited.add(current)

        for neighbor, weight in graph[current]:
            distance = current_dist + weight

            if distance < distances[neighbor]:
                distances[neighbor] = distance
                previous[neighbor] = current
                heapq.heappush(pq, (distance, neighbor))

    # Reconstruct path
    path = []
    current = end
    while current is not None:
        path.append(current)
        current = previous[current]

    return distances[end], path[::-1]

# Time: O((V + E) log V), Space: O(V)
```

## Backtracking

Systematic trial and error approach that abandons candidates when they cannot lead to valid solutions.

**N-Queens Problem:**
```python
def solve_n_queens(n):
    def is_safe(board, row, col):
        # Check column
        for i in range(row):
            if board[i][col] == 1:
                return False

        # Check diagonals
        for i, j in zip(range(row-1, -1, -1), range(col-1, -1, -1)):
            if board[i][j] == 1:
                return False

        for i, j in zip(range(row-1, -1, -1), range(col+1, n)):
            if board[i][j] == 1:
                return False

        return True

    def backtrack(board, row):
        if row == n:
            return True

        for col in range(n):
            if is_safe(board, row, col):
                board[row][col] = 1

                if backtrack(board, row + 1):
                    return True

                board[row][col] = 0  # Backtrack

        return False

    board = [[0] * n for _ in range(n)]
    if backtrack(board, 0):
        return board
    return None

# Find all solutions
def solve_n_queens_all(n):
    solutions = []

    def backtrack(board, row):
        if row == n:
            solutions.append([row[:] for row in board])
            return

        for col in range(n):
            if is_safe(board, row, col):
                board[row][col] = 1
                backtrack(board, row + 1)
                board[row][col] = 0

    def is_safe(board, row, col):
        for i in range(row):
            if board[i][col] == 1:
                return False

        for i, j in zip(range(row-1, -1, -1), range(col-1, -1, -1)):
            if board[i][j] == 1:
                return False

        for i, j in zip(range(row-1, -1, -1), range(col+1, n)):
            if board[i][j] == 1:
                return False

        return True

    board = [[0] * n for _ in range(n)]
    backtrack(board, 0)
    return solutions

# Time: O(N!), Space: O(N²)
```

**Sudoku Solver:**
```python
def solve_sudoku(board):
    def is_valid(board, row, col, num):
        # Check row
        for j in range(9):
            if board[row][j] == num:
                return False

        # Check column
        for i in range(9):
            if board[i][col] == num:
                return False

        # Check 3x3 box
        start_row, start_col = 3 * (row // 3), 3 * (col // 3)
        for i in range(start_row, start_row + 3):
            for j in range(start_col, start_col + 3):
                if board[i][j] == num:
                    return False

        return True

    def backtrack(board):
        for i in range(9):
            for j in range(9):
                if board[i][j] == 0:
                    for num in range(1, 10):
                        if is_valid(board, i, j, num):
                            board[i][j] = num

                            if backtrack(board):
                                return True

                            board[i][j] = 0  # Backtrack

                    return False
        return True

    backtrack(board)
    return board

# Time: O(9^(n*n)), Space: O(n*n)
```

**Subset Sum:**
```python
def subset_sum(nums, target):
    def backtrack(index, current_sum, path):
        if current_sum == target:
            result.append(path[:])
            return

        if index >= len(nums) or current_sum > target:
            return

        # Include current number
        path.append(nums[index])
        backtrack(index + 1, current_sum + nums[index], path)
        path.pop()

        # Exclude current number
        backtrack(index + 1, current_sum, path)

    result = []
    backtrack(0, 0, [])
    return result

# Generate all subsets
def generate_subsets(nums):
    def backtrack(index, path):
        result.append(path[:])

        for i in range(index, len(nums)):
            path.append(nums[i])
            backtrack(i + 1, path)
            path.pop()

    result = []
    backtrack(0, [])
    return result

# Time: O(2^n), Space: O(n)
```

## Graph Algorithms

**Topological Sort:**
```python
from collections import deque, defaultdict

def topological_sort_kahn(graph):
    in_degree = defaultdict(int)

    # Calculate in-degrees
    for node in graph:
        for neighbor in graph[node]:
            in_degree[neighbor] += 1

    # Find nodes with no incoming edges
    queue = deque([node for node in graph if in_degree[node] == 0])
    result = []

    while queue:
        node = queue.popleft()
        result.append(node)

        for neighbor in graph[node]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    # Check for cycle
    if len(result) != len(graph):
        return None  # Cycle detected

    return result

def topological_sort_dfs(graph):
    visited = set()
    stack = []

    def dfs(node):
        visited.add(node)
        for neighbor in graph[node]:
            if neighbor not in visited:
                dfs(neighbor)
        stack.append(node)

    for node in graph:
        if node not in visited:
            dfs(node)

    return stack[::-1]

# Time: O(V + E), Space: O(V)
```

**Minimum Spanning Tree (Kruskal's):**
```python
class UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x):
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x, y):
        px, py = self.find(x), self.find(y)
        if px == py:
            return False

        if self.rank[px] < self.rank[py]:
            px, py = py, px

        self.parent[py] = px
        if self.rank[px] == self.rank[py]:
            self.rank[px] += 1

        return True

def kruskal_mst(edges, n):
    # edges: [(weight, u, v), ...]
    edges.sort()  # Sort by weight

    uf = UnionFind(n)
    mst = []
    total_weight = 0

    for weight, u, v in edges:
        if uf.union(u, v):
            mst.append((u, v, weight))
            total_weight += weight

            if len(mst) == n - 1:
                break

    return mst, total_weight

# Time: O(E log E), Space: O(V)
```

**Strongly Connected Components (Tarjan's):**
```python
def tarjan_scc(graph):
    index_counter = [0]
    stack = []
    lowlinks = {}
    index = {}
    on_stack = {}
    sccs = []

    def strongconnect(v):
        index[v] = index_counter[0]
        lowlinks[v] = index_counter[0]
        index_counter[0] += 1
        stack.append(v)
        on_stack[v] = True

        for w in graph[v]:
            if w not in index:
                strongconnect(w)
                lowlinks[v] = min(lowlinks[v], lowlinks[w])
            elif on_stack[w]:
                lowlinks[v] = min(lowlinks[v], index[w])

        if lowlinks[v] == index[v]:
            component = []
            while True:
                w = stack.pop()
                on_stack[w] = False
                component.append(w)
                if w == v:
                    break
            sccs.append(component)

    for v in graph:
        if v not in index:
            strongconnect(v)

    return sccs

# Time: O(V + E), Space: O(V)
```

# String Algorithms

## Pattern Matching

**KMP (Knuth-Morris-Pratt) Algorithm:**
```python
def kmp_search(text, pattern):
    def compute_lps(pattern):
        lps = [0] * len(pattern)
        length = 0
        i = 1

        while i < len(pattern):
            if pattern[i] == pattern[length]:
                length += 1
                lps[i] = length
                i += 1
            else:
                if length != 0:
                    length = lps[length - 1]
                else:
                    lps[i] = 0
                    i += 1

        return lps

    if not pattern:
        return []

    lps = compute_lps(pattern)
    matches = []

    i = j = 0
    while i < len(text):
        if pattern[j] == text[i]:
            i += 1
            j += 1

        if j == len(pattern):
            matches.append(i - j)
            j = lps[j - 1]
        elif i < len(text) and pattern[j] != text[i]:
            if j != 0:
                j = lps[j - 1]
            else:
                i += 1

    return matches

# Time: O(n + m), Space: O(m)
```

**Rabin-Karp Algorithm:**
```python
def rabin_karp_search(text, pattern, prime=101):
    n, m = len(text), len(pattern)
    if m > n:
        return []

    # Calculate hash values
    pattern_hash = 0
    text_hash = 0
    h = 1

    # Calculate h = pow(256, m-1) % prime
    for i in range(m - 1):
        h = (h * 256) % prime

    # Calculate hash for pattern and first window
    for i in range(m):
        pattern_hash = (256 * pattern_hash + ord(pattern[i])) % prime
        text_hash = (256 * text_hash + ord(text[i])) % prime

    matches = []

    for i in range(n - m + 1):
        # Check if hash values match
        if pattern_hash == text_hash:
            # Check characters one by one
            if text[i:i+m] == pattern:
                matches.append(i)

        # Calculate hash for next window
        if i < n - m:
            text_hash = (256 * (text_hash - ord(text[i]) * h) +
                        ord(text[i + m])) % prime

            # Handle negative hash
            if text_hash < 0:
                text_hash += prime

    return matches

# Average Time: O(n + m), Worst: O(nm)
```

## String Processing

**Longest Palindromic Substring:**
```python
def longest_palindrome(s):
    if not s:
        return ""

    start = 0
    max_len = 1

    def expand_around_center(left, right):
        while left >= 0 and right < len(s) and s[left] == s[right]:
            left -= 1
            right += 1
        return right - left - 1

    for i in range(len(s)):
        # Odd length palindromes
        len1 = expand_around_center(i, i)
        # Even length palindromes
        len2 = expand_around_center(i, i + 1)

        current_max = max(len1, len2)
        if current_max > max_len:
            max_len = current_max
            start = i - (current_max - 1) // 2

    return s[start:start + max_len]

# Manacher's algorithm (linear time)
def manacher_longest_palindrome(s):
    # Preprocess string
    processed = '#'.join('^{}$'.format(s))
    n = len(processed)

    p = [0] * n  # Array to store palindrome lengths
    center = right = 0

    for i in range(1, n - 1):
        mirror = 2 * center - i

        if i < right:
            p[i] = min(right - i, p[mirror])

        # Try to expand palindrome centered at i
        while processed[i + p[i] + 1] == processed[i - p[i] - 1]:
            p[i] += 1

        # Update center and right boundary
        if i + p[i] > right:
            center, right = i, i + p[i]

    # Find longest palindrome
    max_len = 0
    center_index = 0

    for i in range(1, n - 1):
        if p[i] > max_len:
            max_len = p[i]
            center_index = i

    start = (center_index - max_len) // 2
    return s[start:start + max_len]

# Time: O(n), Space: O(n)
```

**String Matching with Wildcards:**
```python
def wildcard_match(s, p):
    m, n = len(s), len(p)
    dp = [[False] * (n + 1) for _ in range(m + 1)]

    # Empty pattern matches empty string
    dp[0][0] = True

    # Handle patterns like a*, a*b*, a*b*c*
    for j in range(1, n + 1):
        if p[j-1] == '*':
            dp[0][j] = dp[0][j-1]

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if p[j-1] == '*':
                # '*' matches empty or any sequence
                dp[i][j] = dp[i][j-1] or dp[i-1][j]
            elif p[j-1] == '?' or s[i-1] == p[j-1]:
                # Character match or '?' wildcard
                dp[i][j] = dp[i-1][j-1]

    return dp[m][n]

# Time: O(m*n), Space: O(m*n)
```

## Text Algorithms

**Suffix Array:**
```python
def build_suffix_array(s):
    n = len(s)
    suffixes = [(s[i:], i) for i in range(n)]
    suffixes.sort()
    return [suffix[1] for suffix in suffixes]

def lcp_array(s, suffix_array):
    n = len(s)
    rank = [0] * n
    lcp = [0] * (n - 1)

    # Build rank array
    for i in range(n):
        rank[suffix_array[i]] = i

    # Compute LCP array
    k = 0
    for i in range(n):
        if rank[i] == n - 1:
            k = 0
            continue

        j = suffix_array[rank[i] + 1]

        while i + k < n and j + k < n and s[i + k] == s[j + k]:
            k += 1

        lcp[rank[i]] = k

        if k > 0:
            k -= 1

    return lcp

# Time: O(n² log n) for naive, O(n log n) optimized
```

**Text Compression (LZ77):**
```python
def lz77_compress(text, window_size=20, buffer_size=15):
    compressed = []
    i = 0

    while i < len(text):
        match_length = 0
        match_distance = 0

        # Search for longest match in sliding window
        search_start = max(0, i - window_size)

        for j in range(search_start, i):
            length = 0
            while (i + length < len(text) and
                   j + length < i and
                   text[j + length] == text[i + length] and
                   length < buffer_size):
                length += 1

            if length > match_length:
                match_length = length
                match_distance = i - j

        if match_length > 0:
            # Output (distance, length, next_char)
            next_char = text[i + match_length] if i + match_length < len(text) else ''
            compressed.append((match_distance, match_length, next_char))
            i += match_length + 1
        else:
            # No match found
            compressed.append((0, 0, text[i]))
            i += 1

    return compressed

def lz77_decompress(compressed):
    text = []

    for distance, length, next_char in compressed:
        if distance > 0 and length > 0:
            # Copy from previous position
            start = len(text) - distance
            for i in range(length):
                text.append(text[start + i])

        if next_char:
            text.append(next_char)

    return ''.join(text)

# Time: O(n * window_size * buffer_size)
```

---

# Computer Systems

## Computer Architecture

Understanding how computers work at the hardware level.

**Von Neumann Architecture:**
```
┌─────────────────────────────────────────────────────────┐
│                       Computer                          │
├─────────────────┬───────────────────┬───────────────────┤
│       CPU       │      Memory       │   Input/Output    │
│  ┌───────────┐  │  ┌─────────────┐  │  ┌─────────────┐  │
│  │    ALU    │  │  │ Instructions│  │  │  Keyboard   │  │
│  │           │  │  │    Data     │  │  │   Mouse     │  │
│  │ Control   │  │  │             │  │  │  Display    │  │
│  │   Unit    │  │  │             │  │  │   Disk      │  │
│  │           │  │  │             │  │  │             │  │
│  │ Registers │  │  │             │  │  │             │  │
│  └───────────┘  │  └─────────────┘  │  └─────────────┘  │
└─────────────────┴───────────────────┴───────────────────┘
```

**CPU Components:**

**Registers:**
```assembly
; x86-64 General Purpose Registers
RAX - Accumulator (return values)
RBX - Base register
RCX - Counter register
RDX - Data register
RSI - Source index
RDI - Destination index
RBP - Base pointer (stack frame)
RSP - Stack pointer

; Special Registers
RIP - Instruction pointer
RFLAGS - Status flags
```

**Instruction Cycle:**
```python
class SimpleCPU:
    def __init__(self):
        self.registers = [0] * 16  # 16 general purpose registers
        self.memory = [0] * 1024   # 1KB memory
        self.pc = 0                # Program counter
        self.running = True

    def fetch(self):
        instruction = self.memory[self.pc]
        self.pc += 1
        return instruction

    def decode(self, instruction):
        # Instruction format: OPCODE (4 bits) | REG1 (4 bits) | REG2 (4 bits) | IMM (4 bits)
        opcode = (instruction >> 12) & 0xF
        reg1 = (instruction >> 8) & 0xF
        reg2 = (instruction >> 4) & 0xF
        immediate = instruction & 0xF
        return opcode, reg1, reg2, immediate

    def execute(self, opcode, reg1, reg2, immediate):
        if opcode == 0x1:    # LOAD immediate
            self.registers[reg1] = immediate
        elif opcode == 0x2:  # ADD registers
            self.registers[reg1] = self.registers[reg1] + self.registers[reg2]
        elif opcode == 0x3:  # STORE to memory
            self.memory[immediate] = self.registers[reg1]
        elif opcode == 0xF:  # HALT
            self.running = False

    def run(self):
        while self.running:
            instruction = self.fetch()
            opcode, reg1, reg2, immediate = self.decode(instruction)
            self.execute(opcode, reg1, reg2, immediate)

# Example program: Add two numbers
cpu = SimpleCPU()
cpu.memory[0] = 0x1105  # LOAD R1, 5
cpu.memory[1] = 0x1203  # LOAD R2, 3
cpu.memory[2] = 0x2312  # ADD R3, R1, R2
cpu.memory[3] = 0x3308  # STORE R3, [8]
cpu.memory[4] = 0xF000  # HALT
cpu.run()
```

**Pipelining:**
```python
class PipelinedCPU:
    def __init__(self):
        self.pipeline = {
            'fetch': None,
            'decode': None,
            'execute': None,
            'memory': None,
            'writeback': None
        }
        self.registers = [0] * 32
        self.memory = [0] * 1024
        self.pc = 0
        self.cycle = 0

    def pipeline_step(self):
        # Execute stages in reverse order to avoid conflicts
        self.writeback_stage()
        self.memory_stage()
        self.execute_stage()
        self.decode_stage()
        self.fetch_stage()

        self.cycle += 1

    def fetch_stage(self):
        if self.pc < len(self.memory):
            instruction = self.memory[self.pc]
            self.pipeline['fetch'] = {
                'instruction': instruction,
                'pc': self.pc
            }
            self.pc += 1

    def decode_stage(self):
        if self.pipeline['fetch']:
            fetch_data = self.pipeline['fetch']
            # Decode instruction
            self.pipeline['decode'] = {
                'opcode': (fetch_data['instruction'] >> 12) & 0xF,
                'reg1': (fetch_data['instruction'] >> 8) & 0xF,
                'reg2': (fetch_data['instruction'] >> 4) & 0xF,
                'immediate': fetch_data['instruction'] & 0xF,
                'pc': fetch_data['pc']
            }
            self.pipeline['fetch'] = None

    # Additional pipeline stages...
```

## Memory Hierarchy

**Memory Types and Characteristics:**
```python
class MemoryHierarchy:
    def __init__(self):
        # Speed (cycles), Size (bytes), Cost per byte
        self.levels = {
            'registers': {'speed': 1, 'size': 32, 'cost': 1000},
            'l1_cache': {'speed': 2, 'size': 32*1024, 'cost': 100},
            'l2_cache': {'speed': 10, 'size': 256*1024, 'cost': 10},
            'l3_cache': {'speed': 40, 'size': 8*1024*1024, 'cost': 5},
            'main_memory': {'speed': 200, 'size': 8*1024*1024*1024, 'cost': 0.01},
            'ssd': {'speed': 50000, 'size': 1024*1024*1024*1024, 'cost': 0.001},
            'hdd': {'speed': 10000000, 'size': 4*1024*1024*1024*1024, 'cost': 0.0001}
        }

    def access_time(self, level):
        return self.levels[level]['speed']

    def capacity(self, level):
        return self.levels[level]['size']
```

**Cache Implementation:**
```python
class CacheSimulator:
    def __init__(self, cache_size, block_size, associativity):
        self.cache_size = cache_size
        self.block_size = block_size
        self.associativity = associativity
        self.num_sets = cache_size // (block_size * associativity)

        # Initialize cache
        self.cache = []
        for _ in range(self.num_sets):
            self.cache.append([{'valid': False, 'tag': 0, 'data': None, 'lru': 0}
                              for _ in range(associativity)])

        self.hits = 0
        self.misses = 0
        self.accesses = 0

    def access(self, address):
        self.accesses += 1

        # Parse address
        block_address = address // self.block_size
        set_index = block_address % self.num_sets
        tag = block_address // self.num_sets

        # Check for hit
        cache_set = self.cache[set_index]
        hit_way = -1

        for way in range(self.associativity):
            if cache_set[way]['valid'] and cache_set[way]['tag'] == tag:
                hit_way = way
                break

        if hit_way != -1:
            # Cache hit
            self.hits += 1
            self._update_lru(set_index, hit_way)
            return cache_set[hit_way]['data']
        else:
            # Cache miss
            self.misses += 1
            victim_way = self._find_victim(set_index)

            # Simulate loading from memory
            data = self._load_from_memory(address)

            # Replace cache line
            cache_set[victim_way] = {
                'valid': True,
                'tag': tag,
                'data': data,
                'lru': 0
            }

            self._update_lru(set_index, victim_way)
            return data

    def _find_victim(self, set_index):
        cache_set = self.cache[set_index]

        # Find invalid line first
        for way in range(self.associativity):
            if not cache_set[way]['valid']:
                return way

        # Use LRU replacement
        lru_way = 0
        for way in range(1, self.associativity):
            if cache_set[way]['lru'] > cache_set[lru_way]['lru']:
                lru_way = way

        return lru_way

    def _update_lru(self, set_index, accessed_way):
        cache_set = self.cache[set_index]

        # Increment LRU counters for all valid lines
        for way in range(self.associativity):
            if cache_set[way]['valid']:
                cache_set[way]['lru'] += 1

        # Reset accessed line's LRU counter
        cache_set[accessed_way]['lru'] = 0

    def _load_from_memory(self, address):
        # Simulate memory access delay
        return f"data_at_{address}"

    def hit_rate(self):
        if self.accesses == 0:
            return 0
        return self.hits / self.accesses
```

**Virtual Memory:**
```python
class VirtualMemoryManager:
    def __init__(self, page_size=4096, physical_pages=1024):
        self.page_size = page_size
        self.physical_pages = physical_pages
        self.page_table = {}  # virtual_page -> physical_page
        self.free_physical_pages = set(range(physical_pages))
        self.physical_memory = [None] * physical_pages
        self.page_faults = 0
        self.memory_accesses = 0

    def translate_address(self, virtual_address):
        self.memory_accesses += 1

        virtual_page = virtual_address // self.page_size
        offset = virtual_address % self.page_size

        if virtual_page not in self.page_table:
            # Page fault
            self.page_faults += 1
            self._handle_page_fault(virtual_page)

        physical_page = self.page_table[virtual_page]
        physical_address = physical_page * self.page_size + offset

        return physical_address

    def _handle_page_fault(self, virtual_page):
        if not self.free_physical_pages:
            # Need to evict a page
            victim_page = self._select_victim()
            self._evict_page(victim_page)

        # Allocate physical page
        physical_page = self.free_physical_pages.pop()
        self.page_table[virtual_page] = physical_page

        # Load page from disk (simulated)
        self.physical_memory[physical_page] = f"page_{virtual_page}_data"

    def _select_victim(self):
        # Simple FIFO replacement
        return next(iter(self.page_table.values()))

    def _evict_page(self, physical_page):
        # Find virtual page that maps to this physical page
        virtual_page = None
        for vp, pp in self.page_table.items():
            if pp == physical_page:
                virtual_page = vp
                break

        if virtual_page is not None:
            del self.page_table[virtual_page]
            self.free_physical_pages.add(physical_page)
            # Write to disk if dirty (simulated)

    def page_fault_rate(self):
        if self.memory_accesses == 0:
            return 0
        return self.page_faults / self.memory_accesses
```

## Operating Systems

**Process Management:**
```python
import time
from enum import Enum
from collections import deque

class ProcessState(Enum):
    NEW = 1
    READY = 2
    RUNNING = 3
    WAITING = 4
    TERMINATED = 5

class Process:
    def __init__(self, pid, burst_time, arrival_time=0, priority=0):
        self.pid = pid
        self.burst_time = burst_time
        self.remaining_time = burst_time
        self.arrival_time = arrival_time
        self.priority = priority
        self.state = ProcessState.NEW
        self.start_time = None
        self.completion_time = None
        self.waiting_time = 0
        self.turnaround_time = 0

class CPUScheduler:
    def __init__(self):
        self.processes = []
        self.ready_queue = deque()
        self.current_process = None
        self.current_time = 0
        self.completed_processes = []

    def add_process(self, process):
        self.processes.append(process)

    def fcfs_schedule(self):
        """First Come First Served scheduling"""
        # Sort by arrival time
        self.processes.sort(key=lambda p: p.arrival_time)

        for process in self.processes:
            if self.current_time < process.arrival_time:
                self.current_time = process.arrival_time

            process.start_time = self.current_time
            process.waiting_time = self.current_time - process.arrival_time

            self.current_time += process.burst_time
            process.completion_time = self.current_time
            process.turnaround_time = process.completion_time - process.arrival_time

            self.completed_processes.append(process)

    def sjf_schedule(self):
        """Shortest Job First scheduling"""
        remaining_processes = self.processes[:]

        while remaining_processes:
            # Find processes that have arrived
            available = [p for p in remaining_processes
                        if p.arrival_time <= self.current_time]

            if not available:
                # No process has arrived, advance time
                self.current_time = min(p.arrival_time for p in remaining_processes)
                continue

            # Select shortest job
            shortest = min(available, key=lambda p: p.burst_time)

            shortest.start_time = self.current_time
            shortest.waiting_time = self.current_time - shortest.arrival_time

            self.current_time += shortest.burst_time
            shortest.completion_time = self.current_time
            shortest.turnaround_time = shortest.completion_time - shortest.arrival_time

            remaining_processes.remove(shortest)
            self.completed_processes.append(shortest)

    def round_robin_schedule(self, time_quantum):
        """Round Robin scheduling"""
        remaining_processes = self.processes[:]
        ready_queue = deque()

        while remaining_processes or ready_queue:
            # Add newly arrived processes to ready queue
            newly_arrived = [p for p in remaining_processes
                           if p.arrival_time <= self.current_time]
            for process in newly_arrived:
                ready_queue.append(process)
                remaining_processes.remove(process)

            if not ready_queue:
                # No process ready, advance time
                if remaining_processes:
                    self.current_time = min(p.arrival_time for p in remaining_processes)
                continue

            current_process = ready_queue.popleft()

            if current_process.start_time is None:
                current_process.start_time = self.current_time

            # Execute for time quantum or until completion
            execution_time = min(time_quantum, current_process.remaining_time)
            self.current_time += execution_time
            current_process.remaining_time -= execution_time

            # Add newly arrived processes
            newly_arrived = [p for p in remaining_processes
                           if p.arrival_time <= self.current_time]
            for process in newly_arrived:
                ready_queue.append(process)
                remaining_processes.remove(process)

            if current_process.remaining_time == 0:
                # Process completed
                current_process.completion_time = self.current_time
                current_process.turnaround_time = (current_process.completion_time -
                                                 current_process.arrival_time)
                current_process.waiting_time = (current_process.turnaround_time -
                                              current_process.burst_time)
                self.completed_processes.append(current_process)
            else:
                # Process not completed, add back to queue
                ready_queue.append(current_process)

    def calculate_metrics(self):
        if not self.completed_processes:
            return {}

        avg_waiting_time = sum(p.waiting_time for p in self.completed_processes) / len(self.completed_processes)
        avg_turnaround_time = sum(p.turnaround_time for p in self.completed_processes) / len(self.completed_processes)

        return {
            'average_waiting_time': avg_waiting_time,
            'average_turnaround_time': avg_turnaround_time,
            'total_processes': len(self.completed_processes)
        }
```

**Deadlock Detection:**
```python
class DeadlockDetector:
    def __init__(self, num_processes, num_resources):
        self.num_processes = num_processes
        self.num_resources = num_resources
        self.allocation = [[0] * num_resources for _ in range(num_processes)]
        self.request = [[0] * num_resources for _ in range(num_processes)]
        self.available = [0] * num_resources

    def set_allocation(self, process, resource, amount):
        self.allocation[process][resource] = amount

    def set_request(self, process, resource, amount):
        self.request[process][resource] = amount

    def set_available(self, resource, amount):
        self.available[resource] = amount

    def detect_deadlock(self):
        # Banker's algorithm for deadlock detection
        work = self.available[:]
        finish = [False] * self.num_processes
        safe_sequence = []

        while True:
            found = False

            for p in range(self.num_processes):
                if not finish[p]:
                    # Check if request can be satisfied
                    can_finish = True
                    for r in range(self.num_resources):
                        if self.request[p][r] > work[r]:
                            can_finish = False
                            break

                    if can_finish:
                        # Process can finish
                        finish[p] = True
                        safe_sequence.append(p)

                        # Release allocated resources
                        for r in range(self.num_resources):
                            work[r] += self.allocation[p][r]

                        found = True
                        break

            if not found:
                break

        # Check if all processes can finish
        deadlocked_processes = [p for p in range(self.num_processes) if not finish[p]]

        return {
            'deadlock_detected': len(deadlocked_processes) > 0,
            'deadlocked_processes': deadlocked_processes,
            'safe_sequence': safe_sequence if not deadlocked_processes else None
        }

    def find_deadlock_cycle(self):
        # Build wait-for graph
        wait_for = {p: set() for p in range(self.num_processes)}

        for p1 in range(self.num_processes):
            for r in range(self.num_resources):
                if self.request[p1][r] > 0:
                    # p1 is waiting for resource r
                    for p2 in range(self.num_processes):
                        if p1 != p2 and self.allocation[p2][r] > 0:
                            wait_for[p1].add(p2)

        # Detect cycles using DFS
        visited = set()
        rec_stack = set()

        def has_cycle(node, path):
            if node in rec_stack:
                # Found cycle
                cycle_start = path.index(node)
                return path[cycle_start:]

            if node in visited:
                return None

            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in wait_for[node]:
                cycle = has_cycle(neighbor, path)
                if cycle:
                    return cycle

            rec_stack.remove(node)
            path.pop()
            return None

        for p in range(self.num_processes):
            if p not in visited:
                cycle = has_cycle(p, [])
                if cycle:
                    return cycle

        return None
```

## File Systems

**File System Implementation:**
```python
import json
import time
from collections import defaultdict

class INode:
    def __init__(self, file_type='file', size=0):
        self.file_type = file_type  # 'file' or 'directory'
        self.size = size
        self.permissions = 0o755
        self.creation_time = time.time()
        self.modification_time = time.time()
        self.access_time = time.time()
        self.link_count = 1
        self.blocks = []  # List of block numbers
        self.indirect_blocks = []  # For large files

class Block:
    def __init__(self, block_id, size=4096):
        self.block_id = block_id
        self.size = size
        self.data = bytearray(size)
        self.used = 0

class SimpleFileSystem:
    def __init__(self, total_blocks=1024, block_size=4096):
        self.block_size = block_size
        self.total_blocks = total_blocks
        self.blocks = [Block(i, block_size) for i in range(total_blocks)]
        self.free_blocks = set(range(1, total_blocks))  # Block 0 reserved for superblock
        self.inodes = {}  # inode_id -> INode
        self.directory_entries = defaultdict(dict)  # parent_inode -> {name: inode_id}
        self.next_inode_id = 1

        # Create root directory
        root_inode = INode('directory')
        self.inodes[0] = root_inode
        self.directory_entries[0] = {}

    def allocate_block(self):
        if not self.free_blocks:
            raise Exception("No free blocks available")

        block_id = self.free_blocks.pop()
        return block_id

    def free_block(self, block_id):
        self.free_blocks.add(block_id)
        self.blocks[block_id].used = 0
        self.blocks[block_id].data = bytearray(self.block_size)

    def allocate_inode(self, file_type='file'):
        inode_id = self.next_inode_id
        self.next_inode_id += 1

        inode = INode(file_type)
        self.inodes[inode_id] = inode

        return inode_id

    def create_file(self, parent_inode_id, filename, data=b""):
        if filename in self.directory_entries[parent_inode_id]:
            raise Exception(f"File {filename} already exists")

        # Allocate inode
        inode_id = self.allocate_inode('file')
        inode = self.inodes[inode_id]

        # Write data to blocks
        if data:
            self.write_file_data(inode_id, data)

        # Add to directory
        self.directory_entries[parent_inode_id][filename] = inode_id

        return inode_id

    def create_directory(self, parent_inode_id, dirname):
        if dirname in self.directory_entries[parent_inode_id]:
            raise Exception(f"Directory {dirname} already exists")

        # Allocate inode
        inode_id = self.allocate_inode('directory')

        # Add to parent directory
        self.directory_entries[parent_inode_id][dirname] = inode_id

        # Initialize empty directory
        self.directory_entries[inode_id] = {}

        return inode_id

    def write_file_data(self, inode_id, data):
        inode = self.inodes[inode_id]

        # Free existing blocks
        for block_id in inode.blocks:
            self.free_block(block_id)
        inode.blocks = []

        # Calculate required blocks
        required_blocks = (len(data) + self.block_size - 1) // self.block_size

        if required_blocks > len(self.free_blocks):
            raise Exception("Not enough free blocks")

        # Allocate and write blocks
        offset = 0
        for _ in range(required_blocks):
            block_id = self.allocate_block()
            inode.blocks.append(block_id)

            chunk_size = min(self.block_size, len(data) - offset)
            self.blocks[block_id].data[:chunk_size] = data[offset:offset + chunk_size]
            self.blocks[block_id].used = chunk_size

            offset += chunk_size

        inode.size = len(data)
        inode.modification_time = time.time()

    def read_file_data(self, inode_id):
        inode = self.inodes[inode_id]

        if inode.file_type != 'file':
            raise Exception("Not a file")

        data = bytearray()

        for block_id in inode.blocks:
            block = self.blocks[block_id]
            data.extend(block.data[:block.used])

        inode.access_time = time.time()
        return bytes(data)

    def list_directory(self, inode_id):
        inode = self.inodes[inode_id]

        if inode.file_type != 'directory':
            raise Exception("Not a directory")

        entries = []
        for name, child_inode_id in self.directory_entries[inode_id].items():
            child_inode = self.inodes[child_inode_id]
            entries.append({
                'name': name,
                'type': child_inode.file_type,
                'size': child_inode.size,
                'modification_time': child_inode.modification_time
            })

        inode.access_time = time.time()
        return entries

    def delete_file(self, parent_inode_id, filename):
        if filename not in self.directory_entries[parent_inode_id]:
            raise Exception(f"File {filename} not found")

        inode_id = self.directory_entries[parent_inode_id][filename]
        inode = self.inodes[inode_id]

        # Free blocks
        for block_id in inode.blocks:
            self.free_block(block_id)

        # Remove from directory
        del self.directory_entries[parent_inode_id][filename]

        # Remove inode
        del self.inodes[inode_id]

    def get_file_stats(self):
        total_files = sum(1 for inode in self.inodes.values()
                         if inode.file_type == 'file')
        total_directories = sum(1 for inode in self.inodes.values()
                              if inode.file_type == 'directory')
        used_blocks = self.total_blocks - len(self.free_blocks)

        return {
            'total_files': total_files,
            'total_directories': total_directories,
            'used_blocks': used_blocks,
            'free_blocks': len(self.free_blocks),
            'total_blocks': self.total_blocks,
            'utilization': used_blocks / self.total_blocks
        }
```

# Networking Fundamentals

Understanding how computers communicate across networks.

## IP Addressing and Subnetting

**IPv4 Address Structure:**
```
192.168.1.100/24
│   │   │ │   └── Host bits (8 bits = 256 addresses)
│   │   │ └────── Network bits (24 bits)
└───┴───┴────────── Dotted decimal notation
```

**Address Classes:**
```python
def identify_ip_class(ip):
    """Identify IPv4 address class"""
    first_octet = int(ip.split('.')[0])

    if 1 <= first_octet <= 126:
        return "Class A", "255.0.0.0", "/8"
    elif 128 <= first_octet <= 191:
        return "Class B", "255.255.0.0", "/16"
    elif 192 <= first_octet <= 223:
        return "Class C", "255.255.255.0", "/24"
    elif 224 <= first_octet <= 239:
        return "Class D (Multicast)", "N/A", "N/A"
    else:
        return "Class E (Reserved)", "N/A", "N/A"

# Examples
print(identify_ip_class("10.0.0.1"))      # Class A
print(identify_ip_class("172.16.0.1"))    # Class B
print(identify_ip_class("192.168.1.1"))   # Class C
```

**Subnetting Calculations:**
```python
def subnet_calculator(network, new_prefix):
    """Calculate subnet information"""
    import ipaddress

    # Original network
    net = ipaddress.IPv4Network(network, strict=False)

    # Calculate new subnets
    subnets = list(net.subnets(new_prefix=new_prefix))

    return {
        'original_network': str(net),
        'original_hosts': net.num_addresses - 2,  # Subtract network and broadcast
        'new_prefix': new_prefix,
        'num_subnets': len(subnets),
        'hosts_per_subnet': subnets[0].num_addresses - 2,
        'first_subnet': str(subnets[0]),
        'last_subnet': str(subnets[-1])
    }

# Example: Subnet 192.168.1.0/24 into /26 networks
result = subnet_calculator("192.168.1.0/24", 26)
print(f"Original: {result['original_network']} ({result['original_hosts']} hosts)")
print(f"New: {result['num_subnets']} subnets with {result['hosts_per_subnet']} hosts each")
```

**CIDR Notation:**
```python
def cidr_to_subnet_mask(cidr):
    """Convert CIDR to subnet mask"""
    mask_bits = '1' * cidr + '0' * (32 - cidr)
    octets = [mask_bits[i:i+8] for i in range(0, 32, 8)]
    return '.'.join([str(int(octet, 2)) for octet in octets])

def subnet_mask_to_cidr(mask):
    """Convert subnet mask to CIDR"""
    octets = mask.split('.')
    binary = ''.join([format(int(octet), '08b') for octet in octets])
    return binary.count('1')

# Examples
print(cidr_to_subnet_mask(24))    # 255.255.255.0
print(subnet_mask_to_cidr("255.255.252.0"))  # 22
```

## Network Protocols

**OSI Model Layers:**
```
7. Application  - HTTP, FTP, SMTP, DNS
6. Presentation - SSL/TLS, encryption
5. Session      - NetBIOS, RPC
4. Transport    - TCP, UDP
3. Network      - IP, ICMP, ARP
2. Data Link    - Ethernet, Wi-Fi
1. Physical     - Cables, radio waves
```

**TCP vs UDP:**
```python
class ProtocolComparison:
    def __init__(self):
        self.tcp_features = {
            'connection': 'Connection-oriented',
            'reliability': 'Reliable delivery',
            'ordering': 'Ordered delivery',
            'overhead': 'Higher overhead',
            'use_cases': ['Web browsing', 'Email', 'File transfer']
        }

        self.udp_features = {
            'connection': 'Connectionless',
            'reliability': 'Best-effort delivery',
            'ordering': 'No ordering guarantee',
            'overhead': 'Lower overhead',
            'use_cases': ['Video streaming', 'Gaming', 'DNS queries']
        }

def tcp_handshake():
    """Simulate TCP three-way handshake"""
    steps = [
        "1. Client → Server: SYN (sequence=100)",
        "2. Server → Client: SYN-ACK (sequence=200, ack=101)",
        "3. Client → Server: ACK (sequence=101, ack=201)",
        "Connection established!"
    ]
    return steps
```

**DNS Resolution Process:**
```python
def dns_resolution(domain):
    """Simulate DNS resolution process"""
    steps = [
        f"1. Check local cache for {domain}",
        "2. Query recursive resolver (ISP DNS)",
        "3. Query root nameserver (.) if not cached",
        "4. Query TLD nameserver (.com) if not cached",
        f"5. Query authoritative nameserver for {domain}",
        "6. Return IP address to client",
        "7. Cache result for future queries"
    ]
    return steps

# Example DNS hierarchy
dns_hierarchy = {
    'root': '.',
    'tld': '.com, .org, .net',
    'domain': 'example.com',
    'subdomain': 'www.example.com'
}
```

## Network Security Fundamentals

**Common Threats:**
```python
def network_threats():
    """Common network security threats"""
    return {
        'eavesdropping': 'Intercepting network traffic',
        'man_in_middle': 'Intercepting and modifying communications',
        'spoofing': 'Impersonating another device or service',
        'ddos': 'Overwhelming target with traffic',
        'packet_injection': 'Inserting malicious packets'
    }

def security_measures():
    """Network security countermeasures"""
    return {
        'encryption': 'TLS/SSL for data in transit',
        'authentication': 'Verify identity of communicating parties',
        'firewalls': 'Filter traffic based on rules',
        'vpn': 'Encrypted tunnels over public networks',
        'ids_ips': 'Monitor and block suspicious activity'
    }
```

**Firewall Rules Example:**
```python
def firewall_rules():
    """Example firewall rule structure"""
    rules = [
        {'action': 'ALLOW', 'src': '192.168.1.0/24', 'dst': 'any', 'port': 80, 'protocol': 'TCP'},
        {'action': 'ALLOW', 'src': '192.168.1.0/24', 'dst': 'any', 'port': 443, 'protocol': 'TCP'},
        {'action': 'ALLOW', 'src': 'any', 'dst': '192.168.1.100', 'port': 22, 'protocol': 'TCP'},
        {'action': 'DENY', 'src': 'any', 'dst': 'any', 'port': 'any', 'protocol': 'any'}  # Default deny
    ]
    return rules
```

# Network Topologies and Infrastructure

Understanding physical and logical network layouts.

## Physical Topologies

**Common Topologies:**
```python
class NetworkTopology:
    def __init__(self, name, characteristics):
        self.name = name
        self.characteristics = characteristics

topologies = {
    'bus': NetworkTopology('Bus', {
        'structure': 'Linear backbone cable',
        'pros': ['Simple', 'Cost-effective', 'Easy to extend'],
        'cons': ['Single point of failure', 'Performance degrades with distance'],
        'use_case': 'Small networks, legacy systems'
    }),

    'star': NetworkTopology('Star', {
        'structure': 'Central hub/switch with spokes',
        'pros': ['Easy troubleshooting', 'Fault isolation', 'Scalable'],
        'cons': ['Central point failure', 'More cable required'],
        'use_case': 'Most common in modern LANs'
    }),

    'ring': NetworkTopology('Ring', {
        'structure': 'Circular connection',
        'pros': ['Predictable performance', 'No collisions'],
        'cons': ['Single break affects all', 'Difficult to troubleshoot'],
        'use_case': 'Token Ring networks (legacy)'
    }),

    'mesh': NetworkTopology('Mesh', {
        'structure': 'Every node connected to every other',
        'pros': ['High redundancy', 'Fault tolerant'],
        'cons': ['Expensive', 'Complex management'],
        'use_case': 'Critical infrastructure, WANs'
    })
}
```

## Network Infrastructure Components

**Networking Devices:**
```python
def network_devices():
    """Network infrastructure components and their functions"""
    return {
        'hub': {
            'layer': 'Physical (Layer 1)',
            'function': 'Repeats signals to all ports',
            'collision_domain': 'Single large domain',
            'duplex': 'Half-duplex',
            'intelligence': None
        },

        'switch': {
            'layer': 'Data Link (Layer 2)',
            'function': 'Learns MAC addresses, forwards to specific ports',
            'collision_domain': 'Per-port isolation',
            'duplex': 'Full-duplex',
            'intelligence': 'MAC address table'
        },

        'router': {
            'layer': 'Network (Layer 3)',
            'function': 'Routes packets between different networks',
            'collision_domain': 'Broadcast domain separation',
            'duplex': 'Full-duplex',
            'intelligence': 'Routing table, ARP table'
        },

        'access_point': {
            'layer': 'Data Link (Layer 2)',
            'function': 'Wireless connectivity to wired network',
            'collision_domain': 'Wireless collision domain',
            'duplex': 'Half-duplex (wireless)',
            'intelligence': 'Association table'
        }
    }
```

**VLAN Implementation:**
```python
class VLAN:
    def __init__(self, vlan_id, name, subnet):
        self.vlan_id = vlan_id
        self.name = name
        self.subnet = subnet
        self.ports = []

    def add_port(self, switch, port):
        self.ports.append(f"{switch}:{port}")

def vlan_configuration():
    """Example VLAN setup"""
    vlans = {
        10: VLAN(10, "Management", "192.168.10.0/24"),
        20: VLAN(20, "Sales", "192.168.20.0/24"),
        30: VLAN(30, "Engineering", "192.168.30.0/24"),
        99: VLAN(99, "Guest", "192.168.99.0/24")
    }

    # Port assignments
    vlans[10].add_port("SW1", "Gi0/1")  # Management VLAN
    vlans[20].add_port("SW1", "Gi0/2-10")  # Sales department
    vlans[30].add_port("SW1", "Gi0/11-20")  # Engineering

    return vlans
```

## Wide Area Networks (WAN)

**WAN Technologies:**
```python
def wan_technologies():
    """Different WAN connection types"""
    return {
        'leased_line': {
            'type': 'Dedicated point-to-point',
            'bandwidth': '64 Kbps to 10 Gbps',
            'cost': 'High',
            'reliability': 'Very high',
            'use_case': 'Critical business connections'
        },

        'mpls': {
            'type': 'Multi-Protocol Label Switching',
            'bandwidth': 'Variable',
            'cost': 'Medium-High',
            'reliability': 'High',
            'use_case': 'Enterprise networks with QoS requirements'
        },

        'internet_vpn': {
            'type': 'VPN over public internet',
            'bandwidth': 'Depends on internet connection',
            'cost': 'Low',
            'reliability': 'Medium',
            'use_case': 'Small to medium businesses'
        },

        'sd_wan': {
            'type': 'Software-Defined WAN',
            'bandwidth': 'Multiple paths, dynamic',
            'cost': 'Medium',
            'reliability': 'High (with redundancy)',
            'use_case': 'Modern distributed enterprises'
        }
    }
```

**Network Redundancy Protocols:**
```python
def redundancy_protocols():
    """High availability networking protocols"""
    return {
        'stp': {
            'name': 'Spanning Tree Protocol',
            'purpose': 'Prevents switching loops',
            'mechanism': 'Blocks redundant paths, activates on failure'
        },

        'hsrp': {
            'name': 'Hot Standby Router Protocol',
            'purpose': 'Router redundancy',
            'mechanism': 'Virtual IP shared between routers'
        },

        'vrrp': {
            'name': 'Virtual Router Redundancy Protocol',
            'purpose': 'Standard router redundancy',
            'mechanism': 'Master/backup router election'
        },

        'lacp': {
            'name': 'Link Aggregation Control Protocol',
            'purpose': 'Bundle multiple links',
            'mechanism': 'Load balancing and redundancy'
        }
    }
```

---

# Databases

## Database Design

**Entity-Relationship (ER) Model:**
```
Entity: Real-world object (Student, Course, Professor)
Attribute: Property of entity (Name, Age, ID)
Relationship: Association between entities (Enrollment, Teaching)

Example ER Diagram:
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Student   │    │ Enrollment  │    │   Course    │
│             │────│             │────│             │
│ student_id  │ 1  │ grade       │  M │ course_id   │
│ name        │    │ semester    │    │ title       │
│ email       │    │             │    │ credits     │
└─────────────┘    └─────────────┘    └─────────────┘
```

**Normalization:**
```sql
-- 1NF: Atomic values, no repeating groups
-- Before (violates 1NF):
CREATE TABLE students_bad (
    id INT,
    name VARCHAR(100),
    courses VARCHAR(500)  -- "Math,Physics,Chemistry"
);

-- After (1NF):
CREATE TABLE students (
    id INT PRIMARY KEY,
    name VARCHAR(100)
);

CREATE TABLE enrollments (
    student_id INT,
    course VARCHAR(100),
    FOREIGN KEY (student_id) REFERENCES students(id)
);

-- 2NF: 1NF + No partial dependencies
-- Before (violates 2NF):
CREATE TABLE enrollment_bad (
    student_id INT,
    course_id INT,
    student_name VARCHAR(100),  -- Depends only on student_id
    grade CHAR(1),
    PRIMARY KEY (student_id, course_id)
);

-- After (2NF):
CREATE TABLE students (
    student_id INT PRIMARY KEY,
    student_name VARCHAR(100)
);

CREATE TABLE enrollments (
    student_id INT,
    course_id INT,
    grade CHAR(1),
    PRIMARY KEY (student_id, course_id),
    FOREIGN KEY (student_id) REFERENCES students(student_id)
);

-- 3NF: 2NF + No transitive dependencies
-- Before (violates 3NF):
CREATE TABLE employees_bad (
    emp_id INT PRIMARY KEY,
    emp_name VARCHAR(100),
    dept_id INT,
    dept_name VARCHAR(100)  -- Depends on dept_id, not emp_id
);

-- After (3NF):
CREATE TABLE departments (
    dept_id INT PRIMARY KEY,
    dept_name VARCHAR(100)
);

CREATE TABLE employees (
    emp_id INT PRIMARY KEY,
    emp_name VARCHAR(100),
    dept_id INT,
    FOREIGN KEY (dept_id) REFERENCES departments(dept_id)
);
```

## SQL and NoSQL

**SQL Database Operations:**
```sql
-- DDL (Data Definition Language)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);

-- DML (Data Manipulation Language)
INSERT INTO users (username, email)
VALUES ('john_doe', 'john@example.com');

UPDATE users
SET email = 'newemail@example.com'
WHERE username = 'john_doe';

DELETE FROM users
WHERE created_at < '2020-01-01';

-- Complex Queries
SELECT u.username, COUNT(p.id) as post_count
FROM users u
LEFT JOIN posts p ON u.id = p.user_id
WHERE u.created_at >= '2023-01-01'
GROUP BY u.id, u.username
HAVING COUNT(p.id) > 5
ORDER BY post_count DESC;

-- Window Functions
SELECT
    username,
    salary,
    AVG(salary) OVER (PARTITION BY department) as avg_dept_salary,
    ROW_NUMBER() OVER (ORDER BY salary DESC) as salary_rank
FROM employees;

-- Common Table Expressions (CTE)
WITH RECURSIVE employee_hierarchy AS (
    SELECT id, name, manager_id, 1 as level
    FROM employees
    WHERE manager_id IS NULL

    UNION ALL

    SELECT e.id, e.name, e.manager_id, eh.level + 1
    FROM employees e
    JOIN employee_hierarchy eh ON e.manager_id = eh.id
)
SELECT * FROM employee_hierarchy;
```

**NoSQL Database Types:**

**Document Database (MongoDB):**
```javascript
// Document structure
{
  "_id": ObjectId("507f1f77bcf86cd799439011"),
  "username": "john_doe",
  "profile": {
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@example.com"
  },
  "posts": [
    {
      "title": "My First Post",
      "content": "Hello World!",
      "tags": ["intro", "personal"],
      "createdAt": ISODate("2023-01-15")
    }
  ]
}

// MongoDB operations
db.users.insertOne({
  username: "jane_doe",
  profile: { firstName: "Jane", lastName: "Doe" }
});

db.users.find({ "profile.firstName": "John" });

db.users.updateOne(
  { username: "john_doe" },
  { $push: { posts: { title: "Second Post", content: "More content" } } }
);

// Aggregation pipeline
db.users.aggregate([
  { $match: { "posts.tags": "intro" } },
  { $unwind: "$posts" },
  { $group: { _id: "$username", postCount: { $sum: 1 } } }
]);
```

**Key-Value Store (Redis):**
```python
import redis

r = redis.Redis(host='localhost', port=6379, db=0)

# Basic operations
r.set('user:1000:name', 'John Doe')
r.get('user:1000:name')  # b'John Doe'

# Hash operations
r.hset('user:1000', mapping={
    'name': 'John Doe',
    'email': 'john@example.com',
    'age': 30
})

r.hget('user:1000', 'email')
r.hgetall('user:1000')

# List operations
r.lpush('tasks', 'task1', 'task2', 'task3')
r.lrange('tasks', 0, -1)

# Set operations
r.sadd('tags', 'python', 'redis', 'database')
r.smembers('tags')

# Sorted sets
r.zadd('leaderboard', {'player1': 100, 'player2': 150, 'player3': 200})
r.zrange('leaderboard', 0, -1, withscores=True)

# Expiration
r.setex('session:abc123', 3600, 'session_data')  # Expires in 1 hour
```

**Graph Database (Neo4j):**
```cypher
// Create nodes
CREATE (john:Person {name: 'John', age: 30})
CREATE (mary:Person {name: 'Mary', age: 25})
CREATE (company:Company {name: 'TechCorp'})

// Create relationships
CREATE (john)-[:WORKS_FOR {since: 2020}]->(company)
CREATE (mary)-[:WORKS_FOR {since: 2021}]->(company)
CREATE (john)-[:KNOWS {since: 2019}]->(mary)

// Query patterns
MATCH (p:Person)-[:WORKS_FOR]->(c:Company)
WHERE c.name = 'TechCorp'
RETURN p.name, p.age

// Find friends of friends
MATCH (john:Person {name: 'John'})-[:KNOWS*2..3]-(friend)
RETURN DISTINCT friend.name

// Shortest path
MATCH path = shortestPath(
  (start:Person {name: 'John'})-[*]-(end:Person {name: 'Bob'})
)
RETURN path
```

## Transactions

**ACID Properties:**
```python
class DatabaseTransaction:
    def __init__(self):
        self.operations = []
        self.state = "ACTIVE"  # ACTIVE, COMMITTED, ABORTED

    def atomicity_example(self):
        """All operations succeed or all fail"""
        try:
            # Transfer money between accounts
            self.debit_account("account_1", 100)
            self.credit_account("account_2", 100)
            self.commit()
        except Exception:
            self.rollback()  # Undo all operations

    def consistency_example(self):
        """Database remains in valid state"""
        # Before transaction: total_balance = 1000
        balance_before = self.get_total_balance()

        self.transfer_money("account_1", "account_2", 100)

        balance_after = self.get_total_balance()
        assert balance_before == balance_after  # Consistency maintained

    def isolation_example(self):
        """Concurrent transactions don't interfere"""
        # Transaction 1: Read account balance
        # Transaction 2: Update same account
        # Isolation ensures T1 sees consistent snapshot
        pass

    def durability_example(self):
        """Committed changes persist even after system failure"""
        self.transfer_money("account_1", "account_2", 100)
        self.commit()  # Changes written to persistent storage
        # Even if system crashes here, changes are preserved
```

**Concurrency Control:**
```python
class LockManager:
    def __init__(self):
        self.locks = {}  # resource_id -> lock_info

    def two_phase_locking(self, transaction_id, operations):
        """Two-Phase Locking Protocol"""
        # Phase 1: Growing phase - acquire locks
        acquired_locks = []

        for op in operations:
            resource_id = op['resource']
            lock_type = 'shared' if op['type'] == 'read' else 'exclusive'

            if self.acquire_lock(transaction_id, resource_id, lock_type):
                acquired_locks.append((resource_id, lock_type))
            else:
                # Deadlock detection/prevention
                self.handle_deadlock(transaction_id, resource_id)

        # Execute operations
        results = []
        for op in operations:
            results.append(self.execute_operation(op))

        # Phase 2: Shrinking phase - release locks
        for resource_id, lock_type in acquired_locks:
            self.release_lock(transaction_id, resource_id, lock_type)

        return results

    def optimistic_concurrency_control(self, transaction):
        """Optimistic Concurrency Control"""
        # Phase 1: Read phase
        read_set = set()
        write_set = {}

        for op in transaction.operations:
            if op.type == 'read':
                value = self.read_with_timestamp(op.resource)
                read_set.add((op.resource, value.timestamp))
            else:  # write
                write_set[op.resource] = op.value

        # Phase 2: Validation phase
        if self.validate_transaction(transaction.id, read_set, write_set):
            # Phase 3: Write phase
            for resource, value in write_set.items():
                self.write_with_timestamp(resource, value)
            return True
        else:
            # Abort and retry
            return False
```

**Distributed Transactions:**
```python
class TwoPhaseCommitCoordinator:
    def __init__(self, participants):
        self.participants = participants

    def execute_distributed_transaction(self, transaction):
        """Two-Phase Commit Protocol"""
        # Phase 1: Prepare phase
        prepare_responses = []

        for participant in self.participants:
            response = participant.prepare(transaction)
            prepare_responses.append(response)

        # Check if all participants can commit
        if all(response == "PREPARED" for response in prepare_responses):
            # Phase 2: Commit phase
            for participant in self.participants:
                participant.commit(transaction)
            return "COMMITTED"
        else:
            # Abort transaction
            for participant in self.participants:
                participant.abort(transaction)
            return "ABORTED"

class TwoPhaseCommitParticipant:
    def __init__(self, participant_id):
        self.participant_id = participant_id
        self.prepared_transactions = {}

    def prepare(self, transaction):
        try:
            # Validate transaction and acquire locks
            self.validate_transaction(transaction)
            self.acquire_locks(transaction)

            # Write to transaction log
            self.write_prepare_log(transaction)

            self.prepared_transactions[transaction.id] = transaction
            return "PREPARED"
        except Exception:
            return "ABORTED"

    def commit(self, transaction):
        if transaction.id in self.prepared_transactions:
            # Apply changes and release locks
            self.apply_changes(transaction)
            self.release_locks(transaction)
            self.write_commit_log(transaction)
            del self.prepared_transactions[transaction.id]

    def abort(self, transaction):
        if transaction.id in self.prepared_transactions:
            # Rollback changes and release locks
            self.rollback_changes(transaction)
            self.release_locks(transaction)
            self.write_abort_log(transaction)
            del self.prepared_transactions[transaction.id]
```

## Indexing

**Index Types and Implementation:**
```python
class BTreeIndex:
    """B-Tree index for range queries"""
    def __init__(self, order=3):
        self.order = order  # Maximum children per node
        self.root = BTreeNode()

    def search(self, key):
        return self._search_node(self.root, key)

    def _search_node(self, node, key):
        i = 0
        while i < len(node.keys) and key > node.keys[i]:
            i += 1

        if i < len(node.keys) and key == node.keys[i]:
            return node.values[i]  # Found

        if node.is_leaf:
            return None  # Not found

        return self._search_node(node.children[i], key)

    def insert(self, key, value):
        if self.root.is_full():
            new_root = BTreeNode()
            new_root.children.append(self.root)
            self._split_child(new_root, 0)
            self.root = new_root

        self._insert_non_full(self.root, key, value)

    def range_query(self, start_key, end_key):
        """Efficiently retrieve records in range"""
        results = []
        self._range_search(self.root, start_key, end_key, results)
        return results

class HashIndex:
    """Hash index for equality queries"""
    def __init__(self, size=1000):
        self.size = size
        self.buckets = [[] for _ in range(size)]

    def _hash(self, key):
        return hash(key) % self.size

    def insert(self, key, value):
        bucket_index = self._hash(key)
        bucket = self.buckets[bucket_index]

        # Update existing key or add new
        for i, (k, v) in enumerate(bucket):
            if k == key:
                bucket[i] = (key, value)
                return
        bucket.append((key, value))

    def search(self, key):
        bucket_index = self._hash(key)
        bucket = self.buckets[bucket_index]

        for k, v in bucket:
            if k == key:
                return v
        return None

class BitmapIndex:
    """Bitmap index for low-cardinality columns"""
    def __init__(self, distinct_values):
        self.distinct_values = distinct_values
        self.bitmaps = {value: [] for value in distinct_values}

    def insert(self, row_id, value):
        # Extend bitmaps if necessary
        for val in self.distinct_values:
            while len(self.bitmaps[val]) <= row_id:
                self.bitmaps[val].append(False)

        # Set bit for the value
        self.bitmaps[value][row_id] = True

    def query_equals(self, value):
        """Find all rows where column = value"""
        return [i for i, bit in enumerate(self.bitmaps[value]) if bit]

    def query_and(self, value1, value2):
        """Find rows matching both conditions"""
        bitmap1 = self.bitmaps[value1]
        bitmap2 = self.bitmaps[value2]

        result = []
        for i in range(min(len(bitmap1), len(bitmap2))):
            if bitmap1[i] and bitmap2[i]:
                result.append(i)
        return result

    def query_or(self, value1, value2):
        """Find rows matching either condition"""
        bitmap1 = self.bitmaps[value1]
        bitmap2 = self.bitmaps[value2]

        result = []
        max_len = max(len(bitmap1), len(bitmap2))

        for i in range(max_len):
            bit1 = bitmap1[i] if i < len(bitmap1) else False
            bit2 = bitmap2[i] if i < len(bitmap2) else False
            if bit1 or bit2:
                result.append(i)
        return result
```

**Query Optimization:**
```python
class QueryOptimizer:
    def __init__(self, database):
        self.database = database
        self.statistics = database.get_statistics()

    def optimize_query(self, query):
        """Cost-based query optimization"""
        # Parse query into relational algebra tree
        algebra_tree = self.parse_to_algebra(query)

        # Apply optimization rules
        optimized_tree = self.apply_optimizations(algebra_tree)

        # Generate execution plans
        plans = self.generate_execution_plans(optimized_tree)

        # Choose plan with lowest estimated cost
        best_plan = min(plans, key=self.estimate_cost)

        return best_plan

    def apply_optimizations(self, tree):
        """Apply transformation rules"""
        # Selection pushdown
        tree = self.push_down_selections(tree)

        # Projection pushdown
        tree = self.push_down_projections(tree)

        # Join reordering
        tree = self.optimize_join_order(tree)

        return tree

    def estimate_cost(self, plan):
        """Estimate execution cost"""
        total_cost = 0

        for operation in plan.operations:
            if operation.type == "TABLE_SCAN":
                # Cost = number of pages to read
                total_cost += self.statistics.get_table_size(operation.table)

            elif operation.type == "INDEX_SCAN":
                # Cost based on index selectivity
                selectivity = self.estimate_selectivity(operation.condition)
                total_cost += selectivity * self.statistics.get_table_size(operation.table)

            elif operation.type == "HASH_JOIN":
                # Cost = cost to build hash table + cost to probe
                build_cost = self.estimate_cost(operation.left_input)
                probe_cost = self.estimate_cost(operation.right_input)
                total_cost += build_cost + probe_cost

            elif operation.type == "SORT":
                # Cost = n * log(n) where n is input size
                input_size = self.estimate_output_size(operation.input)
                total_cost += input_size * math.log2(input_size)

        return total_cost

    def estimate_selectivity(self, condition):
        """Estimate what fraction of rows satisfy condition"""
        if condition.operator == "=":
            # For equality, selectivity = 1 / distinct_values
            distinct_values = self.statistics.get_distinct_values(condition.column)
            return 1.0 / distinct_values

        elif condition.operator in ["<", "<=", ">", ">="]:
            # For range conditions, use histogram
            histogram = self.statistics.get_histogram(condition.column)
            return histogram.estimate_range_selectivity(condition.value, condition.operator)

        elif condition.operator == "LIKE":
            # Rough estimate for string matching
            if condition.value.startswith("%"):
                return 0.1  # Very selective
            else:
                return 0.01  # Less selective

        return 0.1  # Default estimate
```

---

# Networks and Distributed Systems

## Network Protocols

**OSI Model Implementation:**
```python
class OSILayer:
    """Base class for OSI layers"""
    def __init__(self, layer_number, name):
        self.layer_number = layer_number
        self.name = name

class PhysicalLayer(OSILayer):
    """Layer 1: Physical transmission of bits"""
    def __init__(self):
        super().__init__(1, "Physical")

    def transmit_bits(self, bits, medium="ethernet"):
        """Convert bits to physical signals"""
        if medium == "ethernet":
            return self.electrical_signals(bits)
        elif medium == "wifi":
            return self.radio_signals(bits)
        elif medium == "fiber":
            return self.optical_signals(bits)

    def electrical_signals(self, bits):
        # Convert 0s and 1s to voltage levels
        signals = []
        for bit in bits:
            signals.append(5.0 if bit == '1' else 0.0)  # 5V for 1, 0V for 0
        return signals

class DataLinkLayer(OSILayer):
    """Layer 2: Frame formatting and error detection"""
    def __init__(self):
        super().__init__(2, "Data Link")

    def create_ethernet_frame(self, src_mac, dst_mac, payload):
        """Create Ethernet frame"""
        frame = {
            'preamble': '10101010' * 7 + '10101011',  # 64 bits
            'dst_mac': dst_mac,                        # 48 bits
            'src_mac': src_mac,                        # 48 bits
            'ethertype': 0x0800,                       # IPv4
            'payload': payload,                         # 46-1500 bytes
            'fcs': self.calculate_crc(payload)         # 32 bits CRC
        }
        return frame

    def calculate_crc(self, data):
        """Calculate CRC-32 for error detection"""
        polynomial = 0x04C11DB7
        crc = 0xFFFFFFFF

        for byte in data:
            crc ^= (byte << 24)
            for _ in range(8):
                if crc & 0x80000000:
                    crc = (crc << 1) ^ polynomial
                else:
                    crc <<= 1
                crc &= 0xFFFFFFFF

        return crc ^ 0xFFFFFFFF

class NetworkLayer(OSILayer):
    """Layer 3: Routing and IP addressing"""
    def __init__(self):
        super().__init__(3, "Network")
        self.routing_table = {}

    def create_ip_packet(self, src_ip, dst_ip, payload, ttl=64):
        """Create IPv4 packet"""
        packet = {
            'version': 4,              # 4 bits
            'ihl': 5,                  # 4 bits (header length)
            'tos': 0,                  # 8 bits (type of service)
            'total_length': 20 + len(payload),  # 16 bits
            'identification': self.generate_id(),  # 16 bits
            'flags': 0,                # 3 bits
            'fragment_offset': 0,      # 13 bits
            'ttl': ttl,                # 8 bits
            'protocol': 6,             # 8 bits (TCP)
            'header_checksum': 0,      # 16 bits (calculated later)
            'src_ip': src_ip,          # 32 bits
            'dst_ip': dst_ip,          # 32 bits
            'payload': payload
        }

        packet['header_checksum'] = self.calculate_ip_checksum(packet)
        return packet

    def route_packet(self, packet):
        """Determine next hop for packet"""
        dst_ip = packet['dst_ip']

        # Longest prefix match
        best_match = None
        best_prefix_len = -1

        for network, (next_hop, prefix_len) in self.routing_table.items():
            if self.ip_in_network(dst_ip, network, prefix_len):
                if prefix_len > best_prefix_len:
                    best_match = next_hop
                    best_prefix_len = prefix_len

        return best_match

    def ip_in_network(self, ip, network, prefix_len):
        """Check if IP is in network subnet"""
        ip_int = self.ip_to_int(ip)
        network_int = self.ip_to_int(network)
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF

        return (ip_int & mask) == (network_int & mask)

class TransportLayer(OSILayer):
    """Layer 4: End-to-end communication"""
    def __init__(self):
        super().__init__(4, "Transport")

    def create_tcp_segment(self, src_port, dst_port, seq_num, ack_num,
                          flags, window_size, payload):
        """Create TCP segment"""
        segment = {
            'src_port': src_port,      # 16 bits
            'dst_port': dst_port,      # 16 bits
            'seq_num': seq_num,        # 32 bits
            'ack_num': ack_num,        # 32 bits
            'data_offset': 5,          # 4 bits (header length)
            'reserved': 0,             # 3 bits
            'flags': flags,            # 9 bits (NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
            'window_size': window_size, # 16 bits
            'checksum': 0,             # 16 bits (calculated later)
            'urgent_pointer': 0,       # 16 bits
            'payload': payload
        }

        segment['checksum'] = self.calculate_tcp_checksum(segment)
        return segment

    def tcp_three_way_handshake(self, client, server):
        """Simulate TCP 3-way handshake"""
        # Step 1: Client sends SYN
        syn_segment = self.create_tcp_segment(
            src_port=client.port,
            dst_port=server.port,
            seq_num=client.initial_seq,
            ack_num=0,
            flags={'SYN': True},
            window_size=65535,
            payload=b''
        )

        # Step 2: Server responds with SYN-ACK
        syn_ack_segment = self.create_tcp_segment(
            src_port=server.port,
            dst_port=client.port,
            seq_num=server.initial_seq,
            ack_num=client.initial_seq + 1,
            flags={'SYN': True, 'ACK': True},
            window_size=65535,
            payload=b''
        )

        # Step 3: Client sends ACK
        ack_segment = self.create_tcp_segment(
            src_port=client.port,
            dst_port=server.port,
            seq_num=client.initial_seq + 1,
            ack_num=server.initial_seq + 1,
            flags={'ACK': True},
            window_size=65535,
            payload=b''
        )

        return [syn_segment, syn_ack_segment, ack_segment]
```

**HTTP Protocol Implementation:**
```python
class HTTPServer:
    def __init__(self, host='localhost', port=8080):
        self.host = host
        self.port = port
        self.routes = {}

    def route(self, path, methods=['GET']):
        """Decorator for registering routes"""
        def decorator(func):
            for method in methods:
                self.routes[(method, path)] = func
            return func
        return decorator

    def parse_request(self, raw_request):
        """Parse HTTP request"""
        lines = raw_request.split('\r\n')

        # Parse request line
        request_line = lines[0]
        method, path, version = request_line.split(' ')

        # Parse headers
        headers = {}
        i = 1
        while i < len(lines) and lines[i] != '':
            header_line = lines[i]
            key, value = header_line.split(': ', 1)
            headers[key.lower()] = value
            i += 1

        # Parse body (if present)
        body = ''
        if i + 1 < len(lines):
            body = '\r\n'.join(lines[i + 1:])

        return {
            'method': method,
            'path': path,
            'version': version,
            'headers': headers,
            'body': body
        }

    def create_response(self, status_code, headers=None, body=''):
        """Create HTTP response"""
        status_messages = {
            200: 'OK',
            404: 'Not Found',
            500: 'Internal Server Error'
        }

        response = f"HTTP/1.1 {status_code} {status_messages.get(status_code, 'Unknown')}\r\n"

        if headers is None:
            headers = {}

        headers['Content-Length'] = str(len(body))
        headers['Server'] = 'CustomHTTPServer/1.0'

        for key, value in headers.items():
            response += f"{key}: {value}\r\n"

        response += f"\r\n{body}"
        return response

    def handle_request(self, request):
        """Handle incoming HTTP request"""
        parsed = self.parse_request(request)

        route_key = (parsed['method'], parsed['path'])

        if route_key in self.routes:
            try:
                handler = self.routes[route_key]
                result = handler(parsed)

                if isinstance(result, str):
                    return self.create_response(200, {'Content-Type': 'text/html'}, result)
                elif isinstance(result, dict):
                    import json
                    body = json.dumps(result)
                    return self.create_response(200, {'Content-Type': 'application/json'}, body)
                else:
                    return self.create_response(200, body=str(result))

            except Exception as e:
                return self.create_response(500, body=f"Internal Server Error: {str(e)}")
        else:
            return self.create_response(404, body="Page not found")

# Usage example
server = HTTPServer()

@server.route('/')
def home(request):
    return "<h1>Welcome to Custom HTTP Server!</h1>"

@server.route('/api/users', methods=['GET', 'POST'])
def users_api(request):
    if request['method'] == 'GET':
        return {'users': ['alice', 'bob', 'charlie']}
    elif request['method'] == 'POST':
        # Parse JSON body and add user
        import json
        data = json.loads(request['body'])
        return {'message': f"User {data['name']} created"}
```

## Client-Server Architecture

**Socket Programming:**
```python
import socket
import threading
import json

class TCPServer:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = []

    def start(self):
        """Start the server"""
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

        try:
            while True:
                client_socket, address = self.socket.accept()
                print(f"Connection from {address}")

                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()

        except KeyboardInterrupt:
            print("Server shutting down...")
        finally:
            self.socket.close()

    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        self.clients.append(client_socket)

        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break

                message = data.decode('utf-8')
                print(f"Received from {address}: {message}")

                # Echo message back to client
                response = f"Echo: {message}"
                client_socket.send(response.encode('utf-8'))

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            self.clients.remove(client_socket)
            client_socket.close()
            print(f"Connection with {address} closed")

class TCPClient:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        """Connect to server"""
        try:
            self.socket.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"Failed to connect: {e}")
            return False

    def send_message(self, message):
        """Send message to server"""
        try:
            self.socket.send(message.encode('utf-8'))
            response = self.socket.recv(1024)
            return response.decode('utf-8')
        except Exception as e:
            print(f"Error sending message: {e}")
            return None

    def close(self):
        """Close connection"""
        self.socket.close()

class ChatServer(TCPServer):
    """Multi-client chat server"""
    def __init__(self, host='localhost', port=8888):
        super().__init__(host, port)
        self.client_names = {}  # socket -> name mapping

    def handle_client(self, client_socket, address):
        """Handle chat client"""
        self.clients.append(client_socket)

        try:
            # Get client name
            client_socket.send("Enter your name: ".encode('utf-8'))
            name_data = client_socket.recv(1024)
            client_name = name_data.decode('utf-8').strip()
            self.client_names[client_socket] = client_name

            # Notify all clients
            join_message = f"{client_name} joined the chat"
            self.broadcast_message(join_message, exclude=client_socket)

            while True:
                data = client_socket.recv(1024)
                if not data:
                    break

                message = data.decode('utf-8').strip()
                if message.lower() == '/quit':
                    break

                # Broadcast message to all clients
                full_message = f"{client_name}: {message}"
                self.broadcast_message(full_message, exclude=client_socket)

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            # Clean up
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            if client_socket in self.client_names:
                name = self.client_names[client_socket]
                del self.client_names[client_socket]

                # Notify others about departure
                leave_message = f"{name} left the chat"
                self.broadcast_message(leave_message)

            client_socket.close()

    def broadcast_message(self, message, exclude=None):
        """Send message to all connected clients"""
        print(f"Broadcasting: {message}")

        for client in self.clients[:]:  # Copy list to avoid modification during iteration
            if client != exclude:
                try:
                    client.send(message.encode('utf-8'))
                except:
                    # Remove disconnected client
                    self.clients.remove(client)
                    if client in self.client_names:
                        del self.client_names[client]
```

**RESTful API Design:**
```python
class RESTAPIServer:
    def __init__(self):
        self.resources = {
            'users': {},
            'posts': {},
            'comments': {}
        }
        self.next_id = 1

    def handle_request(self, method, path, headers, body):
        """Handle REST API request"""
        path_parts = path.strip('/').split('/')

        if not path_parts or path_parts[0] == '':
            return self.create_response(404, "Resource not found")

        resource_type = path_parts[0]

        if resource_type not in self.resources:
            return self.create_response(404, "Resource type not found")

        # Route to appropriate handler
        if method == 'GET':
            if len(path_parts) == 1:
                # GET /users (list all)
                return self.list_resources(resource_type)
            else:
                # GET /users/123 (get specific)
                resource_id = path_parts[1]
                return self.get_resource(resource_type, resource_id)

        elif method == 'POST':
            # POST /users (create new)
            return self.create_resource(resource_type, body)

        elif method == 'PUT':
            # PUT /users/123 (update)
            if len(path_parts) < 2:
                return self.create_response(400, "Resource ID required for PUT")
            resource_id = path_parts[1]
            return self.update_resource(resource_type, resource_id, body)

        elif method == 'DELETE':
            # DELETE /users/123 (delete)
            if len(path_parts) < 2:
                return self.create_response(400, "Resource ID required for DELETE")
            resource_id = path_parts[1]
            return self.delete_resource(resource_type, resource_id)

        else:
            return self.create_response(405, "Method not allowed")

    def list_resources(self, resource_type):
        """GET /resource - List all resources"""
        resources = list(self.resources[resource_type].values())
        return self.create_response(200, resources)

    def get_resource(self, resource_type, resource_id):
        """GET /resource/id - Get specific resource"""
        if resource_id in self.resources[resource_type]:
            resource = self.resources[resource_type][resource_id]
            return self.create_response(200, resource)
        else:
            return self.create_response(404, "Resource not found")

    def create_resource(self, resource_type, body):
        """POST /resource - Create new resource"""
        try:
            import json
            data = json.loads(body) if body else {}

            resource_id = str(self.next_id)
            self.next_id += 1

            resource = {
                'id': resource_id,
                'created_at': self.get_timestamp(),
                **data
            }

            self.resources[resource_type][resource_id] = resource

            return self.create_response(201, resource)

        except json.JSONDecodeError:
            return self.create_response(400, "Invalid JSON")

    def update_resource(self, resource_type, resource_id, body):
        """PUT /resource/id - Update resource"""
        if resource_id not in self.resources[resource_type]:
            return self.create_response(404, "Resource not found")

        try:
            import json
            data = json.loads(body) if body else {}

            # Update existing resource
            resource = self.resources[resource_type][resource_id]
            resource.update(data)
            resource['updated_at'] = self.get_timestamp()

            return self.create_response(200, resource)

        except json.JSONDecodeError:
            return self.create_response(400, "Invalid JSON")

    def delete_resource(self, resource_type, resource_id):
        """DELETE /resource/id - Delete resource"""
        if resource_id not in self.resources[resource_type]:
            return self.create_response(404, "Resource not found")

        del self.resources[resource_type][resource_id]
        return self.create_response(204, "")  # No content

    def create_response(self, status_code, data):
        """Create HTTP response"""
        import json

        if isinstance(data, (dict, list)):
            body = json.dumps(data)
            content_type = "application/json"
        else:
            body = str(data)
            content_type = "text/plain"

        return {
            'status_code': status_code,
            'headers': {
                'Content-Type': content_type,
                'Content-Length': len(body)
            },
            'body': body
        }

    def get_timestamp(self):
        import time
        return int(time.time())
```

## Distributed Computing

**MapReduce Implementation:**
```python
import multiprocessing
from functools import reduce
from collections import defaultdict

class MapReduceFramework:
    def __init__(self, num_workers=4):
        self.num_workers = num_workers

    def map_reduce(self, data, map_func, reduce_func):
        """Execute MapReduce job"""
        # Phase 1: Map
        map_results = self.map_phase(data, map_func)

        # Phase 2: Shuffle
        shuffled = self.shuffle_phase(map_results)

        # Phase 3: Reduce
        final_results = self.reduce_phase(shuffled, reduce_func)

        return final_results

    def map_phase(self, data, map_func):
        """Distribute map tasks across workers"""
        chunk_size = len(data) // self.num_workers
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

        with multiprocessing.Pool(self.num_workers) as pool:
            map_results = pool.map(self.map_worker, [(chunk, map_func) for chunk in chunks])

        # Flatten results
        flattened = []
        for result in map_results:
            flattened.extend(result)

        return flattened

    def map_worker(self, args):
        """Worker process for map phase"""
        chunk, map_func = args
        results = []

        for item in chunk:
            mapped = map_func(item)
            if isinstance(mapped, list):
                results.extend(mapped)
            else:
                results.append(mapped)

        return results

    def shuffle_phase(self, map_results):
        """Group map results by key"""
        grouped = defaultdict(list)

        for key, value in map_results:
            grouped[key].append(value)

        return dict(grouped)

    def reduce_phase(self, shuffled_data, reduce_func):
        """Apply reduce function to grouped data"""
        reduce_tasks = [(key, values, reduce_func) for key, values in shuffled_data.items()]

        with multiprocessing.Pool(self.num_workers) as pool:
            results = pool.map(self.reduce_worker, reduce_tasks)

        return dict(results)

    def reduce_worker(self, args):
        """Worker process for reduce phase"""
        key, values, reduce_func = args
        reduced_value = reduce_func(values)
        return key, reduced_value

# Example: Word Count
def word_count_example():
    # Sample data
    documents = [
        "hello world hello",
        "world of warcraft",
        "hello python world",
        "python is great"
    ]

    # Map function: split document into words
    def map_words(document):
        words = document.lower().split()
        return [(word, 1) for word in words]

    # Reduce function: sum counts for each word
    def reduce_counts(counts):
        return sum(counts)

    # Execute MapReduce
    mr = MapReduceFramework()
    word_counts = mr.map_reduce(documents, map_words, reduce_counts)

    return word_counts

# Example: Distributed Grep
def distributed_grep_example():
    files = [
        "file1.txt: hello world\nthis is file1\nhello again",
        "file2.txt: goodbye world\nthis is file2\nhello there",
        "file3.txt: python programming\nthis is file3\nhello python"
    ]

    search_term = "hello"

    def map_grep(file_content):
        filename, content = file_content.split(":", 1)
        results = []

        for line_num, line in enumerate(content.strip().split('\n'), 1):
            if search_term in line.lower():
                results.append((filename, f"Line {line_num}: {line}"))

        return results

    def reduce_grep(matches):
        return matches  # Just collect all matches

    mr = MapReduceFramework()
    grep_results = mr.map_reduce(files, map_grep, reduce_grep)

    return grep_results
```

**Consensus Algorithms:**
```python
import random
import time
from enum import Enum

class NodeState(Enum):
    FOLLOWER = 1
    CANDIDATE = 2
    LEADER = 3

class RaftNode:
    """Raft consensus algorithm implementation"""
    def __init__(self, node_id, cluster_nodes):
        self.node_id = node_id
        self.cluster_nodes = cluster_nodes
        self.state = NodeState.FOLLOWER

        # Persistent state
        self.current_term = 0
        self.voted_for = None
        self.log = []  # List of log entries

        # Volatile state
        self.commit_index = 0
        self.last_applied = 0

        # Leader state
        self.next_index = {}  # For each server, index of next log entry to send
        self.match_index = {}  # For each server, index of highest log entry known to be replicated

        # Timers
        self.election_timeout = self.random_election_timeout()
        self.last_heartbeat = time.time()

    def random_election_timeout(self):
        """Random timeout between 150-300ms"""
        return random.uniform(0.15, 0.3)

    def start_election(self):
        """Start leader election"""
        self.state = NodeState.CANDIDATE
        self.current_term += 1
        self.voted_for = self.node_id
        self.election_timeout = self.random_election_timeout()

        votes_received = 1  # Vote for self

        # Send RequestVote RPCs to all other nodes
        for node in self.cluster_nodes:
            if node != self.node_id:
                if self.send_request_vote(node):
                    votes_received += 1

        # Check if won election
        if votes_received > len(self.cluster_nodes) // 2:
            self.become_leader()
        else:
            self.state = NodeState.FOLLOWER

    def send_request_vote(self, target_node):
        """Send RequestVote RPC"""
        request = {
            'term': self.current_term,
            'candidate_id': self.node_id,
            'last_log_index': len(self.log) - 1 if self.log else -1,
            'last_log_term': self.log[-1]['term'] if self.log else 0
        }

        # Simulate RPC call
        response = self.simulate_request_vote_rpc(target_node, request)

        if response['term'] > self.current_term:
            self.current_term = response['term']
            self.voted_for = None
            self.state = NodeState.FOLLOWER
            return False

        return response['vote_granted']

    def become_leader(self):
        """Become leader and start sending heartbeats"""
        self.state = NodeState.LEADER

        # Initialize leader state
        for node in self.cluster_nodes:
            if node != self.node_id:
                self.next_index[node] = len(self.log)
                self.match_index[node] = 0

        # Send initial heartbeat
        self.send_heartbeats()

    def send_heartbeats(self):
        """Send heartbeat (empty AppendEntries) to all followers"""
        for node in self.cluster_nodes:
            if node != self.node_id:
                self.send_append_entries(node, heartbeat=True)

    def send_append_entries(self, target_node, heartbeat=False):
        """Send AppendEntries RPC"""
        prev_log_index = self.next_index[target_node] - 1
        prev_log_term = 0

        if prev_log_index >= 0 and prev_log_index < len(self.log):
            prev_log_term = self.log[prev_log_index]['term']

        entries = []
        if not heartbeat and self.next_index[target_node] < len(self.log):
            entries = self.log[self.next_index[target_node]:]

        request = {
            'term': self.current_term,
            'leader_id': self.node_id,
            'prev_log_index': prev_log_index,
            'prev_log_term': prev_log_term,
            'entries': entries,
            'leader_commit': self.commit_index
        }

        # Simulate RPC call
        response = self.simulate_append_entries_rpc(target_node, request)

        if response['term'] > self.current_term:
            self.current_term = response['term']
            self.state = NodeState.FOLLOWER
            self.voted_for = None
            return

        if response['success']:
            # Update next_index and match_index
            self.match_index[target_node] = prev_log_index + len(entries)
            self.next_index[target_node] = self.match_index[target_node] + 1
        else:
            # Decrement next_index and retry
            self.next_index[target_node] = max(0, self.next_index[target_node] - 1)

    def append_log_entry(self, command):
        """Append new entry to log (leader only)"""
        if self.state != NodeState.LEADER:
            return False

        entry = {
            'term': self.current_term,
            'command': command,
            'index': len(self.log)
        }

        self.log.append(entry)

        # Replicate to followers
        for node in self.cluster_nodes:
            if node != self.node_id:
                self.send_append_entries(node)

        return True

    def update_commit_index(self):
        """Update commit index based on majority replication"""
        if self.state != NodeState.LEADER:
            return

        # Find highest index replicated on majority of servers
        for index in range(self.commit_index + 1, len(self.log)):
            replicated_count = 1  # Count leader

            for node in self.cluster_nodes:
                if node != self.node_id and self.match_index.get(node, 0) >= index:
                    replicated_count += 1

            if replicated_count > len(self.cluster_nodes) // 2:
                if self.log[index]['term'] == self.current_term:
                    self.commit_index = index
            else:
                break

    def simulate_request_vote_rpc(self, target_node, request):
        """Simulate RequestVote RPC response"""
        # In real implementation, this would be network call
        return {
            'term': request['term'],
            'vote_granted': random.choice([True, False])
        }

    def simulate_append_entries_rpc(self, target_node, request):
        """Simulate AppendEntries RPC response"""
        # In real implementation, this would be network call
        return {
            'term': request['term'],
            'success': random.choice([True, False])
        }
```

## Concurrency and Parallelism

**Thread Synchronization:**
```python
import threading
import time
from collections import deque

class ThreadSafeQueue:
    """Thread-safe queue implementation"""
    def __init__(self, maxsize=0):
        self.queue = deque()
        self.maxsize = maxsize
        self.mutex = threading.Lock()
        self.not_empty = threading.Condition(self.mutex)
        self.not_full = threading.Condition(self.mutex)

    def put(self, item, block=True, timeout=None):
        """Put item into queue"""
        with self.not_full:
            if self.maxsize > 0:
                while len(self.queue) >= self.maxsize:
                    if not block:
                        raise Exception("Queue is full")
                    if not self.not_full.wait(timeout):
                        raise Exception("Timeout")

            self.queue.append(item)
            self.not_empty.notify()

    def get(self, block=True, timeout=None):
        """Get item from queue"""
        with self.not_empty:
            while len(self.queue) == 0:
                if not block:
                    raise Exception("Queue is empty")
                if not self.not_empty.wait(timeout):
                    raise Exception("Timeout")

            item = self.queue.popleft()
            self.not_full.notify()
            return item

    def size(self):
        """Get queue size"""
        with self.mutex:
            return len(self.queue)

class ReadWriteLock:
    """Reader-writer lock implementation"""
    def __init__(self):
        self.read_ready = threading.Condition(threading.RLock())
        self.readers = 0

    def acquire_read(self):
        """Acquire read lock"""
        self.read_ready.acquire()
        try:
            self.readers += 1
        finally:
            self.read_ready.release()

    def release_read(self):
        """Release read lock"""
        self.read_ready.acquire()
        try:
            self.readers -= 1
            if self.readers == 0:
                self.read_ready.notifyAll()
        finally:
            self.read_ready.release()

    def acquire_write(self):
        """Acquire write lock"""
        self.read_ready.acquire()
        while self.readers > 0:
            self.read_ready.wait()

    def release_write(self):
        """Release write lock"""
        self.read_ready.release()

class ThreadPool:
    """Thread pool implementation"""
    def __init__(self, num_threads=4):
        self.num_threads = num_threads
        self.task_queue = ThreadSafeQueue()
        self.threads = []
        self.shutdown_flag = threading.Event()

        # Create and start worker threads
        for i in range(num_threads):
            thread = threading.Thread(target=self.worker, args=(i,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)

    def worker(self, worker_id):
        """Worker thread function"""
        while not self.shutdown_flag.is_set():
            try:
                task = self.task_queue.get(timeout=1.0)
                if task is None:  # Poison pill
                    break

                func, args, kwargs = task
                try:
                    func(*args, **kwargs)
                except Exception as e:
                    print(f"Worker {worker_id} error: {e}")

            except:
                continue  # Timeout, check shutdown flag

    def submit(self, func, *args, **kwargs):
        """Submit task to thread pool"""
        if not self.shutdown_flag.is_set():
            self.task_queue.put((func, args, kwargs))

    def shutdown(self, wait=True):
        """Shutdown thread pool"""
        self.shutdown_flag.set()

        # Add poison pills
        for _ in range(self.num_threads):
            self.task_queue.put(None)

        if wait:
            for thread in self.threads:
                thread.join()

class ProducerConsumer:
    """Producer-Consumer pattern implementation"""
    def __init__(self, buffer_size=10):
        self.buffer = ThreadSafeQueue(buffer_size)
        self.running = True

    def producer(self, producer_id, items):
        """Producer function"""
        for item in items:
            if not self.running:
                break

            self.buffer.put(f"Producer-{producer_id}: {item}")
            print(f"Produced: {item}")
            time.sleep(0.1)  # Simulate work

    def consumer(self, consumer_id):
        """Consumer function"""
        while self.running:
            try:
                item = self.buffer.get(timeout=1.0)
                print(f"Consumer-{consumer_id} consumed: {item}")
                time.sleep(0.2)  # Simulate processing
            except:
                continue

    def run_simulation(self, num_producers=2, num_consumers=3):
        """Run producer-consumer simulation"""
        threads = []

        # Start producers
        for i in range(num_producers):
            items = [f"item-{j}" for j in range(5)]
            thread = threading.Thread(target=self.producer, args=(i, items))
            thread.start()
            threads.append(thread)

        # Start consumers
        for i in range(num_consumers):
            thread = threading.Thread(target=self.consumer, args=(i,))
            thread.daemon = True
            thread.start()
            threads.append(thread)

        # Wait for producers to finish
        for thread in threads[:num_producers]:
            thread.join()

        # Stop consumers
        time.sleep(2)  # Let consumers finish current items
        self.running = False
```

**Parallel Processing:**
```python
import multiprocessing
import concurrent.futures
import time
import numpy as np

class ParallelProcessor:
    """Parallel processing utilities"""

    @staticmethod
    def cpu_bound_task(n):
        """CPU-intensive task for demonstration"""
        total = 0
        for i in range(n):
            total += i * i
        return total

    @staticmethod
    def io_bound_task(duration):
        """I/O-bound task simulation"""
        time.sleep(duration)
        return f"Task completed after {duration} seconds"

    def parallel_cpu_tasks(self, tasks, max_workers=None):
        """Execute CPU-bound tasks in parallel using processes"""
        if max_workers is None:
            max_workers = multiprocessing.cpu_count()

        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.cpu_bound_task, task) for task in tasks]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

        return results

    def parallel_io_tasks(self, tasks, max_workers=None):
        """Execute I/O-bound tasks in parallel using threads"""
        if max_workers is None:
            max_workers = min(32, len(tasks) + 4)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.io_bound_task, task) for task in tasks]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

        return results

    def parallel_map(self, func, data, chunk_size=None):
        """Parallel map operation"""
        if chunk_size is None:
            chunk_size = max(1, len(data) // multiprocessing.cpu_count())

        with multiprocessing.Pool() as pool:
            result = pool.map(func, data, chunksize=chunk_size)

        return result

# Matrix multiplication example
def parallel_matrix_multiply():
    """Parallel matrix multiplication"""
    def multiply_chunk(args):
        A_chunk, B, start_row = args
        result_chunk = np.dot(A_chunk, B)
        return start_row, result_chunk

    def parallel_matrix_mult(A, B, num_processes=None):
        if num_processes is None:
            num_processes = multiprocessing.cpu_count()

        # Split matrix A into chunks
        chunk_size = A.shape[0] // num_processes
        chunks = []

        for i in range(num_processes):
            start = i * chunk_size
            end = start + chunk_size if i < num_processes - 1 else A.shape[0]
            chunks.append((A[start:end], B, start))

        # Process chunks in parallel
        with multiprocessing.Pool(num_processes) as pool:
            results = pool.map(multiply_chunk, chunks)

        # Combine results
        result_matrix = np.zeros((A.shape[0], B.shape[1]))
        for start_row, chunk_result in results:
            end_row = start_row + chunk_result.shape[0]
            result_matrix[start_row:end_row] = chunk_result

        return result_matrix

    # Example usage
    A = np.random.rand(1000, 500)
    B = np.random.rand(500, 800)

    start_time = time.time()
    result = parallel_matrix_mult(A, B)
    parallel_time = time.time() - start_time

    start_time = time.time()
    result_serial = np.dot(A, B)
    serial_time = time.time() - start_time

    print(f"Serial time: {serial_time:.4f}s")
    print(f"Parallel time: {parallel_time:.4f}s")
    print(f"Speedup: {serial_time / parallel_time:.2f}x")

    return result

# Async/await pattern
import asyncio

class AsyncProcessor:
    """Asynchronous processing example"""

    async def async_io_task(self, task_id, duration):
        """Asynchronous I/O task"""
        print(f"Task {task_id} starting")
        await asyncio.sleep(duration)  # Simulate async I/O
        print(f"Task {task_id} completed after {duration}s")
        return f"Result from task {task_id}"

    async def run_concurrent_tasks(self, tasks):
        """Run multiple async tasks concurrently"""
        # Create tasks
        async_tasks = [
            self.async_io_task(i, duration)
            for i, duration in enumerate(tasks)
        ]

        # Wait for all tasks to complete
        results = await asyncio.gather(*async_tasks)
        return results

    async def producer_consumer_async(self):
        """Async producer-consumer pattern"""
        queue = asyncio.Queue(maxsize=5)

        async def producer(name, queue):
            for i in range(5):
                item = f"{name}-item-{i}"
                await queue.put(item)
                print(f"Produced: {item}")
                await asyncio.sleep(0.1)

        async def consumer(name, queue):
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=1.0)
                    print(f"Consumer {name} got: {item}")
                    queue.task_done()
                    await asyncio.sleep(0.2)
                except asyncio.TimeoutError:
                    break

        # Create producers and consumers
        producers = [
            producer("P1", queue),
            producer("P2", queue)
        ]

        consumers = [
            consumer("C1", queue),
            consumer("C2", queue)
        ]

        # Run concurrently
        await asyncio.gather(*producers, *consumers)

# Example usage
async def async_example():
    processor = AsyncProcessor()

    # Run concurrent I/O tasks
    tasks = [0.5, 1.0, 0.3, 0.8, 0.6]
    results = await processor.run_concurrent_tasks(tasks)
    print("Results:", results)

    # Run producer-consumer
    await processor.producer_consumer_async()

# Run async example
# asyncio.run(async_example())
```

---

**Stage 4 Complete!**

This final stage covers Databases (design, SQL/NoSQL, transactions, indexing), Networks and Distributed Systems (protocols, client-server, distributed computing, concurrency), providing comprehensive coverage of Computer Science fundamentals through advanced topics.