# Assembly Language Learning Guide

## Table of Contents

1. [Assembly Fundamentals](#1-assembly-fundamentals)
2. [Registers and Data Types](#2-registers-and-data-types)
3. [Basic Instructions](#3-basic-instructions)
4. [Memory Addressing](#4-memory-addressing)
5. [Arithmetic Operations](#5-arithmetic-operations)
6. [Logical Operations](#6-logical-operations)
7. [Control Flow Instructions](#7-control-flow-instructions)
8. [Comparison and Conditional Jumps](#8-comparison-and-conditional-jumps)
9. [String Operations](#9-string-operations)
10. [Input/Output Operations](#10-inputoutput-operations)
11. [Advanced Instructions](#11-advanced-instructions)
12. [Memory Management](#12-memory-management)
13. [Procedures and Functions](#13-procedures-and-functions)
14. [Stack Operations](#14-stack-operations)
15. [System Calls](#15-system-calls)
16. [Floating Point Operations](#16-floating-point-operations)
17. [Optimization Techniques](#17-optimization-techniques)
18. [Debugging Assembly](#18-debugging-assembly)
19. [Inline Assembly](#19-inline-assembly)
20. [Assembly Best Practices](#20-assembly-best-practices)

---

## 1. Assembly Fundamentals

Assembly language is a low-level programming language that directly corresponds to machine code instructions.

### What is Assembly Language?

```assembly
; Assembly language characteristics
; - One-to-one correspondence with machine code
; - Platform-specific (x86, x64, ARM, etc.)
; - Direct hardware control
; - Maximum performance potential
; - Minimal abstraction
```

### Assembly Program Structure

```assembly
; NASM syntax (x86-64)
section .data
    msg db 'Hello, World!', 0    ; Define string with null terminator
    len equ $ - msg              ; Calculate string length

section .bss
    buffer resb 256              ; Reserve 256 bytes

section .text
    global _start                ; Entry point

_start:
    ; Program instructions go here
    mov rax, 60                  ; System call: exit
    mov rdi, 0                   ; Exit status
    syscall                      ; Invoke system call
```

### MASM vs NASM vs GAS Syntax

```assembly
; MASM (Microsoft Macro Assembler)
.data
    msg db 'Hello World', 0
.code
main proc
    mov eax, 0
    ret
main endp

; NASM (Netwide Assembler)
section .data
    msg db 'Hello World', 0
section .text
    global main
main:
    mov eax, 0
    ret

; GAS (GNU Assembler) - AT&T syntax
.data
    msg: .asciz "Hello World"
.text
.globl main
main:
    movl $0, %eax
    ret
```

### Basic Program Example

```assembly
; hello.asm - Simple Hello World (NASM x86-64 Linux)
section .data
    hello db 'Hello, Assembly!', 10, 0
    hello_len equ $ - hello - 1

section .text
    global _start

_start:
    ; Write system call
    mov rax, 1          ; sys_write
    mov rdi, 1          ; stdout
    mov rsi, hello      ; message
    mov rdx, hello_len  ; message length
    syscall

    ; Exit system call
    mov rax, 60         ; sys_exit
    mov rdi, 0          ; exit status
    syscall
```

## 2. Registers and Data Types

Registers are high-speed storage locations in the CPU.

### x86-64 General Purpose Registers

```assembly
; 64-bit registers (full)
rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15

; 32-bit registers (lower 32 bits)
eax, ebx, ecx, edx, esi, edi, ebp, esp, r8d-r15d

; 16-bit registers (lower 16 bits)
ax, bx, cx, dx, si, di, bp, sp, r8w-r15w

; 8-bit registers (lower 8 bits)
al, bl, cl, dl, sil, dil, bpl, spl, r8b-r15b

; 8-bit registers (bits 8-15 of ax, bx, cx, dx)
ah, bh, ch, dh
```

### Register Usage Examples

```assembly
section .text
global _start

_start:
    ; 64-bit operations
    mov rax, 0x1234567890ABCDEF
    mov rbx, rax
    
    ; 32-bit operations (automatically zeros upper 32 bits)
    mov eax, 0x12345678
    mov ebx, eax
    
    ; 16-bit operations
    mov ax, 0x1234
    mov bx, ax
    
    ; 8-bit operations
    mov al, 0x12
    mov bl, al
    mov ah, 0x34    ; High byte of ax
    
    ; Register arithmetic
    add rax, rbx    ; rax = rax + rbx
    sub rcx, rdx    ; rcx = rcx - rdx
    mul rbx         ; rax = rax * rbx (unsigned)
```

### Special Purpose Registers

```assembly
; Instruction Pointer
rip             ; Points to next instruction

; Stack Pointer
rsp             ; Points to top of stack

; Base Pointer
rbp             ; Base pointer for stack frames

; Flags Register
rflags          ; Contains status flags (carry, zero, sign, etc.)

; Flags register bits
CF              ; Carry Flag (bit 0)
ZF              ; Zero Flag (bit 6)
SF              ; Sign Flag (bit 7)
OF              ; Overflow Flag (bit 11)
```

### Data Types and Sizes

```assembly
section .data
    ; Integer data types
    byte_val    db 255          ; 8-bit (1 byte)
    word_val    dw 65535        ; 16-bit (2 bytes)
    dword_val   dd 4294967295   ; 32-bit (4 bytes)
    qword_val   dq 0x123456789ABCDEF ; 64-bit (8 bytes)
    
    ; Character and string data
    char_val    db 'A'          ; Single character
    string_val  db 'Hello', 0   ; Null-terminated string
    
    ; Arrays
    array_bytes db 1, 2, 3, 4, 5
    array_words dw 100, 200, 300, 400
    array_dwords dd 1000, 2000, 3000
    
    ; Floating point (requires FPU)
    float_val   dd 3.14159      ; 32-bit float
    double_val  dq 2.71828      ; 64-bit double
    
    ; Uninitialized data
section .bss
    buffer      resb 1024       ; Reserve 1024 bytes
    int_buffer  resd 256        ; Reserve 256 dwords
```

## 3. Basic Instructions

Fundamental assembly instructions for data movement and basic operations.

### MOV - Data Movement

```assembly
section .data
    value1 dd 42
    value2 dd 0

section .text
global _start

_start:
    ; Register to register
    mov rax, rbx        ; Copy rbx to rax
    
    ; Immediate to register
    mov rax, 42         ; Load immediate value 42 into rax
    mov rbx, 0x1234     ; Load hex value into rbx
    
    ; Memory to register
    mov rax, [value1]   ; Load value from memory address value1
    mov rbx, [rax]      ; Load value from address stored in rax
    
    ; Register to memory
    mov [value2], rax   ; Store rax value to memory address value2
    mov [rbx], 100      ; Store immediate value to address in rbx
    
    ; Different sizes
    mov al, 0xFF        ; 8-bit move
    mov ax, 0x1234      ; 16-bit move
    mov eax, 0x12345678 ; 32-bit move
    mov rax, 0x123456789ABCDEF ; 64-bit move
```

### PUSH and POP - Stack Operations

```assembly
section .text
global _start

_start:
    ; Push values onto stack
    push rax            ; Push rax onto stack
    push 42             ; Push immediate value
    push qword [value1] ; Push memory value
    
    ; Pop values from stack (LIFO - Last In, First Out)
    pop rbx             ; Pop top value into rbx
    pop rcx             ; Pop next value into rcx
    pop rdx             ; Pop next value into rdx
    
    ; Stack pointer manipulation
    mov rax, rsp        ; Get current stack pointer
    sub rsp, 16         ; Allocate 16 bytes on stack
    add rsp, 16         ; Deallocate 16 bytes
```

### LEA - Load Effective Address

```assembly
section .data
    array dd 10, 20, 30, 40, 50

section .text
global _start

_start:
    ; LEA calculates address without accessing memory
    lea rax, [array]        ; rax = address of array
    lea rbx, [rax + 4]      ; rbx = address of array[1]
    lea rcx, [rax + rsi*4]  ; rcx = address of array[rsi]
    lea rdx, [rax + rsi*4 + 8] ; rdx = address of array[rsi+2]
    
    ; LEA for arithmetic (clever use)
    mov rsi, 5
    lea rax, [rsi + rsi*2]  ; rax = rsi * 3 (5 * 3 = 15)
    lea rbx, [rsi*8 + 7]    ; rbx = rsi * 8 + 7
```

### XCHG - Exchange Values

```assembly
section .text
global _start

_start:
    mov rax, 10
    mov rbx, 20
    
    ; Exchange register contents
    xchg rax, rbx       ; rax = 20, rbx = 10
    
    ; Exchange register with memory
    mov rax, 30
    xchg rax, [value1]  ; rax gets value1, value1 gets 30
    
    ; Common idiom: clear register
    xor rax, rax        ; rax = 0 (faster than mov rax, 0)
```

## 4. Memory Addressing

Different ways to access memory locations in assembly.

### Addressing Modes

```assembly
section .data
    array dd 10, 20, 30, 40, 50
    base_addr dq array

section .text
global _start

_start:
    ; Direct addressing
    mov rax, [array]        ; Load first element directly
    
    ; Register indirect
    mov rbx, array          ; rbx = address of array
    mov rax, [rbx]          ; rax = value at address in rbx
    
    ; Register + displacement
    mov rax, [rbx + 4]      ; rax = value at rbx + 4 bytes
    mov rax, [rbx + 8]      ; rax = value at rbx + 8 bytes
    
    ; Base + index
    mov rsi, 2              ; Index
    mov rax, [rbx + rsi*4]  ; rax = array[rsi] (rsi*4 for dword)
    
    ; Base + index + displacement
    mov rax, [rbx + rsi*4 + 8] ; rax = array[rsi + 2]
    
    ; Scale factors: 1, 2, 4, 8
    mov rax, [rbx + rsi*1]  ; Byte array
    mov rax, [rbx + rsi*2]  ; Word array
    mov rax, [rbx + rsi*4]  ; Dword array
    mov rax, [rbx + rsi*8]  ; Qword array
```

### Working with Arrays

```assembly
section .data
    numbers dd 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
    count equ ($ - numbers) / 4    ; Number of elements

section .text
global _start

_start:
    ; Array traversal
    mov rsi, 0              ; Index
    mov rbx, numbers        ; Base address
    
loop_start:
    mov rax, [rbx + rsi*4]  ; Load numbers[rsi]
    ; Process rax here
    inc rsi                 ; Increment index
    cmp rsi, count          ; Compare with array size
    jl loop_start           ; Jump if less than count
    
    ; Alternative: pointer arithmetic
    mov rbx, numbers        ; Start address
    mov rcx, numbers + count*4  ; End address
    
ptr_loop:
    mov rax, [rbx]          ; Load current value
    ; Process rax here
    add rbx, 4              ; Move to next element
    cmp rbx, rcx            ; Compare with end
    jl ptr_loop             ; Continue if not at end
```

### String Operations

```assembly
section .data
    source db 'Hello', 0
    dest times 10 db 0      ; Destination buffer

section .text
global _start

_start:
    ; Manual string copy
    mov rsi, source         ; Source address
    mov rdi, dest           ; Destination address
    
copy_loop:
    mov al, [rsi]           ; Load byte from source
    mov [rdi], al           ; Store byte to destination
    inc rsi                 ; Next source byte
    inc rdi                 ; Next destination byte
    test al, al             ; Check if null terminator
    jnz copy_loop           ; Continue if not zero
    
    ; Using string instructions (more efficient)
    mov rsi, source
    mov rdi, dest
    mov rcx, 6              ; Number of bytes to copy
    rep movsb               ; Repeat move string byte
```

## 5. Arithmetic Operations

Basic and advanced arithmetic operations in assembly.

### Addition and Subtraction

```assembly
section .data
    num1 dd 100
    num2 dd 50
    result dd 0

section .text
global _start

_start:
    ; Basic addition
    mov rax, 10
    add rax, 5              ; rax = 15
    
    ; Addition with memory
    mov rax, [num1]         ; Load num1
    add rax, [num2]         ; Add num2
    mov [result], rax       ; Store result
    
    ; Subtraction
    mov rax, 20
    sub rax, 8              ; rax = 12
    
    ; Add with carry (for multi-precision arithmetic)
    mov rax, 0xFFFFFFFFFFFFFFFF
    mov rbx, 1
    add rax, rbx            ; Sets carry flag
    adc rcx, 0              ; Add carry to rcx
    
    ; Subtract with borrow
    mov rax, 0
    mov rbx, 1
    sub rax, rbx            ; Sets carry flag (borrow)
    sbb rcx, 0              ; Subtract borrow from rcx
    
    ; Increment and decrement
    inc rax                 ; rax = rax + 1
    dec rbx                 ; rbx = rbx - 1
```

### Multiplication and Division

```assembly
section .text
global _start

_start:
    ; Unsigned multiplication
    mov rax, 10
    mov rbx, 5
    mul rbx                 ; rax = rax * rbx (result in rdx:rax)
    
    ; Signed multiplication
    mov rax, -10
    mov rbx, 5
    imul rbx                ; rax = rax * rbx (signed)
    
    ; Immediate multiplication
    mov rax, 10
    imul rax, 3             ; rax = rax * 3
    imul rax, rbx, 4        ; rax = rbx * 4
    
    ; Division preparation
    xor rdx, rdx            ; Clear rdx (high part of dividend)
    mov rax, 100            ; Dividend (low part)
    mov rbx, 7              ; Divisor
    
    ; Unsigned division
    div rbx                 ; rax = quotient, rdx = remainder
    
    ; Signed division
    mov rax, -100
    cqo                     ; Sign extend rax into rdx:rax
    mov rbx, 7
    idiv rbx                ; rax = quotient, rdx = remainder
    
    ; Power of 2 multiplication/division (faster)
    mov rax, 10
    shl rax, 1              ; rax = rax * 2 (shift left)
    shl rax, 2              ; rax = rax * 4 (shift left by 2)
    shr rax, 1              ; rax = rax / 2 (shift right)
```

### Bit Manipulation

```assembly
section .text
global _start

_start:
    ; Bit shifts
    mov rax, 0b11110000     ; Binary literal
    shl rax, 1              ; Shift left: 0b111100000
    shr rax, 2              ; Shift right: 0b1111000
    
    ; Arithmetic shift (preserves sign)
    mov rax, -8             ; Negative number
    sar rax, 1              ; Arithmetic shift right: -4
    
    ; Rotate operations
    mov rax, 0x8000000000000001
    rol rax, 1              ; Rotate left
    ror rax, 1              ; Rotate right
    
    ; Bit operations
    mov rax, 0xFF00
    mov rbx, 0x0F0F
    
    and rax, rbx            ; Bitwise AND
    or rax, rbx             ; Bitwise OR
    xor rax, rbx            ; Bitwise XOR
    not rax                 ; Bitwise NOT
    
    ; Testing bits
    test rax, 0x01          ; Test if bit 0 is set
    jnz bit_set             ; Jump if bit is set
    
    ; Setting/clearing bits
    bts rax, 5              ; Set bit 5
    btr rax, 3              ; Clear bit 3
    btc rax, 7              ; Complement bit 7

bit_set:
    nop                     ; No operation
```

## 6. Logical Operations

Logical operations and bit manipulation techniques.

### Boolean Logic

```assembly
section .data
    flag1 db 1
    flag2 db 0
    result db 0

section .text
global _start

_start:
    ; Logical AND
    mov al, [flag1]
    and al, [flag2]         ; al = flag1 AND flag2
    mov [result], al
    
    ; Logical OR
    mov al, [flag1]
    or al, [flag2]          ; al = flag1 OR flag2
    
    ; Logical XOR (exclusive OR)
    mov al, [flag1]
    xor al, [flag2]         ; al = flag1 XOR flag2
    
    ; Logical NOT
    mov al, [flag1]
    not al                  ; al = NOT flag1
    
    ; Clear register (common idiom)
    xor rax, rax            ; rax = 0 (faster than mov rax, 0)
    
    ; Toggle bits
    xor rax, 0xFF           ; Toggle lower 8 bits
```

### Bit Field Operations

```assembly
section .data
    flags dq 0              ; 64-bit flag register

section .text
global _start

_start:
    ; Set specific bits
    mov rax, [flags]
    or rax, 0x07            ; Set bits 0, 1, 2
    mov [flags], rax
    
    ; Clear specific bits
    mov rax, [flags]
    and rax, ~0x18          ; Clear bits 3, 4 (NOT 0x18)
    mov [flags], rax
    
    ; Extract bit field (bits 4-7)
    mov rax, [flags]
    shr rax, 4              ; Shift right to position
    and rax, 0x0F           ; Mask to get 4 bits
    
    ; Insert bit field
    mov rbx, 0x0A           ; Value to insert (4 bits)
    shl rbx, 4              ; Shift to position
    mov rax, [flags]
    and rax, ~0xF0          ; Clear target bits
    or rax, rbx             ; Insert new value
    mov [flags], rax
    
    ; Check if any bit is set
    test rax, 0xFF          ; Test if any of lower 8 bits set
    jnz some_bit_set
    
    ; Check specific bit
    bt rax, 5               ; Test bit 5
    jc bit_5_set            ; Jump if carry (bit was set)

some_bit_set:
bit_5_set:
    nop
```

### Bit Counting

```assembly
section .text
global _start

_start:
    mov rax, 0b11010110     ; Test value
    
    ; Count set bits (population count)
    xor rcx, rcx            ; Counter
    mov rbx, rax            ; Copy for counting
    
count_loop:
    test rbx, rbx           ; Check if zero
    jz count_done
    inc rcx                 ; Increment counter
    and rbx, rbx - 1        ; Clear lowest set bit
    jmp count_loop
    
count_done:
    ; rcx now contains number of set bits
    
    ; Find first set bit (bit scan forward)
    mov rax, 0b11010000
    bsf rbx, rax            ; rbx = index of first set bit
    jz no_bits_set          ; Jump if no bits set
    
    ; Find last set bit (bit scan reverse)
    bsr rcx, rax            ; rcx = index of last set bit
    
    ; Leading zero count
    mov rax, 0x0000FF00
    lzcnt rbx, rax          ; Count leading zeros
    
no_bits_set:
    nop
```

## 7. Control Flow Instructions

Instructions that control program execution flow.

### Unconditional Jumps

```assembly
section .text
global _start

_start:
    ; Unconditional jump
    jmp target              ; Jump to target label
    
    ; This code is never executed
    mov rax, 999
    
target:
    mov rax, 42
    
    ; Short jump (within -128 to +127 bytes)
    jmp short nearby_label
    
    ; Near jump (within same segment)
    jmp near far_label
    
nearby_label:
    nop
    
far_label:
    ; Jump table example
    mov rax, 2              ; Index
    jmp [jump_table + rax*8] ; Jump to address in table
    
    ; Jump table data
jump_table:
    dq case_0
    dq case_1
    dq case_2
    
case_0:
    ; Handle case 0
    jmp end_switch
    
case_1:
    ; Handle case 1
    jmp end_switch
    
case_2:
    ; Handle case 2
    
end_switch:
    nop
```

### Conditional Jumps

```assembly
section .text
global _start

_start:
    mov rax, 10
    mov rbx, 20
    
    ; Compare and jump
    cmp rax, rbx            ; Compare rax with rbx
    je equal                ; Jump if equal (ZF = 1)
    jne not_equal           ; Jump if not equal (ZF = 0)
    jl less                 ; Jump if less (signed)
    jle less_equal          ; Jump if less or equal (signed)
    jg greater              ; Jump if greater (signed)
    jge greater_equal       ; Jump if greater or equal (signed)
    
    ; Unsigned comparisons
    jb below                ; Jump if below (unsigned less)
    jbe below_equal         ; Jump if below or equal
    ja above                ; Jump if above (unsigned greater)
    jae above_equal         ; Jump if above or equal
    
    ; Flag-based jumps
    test rax, rax           ; Test if rax is zero
    jz is_zero              ; Jump if zero (ZF = 1)
    jnz not_zero            ; Jump if not zero (ZF = 0)
    
    ; Carry flag jumps
    add rax, rbx            ; Addition might set carry
    jc carry_set            ; Jump if carry flag set
    jnc no_carry            ; Jump if carry flag clear
    
    ; Overflow jumps
    add rax, 0x7FFFFFFFFFFFFFFF
    jo overflow             ; Jump if overflow
    jno no_overflow         ; Jump if no overflow
    
    ; Sign flag jumps
    mov rax, -5
    test rax, rax
    js negative             ; Jump if sign flag set (negative)
    jns positive            ; Jump if sign flag clear (positive)

equal:
not_equal:
less:
less_equal:
greater:
greater_equal:
below:
below_equal:
above:
above_equal:
is_zero:
not_zero:
carry_set:
no_carry:
overflow:
no_overflow:
negative:
positive:
    nop
```

### Loops

```assembly
section .data
    array dd 1, 2, 3, 4, 5
    count equ 5

section .text
global _start

_start:
    ; Simple loop with counter
    mov rcx, count          ; Loop counter
    xor rax, rax            ; Sum accumulator
    mov rsi, 0              ; Array index
    
simple_loop:
    add rax, [array + rsi*4] ; Add array element
    inc rsi                 ; Next element
    dec rcx                 ; Decrement counter
    jnz simple_loop         ; Jump if not zero
    
    ; Loop with explicit condition
    mov rsi, 0              ; Index
    xor rax, rax            ; Sum
    
condition_loop:
    cmp rsi, count          ; Compare index with count
    jge loop_end            ; Jump if greater or equal
    add rax, [array + rsi*4] ; Add element
    inc rsi                 ; Next index
    jmp condition_loop      ; Repeat
    
loop_end:
    ; LOOP instruction (decrements rcx and jumps if not zero)
    mov rcx, count
    mov rsi, 0
    xor rax, rax
    
loop_instruction:
    add rax, [array + rsi*4]
    inc rsi
    loop loop_instruction   ; Equivalent to: dec rcx; jnz loop_instruction
    
    ; While loop equivalent
    mov rsi, 0
    
while_loop:
    cmp rsi, count
    jge while_end
    ; Loop body
    inc rsi
    jmp while_loop
    
while_end:
    ; Do-while loop equivalent
    mov rsi, 0
    
do_while:
    ; Loop body
    inc rsi
    cmp rsi, count
    jl do_while             ; Continue if less than count
```

## 8. Comparison and Conditional Jumps

Detailed examination of comparison operations and conditional execution.

### CMP Instruction Variations

```assembly
section .data
    val1 dd 42
    val2 dd 42

section .text
global _start

_start:
    ; Compare register with register
    mov rax, 10
    mov rbx, 20
    cmp rax, rbx            ; Sets flags based on rax - rbx
    
    ; Compare register with immediate
    cmp rax, 15             ; Compare rax with 15
    
    ; Compare register with memory
    cmp rax, [val1]         ; Compare rax with value at val1
    
    ; Compare memory with immediate
    cmp dword [val1], 42    ; Compare memory value with 42
    
    ; Different data sizes
    cmp al, 0xFF            ; 8-bit compare
    cmp ax, 0x1234          ; 16-bit compare
    cmp eax, 0x12345678     ; 32-bit compare
    cmp rax, 0x123456789ABCDEF ; 64-bit compare
```

### TEST Instruction

```assembly
section .text
global _start

_start:
    mov rax, 0b11010110
    
    ; Test if register is zero
    test rax, rax           ; Equivalent to AND but doesn't modify rax
    jz is_zero              ; Jump if result is zero
    
    ; Test specific bits
    test rax, 0x01          ; Test if bit 0 is set
    jnz bit_0_set
    
    test rax, 0x80          ; Test if bit 7 is set
    jnz bit_7_set
    
    ; Test multiple bits
    test rax, 0x18          ; Test if bits 3 or 4 are set
    jnz some_bits_set
    
    ; Test for even/odd
    test rax, 1             ; Test lowest bit
    jz is_even              ; Jump if even (bit 0 clear)
    jnz is_odd              ; Jump if odd (bit 0 set)

is_zero:
bit_0_set:
bit_7_set:
some_bits_set:
is_even:
is_odd:
    nop
```

### Conditional Set Instructions

```assembly
section .data
    result db 0

section .text
global _start

_start:
    mov rax, 10
    mov rbx, 20
    cmp rax, rbx
    
    ; Set byte based on condition
    sete [result]           ; Set if equal (ZF = 1)
    setne [result]          ; Set if not equal (ZF = 0)
    setl [result]           ; Set if less (signed)
    setle [result]          ; Set if less or equal (signed)
    setg [result]           ; Set if greater (signed)
    setge [result]          ; Set if greater or equal (signed)
    setb [result]           ; Set if below (unsigned)
    setbe [result]          ; Set if below or equal (unsigned)
    seta [result]           ; Set if above (unsigned)
    setae [result]          ; Set if above or equal (unsigned)
    
    ; Flag-based sets
    setz [result]           ; Set if zero flag set
    setnz [result]          ; Set if zero flag clear
    setc [result]           ; Set if carry flag set
    setnc [result]          ; Set if carry flag clear
    sets [result]           ; Set if sign flag set
    setns [result]          ; Set if sign flag clear
    seto [result]           ; Set if overflow flag set
    setno [result]          ; Set if overflow flag clear
```

### Complex Conditional Logic

```assembly
section .text
global _start

_start:
    ; Multiple condition checks
    mov rax, 15
    mov rbx, 10
    mov rcx, 20
    
    ; Check if rax is between rbx and rcx (rbx <= rax <= rcx)
    cmp rax, rbx
    jl not_in_range         ; Jump if rax < rbx
    cmp rax, rcx
    jg not_in_range         ; Jump if rax > rcx
    ; rax is in range
    jmp in_range
    
not_in_range:
    ; Handle out of range
    jmp end_range_check
    
in_range:
    ; Handle in range
    
end_range_check:
    ; Logical AND condition: (rax > 5) AND (rax < 25)
    cmp rax, 5
    jle and_false           ; Jump if rax <= 5
    cmp rax, 25
    jge and_false           ; Jump if rax >= 25
    ; Both conditions true
    jmp and_true
    
and_false:
    ; At least one condition false
    jmp end_and
    
and_true:
    ; Both conditions true
    
end_and:
    ; Logical OR condition: (rax < 10) OR (rax > 50)
    cmp rax, 10
    jl or_true              ; Jump if rax < 10
    cmp rax, 50
    jg or_true              ; Jump if rax > 50
    ; Neither condition true
    jmp or_false
    
or_true:
    ; At least one condition true
    jmp end_or
    
or_false:
    ; Both conditions false
    
end_or:
    nop
```

### Switch Statement Implementation

```assembly
section .data
    choice dd 2

section .text
global _start

_start:
    mov eax, [choice]
    
    ; Range check
    cmp eax, 0
    jl default_case         ; Less than 0
    cmp eax, 3
    jg default_case         ; Greater than 3
    
    ; Jump table approach
    jmp [jump_table + rax*8]

jump_table:
    dq case_0
    dq case_1
    dq case_2
    dq case_3
    
case_0:
    ; Handle case 0
    mov rbx, 100
    jmp switch_end
    
case_1:
    ; Handle case 1
    mov rbx, 200
    jmp switch_end
    
case_2:
    ; Handle case 2
    mov rbx, 300
    jmp switch_end
    
case_3:
    ; Handle case 3
    mov rbx, 400
    jmp switch_end
    
default_case:
    ; Handle default case
    mov rbx, 0
    
switch_end:
    nop
```

## 9. String Operations

String manipulation and processing operations.

### Basic String Operations

```assembly
section .data
    source db 'Hello World', 0
    dest times 20 db 0
    pattern db 'World', 0
    
section .text
global _start

_start:
    ; Manual string length calculation
    mov rsi, source         ; Source pointer
    xor rcx, rcx            ; Length counter
    
strlen_loop:
    mov al, [rsi + rcx]     ; Load character
    test al, al             ; Check for null terminator
    jz strlen_done          ; Jump if zero (end of string)
    inc rcx                 ; Increment counter
    jmp strlen_loop         ; Continue
    
strlen_done:
    ; rcx now contains string length
    
    ; Manual string copy
    mov rsi, source         ; Source
    mov rdi, dest           ; Destination
    
strcpy_loop:
    mov al, [rsi]           ; Load source character
    mov [rdi], al           ; Store to destination
    inc rsi                 ; Next source
    inc rdi                 ; Next destination
    test al, al             ; Check for null terminator
    jnz strcpy_loop         ; Continue if not zero
    
    ; String comparison
    mov rsi, source         ; First string
    mov rdi, dest           ; Second string
    
strcmp_loop:
    mov al, [rsi]           ; Load from first string
    mov bl, [rdi]           ; Load from second string
    cmp al, bl              ; Compare characters
    jne strings_different   ; Jump if different
    test al, al             ; Check for end of string
    jz strings_equal        ; Both strings ended, they're equal
    inc rsi                 ; Next character in first string
    inc rdi                 ; Next character in second string
    jmp strcmp_loop         ; Continue
    
strings_equal:
    mov rax, 0              ; Strings are equal
    jmp strcmp_done
    
strings_different:
    mov rax, 1              ; Strings are different
    
strcmp_done:
    nop
```

### REP String Instructions

```assembly
section .data
    source db 'Assembly Language Programming', 0
    dest times 50 db 0
    fill_char db 'X'
    search_char db 'g'

section .text
global _start

_start:
    ; REP MOVSB - Copy string
    mov rsi, source         ; Source
    mov rdi, dest           ; Destination
    mov rcx, 30             ; Number of bytes to copy
    cld                     ; Clear direction flag (forward)
    rep movsb               ; Repeat move string byte
    
    ; REP STOSB - Fill memory with character
    mov rdi, dest           ; Destination
    mov al, [fill_char]     ; Character to fill
    mov rcx, 20             ; Number of bytes to fill
    rep stosb               ; Repeat store string byte
    
    ; REP SCASB - Search for character
    mov rdi, source         ; String to search
    mov al, [search_char]   ; Character to find
    mov rcx, 30             ; Maximum characters to search
    repne scasb             ; Repeat while not equal
    jne char_not_found      ; Jump if character not found
    ; Character found, rdi points to character after match
    sub rdi, source         ; Calculate position
    dec rdi                 ; Adjust for post-increment
    jmp search_done
    
char_not_found:
    mov rdi, -1             ; Character not found
    
search_done:
    ; REP CMPSB - Compare strings
    mov rsi, source         ; First string
    mov rdi, dest           ; Second string
    mov rcx, 20             ; Number of bytes to compare
    repe cmpsb              ; Repeat while equal
    je strings_match        ; Jump if all compared bytes match
    ; Strings don't match
    jmp compare_done
    
strings_match:
    ; Strings match
    
compare_done:
    nop
```

### Advanced String Operations

```assembly
section .data
    text db 'The quick brown fox jumps over the lazy dog', 0
    substring db 'fox', 0
    replacement db 'cat', 0
    result times 100 db 0

section .text
global _start

_start:
    ; Find substring
    mov rsi, text           ; Source text
    mov rdi, substring      ; Substring to find
    
find_substring:
    mov rcx, rsi            ; Save current position
    mov rdx, rdi            ; Reset substring pointer
    
compare_chars:
    mov al, [rcx]           ; Character from text
    mov bl, [rdx]           ; Character from substring
    test bl, bl             ; End of substring?
    jz substring_found      ; Yes, found match
    cmp al, bl              ; Characters match?
    jne try_next_position   ; No, try next position
    inc rcx                 ; Next character in text
    inc rdx                 ; Next character in substring
    jmp compare_chars       ; Continue comparison
    
try_next_position:
    inc rsi                 ; Move to next position in text
    mov al, [rsi]           ; Check if end of text
    test al, al
    jnz find_substring      ; Continue if not end
    ; Substring not found
    mov rsi, -1
    jmp find_done
    
substring_found:
    ; rsi points to start of found substring
    
find_done:
    ; Convert to uppercase
    mov rsi, text
    
to_uppercase:
    mov al, [rsi]           ; Load character
    test al, al             ; End of string?
    jz uppercase_done
    cmp al, 'a'             ; Check if lowercase
    jl next_char            ; Skip if not lowercase
    cmp al, 'z'
    jg next_char            ; Skip if not lowercase
    sub al, 32              ; Convert to uppercase
    mov [rsi], al           ; Store back
    
next_char:
    inc rsi                 ; Next character
    jmp to_uppercase        ; Continue
    
uppercase_done:
    ; Count words (spaces + 1)
    mov rsi, text
    xor rcx, rcx            ; Word counter
    mov bl, 1               ; Flag for word start
    
count_words:
    mov al, [rsi]           ; Load character
    test al, al             ; End of string?
    jz count_done
    
    cmp al, ' '             ; Is it a space?
    je found_space
    cmp al, 9               ; Is it a tab?
    je found_space
    
    ; Not a space, check if start of new word
    test bl, bl             ; Are we at word start?
    jz not_word_start
    inc rcx                 ; Increment word count
    xor bl, bl              ; Clear word start flag
    
not_word_start:
    jmp next_word_char
    
found_space:
    mov bl, 1               ; Set word start flag
    
next_word_char:
    inc rsi                 ; Next character
    jmp count_words         ; Continue
    
count_done:
    ; rcx contains word count
    nop
```

## 10. Input/Output Operations

Basic I/O operations using system calls and BIOS interrupts.

### Console Output (Linux)

```assembly
section .data
    msg db 'Hello, Assembly World!', 10, 0
    msg_len equ $ - msg - 1
    number_str db '12345', 10, 0
    number_len equ $ - number_str - 1

section .text
global _start

_start:
    ; Write system call
    mov rax, 1              ; sys_write
    mov rdi, 1              ; stdout file descriptor
    mov rsi, msg            ; message buffer
    mov rdx, msg_len        ; message length
    syscall                 ; invoke system call
    
    ; Write number
    mov rax, 1
    mov rdi, 1
    mov rsi, number_str
    mov rdx, number_len
    syscall
```

### Console Input (Linux)

```assembly
section .bss
    input_buffer resb 256   ; Reserve 256 bytes for input

section .data
    prompt db 'Enter text: ', 0
    prompt_len equ $ - prompt - 1
    newline db 10, 0

section .text
global _start

_start:
    ; Display prompt
    mov rax, 1              ; sys_write
    mov rdi, 1              ; stdout
    mov rsi, prompt         ; prompt message
    mov rdx, prompt_len     ; prompt length
    syscall
    
    ; Read input
    mov rax, 0              ; sys_read
    mov rdi, 0              ; stdin file descriptor
    mov rsi, input_buffer   ; input buffer
    mov rdx, 255            ; maximum bytes to read
    syscall                 ; invoke system call
    
    ; rax now contains number of bytes read
    mov rcx, rax            ; Save bytes read count
    
    ; Echo input back
    mov rax, 1              ; sys_write
    mov rdi, 1              ; stdout
    mov rsi, input_buffer   ; input buffer
    mov rdx, rcx            ; bytes read
    syscall
```

### Number to String Conversion

```assembly
section .bss
    buffer resb 20          ; Buffer for number string

section .data
    newline db 10, 0

section .text
global _start

_start:
    mov rax, 12345          ; Number to convert
    mov rdi, buffer         ; Buffer pointer
    add rdi, 19             ; Point to end of buffer
    mov byte [rdi], 0       ; Null terminator
    dec rdi                 ; Move back one position
    
    mov rbx, 10             ; Divisor (base 10)
    
convert_loop:
    xor rdx, rdx            ; Clear remainder
    div rbx                 ; Divide by 10
    add dl, '0'             ; Convert remainder to ASCII
    mov [rdi], dl           ; Store digit
    dec rdi                 ; Move to previous position
    test rax, rax           ; Check if quotient is zero
    jnz convert_loop        ; Continue if not zero
    
    inc rdi                 ; Adjust pointer to first digit
    
    ; Calculate string length
    mov rsi, buffer
    add rsi, 19             ; End of buffer
    sub rsi, rdi            ; Length = end - start
    mov rdx, rsi            ; String length
    
    ; Print the number
    mov rax, 1              ; sys_write
    mov rsi, rdi            ; Number string
    mov rdi, 1              ; stdout
    syscall
    
    ; Print newline
    mov rax, 1
    mov rdi, 1
    mov rsi, newline
    mov rdx, 1
    syscall
```

### String to Number Conversion

```assembly
section .data
    input_str db '98765', 0 ; Input string
    
section .text
global _start

_start:
    mov rsi, input_str      ; String pointer
    xor rax, rax            ; Result accumulator
    xor rbx, rbx            ; Temporary for character
    mov rcx, 10             ; Multiplier (base 10)
    
parse_loop:
    mov bl, [rsi]           ; Load character
    test bl, bl             ; Check for null terminator
    jz parse_done           ; End of string
    
    ; Check if character is a digit
    cmp bl, '0'
    jl parse_error          ; Less than '0'
    cmp bl, '9'
    jg parse_error          ; Greater than '9'
    
    ; Convert character to digit
    sub bl, '0'             ; Convert ASCII to numeric value
    
    ; Multiply current result by 10 and add new digit
    mul rcx                 ; rax = rax * 10
    add rax, rbx            ; Add new digit
    
    inc rsi                 ; Next character
    jmp parse_loop          ; Continue
    
parse_done:
    ; rax contains the converted number
    jmp conversion_success
    
parse_error:
    ; Invalid character found
    mov rax, -1             ; Error indicator
    
conversion_success:
    nop
```

### File Operations (Linux)

```assembly
section .data
    filename db 'test.txt', 0
    write_data db 'Hello, File!', 10, 0
    write_len equ $ - write_data - 1

section .bss
    read_buffer resb 256

section .text
global _start

_start:
    ; Open file for writing (create if doesn't exist)
    mov rax, 2              ; sys_open
    mov rdi, filename       ; filename
    mov rsi, 0o1101         ; flags: O_WRONLY | O_CREAT | O_TRUNC
    mov rdx, 0o644          ; permissions: rw-r--r--
    syscall
    
    ; Check for error
    cmp rax, 0
    jl file_error           ; Jump if error (negative return)
    
    mov rbx, rax            ; Save file descriptor
    
    ; Write to file
    mov rax, 1              ; sys_write
    mov rdi, rbx            ; file descriptor
    mov rsi, write_data     ; data to write
    mov rdx, write_len      ; data length
    syscall
    
    ; Close file
    mov rax, 3              ; sys_close
    mov rdi, rbx            ; file descriptor
    syscall
    
    ; Open file for reading
    mov rax, 2              ; sys_open
    mov rdi, filename       ; filename
    mov rsi, 0              ; flags: O_RDONLY
    mov rdx, 0              ; permissions (ignored for read)
    syscall
    
    cmp rax, 0
    jl file_error
    
    mov rbx, rax            ; Save file descriptor
    
    ; Read from file
    mov rax, 0              ; sys_read
    mov rdi, rbx            ; file descriptor
    mov rsi, read_buffer    ; buffer to read into
    mov rdx, 255            ; maximum bytes to read
    syscall
    
    ; Close file
    mov rax, 3              ; sys_close
    mov rdi, rbx            ; file descriptor
    syscall
    
    jmp program_end
    
file_error:
    ; Handle file error
    mov rax, 60             ; sys_exit
    mov rdi, 1              ; error exit code
    syscall
    
program_end:
    ; Normal exit
    mov rax, 60             ; sys_exit
    mov rdi, 0              ; success exit code
    syscall
```

## 11. Advanced Instructions

Advanced x86-64 instructions for specialized operations.

### Conditional Move Instructions

```assembly
section .data
    a dd 10
    b dd 20
    max_val dd 0
    min_val dd 0

section .text
global _start

_start:
    mov eax, [a]
    mov ebx, [b]
    
    ; Conditional move (no branching)
    cmp eax, ebx
    cmovg eax, ebx          ; Move ebx to eax if eax > ebx
    mov [max_val], eax
    
    mov eax, [a]
    mov ebx, [b]
    cmovl eax, ebx          ; Move ebx to eax if eax < ebx
    mov [min_val], eax
    
    ; Other conditional moves
    mov eax, 5
    mov ebx, 10
    cmp eax, 0
    cmovz ebx, eax          ; Move if zero
    cmovnz ebx, eax         ; Move if not zero
    cmovc ebx, eax          ; Move if carry
    cmovnc ebx, eax         ; Move if not carry
    cmovo ebx, eax          ; Move if overflow
    cmovno ebx, eax         ; Move if not overflow
    cmovs ebx, eax          ; Move if sign
    cmovns ebx, eax         ; Move if not sign
    
    ; Signed comparisons
    cmove ebx, eax          ; Move if equal
    cmovne ebx, eax         ; Move if not equal
    cmovl ebx, eax          ; Move if less
    cmovle ebx, eax         ; Move if less or equal
    cmovg ebx, eax          ; Move if greater
    cmovge ebx, eax         ; Move if greater or equal
    
    ; Unsigned comparisons
    cmovb ebx, eax          ; Move if below
    cmovbe ebx, eax         ; Move if below or equal
    cmova ebx, eax          ; Move if above
    cmovae ebx, eax         ; Move if above or equal
```

### Advanced Arithmetic Instructions

```assembly
section .text
global _start

_start:
    ; Extended precision arithmetic
    mov rax, 0xFFFFFFFFFFFFFFFF
    mov rbx, 0xFFFFFFFFFFFFFFFF
    
    ; Add with carry
    add rax, rbx            ; Add lower parts
    adc rcx, rdx            ; Add upper parts with carry
    
    ; Subtract with borrow
    mov rax, 0x1000000000000000
    mov rbx, 1
    sub rax, rbx            ; Subtract lower parts
    sbb rcx, 0              ; Subtract borrow from upper part
    
    ; Multiply high/low
    mov rax, 0x123456789ABCDEF0
    mov rbx, 0x0FEDCBA987654321
    mul rbx                 ; rdx:rax = rax * rbx (unsigned)
    
    mov rax, -100
    mov rbx, -50
    imul rbx                ; rdx:rax = rax * rbx (signed)
    
    ; Three operand multiply
    mov rbx, 25
    imul rax, rbx, 4        ; rax = rbx * 4
    
    ; Bit scan operations
    mov rax, 0b0001101000
    bsf rbx, rax            ; rbx = index of first set bit
    bsr rcx, rax            ; rcx = index of last set bit
    
    ; Population count (count set bits)
    popcnt rdx, rax         ; rdx = number of set bits in rax
    
    ; Leading zero count
    lzcnt r8, rax           ; r8 = number of leading zeros
    
    ; Trailing zero count
    tzcnt r9, rax           ; r9 = number of trailing zeros
```

### Byte/Word Manipulation

```assembly
section .data
    packed_data dq 0x123456789ABCDEF0

section .text
global _start

_start:
    mov rax, [packed_data]
    
    ; Byte swap
    bswap rax               ; Reverse byte order (endian conversion)
    
    ; Extract bytes
    mov rbx, rax
    and rbx, 0xFF           ; Extract lowest byte
    
    mov rcx, rax
    shr rcx, 8
    and rcx, 0xFF           ; Extract second byte
    
    ; Pack bytes
    mov al, 0x12
    mov ah, 0x34
    ; ax now contains 0x3412
    
    ; Sign extension
    mov al, 0x80            ; Negative byte
    cbw                     ; Convert byte to word (al -> ax)
    cwde                    ; Convert word to dword (ax -> eax)
    cdqe                    ; Convert dword to qword (eax -> rax)
    
    ; Zero extension
    mov al, 0xFF
    movzx ax, al            ; Zero extend byte to word
    movzx eax, al           ; Zero extend byte to dword
    movzx rax, al           ; Zero extend byte to qword
    
    ; Sign extension
    mov al, 0x80
    movsx ax, al            ; Sign extend byte to word
    movsx eax, al           ; Sign extend byte to dword
    movsx rax, al           ; Sign extend byte to qword
```

### SIMD Instructions (SSE/AVX)

```assembly
section .data
    align 16
    vector1 dd 1.0, 2.0, 3.0, 4.0      ; 4 floats
    vector2 dd 5.0, 6.0, 7.0, 8.0      ; 4 floats
    result dd 0.0, 0.0, 0.0, 0.0        ; Result vector
    
    align 16
    int_vec1 dd 1, 2, 3, 4              ; 4 integers
    int_vec2 dd 5, 6, 7, 8              ; 4 integers

section .text
global _start

_start:
    ; Load vectors into SSE registers
    movaps xmm0, [vector1]  ; Load aligned packed floats
    movaps xmm1, [vector2]  ; Load aligned packed floats
    
    ; Vector arithmetic
    addps xmm0, xmm1        ; Add packed floats
    movaps [result], xmm0   ; Store result
    
    ; Vector multiplication
    movaps xmm0, [vector1]
    mulps xmm0, xmm1        ; Multiply packed floats
    
    ; Vector comparison
    cmpps xmm0, xmm1, 1     ; Compare less than (sets mask)
    
    ; Integer vector operations
    movdqa xmm2, [int_vec1] ; Load aligned packed integers
    movdqa xmm3, [int_vec2]
    paddd xmm2, xmm3        ; Add packed doublewords
    
    ; Shuffle operations
    shufps xmm0, xmm1, 0xE4 ; Shuffle floats
    
    ; Convert between types
    cvtps2dq xmm4, xmm0     ; Convert floats to integers
    cvtdq2ps xmm5, xmm4     ; Convert integers to floats
    
    ; Horizontal operations
    haddps xmm0, xmm1       ; Horizontal add
    
    ; Min/Max operations
    minps xmm0, xmm1        ; Packed minimum
    maxps xmm0, xmm1        ; Packed maximum
```

## 12. Memory Management

Advanced memory management and addressing techniques.

### Segment Registers and Memory Models

```assembly
section .data
    data_seg_addr dq 0
    code_seg_addr dq 0

section .text
global _start

_start:
    ; Segment register access (legacy in 64-bit mode)
    mov ax, ds              ; Data segment
    mov bx, es              ; Extra segment
    mov cx, fs              ; FS segment (used for thread-local storage)
    mov dx, gs              ; GS segment (used for processor-specific data)
    
    ; FS and GS are still useful in 64-bit mode
    mov rax, fs:[0x28]      ; Access thread-local storage
    mov rbx, gs:[0x10]      ; Access processor-specific data
    
    ; Get segment base addresses (using system calls or MSRs)
    ; This is typically done by the OS, shown for educational purposes
    rdfsbase rax            ; Read FS base address
    rdgsbase rbx            ; Read GS base address
    
    ; Write segment base addresses (privileged)
    ; wrfsbase rax          ; Write FS base address
    ; wrgsbase rbx          ; Write GS base address
```

### Page Fault Handling and Virtual Memory

```assembly
section .data
    ; Page size constants
    PAGE_SIZE equ 4096
    PAGE_MASK equ 0xFFFFFFFFFFFFF000
    
    virtual_addr dq 0x400000000000

section .text
global _start

_start:
    ; Calculate page-aligned addresses
    mov rax, [virtual_addr]
    and rax, PAGE_MASK      ; Clear lower 12 bits (page align)
    
    ; Calculate offset within page
    mov rbx, [virtual_addr]
    and rbx, 0xFFF          ; Keep only lower 12 bits (offset)
    
    ; Memory allocation using mmap system call
    mov rax, 9              ; sys_mmap
    mov rdi, 0              ; addr (let kernel choose)
    mov rsi, PAGE_SIZE      ; length (one page)
    mov rdx, 3              ; prot (PROT_READ | PROT_WRITE)
    mov r10, 34             ; flags (MAP_PRIVATE | MAP_ANONYMOUS)
    mov r8, -1              ; fd (not used for anonymous mapping)
    mov r9, 0               ; offset (not used)
    syscall
    
    ; Check for error
    cmp rax, -1
    je mmap_error
    
    ; rax now contains the allocated memory address
    mov rbx, rax            ; Save allocated address
    
    ; Write to allocated memory
    mov qword [rbx], 0x123456789ABCDEF0
    
    ; Read back from memory
    mov rcx, [rbx]
    
    ; Free memory using munmap
    mov rax, 11             ; sys_munmap
    mov rdi, rbx            ; addr
    mov rsi, PAGE_SIZE      ; length
    syscall
    
    jmp memory_done

mmap_error:
    ; Handle allocation error
    mov rax, 60             ; sys_exit
    mov rdi, 1              ; error code
    syscall

memory_done:
    nop
```

### Cache Optimization Techniques

```assembly
section .data
    ; Align data to cache line boundaries (64 bytes on most systems)
    align 64
    cache_data times 16 dq 0    ; 128 bytes of data
    
    align 64
    hot_data dq 1, 2, 3, 4, 5, 6, 7, 8  ; Frequently accessed data

section .text
global _start

_start:
    ; Prefetch data into cache
    mov rsi, cache_data
    prefetcht0 [rsi]        ; Prefetch to L1 cache
    prefetcht1 [rsi + 64]   ; Prefetch to L2 cache
    prefetcht2 [rsi + 128]  ; Prefetch to L3 cache
    prefetchnta [rsi + 192] ; Prefetch non-temporal (bypass cache)
    
    ; Cache-friendly loop (stride of 1)
    mov rsi, cache_data
    mov rcx, 16             ; Number of qwords
    
cache_loop:
    mov rax, [rsi]          ; Load data
    ; Process data
    add rsi, 8              ; Next qword (stride of 8 bytes)
    dec rcx
    jnz cache_loop
    
    ; Memory fencing for ordering
    mfence                  ; Full memory fence
    lfence                  ; Load fence
    sfence                  ; Store fence
    
    ; Non-temporal stores (bypass cache)
    mov rax, 0x123456789ABCDEF0
    movnti [cache_data], rax    ; Non-temporal store
    
    ; Flush cache line
    clflush [cache_data]    ; Flush cache line containing this address
    
    ; Memory barriers
    lock nop                ; Serializing instruction
```

### Memory Protection and Access Control

```assembly
section .data
    protected_data dq 0x1234567890ABCDEF

section .text
global _start

_start:
    ; Check memory access (this would normally be done by OS)
    mov rax, protected_data
    
    ; Attempt to read memory
    mov rbx, [rax]          ; This might cause segmentation fault if protected
    
    ; Using mprotect to change memory protection
    mov rax, 10             ; sys_mprotect
    mov rdi, protected_data ; addr (page-aligned)
    mov rsi, 4096           ; len (page size)
    mov rdx, 1              ; prot (PROT_READ only)
    syscall
    
    ; Now only read access is allowed
    mov rbx, [protected_data]   ; This should work
    ; mov [protected_data], rbx ; This would cause segmentation fault
    
    ; Restore write access
    mov rax, 10             ; sys_mprotect
    mov rdi, protected_data ; addr
    mov rsi, 4096           ; len
    mov rdx, 3              ; prot (PROT_READ | PROT_WRITE)
    syscall
    
    ; Now both read and write access allowed
    mov [protected_data], rbx   ; This should work again
```

### Advanced Pointer Arithmetic

```assembly
section .data
    matrix dd 1, 2, 3, 4
           dd 5, 6, 7, 8
           dd 9, 10, 11, 12
           dd 13, 14, 15, 16
    
    ; Matrix dimensions
    ROWS equ 4
    COLS equ 4
    ELEMENT_SIZE equ 4

section .text
global _start

_start:
    ; Access matrix element [row][col]
    mov rsi, 2              ; row index
    mov rdi, 1              ; column index
    
    ; Calculate address: base + (row * cols + col) * element_size
    mov rax, rsi            ; row
    mov rbx, COLS           ; columns per row
    mul rbx                 ; rax = row * cols
    add rax, rdi            ; rax = row * cols + col
    mov rbx, ELEMENT_SIZE
    mul rbx                 ; rax = (row * cols + col) * element_size
    
    mov rbx, matrix         ; base address
    add rbx, rax            ; rbx = address of matrix[row][col]
    mov ecx, [rbx]          ; load matrix element
    
    ; Pointer to pointer example
    mov rax, matrix         ; rax points to matrix
    mov rbx, rax            ; rbx = pointer to matrix
    mov rcx, rbx            ; rcx = pointer to pointer to matrix
    
    ; Dereference pointer to pointer
    mov rdx, [rcx]          ; rdx = value at address in rcx (= rbx)
    mov r8, [rdx]           ; r8 = value at address in rdx (first matrix element)
    
    ; Function pointer example
    mov rax, function1      ; rax = address of function1
    call rax                ; call function through pointer
    
    ; Array of function pointers
    mov rsi, 1              ; function index
    mov rax, [func_table + rsi*8]  ; load function address
    call rax                ; call function
    
    jmp end_program

function1:
    ; Function implementation
    mov rax, 42
    ret

function2:
    ; Another function implementation
    mov rax, 84
    ret

section .data
func_table:
    dq function1
    dq function2

section .text
end_program:
    nop
```

## 13. Procedures and Functions

Function creation, calling conventions, and parameter passing.

### Function Definition and Calling

```assembly
section .data
    result dq 0

section .text
global _start

_start:
    ; Call function with parameters
    mov rdi, 10             ; First parameter
    mov rsi, 20             ; Second parameter
    call add_numbers        ; Call function
    mov [result], rax       ; Store result
    
    ; Call function with more parameters
    mov rdi, 5              ; Parameter 1
    mov rsi, 10             ; Parameter 2
    mov rdx, 15             ; Parameter 3
    mov rcx, 20             ; Parameter 4
    call sum_four_numbers
    
    ; Exit program
    mov rax, 60             ; sys_exit
    mov rdi, 0              ; exit status
    syscall

; Function: add two numbers
; Parameters: rdi = first number, rsi = second number
; Returns: rax = sum
add_numbers:
    mov rax, rdi            ; Load first parameter
    add rax, rsi            ; Add second parameter
    ret                     ; Return to caller

; Function: sum four numbers
; Parameters: rdi, rsi, rdx, rcx
; Returns: rax = sum
sum_four_numbers:
    mov rax, rdi            ; Start with first parameter
    add rax, rsi            ; Add second
    add rax, rdx            ; Add third
    add rax, rcx            ; Add fourth
    ret                     ; Return sum
```

### Calling Conventions (System V ABI)

```assembly
section .text
global _start

_start:
    ; System V ABI calling convention for x86-64
    ; Integer/pointer arguments: rdi, rsi, rdx, rcx, r8, r9
    ; Floating point arguments: xmm0-xmm7
    ; Return values: rax (integer), xmm0 (float)
    ; Caller-saved: rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11
    ; Callee-saved: rbx, rbp, r12, r13, r14, r15
    
    ; Save caller-saved registers before function call
    push rax
    push rcx
    push rdx
    
    mov rdi, 100            ; First argument
    mov rsi, 200            ; Second argument
    mov rdx, 300            ; Third argument
    mov rcx, 400            ; Fourth argument
    mov r8, 500             ; Fifth argument
    mov r9, 600             ; Sixth argument
    
    ; Additional arguments go on stack (right to left)
    push 800                ; Eighth argument
    push 700                ; Seventh argument
    
    call complex_function
    
    ; Clean up stack (remove pushed arguments)
    add rsp, 16             ; Remove 2 arguments (8 bytes each)
    
    ; Restore caller-saved registers
    pop rdx
    pop rcx
    pop rax
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall

; Function demonstrating callee-saved registers
complex_function:
    ; Save callee-saved registers that we'll modify
    push rbx
    push r12
    push r13
    
    ; Function body
    mov rbx, rdi            ; Use callee-saved register
    mov r12, rsi
    mov r13, rdx
    
    ; Do some work
    add rbx, r12
    add rbx, r13
    add rbx, rcx
    add rbx, r8
    add rbx, r9
    
    ; Access stack arguments
    mov rax, [rsp + 24]     ; Seventh argument (after 3 pushed regs)
    add rbx, rax
    mov rax, [rsp + 32]     ; Eighth argument
    add rbx, rax
    
    mov rax, rbx            ; Return value
    
    ; Restore callee-saved registers
    pop r13
    pop r12
    pop rbx
    ret
```

### Stack Frame Management

```assembly
section .bss
    local_buffer resb 1024

section .text
global _start

_start:
    push 300                ; Argument 3
    push 200                ; Argument 2
    push 100                ; Argument 1
    call function_with_locals
    add rsp, 24             ; Clean up stack arguments
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall

; Function with local variables and stack frame
function_with_locals:
    ; Prologue: set up stack frame
    push rbp                ; Save old base pointer
    mov rbp, rsp            ; Set new base pointer
    sub rsp, 64             ; Allocate space for local variables
    
    ; Now we can access:
    ; [rbp + 16] = first argument (after return address and saved rbp)
    ; [rbp + 24] = second argument
    ; [rbp + 32] = third argument
    ; [rbp - 8]  = first local variable
    ; [rbp - 16] = second local variable
    ; etc.
    
    ; Access function parameters
    mov rax, [rbp + 16]     ; First argument
    mov rbx, [rbp + 24]     ; Second argument
    mov rcx, [rbp + 32]     ; Third argument
    
    ; Use local variables
    mov qword [rbp - 8], rax    ; Local variable 1
    mov qword [rbp - 16], rbx   ; Local variable 2
    mov qword [rbp - 24], rcx   ; Local variable 3
    
    ; Perform calculations
    add rax, rbx
    add rax, rcx
    mov [rbp - 32], rax     ; Store result in local variable
    
    ; Allocate more local space dynamically
    sub rsp, 256            ; Allocate 256 bytes
    
    ; Use the allocated space
    mov rdi, rsp            ; Pointer to allocated space
    mov rsi, 0xAA           ; Fill value
    mov rcx, 256            ; Number of bytes
    rep stosb               ; Fill allocated space
    
    ; Free dynamically allocated space
    add rsp, 256            ; Restore stack pointer
    
    ; Return value
    mov rax, [rbp - 32]     ; Load result
    
    ; Epilogue: restore stack frame
    mov rsp, rbp            ; Restore stack pointer
    pop rbp                 ; Restore old base pointer
    ret                     ; Return to caller
```

### Recursive Functions

```assembly
section .text
global _start

_start:
    mov rdi, 5              ; Calculate factorial of 5
    call factorial
    ; rax now contains 120 (5!)
    
    mov rdi, 10             ; Calculate Fibonacci of 10
    call fibonacci
    ; rax now contains 55
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall

; Recursive factorial function
; Parameter: rdi = n
; Returns: rax = n!
factorial:
    ; Base case: if n <= 1, return 1
    cmp rdi, 1
    jle factorial_base
    
    ; Recursive case: n * factorial(n-1)
    push rdi                ; Save n
    dec rdi                 ; n - 1
    call factorial          ; factorial(n-1)
    pop rdi                 ; Restore n
    mul rdi                 ; n * factorial(n-1)
    ret

factorial_base:
    mov rax, 1              ; Return 1
    ret

; Recursive Fibonacci function
; Parameter: rdi = n
; Returns: rax = fibonacci(n)
fibonacci:
    ; Base cases
    cmp rdi, 0
    je fib_zero
    cmp rdi, 1
    je fib_one
    
    ; Recursive case: fib(n-1) + fib(n-2)
    push rdi                ; Save n
    
    dec rdi                 ; n - 1
    call fibonacci          ; fib(n-1)
    push rax                ; Save fib(n-1)
    
    mov rdi, [rsp + 8]      ; Restore n
    sub rdi, 2              ; n - 2
    call fibonacci          ; fib(n-2)
    
    pop rbx                 ; Restore fib(n-1)
    add rax, rbx            ; fib(n-1) + fib(n-2)
    
    add rsp, 8              ; Clean up saved n
    ret

fib_zero:
    xor rax, rax            ; Return 0
    ret

fib_one:
    mov rax, 1              ; Return 1
    ret
```

### Function Pointers and Callbacks

```assembly
section .data
    ; Array of function pointers
    operations:
        dq add_operation
        dq sub_operation
        dq mul_operation
        dq div_operation
    
    results times 4 dq 0

section .text
global _start

_start:
    ; Test all operations
    mov rcx, 0              ; Operation index
    
test_loop:
    mov rdi, 20             ; First operand
    mov rsi, 4              ; Second operand
    mov rdx, rcx            ; Operation index
    call perform_operation
    mov [results + rcx*8], rax  ; Store result
    
    inc rcx
    cmp rcx, 4
    jl test_loop
    
    ; Use callback function
    mov rdi, process_callback   ; Callback function
    mov rsi, 42                 ; Data to process
    call apply_callback
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall

; Function that takes a callback
; Parameters: rdi = callback function, rsi = data
apply_callback:
    push rdi                ; Save callback
    mov rdi, rsi            ; Move data to first parameter
    call [rsp]              ; Call callback function
    add rsp, 8              ; Clean up stack
    ret

; Callback function
process_callback:
    add rdi, 100            ; Process the data
    mov rax, rdi            ; Return processed data
    ret

; Dispatcher function using function pointers
; Parameters: rdi = operand1, rsi = operand2, rdx = operation index
perform_operation:
    ; Bounds check
    cmp rdx, 4
    jge invalid_operation
    
    ; Call function through pointer
    call [operations + rdx*8]
    ret

invalid_operation:
    mov rax, -1             ; Error code
    ret

; Operation functions
add_operation:
    mov rax, rdi
    add rax, rsi
    ret

sub_operation:
    mov rax, rdi
    sub rax, rsi
    ret

mul_operation:
    mov rax, rdi
    imul rax, rsi
    ret

div_operation:
    mov rax, rdi
    xor rdx, rdx            ; Clear remainder
    div rsi                 ; Unsigned division
    ret
```

## 14. Stack Operations

Advanced stack manipulation and management techniques.

### Stack Frame Inspection

```assembly
section .text
global _start

_start:
    ; Set up initial stack state
    push 0x1111111111111111 ; Push some test data
    push 0x2222222222222222
    push 0x3333333333333333
    
    call inspect_stack
    
    ; Clean up
    add rsp, 24             ; Remove test data
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall

inspect_stack:
    push rbp                ; Standard prologue
    mov rbp, rsp
    sub rsp, 32             ; Local space
    
    ; Inspect current stack pointer
    mov rax, rsp            ; Current stack pointer
    mov [rbp - 8], rax      ; Store in local variable
    
    ; Walk up the stack
    mov rsi, rbp            ; Start from current frame
    mov rcx, 5              ; Number of stack entries to examine
    
stack_walk:
    mov rax, [rsi]          ; Load value at current position
    ; In real code, you would examine or print this value
    add rsi, 8              ; Move to next stack entry
    dec rcx
    jnz stack_walk
    
    ; Access return address
    mov rax, [rbp + 8]      ; Return address
    
    ; Access caller's frame
    mov rbx, [rbp]          ; Caller's saved rbp
    ; rbx now points to caller's stack frame
    
    ; Calculate stack depth
    mov rax, rbp            ; Current frame pointer
    mov rbx, rsp            ; Current stack pointer
    sub rax, rbx            ; Stack depth in bytes
    
    mov rsp, rbp            ; Standard epilogue
    pop rbp
    ret
```

### Stack Buffer Management

```assembly
section .text
global _start

_start:
    call test_stack_buffer
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall

test_stack_buffer:
    push rbp
    mov rbp, rsp
    sub rsp, 1024           ; Allocate 1KB buffer on stack
    
    ; Initialize buffer
    mov rdi, rsp            ; Buffer start
    mov rax, 0x4142434445464748  ; Pattern
    mov rcx, 128            ; Number of qwords (1024/8)
    rep stosq               ; Fill buffer with pattern
    
    ; Use buffer as character array
    mov rdi, rsp            ; Buffer start
    mov rsi, hello_string   ; Source string
    call strcpy_stack       ; Copy string to stack buffer
    
    ; Use buffer for temporary calculations
    mov rdi, rsp            ; Buffer as integer array
    mov rcx, 10             ; Number of integers to generate
    
fill_integers:
    mov rax, rcx            ; Use loop counter as value
    mov [rdi], rax          ; Store in buffer
    add rdi, 8              ; Next position
    dec rcx
    jnz fill_integers
    
    ; Calculate sum of integers in buffer
    mov rdi, rsp            ; Buffer start
    mov rcx, 10             ; Number of integers
    xor rax, rax            ; Sum accumulator
    
sum_loop:
    add rax, [rdi]          ; Add current integer
    add rdi, 8              ; Next integer
    dec rcx
    jnz sum_loop
    
    ; Check stack canary (basic stack protection)
    mov rbx, [rbp - 8]      ; Load canary value
    cmp rbx, 0x4142434445464748  ; Check if corrupted
    jne stack_corruption
    
    mov rsp, rbp            ; Clean up
    pop rbp
    ret

stack_corruption:
    ; Handle stack corruption
    mov rax, 60             ; Exit immediately
    mov rdi, 1              ; Error code
    syscall

; Copy string to stack buffer
strcpy_stack:
    ; rdi = destination, rsi = source
copy_char:
    mov al, [rsi]           ; Load source character
    mov [rdi], al           ; Store to destination
    inc rsi                 ; Next source
    inc rdi                 ; Next destination
    test al, al             ; Check for null terminator
    jnz copy_char           ; Continue if not zero
    ret

section .data
hello_string db 'Hello Stack!', 0
```

### Stack Unwinding and Exception Handling

```assembly
section .data
    exception_flag dq 0

section .text
global _start

_start:
    ; Set up exception handler
    mov qword [exception_flag], 0
    
    call risky_function
    
    ; Check if exception occurred
    cmp qword [exception_flag], 0
    jne handle_exception
    
    ; Normal exit
    mov rax, 60
    mov rdi, 0
    syscall

handle_exception:
    ; Exception handling code
    mov rax, 60
    mov rdi, 1              ; Error exit code
    syscall

risky_function:
    push rbp
    mov rbp, rsp
    push rbx                ; Save callee-saved register
    
    ; Simulate risky operation
    mov rbx, 10
    cmp rbx, 5
    jl trigger_exception    ; Simulate error condition
    
    ; Normal operation
    add rbx, 5
    jmp function_end

trigger_exception:
    ; Set exception flag
    mov qword [exception_flag], 1
    
    ; Unwind stack properly
    pop rbx                 ; Restore callee-saved register
    mov rsp, rbp            ; Restore stack pointer
    pop rbp                 ; Restore base pointer
    ret                     ; Return to caller

function_end:
    ; Normal function end
    pop rbx
    mov rsp, rbp
    pop rbp
    ret
```

### Variable Length Argument Lists

```assembly
section .text
global _start

_start:
    ; Call function with variable arguments
    ; First argument is count, rest are values to sum
    push 30                 ; 5th argument
    push 40                 ; 4th argument
    push 20                 ; 3rd argument
    push 10                 ; 2nd argument
    push 4                  ; 1st argument (count)
    call sum_varargs
    add rsp, 40             ; Clean up stack (5 * 8 bytes)
    
    ; Exit with sum as exit code
    mov rdi, rax
    mov rax, 60
    syscall

; Function with variable arguments
; First argument: number of additional arguments
; Following arguments: values to sum
sum_varargs:
    push rbp
    mov rbp, rsp
    
    ; Get argument count
    mov rcx, [rbp + 16]     ; First argument (count)
    mov rsi, rbp            ; Stack pointer for arguments
    add rsi, 24             ; Point to second argument
    
    xor rax, rax            ; Sum accumulator
    
vararg_loop:
    test rcx, rcx           ; Check if more arguments
    jz vararg_done
    
    add rax, [rsi]          ; Add current argument to sum
    add rsi, 8              ; Next argument
    dec rcx                 ; Decrement count
    jmp vararg_loop

vararg_done:
    pop rbp
    ret
```

## 15. System Calls

Interface with the operating system through system calls.

### Linux System Call Interface

```assembly
section .data
    ; System call numbers for Linux x86-64
    SYS_READ    equ 0
    SYS_WRITE   equ 1
    SYS_OPEN    equ 2
    SYS_CLOSE   equ 3
    SYS_LSEEK   equ 8
    SYS_MMAP    equ 9
    SYS_MUNMAP  equ 11
    SYS_BRK     equ 12
    SYS_GETPID  equ 39
    SYS_EXIT    equ 60
    
    ; File constants
    O_RDONLY    equ 0
    O_WRONLY    equ 1
    O_RDWR      equ 2
    O_CREAT     equ 64
    O_TRUNC     equ 512
    
    filename db '/tmp/test.txt', 0
    write_msg db 'Hello from assembly!', 10, 0
    write_len equ $ - write_msg - 1

section .bss
    read_buffer resb 256
    pid_buffer resb 16

section .text
global _start

_start:
    ; Get process ID
    mov rax, SYS_GETPID
    syscall
    ; rax now contains PID
    
    ; Open file for writing
    mov rax, SYS_OPEN
    mov rdi, filename           ; filename
    mov rsi, O_WRONLY | O_CREAT | O_TRUNC  ; flags
    mov rdx, 0644              ; permissions
    syscall
    
    ; Check for error
    cmp rax, 0
    jl file_error
    
    mov rbx, rax               ; Save file descriptor
    
    ; Write to file
    mov rax, SYS_WRITE
    mov rdi, rbx               ; file descriptor
    mov rsi, write_msg         ; buffer
    mov rdx, write_len         ; count
    syscall
    
    ; Close file
    mov rax, SYS_CLOSE
    mov rdi, rbx               ; file descriptor
    syscall
    
    ; Open file for reading
    mov rax, SYS_OPEN
    mov rdi, filename          ; filename
    mov rsi, O_RDONLY          ; flags
    mov rdx, 0                 ; permissions (ignored)
    syscall
    
    cmp rax, 0
    jl file_error
    
    mov rbx, rax               ; Save file descriptor
    
    ; Read from file
    mov rax, SYS_READ
    mov rdi, rbx               ; file descriptor
    mov rsi, read_buffer       ; buffer
    mov rdx, 255               ; count
    syscall
    
    ; Close file
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall
    
    ; Normal exit
    mov rax, SYS_EXIT
    mov rdi, 0
    syscall

file_error:
    ; Error exit
    mov rax, SYS_EXIT
    mov rdi, 1
    syscall
```

### Memory Management System Calls

```assembly
section .data
    PAGE_SIZE equ 4096
    
    ; mmap protection flags
    PROT_READ   equ 1
    PROT_WRITE  equ 2
    PROT_EXEC   equ 4
    
    ; mmap flags
    MAP_PRIVATE equ 2
    MAP_ANON    equ 32

section .text
global _start

_start:
    ; Allocate memory using mmap
    mov rax, 9                 ; sys_mmap
    mov rdi, 0                 ; addr (let kernel choose)
    mov rsi, PAGE_SIZE * 4     ; length (4 pages)
    mov rdx, PROT_READ | PROT_WRITE  ; protection
    mov r10, MAP_PRIVATE | MAP_ANON  ; flags
    mov r8, -1                 ; fd (not used)
    mov r9, 0                  ; offset (not used)
    syscall
    
    cmp rax, -1
    je mmap_error
    
    mov rbx, rax               ; Save allocated address
    
    ; Write to allocated memory
    mov qword [rbx], 0x123456789ABCDEF0
    mov qword [rbx + 8], 0xFEDCBA9876543210
    
    ; Change memory protection to read-only
    mov rax, 10                ; sys_mprotect
    mov rdi, rbx               ; addr
    mov rsi, PAGE_SIZE         ; len
    mov rdx, PROT_READ         ; new protection
    syscall
    
    ; Read from memory (should work)
    mov rcx, [rbx]
    
    ; Attempt to write would cause segmentation fault
    ; mov [rbx], rcx
    
    ; Restore write permission
    mov rax, 10                ; sys_mprotect
    mov rdi, rbx               ; addr
    mov rsi, PAGE_SIZE         ; len
    mov rdx, PROT_READ | PROT_WRITE  ; new protection
    syscall
    
    ; Now write should work again
    mov [rbx], rcx
    
    ; Free memory
    mov rax, 11                ; sys_munmap
    mov rdi, rbx               ; addr
    mov rsi, PAGE_SIZE * 4     ; length
    syscall
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall

mmap_error:
    mov rax, 60
    mov rdi, 1
    syscall
```

### Process and Signal Management

```assembly
section .data
    child_msg db 'Child process', 10, 0
    child_msg_len equ $ - child_msg - 1
    parent_msg db 'Parent process', 10, 0
    parent_msg_len equ $ - parent_msg - 1

section .text
global _start

_start:
    ; Fork process
    mov rax, 57                ; sys_fork
    syscall
    
    cmp rax, 0
    je child_process           ; rax = 0 in child
    jl fork_error              ; rax < 0 on error
    
    ; Parent process (rax > 0, contains child PID)
    mov rbx, rax               ; Save child PID
    
    ; Print parent message
    mov rax, 1                 ; sys_write
    mov rdi, 1                 ; stdout
    mov rsi, parent_msg
    mov rdx, parent_msg_len
    syscall
    
    ; Wait for child to complete
    mov rax, 61                ; sys_wait4
    mov rdi, rbx               ; child PID
    mov rsi, 0                 ; status pointer (null)
    mov rdx, 0                 ; options
    mov r10, 0                 ; rusage pointer (null)
    syscall
    
    ; Parent exit
    mov rax, 60
    mov rdi, 0
    syscall

child_process:
    ; Child process code
    mov rax, 1                 ; sys_write
    mov rdi, 1                 ; stdout
    mov rsi, child_msg
    mov rdx, child_msg_len
    syscall
    
    ; Child exit
    mov rax, 60
    mov rdi, 0
    syscall

fork_error:
    ; Fork failed
    mov rax, 60
    mov rdi, 1
    syscall
```

### Time and Date System Calls

```assembly
section .bss
    time_buffer resb 16        ; Buffer for time values
    
section .data
    time_msg db 'Current time: ', 0
    time_msg_len equ $ - time_msg - 1

section .text
global _start

_start:
    ; Get current time
    mov rax, 96                ; sys_gettimeofday
    mov rdi, time_buffer       ; timeval structure
    mov rsi, 0                 ; timezone (deprecated)
    syscall
    
    ; time_buffer now contains:
    ; [0-7]: seconds since epoch
    ; [8-15]: microseconds
    
    ; Print time message
    mov rax, 1
    mov rdi, 1
    mov rsi, time_msg
    mov rdx, time_msg_len
    syscall
    
    ; Convert time to string and print (simplified)
    mov rax, [time_buffer]     ; Load seconds
    ; In a real program, you would convert this to readable format
    
    ; Sleep for 2 seconds
    mov rax, 35                ; sys_nanosleep
    mov rdi, sleep_spec        ; timespec pointer
    mov rsi, 0                 ; remaining time (null)
    syscall
    
    ; Get time again to show difference
    mov rax, 96                ; sys_gettimeofday
    mov rdi, time_buffer       ; timeval structure
    mov rsi, 0                 ; timezone
    syscall
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall

section .data
sleep_spec:
    dq 2                       ; seconds
    dq 0                       ; nanoseconds
```

## 16. Floating Point Operations

Working with floating-point numbers using the x87 FPU and SSE instructions.

### x87 FPU Stack Operations

```assembly
section .data
    float_a dd 3.14159          ; Single precision (32-bit)
    float_b dd 2.71828
    double_a dq 1.41421356      ; Double precision (64-bit)
    double_b dq 1.73205080
    result_float dd 0.0
    result_double dq 0.0

section .text
global _start

_start:
    ; Load values onto FPU stack
    fld dword [float_a]     ; ST(0) = 3.14159
    fld dword [float_b]     ; ST(0) = 2.71828, ST(1) = 3.14159
    
    ; Basic arithmetic operations
    fadd                    ; ST(0) = ST(0) + ST(1), pop ST(1)
    fstp dword [result_float]  ; Store and pop ST(0)
    
    ; Load double precision values
    fld qword [double_a]    ; ST(0) = 1.41421356
    fld qword [double_b]    ; ST(0) = 1.73205080, ST(1) = 1.41421356
    
    ; More operations
    fmul                    ; ST(0) = ST(0) * ST(1)
    fstp qword [result_double]  ; Store result
    
    ; Load constant values
    fldpi                   ; Load π
    fld1                    ; Load 1.0
    fldz                    ; Load 0.0
    fldl2e                  ; Load log₂(e)
    
    ; Clear FPU stack
    finit                   ; Initialize FPU
    
    ; Trigonometric functions
    fld dword [float_a]     ; Load angle in radians
    fsin                    ; ST(0) = sin(ST(0))
    fcos                    ; ST(0) = cos(ST(0))
    fptan                   ; ST(0) = tan(ST(0)), ST(1) = 1.0
    
    ; Logarithmic functions
    fld dword [float_b]
    fyl2x                   ; ST(0) = ST(1) * log₂(ST(0))
    
    ; Square root
    fld dword [float_a]
    fsqrt                   ; ST(0) = √(ST(0))
    
    ; Comparison
    fld dword [float_a]
    fld dword [float_b]
    fcompp                  ; Compare and pop both
    fstsw ax                ; Store status word to AX
    sahf                    ; Store AH to flags
    ja float_a_greater      ; Jump if float_a > float_b

float_a_greater:
    nop
```

### SSE Floating Point Operations

```assembly
section .data
    align 16
    float_vec1 dd 1.0, 2.0, 3.0, 4.0       ; 4 floats
    float_vec2 dd 5.0, 6.0, 7.0, 8.0       ; 4 floats
    double_vec1 dq 1.5, 2.5                ; 2 doubles
    double_vec2 dq 3.5, 4.5                ; 2 doubles
    scalar_float dd 10.0
    scalar_double dq 20.0

section .text
global _start

_start:
    ; Single precision packed operations
    movaps xmm0, [float_vec1]   ; Load 4 floats
    movaps xmm1, [float_vec2]   ; Load 4 floats
    
    addps xmm0, xmm1            ; Add packed singles
    subps xmm0, xmm1            ; Subtract packed singles
    mulps xmm0, xmm1            ; Multiply packed singles
    divps xmm0, xmm1            ; Divide packed singles
    
    ; Single precision scalar operations
    movss xmm2, [scalar_float]  ; Load single scalar
    movss xmm3, [scalar_float]
    
    addss xmm2, xmm3            ; Add scalars
    subss xmm2, xmm3            ; Subtract scalars
    mulss xmm2, xmm3            ; Multiply scalars
    divss xmm2, xmm3            ; Divide scalars
    
    ; Double precision packed operations
    movapd xmm4, [double_vec1]  ; Load 2 doubles
    movapd xmm5, [double_vec2]  ; Load 2 doubles
    
    addpd xmm4, xmm5            ; Add packed doubles
    subpd xmm4, xmm5            ; Subtract packed doubles
    mulpd xmm4, xmm5            ; Multiply packed doubles
    divpd xmm4, xmm5            ; Divide packed doubles
    
    ; Double precision scalar operations
    movsd xmm6, [scalar_double] ; Load double scalar
    movsd xmm7, [scalar_double]
    
    addsd xmm6, xmm7            ; Add scalars
    subsd xmm6, xmm7            ; Subtract scalars
    mulsd xmm6, xmm7            ; Multiply scalars
    divsd xmm6, xmm7            ; Divide scalars
    
    ; Comparison operations
    cmpps xmm0, xmm1, 0         ; Compare equal
    cmpps xmm0, xmm1, 1         ; Compare less than
    cmpps xmm0, xmm1, 2         ; Compare less than or equal
    cmpps xmm0, xmm1, 4         ; Compare not equal
    
    ; Min/Max operations
    minps xmm0, xmm1            ; Packed minimum
    maxps xmm0, xmm1            ; Packed maximum
    
    ; Square root
    sqrtps xmm0, xmm1           ; Packed square root
    sqrtss xmm2, xmm3           ; Scalar square root
    
    ; Reciprocal operations
    rcpps xmm0, xmm1            ; Packed reciprocal (approximate)
    rsqrtps xmm0, xmm1          ; Packed reciprocal square root
```

### Floating Point Conversions

```assembly
section .data
    int_val dd 42
    float_val dd 42.5
    double_val dq 123.456
    
section .bss
    converted_int resd 1
    converted_float resd 1
    converted_double resq 1

section .text
global _start

_start:
    ; Convert integer to float (x87)
    fild dword [int_val]        ; Load integer and convert to float
    fstp dword [converted_float] ; Store as float
    
    ; Convert float to integer (x87)
    fld dword [float_val]       ; Load float
    fistp dword [converted_int] ; Convert to integer and store
    
    ; SSE conversions
    movd xmm0, [int_val]        ; Load integer to XMM
    cvtdq2ps xmm1, xmm0         ; Convert int32 to float32
    cvtps2dq xmm2, xmm1         ; Convert float32 to int32
    
    ; Double conversions
    movsd xmm3, [double_val]    ; Load double
    cvtsd2ss xmm4, xmm3         ; Convert double to float
    cvtss2sd xmm5, xmm4         ; Convert float to double
    
    ; Truncation vs rounding
    movss xmm0, [float_val]
    cvttss2si eax, xmm0         ; Truncate float to integer
    cvtss2si ebx, xmm0          ; Round float to integer
    
    ; Packed conversions
    movaps xmm0, [float_vec1]
    cvtps2pd xmm1, xmm0         ; Convert 2 floats to 2 doubles
    cvtpd2ps xmm2, xmm1         ; Convert 2 doubles to 2 floats
```

## 17. Optimization Techniques

Performance optimization strategies and techniques in assembly.

### Loop Optimization

```assembly
section .data
    array times 1000 dd 0
    count equ 1000

section .text
global _start

_start:
    ; Unoptimized loop
    mov rcx, count
    mov rsi, 0
unoptimized_loop:
    mov eax, [array + rsi*4]
    inc eax
    mov [array + rsi*4], eax
    inc rsi
    dec rcx
    jnz unoptimized_loop
    
    ; Loop unrolling (process 4 elements at once)
    mov rcx, count / 4
    mov rsi, 0
unrolled_loop:
    mov eax, [array + rsi*4]      ; Element 0
    inc eax
    mov [array + rsi*4], eax
    
    mov eax, [array + rsi*4 + 4]  ; Element 1
    inc eax
    mov [array + rsi*4 + 4], eax
    
    mov eax, [array + rsi*4 + 8]  ; Element 2
    inc eax
    mov [array + rsi*4 + 8], eax
    
    mov eax, [array + rsi*4 + 12] ; Element 3
    inc eax
    mov [array + rsi*4 + 12], eax
    
    add rsi, 4                    ; Process 4 elements
    dec rcx
    jnz unrolled_loop
    
    ; SIMD optimization (process 4 integers at once)
    mov rcx, count / 4
    mov rsi, 0
    movdqa xmm1, [ones]           ; Load vector of ones
    
simd_loop:
    movdqa xmm0, [array + rsi*4]  ; Load 4 integers
    paddd xmm0, xmm1              ; Add 1 to each
    movdqa [array + rsi*4], xmm0  ; Store back
    add rsi, 4                    ; Next 4 elements
    dec rcx
    jnz simd_loop
    
    ; Software pipelining (overlapping operations)
    mov rcx, count - 1
    mov rsi, 0
    mov eax, [array + rsi*4]      ; Preload first element
    
pipelined_loop:
    inc eax                       ; Process current
    mov ebx, [array + rsi*4 + 4]  ; Load next while processing current
    mov [array + rsi*4], eax      ; Store current
    mov eax, ebx                  ; Move next to current
    inc rsi
    dec rcx
    jnz pipelined_loop
    
    ; Process last element
    inc eax
    mov [array + rsi*4], eax

section .data
ones dd 1, 1, 1, 1
```

### Branch Optimization

```assembly
section .data
    test_values dd 1, 5, 10, 15, 20, 25
    results times 6 dd 0

section .text
global _start

_start:
    ; Branch prediction optimization
    mov rcx, 6
    mov rsi, 0

optimized_branch_loop:
    mov eax, [test_values + rsi*4]
    
    ; Arrange branches from most likely to least likely
    cmp eax, 10
    jl less_than_10         ; Most common case first
    cmp eax, 20
    jl between_10_20        ; Second most common
    jmp greater_equal_20    ; Least common
    
less_than_10:
    shl eax, 1              ; Multiply by 2
    jmp store_result
    
between_10_20:
    shl eax, 2              ; Multiply by 4
    jmp store_result
    
greater_equal_20:
    shl eax, 3              ; Multiply by 8
    
store_result:
    mov [results + rsi*4], eax
    inc rsi
    dec rcx
    jnz optimized_branch_loop
    
    ; Branchless optimization using conditional moves
    mov rcx, 6
    mov rsi, 0

branchless_loop:
    mov eax, [test_values + rsi*4]
    mov ebx, eax
    mov edx, eax
    
    ; Prepare all possible results
    shl ebx, 1              ; * 2
    shl edx, 2              ; * 4
    shl eax, 3              ; * 8
    
    ; Use conditional moves instead of branches
    cmp dword [test_values + rsi*4], 10
    cmovl eax, ebx          ; Use *2 if < 10
    
    cmp dword [test_values + rsi*4], 20
    cmovl eax, edx          ; Use *4 if < 20 (and >= 10)
    
    mov [results + rsi*4], eax
    inc rsi
    dec rcx
    jnz branchless_loop
```

### Memory Access Optimization

```assembly
section .data
    align 64                    ; Align to cache line boundary
    matrix1 times 256 dd 0      ; 16x16 matrix
    matrix2 times 256 dd 0
    result_matrix times 256 dd 0

section .text
global _start

_start:
    ; Cache-friendly matrix multiplication
    mov r8, 0                   ; i (row)
    
outer_loop:
    mov r9, 0                   ; j (column)
    
middle_loop:
    mov r10, 0                  ; k (inner product)
    xor eax, eax                ; sum = 0
    
    ; Prefetch next cache line
    mov r11, r8
    inc r11
    shl r11, 6                  ; r11 = (i+1) * 16 * 4
    prefetcht0 [matrix1 + r11]
    
inner_loop:
    ; Calculate addresses
    mov r11, r8
    shl r11, 4                  ; r11 = i * 16
    add r11, r10                ; r11 = i * 16 + k
    shl r11, 2                  ; r11 = (i * 16 + k) * 4
    
    mov r12, r10
    shl r12, 4                  ; r12 = k * 16
    add r12, r9                 ; r12 = k * 16 + j
    shl r12, 2                  ; r12 = (k * 16 + j) * 4
    
    ; Multiply and accumulate
    mov ebx, [matrix1 + r11]    ; matrix1[i][k]
    mov ecx, [matrix2 + r12]    ; matrix2[k][j]
    imul ebx, ecx               ; matrix1[i][k] * matrix2[k][j]
    add eax, ebx                ; sum += product
    
    inc r10                     ; k++
    cmp r10, 16
    jl inner_loop
    
    ; Store result
    mov r11, r8
    shl r11, 4                  ; r11 = i * 16
    add r11, r9                 ; r11 = i * 16 + j
    shl r11, 2                  ; r11 = (i * 16 + j) * 4
    mov [result_matrix + r11], eax
    
    inc r9                      ; j++
    cmp r9, 16
    jl middle_loop
    
    inc r8                      ; i++
    cmp r8, 16
    jl outer_loop
    
    ; Block-based optimization for larger matrices
    ; Process matrices in cache-friendly blocks
    mov r13, 0                  ; block_i
    
block_outer:
    mov r14, 0                  ; block_j
    
block_middle:
    mov r15, 0                  ; block_k
    
block_inner:
    ; Process 4x4 sub-block
    call process_4x4_block
    
    add r15, 4                  ; Next k block
    cmp r15, 16
    jl block_inner
    
    add r14, 4                  ; Next j block
    cmp r14, 16
    jl block_middle
    
    add r13, 4                  ; Next i block
    cmp r13, 16
    jl block_outer

process_4x4_block:
    ; Implementation of 4x4 block processing
    ; (simplified for brevity)
    ret
```

### Instruction Pipeline Optimization

```assembly
section .data
    data1 times 100 dq 0
    data2 times 100 dq 0
    results times 100 dq 0

section .text
global _start

_start:
    ; Poorly pipelined code (dependencies)
    mov rcx, 100
    mov rsi, 0
    
poor_pipeline:
    mov rax, [data1 + rsi*8]    ; Load
    add rax, [data2 + rsi*8]    ; Dependent on previous load
    imul rax, rax               ; Dependent on previous add
    mov [results + rsi*8], rax  ; Dependent on previous imul
    inc rsi                     ; Independent
    dec rcx                     ; Dependent on inc
    jnz poor_pipeline           ; Dependent on dec
    
    ; Well-pipelined code (reduced dependencies)
    mov rcx, 100
    mov rsi, 0
    
good_pipeline:
    mov rax, [data1 + rsi*8]        ; Load 1
    mov rbx, [data2 + rsi*8]        ; Load 2 (independent)
    mov rdx, [data1 + rsi*8 + 8]    ; Preload next (independent)
    mov r8, [data2 + rsi*8 + 8]     ; Preload next (independent)
    
    add rax, rbx                    ; Process current
    add rdx, r8                     ; Process next (independent)
    
    imul rax, rax                   ; Square current
    imul rdx, rdx                   ; Square next (independent)
    
    mov [results + rsi*8], rax      ; Store current
    mov [results + rsi*8 + 8], rdx  ; Store next
    
    add rsi, 2                      ; Process 2 at once
    sub rcx, 2                      ; Adjust counter
    jnz good_pipeline
    
    ; Instruction level parallelism
    mov rcx, 25                     ; Process 4 at once
    mov rsi, 0
    
ilp_loop:
    ; Load phase (can execute in parallel)
    mov rax, [data1 + rsi*8]        ; Element 0
    mov rbx, [data1 + rsi*8 + 8]    ; Element 1
    mov rdx, [data1 + rsi*8 + 16]   ; Element 2
    mov r8, [data1 + rsi*8 + 24]    ; Element 3
    
    mov r9, [data2 + rsi*8]         ; Element 0
    mov r10, [data2 + rsi*8 + 8]    ; Element 1
    mov r11, [data2 + rsi*8 + 16]   ; Element 2
    mov r12, [data2 + rsi*8 + 24]   ; Element 3
    
    ; Compute phase (can execute in parallel)
    add rax, r9                     ; Process 0
    add rbx, r10                    ; Process 1
    add rdx, r11                    ; Process 2
    add r8, r12                     ; Process 3
    
    imul rax, rax                   ; Square 0
    imul rbx, rbx                   ; Square 1
    imul rdx, rdx                   ; Square 2
    imul r8, r8                     ; Square 3
    
    ; Store phase (can execute in parallel)
    mov [results + rsi*8], rax      ; Store 0
    mov [results + rsi*8 + 8], rbx  ; Store 1
    mov [results + rsi*8 + 16], rdx ; Store 2
    mov [results + rsi*8 + 24], r8  ; Store 3
    
    add rsi, 4                      ; Next 4 elements
    dec rcx
    jnz ilp_loop
```

## 18. Debugging Assembly

Debugging techniques and tools for assembly programs.

### GDB Assembly Debugging

```assembly
; debug_example.asm - Example program for debugging
section .data
    numbers dd 10, 20, 30, 40, 50
    count equ 5
    result dd 0

section .text
global _start

_start:
    ; Calculate sum of array
    mov ecx, count
    mov esi, 0          ; index
    mov eax, 0          ; sum

sum_loop:
    add eax, [numbers + esi*4]
    inc esi
    dec ecx
    jnz sum_loop
    
    mov [result], eax
    
    ; Intentional bug for debugging
    mov ebx, 0
    div ebx             ; Division by zero
    
    ; Exit
    mov eax, 60
    mov edi, 0
    syscall

; GDB commands for debugging:
; gdb ./debug_example
; (gdb) break _start
; (gdb) run
; (gdb) stepi                    ; Step one instruction
; (gdb) info registers          ; Show all registers
; (gdb) print $eax              ; Print register value
; (gdb) x/5wd numbers           ; Examine memory (5 words decimal)
; (gdb) x/10i $pc              ; Examine 10 instructions at PC
; (gdb) watch result            ; Watch variable for changes
; (gdb) backtrace              ; Show call stack
; (gdb) disassemble _start     ; Disassemble function
```

### Debug Symbols and Information

```assembly
; compile with: nasm -f elf64 -g -F dwarf debug_symbols.asm
; link with: ld -o debug_symbols debug_symbols.o

section .data
    debug_var dd 42
    debug_array dd 1, 2, 3, 4, 5

section .bss
    debug_buffer resb 100

section .text
global _start

_start:
    ; Function to debug
    call debug_function
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall

debug_function:
    push rbp
    mov rbp, rsp
    sub rsp, 32             ; Local variables space
    
    ; Local variable simulation
    mov dword [rbp-4], 100  ; local_var1
    mov dword [rbp-8], 200  ; local_var2
    
    ; Some operations to debug
    mov eax, [debug_var]
    add eax, [rbp-4]
    mov [rbp-12], eax       ; local_result
    
    ; Array access
    mov esi, 2              ; index
    mov eax, [debug_array + esi*4]
    add [rbp-12], eax
    
    mov esp, ebp
    pop rbp
    ret

; Advanced GDB debugging:
; (gdb) info locals            ; Show local variables
; (gdb) info args             ; Show function arguments
; (gdb) frame                 ; Show current frame
; (gdb) up/down               ; Navigate call stack
; (gdb) set var debug_var=100 ; Change variable value
; (gdb) call debug_function   ; Call function manually
; (gdb) finish                ; Run until function returns
```

### Assembly with C Integration for Debugging

```c
// debug_helper.c - C helper for debugging assembly
#include <stdio.h>
#include <stdint.h>

// External assembly functions
extern int asm_function(int a, int b);
extern void asm_array_process(int* array, int size);

// Debug helper functions
void print_registers(uint64_t rax, uint64_t rbx, uint64_t rcx, uint64_t rdx) {
    printf("RAX: 0x%lx, RBX: 0x%lx, RCX: 0x%lx, RDX: 0x%lx\n", 
           rax, rbx, rcx, rdx);
}

void print_memory(void* addr, int size) {
    unsigned char* ptr = (unsigned char*)addr;
    printf("Memory at %p: ", addr);
    for (int i = 0; i < size; i++) {
        printf("%02x ", ptr[i]);
    }
    printf("\n");
}

int main() {
    int array[] = {1, 2, 3, 4, 5};
    
    printf("Before assembly function:\n");
    for (int i = 0; i < 5; i++) {
        printf("array[%d] = %d\n", i, array[i]);
    }
    
    asm_array_process(array, 5);
    
    printf("After assembly function:\n");
    for (int i = 0; i < 5; i++) {
        printf("array[%d] = %d\n", i, array[i]);
    }
    
    return 0;
}
```

```assembly
; debug_mixed.asm - Assembly with C integration
section .text
global asm_function
global asm_array_process
extern print_registers
extern print_memory

asm_function:
    push rbp
    mov rbp, rsp
    
    ; Save parameters for debugging
    mov rax, rdi        ; first parameter
    mov rbx, rsi        ; second parameter
    
    ; Call C debug function
    push rax
    push rbx
    push rcx
    push rdx
    call print_registers
    add rsp, 32
    
    ; Actual function logic
    add rax, rbx
    
    pop rbp
    ret

asm_array_process:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    
    mov r12, rdi        ; array pointer
    mov r13, rsi        ; array size
    
    ; Print original memory
    mov rdi, r12
    mov rsi, 20         ; 5 ints * 4 bytes
    call print_memory
    
    ; Process array
    mov rcx, r13
    mov rbx, 0
    
process_loop:
    mov eax, [r12 + rbx*4]
    shl eax, 1          ; multiply by 2
    mov [r12 + rbx*4], eax
    inc rbx
    dec rcx
    jnz process_loop
    
    ; Print modified memory
    mov rdi, r12
    mov rsi, 20
    call print_memory
    
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; Compile and link:
; nasm -f elf64 -g debug_mixed.asm
; gcc -c debug_helper.c
; gcc -o debug_mixed debug_mixed.o debug_helper.o
; gdb ./debug_mixed
```

### Performance Profiling

```assembly
; profile_example.asm - Example for performance profiling
section .data
    large_array times 1000000 dd 0
    iterations equ 1000

section .text
global _start

_start:
    ; Hot path - frequently executed code
    mov r15, iterations
    
performance_loop:
    ; Simulate computationally intensive work
    mov rcx, 1000000
    mov rsi, 0
    xor rax, rax
    
inner_computation:
    add eax, [large_array + rsi*4]
    ror eax, 1          ; Rotate for mixing
    xor eax, esi        ; More computation
    inc rsi
    dec rcx
    jnz inner_computation
    
    ; Store result to prevent optimization
    mov [large_array], eax
    
    dec r15
    jnz performance_loop
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall

; Profiling with perf:
; perf record -g ./profile_example
; perf report
; 
; Profiling specific events:
; perf stat -e cycles,instructions,cache-misses,branch-misses ./profile_example
; 
; Hot spot analysis:
; perf annotate
; 
; Cache analysis:
; perf stat -e L1-dcache-loads,L1-dcache-load-misses ./profile_example
```

### Memory Debugging with Valgrind

```assembly
; valgrind_example.asm - Example for memory debugging
section .text
global _start

_start:
    ; Allocate memory using mmap
    mov rax, 9          ; sys_mmap
    mov rdi, 0          ; addr
    mov rsi, 4096       ; length
    mov rdx, 3          ; prot (PROT_READ | PROT_WRITE)
    mov r10, 34         ; flags (MAP_PRIVATE | MAP_ANONYMOUS)
    mov r8, -1          ; fd
    mov r9, 0           ; offset
    syscall
    
    mov rbx, rax        ; Save allocated address
    
    ; Write to allocated memory
    mov dword [rbx], 0x12345678
    mov dword [rbx + 4], 0x9ABCDEF0
    
    ; Intentional memory error for testing
    ; mov dword [rbx + 4096], 0x11111111  ; Out of bounds write
    
    ; Read from memory
    mov eax, [rbx]
    mov ecx, [rbx + 4]
    
    ; Free memory
    mov rax, 11         ; sys_munmap
    mov rdi, rbx        ; addr
    mov rsi, 4096       ; length
    syscall
    
    ; Intentional use after free for testing
    ; mov eax, [rbx]     ; Use after free
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall

; Run with Valgrind:
; valgrind --tool=memcheck --leak-check=full --track-origins=yes ./valgrind_example
; 
; For assembly-specific issues:
; valgrind --tool=memcheck --track-fds=yes --show-reachable=yes ./valgrind_example
```

## 19. Inline Assembly

Integrating assembly code within high-level languages.

### GCC Inline Assembly

```c
// gcc_inline.c - GCC inline assembly examples
#include <stdio.h>
#include <stdint.h>

int main() {
    int a = 10, b = 20, result;
    
    // Basic inline assembly
    asm("addl %1, %0"           // instruction
        : "=r" (result)         // output operands
        : "r" (a), "0" (b)      // input operands
        :                       // clobbered registers
    );
    printf("Basic add: %d\n", result);
    
    // Assembly with multiple operations
    int x = 5, y = 3;
    asm volatile (
        "movl %1, %%eax\n\t"    // Move x to eax
        "addl %2, %%eax\n\t"    // Add y to eax
        "imull %%eax, %%eax\n\t" // Square the result
        "movl %%eax, %0"        // Store result
        : "=m" (result)         // output: memory
        : "m" (x), "m" (y)      // inputs: memory
        : "eax"                 // clobbered: eax
    );
    printf("(x + y)^2 = %d\n", result);
    
    // Using specific registers
    uint64_t cycles_start, cycles_end;
    asm volatile ("rdtsc\n\t"
                  "shl $32, %%rdx\n\t"
                  "or %%rdx, %%rax"
                  : "=a" (cycles_start)
                  :
                  : "rdx");
    
    // Some work here
    volatile int dummy = 0;
    for (int i = 0; i < 1000000; i++) {
        dummy += i;
    }
    
    asm volatile ("rdtsc\n\t"
                  "shl $32, %%rdx\n\t"
                  "or %%rdx, %%rax"
                  : "=a" (cycles_end)
                  :
                  : "rdx");
    
    printf("Cycles taken: %lu\n", cycles_end - cycles_start);
    
    // Memory constraints
    int array[4] = {1, 2, 3, 4};
    asm volatile (
        "movdqu %1, %%xmm0\n\t"     // Load array to XMM0
        "paddd %%xmm0, %%xmm0\n\t"  // Double each element
        "movdqu %%xmm0, %0"         // Store back
        : "=m" (*array)             // output: array
        : "m" (*array)              // input: array
        : "xmm0"                    // clobbered: xmm0
    );
    
    printf("Doubled array: ");
    for (int i = 0; i < 4; i++) {
        printf("%d ", array[i]);
    }
    printf("\n");
    
    return 0;
}
```

### Advanced Inline Assembly Patterns

```c
// advanced_inline.c - Advanced inline assembly patterns
#include <stdio.h>
#include <stdint.h>
#include <immintrin.h>

// Assembly function wrapper
static inline uint64_t read_tsc(void) {
    uint32_t lo, hi;
    asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

// Atomic operations
static inline int atomic_add(volatile int *ptr, int value) {
    int result;
    asm volatile (
        "lock xaddl %0, %1"
        : "=r" (result), "+m" (*ptr)
        : "0" (value)
        : "memory"
    );
    return result;
}

// Memory barriers
static inline void memory_barrier(void) {
    asm volatile ("mfence" ::: "memory");
}

// CPU feature detection
static inline void cpuid(uint32_t eax_in, uint32_t *eax, uint32_t *ebx, 
                        uint32_t *ecx, uint32_t *edx) {
    asm volatile (
        "cpuid"
        : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
        : "a" (eax_in)
    );
}

// Fast string operations
static inline void fast_memcpy(void *dest, const void *src, size_t n) {
    asm volatile (
        "rep movsb"
        : "+D" (dest), "+S" (src), "+c" (n)
        :
        : "memory"
    );
}

// Bit manipulation
static inline int count_set_bits(uint32_t x) {
    int count;
    asm ("popcnt %1, %0" : "=r" (count) : "r" (x));
    return count;
}

static inline int find_first_set(uint32_t x) {
    int result;
    asm ("bsf %1, %0" : "=r" (result) : "r" (x));
    return result;
}

// SIMD operations
static inline void vector_add_asm(float *a, float *b, float *result) {
    asm volatile (
        "movups %1, %%xmm0\n\t"
        "movups %2, %%xmm1\n\t"
        "addps %%xmm1, %%xmm0\n\t"
        "movups %%xmm0, %0"
        : "=m" (*result)
        : "m" (*a), "m" (*b)
        : "xmm0", "xmm1"
    );
}

int main() {
    // Test atomic operations
    volatile int counter = 0;
    int old_value = atomic_add(&counter, 5);
    printf("Atomic add: old=%d, new=%d\n", old_value, counter);
    
    // Test CPU features
    uint32_t eax, ebx, ecx, edx;
    cpuid(1, &eax, &ebx, &ecx, &edx);
    printf("CPU features: ECX=0x%x, EDX=0x%x\n", ecx, edx);
    
    // Test bit operations
    uint32_t value = 0b11010110;
    printf("Set bits in %u: %d\n", value, count_set_bits(value));
    printf("First set bit: %d\n", find_first_set(value));
    
    // Test SIMD
    float a[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float b[4] = {5.0f, 6.0f, 7.0f, 8.0f};
    float result[4];
    vector_add_asm(a, b, result);
    
    printf("SIMD add result: ");
    for (int i = 0; i < 4; i++) {
        printf("%.1f ", result[i]);
    }
    printf("\n");
    
    // Performance measurement
    uint64_t start = read_tsc();
    
    // Some work
    volatile int sum = 0;
    for (int i = 0; i < 100000; i++) {
        sum += i;
    }
    
    uint64_t end = read_tsc();
    printf("Cycles for loop: %lu\n", end - start);
    
    return 0;
}
```

### Microsoft Visual C++ Inline Assembly

```c
// msvc_inline.c - MSVC inline assembly (x86 only, not x64)
#ifdef _MSC_VER
#include <stdio.h>
#include <intrin.h>

void msvc_inline_examples() {
    int a = 10, b = 20, result;
    
    // Basic MSVC inline assembly (32-bit only)
    #ifdef _M_IX86
    __asm {
        mov eax, a
        add eax, b
        mov result, eax
    }
    printf("MSVC inline result: %d\n", result);
    
    // More complex example
    int array[4] = {1, 2, 3, 4};
    __asm {
        mov esi, offset array
        mov ecx, 4
        mov eax, 0
        
    sum_loop:
        add eax, dword ptr [esi]
        add esi, 4
        dec ecx
        jnz sum_loop
        
        mov result, eax
    }
    printf("Array sum: %d\n", result);
    #endif
    
    // For x64, use intrinsics instead
    unsigned __int64 tsc = __rdtsc();
    printf("Timestamp counter: %llu\n", tsc);
}

int main() {
    msvc_inline_examples();
    return 0;
}
#endif
```

## 20. Assembly Best Practices

Best practices and conventions for writing maintainable assembly code.

### Code Organization and Documentation

```assembly
; best_practices.asm - Example of well-organized assembly code
; Author: Assembly Programmer
; Date: 2024
; Purpose: Demonstrate best practices in assembly programming

;===============================================================================
; CONSTANTS AND DEFINITIONS
;===============================================================================
BUFFER_SIZE     equ 1024        ; Input buffer size
MAX_ITERATIONS  equ 100         ; Maximum loop iterations
SUCCESS         equ 0           ; Success return code
ERROR           equ -1          ; Error return code

;===============================================================================
; DATA SECTION
;===============================================================================
section .data
    ; Program messages
    welcome_msg     db 'Assembly Best Practices Demo', 10, 0
    welcome_len     equ $ - welcome_msg - 1
    
    error_msg       db 'Error occurred', 10, 0
    error_len       equ $ - error_msg - 1
    
    ; Configuration data
    config_values   dd 42, 84, 126, 168, 210
    config_count    equ ($ - config_values) / 4

;===============================================================================
; BSS SECTION - UNINITIALIZED DATA
;===============================================================================
section .bss
    input_buffer    resb BUFFER_SIZE    ; User input buffer
    temp_storage    resq 10             ; Temporary storage
    result_array    resd MAX_ITERATIONS ; Results storage

;===============================================================================
; TEXT SECTION - CODE
;===============================================================================
section .text
    global _start

;-------------------------------------------------------------------------------
; FUNCTION: _start
; PURPOSE:  Program entry point
; INPUTS:   None
; OUTPUTS:  Exit code in rdi
; MODIFIES: All registers
;-------------------------------------------------------------------------------
_start:
    ; Initialize program
    call display_welcome
    call initialize_data
    
    ; Main program logic
    call process_data
    test rax, rax
    jnz .error_exit
    
    ; Normal exit
    mov rdi, SUCCESS
    jmp .exit
    
.error_exit:
    call display_error
    mov rdi, ERROR
    
.exit:
    mov rax, 60                 ; sys_exit
    syscall

;-------------------------------------------------------------------------------
; FUNCTION: display_welcome
; PURPOSE:  Display welcome message
; INPUTS:   None
; OUTPUTS:  None
; MODIFIES: rax, rdi, rsi, rdx
;-------------------------------------------------------------------------------
display_welcome:
    mov rax, 1                  ; sys_write
    mov rdi, 1                  ; stdout
    mov rsi, welcome_msg        ; message
    mov rdx, welcome_len        ; length
    syscall
    ret

;-------------------------------------------------------------------------------
; FUNCTION: display_error
; PURPOSE:  Display error message
; INPUTS:   None
; OUTPUTS:  None
; MODIFIES: rax, rdi, rsi, rdx
;-------------------------------------------------------------------------------
display_error:
    mov rax, 1                  ; sys_write
    mov rdi, 2                  ; stderr
    mov rsi, error_msg          ; message
    mov rdx, error_len          ; length
    syscall
    ret

;-------------------------------------------------------------------------------
; FUNCTION: initialize_data
; PURPOSE:  Initialize program data structures
; INPUTS:   None
; OUTPUTS:  None
; MODIFIES: rax, rcx, rdi
;-------------------------------------------------------------------------------
initialize_data:
    ; Clear result array
    mov rdi, result_array
    mov rcx, MAX_ITERATIONS
    xor rax, rax
    rep stosd                   ; Store zero to each dword
    
    ; Clear temp storage
    mov rdi, temp_storage
    mov rcx, 10
    rep stosq                   ; Store zero to each qword
    
    ret

;-------------------------------------------------------------------------------
; FUNCTION: process_data
; PURPOSE:  Main data processing routine
; INPUTS:   None
; OUTPUTS:  rax = 0 on success, non-zero on error
; MODIFIES: rax, rbx, rcx, rdx, rsi, rdi
;-------------------------------------------------------------------------------
process_data:
    push rbp
    mov rbp, rsp
    push rbx                    ; Save callee-saved register
    push r12
    push r13
    
    ; Local variables on stack
    sub rsp, 32
    ; [rbp-8]  = loop counter
    ; [rbp-16] = current sum
    ; [rbp-24] = error flag
    ; [rbp-32] = temp value
    
    ; Initialize local variables
    mov qword [rbp-8], 0        ; loop counter
    mov qword [rbp-16], 0       ; current sum
    mov qword [rbp-24], 0       ; error flag
    
    ; Main processing loop
.process_loop:
    mov rax, [rbp-8]            ; Get loop counter
    cmp rax, config_count       ; Check bounds
    jge .loop_done
    
    ; Get configuration value
    mov rsi, config_values
    mov ebx, [rsi + rax*4]      ; Load config_values[counter]
    
    ; Validate input (example validation)
    test ebx, ebx
    jz .validation_error
    
    ; Process value
    call process_single_value   ; Process value in ebx
    test rax, rax               ; Check for error
    jnz .processing_error
    
    ; Update sum
    add [rbp-16], rax
    
    ; Store result
    mov rsi, [rbp-8]
    mov rdi, result_array
    mov [rdi + rsi*4], eax
    
    ; Next iteration
    inc qword [rbp-8]
    jmp .process_loop
    
.validation_error:
    mov qword [rbp-24], 1       ; Set error flag
    jmp .error_exit
    
.processing_error:
    mov qword [rbp-24], 2       ; Set error flag
    jmp .error_exit
    
.loop_done:
    ; Success
    xor rax, rax
    jmp .cleanup
    
.error_exit:
    mov rax, [rbp-24]           ; Return error code
    
.cleanup:
    add rsp, 32                 ; Clean up local variables
    pop r13                     ; Restore callee-saved registers
    pop r12
    pop rbx
    pop rbp
    ret

;-------------------------------------------------------------------------------
; FUNCTION: process_single_value
; PURPOSE:  Process a single configuration value
; INPUTS:   ebx = value to process
; OUTPUTS:  rax = processed value, or error code
; MODIFIES: rax, rdx
;-------------------------------------------------------------------------------
process_single_value:
    ; Input validation
    test ebx, ebx
    jz .error                   ; Zero is invalid
    
    ; Simple processing: square the value
    mov eax, ebx
    mul eax                     ; eax = eax * eax
    
    ; Check for overflow (simplified)
    test edx, edx
    jnz .error
    
    ; Success
    ret
    
.error:
    mov rax, ERROR
    ret
```

### Performance Guidelines

```assembly
; performance_guidelines.asm - Performance optimization examples

section .data
    align 64                    ; Align to cache line
    hot_data times 16 dq 0      ; Frequently accessed data
    
    align 16                    ; Align for SIMD
    vector_data dd 1.0, 2.0, 3.0, 4.0

section .text
global _start

_start:
    ; GUIDELINE 1: Minimize memory accesses
    ; BAD: Multiple memory accesses
    mov eax, [hot_data]
    add eax, 1
    mov [hot_data], eax
    mov eax, [hot_data]
    add eax, 1
    mov [hot_data], eax
    
    ; GOOD: Keep value in register
    mov eax, [hot_data]
    add eax, 1
    add eax, 1
    mov [hot_data], eax
    
    ; GUIDELINE 2: Use appropriate instruction sizes
    ; BAD: Unnecessary 64-bit when 32-bit suffices
    mov rax, 42
    add rax, 1
    
    ; GOOD: Use 32-bit when possible (automatically zeros upper 32 bits)
    mov eax, 42
    add eax, 1
    
    ; GUIDELINE 3: Avoid partial register updates
    ; BAD: Partial register update causes dependency
    mov eax, 0x12345678
    mov al, 0xFF                ; Creates false dependency
    
    ; GOOD: Use full register or zero first
    mov eax, 0x12345678
    and eax, 0xFFFFFF00
    or eax, 0xFF
    
    ; GUIDELINE 4: Use SIMD when possible
    ; Process 4 floats at once instead of one by one
    movaps xmm0, [vector_data]
    addps xmm0, xmm0            ; Double all 4 values
    movaps [vector_data], xmm0
    
    ; GUIDELINE 5: Branch prediction optimization
    ; Arrange code so likely branches fall through
    mov eax, [hot_data]
    test eax, eax
    jz rare_case                ; Unlikely branch jumps
    
    ; Common case code here (falls through)
    inc eax
    jmp continue
    
rare_case:
    ; Rare case code
    mov eax, 1
    
continue:
    ; GUIDELINE 6: Loop optimization
    mov rcx, 1000
    mov rsi, hot_data
    
optimized_loop:
    ; Unroll loop for better performance
    add qword [rsi], 1          ; Iteration 1
    add qword [rsi+8], 1        ; Iteration 2
    add qword [rsi+16], 1       ; Iteration 3
    add qword [rsi+24], 1       ; Iteration 4
    
    add rsi, 32                 ; Process 4 elements
    sub rcx, 4                  ; Adjust counter
    jnz optimized_loop
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall
```

### Error Handling Patterns

```assembly
; error_handling.asm - Error handling best practices

section .data
    ; Error codes
    ERR_SUCCESS         equ 0
    ERR_INVALID_INPUT   equ 1
    ERR_OUT_OF_BOUNDS   equ 2
    ERR_MEMORY_ERROR    equ 3
    
    test_array dd 1, 2, 3, 4, 5
    array_size equ 5

section .text
global _start

_start:
    ; Example: Safe array access with error handling
    mov rdi, 3                  ; Index to access
    call safe_array_access
    test rax, rax
    jnz .handle_error
    
    ; Success path
    jmp .exit_success
    
.handle_error:
    ; Handle specific error
    cmp rax, ERR_OUT_OF_BOUNDS
    je .bounds_error
    cmp rax, ERR_INVALID_INPUT
    je .input_error
    
    ; Unknown error
    mov rdi, 99
    jmp .exit
    
.bounds_error:
    mov rdi, ERR_OUT_OF_BOUNDS
    jmp .exit
    
.input_error:
    mov rdi, ERR_INVALID_INPUT
    jmp .exit
    
.exit_success:
    mov rdi, ERR_SUCCESS
    
.exit:
    mov rax, 60
    syscall

;-------------------------------------------------------------------------------
; FUNCTION: safe_array_access
; PURPOSE:  Safely access array element with bounds checking
; INPUTS:   rdi = index
; OUTPUTS:  rax = error code (0 = success), rdx = value if success
; MODIFIES: rax, rdx
;-------------------------------------------------------------------------------
safe_array_access:
    ; Validate input
    test rdi, rdi
    js .invalid_input           ; Negative index
    
    ; Bounds check
    cmp rdi, array_size
    jge .out_of_bounds          ; Index >= size
    
    ; Access array safely
    mov rax, test_array
    mov edx, [rax + rdi*4]      ; Get array element
    
    ; Success
    xor rax, rax                ; Return success
    ret
    
.invalid_input:
    mov rax, ERR_INVALID_INPUT
    ret
    
.out_of_bounds:
    mov rax, ERR_OUT_OF_BOUNDS
    ret

;-------------------------------------------------------------------------------
; FUNCTION: cleanup_on_error
; PURPOSE:  Centralized cleanup for error conditions
; INPUTS:   None
; OUTPUTS:  None
; MODIFIES: All registers (cleanup function)
;-------------------------------------------------------------------------------
cleanup_on_error:
    ; Free any allocated memory
    ; Close any open file descriptors
    ; Reset global state
    ; etc.
    ret
```

### Portability Considerations

```assembly
; portability.asm - Writing portable assembly code

%ifdef LINUX
    ; Linux-specific definitions
    SYS_WRITE   equ 1
    SYS_EXIT    equ 60
    STDOUT      equ 1
%endif

%ifdef WINDOWS
    ; Windows-specific definitions (would need different approach)
    ; extern ExitProcess
    ; extern WriteConsole
%endif

section .data
    msg db 'Portable Assembly', 10, 0
    msg_len equ $ - msg - 1

section .text
global _start

_start:
    ; Use macros for system calls to improve portability
    WRITE_STRING msg, msg_len
    EXIT_PROGRAM 0

; Portable macros
%macro WRITE_STRING 2
    mov rax, SYS_WRITE
    mov rdi, STDOUT
    mov rsi, %1
    mov rdx, %2
    syscall
%endmacro

%macro EXIT_PROGRAM 1
    mov rax, SYS_EXIT
    mov rdi, %1
    syscall
%endmacro

; Architecture-specific optimizations
%ifdef x86_64
    ; 64-bit specific code
    %define WORD_SIZE 8
    %define REG_PREFIX r
%else
    ; 32-bit fallback
    %define WORD_SIZE 4
    %define REG_PREFIX e
%endif

; Feature detection at runtime
check_cpu_features:
    ; Check for SSE support
    mov eax, 1
    cpuid
    test edx, 1 << 25           ; SSE bit
    jz .no_sse
    
    ; SSE available
    ret
    
.no_sse:
    ; Fallback to x87 or basic operations
    ret
```

## Advanced Topics and Modern Assembly

### SIMD Programming with AVX/AVX2

```assembly
; avx_examples.asm - Advanced SIMD programming
section .data
    align 32
    float_array dd 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0
    double_array dq 1.5, 2.5, 3.5, 4.5
    int_array dd 10, 20, 30, 40, 50, 60, 70, 80

section .text
global _start

_start:
    ; AVX 256-bit operations
    vmovaps ymm0, [float_array]     ; Load 8 floats into YMM0
    vmovaps ymm1, [float_array]     ; Load 8 floats into YMM1
    
    ; Vector arithmetic
    vaddps ymm2, ymm0, ymm1         ; Add 8 floats in parallel
    vmulps ymm3, ymm0, ymm1         ; Multiply 8 floats in parallel
    vsubps ymm4, ymm2, ymm3         ; Subtract vectors
    
    ; Horizontal operations
    vhaddps ymm5, ymm0, ymm1        ; Horizontal add
    vdpps ymm6, ymm0, ymm1, 0xFF    ; Dot product
    
    ; Permutations and shuffles
    vpermilps ymm7, ymm0, 0x1B      ; Permute within 128-bit lanes
    vperm2f128 ymm8, ymm0, ymm1, 0x21  ; Permute 128-bit lanes
    
    ; Double precision operations
    vmovapd ymm9, [double_array]    ; Load 4 doubles
    vmovapd ymm10, [double_array]
    vaddpd ymm11, ymm9, ymm10       ; Add 4 doubles
    
    ; Integer operations
    vmovdqa ymm12, [int_array]      ; Load 8 integers
    vpaddd ymm13, ymm12, ymm12      ; Add integers (double values)
    
    ; Gather operations (AVX2)
    ; vgatherdps ymm14, [base + ymm_indices*4], ymm_mask
    
    ; Broadcast operations
    vbroadcastss ymm15, [float_array]   ; Broadcast first float to all 8 elements
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall
```

### Multi-threading and Synchronization

```assembly
; threading.asm - Multi-threading example
section .data
    shared_counter dq 0
    thread_count equ 4
    stack_size equ 8192

section .bss
    thread_stacks resb thread_count * stack_size
    thread_ids resq thread_count

section .text
global _start

_start:
    ; Create multiple threads
    mov rcx, thread_count
    mov rsi, 0                      ; Thread index
    
create_threads:
    push rcx
    push rsi
    
    ; Calculate stack pointer for this thread
    mov rax, rsi
    imul rax, stack_size
    add rax, thread_stacks
    add rax, stack_size             ; Top of stack
    
    ; Clone system call (simplified)
    mov rdi, 0x00010000             ; CLONE_VM
    mov rdx, 0                      ; Parent TID
    mov r10, 0                      ; Child TID
    mov r8, 0                       ; TLS
    mov rax, 56                     ; sys_clone
    syscall
    
    test rax, rax
    jz thread_function              ; Child process
    
    ; Parent: save thread ID
    pop rsi
    mov [thread_ids + rsi*8], rax
    inc rsi
    pop rcx
    dec rcx
    jnz create_threads
    
    ; Wait for all threads
    mov rcx, thread_count
    mov rsi, 0
    
wait_threads:
    push rcx
    push rsi
    
    mov rax, 61                     ; sys_wait4
    mov rdi, [thread_ids + rsi*8]   ; Thread ID
    mov rsi, 0                      ; Status
    mov rdx, 0                      ; Options
    mov r10, 0                      ; Resource usage
    syscall
    
    pop rsi
    pop rcx
    inc rsi
    dec rcx
    jnz wait_threads
    
    ; Print final counter value (simplified)
    mov rax, 60
    mov rdi, 0
    syscall

thread_function:
    ; Atomic increment of shared counter
    mov rcx, 1000000                ; Iterations per thread
    
increment_loop:
    lock inc qword [shared_counter] ; Atomic increment
    dec rcx
    jnz increment_loop
    
    ; Thread exit
    mov rax, 60
    mov rdi, 0
    syscall
```

### x86-64 Processor Features

```assembly
; cpu_features.asm - CPU feature detection and usage
section .bss
    cpu_info resd 4                 ; EAX, EBX, ECX, EDX
    feature_flags resq 1

section .text
global _start

_start:
    ; Basic CPU identification
    mov eax, 0                      ; Get vendor ID
    cpuid
    mov [cpu_info], eax             ; Max standard function
    mov [cpu_info + 4], ebx         ; Vendor ID part 1
    mov [cpu_info + 8], edx         ; Vendor ID part 2
    mov [cpu_info + 12], ecx        ; Vendor ID part 3
    
    ; Get feature flags
    mov eax, 1                      ; Standard feature flags
    cpuid
    mov [feature_flags], edx        ; Standard features in EDX
    mov [feature_flags + 4], ecx    ; Extended features in ECX
    
    ; Check for specific features
    test edx, 1 << 15               ; Check for CMOV
    jz no_cmov
    ; CMOV supported
    
no_cmov:
    test edx, 1 << 23               ; Check for MMX
    jz no_mmx
    ; MMX supported
    
no_mmx:
    test edx, 1 << 25               ; Check for SSE
    jz no_sse
    ; SSE supported
    
no_sse:
    test ecx, 1 << 0                ; Check for SSE3
    jz no_sse3
    ; SSE3 supported
    
no_sse3:
    test ecx, 1 << 28               ; Check for AVX
    jz no_avx
    ; AVX supported
    
no_avx:
    ; Extended feature detection
    mov eax, 0x80000000             ; Get max extended function
    cpuid
    cmp eax, 0x80000001
    jb no_extended
    
    mov eax, 0x80000001             ; Extended features
    cpuid
    test edx, 1 << 29               ; Check for 64-bit mode
    jz no_64bit
    ; 64-bit mode supported
    
no_64bit:
no_extended:
    ; Use TSC (Time Stamp Counter)
    rdtsc                           ; Read TSC into EDX:EAX
    mov rbx, rax                    ; Save low part
    mov rcx, rdx                    ; Save high part
    
    ; Some work
    mov rax, 1000000
delay_loop:
    dec rax
    jnz delay_loop
    
    ; Read TSC again
    rdtsc
    sub rax, rbx                    ; Calculate cycles elapsed
    sbb rdx, rcx
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall
```

### Advanced Memory Management

```assembly
; memory_advanced.asm - Advanced memory management techniques
section .data
    PAGE_SIZE equ 4096
    HUGE_PAGE_SIZE equ 2097152      ; 2MB huge pages

section .text
global _start

_start:
    ; Allocate huge pages
    mov rax, 9                      ; sys_mmap
    mov rdi, 0                      ; addr (let kernel choose)
    mov rsi, HUGE_PAGE_SIZE         ; length (2MB)
    mov rdx, 3                      ; prot (PROT_READ | PROT_WRITE)
    mov r10, 0x40022                ; MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB
    mov r8, -1                      ; fd
    mov r9, 0                       ; offset
    syscall
    
    cmp rax, -1
    je huge_page_failed
    mov rbx, rax                    ; Save huge page address
    
    ; Use NUMA-aware allocation
    mov rax, 9                      ; sys_mmap
    mov rdi, 0                      ; addr
    mov rsi, PAGE_SIZE * 16         ; length
    mov rdx, 3                      ; prot
    mov r10, 0x00008002             ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1                      ; fd
    mov r9, 0                       ; offset
    syscall
    
    mov rcx, rax                    ; Save NUMA page address
    
    ; Memory prefaulting
    mov rdi, rcx                    ; Start address
    mov rsi, PAGE_SIZE * 16         ; Length
    mov rax, 28                     ; sys_madvise
    mov rdx, 1                      ; MADV_WILLNEED
    syscall
    
    ; Lock pages in memory
    mov rax, 149                    ; sys_mlock
    mov rdi, rcx                    ; addr
    mov rsi, PAGE_SIZE * 16         ; len
    syscall
    
    ; Memory barriers and cache control
    mfence                          ; Full memory fence
    
    ; Non-temporal stores to avoid cache pollution
    mov rdi, rbx                    ; Huge page address
    mov rax, 0x1234567890ABCDEF
    mov rcx, HUGE_PAGE_SIZE / 8     ; Number of qwords
    
non_temporal_loop:
    movnti [rdi], rax               ; Non-temporal store
    add rdi, 8
    dec rcx
    jnz non_temporal_loop
    
    sfence                          ; Store fence
    
    ; Memory bandwidth test
    rdtsc
    mov r8, rax                     ; Save start time
    mov r9, rdx
    
    mov rdi, rbx                    ; Source
    mov rsi, rcx                    ; Destination  
    mov rcx, HUGE_PAGE_SIZE / 8     ; Copy size
    rep movsq                       ; Fast memory copy
    
    rdtsc
    sub rax, r8                     ; Calculate elapsed cycles
    sbb rdx, r9
    
    ; Cleanup
    mov rax, 11                     ; sys_munmap
    mov rdi, rbx                    ; huge page addr
    mov rsi, HUGE_PAGE_SIZE         ; length
    syscall
    
    mov rax, 11                     ; sys_munmap
    mov rdi, rcx                    ; NUMA page addr
    mov rsi, PAGE_SIZE * 16         ; length
    syscall
    
    jmp exit_program

huge_page_failed:
    ; Fallback to regular pages
    mov rax, 9                      ; sys_mmap
    mov rdi, 0                      ; addr
    mov rsi, HUGE_PAGE_SIZE         ; length (same size)
    mov rdx, 3                      ; prot
    mov r10, 0x22                   ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1                      ; fd
    mov r9, 0                       ; offset
    syscall
    mov rbx, rax

exit_program:
    mov rax, 60
    mov rdi, 0
    syscall
```

### Security Features and Mitigations

```assembly
; security.asm - Working with modern security features
section .data
    canary_value dq 0x1234567890ABCDEF
    
section .text
global _start

_start:
    ; Stack canary implementation
    mov rax, [canary_value]
    push rax                        ; Save canary on stack
    
    ; Function call with stack protection
    call protected_function
    
    ; Check canary
    pop rax
    cmp rax, [canary_value]
    jne stack_smash_detected
    
    ; Control Flow Integrity (CFI) - Intel CET simulation
    ; In real implementation, this would use ENDBR64 instructions
    
    ; Address Space Layout Randomization (ASLR) detection
    call get_stack_address
    mov rbx, rax                    ; Save stack address
    
    call get_heap_address
    mov rcx, rax                    ; Save heap address
    
    ; Compare addresses to detect ASLR
    xor rbx, rcx                    ; XOR stack and heap addresses
    test rbx, 0xFF00000000000000    ; Check if high bits differ
    jnz aslr_detected
    
aslr_detected:
    ; Position Independent Code (PIC) example
    call get_rip
    mov rbx, rax                    ; RBX = current RIP
    
    ; Calculate relative address
    lea rcx, [rbx + data_offset - get_rip]
    
    ; Use computed address
    mov rax, [rcx]
    
    ; Exit normally
    mov rax, 60
    mov rdi, 0
    syscall

stack_smash_detected:
    ; Handle stack buffer overflow
    mov rax, 60
    mov rdi, 1                      ; Error exit
    syscall

protected_function:
    push rbp
    mov rbp, rsp
    sub rsp, 128                    ; Local buffer
    
    ; Stack canary check
    mov rax, [rsp + 136]            ; Load canary from stack
    cmp rax, [canary_value]
    jne stack_smash_detected
    
    ; Simulate vulnerable function
    mov rdi, rsp                    ; Buffer address
    mov rsi, 256                    ; Dangerous size (larger than buffer)
    ; call unsafe_copy              ; Would cause overflow
    
    mov rsp, rbp
    pop rbp
    ret

get_rip:
    mov rax, [rsp]                  ; Return address = current RIP
    ret

get_stack_address:
    mov rax, rsp
    ret

get_heap_address:
    ; Allocate small heap block to get heap address
    mov rax, 9                      ; sys_mmap
    mov rdi, 0                      ; addr
    mov rsi, 4096                   ; length
    mov rdx, 3                      ; prot
    mov r10, 0x22                   ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1                      ; fd
    mov r9, 0                       ; offset
    syscall
    ret

data_offset:
    dq 0x4141414141414141
```

### Performance Monitoring and Profiling

```assembly
; performance.asm - Advanced performance monitoring
section .data
    test_data times 1000000 dq 0
    
section .text
global _start

_start:
    ; Performance counter setup (requires kernel support)
    ; This is a simplified example
    
    ; Read Performance Monitoring Counters (PMC)
    ; Note: This requires special permissions
    
    ; Basic cycle counting
    rdtsc
    mov r8, rax                     ; Save start cycles (low)
    mov r9, rdx                     ; Save start cycles (high)
    
    ; Cache performance test
    mov rsi, test_data
    mov rcx, 1000000
    xor rax, rax
    
cache_test_loop:
    add rax, [rsi]                  ; Read from memory
    add rsi, 64                     ; Next cache line
    dec rcx
    jnz cache_test_loop
    
    ; End timing
    rdtsc
    sub rax, r8                     ; Calculate elapsed cycles
    sbb rdx, r9
    
    ; Branch prediction test
    rdtsc
    mov r10, rax                    ; Save start time
    mov r11, rdx
    
    mov rcx, 10000000
    xor rax, rax
    
branch_test_loop:
    ; Predictable branch pattern
    inc rax
    test rax, 1                     ; Test if odd
    jz even_case
    ; Odd case
    add rbx, rax
    jmp continue_branch
even_case:
    ; Even case
    sub rbx, rax
continue_branch:
    dec rcx
    jnz branch_test_loop
    
    rdtsc
    sub rax, r10                    ; Branch test cycles
    sbb rdx, r11
    
    ; Instruction-level parallelism test
    rdtsc
    mov r12, rax
    mov r13, rdx
    
    mov rcx, 1000000
    xor rax, rax
    xor rbx, rbx
    xor rdx, rdx
    xor r8, r8
    
ilp_test_loop:
    ; Independent operations that can execute in parallel
    inc rax                         ; Port 0/1/5/6
    inc rbx                         ; Port 0/1/5/6
    inc rdx                         ; Port 0/1/5/6
    inc r8                          ; Port 0/1/5/6
    add rax, 1                      ; Port 0/1/5/6
    add rbx, 1                      ; Port 0/1/5/6
    add rdx, 1                      ; Port 0/1/5/6
    add r8, 1                       ; Port 0/1/5/6
    dec rcx
    jnz ilp_test_loop
    
    rdtsc
    sub rax, r12                    ; ILP test cycles
    sbb rdx, r13
    
    ; Memory bandwidth test
    rdtsc
    mov r14, rax
    mov r15, rdx
    
    mov rsi, test_data
    mov rdi, test_data + 500000*8   ; Offset destination
    mov rcx, 500000                 ; Copy 500K qwords
    rep movsq                       ; Optimized memory copy
    
    rdtsc
    sub rax, r14                    ; Memory bandwidth cycles
    sbb rdx, r15
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall
```

### Modern Assembly Techniques

```assembly
; modern_techniques.asm - Modern assembly programming patterns
section .data
    align 64
    lookup_table times 256 db 0    ; Lookup table for fast operations
    
section .text
global _start

_start:
    ; Initialize lookup table for fast bit counting
    call init_popcount_table
    
    ; Vectorized operations using function pointers
    mov rdi, vector_add_func
    mov rsi, test_vector1
    mov rdx, test_vector2
    mov rcx, result_vector
    call execute_vector_op
    
    ; Template metaprogramming simulation
    mov rax, 8                      ; Element size
    mov rbx, 1000                   ; Count
    call generic_copy
    
    ; Exit
    mov rax, 60
    mov rdi, 0
    syscall

; Initialize popcount lookup table
init_popcount_table:
    xor rcx, rcx                    ; Counter
    
init_loop:
    mov rax, rcx                    ; Current value
    call count_bits                 ; Count bits in RAX
    mov [lookup_table + rcx], al    ; Store result
    inc rcx
    cmp rcx, 256
    jl init_loop
    ret

; Count bits in RAX (Brian Kernighan's algorithm)
count_bits:
    xor rdx, rdx                    ; Bit counter
    
count_loop:
    test rax, rax
    jz count_done
    inc rdx
    dec rax
    and rax, rax                    ; Clear lowest set bit
    ; Actually: and rax, (rax-1) but we already decremented
    jmp count_loop
    
count_done:
    mov rax, rdx
    ret

; Generic vector operation executor
execute_vector_op:
    ; RDI = function pointer
    ; RSI = vector1
    ; RDX = vector2  
    ; RCX = result vector
    push rbp
    mov rbp, rsp
    
    ; Save parameters
    push rsi
    push rdx
    push rcx
    
    ; Call vector function
    call rdi
    
    ; Restore stack
    add rsp, 24
    pop rbp
    ret

; Vector add function
vector_add_func:
    ; Load vectors
    vmovaps ymm0, [rsi]             ; Load vector1
    vmovaps ymm1, [rdx]             ; Load vector2
    vaddps ymm2, ymm0, ymm1         ; Add vectors
    vmovaps [rcx], ymm2             ; Store result
    ret

; Generic copy function (template simulation)
generic_copy:
    ; RAX = element size
    ; RBX = count
    ; Specialized based on element size
    
    cmp rax, 1
    je copy_bytes
    cmp rax, 2
    je copy_words
    cmp rax, 4
    je copy_dwords
    cmp rax, 8
    je copy_qwords
    ret                             ; Unsupported size

copy_bytes:
    mov rcx, rbx
    rep movsb
    ret

copy_words:
    mov rcx, rbx
    rep movsw
    ret

copy_dwords:
    mov rcx, rbx
    rep movsd
    ret

copy_qwords:
    mov rcx, rbx
    rep movsq
    ret

; RAII-style resource management
acquire_resource:
    ; Allocate resource
    mov rax, 9                      ; sys_mmap
    mov rdi, 0                      ; addr
    mov rsi, 4096                   ; length
    mov rdx, 3                      ; prot
    mov r10, 0x22                   ; flags
    mov r8, -1                      ; fd
    mov r9, 0                       ; offset
    syscall
    
    ; Set up automatic cleanup
    push rax                        ; Resource handle
    call register_cleanup
    ret

register_cleanup:
    ; In a real implementation, this would set up
    ; automatic resource cleanup on scope exit
    ret

cleanup_resource:
    ; Cleanup function
    mov rax, 11                     ; sys_munmap
    mov rdi, [rsp + 8]              ; Resource handle
    mov rsi, 4096                   ; length
    syscall
    ret

section .data
test_vector1 dd 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0
test_vector2 dd 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0
result_vector times 8 dd 0.0
```