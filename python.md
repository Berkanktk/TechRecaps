# Python Learning Guide

## Table of Contents

1. [Python Basics](#python-basics)
   1. [What is Python](#what-is-python)
   2. [Variables and Data Types](#variables-and-data-types)
   3. [Operators](#operators)
   4. [Input and Output](#input-and-output)
2. [Control Flow](#control-flow)
   1. [Conditional Statements](#conditional-statements)
   2. [Loops](#loops)
   3. [Break and Continue](#break-and-continue)
   4. [Match Statements](#match-statements)
3. [Data Structures](#data-structures)
   1. [Lists](#lists)
   2. [Tuples](#tuples)
   3. [Dictionaries](#dictionaries)
   4. [Sets](#sets)
4. [Functions](#functions)
   1. [Basic Functions](#basic-functions)
   2. [Parameters and Arguments](#parameters-and-arguments)
   3. [Lambda Functions](#lambda-functions)
   4. [Decorators](#decorators)
5. [Object-Oriented Programming](#object-oriented-programming)
   1. [Classes and Objects](#classes-and-objects)
   2. [Inheritance](#inheritance)
   3. [Polymorphism](#polymorphism)
   4. [Special Methods](#special-methods)
6. [Modules and Packages](#modules-and-packages)
   1. [Importing Modules](#importing-modules)
   2. [Creating Modules](#creating-modules)
   3. [Packages](#packages)
   4. [Virtual Environments](#virtual-environments)
7. [File Handling](#file-handling)
   1. [Reading Files](#reading-files)
   2. [Writing Files](#writing-files)
   3. [File Context Managers](#file-context-managers)
   4. [Working with Paths](#working-with-paths)
8. [Error Handling](#error-handling)
   1. [Try-Except](#try-except)
   2. [Custom Exceptions](#custom-exceptions)
   3. [Finally and Else](#finally-and-else)
   4. [Context Managers](#context-managers)
9. [Advanced Features](#advanced-features)
   1. [List Comprehensions](#list-comprehensions)
   2. [Generators](#generators)
   3. [Iterators](#iterators)
   4. [Regular Expressions](#regular-expressions)
10. [Standard Library](#standard-library)
    1. [Collections](#collections)
    2. [DateTime](#datetime)
    3. [JSON](#json)
    4. [HTTP Requests](#http-requests)
11. [Popular Libraries](#popular-libraries)
    1. [NumPy](#numpy)
    2. [Pandas](#pandas)
    3. [Requests](#requests)
    4. [Flask/Django](#flaskdjango)
12. [Best Practices](#best-practices)
    1. [Code Style](#code-style)
    2. [Testing](#testing)
    3. [Performance](#performance)
    4. [Debugging](#debugging)

---

## Python Basics

### What is Python

**Python** is a high-level, interpreted programming language known for simplicity and readability.

**Key Features:**
- Easy to learn and read
- Cross-platform
- Extensive standard library
- Large ecosystem of packages
- Interpreted (no compilation needed)

**Common Uses:**
- Web development
- Data science and AI
- Automation and scripting
- Desktop applications

### Variables and Data Types

```python
# Variables (no declaration needed)
name = "Alice"
age = 30
height = 5.6
is_student = True

# Multiple assignment
x, y, z = 1, 2, 3
a = b = c = 0

# Data types
text = "Hello"             # str
number = 42                # int
decimal = 3.14             # float
flag = True                # bool
nothing = None             # NoneType

# Type checking
print(type(name))           # <class 'str'>
print(isinstance(age, int)) # True

# Type conversion
str_num = "123"
int_num = int(str_num)     # 123
float_num = float(str_num) # 123.0
str_bool = str(True)       # "True"
```

### Operators

```python
# Arithmetic operators
a, b = 10, 3
print(a + b)    # 13 (addition)
print(a - b)    # 7 (subtraction)
print(a * b)    # 30 (multiplication)
print(a / b)    # 3.333... (division)
print(a // b)   # 3 (floor division)
print(a % b)    # 1 (modulo)
print(a ** b)   # 1000 (exponentiation)

# Comparison operators
print(a > b)    # True
print(a == b)   # False
print(a != b)   # True
print(a <= b)   # False

# Logical operators
x, y = True, False
print(x and y)  # False
print(x or y)   # True
print(not x)    # False

# Assignment operators
a += 5    # a = a + 5
a -= 2    # a = a - 2
a *= 3    # a = a * 3

# Membership operators
numbers = [1, 2, 3, 4, 5]
print(3 in numbers)     # True
print(6 not in numbers) # True
```

### Input and Output

```python
# Output
print("Hello, World!")
print("Name:", name, "Age:", age)
print(f"Hello, {name}! You are {age} years old.")

# Formatted output
name = "Alice"
age = 30
print("Name: %s, Age: %d" % (name, age))
print("Name: {}, Age: {}".format(name, age))
print(f"Name: {name}, Age: {age}")

# Input
name = input("Enter your name: ")
age = int(input("Enter your age: "))

# Multiple outputs
print("Line 1", end="")  # No newline
print(" Line 2")         # Same line
print("A", "B", "C", sep="-")  # A-B-C
```

---

## Control Flow

### Conditional Statements

```python
# If statement
age = 18
if age >= 18:
    print("Adult")

# If-else
if age >= 18:
    print("Adult")
else:
    print("Minor")

# If-elif-else
score = 85
if score >= 90:
    grade = "A"
elif score >= 80:
    grade = "B"
elif score >= 70:
    grade = "C"
else:
    grade = "F"

# Ternary operator
status = "adult" if age >= 18 else "minor"

# Multiple conditions
if age >= 18 and score >= 70:
    print("Eligible")

if age < 13 or age > 65:
    print("Special rate")

# Truthiness
if name:           # True if not empty
    print("Name provided")

if not numbers:    # True if empty list
    print("No numbers")
```

### Loops

```python
# For loop with range
for i in range(5):        # 0 to 4
    print(i)

for i in range(1, 6):     # 1 to 5
    print(i)

for i in range(0, 10, 2): # 0, 2, 4, 6, 8
    print(i)

# For loop with lists
fruits = ["apple", "banana", "orange"]
for fruit in fruits:
    print(fruit)

# For loop with enumerate
for index, fruit in enumerate(fruits):
    print(f"{index}: {fruit}")

# For loop with dictionaries
person = {"name": "Alice", "age": 30}
for key in person:
    print(key, person[key])

for key, value in person.items():
    print(f"{key}: {value}")

# While loop
count = 0
while count < 5:
    print(count)
    count += 1

# Infinite loop with break
while True:
    user_input = input("Enter 'quit' to exit: ")
    if user_input == "quit":
        break
    print(f"You entered: {user_input}")
```

### Break and Continue

```python
# Break - exit loop completely
for i in range(10):
    if i == 5:
        break
    print(i)  # Prints 0, 1, 2, 3, 4

# Continue - skip current iteration
for i in range(5):
    if i == 2:
        continue
    print(i)  # Prints 0, 1, 3, 4

# Nested loops
for i in range(3):
    for j in range(3):
        if i == j == 1:
            break  # Only breaks inner loop
        print(f"({i}, {j})")

# Loop with else (runs if no break)
for i in range(5):
    if i == 10:  # Never true
        break
else:
    print("Loop completed normally")
```

### Match Statements

```python
# Match statement (Python 3.10+)
def handle_status(status):
    match status:
        case "pending":
            return "Waiting for approval"
        case "approved":
            return "Ready to proceed"
        case "rejected":
            return "Application denied"
        case _:  # Default case
            return "Unknown status"

# Match with values
def process_grade(grade):
    match grade:
        case 90 | 91 | 92 | 93 | 94 | 95 | 96 | 97 | 98 | 99 | 100:
            return "A"
        case x if 80 <= x <= 89:
            return "B"
        case x if x >= 70:
            return "C"
        case _:
            return "F"

# Match with patterns
def process_data(data):
    match data:
        case []:
            return "Empty list"
        case [x]:
            return f"Single item: {x}"
        case [x, y]:
            return f"Two items: {x}, {y}"
        case [x, *rest]:
            return f"First: {x}, Rest: {rest}"
```

---

## Data Structures

### Lists

```python
# Creating lists
numbers = [1, 2, 3, 4, 5]
mixed = [1, "hello", 3.14, True]
empty = []

# Accessing elements
print(numbers[0])      # 1 (first)
print(numbers[-1])     # 5 (last)
print(numbers[1:4])    # [2, 3, 4] (slice)
print(numbers[:3])     # [1, 2, 3] (first 3)
print(numbers[2:])     # [3, 4, 5] (from index 2)

# Modifying lists
numbers.append(6)           # Add to end
numbers.insert(0, 0)        # Insert at index
numbers.extend([7, 8])      # Add multiple
numbers.remove(3)           # Remove first occurrence
popped = numbers.pop()      # Remove and return last
numbers[0] = 10            # Change by index

# List methods
print(len(numbers))         # Length
print(numbers.count(2))     # Count occurrences
print(numbers.index(4))     # Find index
numbers.reverse()           # Reverse in place
numbers.sort()             # Sort in place
sorted_copy = sorted(numbers)  # Return sorted copy

# List operations
list1 = [1, 2, 3]
list2 = [4, 5, 6]
combined = list1 + list2    # [1, 2, 3, 4, 5, 6]
repeated = list1 * 3        # [1, 2, 3, 1, 2, 3, 1, 2, 3]

# Checking membership
print(3 in numbers)         # True
print(10 not in numbers)    # True
```

### Tuples

```python
# Creating tuples
coordinates = (10, 20)
single_item = (42,)        # Comma needed for single item
empty_tuple = ()
mixed_tuple = (1, "hello", 3.14)

# Accessing elements (same as lists)
print(coordinates[0])      # 10
print(coordinates[-1])     # 20

# Tuple unpacking
x, y = coordinates
print(f"X: {x}, Y: {y}")

# Multiple assignment
a, b, c = (1, 2, 3)
first, *middle, last = (1, 2, 3, 4, 5)  # first=1, middle=[2,3,4], last=5

# Tuple methods
numbers = (1, 2, 3, 2, 4)
print(numbers.count(2))    # 2
print(numbers.index(3))    # 2

# Tuples are immutable
# coordinates[0] = 15      # Error!

# But can contain mutable objects
tuple_with_list = ([1, 2], [3, 4])
tuple_with_list[0].append(3)  # OK: [1, 2, 3]
```

### Dictionaries

```python
# Creating dictionaries
person = {"name": "Alice", "age": 30, "city": "New York"}
empty_dict = {}
dict_from_keys = dict.fromkeys(["a", "b", "c"], 0)  # {"a": 0, "b": 0, "c": 0}

# Accessing elements
print(person["name"])          # Alice
print(person.get("age"))       # 30
print(person.get("height", 0)) # 0 (default if not found)

# Modifying dictionaries
person["email"] = "alice@email.com"  # Add new key
person["age"] = 31                   # Update existing
del person["city"]                   # Delete key
removed = person.pop("email")        # Remove and return value

# Dictionary methods
print(person.keys())           # dict_keys(['name', 'age'])
print(person.values())         # dict_values(['Alice', 31])
print(person.items())          # dict_items([('name', 'Alice'), ('age', 31)])

# Iterating dictionaries
for key in person:
    print(key, person[key])

for key, value in person.items():
    print(f"{key}: {value}")

# Dictionary comprehension
squares = {x: x**2 for x in range(5)}  # {0: 0, 1: 1, 2: 4, 3: 9, 4: 16}

# Merging dictionaries
dict1 = {"a": 1, "b": 2}
dict2 = {"c": 3, "d": 4}
merged = {**dict1, **dict2}    # {"a": 1, "b": 2, "c": 3, "d": 4}
dict1.update(dict2)            # Modify dict1 in place
```

### Sets

```python
# Creating sets
numbers = {1, 2, 3, 4, 5}
empty_set = set()              # {} creates empty dict, not set
from_list = set([1, 2, 2, 3])  # {1, 2, 3} - duplicates removed

# Set operations
set1 = {1, 2, 3, 4}
set2 = {3, 4, 5, 6}

print(set1 | set2)    # {1, 2, 3, 4, 5, 6} (union)
print(set1 & set2)    # {3, 4} (intersection)
print(set1 - set2)    # {1, 2} (difference)
print(set1 ^ set2)    # {1, 2, 5, 6} (symmetric difference)

# Set methods
numbers.add(6)              # Add single element
numbers.update([7, 8, 9])   # Add multiple elements
numbers.remove(5)           # Remove (raises error if not found)
numbers.discard(10)         # Remove (no error if not found)
popped = numbers.pop()      # Remove and return arbitrary element

# Set comparisons
print(set1.issubset(set2))     # False
print(set1.issuperset(set2))   # False
print(set1.isdisjoint(set2))   # False (they share elements)

# Set comprehension
squares = {x**2 for x in range(5)}  # {0, 1, 4, 9, 16}
```

---

## Functions

### Basic Functions

```python
# Simple function
def greet():
    print("Hello, World!")

greet()  # Call function

# Function with parameters
def greet_person(name):
    print(f"Hello, {name}!")

greet_person("Alice")

# Function with return value
def add(a, b):
    return a + b

result = add(5, 3)  # 8

# Multiple return values
def get_name_age():
    return "Alice", 30

name, age = get_name_age()

# Function with docstring
def calculate_area(radius):
    """Calculate the area of a circle."""
    return 3.14159 * radius ** 2

print(calculate_area.__doc__)  # Print docstring
```

### Parameters and Arguments

```python
# Default parameters
def greet(name, greeting="Hello"):
    return f"{greeting}, {name}!"

print(greet("Alice"))           # Hello, Alice!
print(greet("Bob", "Hi"))       # Hi, Bob!

# Keyword arguments
def create_user(name, age, email, active=True):
    return {"name": name, "age": age, "email": email, "active": active}

user = create_user(name="Alice", email="alice@email.com", age=30)

# Variable-length arguments (*args)
def sum_all(*numbers):
    return sum(numbers)

print(sum_all(1, 2, 3, 4, 5))  # 15

# Keyword variable-length arguments (**kwargs)
def create_person(**kwargs):
    return kwargs

person = create_person(name="Alice", age=30, city="NYC")

# Combined parameters
def process_data(required_param, *args, **kwargs):
    print(f"Required: {required_param}")
    print(f"Args: {args}")
    print(f"Kwargs: {kwargs}")

process_data("test", 1, 2, 3, name="Alice", age=30)

# Positional-only and keyword-only parameters (Python 3.8+)
def func(pos_only, /, standard, *, kw_only):
    print(pos_only, standard, kw_only)

func(1, standard=2, kw_only=3)  # Valid
# func(pos_only=1, standard=2, kw_only=3)  # Error
```

### Lambda Functions

```python
# Basic lambda
square = lambda x: x ** 2
print(square(5))  # 25

# Lambda with multiple parameters
add = lambda x, y: x + y
print(add(3, 4))  # 7

# Lambda in higher-order functions
numbers = [1, 2, 3, 4, 5]
squared = list(map(lambda x: x**2, numbers))      # [1, 4, 9, 16, 25]
evens = list(filter(lambda x: x % 2 == 0, numbers))  # [2, 4]

# Lambda with conditional
max_val = lambda x, y: x if x > y else y
print(max_val(10, 5))  # 10

# Sorting with lambda
students = [("Alice", 85), ("Bob", 90), ("Charlie", 78)]
students.sort(key=lambda student: student[1])  # Sort by grade
print(students)  # [('Charlie', 78), ('Alice', 85), ('Bob', 90)]

# Lambda limitations (single expression only)
# Can't use statements like print, assignments, etc.
```

### Decorators

```python
# Simple decorator
def my_decorator(func):
    def wrapper():
        print("Before function")
        func()
        print("After function")
    return wrapper

@my_decorator
def say_hello():
    print("Hello!")

say_hello()
# Output:
# Before function
# Hello!
# After function

# Decorator with arguments
def repeat(times):
    def decorator(func):
        def wrapper(*args, **kwargs):
            for _ in range(times):
                result = func(*args, **kwargs)
            return result
        return wrapper
    return decorator

@repeat(3)
def greet(name):
    print(f"Hello, {name}!")

greet("Alice")  # Prints 3 times

# Built-in decorators
class MyClass:
    def __init__(self, value):
        self._value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, new_value):
        if new_value < 0:
            raise ValueError("Value must be positive")
        self._value = new_value

    @staticmethod
    def utility_function():
        return "This is a utility function"

    @classmethod
    def create_default(cls):
        return cls(0)

# Timer decorator
import time
import functools

def timer(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print(f"{func.__name__} took {end - start:.4f} seconds")
        return result
    return wrapper

@timer
def slow_function():
    time.sleep(1)
    return "Done"
```

---

## Object-Oriented Programming

### Classes and Objects

```python
# Basic class
class Person:
    def __init__(self, name, age):
        self.name = name
        self.age = age

    def greet(self):
        return f"Hello, I'm {self.name}"

    def have_birthday(self):
        self.age += 1

# Creating objects
person1 = Person("Alice", 30)
person2 = Person("Bob", 25)

print(person1.greet())  # Hello, I'm Alice
person1.have_birthday()
print(person1.age)      # 31

# Class variables vs instance variables
class Car:
    wheels = 4  # Class variable (shared by all instances)

    def __init__(self, brand, model):
        self.brand = brand    # Instance variable
        self.model = model    # Instance variable

car1 = Car("Toyota", "Camry")
car2 = Car("Honda", "Civic")

print(car1.wheels)  # 4
print(Car.wheels)   # 4

# Private attributes (convention: prefix with _)
class BankAccount:
    def __init__(self, balance):
        self._balance = balance  # "Private" attribute

    def deposit(self, amount):
        if amount > 0:
            self._balance += amount

    def get_balance(self):
        return self._balance

account = BankAccount(1000)
account.deposit(500)
print(account.get_balance())  # 1500
```

### Inheritance

```python
# Basic inheritance
class Animal:
    def __init__(self, name, species):
        self.name = name
        self.species = species

    def make_sound(self):
        return f"{self.name} makes a sound"

    def sleep(self):
        return f"{self.name} is sleeping"

class Dog(Animal):
    def __init__(self, name, breed):
        super().__init__(name, "Canine")  # Call parent constructor
        self.breed = breed

    def make_sound(self):  # Override parent method
        return f"{self.name} barks: Woof!"

    def fetch(self):  # New method specific to Dog
        return f"{self.name} fetches the ball"

class Cat(Animal):
    def __init__(self, name, indoor=True):
        super().__init__(name, "Feline")
        self.indoor = indoor

    def make_sound(self):
        return f"{self.name} meows: Meow!"

# Using inheritance
dog = Dog("Buddy", "Golden Retriever")
cat = Cat("Whiskers")

print(dog.make_sound())  # Buddy barks: Woof!
print(dog.sleep())       # Buddy is sleeping (inherited)
print(dog.fetch())       # Buddy fetches the ball

# Multiple inheritance
class Swimmer:
    def swim(self):
        return "Swimming"

class Flyer:
    def fly(self):
        return "Flying"

class Duck(Animal, Swimmer, Flyer):
    def __init__(self, name):
        super().__init__(name, "Waterfowl")

duck = Duck("Donald")
print(duck.swim())  # Swimming
print(duck.fly())   # Flying

# Method Resolution Order (MRO)
print(Duck.__mro__)  # Shows inheritance order
```

### Polymorphism

```python
# Polymorphism through inheritance
class Shape:
    def area(self):
        pass

    def perimeter(self):
        pass

class Rectangle(Shape):
    def __init__(self, width, height):
        self.width = width
        self.height = height

    def area(self):
        return self.width * self.height

    def perimeter(self):
        return 2 * (self.width + self.height)

class Circle(Shape):
    def __init__(self, radius):
        self.radius = radius

    def area(self):
        return 3.14159 * self.radius ** 2

    def perimeter(self):
        return 2 * 3.14159 * self.radius

# Polymorphic behavior
shapes = [Rectangle(4, 5), Circle(3), Rectangle(2, 8)]

for shape in shapes:
    print(f"Area: {shape.area():.2f}")  # Calls appropriate method

# Duck typing (if it walks like a duck...)
class FileWriter:
    def write(self, data):
        with open("file.txt", "w") as f:
            f.write(data)

class ConsoleWriter:
    def write(self, data):
        print(data)

def save_data(writer, data):
    writer.write(data)  # Works with any object that has write method

save_data(FileWriter(), "Hello, File!")
save_data(ConsoleWriter(), "Hello, Console!")
```

### Special Methods

```python
# Magic methods (dunder methods)
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __str__(self):  # Human-readable string
        return f"Point({self.x}, {self.y})"

    def __repr__(self):  # Developer-friendly representation
        return f"Point(x={self.x}, y={self.y})"

    def __add__(self, other):  # Addition operator
        return Point(self.x + other.x, self.y + other.y)

    def __eq__(self, other):  # Equality operator
        return self.x == other.x and self.y == other.y

    def __lt__(self, other):  # Less than operator
        return (self.x**2 + self.y**2) < (other.x**2 + other.y**2)

    def __len__(self):  # Length (distance from origin)
        return int((self.x**2 + self.y**2)**0.5)

    def __getitem__(self, index):  # Indexing
        if index == 0:
            return self.x
        elif index == 1:
            return self.y
        else:
            raise IndexError("Point index out of range")

# Using special methods
p1 = Point(3, 4)
p2 = Point(1, 2)

print(str(p1))      # Point(3, 4)
print(repr(p1))     # Point(x=3, y=4)
print(p1 + p2)      # Point(4, 6)
print(p1 == p2)     # False
print(p1 > p2)      # True
print(len(p1))      # 5
print(p1[0])        # 3

# Context manager
class FileManager:
    def __init__(self, filename, mode):
        self.filename = filename
        self.mode = mode
        self.file = None

    def __enter__(self):
        print(f"Opening {self.filename}")
        self.file = open(self.filename, self.mode)
        return self.file

    def __exit__(self, exc_type, exc_val, exc_tb):
        print(f"Closing {self.filename}")
        if self.file:
            self.file.close()

# Using context manager
with FileManager("test.txt", "w") as f:
    f.write("Hello, World!")
```

---

## Modules and Packages

### Importing Modules

```python
# Different import styles
import math
import datetime as dt
from random import randint, choice
from collections import *

# Using imported modules
print(math.pi)              # 3.141592653589793
print(math.sqrt(16))        # 4.0

now = dt.datetime.now()
print(now)

random_num = randint(1, 10)
random_item = choice(['a', 'b', 'c'])

# Standard library modules
import os
import sys
import json
import re

# Getting module information
print(math.__name__)        # math
print(dir(math))           # List all attributes
help(math.sqrt)            # Documentation

# Conditional imports
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

if HAS_NUMPY:
    arr = np.array([1, 2, 3])
```

### Creating Modules

```python
# mymodule.py
"""
A simple module for mathematical operations.
"""

PI = 3.14159

def add(a, b):
    """Add two numbers."""
    return a + b

def multiply(a, b):
    """Multiply two numbers."""
    return a * b

class Calculator:
    """A simple calculator class."""

    def __init__(self):
        self.history = []

    def add(self, a, b):
        result = a + b
        self.history.append(f"{a} + {b} = {result}")
        return result

# Code that runs only when module is executed directly
if __name__ == "__main__":
    print("Module is being run directly")
    calc = Calculator()
    print(calc.add(5, 3))

# Using the module (in another file)
# import mymodule
# from mymodule import Calculator, PI

# result = mymodule.add(5, 3)
# calc = Calculator()
```

### Packages

```python
# Package structure:
# mypackage/
#   __init__.py
#   module1.py
#   module2.py
#   subpackage/
#     __init__.py
#     submodule.py

# mypackage/__init__.py
"""
My Package - A collection of useful modules.
"""

__version__ = "1.0.0"
__author__ = "Your Name"

# Import commonly used items
from .module1 import function1
from .module2 import Class2

# Package-level function
def package_info():
    return f"Package version: {__version__}"

# mypackage/module1.py
def function1():
    return "Hello from module1"

def helper_function():
    return "Helper function"

# mypackage/module2.py
class Class2:
    def method(self):
        return "Method from Class2"

# Using the package
# from mypackage import function1, Class2
# import mypackage.module1 as mod1
# from mypackage.subpackage import submodule
```

### Virtual Environments

```bash
# Creating virtual environment
python -m venv myenv

# Activating (Windows)
myenv\Scripts\activate

# Activating (macOS/Linux)
source myenv/bin/activate

# Installing packages
pip install requests numpy pandas

# Creating requirements file
pip freeze > requirements.txt

# Installing from requirements
pip install -r requirements.txt

# Deactivating
deactivate
```

```python
# Check if in virtual environment
import sys
print(sys.prefix)  # Shows virtual env path if active

# Environment variables
import os
print(os.environ.get('VIRTUAL_ENV'))  # Virtual env path
```

---

## File Handling

### Reading Files

```python
# Reading entire file
with open("file.txt", "r") as f:
    content = f.read()
    print(content)

# Reading line by line
with open("file.txt", "r") as f:
    for line in f:
        print(line.strip())  # Remove newline characters

# Reading all lines into list
with open("file.txt", "r") as f:
    lines = f.readlines()

# Reading specific number of characters
with open("file.txt", "r") as f:
    chunk = f.read(100)  # Read first 100 characters

# Reading with encoding
with open("file.txt", "r", encoding="utf-8") as f:
    content = f.read()

# Safe file reading
import os

filename = "data.txt"
if os.path.exists(filename):
    with open(filename, "r") as f:
        content = f.read()
else:
    print("File not found")

# Reading CSV
import csv

with open("data.csv", "r") as f:
    csv_reader = csv.reader(f)
    for row in csv_reader:
        print(row)

# Reading JSON
import json

with open("data.json", "r") as f:
    data = json.load(f)
    print(data)
```

### Writing Files

```python
# Writing to file (overwrites existing)
with open("output.txt", "w") as f:
    f.write("Hello, World!\n")
    f.write("Second line\n")

# Appending to file
with open("output.txt", "a") as f:
    f.write("Appended line\n")

# Writing multiple lines
lines = ["Line 1\n", "Line 2\n", "Line 3\n"]
with open("output.txt", "w") as f:
    f.writelines(lines)

# Writing with encoding
with open("output.txt", "w", encoding="utf-8") as f:
    f.write("Unicode content: café, naïve, résumé")

# Writing CSV
import csv

data = [
    ["Name", "Age", "City"],
    ["Alice", 30, "New York"],
    ["Bob", 25, "London"]
]

with open("output.csv", "w", newline="") as f:
    csv_writer = csv.writer(f)
    csv_writer.writerows(data)

# Writing JSON
import json

data = {"name": "Alice", "age": 30, "city": "New York"}

with open("output.json", "w") as f:
    json.dump(data, f, indent=2)

# Binary file operations
with open("image.jpg", "rb") as f:
    data = f.read()

with open("copy.jpg", "wb") as f:
    f.write(data)
```

### File Context Managers

```python
# Context manager ensures file is closed
with open("file.txt", "r") as f:
    content = f.read()
    # File automatically closed after this block

# Multiple files
with open("input.txt", "r") as infile, open("output.txt", "w") as outfile:
    data = infile.read()
    processed_data = data.upper()
    outfile.write(processed_data)

# Custom context manager for files
class FileManager:
    def __init__(self, filename, mode):
        self.filename = filename
        self.mode = mode
        self.file = None

    def __enter__(self):
        self.file = open(self.filename, self.mode)
        return self.file

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()

with FileManager("test.txt", "w") as f:
    f.write("Context manager example")

# Exception handling with files
try:
    with open("nonexistent.txt", "r") as f:
        content = f.read()
except FileNotFoundError:
    print("File not found")
except PermissionError:
    print("Permission denied")
except IOError:
    print("IO error occurred")
```

### Working with Paths

```python
import os
import pathlib
from pathlib import Path

# Using os.path
current_dir = os.getcwd()
file_path = os.path.join(current_dir, "data", "file.txt")
directory = os.path.dirname(file_path)
filename = os.path.basename(file_path)
name, extension = os.path.splitext(filename)

print(f"Directory: {directory}")
print(f"Filename: {filename}")
print(f"Name: {name}, Extension: {extension}")

# Path existence and properties
if os.path.exists(file_path):
    print("File exists")
    print(f"Size: {os.path.getsize(file_path)} bytes")
    print(f"Is file: {os.path.isfile(file_path)}")
    print(f"Is directory: {os.path.isdir(file_path)}")

# Using pathlib (modern approach)
path = Path("data/file.txt")
print(f"Parent: {path.parent}")
print(f"Name: {path.name}")
print(f"Stem: {path.stem}")
print(f"Suffix: {path.suffix}")

# Creating directories
os.makedirs("new/nested/directory", exist_ok=True)
Path("another/directory").mkdir(parents=True, exist_ok=True)

# Listing directory contents
for item in os.listdir("."):
    print(item)

# Using pathlib for directory listing
for item in Path(".").iterdir():
    if item.is_file():
        print(f"File: {item}")
    elif item.is_dir():
        print(f"Directory: {item}")

# Finding files with patterns
import glob

txt_files = glob.glob("*.txt")
all_py_files = glob.glob("**/*.py", recursive=True)

# Using pathlib for pattern matching
for py_file in Path(".").rglob("*.py"):
    print(py_file)
```

---

## Error Handling

### Try-Except

```python
# Basic try-except
try:
    result = 10 / 0
except ZeroDivisionError:
    print("Cannot divide by zero!")

# Multiple exceptions
try:
    number = int(input("Enter a number: "))
    result = 10 / number
    print(f"Result: {result}")
except ValueError:
    print("Invalid input! Please enter a number.")
except ZeroDivisionError:
    print("Cannot divide by zero!")

# Catching multiple exceptions together
try:
    # Some risky operation
    pass
except (ValueError, TypeError, KeyError) as e:
    print(f"Error occurred: {e}")

# Catching all exceptions
try:
    # Risky operation
    pass
except Exception as e:
    print(f"An error occurred: {e}")

# Exception hierarchy
try:
    # Some operation
    pass
except FileNotFoundError:
    print("File not found")
except PermissionError:
    print("Permission denied")
except OSError:  # Parent class of above exceptions
    print("OS error")
except Exception:  # Catches all other exceptions
    print("Unknown error")

# Getting exception details
import traceback

try:
    result = 1 / 0
except Exception as e:
    print(f"Exception type: {type(e).__name__}")
    print(f"Exception message: {str(e)}")
    print("Full traceback:")
    traceback.print_exc()
```

### Custom Exceptions

```python
# Custom exception class
class CustomError(Exception):
    """Custom exception for specific errors."""
    pass

class ValidationError(Exception):
    """Raised when validation fails."""
    def __init__(self, message, field=None):
        super().__init__(message)
        self.field = field

class InsufficientFundsError(Exception):
    """Raised when account has insufficient funds."""
    def __init__(self, balance, amount):
        self.balance = balance
        self.amount = amount
        super().__init__(f"Insufficient funds. Balance: {balance}, Requested: {amount}")

# Using custom exceptions
def validate_age(age):
    if not isinstance(age, int):
        raise ValidationError("Age must be an integer", "age")
    if age < 0:
        raise ValidationError("Age cannot be negative", "age")
    if age > 150:
        raise ValidationError("Age seems unrealistic", "age")

def withdraw(balance, amount):
    if amount > balance:
        raise InsufficientFundsError(balance, amount)
    return balance - amount

# Handling custom exceptions
try:
    validate_age(-5)
except ValidationError as e:
    print(f"Validation error in field '{e.field}': {e}")

try:
    new_balance = withdraw(100, 150)
except InsufficientFundsError as e:
    print(f"Cannot withdraw: {e}")
    print(f"Available: {e.balance}, Requested: {e.amount}")

# Re-raising exceptions
def process_data(data):
    try:
        # Process data
        result = risky_operation(data)
        return result
    except ValueError as e:
        print(f"Logging error: {e}")
        raise  # Re-raise the same exception
```

### Finally and Else

```python
# finally block (always executes)
def read_file(filename):
    file = None
    try:
        file = open(filename, "r")
        content = file.read()
        return content
    except FileNotFoundError:
        print("File not found")
        return None
    except PermissionError:
        print("Permission denied")
        return None
    finally:
        if file:
            file.close()
            print("File closed")

# else block (executes if no exception)
def divide_numbers(a, b):
    try:
        result = a / b
    except ZeroDivisionError:
        print("Cannot divide by zero")
        return None
    else:
        print("Division successful")
        return result
    finally:
        print("Division operation completed")

# Practical example
def safe_operation():
    try:
        # Risky operation
        data = get_data()
        process_data(data)
    except DataError:
        print("Data error occurred")
        handle_data_error()
    except NetworkError:
        print("Network error occurred")
        handle_network_error()
    else:
        print("Operation completed successfully")
        cleanup_success()
    finally:
        print("Cleaning up resources")
        cleanup_resources()

# Nested try-except
def complex_operation():
    try:
        # Outer operation
        outer_data = get_outer_data()

        try:
            # Inner operation
            inner_data = process_inner_data(outer_data)
            return inner_data
        except InnerError:
            print("Inner operation failed")
            return fallback_data()
    except OuterError:
        print("Outer operation failed")
        return None
    finally:
        print("Complex operation finished")
```

### Context Managers

```python
# Built-in context managers
with open("file.txt", "r") as f:
    content = f.read()
# File automatically closed

# Multiple context managers
with open("input.txt", "r") as infile, open("output.txt", "w") as outfile:
    data = infile.read()
    outfile.write(data.upper())

# Custom context manager (class-based)
class DatabaseConnection:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.connection = None

    def __enter__(self):
        print(f"Connecting to {self.host}:{self.port}")
        # Simulate connection
        self.connection = f"Connected to {self.host}:{self.port}"
        return self.connection

    def __exit__(self, exc_type, exc_val, exc_tb):
        print("Closing database connection")
        self.connection = None
        # Return False to propagate exceptions
        return False

with DatabaseConnection("localhost", 5432) as conn:
    print(f"Using connection: {conn}")
    # Connection automatically closed after this block

# Context manager using contextlib
from contextlib import contextmanager

@contextmanager
def temporary_file(filename):
    print(f"Creating temporary file: {filename}")
    try:
        with open(filename, "w") as f:
            yield f
    finally:
        import os
        if os.path.exists(filename):
            os.remove(filename)
            print(f"Temporary file {filename} deleted")

with temporary_file("temp.txt") as f:
    f.write("Temporary content")

# Suppressing exceptions
from contextlib import suppress

with suppress(FileNotFoundError):
    with open("nonexistent.txt", "r") as f:
        content = f.read()
# No exception raised if file doesn't exist

# Multiple exception types
with suppress(ValueError, TypeError, KeyError):
    risky_operation()
```

---

## Advanced Features

### List Comprehensions

```python
# Basic list comprehension
numbers = [1, 2, 3, 4, 5]
squares = [x**2 for x in numbers]  # [1, 4, 9, 16, 25]

# With condition
evens = [x for x in numbers if x % 2 == 0]  # [2, 4]

# Transform and filter
words = ["hello", "world", "python", "programming"]
long_upper = [word.upper() for word in words if len(word) > 5]

# Nested loops
matrix = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
flattened = [num for row in matrix for num in row]  # [1, 2, 3, 4, 5, 6, 7, 8, 9]

# Conditional expression
numbers = [-2, -1, 0, 1, 2]
abs_numbers = [x if x >= 0 else -x for x in numbers]  # [2, 1, 0, 1, 2]

# Dictionary comprehension
word_lengths = {word: len(word) for word in words}
squared_dict = {x: x**2 for x in range(5)}  # {0: 0, 1: 1, 2: 4, 3: 9, 4: 16}

# Set comprehension
unique_lengths = {len(word) for word in words}

# Generator expression (memory efficient)
squares_gen = (x**2 for x in range(1000000))  # Doesn't create full list in memory

# Nested comprehensions
matrix = [[j for j in range(3)] for i in range(3)]  # [[0, 1, 2], [0, 1, 2], [0, 1, 2]]

# Complex example
students = [
    {"name": "Alice", "grades": [85, 90, 78]},
    {"name": "Bob", "grades": [92, 88, 84]},
    {"name": "Charlie", "grades": [76, 80, 85]}
]

# Get names of students with average grade > 80
good_students = [
    student["name"]
    for student in students
    if sum(student["grades"]) / len(student["grades"]) > 80
]
```

### Generators

```python
# Generator function
def countdown(n):
    while n > 0:
        yield n
        n -= 1

# Using generator
for num in countdown(5):
    print(num)  # 5, 4, 3, 2, 1

# Generator saves memory
def fibonacci():
    a, b = 0, 1
    while True:
        yield a
        a, b = b, a + b

# Use with next()
fib = fibonacci()
print(next(fib))  # 0
print(next(fib))  # 1
print(next(fib))  # 1

# Generator with send()
def accumulator():
    total = 0
    while True:
        value = yield total
        if value is not None:
            total += value

acc = accumulator()
next(acc)  # Prime the generator
print(acc.send(10))  # 10
print(acc.send(5))   # 15
print(acc.send(3))   # 18

# Generator pipeline
def read_lines(filename):
    with open(filename) as f:
        for line in f:
            yield line.strip()

def filter_lines(lines, keyword):
    for line in lines:
        if keyword in line:
            yield line

def process_lines(lines):
    for line in lines:
        yield line.upper()

# Chain generators
lines = read_lines("data.txt")
filtered = filter_lines(lines, "python")
processed = process_lines(filtered)

for line in processed:
    print(line)

# Generator with exception handling
def safe_division():
    while True:
        try:
            x, y = yield
            yield x / y
        except ZeroDivisionError:
            yield "Cannot divide by zero"

div = safe_division()
next(div)  # Prime
print(div.send((10, 2)))  # 5.0
next(div)
print(div.send((10, 0)))  # Cannot divide by zero
```

### Iterators

```python
# Creating iterator from iterable
numbers = [1, 2, 3, 4, 5]
num_iter = iter(numbers)

print(next(num_iter))  # 1
print(next(num_iter))  # 2

# Custom iterator class
class Counter:
    def __init__(self, start, end):
        self.current = start
        self.end = end

    def __iter__(self):
        return self

    def __next__(self):
        if self.current >= self.end:
            raise StopIteration
        else:
            self.current += 1
            return self.current - 1

# Using custom iterator
for num in Counter(0, 5):
    print(num)  # 0, 1, 2, 3, 4

# Iterator protocol with class
class Fibonacci:
    def __init__(self, max_count):
        self.max_count = max_count
        self.count = 0
        self.a, self.b = 0, 1

    def __iter__(self):
        return self

    def __next__(self):
        if self.count >= self.max_count:
            raise StopIteration

        if self.count == 0:
            self.count += 1
            return self.a
        elif self.count == 1:
            self.count += 1
            return self.b
        else:
            self.a, self.b = self.b, self.a + self.b
            self.count += 1
            return self.b

fib = Fibonacci(10)
for num in fib:
    print(num)

# Built-in iterators
# range is an iterator
for i in range(5):
    print(i)

# enumerate creates iterator of (index, value) pairs
words = ["apple", "banana", "cherry"]
for index, word in enumerate(words):
    print(f"{index}: {word}")

# zip combines multiple iterables
names = ["Alice", "Bob", "Charlie"]
ages = [25, 30, 35]
for name, age in zip(names, ages):
    print(f"{name} is {age} years old")

# itertools module
import itertools

# Infinite iterators
count_iter = itertools.count(10, 2)  # 10, 12, 14, 16, ...
cycle_iter = itertools.cycle(['A', 'B', 'C'])  # A, B, C, A, B, C, ...

# Finite iterators
repeat_iter = itertools.repeat('Hello', 3)  # Hello, Hello, Hello

# Combinatorial iterators
perms = itertools.permutations(['A', 'B', 'C'], 2)  # AB, AC, BA, BC, CA, CB
combs = itertools.combinations(['A', 'B', 'C'], 2)  # AB, AC, BC

for perm in perms:
    print(perm)
```

### Regular Expressions

```python
import re

# Basic pattern matching
text = "The phone number is 123-456-7890"
pattern = r"\d{3}-\d{3}-\d{4}"
match = re.search(pattern, text)

if match:
    print(f"Found: {match.group()}")  # Found: 123-456-7890

# Common patterns
email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
phone_pattern = r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
url_pattern = r"https?://[^\s]+"

# Finding all matches
text = "Contact us at john@email.com or jane@company.org"
emails = re.findall(email_pattern, text)
print(emails)  # ['john@email.com', 'jane@company.org']

# Groups and capturing
date_pattern = r"(\d{4})-(\d{2})-(\d{2})"
text = "Today is 2024-03-15"
match = re.search(date_pattern, text)

if match:
    year, month, day = match.groups()
    print(f"Year: {year}, Month: {month}, Day: {day}")

# Named groups
named_pattern = r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
match = re.search(named_pattern, text)

if match:
    print(match.groupdict())  # {'year': '2024', 'month': '03', 'day': '15'}

# Substitution
text = "Hello world! This is a test."
new_text = re.sub(r"world", "Python", text)
print(new_text)  # Hello Python! This is a test.

# Case-insensitive matching
pattern = re.compile(r"python", re.IGNORECASE)
text = "I love Python programming"
matches = pattern.findall(text)  # ['Python']

# Multiline and dotall flags
text = """Line 1
Line 2
Line 3"""

# Match across lines
pattern = re.compile(r"Line.*Line", re.DOTALL)
match = pattern.search(text)

# Splitting
text = "apple,banana;orange:grape"
fruits = re.split(r"[,;:]", text)
print(fruits)  # ['apple', 'banana', 'orange', 'grape']

# Validation function
def validate_email(email):
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))

print(validate_email("user@example.com"))  # True
print(validate_email("invalid.email"))     # False

# Common regex patterns
patterns = {
    "phone": r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "url": r"https?://[^\s]+",
    "ip_address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "date": r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"
}

# Extract information
def extract_info(text):
    results = {}
    for name, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            results[name] = matches
    return results

sample_text = """
Contact John at john@email.com or call 555-123-4567.
Visit our website at https://example.com.
IP address: 192.168.1.1
"""

info = extract_info(sample_text)
for key, values in info.items():
    print(f"{key}: {values}")
```

---

## Standard Library

### Collections

```python
from collections import defaultdict, Counter, deque, namedtuple, OrderedDict

# defaultdict - provides default values for missing keys
dd = defaultdict(list)
dd['fruits'].append('apple')
dd['fruits'].append('banana')
print(dd['fruits'])  # ['apple', 'banana']
print(dd['vegetables'])  # [] (empty list, not KeyError)

# Counter - counts occurrences
text = "hello world"
counter = Counter(text)
print(counter)  # Counter({'l': 3, 'o': 2, 'h': 1, 'e': 1, ' ': 1, 'w': 1, 'r': 1, 'd': 1})
print(counter.most_common(3))  # [('l', 3), ('o', 2), ('h', 1)]

words = ['apple', 'banana', 'apple', 'cherry', 'banana', 'apple']
word_count = Counter(words)
print(word_count['apple'])  # 3

# deque - double-ended queue
dq = deque([1, 2, 3])
dq.appendleft(0)    # deque([0, 1, 2, 3])
dq.append(4)        # deque([0, 1, 2, 3, 4])
left = dq.popleft() # 0, deque([1, 2, 3, 4])
right = dq.pop()    # 4, deque([1, 2, 3])

# Rotating deque
dq.rotate(1)  # deque([3, 1, 2])
dq.rotate(-1) # deque([1, 2, 3])

# namedtuple - immutable objects with named fields
Point = namedtuple('Point', ['x', 'y'])
p = Point(10, 20)
print(p.x, p.y)  # 10 20
print(p[0], p[1])  # 10 20

Person = namedtuple('Person', 'name age city')
alice = Person('Alice', 30, 'New York')
print(alice.name)  # Alice

# OrderedDict - maintains insertion order (Python 3.7+ dict does this too)
od = OrderedDict()
od['first'] = 1
od['second'] = 2
od['third'] = 3

for key, value in od.items():
    print(f"{key}: {value}")

# ChainMap - combines multiple dicts
from collections import ChainMap

defaults = {'theme': 'dark', 'language': 'en'}
user_settings = {'theme': 'light'}
combined = ChainMap(user_settings, defaults)

print(combined['theme'])    # 'light' (from user_settings)
print(combined['language']) # 'en' (from defaults)
```

### DateTime

```python
from datetime import datetime, date, time, timedelta, timezone
import calendar

# Current date and time
now = datetime.now()
today = date.today()
current_time = datetime.now().time()

print(f"Now: {now}")
print(f"Today: {today}")
print(f"Time: {current_time}")

# Creating specific dates
specific_date = date(2024, 3, 15)
specific_datetime = datetime(2024, 3, 15, 14, 30, 45)
specific_time = time(14, 30, 45)

# Formatting dates
print(now.strftime("%Y-%m-%d %H:%M:%S"))  # 2024-03-15 14:30:45
print(now.strftime("%B %d, %Y"))          # March 15, 2024
print(now.strftime("%A, %b %d"))          # Friday, Mar 15

# Parsing dates from strings
date_string = "2024-03-15 14:30:45"
parsed_date = datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")

# Date arithmetic with timedelta
tomorrow = today + timedelta(days=1)
next_week = today + timedelta(weeks=1)
past_hour = now - timedelta(hours=1)

print(f"Tomorrow: {tomorrow}")
print(f"Next week: {next_week}")

# Date differences
birth_date = date(1990, 5, 15)
age_in_days = today - birth_date
print(f"Age in days: {age_in_days.days}")

# Working with timezones
from datetime import timezone

utc_now = datetime.now(timezone.utc)
print(f"UTC time: {utc_now}")

# Calendar operations
print(f"Is 2024 a leap year? {calendar.isleap(2024)}")
print(f"Days in March 2024: {calendar.monthrange(2024, 3)[1]}")

# First day of week for March 2024
print(calendar.month(2024, 3))

# Date validation
def is_valid_date(year, month, day):
    try:
        date(year, month, day)
        return True
    except ValueError:
        return False

print(is_valid_date(2024, 2, 29))  # True (leap year)
print(is_valid_date(2023, 2, 29))  # False

# Working with timestamps
timestamp = now.timestamp()
from_timestamp = datetime.fromtimestamp(timestamp)

print(f"Timestamp: {timestamp}")
print(f"From timestamp: {from_timestamp}")

# ISO format
iso_string = now.isoformat()
from_iso = datetime.fromisoformat(iso_string)

print(f"ISO format: {iso_string}")
```

### JSON

```python
import json

# Python to JSON
data = {
    "name": "Alice",
    "age": 30,
    "city": "New York",
    "hobbies": ["reading", "swimming"],
    "married": False,
    "spouse": None
}

# Convert to JSON string
json_string = json.dumps(data)
print(json_string)

# Pretty print JSON
pretty_json = json.dumps(data, indent=2)
print(pretty_json)

# JSON to Python
parsed_data = json.loads(json_string)
print(type(parsed_data))  # <class 'dict'>

# Writing to file
with open("data.json", "w") as f:
    json.dump(data, f, indent=2)

# Reading from file
with open("data.json", "r") as f:
    loaded_data = json.load(f)

# Custom JSON encoder
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

data_with_date = {
    "name": "Alice",
    "created": datetime.now()
}

json_with_date = json.dumps(data_with_date, cls=DateTimeEncoder)

# Handling different data types
complex_data = {
    "numbers": [1, 2, 3],
    "nested": {"key": "value"},
    "boolean": True,
    "null_value": None
}

# JSON options
json_compact = json.dumps(complex_data, separators=(',', ':'))
json_sorted = json.dumps(complex_data, sort_keys=True)

# Error handling
invalid_json = '{"name": "Alice", "age": 30,}'  # Trailing comma

try:
    parsed = json.loads(invalid_json)
except json.JSONDecodeError as e:
    print(f"JSON decode error: {e}")

# Working with JSON APIs
def parse_api_response(response_text):
    try:
        data = json.loads(response_text)
        return data
    except json.JSONDecodeError:
        return None

# Validating JSON structure
def validate_user_data(json_data):
    required_fields = ["name", "email", "age"]

    for field in required_fields:
        if field not in json_data:
            return False, f"Missing field: {field}"

    if not isinstance(json_data["age"], int):
        return False, "Age must be an integer"

    return True, "Valid"

user_json = '{"name": "Alice", "email": "alice@email.com", "age": 30}'
user_data = json.loads(user_json)
is_valid, message = validate_user_data(user_data)
print(f"Validation: {is_valid}, {message}")
```

### HTTP Requests

```python
import urllib.request
import urllib.parse
import json

# Basic GET request
url = "https://jsonplaceholder.typicode.com/posts/1"

try:
    with urllib.request.urlopen(url) as response:
        data = response.read()
        json_data = json.loads(data.decode('utf-8'))
        print(json_data['title'])
except Exception as e:
    print(f"Error: {e}")

# POST request
post_data = {
    "title": "New Post",
    "body": "This is the post content",
    "userId": 1
}

# Encode data
encoded_data = json.dumps(post_data).encode('utf-8')

# Create request
request = urllib.request.Request(
    "https://jsonplaceholder.typicode.com/posts",
    data=encoded_data,
    headers={
        'Content-Type': 'application/json',
        'User-Agent': 'Python Script'
    },
    method='POST'
)

try:
    with urllib.request.urlopen(request) as response:
        result = json.loads(response.read().decode('utf-8'))
        print(f"Created post with ID: {result['id']}")
except Exception as e:
    print(f"Error: {e}")

# Using urllib.parse for URL encoding
params = {"q": "python programming", "page": 1}
query_string = urllib.parse.urlencode(params)
full_url = f"https://api.example.com/search?{query_string}"

# Better approach: Use requests library (third-party)
"""
pip install requests

import requests

# GET request
response = requests.get("https://jsonplaceholder.typicode.com/posts/1")
if response.status_code == 200:
    data = response.json()
    print(data['title'])

# POST request
post_data = {"title": "New Post", "body": "Content", "userId": 1}
response = requests.post("https://jsonplaceholder.typicode.com/posts", json=post_data)

# With headers and parameters
headers = {"Authorization": "Bearer token123"}
params = {"page": 1, "limit": 10}
response = requests.get("https://api.example.com/data", headers=headers, params=params)

# Error handling
try:
    response = requests.get("https://api.example.com/data", timeout=5)
    response.raise_for_status()  # Raises exception for bad status codes
    data = response.json()
except requests.exceptions.RequestException as e:
    print(f"Request failed: {e}")
"""

# Simple HTTP server (for testing)
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading

def start_test_server():
    server = HTTPServer(('localhost', 8000), SimpleHTTPRequestHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    return server

# server = start_test_server()
# # Server now running at http://localhost:8000
```

---

## Popular Libraries

### NumPy

```python
# Install: pip install numpy
import numpy as np

# Creating arrays
arr1 = np.array([1, 2, 3, 4, 5])
arr2 = np.array([[1, 2, 3], [4, 5, 6]])
zeros = np.zeros((3, 4))
ones = np.ones((2, 3))
identity = np.eye(3)
random_arr = np.random.random((2, 3))

print(f"Array shape: {arr2.shape}")  # (2, 3)
print(f"Array dtype: {arr1.dtype}")  # int64

# Array operations
a = np.array([1, 2, 3])
b = np.array([4, 5, 6])

print(a + b)      # [5 7 9]
print(a * b)      # [4 10 18]
print(np.dot(a, b))  # 32 (dot product)

# Mathematical functions
arr = np.array([1, 4, 9, 16])
print(np.sqrt(arr))    # [1. 2. 3. 4.]
print(np.sum(arr))     # 30
print(np.mean(arr))    # 7.5
print(np.max(arr))     # 16

# Array slicing and indexing
matrix = np.array([[1, 2, 3], [4, 5, 6], [7, 8, 9]])
print(matrix[0, 1])    # 2
print(matrix[:, 1])    # [2 5 8] (second column)
print(matrix[1:, :2])  # [[4 5], [7 8]]

# Boolean indexing
arr = np.array([1, 2, 3, 4, 5])
mask = arr > 3
print(arr[mask])  # [4 5]

# Reshaping
arr = np.arange(12)
reshaped = arr.reshape(3, 4)
flattened = reshaped.flatten()

print(f"Original: {arr}")
print(f"Reshaped: {reshaped}")
print(f"Flattened: {flattened}")
```

### Pandas

```python
# Install: pip install pandas
import pandas as pd
import numpy as np

# Creating DataFrames
data = {
    'Name': ['Alice', 'Bob', 'Charlie', 'Diana'],
    'Age': [25, 30, 35, 28],
    'City': ['NY', 'LA', 'Chicago', 'Boston'],
    'Salary': [50000, 60000, 70000, 55000]
}

df = pd.DataFrame(data)
print(df)

# Basic DataFrame operations
print(df.head())          # First 5 rows
print(df.tail(2))         # Last 2 rows
print(df.info())          # DataFrame info
print(df.describe())      # Statistical summary

# Selecting data
print(df['Name'])         # Single column
print(df[['Name', 'Age']]) # Multiple columns
print(df.loc[0])          # Row by index
print(df.loc[df['Age'] > 30])  # Conditional selection

# Adding new columns
df['Bonus'] = df['Salary'] * 0.1
df['Full_Info'] = df['Name'] + ' (' + df['City'] + ')'

# Grouping and aggregation
city_stats = df.groupby('City')['Salary'].agg(['mean', 'max', 'count'])
print(city_stats)

# Reading/writing files
# df.to_csv('employees.csv', index=False)
# df_from_csv = pd.read_csv('employees.csv')

# Data manipulation
df_sorted = df.sort_values('Salary', ascending=False)
df_filtered = df[df['Age'].between(25, 30)]

# Handling missing data
df_with_nulls = df.copy()
df_with_nulls.loc[0, 'Salary'] = np.nan

print(df_with_nulls.isna().sum())  # Count null values
df_filled = df_with_nulls.fillna(df_with_nulls['Salary'].mean())
df_dropped = df_with_nulls.dropna()

# Date operations
dates = pd.date_range('2024-01-01', periods=4, freq='D')
df['Date'] = dates
df['Year'] = df['Date'].dt.year
df['Month'] = df['Date'].dt.month

# Series operations (1D data)
series = pd.Series([1, 2, 3, 4, 5], index=['a', 'b', 'c', 'd', 'e'])
print(series['b'])  # 2
print(series[series > 3])  # Values greater than 3
```

### Requests

```python
# Install: pip install requests
import requests
import json

# Basic GET request
response = requests.get('https://jsonplaceholder.typicode.com/posts/1')
print(f"Status Code: {response.status_code}")
print(f"Response: {response.json()}")

# POST request
new_post = {
    'title': 'My New Post',
    'body': 'This is the content of my post',
    'userId': 1
}

response = requests.post(
    'https://jsonplaceholder.typicode.com/posts',
    json=new_post
)

if response.status_code == 201:
    print("Post created successfully!")
    print(response.json())

# GET with parameters
params = {'userId': 1}
response = requests.get(
    'https://jsonplaceholder.typicode.com/posts',
    params=params
)

posts = response.json()
print(f"Found {len(posts)} posts for user 1")

# Headers and authentication
headers = {
    'User-Agent': 'My Python App 1.0',
    'Authorization': 'Bearer your-token-here'
}

response = requests.get(
    'https://api.example.com/data',
    headers=headers
)

# Session for maintaining cookies/auth
session = requests.Session()
session.headers.update({'Authorization': 'Bearer token123'})

# Multiple requests with same session
response1 = session.get('https://api.example.com/profile')
response2 = session.get('https://api.example.com/settings')

# Error handling
try:
    response = requests.get(
        'https://api.example.com/data',
        timeout=5  # 5 second timeout
    )
    response.raise_for_status()  # Raises exception for 4xx/5xx status codes
    data = response.json()
except requests.exceptions.Timeout:
    print("Request timed out")
except requests.exceptions.RequestException as e:
    print(f"Request failed: {e}")

# File upload
files = {'file': open('document.pdf', 'rb')}
response = requests.post('https://httpbin.org/post', files=files)

# Download file
def download_file(url, filename):
    response = requests.get(url, stream=True)
    response.raise_for_status()

    with open(filename, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)

    print(f"Downloaded {filename}")

# download_file('https://example.com/largefile.zip', 'largefile.zip')

# Custom session with retry logic
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def create_session_with_retries():
    session = requests.Session()

    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    return session

session = create_session_with_retries()
response = session.get('https://unreliable-api.com/data')
```

### Flask/Django

```python
# Flask (Install: pip install flask)
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# Simple route
@app.route('/')
def home():
    return "Hello, Flask!"

# Route with parameter
@app.route('/user/<username>')
def user_profile(username):
    return f"Profile page for {username}"

# POST endpoint
@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.get_json()

    # Validate data
    if not data or 'name' not in data:
        return jsonify({'error': 'Name is required'}), 400

    # Create user (simplified)
    user = {
        'id': 123,
        'name': data['name'],
        'email': data.get('email', '')
    }

    return jsonify(user), 201

# Query parameters
@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    limit = request.args.get('limit', 10, type=int)

    results = [f"Result {i} for '{query}'" for i in range(1, limit + 1)]

    return jsonify({
        'query': query,
        'results': results,
        'total': len(results)
    })

# Error handling
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

# Run the app
if __name__ == '__main__':
    app.run(debug=True)

# Usage:
# python app.py
# Visit: http://localhost:5000

# Django basics (Install: pip install django)
"""
# Create project
django-admin startproject myproject
cd myproject

# Create app
python manage.py startapp myapp

# models.py
from django.db import models

class User(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

# views.py
from django.shortcuts import render
from django.http import JsonResponse
from .models import User

def user_list(request):
    users = User.objects.all()
    return render(request, 'users.html', {'users': users})

def api_users(request):
    users = list(User.objects.values('id', 'name', 'email'))
    return JsonResponse({'users': users})

# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('users/', views.user_list, name='user_list'),
    path('api/users/', views.api_users, name='api_users'),
]

# Run migrations
python manage.py makemigrations
python manage.py migrate

# Run server
python manage.py runserver
"""

# REST API with Flask-RESTful
"""
from flask import Flask
from flask_restful import Api, Resource, reqparse

app = Flask(__name__)
api = Api(app)

# In-memory data store
users = [
    {'id': 1, 'name': 'Alice', 'email': 'alice@email.com'},
    {'id': 2, 'name': 'Bob', 'email': 'bob@email.com'}
]

class UserList(Resource):
    def get(self):
        return users

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', required=True)
        parser.add_argument('email', required=True)
        args = parser.parse_args()

        new_user = {
            'id': len(users) + 1,
            'name': args['name'],
            'email': args['email']
        }
        users.append(new_user)
        return new_user, 201

class User(Resource):
    def get(self, user_id):
        user = next((u for u in users if u['id'] == user_id), None)
        return user if user else {'error': 'User not found'}, 404 if not user else 200

api.add_resource(UserList, '/api/users')
api.add_resource(User, '/api/users/<int:user_id>')
"""
```

---

## Best Practices

### Code Style

```python
# PEP 8 - Python Style Guide

# Naming conventions
class UserAccount:          # CamelCase for classes
    pass

def calculate_total():      # snake_case for functions
    pass

user_name = "Alice"        # snake_case for variables
CONSTANT_VALUE = 100       # UPPER_CASE for constants

# Indentation (4 spaces)
def example_function():
    if True:
        print("Properly indented")
        for i in range(3):
            print(i)

# Line length (max 79 characters)
def long_function_name(
    parameter_one, parameter_two, parameter_three,
    parameter_four, parameter_five
):
    return parameter_one + parameter_two

# Imports
import os
import sys
import json

from collections import defaultdict, Counter
from datetime import datetime, timedelta

import requests
import numpy as np

# Whitespace
def good_spacing():
    x = 1
    y = 2
    result = x + y

    my_list = [1, 2, 3, 4, 5]
    my_dict = {'key': 'value', 'another': 'item'}

    if x == 1:
        print("x is one")

# Comments and docstrings
def calculate_area(radius):
    """
    Calculate the area of a circle.

    Args:
        radius (float): The radius of the circle.

    Returns:
        float: The area of the circle.

    Raises:
        ValueError: If radius is negative.
    """
    if radius < 0:
        raise ValueError("Radius cannot be negative")

    return 3.14159 * radius ** 2

# Type hints (Python 3.5+)
from typing import List, Dict, Optional, Union

def process_data(
    items: List[str],
    multiplier: int = 1
) -> Dict[str, int]:
    """Process a list of items and return counts."""
    result = {}
    for item in items:
        result[item] = len(item) * multiplier
    return result

def find_user(user_id: int) -> Optional[Dict[str, str]]:
    """Find user by ID, return None if not found."""
    # Implementation here
    return None

# Code organization
class BankAccount:
    """A simple bank account class."""

    def __init__(self, account_number: str, initial_balance: float = 0.0):
        self.account_number = account_number
        self._balance = initial_balance
        self._transactions = []

    @property
    def balance(self) -> float:
        """Get current balance."""
        return self._balance

    def deposit(self, amount: float) -> None:
        """Deposit money to account."""
        if amount <= 0:
            raise ValueError("Deposit amount must be positive")

        self._balance += amount
        self._transactions.append(f"Deposit: +${amount}")

    def withdraw(self, amount: float) -> bool:
        """Withdraw money from account."""
        if amount <= 0:
            raise ValueError("Withdrawal amount must be positive")

        if amount > self._balance:
            return False

        self._balance -= amount
        self._transactions.append(f"Withdrawal: -${amount}")
        return True

    def get_statement(self) -> List[str]:
        """Get transaction history."""
        return self._transactions.copy()

# Constants at module level
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
API_BASE_URL = "https://api.example.com"
```

### Testing

```python
# Unit testing with unittest
import unittest

class TestCalculator(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.calc = Calculator()

    def test_addition(self):
        """Test addition operation."""
        result = self.calc.add(2, 3)
        self.assertEqual(result, 5)

    def test_division_by_zero(self):
        """Test division by zero raises exception."""
        with self.assertRaises(ZeroDivisionError):
            self.calc.divide(10, 0)

    def test_multiple_operations(self):
        """Test multiple operations."""
        self.assertEqual(self.calc.add(2, 3), 5)
        self.assertEqual(self.calc.subtract(10, 4), 6)
        self.assertEqual(self.calc.multiply(3, 4), 12)
        self.assertAlmostEqual(self.calc.divide(10, 3), 3.333, places=3)

    def tearDown(self):
        """Clean up after each test method."""
        pass

if __name__ == '__main__':
    unittest.main()

# pytest (Install: pip install pytest)
"""
def test_addition():
    assert add(2, 3) == 5

def test_division_by_zero():
    with pytest.raises(ZeroDivisionError):
        divide(10, 0)

@pytest.fixture
def sample_data():
    return [1, 2, 3, 4, 5]

def test_with_fixture(sample_data):
    assert len(sample_data) == 5
    assert sum(sample_data) == 15

# Run with: pytest test_file.py
"""

# Mocking
from unittest.mock import Mock, patch

class TestUserService:

    @patch('requests.get')
    def test_get_user_data(self, mock_get):
        # Mock the API response
        mock_response = Mock()
        mock_response.json.return_value = {'id': 1, 'name': 'Alice'}
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        # Test the function
        user_service = UserService()
        result = user_service.get_user(1)

        assert result['name'] == 'Alice'
        mock_get.assert_called_once_with('https://api.example.com/users/1')

# Test coverage (Install: pip install coverage)
"""
coverage run -m pytest
coverage report
coverage html  # Generates HTML report
"""

# Property-based testing with hypothesis
"""
from hypothesis import given, strategies as st

@given(st.integers(), st.integers())
def test_addition_commutative(a, b):
    assert add(a, b) == add(b, a)

@given(st.lists(st.integers(), min_size=1))
def test_max_element(lst):
    assert max(lst) in lst
"""
```

### Performance

```python
import time
import cProfile
from functools import lru_cache
from memory_profiler import profile

# Timing code execution
def time_function(func, *args, **kwargs):
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    print(f"{func.__name__} took {end_time - start_time:.4f} seconds")
    return result

# List comprehension vs loops
def slow_squares(n):
    result = []
    for i in range(n):
        result.append(i ** 2)
    return result

def fast_squares(n):
    return [i ** 2 for i in range(n)]

# Generator for memory efficiency
def fibonacci_list(n):
    """Memory intensive - creates full list."""
    fib = [0, 1]
    for i in range(2, n):
        fib.append(fib[i-1] + fib[i-2])
    return fib

def fibonacci_gen(n):
    """Memory efficient - yields one at a time."""
    a, b = 0, 1
    for _ in range(n):
        yield a
        a, b = b, a + b

# Caching with lru_cache
@lru_cache(maxsize=128)
def expensive_calculation(n):
    """Simulate expensive calculation."""
    time.sleep(0.1)  # Simulate work
    return n * n

# String concatenation optimization
def slow_string_concat(items):
    result = ""
    for item in items:
        result += str(item) + " "
    return result

def fast_string_concat(items):
    return " ".join(str(item) for item in items)

# Dictionary get vs try-except
def using_get(dictionary, key, default=None):
    return dictionary.get(key, default)

def using_try_except(dictionary, key, default=None):
    try:
        return dictionary[key]
    except KeyError:
        return default

# Set operations for membership testing
def slow_membership_test(items, search_items):
    found = []
    for item in search_items:
        if item in items:  # O(n) for list
            found.append(item)
    return found

def fast_membership_test(items, search_items):
    items_set = set(items)  # O(1) lookup
    return [item for item in search_items if item in items_set]

# Profile memory usage
@profile
def memory_intensive_function():
    # Create large data structures
    large_list = [i for i in range(1000000)]
    large_dict = {i: i**2 for i in range(100000)}
    return len(large_list) + len(large_dict)

# Profiling with cProfile
def profile_function():
    cProfile.run('expensive_function()')

# Performance testing
def benchmark_functions():
    import timeit

    # Time different approaches
    list_comp_time = timeit.timeit(
        lambda: [i**2 for i in range(1000)],
        number=1000
    )

    map_time = timeit.timeit(
        lambda: list(map(lambda x: x**2, range(1000))),
        number=1000
    )

    print(f"List comprehension: {list_comp_time:.4f}s")
    print(f"Map function: {map_time:.4f}s")

# Context manager for timing
class Timer:
    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *args):
        self.end = time.time()
        self.elapsed = self.end - self.start
        print(f"Elapsed time: {self.elapsed:.4f} seconds")

# Usage
with Timer():
    result = expensive_calculation(100)
```

### Debugging

```python
import pdb
import logging
import traceback
from pprint import pprint

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Debug function with logging
def process_user_data(users):
    logger.info(f"Processing {len(users)} users")

    processed = []
    for i, user in enumerate(users):
        logger.debug(f"Processing user {i}: {user.get('name', 'Unknown')}")

        try:
            # Some processing
            result = validate_and_transform_user(user)
            processed.append(result)
            logger.debug(f"Successfully processed user {i}")

        except Exception as e:
            logger.error(f"Failed to process user {i}: {e}")
            logger.error(f"User data: {user}")
            continue

    logger.info(f"Successfully processed {len(processed)} users")
    return processed

# Debugger usage
def debug_example():
    x = 10
    y = 20
    pdb.set_trace()  # Execution will pause here
    result = x + y
    return result

# Pretty printing for debugging
def debug_data_structure():
    complex_data = {
        'users': [
            {'id': 1, 'name': 'Alice', 'settings': {'theme': 'dark'}},
            {'id': 2, 'name': 'Bob', 'settings': {'theme': 'light'}}
        ],
        'config': {'timeout': 30, 'retries': 3}
    }

    print("Complex data structure:")
    pprint(complex_data, indent=2)

# Exception information
def detailed_error_info():
    try:
        # Some operation that might fail
        result = risky_operation()
    except Exception as e:
        # Get detailed exception information
        exc_type, exc_value, exc_traceback = sys.exc_info()

        logger.error("Exception occurred:")
        logger.error(f"Type: {exc_type.__name__}")
        logger.error(f"Value: {exc_value}")
        logger.error("Traceback:")

        # Print full traceback
        traceback.print_exception(exc_type, exc_value, exc_traceback)

        # Get traceback as string
        tb_string = traceback.format_exception(exc_type, exc_value, exc_traceback)
        logger.error("".join(tb_string))

# Assertion for debugging
def validate_input(data):
    assert isinstance(data, dict), f"Expected dict, got {type(data)}"
    assert 'id' in data, "Missing required field: id"
    assert isinstance(data['id'], int), "ID must be an integer"

    return True

# Debug decorator
def debug_calls(func):
    def wrapper(*args, **kwargs):
        print(f"Calling {func.__name__} with args: {args}, kwargs: {kwargs}")
        result = func(*args, **kwargs)
        print(f"{func.__name__} returned: {result}")
        return result
    return wrapper

@debug_calls
def add_numbers(a, b):
    return a + b

# Custom debug print
def debug_print(*args, **kwargs):
    if DEBUG:  # Global debug flag
        print("[DEBUG]", *args, **kwargs)

# Conditional debugging
DEBUG = True

if DEBUG:
    def debug_log(message):
        print(f"[DEBUG] {message}")
else:
    def debug_log(message):
        pass

# Interactive debugging
def interactive_debug():
    import code

    # Local variables for debugging
    x = 42
    y = "hello"
    data = [1, 2, 3, 4, 5]

    # Start interactive interpreter
    code.interact(local=locals())

# Testing with debug output
def test_with_debug():
    test_data = [1, 2, 3, 4, 5]

    print(f"Input data: {test_data}")
    print(f"Data type: {type(test_data)}")
    print(f"Data length: {len(test_data)}")

    result = process_data(test_data)

    print(f"Result: {result}")
    print(f"Result type: {type(result)}")

    return result
```