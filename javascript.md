# JavaScript Learning Guide

## Table of Contents

1. [JavaScript Basics](#javascript-basics)
   1. [Variables and Data Types](#variables-and-data-types)
   2. [Operators](#operators)
   3. [Type Conversion](#type-conversion)
   4. [Comments](#comments)
2. [Control Flow](#control-flow)
   1. [Conditional Statements](#conditional-statements)
   2. [Loops](#loops)
   3. [Switch Statement](#switch-statement)
3. [Functions](#functions)
   1. [Function Declaration](#function-declaration)
   2. [Function Expression](#function-expression)
   3. [Arrow Functions](#arrow-functions)
   4. [Parameters and Arguments](#parameters-and-arguments)
   5. [Scope and Closure](#scope-and-closure)
4. [Objects and Arrays](#objects-and-arrays)
   1. [Objects](#objects)
   2. [Arrays](#arrays)
   3. [Destructuring](#destructuring)
   4. [Spread and Rest](#spread-and-rest)
5. [ES6+ Features](#es6-features)
   1. [Let and Const](#let-and-const)
   2. [Template Literals](#template-literals)
   3. [Classes](#classes)
   4. [Modules](#modules)
   5. [Default Parameters](#default-parameters)
6. [Asynchronous JavaScript](#asynchronous-javascript)
   1. [Callbacks](#callbacks)
   2. [Promises](#promises)
   3. [Async/Await](#asyncawait)
   4. [Fetch API](#fetch-api)
7. [DOM Manipulation](#dom-manipulation)
   1. [Selecting Elements](#selecting-elements)
   2. [Modifying Elements](#modifying-elements)
   3. [Event Handling](#event-handling)
   4. [Creating Elements](#creating-elements)
8. [Error Handling](#error-handling)
   1. [Try/Catch](#trycatch)
   2. [Custom Errors](#custom-errors)
   3. [Debugging](#debugging)
9. [Advanced Concepts](#advanced-concepts)
   1. [Prototypes and Inheritance](#prototypes-and-inheritance)
   2. [Regular Expressions](#regular-expressions)
   3. [JSON](#json)
   4. [Local Storage](#local-storage)
   5. [Higher-Order Functions](#higher-order-functions)
10. [Modern JavaScript Patterns](#modern-javascript-patterns)
    1. [Module Pattern](#module-pattern)
    2. [Factory Functions](#factory-functions)
    3. [Observer Pattern](#observer-pattern)
    4. [Performance Optimization](#performance-optimization)

---

## JavaScript Basics

### Variables and Data Types

```javascript
// Variable declarations
var oldWay = "avoid using var";
let mutableVar = "can be changed";
const immutableVar = "cannot be reassigned";

// Data types
let string = "Hello World";
let number = 42;
let boolean = true;
let undefinedVar;
let nullVar = null;
let symbol = Symbol("unique");
let bigInt = 123n;

// Check types
console.log(typeof string); // "string"
console.log(typeof number); // "number"
console.log(typeof boolean); // "boolean"
```

### Operators

```javascript
// Arithmetic operators
let a = 10, b = 3;
console.log(a + b); // 13
console.log(a - b); // 7
console.log(a * b); // 30
console.log(a / b); // 3.333...
console.log(a % b); // 1 (remainder)
console.log(a ** b); // 1000 (exponentiation)

// Comparison operators
console.log(a > b);   // true
console.log(a === b); // false (strict equality)
console.log(a == b);  // false (loose equality)
console.log(a !== b); // true

// Logical operators
console.log(true && false); // false
console.log(true || false); // true
console.log(!true);         // false

// Assignment operators
a += 5; // a = a + 5
a -= 2; // a = a - 2
a *= 2; // a = a * 2
```

### Type Conversion

```javascript
// String conversion
let num = 123;
let str = String(num);        // "123"
let str2 = num.toString();    // "123"
let str3 = num + "";          // "123"

// Number conversion
let strNum = "456";
let converted = Number(strNum);  // 456
let parsed = parseInt(strNum);   // 456
let parseFloat1 = parseFloat("3.14"); // 3.14

// Boolean conversion
console.log(Boolean(1));        // true
console.log(Boolean(0));        // false
console.log(Boolean(""));       // false
console.log(Boolean("hello"));  // true
```

### Comments

```javascript
// Single line comment

/*
Multi-line comment
Can span multiple lines
*/

/**
 * JSDoc comment for documentation
 * @param {string} name - The name parameter
 * @returns {string} - A greeting message
 */
function greet(name) {
    return `Hello, ${name}!`;
}
```

---

## Control Flow

### Conditional Statements

```javascript
// if...else
let age = 18;
if (age >= 18) {
    console.log("Adult");
} else if (age >= 13) {
    console.log("Teenager");
} else {
    console.log("Child");
}

// Ternary operator
let status = age >= 18 ? "adult" : "minor";

// Nullish coalescing
let username = null;
let displayName = username ?? "Guest";

// Optional chaining
let user = { profile: { name: "John" } };
console.log(user?.profile?.name); // "John"
console.log(user?.address?.street); // undefined
```

### Loops

```javascript
// for loop
for (let i = 0; i < 5; i++) {
    console.log(i);
}

// while loop
let count = 0;
while (count < 3) {
    console.log(count);
    count++;
}

// do...while loop
let x = 0;
do {
    console.log(x);
    x++;
} while (x < 3);

// for...in (object properties)
let obj = { a: 1, b: 2, c: 3 };
for (let key in obj) {
    console.log(key, obj[key]);
}

// for...of (iterable values)
let arr = [1, 2, 3];
for (let value of arr) {
    console.log(value);
}

// Break and continue
for (let i = 0; i < 10; i++) {
    if (i === 5) break;     // Exit loop
    if (i === 2) continue;  // Skip iteration
    console.log(i);
}
```

### Switch Statement

```javascript
let day = "Monday";
switch (day) {
    case "Monday":
        console.log("Start of work week");
        break;
    case "Friday":
        console.log("TGIF!");
        break;
    case "Saturday":
    case "Sunday":
        console.log("Weekend!");
        break;
    default:
        console.log("Regular day");
}
```

---

## Functions

### Function Declaration

```javascript
// Function declaration (hoisted)
function greet(name) {
    return `Hello, ${name}!`;
}

// Function with multiple parameters
function add(a, b) {
    return a + b;
}

// Function with default parameters
function multiply(a, b = 1) {
    return a * b;
}

console.log(greet("John"));     // "Hello, John!"
console.log(add(5, 3));         // 8
console.log(multiply(5));       // 5
```

### Function Expression

```javascript
// Function expression (not hoisted)
const subtract = function(a, b) {
    return a - b;
};

// Named function expression
const divide = function divideNumbers(a, b) {
    if (b === 0) throw new Error("Division by zero");
    return a / b;
};

console.log(subtract(10, 3)); // 7
```

### Arrow Functions

```javascript
// Arrow function syntax
const square = (x) => x * x;
const cube = x => x * x * x;  // Single parameter, no parentheses

// Multiple parameters
const sum = (a, b) => a + b;

// Block body
const processData = (data) => {
    const processed = data.map(x => x * 2);
    return processed.filter(x => x > 10);
};

// Arrow functions don't have their own 'this'
const obj = {
    name: "Test",
    regularFunction: function() {
        console.log(this.name); // "Test"
    },
    arrowFunction: () => {
        console.log(this.name); // undefined (in strict mode)
    }
};
```

### Parameters and Arguments

```javascript
// Rest parameters
function sum(...numbers) {
    return numbers.reduce((total, num) => total + num, 0);
}

console.log(sum(1, 2, 3, 4)); // 10

// Arguments object (traditional functions only)
function showArgs() {
    console.log(arguments.length);
    console.log(Array.from(arguments));
}

// Destructuring parameters
function processUser({ name, age, email = "not provided" }) {
    console.log(`${name}, ${age}, ${email}`);
}

processUser({ name: "John", age: 30 });
```

### Scope and Closure

```javascript
// Global scope
let globalVar = "I'm global";

function outerFunction(x) {
    // Function scope
    let outerVar = "I'm outer";

    function innerFunction(y) {
        // Inner function has access to outer variables (closure)
        console.log(globalVar); // "I'm global"
        console.log(outerVar);  // "I'm outer"
        console.log(x, y);      // Parameters from both functions
    }

    return innerFunction;
}

const closureExample = outerFunction(10);
closureExample(20);

// Practical closure example
function createCounter() {
    let count = 0;
    return function() {
        return ++count;
    };
}

const counter = createCounter();
console.log(counter()); // 1
console.log(counter()); // 2
```

---

## Objects and Arrays

### Objects

```javascript
// Object literal
const person = {
    name: "John",
    age: 30,
    city: "New York",
    greet: function() {
        return `Hello, I'm ${this.name}`;
    },
    // Method shorthand
    introduce() {
        return `I'm ${this.name}, ${this.age} years old`;
    }
};

// Accessing properties
console.log(person.name);        // "John"
console.log(person["age"]);      // 30

// Adding/modifying properties
person.email = "john@email.com";
person["phone"] = "123-456-7890";

// Object methods
console.log(Object.keys(person));     // Array of keys
console.log(Object.values(person));   // Array of values
console.log(Object.entries(person));  // Array of [key, value] pairs

// Object.assign (shallow copy)
const newPerson = Object.assign({}, person, { age: 31 });

// Object destructuring in parameters
function printPersonInfo({ name, age, city = "Unknown" }) {
    console.log(`${name}, ${age}, from ${city}`);
}
```

### Arrays

```javascript
// Array creation
const fruits = ["apple", "banana", "orange"];
const numbers = new Array(1, 2, 3, 4, 5);
const empty = new Array(5); // Creates array with 5 empty slots

// Array methods
fruits.push("grape");           // Add to end
fruits.unshift("mango");        // Add to beginning
let last = fruits.pop();        // Remove from end
let first = fruits.shift();     // Remove from beginning

// Array iteration
fruits.forEach((fruit, index) => {
    console.log(`${index}: ${fruit}`);
});

// Array transformation
const upperFruits = fruits.map(fruit => fruit.toUpperCase());
const longFruits = fruits.filter(fruit => fruit.length > 5);
const total = numbers.reduce((sum, num) => sum + num, 0);

// Finding elements
const found = fruits.find(fruit => fruit.startsWith("a"));
const index = fruits.findIndex(fruit => fruit === "banana");
const includes = fruits.includes("apple");

// Array sorting
const sorted = fruits.sort();
const numSorted = numbers.sort((a, b) => a - b); // Numeric sort
```

### Destructuring

```javascript
// Array destructuring
const colors = ["red", "green", "blue"];
const [first, second, third] = colors;
const [primary, ...others] = colors; // Rest in destructuring

// Skipping elements
const [, , blue] = colors;

// Object destructuring
const user = { name: "Alice", age: 25, city: "Boston" };
const { name, age } = user;
const { name: userName, age: userAge } = user; // Renaming
const { email = "not provided" } = user; // Default value

// Nested destructuring
const student = {
    info: { name: "Bob", grade: "A" },
    subjects: ["Math", "Science"]
};
const { info: { name: studentName }, subjects: [firstSubject] } = student;
```

### Spread and Rest

```javascript
// Spread operator with arrays
const arr1 = [1, 2, 3];
const arr2 = [4, 5, 6];
const combined = [...arr1, ...arr2]; // [1, 2, 3, 4, 5, 6]
const copied = [...arr1]; // Shallow copy

// Spread with objects
const obj1 = { a: 1, b: 2 };
const obj2 = { c: 3, d: 4 };
const merged = { ...obj1, ...obj2 }; // { a: 1, b: 2, c: 3, d: 4 }
const updated = { ...obj1, b: 20 }; // Override property

// Rest operator
function processData(first, second, ...rest) {
    console.log(first, second); // First two arguments
    console.log(rest);          // Array of remaining arguments
}

// Rest in destructuring
const [head, ...tail] = [1, 2, 3, 4, 5];
const { name, ...otherProps } = { name: "John", age: 30, city: "NYC" };
```

---

## ES6+ Features

### Let and Const

```javascript
// Block scope
if (true) {
    let blockScoped = "only available in this block";
    const alsoBlockScoped = "cannot be reassigned";
    var functionScoped = "available in entire function";
}

// Temporal dead zone
console.log(x); // ReferenceError
let x = 5;

// Const with objects (object is mutable, reference is not)
const config = { api: "https://api.example.com" };
config.api = "https://new-api.example.com"; // OK
config.timeout = 5000; // OK
// config = {}; // TypeError: Assignment to constant variable
```

### Template Literals

```javascript
const name = "Alice";
const age = 25;

// Template literals
const message = `Hello, my name is ${name} and I'm ${age} years old.`;

// Multi-line strings
const multiLine = `
    This is a
    multi-line
    string
`;

// Tagged templates
function highlight(strings, ...values) {
    return strings.reduce((result, string, i) => {
        const value = values[i] ? `<mark>${values[i]}</mark>` : '';
        return result + string + value;
    }, '');
}

const highlighted = highlight`Name: ${name}, Age: ${age}`;
```

### Classes

```javascript
// Class declaration
class Person {
    constructor(name, age) {
        this.name = name;
        this.age = age;
    }

    // Method
    greet() {
        return `Hello, I'm ${this.name}`;
    }

    // Getter
    get info() {
        return `${this.name} (${this.age})`;
    }

    // Setter
    set age(value) {
        if (value < 0) throw new Error("Age cannot be negative");
        this._age = value;
    }

    // Static method
    static createAdult(name) {
        return new Person(name, 18);
    }
}

// Inheritance
class Student extends Person {
    constructor(name, age, grade) {
        super(name, age); // Call parent constructor
        this.grade = grade;
    }

    greet() {
        return `${super.greet()}, I'm in grade ${this.grade}`;
    }
}

const student = new Student("Bob", 16, "10th");
console.log(student.greet());
```

### Modules

```javascript
// math.js - Named exports
export const PI = 3.14159;
export function add(a, b) {
    return a + b;
}
export function multiply(a, b) {
    return a * b;
}

// calculator.js - Default export
export default class Calculator {
    add(a, b) { return a + b; }
    subtract(a, b) { return a - b; }
}

// main.js - Importing
import Calculator from './calculator.js';           // Default import
import { add, multiply, PI } from './math.js';      // Named imports
import { add as sum } from './math.js';             // Renamed import
import * as MathUtils from './math.js';             // Namespace import

// Dynamic imports
async function loadModule() {
    const module = await import('./math.js');
    console.log(module.add(5, 3));
}
```

### Default Parameters

```javascript
// Default parameters
function greet(name = "World", greeting = "Hello") {
    return `${greeting}, ${name}!`;
}

console.log(greet());                    // "Hello, World!"
console.log(greet("Alice"));             // "Hello, Alice!"
console.log(greet("Bob", "Hi"));         // "Hi, Bob!"

// Default parameters with expressions
function createUser(name, id = Date.now()) {
    return { name, id };
}

// Default parameters can reference earlier parameters
function buildUrl(protocol = "https", host = "localhost", port = protocol === "https" ? 443 : 80) {
    return `${protocol}://${host}:${port}`;
}
```

---

## Asynchronous JavaScript

### Callbacks

```javascript
// Callback function
function fetchData(callback) {
    setTimeout(() => {
        const data = { id: 1, name: "John" };
        callback(null, data); // (error, result)
    }, 1000);
}

fetchData((error, data) => {
    if (error) {
        console.error("Error:", error);
    } else {
        console.log("Data:", data);
    }
});

// Callback hell example
getData((data1) => {
    processData(data1, (data2) => {
        saveData(data2, (result) => {
            console.log("All done:", result);
        });
    });
});
```

### Promises

```javascript
// Creating a Promise
const fetchUserData = new Promise((resolve, reject) => {
    const success = Math.random() > 0.5;
    setTimeout(() => {
        if (success) {
            resolve({ id: 1, name: "Alice" });
        } else {
            reject(new Error("Failed to fetch user data"));
        }
    }, 1000);
});

// Using Promises
fetchUserData
    .then(data => {
        console.log("User data:", data);
        return data.id; // Return for next .then()
    })
    .then(userId => {
        console.log("User ID:", userId);
    })
    .catch(error => {
        console.error("Error:", error.message);
    })
    .finally(() => {
        console.log("Cleanup operations");
    });

// Promise.all - Wait for all promises
const promise1 = Promise.resolve(3);
const promise2 = new Promise(resolve => setTimeout(() => resolve('foo'), 1000));
const promise3 = Promise.resolve(42);

Promise.all([promise1, promise2, promise3])
    .then(values => console.log(values)); // [3, 'foo', 42]

// Promise.race - First promise to settle
Promise.race([promise1, promise2, promise3])
    .then(value => console.log(value)); // 3

// Promise.allSettled - Wait for all, regardless of outcome
Promise.allSettled([promise1, Promise.reject('error'), promise3])
    .then(results => console.log(results));
```

### Async/Await

```javascript
// Async function
async function fetchUserData() {
    try {
        const response = await fetch('/api/user');
        const userData = await response.json();
        return userData;
    } catch (error) {
        console.error('Error fetching user data:', error);
        throw error;
    }
}

// Using async/await
async function main() {
    try {
        const user = await fetchUserData();
        console.log('User:', user);

        // Sequential execution
        const posts = await fetchUserPosts(user.id);
        const comments = await fetchPostComments(posts[0].id);

        // Parallel execution
        const [profile, settings] = await Promise.all([
            fetchUserProfile(user.id),
            fetchUserSettings(user.id)
        ]);

    } catch (error) {
        console.error('Error in main:', error);
    }
}

// Async arrow function
const quickFetch = async (url) => {
    const response = await fetch(url);
    return response.json();
};

// Async iteration
async function processItems(items) {
    for (const item of items) {
        await processItem(item); // Sequential
    }

    // Parallel processing
    await Promise.all(items.map(item => processItem(item)));
}
```

### Fetch API

```javascript
// Basic GET request
fetch('https://api.example.com/users')
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => console.log(data))
    .catch(error => console.error('Error:', error));

// POST request with async/await
async function createUser(userData) {
    try {
        const response = await fetch('https://api.example.com/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer token123'
            },
            body: JSON.stringify(userData)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const newUser = await response.json();
        return newUser;
    } catch (error) {
        console.error('Error creating user:', error);
        throw error;
    }
}

// File upload
async function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch('/upload', {
        method: 'POST',
        body: formData
    });

    return response.json();
}

// Request with timeout
function fetchWithTimeout(url, timeout = 5000) {
    return Promise.race([
        fetch(url),
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Timeout')), timeout)
        )
    ]);
}
```

---

## DOM Manipulation

### Selecting Elements

```javascript
// Single element selectors
const elementById = document.getElementById('myId');
const elementByClass = document.querySelector('.myClass');
const elementByTag = document.querySelector('p');
const elementByAttribute = document.querySelector('[data-id="123"]');

// Multiple element selectors
const elementsByClass = document.getElementsByClassName('myClass');
const elementsByTag = document.getElementsByTagName('p');
const elementsByQuery = document.querySelectorAll('.item');

// Traversing the DOM
const parent = element.parentNode;
const children = element.children;
const firstChild = element.firstElementChild;
const lastChild = element.lastElementChild;
const nextSibling = element.nextElementSibling;
const previousSibling = element.previousElementSibling;

// Modern traversal
const closest = element.closest('.container'); // Closest ancestor with class
const matches = element.matches('.active');    // Check if element matches selector
```

### Modifying Elements

```javascript
// Content modification
element.textContent = "New text content";
element.innerHTML = "<strong>Bold text</strong>";
element.innerText = "Visible text only";

// Attribute manipulation
element.setAttribute('data-id', '123');
element.getAttribute('data-id');
element.removeAttribute('data-id');
element.hasAttribute('data-id');

// Modern attribute access
element.id = 'newId';
element.className = 'new-class';
element.dataset.userId = '456'; // data-user-id attribute

// Style manipulation
element.style.color = 'red';
element.style.backgroundColor = 'blue';
element.style.cssText = 'color: red; background: blue;';

// Class manipulation
element.classList.add('new-class');
element.classList.remove('old-class');
element.classList.toggle('active');
element.classList.contains('active');
element.classList.replace('old', 'new');

// Properties
element.value = 'new value';        // For form elements
element.checked = true;             // For checkboxes
element.disabled = false;           // For form elements
element.hidden = true;              // Hide element
```

### Event Handling

```javascript
// Adding event listeners
button.addEventListener('click', handleClick);
button.addEventListener('click', handleClick, { once: true }); // Run once
button.addEventListener('click', handleClick, { passive: true }); // Performance

// Event handler function
function handleClick(event) {
    event.preventDefault();    // Prevent default behavior
    event.stopPropagation();  // Stop event bubbling

    console.log('Event type:', event.type);
    console.log('Target:', event.target);
    console.log('Current target:', event.currentTarget);
    console.log('Mouse position:', event.clientX, event.clientY);
}

// Arrow function event handler
const handleSubmit = (event) => {
    event.preventDefault();
    const formData = new FormData(event.target);
    console.log(Object.fromEntries(formData));
};

// Removing event listeners
button.removeEventListener('click', handleClick);

// Event delegation
document.addEventListener('click', (event) => {
    if (event.target.matches('.delete-button')) {
        deleteItem(event.target.dataset.id);
    }
});

// Common events
element.addEventListener('mouseover', handler);
element.addEventListener('mouseout', handler);
element.addEventListener('keydown', handler);
element.addEventListener('focus', handler);
element.addEventListener('blur', handler);
element.addEventListener('change', handler);
element.addEventListener('input', handler);

// Custom events
const customEvent = new CustomEvent('userLogin', {
    detail: { userId: 123, username: 'john' }
});
element.dispatchEvent(customEvent);

element.addEventListener('userLogin', (event) => {
    console.log('User logged in:', event.detail);
});
```

### Creating Elements

```javascript
// Creating elements
const newDiv = document.createElement('div');
const newText = document.createTextNode('Hello World');
const newComment = document.createComment('This is a comment');

// Setting up the element
newDiv.textContent = 'New content';
newDiv.className = 'new-element';
newDiv.setAttribute('data-id', '123');

// Adding to DOM
parentElement.appendChild(newDiv);
parentElement.insertBefore(newDiv, referenceElement);
parentElement.replaceChild(newDiv, oldElement);

// Modern insertion methods
parentElement.prepend(newDiv);        // Add as first child
parentElement.append(newDiv);         // Add as last child
element.before(newDiv);               // Insert before element
element.after(newDiv);                // Insert after element
element.replaceWith(newDiv);          // Replace element

// Removing elements
element.remove();                     // Remove element
parentElement.removeChild(element);   // Old way

// Cloning elements
const clone = element.cloneNode(true); // Deep clone with children
const shallowClone = element.cloneNode(false); // Shallow clone

// Document fragments (performance optimization)
const fragment = document.createDocumentFragment();
for (let i = 0; i < 1000; i++) {
    const li = document.createElement('li');
    li.textContent = `Item ${i}`;
    fragment.appendChild(li);
}
ul.appendChild(fragment); // Single DOM operation

// Template element
const template = document.querySelector('#myTemplate');
const clone = template.content.cloneNode(true);
document.body.appendChild(clone);
```

---

## Error Handling

### Try/Catch

```javascript
// Basic try/catch
try {
    let result = riskyOperation();
    console.log(result);
} catch (error) {
    console.error('An error occurred:', error.message);
} finally {
    console.log('This always runs');
}

// Catching specific error types
try {
    JSON.parse(invalidJson);
} catch (error) {
    if (error instanceof SyntaxError) {
        console.error('Invalid JSON syntax');
    } else if (error instanceof ReferenceError) {
        console.error('Reference error');
    } else {
        console.error('Unknown error:', error);
    }
}

// Async/await with try/catch
async function fetchData() {
    try {
        const response = await fetch('/api/data');
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Fetch failed:', error);
        throw error; // Re-throw if needed
    }
}

// Nested try/catch
function processFile(filename) {
    try {
        const content = readFile(filename);
        try {
            const parsed = JSON.parse(content);
            return parsed;
        } catch (parseError) {
            console.error('Parse error:', parseError.message);
            return null;
        }
    } catch (fileError) {
        console.error('File error:', fileError.message);
        return null;
    }
}
```

### Custom Errors

```javascript
// Custom error class
class ValidationError extends Error {
    constructor(message, field) {
        super(message);
        this.name = 'ValidationError';
        this.field = field;
    }
}

class NetworkError extends Error {
    constructor(message, statusCode) {
        super(message);
        this.name = 'NetworkError';
        this.statusCode = statusCode;
    }
}

// Using custom errors
function validateUser(user) {
    if (!user.email) {
        throw new ValidationError('Email is required', 'email');
    }
    if (!user.email.includes('@')) {
        throw new ValidationError('Invalid email format', 'email');
    }
}

// Error factory function
function createError(type, message, extra = {}) {
    const error = new Error(message);
    error.type = type;
    Object.assign(error, extra);
    return error;
}

// Handling custom errors
try {
    validateUser({ name: 'John' });
} catch (error) {
    if (error instanceof ValidationError) {
        console.error(`Validation failed for ${error.field}: ${error.message}`);
    } else {
        console.error('Unexpected error:', error);
    }
}
```

### Debugging

```javascript
// Console methods
console.log('Basic logging');
console.info('Information');
console.warn('Warning message');
console.error('Error message');

// Structured logging
console.table([
    { name: 'John', age: 30 },
    { name: 'Jane', age: 25 }
]);

console.group('User Data');
console.log('Name: John');
console.log('Age: 30');
console.groupEnd();

// Timing
console.time('operation');
// ... some operation
console.timeEnd('operation'); // Logs elapsed time

// Assertions
console.assert(user.age > 0, 'Age must be positive');

// Stack trace
console.trace('Trace point reached');

// Conditional logging
const DEBUG = true;
DEBUG && console.log('Debug information');

// Object inspection
console.dir(complexObject, { depth: 3 });

// Performance monitoring
function measurePerformance(fn, ...args) {
    const start = performance.now();
    const result = fn(...args);
    const end = performance.now();
    console.log(`Function took ${end - start} milliseconds`);
    return result;
}

// Error boundaries for debugging
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    console.log('Script:', event.filename);
    console.log('Line:', event.lineno);
    console.log('Column:', event.colno);
});

// Promise rejection handling
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    event.preventDefault(); // Prevent default browser behavior
});

// Debugger statement
function complexFunction(data) {
    // Process data
    debugger; // Execution will pause here in dev tools
    return processedData;
}
```

---

## Advanced Concepts

### Prototypes and Inheritance

```javascript
// Constructor function and prototype
function Person(name, age) {
    this.name = name;
    this.age = age;
}

Person.prototype.greet = function() {
    return `Hello, I'm ${this.name}`;
};

Person.prototype.getAge = function() {
    return this.age;
};

// Inheritance with constructor functions
function Student(name, age, grade) {
    Person.call(this, name, age); // Call parent constructor
    this.grade = grade;
}

// Set up prototype chain
Student.prototype = Object.create(Person.prototype);
Student.prototype.constructor = Student;

Student.prototype.study = function() {
    return `${this.name} is studying`;
};

// Prototype chain checking
const student = new Student('Alice', 20, 'A');
console.log(student instanceof Student); // true
console.log(student instanceof Person);  // true

// Object.getPrototypeOf and isPrototypeOf
console.log(Object.getPrototypeOf(student) === Student.prototype); // true
console.log(Person.prototype.isPrototypeOf(student)); // true

// Modern class syntax (same prototype chain)
class ModernPerson {
    constructor(name, age) {
        this.name = name;
        this.age = age;
    }

    greet() {
        return `Hello, I'm ${this.name}`;
    }
}

// Prototype manipulation
Object.setPrototypeOf(obj, newPrototype);
console.log(obj.hasOwnProperty('property'));
```

### Regular Expressions

```javascript
// Creating regex patterns
const pattern1 = /hello/i;                    // Literal notation
const pattern2 = new RegExp('hello', 'i');    // Constructor

// Common patterns
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const phonePattern = /^\(\d{3}\)\s\d{3}-\d{4}$/;
const urlPattern = /https?:\/\/(www\.)?[\w\-]+(\.[\w\-]+)+[/#?]?.*$/;

// String methods with regex
const text = "Hello World 123";
console.log(text.match(/\d+/));           // ["123"]
console.log(text.search(/world/i));       // 6
console.log(text.replace(/\d+/, 'ABC'));  // "Hello World ABC"
console.log(text.split(/\s+/));           // ["Hello", "World", "123"]

// Regex methods
const regex = /(\d{4})-(\d{2})-(\d{2})/;
const dateString = "2023-12-25";

console.log(regex.test(dateString));      // true
console.log(regex.exec(dateString));      // ["2023-12-25", "2023", "12", "25"]

// Global and sticky flags
const globalRegex = /\d+/g;
const text2 = "123 456 789";
console.log(text2.match(globalRegex));    // ["123", "456", "789"]

// Named capture groups
const nameRegex = /(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})/;
const match = nameRegex.exec("2023-12-25");
console.log(match.groups); // { year: "2023", month: "12", day: "25" }

// Lookahead and lookbehind
const positiveLookahead = /\d+(?=px)/;     // Digits followed by "px"
const negativeLookahead = /\d+(?!px)/;     // Digits not followed by "px"
const positiveLookbehind = /(?<=\$)\d+/;   // Digits preceded by "$"
const negativeLookbehind = /(?<!\$)\d+/;   // Digits not preceded by "$"
```

### JSON

```javascript
// JSON.stringify
const obj = {
    name: "John",
    age: 30,
    hobbies: ["reading", "coding"],
    address: { city: "New York", zip: "10001" }
};

const jsonString = JSON.stringify(obj);
console.log(jsonString);

// JSON.stringify with replacer function
const jsonWithReplacer = JSON.stringify(obj, (key, value) => {
    if (key === 'age') return undefined; // Exclude age
    return value;
});

// JSON.stringify with space parameter (pretty print)
const prettyJson = JSON.stringify(obj, null, 2);

// JSON.parse
const parsed = JSON.parse(jsonString);

// JSON.parse with reviver function
const parsedWithReviver = JSON.parse(jsonString, (key, value) => {
    if (key === 'age') return value * 2; // Transform age
    return value;
});

// Handling dates in JSON
const objWithDate = {
    name: "Event",
    date: new Date()
};

const jsonWithDate = JSON.stringify(objWithDate);
const parsedWithDate = JSON.parse(jsonWithDate, (key, value) => {
    if (key === 'date') return new Date(value);
    return value;
});

// Safe JSON parsing
function safeJsonParse(str, defaultValue = null) {
    try {
        return JSON.parse(str);
    } catch (error) {
        console.error('JSON parse error:', error);
        return defaultValue;
    }
}
```

### Local Storage

```javascript
// Storing data
localStorage.setItem('username', 'john_doe');
localStorage.setItem('preferences', JSON.stringify({
    theme: 'dark',
    language: 'en'
}));

// Retrieving data
const username = localStorage.getItem('username');
const preferences = JSON.parse(localStorage.getItem('preferences') || '{}');

// Removing data
localStorage.removeItem('username');
localStorage.clear(); // Clear all

// Storage helper functions
const storage = {
    set(key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
        } catch (error) {
            console.error('Storage set error:', error);
        }
    },

    get(key, defaultValue = null) {
        try {
            const item = localStorage.getItem(key);
            return item ? JSON.parse(item) : defaultValue;
        } catch (error) {
            console.error('Storage get error:', error);
            return defaultValue;
        }
    },

    remove(key) {
        localStorage.removeItem(key);
    },

    clear() {
        localStorage.clear();
    }
};

// Session storage (similar API, but session-scoped)
sessionStorage.setItem('temp_data', 'temporary');
const tempData = sessionStorage.getItem('temp_data');

// Storage events (listen for changes across tabs)
window.addEventListener('storage', (event) => {
    console.log('Storage changed:', {
        key: event.key,
        oldValue: event.oldValue,
        newValue: event.newValue,
        url: event.url
    });
});

// Check storage availability
function isStorageAvailable(type) {
    try {
        const storage = window[type];
        const x = '__storage_test__';
        storage.setItem(x, x);
        storage.removeItem(x);
        return true;
    } catch (e) {
        return false;
    }
}

console.log('localStorage available:', isStorageAvailable('localStorage'));
console.log('sessionStorage available:', isStorageAvailable('sessionStorage'));
```

### Higher-Order Functions

```javascript
// Functions that take other functions as arguments
function withLogging(fn) {
    return function(...args) {
        console.log(`Calling ${fn.name} with:`, args);
        const result = fn.apply(this, args);
        console.log(`Result:`, result);
        return result;
    };
}

const add = (a, b) => a + b;
const loggedAdd = withLogging(add);
console.log(loggedAdd(3, 4)); // Logs function call and result

// Memoization
function memoize(fn) {
    const cache = new Map();
    return function(...args) {
        const key = JSON.stringify(args);
        if (cache.has(key)) {
            return cache.get(key);
        }
        const result = fn.apply(this, args);
        cache.set(key, result);
        return result;
    };
}

const expensiveFunction = memoize((n) => {
    console.log(`Computing for ${n}`);
    return n * n;
});

// Debouncing
function debounce(fn, delay) {
    let timeoutId;
    return function(...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => fn.apply(this, args), delay);
    };
}

const debouncedSearch = debounce((query) => {
    console.log('Searching for:', query);
}, 300);

// Throttling
function throttle(fn, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            fn.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

const throttledScroll = throttle(() => {
    console.log('Scroll event');
}, 100);

// Currying
function curry(fn) {
    return function curried(...args) {
        if (args.length >= fn.length) {
            return fn.apply(this, args);
        } else {
            return function(...nextArgs) {
                return curried.apply(this, args.concat(nextArgs));
            };
        }
    };
}

const multiply = (a, b, c) => a * b * c;
const curriedMultiply = curry(multiply);
console.log(curriedMultiply(2)(3)(4)); // 24

// Partial application
function partial(fn, ...presetArgs) {
    return function(...remainingArgs) {
        return fn(...presetArgs, ...remainingArgs);
    };
}

const greet = (greeting, name) => `${greeting}, ${name}!`;
const sayHello = partial(greet, 'Hello');
console.log(sayHello('Alice')); // "Hello, Alice!"

// Composition
function compose(...fns) {
    return function(value) {
        return fns.reduceRight((acc, fn) => fn(acc), value);
    };
}

const addOne = x => x + 1;
const multiplyByTwo = x => x * 2;
const square = x => x * x;

const composedFn = compose(square, multiplyByTwo, addOne);
console.log(composedFn(3)); // ((3 + 1) * 2)^2 = 64
```

---

## Modern JavaScript Patterns

### Module Pattern

```javascript
// IIFE Module Pattern
const UserModule = (function() {
    // Private variables
    let users = [];
    let currentId = 1;

    // Private functions
    function generateId() {
        return currentId++;
    }

    function validateUser(user) {
        return user.name && user.email;
    }

    // Public API
    return {
        addUser(name, email) {
            const user = {
                id: generateId(),
                name,
                email,
                createdAt: new Date()
            };

            if (validateUser(user)) {
                users.push(user);
                return user;
            }
            throw new Error('Invalid user data');
        },

        getUser(id) {
            return users.find(user => user.id === id);
        },

        getAllUsers() {
            return [...users]; // Return copy
        },

        removeUser(id) {
            const index = users.findIndex(user => user.id === id);
            if (index !== -1) {
                return users.splice(index, 1)[0];
            }
            return null;
        }
    };
})();

// Revealing Module Pattern
const CalculatorModule = (function() {
    let result = 0;

    function add(x) {
        result += x;
        return this;
    }

    function subtract(x) {
        result -= x;
        return this;
    }

    function multiply(x) {
        result *= x;
        return this;
    }

    function getResult() {
        return result;
    }

    function reset() {
        result = 0;
        return this;
    }

    // Reveal public methods
    return {
        add,
        subtract,
        multiply,
        getResult,
        reset
    };
})();

// ES6 Module Pattern
// math-utils.js
export const PI = 3.14159;

export class Calculator {
    constructor() {
        this.result = 0;
    }

    add(value) {
        this.result += value;
        return this;
    }

    getResult() {
        return this.result;
    }
}

export default function createCalculator() {
    return new Calculator();
}
```

### Factory Functions

```javascript
// Basic factory function
function createUser(name, email, role = 'user') {
    return {
        name,
        email,
        role,
        createdAt: new Date(),

        getInfo() {
            return `${this.name} (${this.email}) - ${this.role}`;
        },

        updateEmail(newEmail) {
            this.email = newEmail;
        },

        hasPermission(permission) {
            const permissions = {
                user: ['read'],
                admin: ['read', 'write', 'delete'],
                moderator: ['read', 'write']
            };
            return permissions[this.role]?.includes(permission) || false;
        }
    };
}

// Factory with private variables using closures
function createBankAccount(initialBalance = 0) {
    let balance = initialBalance;
    let transactions = [];

    return {
        deposit(amount) {
            if (amount > 0) {
                balance += amount;
                transactions.push({ type: 'deposit', amount, date: new Date() });
                return balance;
            }
            throw new Error('Amount must be positive');
        },

        withdraw(amount) {
            if (amount > 0 && amount <= balance) {
                balance -= amount;
                transactions.push({ type: 'withdrawal', amount, date: new Date() });
                return balance;
            }
            throw new Error('Invalid withdrawal amount');
        },

        getBalance() {
            return balance;
        },

        getTransactionHistory() {
            return [...transactions]; // Return copy
        }
    };
}

// Factory with composition
function createComponent(type) {
    const base = {
        type,
        id: Math.random().toString(36).substr(2, 9),
        created: new Date(),

        render() {
            return `<${this.type} id="${this.id}"></${this.type}>`;
        }
    };

    // Add specific behavior based on type
    const behaviors = {
        button: {
            click() {
                console.log(`Button ${this.id} clicked`);
            }
        },
        input: {
            setValue(value) {
                this.value = value;
            },
            getValue() {
                return this.value || '';
            }
        },
        modal: {
            show() {
                this.visible = true;
            },
            hide() {
                this.visible = false;
            }
        }
    };

    return Object.assign(base, behaviors[type] || {});
}

const button = createComponent('button');
const input = createComponent('input');
const modal = createComponent('modal');
```

### Observer Pattern

```javascript
// Event Emitter/Observer implementation
class EventEmitter {
    constructor() {
        this.events = {};
    }

    on(event, callback) {
        if (!this.events[event]) {
            this.events[event] = [];
        }
        this.events[event].push(callback);
    }

    off(event, callback) {
        if (this.events[event]) {
            this.events[event] = this.events[event].filter(cb => cb !== callback);
        }
    }

    emit(event, ...args) {
        if (this.events[event]) {
            this.events[event].forEach(callback => {
                try {
                    callback(...args);
                } catch (error) {
                    console.error('Error in event callback:', error);
                }
            });
        }
    }

    once(event, callback) {
        const onceCallback = (...args) => {
            callback(...args);
            this.off(event, onceCallback);
        };
        this.on(event, onceCallback);
    }
}

// Usage example
const emitter = new EventEmitter();

emitter.on('user:login', (user) => {
    console.log(`User ${user.name} logged in`);
});

emitter.on('user:login', (user) => {
    updateUI(user);
});

emitter.emit('user:login', { name: 'John', id: 123 });

// Observable pattern for state management
class Store {
    constructor(initialState = {}) {
        this.state = initialState;
        this.observers = [];
    }

    subscribe(observer) {
        this.observers.push(observer);
        return () => {
            this.observers = this.observers.filter(obs => obs !== observer);
        };
    }

    setState(newState) {
        this.state = { ...this.state, ...newState };
        this.notify();
    }

    getState() {
        return { ...this.state };
    }

    notify() {
        this.observers.forEach(observer => {
            try {
                observer(this.state);
            } catch (error) {
                console.error('Error in observer:', error);
            }
        });
    }
}

// Usage
const store = new Store({ count: 0, user: null });

const unsubscribe = store.subscribe((state) => {
    console.log('State updated:', state);
});

store.setState({ count: 1 });
store.setState({ user: { name: 'Alice' } });
```

### Performance Optimization

```javascript
// Lazy loading with Intersection Observer
function createLazyLoader() {
    const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const img = entry.target;
                img.src = img.dataset.src;
                img.classList.remove('lazy');
                observer.unobserve(img);
            }
        });
    });

    return {
        observe(element) {
            imageObserver.observe(element);
        }
    };
}

// Efficient DOM updates with DocumentFragment
function efficientDOMUpdate(container, items) {
    const fragment = document.createDocumentFragment();

    items.forEach(item => {
        const element = document.createElement('div');
        element.textContent = item.name;
        element.className = 'item';
        fragment.appendChild(element);
    });

    container.appendChild(fragment);
}

// Virtual scrolling for large lists
class VirtualList {
    constructor(container, items, itemHeight = 50) {
        this.container = container;
        this.items = items;
        this.itemHeight = itemHeight;
        this.viewportHeight = container.clientHeight;
        this.visibleCount = Math.ceil(this.viewportHeight / itemHeight) + 1;

        this.setupScrolling();
        this.render();
    }

    setupScrolling() {
        this.container.addEventListener('scroll', this.onScroll.bind(this));
    }

    onScroll() {
        requestAnimationFrame(() => this.render());
    }

    render() {
        const scrollTop = this.container.scrollTop;
        const startIndex = Math.floor(scrollTop / this.itemHeight);
        const endIndex = Math.min(startIndex + this.visibleCount, this.items.length);

        this.container.innerHTML = '';

        for (let i = startIndex; i < endIndex; i++) {
            const item = document.createElement('div');
            item.style.height = `${this.itemHeight}px`;
            item.style.transform = `translateY(${i * this.itemHeight}px)`;
            item.textContent = this.items[i];
            this.container.appendChild(item);
        }
    }
}

// Web Workers for heavy computations
function createWorker(workerFunction) {
    const blob = new Blob([`
        self.onmessage = function(e) {
            const result = (${workerFunction.toString()})(e.data);
            self.postMessage(result);
        }
    `], { type: 'application/javascript' });

    return new Worker(URL.createObjectURL(blob));
}

// Heavy computation function
function heavyComputation(data) {
    // Simulate heavy work
    let result = 0;
    for (let i = 0; i < data.iterations; i++) {
        result += Math.sqrt(i);
    }
    return result;
}

// Usage
const worker = createWorker(heavyComputation);
worker.postMessage({ iterations: 1000000 });
worker.onmessage = (e) => {
    console.log('Result from worker:', e.data);
    worker.terminate();
};

// Request Animation Frame for smooth animations
function smoothAnimation(element, from, to, duration = 1000) {
    const startTime = performance.now();

    function animate(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Easing function (ease-out)
        const eased = 1 - Math.pow(1 - progress, 3);

        const current = from + (to - from) * eased;
        element.style.transform = `translateX(${current}px)`;

        if (progress < 1) {
            requestAnimationFrame(animate);
        }
    }

    requestAnimationFrame(animate);
}

// Memory management and cleanup
class ComponentManager {
    constructor() {
        this.components = new Map();
        this.cleanup = new Map();
    }

    create(id, component) {
        this.components.set(id, component);

        // Store cleanup functions
        const cleanupFunctions = [];

        if (component.intervals) {
            component.intervals.forEach(interval => {
                cleanupFunctions.push(() => clearInterval(interval));
            });
        }

        if (component.timeouts) {
            component.timeouts.forEach(timeout => {
                cleanupFunctions.push(() => clearTimeout(timeout));
            });
        }

        if (component.listeners) {
            component.listeners.forEach(({ element, event, handler }) => {
                cleanupFunctions.push(() => element.removeEventListener(event, handler));
            });
        }

        this.cleanup.set(id, cleanupFunctions);
    }

    destroy(id) {
        const component = this.components.get(id);
        const cleanupFunctions = this.cleanup.get(id);

        if (cleanupFunctions) {
            cleanupFunctions.forEach(cleanup => cleanup());
        }

        this.components.delete(id);
        this.cleanup.delete(id);
    }

    destroyAll() {
        this.components.forEach((_, id) => this.destroy(id));
    }
}
```