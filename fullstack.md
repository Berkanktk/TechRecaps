# Fullstack Development Recap

## Table of Contents

1. [Frontend Fundamentals](#frontend-fundamentals)
   1. [HTML5](#html5)
      1. [Semantic Elements](#semantic-elements)
      2. [Forms and Input Types](#forms-and-input-types)
      3. [APIs and Storage](#apis-and-storage)
   2. [CSS3](#css3)
      1. [Selectors and Specificity](#selectors-and-specificity)
      2. [Flexbox](#flexbox)
      3. [Grid](#grid)
      4. [Responsive Design](#responsive-design)
      5. [Animations and Transitions](#animations-and-transitions)
   3. [JavaScript ES6+](#javascript-es6)
      1. [Variables and Scope](#variables-and-scope)
      2. [Functions and Arrow Functions](#functions-and-arrow-functions)
      3. [Promises and Async/Await](#promises-and-asyncawait)
      4. [Modules](#modules)
      5. [DOM Manipulation](#dom-manipulation)
2. [Frontend Frameworks](#frontend-frameworks)
   1. [React](#react)
      1. [Components and JSX](#components-and-jsx)
      2. [State and Props](#state-and-props)
      3. [Hooks](#hooks)
      4. [Context API](#context-api)
      5. [React Router](#react-router)
   2. [Vue.js](#vuejs)
      1. [Templates and Directives](#templates-and-directives)
      2. [Components](#components)
      3. [Vuex State Management](#vuex-state-management)
      4. [Vue Router](#vue-router)
   3. [Angular](#angular)
      1. [Components and Templates](#components-and-templates)
      2. [Services and Dependency Injection](#services-and-dependency-injection)
      3. [RxJS and Observables](#rxjs-and-observables)
      4. [Angular Router](#angular-router)
3. [Backend Development](#backend-development)
   1. [Node.js](#nodejs)
      1. [Express.js Framework](#expressjs-framework)
      2. [Middleware](#middleware)
      3. [Error Handling](#error-handling)
   2. [Python](#python)
      1. [Django Framework](#django-framework)
      2. [Flask Framework](#flask-framework)
      3. [FastAPI](#fastapi)
   3. [Java](#java)
      1. [Spring Boot](#spring-boot)
      2. [Spring Security](#spring-security)
   4. [C# .NET](#c-net)
      1. [ASP.NET Core](#aspnet-core)
      2. [Entity Framework](#entity-framework)
   5. [PHP](#php)
      1. [Laravel Framework](#laravel-framework)
      2. [Symfony](#symfony)
4. [Databases](#databases)
   1. [SQL Databases](#sql-databases)
      1. [MySQL](#mysql)
      2. [PostgreSQL](#postgresql)
      3. [SQL Server](#sql-server)
      4. [SQLite](#sqlite)
   2. [NoSQL Databases](#nosql-databases)
      1. [MongoDB](#mongodb)
      2. [Redis](#redis)
      3. [Cassandra](#cassandra)
      4. [Firebase Firestore](#firebase-firestore)
   3. [Database Design](#database-design)
      1. [Normalization](#normalization)
      2. [Indexing](#indexing)
      3. [Query Optimization](#query-optimization)
5. [API Development](#api-development)
   1. [REST APIs](#rest-apis)
      1. [HTTP Methods](#http-methods)
      2. [Status Codes](#status-codes)
      3. [API Design Best Practices](#api-design-best-practices)
   2. [GraphQL](#graphql)
      1. [Queries and Mutations](#queries-and-mutations)
      2. [Schema Design](#schema-design)
   3. [API Testing](#api-testing)
      1. [Postman](#postman)
      2. [Jest/Mocha Testing](#jestmocha-testing)
      3. [API Documentation](#api-documentation)
6. [Authentication and Security](#authentication-and-security)
   1. [Authentication Methods](#authentication-methods)
      1. [Session-based Authentication](#session-based-authentication)
      2. [JWT Tokens](#jwt-tokens)
      3. [OAuth 2.0](#oauth-20)
   2. [Security Best Practices](#security-best-practices)
      1. [Input Validation](#input-validation)
      2. [SQL Injection Prevention](#sql-injection-prevention)
      3. [XSS Protection](#xss-protection)
      4. [CSRF Protection](#csrf-protection)
   3. [HTTPS and SSL](#https-and-ssl)
7. [DevOps and Deployment](#devops-and-deployment)
   1. [Version Control](#version-control)
      1. [Git Workflow](#git-workflow)
      2. [Branching Strategies](#branching-strategies)
   2. [Containerization](#containerization)
      1. [Docker](#docker)
      2. [Docker Compose](#docker-compose)
      3. [Kubernetes](#kubernetes)
   3. [Cloud Platforms](#cloud-platforms)
      1. [AWS](#aws)
      2. [Google Cloud Platform](#google-cloud-platform)
      3. [Microsoft Azure](#microsoft-azure)
      4. [Vercel/Netlify](#vercelnetlify)
   4. [CI/CD](#cicd)
      1. [GitHub Actions](#github-actions)
      2. [Jenkins](#jenkins)
      3. [GitLab CI](#gitlab-ci)
8. [Testing](#testing)
   1. [Frontend Testing](#frontend-testing)
      1. [Unit Testing](#unit-testing)
      2. [Integration Testing](#integration-testing)
      3. [E2E Testing](#e2e-testing)
   2. [Backend Testing](#backend-testing)
      1. [API Testing](#api-testing-1)
      2. [Database Testing](#database-testing)
   3. [Testing Tools](#testing-tools)
      1. [Jest](#jest)
      2. [Cypress](#cypress)
      3. [Selenium](#selenium)
9. [Performance Optimization](#performance-optimization)
   1. [Frontend Performance](#frontend-performance)
      1. [Code Splitting](#code-splitting)
      2. [Lazy Loading](#lazy-loading)
      3. [Image Optimization](#image-optimization)
   2. [Backend Performance](#backend-performance)
      1. [Caching Strategies](#caching-strategies)
      2. [Database Optimization](#database-optimization)
      3. [Load Balancing](#load-balancing)
10. [Development Tools](#development-tools)
    1. [Code Editors](#code-editors)
    2. [Build Tools](#build-tools)
    3. [Package Managers](#package-managers)
    4. [Debugging Tools](#debugging-tools)

---

## Frontend Fundamentals

### HTML5

**HTML5** is the latest version of HyperText Markup Language, providing semantic elements, multimedia support, and enhanced APIs.

#### Semantic Elements

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Semantic HTML5</title>
</head>
<body>
    <header>
        <nav>
            <ul>
                <li><a href="#home">Home</a></li>
                <li><a href="#about">About</a></li>
                <li><a href="#contact">Contact</a></li>
            </ul>
        </nav>
    </header>

    <main>
        <article>
            <section>
                <h1>Article Title</h1>
                <p>Article content...</p>
            </section>
        </article>

        <aside>
            <h2>Related Links</h2>
            <ul>
                <li><a href="#">Link 1</a></li>
                <li><a href="#">Link 2</a></li>
            </ul>
        </aside>
    </main>

    <footer>
        <p>&copy; 2024 Company Name</p>
    </footer>
</body>
</html>
```

**Key Semantic Elements:**
- `<header>`, `<nav>`, `<main>`, `<article>`, `<section>`, `<aside>`, `<footer>`
- `<figure>`, `<figcaption>`, `<details>`, `<summary>`
- `<time>`, `<mark>`, `<progress>`

#### Forms and Input Types

```html
<form action="/submit" method="POST">
    <!-- Text inputs -->
    <input type="text" name="username" placeholder="Username" required>
    <input type="email" name="email" placeholder="Email" required>
    <input type="password" name="password" placeholder="Password" required>

    <!-- HTML5 input types -->
    <input type="date" name="birthdate">
    <input type="number" name="age" min="18" max="100">
    <input type="range" name="experience" min="0" max="10">
    <input type="color" name="favorite-color">
    <input type="file" name="resume" accept=".pdf,.doc,.docx">

    <!-- Form validation -->
    <input type="url" name="website" pattern="https://.*">
    <input type="tel" name="phone" pattern="[0-9]{3}-[0-9]{3}-[0-9]{4}">

    <textarea name="bio" placeholder="Tell us about yourself"></textarea>

    <select name="country">
        <option value="us">United States</option>
        <option value="ca">Canada</option>
        <option value="uk">United Kingdom</option>
    </select>

    <input type="submit" value="Submit">
</form>
```

#### APIs and Storage

```javascript
// Local Storage
localStorage.setItem('username', 'john_doe');
const username = localStorage.getItem('username');

// Session Storage
sessionStorage.setItem('sessionId', '123456');

// Geolocation API
navigator.geolocation.getCurrentPosition(
    position => {
        const lat = position.coords.latitude;
        const lng = position.coords.longitude;
        console.log(`Location: ${lat}, ${lng}`);
    },
    error => console.error('Error getting location:', error)
);

// Fetch API
fetch('/api/users')
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error('Error:', error));
```

### CSS3

#### Selectors and Specificity

```css
/* Basic selectors */
.class-name { color: blue; }
#id-name { color: red; }
element { color: green; }

/* Attribute selectors */
input[type="email"] { border: 1px solid blue; }
a[href^="https"] { color: green; }
img[alt$="logo"] { max-width: 200px; }

/* Pseudo-classes */
a:hover { text-decoration: underline; }
li:nth-child(odd) { background-color: #f0f0f0; }
input:focus { outline: 2px solid blue; }
input:valid { border-color: green; }
input:invalid { border-color: red; }

/* Pseudo-elements */
p::first-line { font-weight: bold; }
p::before { content: "→ "; }
p::after { content: " ←"; }

/* Combinators */
div > p { margin: 0; } /* Direct child */
h1 + p { margin-top: 0; } /* Adjacent sibling */
h1 ~ p { color: gray; } /* General sibling */
```

**Specificity Calculation:**
- Inline styles: 1000
- IDs: 100
- Classes, attributes, pseudo-classes: 10
- Elements, pseudo-elements: 1

#### Flexbox

```css
.container {
    display: flex;

    /* Direction */
    flex-direction: row | row-reverse | column | column-reverse;

    /* Wrap */
    flex-wrap: nowrap | wrap | wrap-reverse;

    /* Shorthand */
    flex-flow: row wrap;

    /* Justify content (main axis) */
    justify-content: flex-start | flex-end | center | space-between | space-around | space-evenly;

    /* Align items (cross axis) */
    align-items: stretch | flex-start | flex-end | center | baseline;

    /* Align content (multiple lines) */
    align-content: flex-start | flex-end | center | space-between | space-around | stretch;
}

.item {
    /* Flex grow */
    flex-grow: 1;

    /* Flex shrink */
    flex-shrink: 0;

    /* Flex basis */
    flex-basis: 200px;

    /* Shorthand */
    flex: 1 0 200px;

    /* Individual alignment */
    align-self: auto | flex-start | flex-end | center | baseline | stretch;
}
```

#### Grid

```css
.grid-container {
    display: grid;

    /* Define grid template */
    grid-template-columns: 1fr 2fr 1fr;
    grid-template-rows: 100px auto 50px;

    /* Gap between grid items */
    gap: 20px;
    grid-column-gap: 20px;
    grid-row-gap: 10px;

    /* Named grid lines */
    grid-template-columns: [sidebar-start] 250px [sidebar-end main-start] 1fr [main-end];

    /* Grid areas */
    grid-template-areas:
        "header header header"
        "sidebar main main"
        "footer footer footer";
}

.grid-item {
    /* Position by line numbers */
    grid-column: 1 / 3;
    grid-row: 2 / 4;

    /* Position by named lines */
    grid-column: sidebar-start / main-end;

    /* Position by area name */
    grid-area: header;

    /* Justify and align individual items */
    justify-self: start | end | center | stretch;
    align-self: start | end | center | stretch;
}

/* Responsive grid */
.responsive-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
}
```

#### Responsive Design

```css
/* Mobile-first approach */
.container {
    width: 100%;
    padding: 0 15px;
}

/* Tablet */
@media (min-width: 768px) {
    .container {
        max-width: 750px;
        margin: 0 auto;
    }
}

/* Desktop */
@media (min-width: 1024px) {
    .container {
        max-width: 1200px;
    }
}

/* Common breakpoints */
@media (max-width: 576px) { /* Extra small devices */ }
@media (min-width: 577px) and (max-width: 768px) { /* Small devices */ }
@media (min-width: 769px) and (max-width: 1024px) { /* Medium devices */ }
@media (min-width: 1025px) { /* Large devices */ }

/* Responsive images */
img {
    max-width: 100%;
    height: auto;
}

/* Responsive typography */
html {
    font-size: 16px;
}

@media (min-width: 768px) {
    html {
        font-size: 18px;
    }
}

/* CSS Custom Properties (Variables) */
:root {
    --primary-color: #007bff;
    --secondary-color: #6c757d;
    --font-size-base: 1rem;
}

.button {
    background-color: var(--primary-color);
    font-size: var(--font-size-base);
}
```

#### Animations and Transitions

```css
/* Transitions */
.button {
    background-color: blue;
    transition: background-color 0.3s ease, transform 0.2s ease;
}

.button:hover {
    background-color: darkblue;
    transform: translateY(-2px);
}

/* Keyframe animations */
@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.fade-in {
    animation: fadeIn 0.5s ease-out forwards;
}

/* Complex animation */
@keyframes bounce {
    0%, 20%, 50%, 80%, 100% {
        transform: translateY(0);
    }
    40% {
        transform: translateY(-30px);
    }
    60% {
        transform: translateY(-15px);
    }
}

.bounce {
    animation: bounce 2s infinite;
}

/* Animation properties */
.animated-element {
    animation-name: slideIn;
    animation-duration: 1s;
    animation-timing-function: ease-in-out;
    animation-delay: 0.5s;
    animation-iteration-count: infinite;
    animation-direction: alternate;
    animation-fill-mode: both;
    animation-play-state: running;

    /* Shorthand */
    animation: slideIn 1s ease-in-out 0.5s infinite alternate both;
}
```

### JavaScript ES6+

#### Variables and Scope

```javascript
// Variable declarations
let variableName = 'can be reassigned';
const constantName = 'cannot be reassigned';
var oldStyle = 'function scoped, avoid using';

// Block scope
if (true) {
    let blockScoped = 'only accessible within this block';
    const alsoBlockScoped = 'same here';
    var functionScoped = 'accessible throughout function';
}

// Destructuring assignment
const person = { name: 'John', age: 30, city: 'New York' };
const { name, age } = person;
const { name: personName, age: personAge } = person; // Rename

const numbers = [1, 2, 3, 4, 5];
const [first, second, ...rest] = numbers;

// Template literals
const greeting = `Hello, ${name}! You are ${age} years old.`;
const multiline = `
    This is a
    multiline string
    with ${name}
`;

// Default parameters
function greet(name = 'Guest', greeting = 'Hello') {
    return `${greeting}, ${name}!`;
}

// Rest parameters
function sum(...numbers) {
    return numbers.reduce((total, num) => total + num, 0);
}

// Spread operator
const arr1 = [1, 2, 3];
const arr2 = [4, 5, 6];
const combined = [...arr1, ...arr2];

const obj1 = { a: 1, b: 2 };
const obj2 = { c: 3, d: 4 };
const merged = { ...obj1, ...obj2 };
```

#### Functions and Arrow Functions

```javascript
// Function declaration
function traditionalFunction(param) {
    return param * 2;
}

// Function expression
const functionExpression = function(param) {
    return param * 2;
};

// Arrow functions
const arrowFunction = (param) => param * 2;
const multipleParams = (a, b) => a + b;
const singleParam = param => param * 2; // Parentheses optional for single param
const noParams = () => 'Hello World';

// Block body arrow function
const complexArrowFunction = (param) => {
    const result = param * 2;
    return result;
};

// Arrow functions and 'this' context
class Counter {
    constructor() {
        this.count = 0;
    }

    // Arrow function preserves 'this' context
    increment = () => {
        this.count++;
    }

    // Traditional function has its own 'this'
    traditionalIncrement() {
        this.count++;
    }
}

// Higher-order functions
const numbers = [1, 2, 3, 4, 5];

const doubled = numbers.map(num => num * 2);
const evens = numbers.filter(num => num % 2 === 0);
const sum = numbers.reduce((total, num) => total + num, 0);

// Function currying
const multiply = (a) => (b) => a * b;
const double = multiply(2);
console.log(double(5)); // 10
```

#### Promises and Async/Await

```javascript
// Promise creation
const fetchUserData = (userId) => {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            if (userId > 0) {
                resolve({ id: userId, name: 'John Doe' });
            } else {
                reject(new Error('Invalid user ID'));
            }
        }, 1000);
    });
};

// Promise consumption
fetchUserData(1)
    .then(user => {
        console.log('User:', user);
        return fetchUserPosts(user.id);
    })
    .then(posts => {
        console.log('Posts:', posts);
    })
    .catch(error => {
        console.error('Error:', error);
    })
    .finally(() => {
        console.log('Request completed');
    });

// Async/Await
async function getUserWithPosts(userId) {
    try {
        const user = await fetchUserData(userId);
        const posts = await fetchUserPosts(user.id);
        return { user, posts };
    } catch (error) {
        console.error('Error:', error);
        throw error;
    }
}

// Parallel execution
async function fetchMultipleUsers() {
    try {
        const [user1, user2, user3] = await Promise.all([
            fetchUserData(1),
            fetchUserData(2),
            fetchUserData(3)
        ]);
        return [user1, user2, user3];
    } catch (error) {
        console.error('One or more requests failed:', error);
    }
}

// Promise.allSettled (ES2020)
async function fetchUsersWithResults() {
    const results = await Promise.allSettled([
        fetchUserData(1),
        fetchUserData(-1), // This will reject
        fetchUserData(3)
    ]);

    results.forEach((result, index) => {
        if (result.status === 'fulfilled') {
            console.log(`User ${index + 1}:`, result.value);
        } else {
            console.log(`User ${index + 1} failed:`, result.reason);
        }
    });
}

// Fetch API
async function apiCall() {
    try {
        const response = await fetch('/api/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer token'
            },
            body: JSON.stringify({ name: 'John', email: 'john@example.com' })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Fetch error:', error);
        throw error;
    }
}
```

#### Modules

```javascript
// math.js - Named exports
export const PI = 3.14159;
export const add = (a, b) => a + b;
export const subtract = (a, b) => a - b;

export function multiply(a, b) {
    return a * b;
}

// default export
export default function divide(a, b) {
    return a / b;
}

// utils.js - Export after declaration
function formatCurrency(amount) {
    return `$${amount.toFixed(2)}`;
}

function formatDate(date) {
    return date.toLocaleDateString();
}

export { formatCurrency, formatDate };

// Re-export
export { add, subtract } from './math.js';

// main.js - Importing
import divide, { PI, add, subtract, multiply } from './math.js';
import { formatCurrency, formatDate } from './utils.js';

// Rename imports
import { add as sum } from './math.js';

// Import all
import * as MathUtils from './math.js';

// Dynamic imports
async function loadModule() {
    const module = await import('./math.js');
    console.log(module.add(2, 3));
}

// Conditional imports
if (condition) {
    import('./heavy-module.js').then(module => {
        module.doSomething();
    });
}
```

#### DOM Manipulation

```javascript
// Selecting elements
const element = document.getElementById('myId');
const elements = document.getElementsByClassName('myClass');
const queryElement = document.querySelector('.my-class');
const queryElements = document.querySelectorAll('.my-class');

// Creating elements
const newDiv = document.createElement('div');
newDiv.textContent = 'Hello World';
newDiv.className = 'my-new-div';
newDiv.setAttribute('data-id', '123');

// Modifying elements
element.innerHTML = '<strong>Bold text</strong>';
element.textContent = 'Plain text';
element.style.color = 'red';
element.style.backgroundColor = 'yellow';

// CSS classes
element.classList.add('new-class');
element.classList.remove('old-class');
element.classList.toggle('active');
element.classList.contains('my-class');

// Attributes
element.getAttribute('data-id');
element.setAttribute('data-value', 'new-value');
element.removeAttribute('data-old');

// Adding to DOM
document.body.appendChild(newDiv);
element.insertBefore(newDiv, element.firstChild);
element.insertAdjacentHTML('beforeend', '<p>New paragraph</p>');

// Event handling
element.addEventListener('click', function(event) {
    event.preventDefault();
    console.log('Element clicked');
});

// Modern event handling with arrow functions
element.addEventListener('click', (event) => {
    event.stopPropagation();
    console.log('Event handled');
});

// Removing events
function handleClick(event) {
    console.log('Clicked');
}
element.addEventListener('click', handleClick);
element.removeEventListener('click', handleClick);

// Event delegation
document.addEventListener('click', (event) => {
    if (event.target.matches('.button')) {
        console.log('Button clicked');
    }
});

// Form handling
const form = document.querySelector('#myForm');
form.addEventListener('submit', (event) => {
    event.preventDefault();
    const formData = new FormData(form);
    const data = Object.fromEntries(formData);
    console.log(data);
});

// Modern DOM methods
element.closest('.parent-class'); // Find closest ancestor
element.matches('.my-class'); // Check if element matches selector
element.remove(); // Remove element from DOM
```

---

## Frontend Frameworks

### React

#### Components and JSX

```jsx
// Functional Component
import React from 'react';

function Welcome({ name, age }) {
    return (
        <div className="welcome">
            <h1>Hello, {name}!</h1>
            <p>You are {age} years old.</p>
        </div>
    );
}

// Component with conditional rendering
function UserProfile({ user, isLoggedIn }) {
    if (!isLoggedIn) {
        return <div>Please log in to view profile.</div>;
    }

    return (
        <div className="profile">
            <img src={user.avatar} alt={`${user.name}'s avatar`} />
            <h2>{user.name}</h2>
            <p>{user.email}</p>
            {user.isAdmin && <span className="admin-badge">Admin</span>}
        </div>
    );
}

// List rendering
function TodoList({ todos }) {
    return (
        <ul>
            {todos.map(todo => (
                <li key={todo.id} className={todo.completed ? 'completed' : ''}>
                    {todo.text}
                </li>
            ))}
        </ul>
    );
}

// Event handling
function Button({ onClick, children, disabled = false }) {
    const handleClick = (event) => {
        event.preventDefault();
        if (!disabled && onClick) {
            onClick(event);
        }
    };

    return (
        <button
            onClick={handleClick}
            disabled={disabled}
            className="btn"
        >
            {children}
        </button>
    );
}

export default Welcome;
```

#### State and Props

```jsx
import React, { useState, useEffect } from 'react';

// State with hooks
function Counter() {
    const [count, setCount] = useState(0);
    const [step, setStep] = useState(1);

    const increment = () => setCount(prev => prev + step);
    const decrement = () => setCount(prev => prev - step);
    const reset = () => setCount(0);

    return (
        <div>
            <h2>Count: {count}</h2>
            <input
                type="number"
                value={step}
                onChange={(e) => setStep(Number(e.target.value))}
                placeholder="Step"
            />
            <button onClick={increment}>+</button>
            <button onClick={decrement}>-</button>
            <button onClick={reset}>Reset</button>
        </div>
    );
}

// Complex state object
function UserForm() {
    const [user, setUser] = useState({
        name: '',
        email: '',
        age: 0
    });

    const updateUser = (field, value) => {
        setUser(prev => ({
            ...prev,
            [field]: value
        }));
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        console.log('User data:', user);
    };

    return (
        <form onSubmit={handleSubmit}>
            <input
                value={user.name}
                onChange={(e) => updateUser('name', e.target.value)}
                placeholder="Name"
            />
            <input
                type="email"
                value={user.email}
                onChange={(e) => updateUser('email', e.target.value)}
                placeholder="Email"
            />
            <input
                type="number"
                value={user.age}
                onChange={(e) => updateUser('age', parseInt(e.target.value))}
                placeholder="Age"
            />
            <button type="submit">Submit</button>
        </form>
    );
}

// Props validation with PropTypes
import PropTypes from 'prop-types';

function Product({ name, price, category, onAddToCart }) {
    return (
        <div className="product">
            <h3>{name}</h3>
            <p>Price: ${price}</p>
            <p>Category: {category}</p>
            <button onClick={() => onAddToCart({ name, price })}>
                Add to Cart
            </button>
        </div>
    );
}

Product.propTypes = {
    name: PropTypes.string.isRequired,
    price: PropTypes.number.isRequired,
    category: PropTypes.string,
    onAddToCart: PropTypes.func.isRequired
};

Product.defaultProps = {
    category: 'General'
};
```

#### Hooks

```jsx
import React, { useState, useEffect, useContext, useReducer, useCallback, useMemo, useRef } from 'react';

// useState - State management
function useCounter(initialValue = 0) {
    const [count, setCount] = useState(initialValue);

    const increment = useCallback(() => setCount(c => c + 1), []);
    const decrement = useCallback(() => setCount(c => c - 1), []);
    const reset = useCallback(() => setCount(initialValue), [initialValue]);

    return { count, increment, decrement, reset };
}

// useEffect - Side effects
function DataFetcher({ userId }) {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        let cancelled = false;

        async function fetchUser() {
            try {
                setLoading(true);
                const response = await fetch(`/api/users/${userId}`);
                const userData = await response.json();

                if (!cancelled) {
                    setUser(userData);
                    setError(null);
                }
            } catch (err) {
                if (!cancelled) {
                    setError(err.message);
                }
            } finally {
                if (!cancelled) {
                    setLoading(false);
                }
            }
        }

        fetchUser();

        // Cleanup function
        return () => {
            cancelled = true;
        };
    }, [userId]); // Dependency array

    if (loading) return <div>Loading...</div>;
    if (error) return <div>Error: {error}</div>;
    if (!user) return <div>User not found</div>;

    return <div>Welcome, {user.name}!</div>;
}

// useReducer - Complex state logic
const todoReducer = (state, action) => {
    switch (action.type) {
        case 'ADD_TODO':
            return [...state, { id: Date.now(), text: action.payload, completed: false }];
        case 'TOGGLE_TODO':
            return state.map(todo =>
                todo.id === action.payload
                    ? { ...todo, completed: !todo.completed }
                    : todo
            );
        case 'REMOVE_TODO':
            return state.filter(todo => todo.id !== action.payload);
        default:
            return state;
    }
};

function TodoApp() {
    const [todos, dispatch] = useReducer(todoReducer, []);
    const [inputText, setInputText] = useState('');

    const addTodo = () => {
        if (inputText.trim()) {
            dispatch({ type: 'ADD_TODO', payload: inputText });
            setInputText('');
        }
    };

    return (
        <div>
            <input
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && addTodo()}
            />
            <button onClick={addTodo}>Add Todo</button>
            <ul>
                {todos.map(todo => (
                    <li key={todo.id}>
                        <span
                            style={{ textDecoration: todo.completed ? 'line-through' : 'none' }}
                            onClick={() => dispatch({ type: 'TOGGLE_TODO', payload: todo.id })}
                        >
                            {todo.text}
                        </span>
                        <button onClick={() => dispatch({ type: 'REMOVE_TODO', payload: todo.id })}>
                            Delete
                        </button>
                    </li>
                ))}
            </ul>
        </div>
    );
}

// useRef - DOM references and mutable values
function FocusInput() {
    const inputRef = useRef(null);
    const countRef = useRef(0);

    useEffect(() => {
        inputRef.current.focus();
    }, []);

    const handleClick = () => {
        countRef.current += 1;
        console.log(`Button clicked ${countRef.current} times`);
        inputRef.current.focus();
    };

    return (
        <div>
            <input ref={inputRef} placeholder="Type here..." />
            <button onClick={handleClick}>Focus Input</button>
        </div>
    );
}

// useMemo - Expensive calculations
function ExpensiveComponent({ items, filterText }) {
    const filteredItems = useMemo(() => {
        console.log('Filtering items...'); // Only runs when items or filterText change
        return items.filter(item =>
            item.name.toLowerCase().includes(filterText.toLowerCase())
        );
    }, [items, filterText]);

    const itemCount = useMemo(() => filteredItems.length, [filteredItems]);

    return (
        <div>
            <p>Found {itemCount} items</p>
            <ul>
                {filteredItems.map(item => (
                    <li key={item.id}>{item.name}</li>
                ))}
            </ul>
        </div>
    );
}

// Custom hook
function useLocalStorage(key, initialValue) {
    const [storedValue, setStoredValue] = useState(() => {
        try {
            const item = window.localStorage.getItem(key);
            return item ? JSON.parse(item) : initialValue;
        } catch (error) {
            console.log(error);
            return initialValue;
        }
    });

    const setValue = (value) => {
        try {
            setStoredValue(value);
            window.localStorage.setItem(key, JSON.stringify(value));
        } catch (error) {
            console.log(error);
        }
    };

    return [storedValue, setValue];
}
```

#### Context API

```jsx
import React, { createContext, useContext, useReducer } from 'react';

// Create context
const AuthContext = createContext();
const ThemeContext = createContext();

// Auth context provider
const authReducer = (state, action) => {
    switch (action.type) {
        case 'LOGIN':
            return { ...state, user: action.payload, isAuthenticated: true };
        case 'LOGOUT':
            return { ...state, user: null, isAuthenticated: false };
        case 'UPDATE_PROFILE':
            return { ...state, user: { ...state.user, ...action.payload } };
        default:
            return state;
    }
};

export function AuthProvider({ children }) {
    const [state, dispatch] = useReducer(authReducer, {
        user: null,
        isAuthenticated: false
    });

    const login = async (credentials) => {
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(credentials)
            });
            const user = await response.json();
            dispatch({ type: 'LOGIN', payload: user });
        } catch (error) {
            console.error('Login failed:', error);
        }
    };

    const logout = () => {
        dispatch({ type: 'LOGOUT' });
    };

    const updateProfile = (updates) => {
        dispatch({ type: 'UPDATE_PROFILE', payload: updates });
    };

    return (
        <AuthContext.Provider value={{
            ...state,
            login,
            logout,
            updateProfile
        }}>
            {children}
        </AuthContext.Provider>
    );
}

// Theme context provider
export function ThemeProvider({ children }) {
    const [theme, setTheme] = useState('light');

    const toggleTheme = () => {
        setTheme(prev => prev === 'light' ? 'dark' : 'light');
    };

    const value = {
        theme,
        toggleTheme,
        colors: {
            primary: theme === 'light' ? '#007bff' : '#375a7f',
            background: theme === 'light' ? '#ffffff' : '#222222',
            text: theme === 'light' ? '#333333' : '#ffffff'
        }
    };

    return (
        <ThemeContext.Provider value={value}>
            {children}
        </ThemeContext.Provider>
    );
}

// Custom hooks for consuming context
export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

export const useTheme = () => {
    const context = useContext(ThemeContext);
    if (!context) {
        throw new Error('useTheme must be used within a ThemeProvider');
    }
    return context;
};

// Components using context
function LoginForm() {
    const { login, isAuthenticated } = useAuth();
    const [credentials, setCredentials] = useState({ email: '', password: '' });

    if (isAuthenticated) {
        return <div>Already logged in!</div>;
    }

    const handleSubmit = (e) => {
        e.preventDefault();
        login(credentials);
    };

    return (
        <form onSubmit={handleSubmit}>
            <input
                type="email"
                value={credentials.email}
                onChange={(e) => setCredentials(prev => ({ ...prev, email: e.target.value }))}
                placeholder="Email"
            />
            <input
                type="password"
                value={credentials.password}
                onChange={(e) => setCredentials(prev => ({ ...prev, password: e.target.value }))}
                placeholder="Password"
            />
            <button type="submit">Login</button>
        </form>
    );
}

function Header() {
    const { user, isAuthenticated, logout } = useAuth();
    const { theme, toggleTheme, colors } = useTheme();

    return (
        <header style={{ backgroundColor: colors.primary, color: colors.text }}>
            <h1>My App</h1>
            <button onClick={toggleTheme}>
                Switch to {theme === 'light' ? 'dark' : 'light'} theme
            </button>
            {isAuthenticated ? (
                <div>
                    <span>Welcome, {user.name}!</span>
                    <button onClick={logout}>Logout</button>
                </div>
            ) : (
                <LoginForm />
            )}
        </header>
    );
}

// App component with providers
function App() {
    return (
        <AuthProvider>
            <ThemeProvider>
                <div className="app">
                    <Header />
                    {/* Other components */}
                </div>
            </ThemeProvider>
        </AuthProvider>
    );
}
```

#### React Router

```jsx
import React from 'react';
import {
    BrowserRouter as Router,
    Routes,
    Route,
    Link,
    NavLink,
    Navigate,
    useParams,
    useNavigate,
    useLocation,
    Outlet
} from 'react-router-dom';

// Layout component
function Layout() {
    return (
        <div>
            <nav>
                <ul>
                    <li><NavLink to="/" className={({ isActive }) => isActive ? 'active' : ''}>Home</NavLink></li>
                    <li><NavLink to="/about">About</NavLink></li>
                    <li><NavLink to="/products">Products</NavLink></li>
                    <li><NavLink to="/contact">Contact</NavLink></li>
                </ul>
            </nav>
            <main>
                <Outlet /> {/* Child routes render here */}
            </main>
        </div>
    );
}

// Page components
function Home() {
    const navigate = useNavigate();

    return (
        <div>
            <h1>Home Page</h1>
            <button onClick={() => navigate('/products')}>
                Go to Products
            </button>
        </div>
    );
}

function About() {
    return (
        <div>
            <h1>About Us</h1>
            <p>Learn more about our company.</p>
        </div>
    );
}

function Products() {
    const products = [
        { id: 1, name: 'Laptop' },
        { id: 2, name: 'Phone' },
        { id: 3, name: 'Tablet' }
    ];

    return (
        <div>
            <h1>Products</h1>
            <ul>
                {products.map(product => (
                    <li key={product.id}>
                        <Link to={`/products/${product.id}`}>
                            {product.name}
                        </Link>
                    </li>
                ))}
            </ul>
            <Outlet /> {/* Nested routes render here */}
        </div>
    );
}

function ProductDetail() {
    const { id } = useParams();
    const navigate = useNavigate();
    const location = useLocation();

    // Mock product data
    const product = {
        1: { name: 'Laptop', price: 999, description: 'High-performance laptop' },
        2: { name: 'Phone', price: 699, description: 'Latest smartphone' },
        3: { name: 'Tablet', price: 399, description: 'Portable tablet' }
    }[id];

    if (!product) {
        return <div>Product not found</div>;
    }

    return (
        <div>
            <h2>{product.name}</h2>
            <p>Price: ${product.price}</p>
            <p>{product.description}</p>
            <button onClick={() => navigate(-1)}>Go Back</button>
            <button onClick={() => navigate('/', { replace: true })}>Home</button>
        </div>
    );
}

// Protected route component
function ProtectedRoute({ children }) {
    const { isAuthenticated } = useAuth();
    const location = useLocation();

    if (!isAuthenticated) {
        return <Navigate to="/login" state={{ from: location }} replace />;
    }

    return children;
}

// Login component
function Login() {
    const navigate = useNavigate();
    const location = useLocation();
    const { login } = useAuth();

    const from = location.state?.from?.pathname || '/';

    const handleLogin = async (credentials) => {
        await login(credentials);
        navigate(from, { replace: true });
    };

    return (
        <div>
            <h1>Login</h1>
            {/* Login form */}
        </div>
    );
}

// 404 Not Found component
function NotFound() {
    return (
        <div>
            <h1>404 - Page Not Found</h1>
            <Link to="/">Go Home</Link>
        </div>
    );
}

// Main App with routing
function App() {
    return (
        <Router>
            <Routes>
                <Route path="/" element={<Layout />}>
                    <Route index element={<Home />} />
                    <Route path="about" element={<About />} />
                    <Route path="products" element={<Products />}>
                        <Route path=":id" element={<ProductDetail />} />
                    </Route>
                    <Route
                        path="dashboard"
                        element={
                            <ProtectedRoute>
                                <Dashboard />
                            </ProtectedRoute>
                        }
                    />
                    <Route path="login" element={<Login />} />
                    <Route path="contact" element={<Contact />} />
                </Route>
                {/* Redirect old URLs */}
                <Route path="/old-products" element={<Navigate to="/products" replace />} />
                {/* Catch all route - 404 */}
                <Route path="*" element={<NotFound />} />
            </Routes>
        </Router>
    );
}

// Programmatic navigation hook
function useNavigation() {
    const navigate = useNavigate();

    return {
        goHome: () => navigate('/'),
        goBack: () => navigate(-1),
        goToProduct: (id) => navigate(`/products/${id}`),
        goToLogin: () => navigate('/login'),
        redirect: (path, options = {}) => navigate(path, options)
    };
}

export default App;
```

### Vue.js

#### Templates and Directives

```vue
<!-- Vue Template -->
<template>
  <div id="app">
    <!-- Text interpolation -->
    <h1>{{ title }}</h1>
    <p>{{ message }}</p>

    <!-- Raw HTML -->
    <div v-html="htmlContent"></div>

    <!-- Attribute binding -->
    <img v-bind:src="imageSrc" :alt="imageAlt" />
    <a :href="linkUrl" :class="{ active: isActive }">Link</a>

    <!-- Conditional rendering -->
    <div v-if="showContent">
      <p>This content is conditionally shown</p>
    </div>
    <div v-else-if="showAlternative">
      <p>Alternative content</p>
    </div>
    <div v-else>
      <p>Default content</p>
    </div>

    <!-- Show/hide with v-show -->
    <div v-show="isVisible">This toggles visibility</div>

    <!-- List rendering -->
    <ul>
      <li v-for="(item, index) in items" :key="item.id">
        {{ index }}: {{ item.name }} - ${{ item.price }}
      </li>
    </ul>

    <!-- Object iteration -->
    <ul>
      <li v-for="(value, key) in user" :key="key">
        {{ key }}: {{ value }}
      </li>
    </ul>

    <!-- Event handling -->
    <button @click="handleClick">Click me</button>
    <button @click="increment(5)">Add 5</button>
    <button @click.prevent="handleSubmit">Submit</button>

    <!-- Form input binding -->
    <input v-model="inputText" placeholder="Type here" />
    <textarea v-model="message"></textarea>
    <select v-model="selectedOption">
      <option value="">Choose...</option>
      <option value="option1">Option 1</option>
      <option value="option2">Option 2</option>
    </select>

    <!-- Checkbox and radio -->
    <input type="checkbox" v-model="isChecked" />
    <input type="radio" v-model="radioValue" value="A" />
    <input type="radio" v-model="radioValue" value="B" />

    <!-- Multiple checkboxes -->
    <input type="checkbox" v-model="checkedNames" value="John" />
    <input type="checkbox" v-model="checkedNames" value="Jane" />

    <!-- Computed properties display -->
    <p>Full name: {{ fullName }}</p>
    <p>Items count: {{ itemsCount }}</p>

    <!-- Method calls -->
    <p>{{ formatPrice(item.price) }}</p>

    <!-- Class and style binding -->
    <div :class="[baseClass, { active: isActive, disabled: isDisabled }]">
      Dynamic classes
    </div>

    <div :style="{ color: textColor, fontSize: fontSize + 'px' }">
      Dynamic styles
    </div>
  </div>
</template>

<script>
export default {
  name: 'App',
  data() {
    return {
      title: 'Vue.js Application',
      message: 'Hello Vue!',
      htmlContent: '<strong>Bold text</strong>',
      imageSrc: '/path/to/image.jpg',
      imageAlt: 'Description',
      linkUrl: 'https://example.com',
      isActive: true,
      showContent: true,
      showAlternative: false,
      isVisible: true,
      inputText: '',
      selectedOption: '',
      isChecked: false,
      radioValue: 'A',
      checkedNames: [],
      items: [
        { id: 1, name: 'Laptop', price: 999 },
        { id: 2, name: 'Phone', price: 699 },
        { id: 3, name: 'Tablet', price: 399 }
      ],
      user: {
        name: 'John Doe',
        email: 'john@example.com',
        age: 30
      },
      count: 0,
      baseClass: 'btn',
      isDisabled: false,
      textColor: 'blue',
      fontSize: 16
    };
  },
  computed: {
    fullName() {
      return `${this.user.name} (${this.user.email})`;
    },
    itemsCount() {
      return this.items.length;
    },
    expensiveItems() {
      return this.items.filter(item => item.price > 500);
    }
  },
  methods: {
    handleClick() {
      alert('Button clicked!');
    },
    increment(amount = 1) {
      this.count += amount;
    },
    handleSubmit(event) {
      console.log('Form submitted');
    },
    formatPrice(price) {
      return `$${price.toFixed(2)}`;
    }
  },
  watch: {
    inputText(newValue, oldValue) {
      console.log(`Input changed from "${oldValue}" to "${newValue}"`);
    },
    count: {
      handler(newValue) {
        console.log(`Count changed to: ${newValue}`);
      },
      immediate: true
    }
  }
};
</script>

<style scoped>
.btn {
  padding: 10px 20px;
  border: 1px solid #ccc;
  background-color: #f8f9fa;
  cursor: pointer;
}

.btn.active {
  background-color: #007bff;
  color: white;
}

.btn.disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
</style>
```

#### Components

```vue
<!-- Child Component: UserCard.vue -->
<template>
  <div class="user-card">
    <img :src="user.avatar" :alt="`${user.name}'s avatar`" />
    <h3>{{ user.name }}</h3>
    <p>{{ user.email }}</p>
    <p>Posts: {{ user.posts?.length || 0 }}</p>

    <!-- Emit events to parent -->
    <button @click="$emit('user-selected', user)">Select User</button>
    <button @click="deleteUser">Delete</button>

    <!-- Slots for flexible content -->
    <div class="actions">
      <slot name="actions" :user="user">
        <button>Default Action</button>
      </slot>
    </div>

    <div class="footer">
      <slot :user="user">
        <!-- Default slot content -->
        <p>Default footer content</p>
      </slot>
    </div>
  </div>
</template>

<script>
export default {
  name: 'UserCard',
  props: {
    user: {
      type: Object,
      required: true,
      validator(value) {
        return value.name && value.email;
      }
    },
    showActions: {
      type: Boolean,
      default: true
    }
  },
  emits: ['user-selected', 'user-deleted'],
  methods: {
    deleteUser() {
      if (confirm(`Delete ${this.user.name}?`)) {
        this.$emit('user-deleted', this.user.id);
      }
    }
  }
};
</script>

<!-- Parent Component using UserCard -->
<template>
  <div class="user-list">
    <h2>Users</h2>

    <UserCard
      v-for="user in users"
      :key="user.id"
      :user="user"
      @user-selected="handleUserSelected"
      @user-deleted="handleUserDeleted"
    >
      <!-- Named slot -->
      <template #actions="{ user }">
        <button @click="editUser(user)">Edit</button>
        <button @click="viewProfile(user)">View Profile</button>
      </template>

      <!-- Default slot with slot props -->
      <template #default="{ user }">
        <p>Member since: {{ formatDate(user.createdAt) }}</p>
      </template>
    </UserCard>

    <!-- Dynamic component -->
    <component :is="currentComponent" :data="componentData" />
  </div>
</template>

<script>
import UserCard from './UserCard.vue';
import UserProfile from './UserProfile.vue';
import UserEdit from './UserEdit.vue';

export default {
  components: {
    UserCard,
    UserProfile,
    UserEdit
  },
  data() {
    return {
      users: [
        {
          id: 1,
          name: 'John Doe',
          email: 'john@example.com',
          avatar: '/avatars/john.jpg',
          createdAt: new Date('2023-01-15')
        },
        // More users...
      ],
      currentComponent: 'UserProfile',
      componentData: null
    };
  },
  methods: {
    handleUserSelected(user) {
      console.log('User selected:', user);
      this.currentComponent = 'UserProfile';
      this.componentData = user;
    },
    handleUserDeleted(userId) {
      this.users = this.users.filter(user => user.id !== userId);
    },
    editUser(user) {
      this.currentComponent = 'UserEdit';
      this.componentData = user;
    },
    viewProfile(user) {
      this.currentComponent = 'UserProfile';
      this.componentData = user;
    },
    formatDate(date) {
      return date.toLocaleDateString();
    }
  }
};
</script>
```

#### Vuex State Management

```javascript
// store/index.js
import { createStore } from 'vuex';
import userModule from './modules/user';
import productModule from './modules/product';

export default createStore({
  state: {
    loading: false,
    error: null,
    theme: 'light'
  },
  getters: {
    isLoading: state => state.loading,
    hasError: state => !!state.error,
    isDarkTheme: state => state.theme === 'dark'
  },
  mutations: {
    SET_LOADING(state, loading) {
      state.loading = loading;
    },
    SET_ERROR(state, error) {
      state.error = error;
    },
    CLEAR_ERROR(state) {
      state.error = null;
    },
    TOGGLE_THEME(state) {
      state.theme = state.theme === 'light' ? 'dark' : 'light';
    }
  },
  actions: {
    async fetchData({ commit }, url) {
      commit('SET_LOADING', true);
      commit('CLEAR_ERROR');

      try {
        const response = await fetch(url);
        const data = await response.json();
        return data;
      } catch (error) {
        commit('SET_ERROR', error.message);
        throw error;
      } finally {
        commit('SET_LOADING', false);
      }
    }
  },
  modules: {
    user: userModule,
    product: productModule
  }
});

// store/modules/user.js
export default {
  namespaced: true,
  state: {
    currentUser: null,
    users: [],
    permissions: []
  },
  getters: {
    isAuthenticated: state => !!state.currentUser,
    userName: state => state.currentUser?.name || 'Guest',
    hasPermission: state => permission => {
      return state.permissions.includes(permission);
    },
    getUserById: state => id => {
      return state.users.find(user => user.id === id);
    }
  },
  mutations: {
    SET_CURRENT_USER(state, user) {
      state.currentUser = user;
    },
    SET_USERS(state, users) {
      state.users = users;
    },
    ADD_USER(state, user) {
      state.users.push(user);
    },
    UPDATE_USER(state, updatedUser) {
      const index = state.users.findIndex(user => user.id === updatedUser.id);
      if (index !== -1) {
        state.users.splice(index, 1, updatedUser);
      }
    },
    REMOVE_USER(state, userId) {
      state.users = state.users.filter(user => user.id !== userId);
    },
    SET_PERMISSIONS(state, permissions) {
      state.permissions = permissions;
    }
  },
  actions: {
    async login({ commit, dispatch }, credentials) {
      try {
        const user = await dispatch('fetchData', '/api/login', { root: true });
        commit('SET_CURRENT_USER', user);
        commit('SET_PERMISSIONS', user.permissions);
        return user;
      } catch (error) {
        throw error;
      }
    },

    async logout({ commit }) {
      commit('SET_CURRENT_USER', null);
      commit('SET_PERMISSIONS', []);
    },

    async fetchUsers({ commit, dispatch }) {
      try {
        const users = await dispatch('fetchData', '/api/users', { root: true });
        commit('SET_USERS', users);
        return users;
      } catch (error) {
        throw error;
      }
    },

    async createUser({ commit, dispatch }, userData) {
      try {
        const newUser = await dispatch('fetchData', '/api/users', { root: true });
        commit('ADD_USER', newUser);
        return newUser;
      } catch (error) {
        throw error;
      }
    }
  }
};

// Using Vuex in components
// Component.vue
<template>
  <div>
    <h1>Welcome, {{ userName }}!</h1>
    <p v-if="isLoading">Loading...</p>
    <p v-if="hasError" class="error">{{ error }}</p>

    <button @click="toggleTheme">
      Switch to {{ isDarkTheme ? 'light' : 'dark' }} theme
    </button>

    <div v-if="isAuthenticated">
      <button @click="logout">Logout</button>
      <UserList :users="users" />
    </div>

    <LoginForm v-else @login="handleLogin" />
  </div>
</template>

<script>
import { mapState, mapGetters, mapMutations, mapActions } from 'vuex';

export default {
  computed: {
    // Map store state to computed properties
    ...mapState(['loading', 'error', 'theme']),
    ...mapState('user', ['users']),

    // Map getters
    ...mapGetters(['isLoading', 'hasError', 'isDarkTheme']),
    ...mapGetters('user', ['isAuthenticated', 'userName'])
  },
  methods: {
    // Map mutations
    ...mapMutations(['TOGGLE_THEME']),
    ...mapMutations('user', ['SET_CURRENT_USER']),

    // Map actions
    ...mapActions('user', ['login', 'logout', 'fetchUsers']),

    async handleLogin(credentials) {
      try {
        await this.login(credentials);
        await this.fetchUsers();
      } catch (error) {
        console.error('Login failed:', error);
      }
    },

    toggleTheme() {
      this['TOGGLE_THEME']();
    }
  },
  async created() {
    if (this.isAuthenticated) {
      await this.fetchUsers();
    }
  }
};
</script>
```

#### Vue Router

```javascript
// router/index.js
import { createRouter, createWebHistory } from 'vue-router';
import Home from '../views/Home.vue';
import About from '../views/About.vue';
import Products from '../views/Products.vue';
import ProductDetail from '../views/ProductDetail.vue';
import Login from '../views/Login.vue';
import Dashboard from '../views/Dashboard.vue';
import Profile from '../views/Profile.vue';
import NotFound from '../views/NotFound.vue';
import store from '../store';

const routes = [
  {
    path: '/',
    name: 'Home',
    component: Home
  },
  {
    path: '/about',
    name: 'About',
    component: About,
    meta: { title: 'About Us' }
  },
  {
    path: '/products',
    name: 'Products',
    component: Products,
    children: [
      {
        path: '',
        name: 'ProductList',
        component: () => import('../components/ProductList.vue')
      },
      {
        path: ':id',
        name: 'ProductDetail',
        component: ProductDetail,
        props: true, // Pass route params as props
        beforeEnter: (to, from, next) => {
          // Route-level guard
          const id = parseInt(to.params.id);
          if (isNaN(id)) {
            next({ name: 'NotFound' });
          } else {
            next();
          }
        }
      }
    ]
  },
  {
    path: '/login',
    name: 'Login',
    component: Login,
    meta: { requiresGuest: true }
  },
  {
    path: '/dashboard',
    name: 'Dashboard',
    component: Dashboard,
    meta: { requiresAuth: true, roles: ['admin', 'user'] }
  },
  {
    path: '/profile',
    name: 'Profile',
    component: Profile,
    meta: { requiresAuth: true }
  },
  // Redirect
  {
    path: '/old-path',
    redirect: '/products'
  },
  // Dynamic redirect
  {
    path: '/user/:id',
    redirect: to => `/profile/${to.params.id}`
  },
  // Catch all 404
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: NotFound
  }
];

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior(to, from, savedPosition) {
    if (savedPosition) {
      return savedPosition;
    } else if (to.hash) {
      return { el: to.hash };
    } else {
      return { top: 0 };
    }
  }
});

// Global navigation guards
router.beforeEach((to, from, next) => {
  const isAuthenticated = store.getters['user/isAuthenticated'];
  const userRoles = store.state.user.currentUser?.roles || [];

  // Set page title
  document.title = to.meta.title || 'My App';

  // Check authentication
  if (to.meta.requiresAuth && !isAuthenticated) {
    next({ name: 'Login', query: { redirect: to.fullPath } });
  } else if (to.meta.requiresGuest && isAuthenticated) {
    next({ name: 'Dashboard' });
  } else if (to.meta.roles) {
    // Check user roles
    const hasRequiredRole = to.meta.roles.some(role => userRoles.includes(role));
    if (!hasRequiredRole) {
      next({ name: 'NotFound' });
    } else {
      next();
    }
  } else {
    next();
  }
});

router.afterEach((to, from) => {
  // Analytics, logging, etc.
  console.log(`Navigated from ${from.name} to ${to.name}`);
});

export default router;

// Using router in components
// Navigation component
<template>
  <nav>
    <router-link to="/" exact-active-class="active">Home</router-link>
    <router-link to="/about" active-class="active">About</router-link>
    <router-link to="/products">Products</router-link>

    <template v-if="isAuthenticated">
      <router-link to="/dashboard">Dashboard</router-link>
      <router-link to="/profile">Profile</router-link>
    </template>
    <router-link v-else to="/login">Login</router-link>
  </nav>

  <!-- Router outlet -->
  <router-view />
</template>

// Programmatic navigation in component
<script>
export default {
  methods: {
    goToProduct(productId) {
      this.$router.push({ name: 'ProductDetail', params: { id: productId } });
    },

    goBack() {
      this.$router.go(-1);
    },

    navigateWithQuery() {
      this.$router.push({
        path: '/products',
        query: { category: 'electronics', sort: 'price' }
      });
    },

    handleLogin() {
      const redirect = this.$route.query.redirect || '/dashboard';
      this.$router.replace(redirect);
    }
  },

  computed: {
    currentRoute() {
      return this.$route.name;
    },

    productId() {
      return this.$route.params.id;
    },

    queryParams() {
      return this.$route.query;
    }
  },

  watch: {
    $route(to, from) {
      // React to route changes
      console.log('Route changed:', to.name);
    }
  }
};
</script>
```

### Angular

#### Components and Templates

```typescript
// app.component.ts
import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent implements OnInit, OnDestroy {
  title = 'Angular Application';
  message = 'Hello Angular!';
  isVisible = true;
  users: User[] = [];
  selectedUser: User | null = null;

  private destroy$ = new Subject<void>();

  constructor(private userService: UserService) {}

  ngOnInit() {
    this.loadUsers();
  }

  ngOnDestroy() {
    this.destroy$.next();
    this.destroy$.complete();
  }

  loadUsers() {
    this.userService.getUsers()
      .pipe(takeUntil(this.destroy$))
      .subscribe(users => {
        this.users = users;
      });
  }

  onUserSelected(user: User) {
    this.selectedUser = user;
  }

  toggleVisibility() {
    this.isVisible = !this.isVisible;
  }
}

// user.interface.ts
export interface User {
  id: number;
  name: string;
  email: string;
  avatar?: string;
  isActive: boolean;
  roles: string[];
}
```

```html
<!-- app.component.html -->
<div class="app-container">
  <header>
    <h1>{{ title }}</h1>
    <p>{{ message }}</p>
  </header>

  <main>
    <!-- Structural directives -->
    <div *ngIf="isVisible; else hiddenContent">
      <h2>User List</h2>

      <!-- NgFor with trackBy -->
      <div class="user-grid">
        <app-user-card
          *ngFor="let user of users; trackBy: trackByUserId"
          [user]="user"
          [isSelected]="selectedUser?.id === user.id"
          (userSelected)="onUserSelected($event)"
          (userDeleted)="loadUsers()">
        </app-user-card>
      </div>

      <!-- NgSwitch -->
      <div [ngSwitch]="users.length">
        <p *ngSwitchCase="0">No users found.</p>
        <p *ngSwitchCase="1">One user found.</p>
        <p *ngSwitchDefault>{{ users.length }} users found.</p>
      </div>
    </div>

    <ng-template #hiddenContent>
      <p>Content is hidden</p>
    </ng-template>

    <!-- Property and attribute binding -->
    <button
      [disabled]="users.length === 0"
      [class.primary]="isVisible"
      [attr.aria-label]="'Toggle visibility'"
      (click)="toggleVisibility()">
      {{ isVisible ? 'Hide' : 'Show' }} Users
    </button>

    <!-- Two-way binding -->
    <input [(ngModel)]="message" placeholder="Enter message">

    <!-- Template reference variables -->
    <input #searchInput (keyup)="0" placeholder="Search users">
    <p>You typed: {{ searchInput.value }}</p>

    <!-- Pipes -->
    <div *ngIf="selectedUser">
      <h3>Selected User</h3>
      <p>Name: {{ selectedUser.name | titlecase }}</p>
      <p>Email: {{ selectedUser.email | lowercase }}</p>
      <p>Roles: {{ selectedUser.roles | slice:0:3 | join:', ' }}</p>
      <p>Created: {{ selectedUser.createdAt | date:'medium' }}</p>
    </div>
  </main>
</div>
```

```typescript
// user-card.component.ts
import { Component, Input, Output, EventEmitter, ChangeDetectionStrategy } from '@angular/core';

@Component({
  selector: 'app-user-card',
  templateUrl: './user-card.component.html',
  styleUrls: ['./user-card.component.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class UserCardComponent {
  @Input() user!: User;
  @Input() isSelected = false;

  @Output() userSelected = new EventEmitter<User>();
  @Output() userDeleted = new EventEmitter<number>();

  onSelectUser() {
    this.userSelected.emit(this.user);
  }

  onDeleteUser() {
    if (confirm(`Delete ${this.user.name}?`)) {
      this.userDeleted.emit(this.user.id);
    }
  }

  get statusClass() {
    return {
      'user-active': this.user.isActive,
      'user-inactive': !this.user.isActive,
      'user-selected': this.isSelected
    };
  }
}
```

```html
<!-- user-card.component.html -->
<div class="user-card" [ngClass]="statusClass" (click)="onSelectUser()">
  <img [src]="user.avatar || '/assets/default-avatar.png'"
       [alt]="user.name + ' avatar'">

  <div class="user-info">
    <h4>{{ user.name }}</h4>
    <p>{{ user.email }}</p>

    <div class="user-roles">
      <span *ngFor="let role of user.roles" class="role-badge">
        {{ role }}
      </span>
    </div>

    <div class="user-status">
      <span [class]="user.isActive ? 'status-active' : 'status-inactive'">
        {{ user.isActive ? 'Active' : 'Inactive' }}
      </span>
    </div>
  </div>

  <div class="user-actions">
    <button (click)="$event.stopPropagation(); onDeleteUser()"
            class="btn btn-danger">
      Delete
    </button>
  </div>
</div>
```

#### Services and Dependency Injection

```typescript
// user.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, BehaviorSubject, throwError } from 'rxjs';
import { map, catchError, retry, shareReplay } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private readonly API_URL = '/api/users';
  private usersSubject = new BehaviorSubject<User[]>([]);

  // Expose as observable
  public users$ = this.usersSubject.asObservable();

  constructor(private http: HttpClient) {}

  getUsers(): Observable<User[]> {
    return this.http.get<User[]>(this.API_URL)
      .pipe(
        retry(3),
        map(users => users.map(this.transformUser)),
        shareReplay(1),
        catchError(this.handleError)
      );
  }

  getUserById(id: number): Observable<User> {
    return this.http.get<User>(`${this.API_URL}/${id}`)
      .pipe(
        map(this.transformUser),
        catchError(this.handleError)
      );
  }

  createUser(userData: Partial<User>): Observable<User> {
    return this.http.post<User>(this.API_URL, userData)
      .pipe(
        map(this.transformUser),
        catchError(this.handleError)
      );
  }

  updateUser(id: number, userData: Partial<User>): Observable<User> {
    return this.http.put<User>(`${this.API_URL}/${id}`, userData)
      .pipe(
        map(this.transformUser),
        catchError(this.handleError)
      );
  }

  deleteUser(id: number): Observable<void> {
    return this.http.delete<void>(`${this.API_URL}/${id}`)
      .pipe(
        catchError(this.handleError)
      );
  }

  // Search users
  searchUsers(query: string): Observable<User[]> {
    return this.http.get<User[]>(`${this.API_URL}/search`, {
      params: { q: query }
    }).pipe(
      map(users => users.map(this.transformUser)),
      catchError(this.handleError)
    );
  }

  // Update local state
  refreshUsers() {
    this.getUsers().subscribe(users => {
      this.usersSubject.next(users);
    });
  }

  private transformUser(user: any): User {
    return {
      ...user,
      createdAt: new Date(user.createdAt),
      updatedAt: new Date(user.updatedAt)
    };
  }

  private handleError(error: HttpErrorResponse): Observable<never> {
    let errorMessage = 'An unknown error occurred';

    if (error.error instanceof ErrorEvent) {
      // Client-side error
      errorMessage = `Error: ${error.error.message}`;
    } else {
      // Server-side error
      errorMessage = `Error Code: ${error.status}\nMessage: ${error.message}`;
    }

    console.error(errorMessage);
    return throwError(errorMessage);
  }
}

// auth.service.ts
@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private currentUserSubject = new BehaviorSubject<User | null>(null);
  public currentUser$ = this.currentUserSubject.asObservable();

  constructor(private http: HttpClient) {
    // Check if user is already logged in
    const savedUser = localStorage.getItem('currentUser');
    if (savedUser) {
      this.currentUserSubject.next(JSON.parse(savedUser));
    }
  }

  login(credentials: LoginCredentials): Observable<User> {
    return this.http.post<{ user: User; token: string }>('/api/auth/login', credentials)
      .pipe(
        map(response => {
          // Store user and token
          localStorage.setItem('currentUser', JSON.stringify(response.user));
          localStorage.setItem('token', response.token);
          this.currentUserSubject.next(response.user);
          return response.user;
        }),
        catchError(this.handleError)
      );
  }

  logout(): void {
    localStorage.removeItem('currentUser');
    localStorage.removeItem('token');
    this.currentUserSubject.next(null);
  }

  get currentUserValue(): User | null {
    return this.currentUserSubject.value;
  }

  get isAuthenticated(): boolean {
    return !!this.currentUserValue;
  }

  hasRole(role: string): boolean {
    const user = this.currentUserValue;
    return user ? user.roles.includes(role) : false;
  }

  private handleError(error: HttpErrorResponse): Observable<never> {
    return throwError(error.error?.message || 'Authentication failed');
  }
}

// http.interceptor.ts
import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const token = localStorage.getItem('token');

    if (token) {
      const authReq = req.clone({
        headers: req.headers.set('Authorization', `Bearer ${token}`)
      });
      return next.handle(authReq);
    }

    return next.handle(req);
  }
}
```

#### RxJS and Observables

```typescript
// data.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, Subject, BehaviorSubject, combineLatest, merge, timer } from 'rxjs';
import {
  map,
  filter,
  switchMap,
  debounceTime,
  distinctUntilChanged,
  startWith,
  scan,
  share,
  takeUntil
} from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class DataService {
  private searchTerms = new Subject<string>();
  private refreshTrigger = new Subject<void>();

  constructor(private http: HttpClient) {}

  // Debounced search
  search$ = this.searchTerms.pipe(
    debounceTime(300),
    distinctUntilChanged(),
    switchMap(term => this.searchUsers(term))
  );

  // Auto-refresh every 30 seconds
  autoRefresh$ = timer(0, 30000).pipe(
    switchMap(() => this.getUsers())
  );

  // Manual refresh trigger
  manualRefresh$ = this.refreshTrigger.pipe(
    startWith(null),
    switchMap(() => this.getUsers())
  );

  // Combined data stream
  users$ = merge(this.autoRefresh$, this.manualRefresh$).pipe(
    share()
  );

  // Filtered and sorted users
  filteredUsers$ = combineLatest([
    this.users$,
    this.search$.pipe(startWith(''))
  ]).pipe(
    map(([users, searchTerm]) =>
      users.filter(user =>
        user.name.toLowerCase().includes(searchTerm.toLowerCase())
      ).sort((a, b) => a.name.localeCompare(b.name))
    )
  );

  // User statistics
  userStats$ = this.users$.pipe(
    map(users => ({
      total: users.length,
      active: users.filter(u => u.isActive).length,
      inactive: users.filter(u => !u.isActive).length,
      admins: users.filter(u => u.roles.includes('admin')).length
    }))
  );

  search(term: string): void {
    this.searchTerms.next(term);
  }

  refresh(): void {
    this.refreshTrigger.next();
  }

  private getUsers(): Observable<User[]> {
    return this.http.get<User[]>('/api/users');
  }

  private searchUsers(term: string): Observable<User[]> {
    return this.http.get<User[]>(`/api/users/search?q=${term}`);
  }
}

// Component using observables
@Component({
  selector: 'app-user-list',
  template: `
    <div class="user-list">
      <div class="search-bar">
        <input
          (input)="onSearch($event)"
          placeholder="Search users..."
          #searchInput>
        <button (click)="onRefresh()">Refresh</button>
      </div>

      <div class="stats" *ngIf="userStats$ | async as stats">
        <span>Total: {{ stats.total }}</span>
        <span>Active: {{ stats.active }}</span>
        <span>Inactive: {{ stats.inactive }}</span>
        <span>Admins: {{ stats.admins }}</span>
      </div>

      <div class="users">
        <app-user-card
          *ngFor="let user of filteredUsers$ | async; trackBy: trackByUserId"
          [user]="user">
        </app-user-card>
      </div>

      <div *ngIf="(filteredUsers$ | async)?.length === 0" class="no-results">
        No users found.
      </div>
    </div>
  `
})
export class UserListComponent implements OnInit, OnDestroy {
  filteredUsers$ = this.dataService.filteredUsers$;
  userStats$ = this.dataService.userStats$;

  private destroy$ = new Subject<void>();

  constructor(private dataService: DataService) {}

  ngOnInit() {
    // Subscribe to handle errors
    this.filteredUsers$
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        error: (error) => console.error('Error loading users:', error)
      });
  }

  ngOnDestroy() {
    this.destroy$.next();
    this.destroy$.complete();
  }

  onSearch(event: Event): void {
    const target = event.target as HTMLInputElement;
    this.dataService.search(target.value);
  }

  onRefresh(): void {
    this.dataService.refresh();
  }

  trackByUserId(index: number, user: User): number {
    return user.id;
  }
}

// Advanced observable patterns
@Injectable()
export class AdvancedObservableService {

  // Polling with exponential backoff
  pollWithBackoff<T>(
    source: () => Observable<T>,
    maxRetries = 3
  ): Observable<T> {
    return timer(0, 1000).pipe(
      switchMap(() => source().pipe(
        retry(maxRetries),
        catchError(error => {
          console.error('Polling error:', error);
          return timer(Math.pow(2, maxRetries) * 1000).pipe(
            switchMap(() => throwError(error))
          );
        })
      ))
    );
  }

  // Cache with TTL
  cacheWithTTL<T>(
    source: Observable<T>,
    ttlMs: number = 300000
  ): Observable<T> {
    let cached: T;
    let cacheTime = 0;

    return source.pipe(
      map(data => {
        const now = Date.now();
        if (!cached || now - cacheTime > ttlMs) {
          cached = data;
          cacheTime = now;
        }
        return cached;
      }),
      shareReplay(1)
    );
  }

  // Optimistic updates
  optimisticUpdate<T>(
    currentData: T[],
    optimisticItem: T,
    updateCall: Observable<T>
  ): Observable<T[]> {
    const optimisticData = [...currentData, optimisticItem];

    return of(optimisticData).pipe(
      switchMap(() => updateCall.pipe(
        map(updatedItem =>
          currentData.map(item =>
            item.id === optimisticItem.id ? updatedItem : item
          )
        ),
        catchError(error => {
          // Rollback on error
          console.error('Update failed, rolling back:', error);
          return of(currentData);
        })
      ))
    );
  }
}
```

#### Angular Router

```typescript
// app-routing.module.ts
import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { AboutComponent } from './about/about.component';
import { ProductsComponent } from './products/products.component';
import { ProductDetailComponent } from './product-detail/product-detail.component';
import { LoginComponent } from './login/login.component';
import { DashboardComponent } from './dashboard/dashboard.component';
import { NotFoundComponent } from './not-found/not-found.component';
import { AuthGuard } from './guards/auth.guard';
import { AdminGuard } from './guards/admin.guard';

const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', component: HomeComponent },
  { path: 'about', component: AboutComponent, data: { title: 'About Us' } },
  {
    path: 'products',
    component: ProductsComponent,
    children: [
      { path: '', component: ProductListComponent },
      {
        path: ':id',
        component: ProductDetailComponent,
        resolve: { product: ProductResolver }
      }
    ]
  },
  { path: 'login', component: LoginComponent },
  {
    path: 'dashboard',
    component: DashboardComponent,
    canActivate: [AuthGuard],
    data: { roles: ['user'] }
  },
  {
    path: 'admin',
    loadChildren: () => import('./admin/admin.module').then(m => m.AdminModule),
    canActivate: [AuthGuard, AdminGuard]
  },
  { path: '404', component: NotFoundComponent },
  { path: '**', redirectTo: '/404' }
];

@NgModule({
  imports: [RouterModule.forRoot(routes, {
    enableTracing: false, // Set to true for debugging
    scrollPositionRestoration: 'enabled'
  })],
  exports: [RouterModule]
})
export class AppRoutingModule { }

// auth.guard.ts
import { Injectable } from '@angular/core';
import { CanActivate, Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { Observable } from 'rxjs';
import { AuthService } from '../services/auth.service';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {

  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Observable<boolean> | Promise<boolean> | boolean {

    if (this.authService.isAuthenticated) {
      // Check roles if specified
      const requiredRoles = route.data['roles'] as Array<string>;
      if (requiredRoles) {
        const hasRole = requiredRoles.some(role =>
          this.authService.hasRole(role)
        );
        if (!hasRole) {
          this.router.navigate(['/unauthorized']);
          return false;
        }
      }
      return true;
    }

    // Store the attempted URL for redirecting
    this.router.navigate(['/login'], {
      queryParams: { returnUrl: state.url }
    });
    return false;
  }
}

// product.resolver.ts
import { Injectable } from '@angular/core';
import { Resolve, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { Observable, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { ProductService } from '../services/product.service';

@Injectable({
  providedIn: 'root'
})
export class ProductResolver implements Resolve<Product | null> {

  constructor(private productService: ProductService) {}

  resolve(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Observable<Product | null> {
    const id = route.paramMap.get('id');

    if (id) {
      return this.productService.getProduct(+id).pipe(
        catchError(error => {
          console.error('Error loading product:', error);
          return of(null);
        })
      );
    }

    return of(null);
  }
}

// Component using router
import { Component, OnInit } from '@angular/core';
import { Router, ActivatedRoute, ParamMap } from '@angular/router';
import { switchMap } from 'rxjs/operators';

@Component({
  selector: 'app-product-detail',
  template: `
    <div *ngIf="product">
      <h2>{{ product.name }}</h2>
      <p>{{ product.description }}</p>
      <p>Price: {{ product.price | currency }}</p>

      <button (click)="goBack()">Go Back</button>
      <button (click)="editProduct()">Edit</button>
    </div>
  `
})
export class ProductDetailComponent implements OnInit {
  product: Product | null = null;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private productService: ProductService
  ) {}

  ngOnInit() {
    // Using resolver data
    this.product = this.route.snapshot.data['product'];

    // Alternative: Subscribe to route params
    this.route.paramMap.pipe(
      switchMap((params: ParamMap) => {
        const id = params.get('id');
        return id ? this.productService.getProduct(+id) : of(null);
      })
    ).subscribe(product => {
      this.product = product;
    });

    // Access query parameters
    const category = this.route.snapshot.queryParamMap.get('category');

    // Subscribe to query param changes
    this.route.queryParams.subscribe(params => {
      console.log('Query params:', params);
    });
  }

  goBack() {
    this.router.navigate(['../'], { relativeTo: this.route });
  }

  editProduct() {
    if (this.product) {
      this.router.navigate(['/products', this.product.id, 'edit']);
    }
  }
}

// Programmatic navigation examples
@Component({
  selector: 'app-navigation-example',
  template: `
    <button (click)="navigateToProduct(123)">View Product 123</button>
    <button (click)="navigateWithQueryParams()">Search Products</button>
    <button (click)="navigateAndReplace()">Replace Current Route</button>
  `
})
export class NavigationExampleComponent {

  constructor(private router: Router) {}

  navigateToProduct(id: number) {
    this.router.navigate(['/products', id]);
  }

  navigateWithQueryParams() {
    this.router.navigate(['/products'], {
      queryParams: { category: 'electronics', sort: 'price' },
      fragment: 'top'
    });
  }

  navigateAndReplace() {
    this.router.navigate(['/dashboard'], { replaceUrl: true });
  }

  navigateRelative() {
    // Navigate relative to current route
    this.router.navigate(['../sibling'], { relativeTo: this.route });
  }
}
```

---

## Backend Development

### Node.js

#### Express.js Framework

```javascript
// app.js - Main application setup
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const compression = require('compression');

const userRoutes = require('./routes/users');
const productRoutes = require('./routes/products');
const authRoutes = require('./routes/auth');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Compression and logging
app.use(compression());
app.use(morgan('combined'));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Static files
app.use('/uploads', express.static('uploads'));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/products', productRoutes);

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    method: req.method,
    url: req.originalUrl
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);

  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;

// routes/users.js - User routes
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const auth = require('../middleware/auth');
const router = express.Router();

// Get all users
router.get('/', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10, search } = req.query;
    const offset = (page - 1) * limit;

    let query = {};
    if (search) {
      query = {
        $or: [
          { name: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } }
        ]
      };
    }

    const users = await User.find(query)
      .select('-password')
      .limit(limit * 1)
      .skip(offset)
      .sort({ createdAt: -1 });

    const total = await User.countDocuments(query);

    res.json({
      users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user by ID
router.get('/:id', auth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create user
router.post('/', [
  body('name').isLength({ min: 2 }).trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();

    // Remove password from response
    const userResponse = user.toObject();
    delete userResponse.password;

    res.status(201).json(userResponse);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update user
router.put('/:id', [
  auth,
  body('name').optional().isLength({ min: 2 }).trim().escape(),
  body('email').optional().isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete user
router.delete('/:id', auth, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
```

#### Middleware

```javascript
// middleware/auth.js - Authentication middleware
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({ error: 'No token, authorization denied' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');

    if (!user) {
      return res.status(401).json({ error: 'Token is not valid' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Token is not valid' });
  }
};

// middleware/authorize.js - Role-based authorization
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
    }

    next();
  };
};

// middleware/validate.js - Request validation
const { validationResult } = require('express-validator');

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};

// middleware/upload.js - File upload
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Only image files are allowed'));
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// middleware/cache.js - Caching middleware
const NodeCache = require('node-cache');
const cache = new NodeCache({ stdTTL: 600 }); // 10 minutes default

const cacheMiddleware = (duration = 600) => {
  return (req, res, next) => {
    // Only cache GET requests
    if (req.method !== 'GET') {
      return next();
    }

    const key = req.originalUrl;
    const cachedResponse = cache.get(key);

    if (cachedResponse) {
      return res.json(cachedResponse);
    }

    // Store original res.json
    const originalJson = res.json;

    // Override res.json
    res.json = function(body) {
      // Cache the response
      cache.set(key, body, duration);

      // Call original res.json
      originalJson.call(this, body);
    };

    next();
  };
};

module.exports = {
  auth,
  authorize,
  validate,
  upload,
  cacheMiddleware
};
```

#### Error Handling

```javascript
// utils/AppError.js - Custom error class
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = AppError;

// utils/catchAsync.js - Async error wrapper
const catchAsync = (fn) => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

module.exports = catchAsync;

// middleware/errorHandler.js - Global error handler
const AppError = require('../utils/AppError');

const handleCastErrorDB = (err) => {
  const message = `Invalid ${err.path}: ${err.value}`;
  return new AppError(message, 400);
};

const handleDuplicateFieldsDB = (err) => {
  const value = err.errmsg.match(/(["'])(\\?.)*?\1/)[0];
  const message = `Duplicate field value: ${value}. Please use another value!`;
  return new AppError(message, 400);
};

const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map(el => el.message);
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new AppError(message, 400);
};

const handleJWTError = () =>
  new AppError('Invalid token. Please log in again!', 401);

const handleJWTExpiredError = () =>
  new AppError('Your token has expired! Please log in again.', 401);

const sendErrorDev = (err, res) => {
  res.status(err.statusCode).json({
    status: err.status,
    error: err,
    message: err.message,
    stack: err.stack
  });
};

const sendErrorProd = (err, res) => {
  // Operational, trusted error: send message to client
  if (err.isOperational) {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message
    });
  } else {
    // Programming or other unknown error: don't leak error details
    console.error('ERROR 💥', err);
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong!'
    });
  }
};

module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(err, res);
  } else {
    let error = { ...err };
    error.message = err.message;

    if (error.name === 'CastError') error = handleCastErrorDB(error);
    if (error.code === 11000) error = handleDuplicateFieldsDB(error);
    if (error.name === 'ValidationError') error = handleValidationErrorDB(error);
    if (error.name === 'JsonWebTokenError') error = handleJWTError();
    if (error.name === 'TokenExpiredError') error = handleJWTExpiredError();

    sendErrorProd(error, res);
  }
};

// Usage in routes
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/AppError');

router.get('/users/:id', catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    return next(new AppError('No user found with that ID', 404));
  }

  res.status(200).json({
    status: 'success',
    data: { user }
  });
}));
```

### Python

#### Django Framework

```python
# settings.py - Django settings
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key')
DEBUG = os.environ.get('DEBUG', 'False') == 'True'
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'localhost').split(',')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'corsheaders',
    'django_filters',
    'accounts',
    'products',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'myproject.urls'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'myproject'),
        'USER': os.environ.get('DB_USER', 'postgres'),
        'PASSWORD': os.environ.get('DB_PASSWORD', 'password'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}

# REST Framework configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
}

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# models.py - Django models
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator

class User(AbstractUser):
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=15, blank=True)
    avatar = models.ImageField(upload_to='avatars/', blank=True)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

class Category(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "categories"

    def __str__(self):
        return self.name

class Product(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='products')
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='products')
    image = models.ImageField(upload_to='products/', blank=True)
    stock = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.name

class Review(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='reviews')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    rating = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('product', 'user')

    def __str__(self):
        return f'{self.user.username} - {self.product.name} ({self.rating}★)'

# serializers.py - DRF serializers
from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User, Product, Category, Review

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'password')

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            user = authenticate(username=email, password=password)
            if user:
                if user.is_active:
                    data['user'] = user
                else:
                    raise serializers.ValidationError('User account is disabled.')
            else:
                raise serializers.ValidationError('Unable to log in with provided credentials.')
        else:
            raise serializers.ValidationError('Must include email and password.')

        return data

class CategorySerializer(serializers.ModelSerializer):
    products_count = serializers.SerializerMethodField()

    class Meta:
        model = Category
        fields = '__all__'

    def get_products_count(self, obj):
        return obj.products.count()

class ReviewSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Review
        fields = '__all__'

class ProductSerializer(serializers.ModelSerializer):
    category = CategorySerializer(read_only=True)
    category_id = serializers.IntegerField(write_only=True)
    reviews = ReviewSerializer(many=True, read_only=True)
    average_rating = serializers.SerializerMethodField()
    owner = UserSerializer(read_only=True)

    class Meta:
        model = Product
        fields = '__all__'

    def get_average_rating(self, obj):
        reviews = obj.reviews.all()
        if reviews:
            return sum(review.rating for review in reviews) / len(reviews)
        return 0

# views.py - Django views
from rest_framework import generics, status, filters
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.auth import authenticate
from .models import Product, Category, Review
from .serializers import ProductSerializer, CategorySerializer, ReviewSerializer, UserSerializer, LoginSerializer

@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'user': UserSerializer(user).data,
            'token': token.key
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'user': UserSerializer(user).data,
            'token': token.key
        })
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProductListCreateView(generics.ListCreateAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['category', 'is_active']
    search_fields = ['name', 'description']
    ordering_fields = ['price', 'created_at']

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

class ProductDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer

    def get_permissions(self):
        if self.request.method in ['PUT', 'PATCH', 'DELETE']:
            return [IsAuthenticated()]
        return [AllowAny()]

class CategoryListView(generics.ListAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [AllowAny]

# urls.py - URL patterns
from django.urls import path, include
from . import views

urlpatterns = [
    path('auth/register/', views.register, name='register'),
    path('auth/login/', views.login, name='login'),
    path('products/', views.ProductListCreateView.as_view(), name='product-list'),
    path('products/<int:pk>/', views.ProductDetailView.as_view(), name='product-detail'),
    path('categories/', views.CategoryListView.as_view(), name='category-list'),
]
```

#### Flask Framework

```python
# app.py - Flask application
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-string')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
CORS(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    products = db.relationship('Product', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'created_at': self.created_at.isoformat()
        }

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat()
        }

# Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already taken'}), 400

    user = User(email=data['email'], username=data['username'])
    user.set_password(data['password'])

    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity=user.id)
    return jsonify({
        'access_token': access_token,
        'user': user.to_dict()
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if user and user.check_password(data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'access_token': access_token,
            'user': user.to_dict()
        })

    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/products', methods=['GET', 'POST'])
@jwt_required()
def products():
    if request.method == 'GET':
        products = Product.query.all()
        return jsonify([product.to_dict() for product in products])

    elif request.method == 'POST':
        data = request.get_json()
        current_user_id = get_jwt_identity()

        product = Product(
            name=data['name'],
            description=data['description'],
            price=data['price'],
            user_id=current_user_id
        )

        db.session.add(product)
        db.session.commit()

        return jsonify(product.to_dict()), 201

@app.route('/api/products/<int:product_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    current_user_id = get_jwt_identity()

    if request.method == 'GET':
        return jsonify(product.to_dict())

    elif request.method == 'PUT':
        if product.user_id != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        data = request.get_json()
        product.name = data.get('name', product.name)
        product.description = data.get('description', product.description)
        product.price = data.get('price', product.price)

        db.session.commit()
        return jsonify(product.to_dict())

    elif request.method == 'DELETE':
        if product.user_id != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        db.session.delete(product)
        db.session.commit()
        return '', 204

@app.route('/api/me', methods=['GET'])
@jwt_required()
def get_current_user():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify(user.to_dict())

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
```

#### FastAPI

```python
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt

app = FastAPI()

# Database
engine = create_engine("sqlite:///./test.db")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

# Pydantic models
class UserCreate(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    email: str

# Auth
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "secret"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    return db_user

@app.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
```

### Java

#### Spring Boot

```java
// Application.java
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

// User.java
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String email;

    private String password;

    // getters/setters
}

// UserController.java
@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping
    public List<User> getAllUsers() {
        return userService.findAll();
    }

    @PostMapping
    public ResponseEntity<User> createUser(@RequestBody User user) {
        User savedUser = userService.save(user);
        return ResponseEntity.ok(savedUser);
    }

    @GetMapping("/{id}")
    public ResponseEntity<User> getUser(@PathVariable Long id) {
        return userService.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }
}

// UserService.java
@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public List<User> findAll() {
        return userRepository.findAll();
    }

    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }

    public User save(User user) {
        return userRepository.save(user);
    }
}

// UserRepository.java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
}
```

#### Spring Security

```java
// SecurityConfig.java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }
}

// AuthController.java
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authManager;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest request) {
        Authentication auth = authManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getEmail(),
                request.getPassword()
            )
        );
        String token = jwtService.generateToken(auth);
        return ResponseEntity.ok(token);
    }
}
```

### C# .NET

#### ASP.NET Core

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

// Models/User.cs
public class User
{
    public int Id { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
    public DateTime CreatedAt { get; set; }
}

// Controllers/UsersController.cs
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly AppDbContext _context;

    public UsersController(AppDbContext context)
    {
        _context = context;
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<User>>> GetUsers()
    {
        return await _context.Users.ToListAsync();
    }

    [HttpPost]
    public async Task<ActionResult<User>> PostUser(User user)
    {
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<User>> GetUser(int id)
    {
        var user = await _context.Users.FindAsync(id);
        return user == null ? NotFound() : user;
    }
}
```

#### Entity Framework

```csharp
// Data/AppDbContext.cs
public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users { get; set; }
    public DbSet<Product> Products { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Email)
            .IsUnique();

        modelBuilder.Entity<Product>()
            .HasOne<User>()
            .WithMany()
            .HasForeignKey(p => p.UserId);
    }
}

// Services/UserService.cs
public class UserService
{
    private readonly AppDbContext _context;

    public UserService(AppDbContext context)
    {
        _context = context;
    }

    public async Task<User> CreateUserAsync(User user)
    {
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        return user;
    }

    public async Task<User> GetUserByIdAsync(int id)
    {
        return await _context.Users
            .Include(u => u.Products)
            .FirstOrDefaultAsync(u => u.Id == id);
    }
}
```

### PHP

#### Laravel Framework

```php
// routes/api.php
Route::apiResource('users', UserController::class);
Route::post('login', [AuthController::class, 'login']);

// app/Models/User.php
class User extends Authenticatable
{
    protected $fillable = ['name', 'email', 'password'];
    protected $hidden = ['password'];

    protected $casts = ['password' => 'hashed'];

    public function products()
    {
        return $this->hasMany(Product::class);
    }
}

// app/Http/Controllers/UserController.php
class UserController extends Controller
{
    public function index()
    {
        return User::paginate(10);
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6'
        ]);

        return User::create($validated);
    }

    public function show(User $user)
    {
        return $user->load('products');
    }
}

// app/Http/Controllers/AuthController.php
class AuthController extends Controller
{
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required'
        ]);

        if (Auth::attempt($credentials)) {
            $user = Auth::user();
            $token = $user->createToken('auth-token')->plainTextToken;
            return response()->json(['token' => $token, 'user' => $user]);
        }

        return response()->json(['error' => 'Invalid credentials'], 401);
    }
}
```

---

## Databases

**Databases** store, organize, and retrieve application data. Choosing the right database depends on your data structure, consistency requirements, scaling needs, and query patterns.

**SQL vs NoSQL:**
- **SQL (Relational)**: Structured data, ACID transactions, complex relationships
- **NoSQL**: Flexible schema, horizontal scaling, big data, specific use cases

**Key Considerations:**
- **Consistency**: How important is data accuracy vs availability?
- **Scaling**: Vertical (more powerful servers) vs horizontal (more servers)
- **Query complexity**: Simple lookups vs complex joins and analytics
- **Performance**: Read-heavy vs write-heavy workloads

### SQL Databases

#### MySQL

```sql
-- Database Creation
CREATE DATABASE ecommerce;
USE ecommerce;

-- Table Creation
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX idx_email ON users(email);
CREATE INDEX idx_price ON products(price);

-- Queries
SELECT u.email, COUNT(p.id) as product_count
FROM users u
LEFT JOIN products p ON u.id = p.user_id
GROUP BY u.id;

-- Stored Procedure
DELIMITER //
CREATE PROCEDURE GetUserProducts(IN userId INT)
BEGIN
    SELECT * FROM products WHERE user_id = userId;
END //
DELIMITER ;
```

#### PostgreSQL

```sql
-- Advanced Data Types
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    tags TEXT[],
    metadata JSONB,
    price NUMERIC(10,2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- JSONB Operations
INSERT INTO products (name, tags, metadata, price) VALUES
('Laptop', ARRAY['electronics', 'computers'],
 '{"brand": "Apple", "model": "MacBook Pro"}', 1299.99);

-- Query JSONB
SELECT * FROM products WHERE metadata->>'brand' = 'Apple';
SELECT * FROM products WHERE metadata @> '{"brand": "Apple"}';

-- Full-text Search
ALTER TABLE products ADD COLUMN search_vector tsvector;
UPDATE products SET search_vector = to_tsvector('english', name);
CREATE INDEX idx_search ON products USING gin(search_vector);

SELECT * FROM products WHERE search_vector @@ to_tsquery('laptop');

-- Window Functions
SELECT name, price,
       ROW_NUMBER() OVER (ORDER BY price DESC) as rank,
       LAG(price) OVER (ORDER BY price) as prev_price
FROM products;
```

#### SQL Server

```sql
-- Table with Identity and Constraints
CREATE TABLE Users (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    Email NVARCHAR(255) UNIQUE NOT NULL,
    Password NVARCHAR(255) NOT NULL,
    CreatedAt DATETIME2 DEFAULT GETDATE()
);

-- Common Table Expression (CTE)
WITH ProductStats AS (
    SELECT
        user_id,
        COUNT(*) as product_count,
        AVG(price) as avg_price
    FROM products
    GROUP BY user_id
)
SELECT u.Email, ps.product_count, ps.avg_price
FROM Users u
JOIN ProductStats ps ON u.Id = ps.user_id;

-- Stored Procedure with Error Handling
CREATE PROCEDURE CreateUser
    @Email NVARCHAR(255),
    @Password NVARCHAR(255)
AS
BEGIN
    BEGIN TRY
        BEGIN TRANSACTION
        INSERT INTO Users (Email, Password) VALUES (@Email, @Password)
        COMMIT TRANSACTION
    END TRY
    BEGIN CATCH
        ROLLBACK TRANSACTION
        THROW
    END CATCH
END
```

#### SQLite

```sql
-- Lightweight Database
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- JSON Extension
SELECT json_extract(metadata, '$.brand') as brand
FROM products
WHERE json_extract(metadata, '$.price') > 1000;

-- FTS (Full-Text Search)
CREATE VIRTUAL TABLE products_fts USING fts5(name, description);
INSERT INTO products_fts SELECT name, description FROM products;
SELECT * FROM products_fts WHERE products_fts MATCH 'laptop computer';
```

### NoSQL Databases

#### MongoDB

```javascript
// Connection
const { MongoClient } = require('mongodb');
const client = new MongoClient('mongodb://localhost:27017');

// Basic Operations
const db = client.db('ecommerce');
const users = db.collection('users');

// Insert
await users.insertOne({
    email: 'john@example.com',
    profile: {
        name: 'John Doe',
        age: 30,
        preferences: ['electronics', 'books']
    },
    createdAt: new Date()
});

// Query
const user = await users.findOne({ email: 'john@example.com' });
const youngUsers = await users.find({ 'profile.age': { $lt: 25 } }).toArray();

// Update
await users.updateOne(
    { email: 'john@example.com' },
    { $set: { 'profile.age': 31 }, $push: { 'profile.preferences': 'gaming' } }
);

// Aggregation Pipeline
const result = await users.aggregate([
    { $match: { 'profile.age': { $gte: 18 } } },
    { $group: { _id: '$profile.age', count: { $sum: 1 } } },
    { $sort: { count: -1 } }
]).toArray();

// Indexing
await users.createIndex({ email: 1 });
await users.createIndex({ 'profile.preferences': 1 });
```

#### Redis

```javascript
const redis = require('redis');
const client = redis.createClient();

// String Operations
await client.set('user:1000', JSON.stringify({ name: 'John', age: 30 }));
const userData = JSON.parse(await client.get('user:1000'));

// Hash Operations
await client.hSet('user:1001', {
    name: 'Jane',
    age: '25',
    email: 'jane@example.com'
});
const userName = await client.hGet('user:1001', 'name');

// List Operations (Queue)
await client.lPush('tasks', 'send-email');
await client.lPush('tasks', 'process-payment');
const task = await client.rPop('tasks');

// Set Operations
await client.sAdd('online-users', 'user1', 'user2', 'user3');
const isOnline = await client.sIsMember('online-users', 'user1');

// Sorted Sets (Leaderboard)
await client.zAdd('leaderboard', [
    { score: 100, value: 'player1' },
    { score: 150, value: 'player2' }
]);
const topPlayers = await client.zRange('leaderboard', 0, 9, { REV: true });

// Expiration
await client.setEx('session:abc123', 3600, 'user-data');
```

#### Cassandra

```sql
-- Keyspace Creation
CREATE KEYSPACE ecommerce
WITH REPLICATION = {
    'class': 'SimpleStrategy',
    'replication_factor': 3
};

USE ecommerce;

-- Table with Partition and Clustering Keys
CREATE TABLE user_activities (
    user_id UUID,
    activity_date DATE,
    activity_time TIMESTAMP,
    activity_type TEXT,
    details MAP<TEXT, TEXT>,
    PRIMARY KEY ((user_id, activity_date), activity_time)
) WITH CLUSTERING ORDER BY (activity_time DESC);

-- Insert Data
INSERT INTO user_activities (user_id, activity_date, activity_time, activity_type, details)
VALUES (
    uuid(),
    '2024-01-15',
    '2024-01-15 10:30:00',
    'login',
    {'ip': '192.168.1.1', 'device': 'mobile'}
);

-- Query by Partition Key
SELECT * FROM user_activities
WHERE user_id = 550e8400-e29b-41d4-a716-446655440000
AND activity_date = '2024-01-15';
```

#### Firebase Firestore

```javascript
import { initializeApp } from 'firebase/app';
import { getFirestore, collection, addDoc, getDocs, query, where } from 'firebase/firestore';

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);

// Add Document
const docRef = await addDoc(collection(db, 'users'), {
    name: 'John Doe',
    email: 'john@example.com',
    createdAt: new Date()
});

// Get Documents
const querySnapshot = await getDocs(collection(db, 'users'));
querySnapshot.forEach((doc) => {
    console.log(doc.id, '=>', doc.data());
});

// Query with Conditions
const q = query(collection(db, 'users'), where('age', '>', 18));
const adults = await getDocs(q);

// Real-time Updates
const unsubscribe = onSnapshot(collection(db, 'users'), (snapshot) => {
    snapshot.docChanges().forEach((change) => {
        if (change.type === 'added') {
            console.log('New user: ', change.doc.data());
        }
    });
});
```

### Database Design

#### Normalization

```sql
-- 1NF: Atomic Values
CREATE TABLE customers (
    id INT PRIMARY KEY,
    name VARCHAR(255),
    phone VARCHAR(20) -- Single phone number
);

-- 2NF: No Partial Dependencies
CREATE TABLE order_items (
    order_id INT,
    product_id INT,
    quantity INT,
    unit_price DECIMAL(10,2),
    PRIMARY KEY (order_id, product_id)
);

-- 3NF: No Transitive Dependencies
CREATE TABLE orders (
    id INT PRIMARY KEY,
    customer_id INT,
    order_date DATE,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);

-- Denormalization for Performance
CREATE TABLE order_summary (
    id INT PRIMARY KEY,
    customer_name VARCHAR(255), -- Denormalized
    total_amount DECIMAL(10,2),
    item_count INT
);
```

#### Indexing

```sql
-- Single Column Index
CREATE INDEX idx_email ON users(email);

-- Composite Index
CREATE INDEX idx_name_date ON orders(customer_id, order_date);

-- Partial Index (PostgreSQL)
CREATE INDEX idx_active_users ON users(email) WHERE active = true;

-- Covering Index
CREATE INDEX idx_user_profile ON users(id) INCLUDE (name, email, created_at);

-- Index Usage Analysis
EXPLAIN SELECT * FROM users WHERE email = 'john@example.com';
```

#### Query Optimization

```sql
-- Use EXPLAIN to analyze queries
EXPLAIN ANALYZE SELECT u.name, COUNT(o.id)
FROM users u
LEFT JOIN orders o ON u.id = o.customer_id
WHERE u.created_at > '2024-01-01'
GROUP BY u.id;

-- Optimize with proper indexing
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_orders_customer_id ON orders(customer_id);

-- Avoid N+1 queries with joins
SELECT u.*, o.total_amount
FROM users u
LEFT JOIN orders o ON u.id = o.customer_id;

-- Use LIMIT for pagination
SELECT * FROM products
ORDER BY created_at DESC
LIMIT 20 OFFSET 100;
```

---

## API Development

**APIs (Application Programming Interfaces)** define how different software components communicate. They specify data formats, request/response structures, and available operations, enabling frontend-backend communication and third-party integrations.

**API Design Principles:**
- **Consistency**: Predictable naming and behavior patterns
- **Stateless**: Each request contains all necessary information
- **Resource-based**: URLs represent entities, not actions
- **Proper HTTP methods**: Use GET, POST, PUT, DELETE appropriately
- **Clear error handling**: Meaningful error codes and messages

### REST APIs

**REST (Representational State Transfer)** is an architectural style for designing APIs. RESTful APIs use standard HTTP methods and status codes to perform operations on resources identified by URLs.

**REST Principles:**
- **Stateless**: No server-side session state
- **Cacheable**: Responses can be cached for performance
- **Uniform interface**: Consistent way to interact with resources
- **Client-server separation**: Frontend and backend are independent

#### HTTP Methods

```javascript
// GET - Retrieve data
app.get('/api/users', (req, res) => {
    const users = getUsersFromDB();
    res.json(users);
});

// POST - Create new resource
app.post('/api/users', (req, res) => {
    const newUser = createUser(req.body);
    res.status(201).json(newUser);
});

// PUT - Update entire resource
app.put('/api/users/:id', (req, res) => {
    const updatedUser = updateUser(req.params.id, req.body);
    res.json(updatedUser);
});

// PATCH - Partial update
app.patch('/api/users/:id', (req, res) => {
    const user = partialUpdateUser(req.params.id, req.body);
    res.json(user);
});

// DELETE - Remove resource
app.delete('/api/users/:id', (req, res) => {
    deleteUser(req.params.id);
    res.status(204).send();
});
```

#### Status Codes

```javascript
// Success Codes
res.status(200).json(data);        // OK
res.status(201).json(newResource); // Created
res.status(204).send();            // No Content

// Client Error Codes
res.status(400).json({ error: 'Bad Request' });
res.status(401).json({ error: 'Unauthorized' });
res.status(403).json({ error: 'Forbidden' });
res.status(404).json({ error: 'Not Found' });
res.status(422).json({ error: 'Validation Error' });

// Server Error Codes
res.status(500).json({ error: 'Internal Server Error' });
res.status(503).json({ error: 'Service Unavailable' });
```

#### API Design Best Practices

```javascript
// RESTful URL Structure
GET    /api/users              // Get all users
GET    /api/users/123          // Get specific user
POST   /api/users              // Create user
PUT    /api/users/123          // Update user
DELETE /api/users/123          // Delete user
GET    /api/users/123/posts    // Get user's posts

// Filtering and Pagination
GET /api/users?page=1&limit=20&sort=created_at&filter=active

// Versioning
GET /api/v1/users
GET /api/v2/users

// Standard Response Format
{
    "data": [...],
    "meta": {
        "page": 1,
        "limit": 20,
        "total": 100,
        "pages": 5
    },
    "links": {
        "self": "/api/users?page=1",
        "next": "/api/users?page=2",
        "prev": null
    }
}
```

### GraphQL

**GraphQL** is a query language and runtime for APIs that allows clients to request exactly the data they need. Unlike REST APIs with fixed endpoints, GraphQL provides a single endpoint where clients specify their data requirements.

**Key Benefits:**
- **Precise data fetching**: Request only needed fields, reducing over/under-fetching
- **Single endpoint**: One URL handles all data operations
- **Strong typing**: Schema defines exact data structure and operations
- **Real-time subscriptions**: Live data updates via WebSocket connections
- **Introspection**: API is self-documenting

**GraphQL vs REST:**
- **REST**: Multiple endpoints, fixed response structure
- **GraphQL**: Single endpoint, flexible response structure
- **REST**: Multiple requests for related data
- **GraphQL**: Single request can fetch related data

#### Queries and Mutations

```graphql
# Schema Definition
type User {
    id: ID!
    name: String!
    email: String!
    posts: [Post!]!
}

type Post {
    id: ID!
    title: String!
    content: String!
    author: User!
}

type Query {
    users: [User!]!
    user(id: ID!): User
    posts: [Post!]!
}

type Mutation {
    createUser(input: CreateUserInput!): User!
    updateUser(id: ID!, input: UpdateUserInput!): User!
    deleteUser(id: ID!): Boolean!
}

input CreateUserInput {
    name: String!
    email: String!
}
```

```javascript
// Resolvers
const resolvers = {
    Query: {
        users: () => User.findAll(),
        user: (_, { id }) => User.findById(id),
        posts: () => Post.findAll()
    },

    Mutation: {
        createUser: (_, { input }) => User.create(input),
        updateUser: (_, { id, input }) => User.update(id, input),
        deleteUser: (_, { id }) => User.delete(id)
    },

    User: {
        posts: (user) => Post.findByUserId(user.id)
    }
};

// Client Query
query GetUser($id: ID!) {
    user(id: $id) {
        id
        name
        email
        posts {
            id
            title
        }
    }
}

// Client Mutation
mutation CreateUser($input: CreateUserInput!) {
    createUser(input: $input) {
        id
        name
        email
    }
}
```

#### Schema Design

```graphql
# Interfaces
interface Node {
    id: ID!
}

# Unions
union SearchResult = User | Post | Comment

# Enums
enum PostStatus {
    DRAFT
    PUBLISHED
    ARCHIVED
}

# Custom Scalars
scalar DateTime
scalar Email

# Directives
directive @auth(requires: Role = USER) on FIELD_DEFINITION

type Post implements Node {
    id: ID!
    title: String!
    status: PostStatus!
    publishedAt: DateTime
    author: User! @auth(requires: ADMIN)
}
```

### API Testing

#### Postman

```javascript
// Pre-request Script
pm.environment.set("timestamp", Date.now());

// Test Script
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

pm.test("Response has required fields", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData).to.have.property('id');
    pm.expect(jsonData).to.have.property('email');
});

pm.test("Response time is less than 200ms", function () {
    pm.expect(pm.response.responseTime).to.be.below(200);
});

// Collection Variables
pm.globals.set("base_url", "https://api.example.com");
pm.environment.set("user_id", jsonData.id);
```

#### Jest/Mocha Testing

```javascript
// Jest API Testing
const request = require('supertest');
const app = require('../app');

describe('User API', () => {
    test('GET /api/users should return users list', async () => {
        const response = await request(app)
            .get('/api/users')
            .expect(200);

        expect(response.body).toHaveProperty('data');
        expect(Array.isArray(response.body.data)).toBe(true);
    });

    test('POST /api/users should create user', async () => {
        const userData = {
            name: 'John Doe',
            email: 'john@example.com'
        };

        const response = await request(app)
            .post('/api/users')
            .send(userData)
            .expect(201);

        expect(response.body.name).toBe(userData.name);
        expect(response.body.email).toBe(userData.email);
    });
});

// Mocha with Chai
const chai = require('chai');
const chaiHttp = require('chai-http');
const expect = chai.expect;

chai.use(chaiHttp);

describe('API Tests', () => {
    it('should get all users', (done) => {
        chai.request(app)
            .get('/api/users')
            .end((err, res) => {
                expect(res).to.have.status(200);
                expect(res.body).to.be.an('array');
                done();
            });
    });
});
```

#### API Documentation

```yaml
# OpenAPI/Swagger Specification
openapi: 3.0.0
info:
  title: User API
  version: 1.0.0
  description: API for managing users

paths:
  /users:
    get:
      summary: Get all users
      parameters:
        - name: page
          in: query
          schema:
            type: integer
            default: 1
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    type: array
                    items:
                      $ref: '#/components/schemas/User'

    post:
      summary: Create a new user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateUser'
      responses:
        '201':
          description: User created

components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: integer
        name:
          type: string
        email:
          type: string
          format: email

    CreateUser:
      type: object
      required:
        - name
        - email
      properties:
        name:
          type: string
        email:
          type: string
          format: email
```

---

## Authentication and Security

**Authentication** verifies user identity, while **authorization** determines what authenticated users can access. Security is critical for protecting user data, preventing unauthorized access, and maintaining application integrity.

**Authentication vs Authorization:**
- **Authentication**: "Who are you?" (login with username/password)
- **Authorization**: "What can you do?" (user roles and permissions)

**Security Fundamentals:**
- **Input validation**: Never trust user input
- **Encryption**: Protect data in transit (HTTPS) and at rest
- **Principle of least privilege**: Give minimum necessary permissions
- **Defense in depth**: Multiple security layers

### Authentication Methods

#### Session-based Authentication

**Session-based auth** stores user state on the server. After login, the server creates a session and sends a session ID cookie to the client. The client includes this cookie in subsequent requests.

**Pros:** Server controls sessions, easy to revoke access
**Cons:** Doesn't scale well across multiple servers, requires session storage

#### Session-based Authentication

```javascript
// Express Session Setup
const session = require('express-session');
const MongoStore = require('connect-mongo');

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: 'mongodb://localhost/session-store'
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await authenticateUser(email, password);

    if (user) {
        req.session.userId = user.id;
        res.json({ message: 'Login successful' });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Protected Route Middleware
const requireAuth = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
};
```

#### JWT Tokens

**JWT (JSON Web Tokens)** are self-contained tokens that encode user information. They're stateless - no server-side storage needed. JWTs consist of three parts: header, payload, and signature.

**Pros:** Stateless, scalable across multiple servers, contains user data
**Cons:** Can't be revoked easily, larger than session IDs, sensitive to key compromise

```javascript
const jwt = require('jsonwebtoken');

// Generate JWT
const generateToken = (user) => {
    return jwt.sign(
        { userId: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
    );
};

// Login with JWT
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await authenticateUser(email, password);

    if (user) {
        const token = generateToken(user);
        res.json({ token, user: { id: user.id, email: user.email } });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// JWT Middleware
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Refresh Token Implementation
const generateRefreshToken = (userId) => {
    return jwt.sign({ userId }, process.env.REFRESH_SECRET, { expiresIn: '7d' });
};

app.post('/refresh', (req, res) => {
    const { refreshToken } = req.body;

    try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
        const newToken = generateToken({ id: decoded.userId });
        res.json({ token: newToken });
    } catch (error) {
        res.status(401).json({ error: 'Invalid refresh token' });
    }
});
```

#### OAuth 2.0

```javascript
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
            user = await User.create({
                googleId: profile.id,
                name: profile.displayName,
                email: profile.emails[0].value
            });
        }

        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
}));

// Routes
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        const token = generateToken(req.user);
        res.redirect(`/dashboard?token=${token}`);
    }
);
```

### Security Best Practices

#### Input Validation

```javascript
const { body, validationResult } = require('express-validator');
const xss = require('xss');

// Validation Middleware
const validateUser = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Valid email required'),
    body('password')
        .isLength({ min: 8 })
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .withMessage('Password must contain uppercase, lowercase, number and special character'),
    body('name')
        .trim()
        .escape()
        .isLength({ min: 2, max: 50 })
];

// Route with Validation
app.post('/register', validateUser, (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    // Sanitize input
    const userData = {
        email: req.body.email,
        password: req.body.password,
        name: xss(req.body.name)
    };

    // Create user...
});
```

#### SQL Injection Prevention

```javascript
// Parameterized Queries (Good)
const getUserById = async (id) => {
    const query = 'SELECT * FROM users WHERE id = ?';
    return await db.query(query, [id]);
};

// ORM/ODM Usage (Good)
const user = await User.findById(userId);
const products = await Product.find({ userId: req.user.id });

// String Concatenation (Bad - Never do this)
const query = `SELECT * FROM users WHERE id = ${userId}`; // Vulnerable!
```

#### XSS Protection

```javascript
const helmet = require('helmet');
const xss = require('xss');

// Helmet for security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"]
        }
    }
}));

// XSS Sanitization
const sanitizeInput = (req, res, next) => {
    for (let key in req.body) {
        if (typeof req.body[key] === 'string') {
            req.body[key] = xss(req.body[key]);
        }
    }
    next();
};

// Content Security Policy
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline'"
    );
    next();
});
```

#### CSRF Protection

```javascript
const csrf = require('csurf');

// CSRF Protection
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    }
});

app.use(csrfProtection);

// Provide CSRF token to client
app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Double Submit Cookie Pattern
const generateCSRFToken = () => crypto.randomBytes(32).toString('hex');

app.use((req, res, next) => {
    if (!req.cookies.csrfToken) {
        const token = generateCSRFToken();
        res.cookie('csrfToken', token, { httpOnly: false, secure: true });
        req.csrfToken = token;
    }
    next();
});
```

### HTTPS and SSL

```javascript
const https = require('https');
const fs = require('fs');

// SSL Certificate Setup
const options = {
    key: fs.readFileSync('private-key.pem'),
    cert: fs.readFileSync('certificate.pem')
};

// HTTPS Server
https.createServer(options, app).listen(443, () => {
    console.log('HTTPS Server running on port 443');
});

// Redirect HTTP to HTTPS
app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
        res.redirect(`https://${req.header('host')}${req.url}`);
    } else {
        next();
    }
});

// HSTS Header
app.use((req, res, next) => {
    res.setHeader(
        'Strict-Transport-Security',
        'max-age=31536000; includeSubDomains; preload'
    );
    next();
});
```

---

## DevOps and Deployment

### Version Control

#### Git Workflow

```bash
# Basic Git Commands
git init
git add .
git commit -m "Initial commit"
git push origin main

# Branching
git checkout -b feature/user-auth
git merge feature/user-auth
git branch -d feature/user-auth

# Stashing
git stash
git stash pop
git stash list

# Reset and Revert
git reset --hard HEAD~1
git revert HEAD
```

#### Branching Strategies

```bash
# Git Flow
git flow init
git flow feature start new-feature
git flow feature finish new-feature

# GitHub Flow
git checkout main
git pull origin main
git checkout -b feature-branch
# Make changes, commit, push
# Create pull request

# Conventional Commits
git commit -m "feat: add user authentication"
git commit -m "fix: resolve login bug"
git commit -m "docs: update API documentation"
```

### Containerization

#### Docker

**Docker** is a containerization platform that packages applications and their dependencies into lightweight, portable containers. Containers ensure consistent behavior across different environments (development, testing, production) by isolating applications from the host system.

**Key Benefits:**
- **Consistency**: "Works on my machine" becomes "works everywhere"
- **Isolation**: Applications run independently without conflicts
- **Portability**: Same container runs on any Docker-enabled system
- **Efficiency**: Lighter than virtual machines, faster startup times
- **Scalability**: Easy to scale applications horizontally

```dockerfile
# Dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]

# Multi-stage build
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:18-alpine AS production
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY --from=builder /app/dist ./dist
CMD ["node", "dist/index.js"]
```

```bash
# Docker Commands
docker build -t myapp .
docker run -p 3000:3000 myapp
docker ps
docker logs container_id
docker exec -it container_id sh

# Image management
docker images
docker rmi image_id
docker prune
```

#### Docker Compose

**Docker Compose** is a tool for defining and running multi-container Docker applications. Instead of managing multiple containers individually, Compose uses a YAML file to configure all services, networks, and volumes in one place.

**Use Cases:**
- **Multi-service apps**: Web app + database + cache + load balancer
- **Development environments**: Consistent setup across team members
- **Testing**: Spin up entire application stack for integration tests
- **Local production simulation**: Run production-like environment locally

```yaml
# docker-compose.yml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DB_HOST=db
    depends_on:
      - db
      - redis

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf

volumes:
  postgres_data:
```

```bash
# Docker Compose Commands
docker-compose up -d
docker-compose down
docker-compose logs
docker-compose exec app sh
```

#### Kubernetes

**Kubernetes (K8s)** is a container orchestration platform that automates deployment, scaling, and management of containerized applications. While Docker runs containers, Kubernetes manages them at scale across multiple machines.

**Core Concepts:**
- **Pods**: Smallest deployable units (usually one container)
- **Deployments**: Manage replicas and updates of pods
- **Services**: Expose pods to network traffic
- **ConfigMaps/Secrets**: Manage configuration and sensitive data
- **Ingress**: Handle external access and load balancing

**Why Use Kubernetes:**
- **Auto-scaling**: Scale pods based on CPU/memory usage
- **Self-healing**: Restart failed containers automatically
- **Rolling updates**: Deploy new versions without downtime
- **Load balancing**: Distribute traffic across healthy pods
- **Service discovery**: Pods can find and communicate with each other

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: myapp
        image: myapp:latest
        ports:
        - containerPort: 3000
        env:
        - name: DB_HOST
          value: "postgres-service"

---
apiVersion: v1
kind: Service
metadata:
  name: myapp-service
spec:
  selector:
    app: myapp
  ports:
  - port: 80
    targetPort: 3000
  type: LoadBalancer
```

```bash
# Kubernetes Commands
kubectl apply -f deployment.yaml
kubectl get pods
kubectl get services
kubectl logs pod-name
kubectl scale deployment myapp --replicas=5
```

### Cloud Platforms

#### AWS

```yaml
# CloudFormation Template
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  EC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0abcdef1234567890
      InstanceType: t3.micro
      SecurityGroups:
        - !Ref WebServerSecurityGroup

  WebServerSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Security group for web server
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
```

```javascript
// AWS SDK Example
const AWS = require('aws-sdk');
const s3 = new AWS.S3();

// Upload file to S3
const uploadFile = async (bucketName, key, body) => {
    const params = {
        Bucket: bucketName,
        Key: key,
        Body: body,
        ContentType: 'application/json'
    };
    return await s3.upload(params).promise();
};

// Lambda Function
exports.handler = async (event) => {
    console.log('Event:', JSON.stringify(event));
    return {
        statusCode: 200,
        body: JSON.stringify({ message: 'Success' })
    };
};
```

#### Google Cloud Platform

```yaml
# app.yaml for App Engine
runtime: nodejs18
service: default

automatic_scaling:
  min_instances: 1
  max_instances: 10

env_variables:
  NODE_ENV: production
  DB_HOST: 10.0.0.1
```

```bash
# GCP Commands
gcloud app deploy
gcloud compute instances list
gcloud sql connect myinstance --user=root
```

#### Microsoft Azure

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Web/sites",
      "apiVersion": "2021-02-01",
      "name": "mywebapp",
      "location": "[resourceGroup().location]",
      "properties": {
        "serverFarmId": "[resourceId('Microsoft.Web/serverfarms', 'myappplan')]"
      }
    }
  ]
}
```

#### Vercel/Netlify

```json
// vercel.json
{
  "version": 2,
  "builds": [
    {
      "src": "package.json",
      "use": "@vercel/node"
    }
  ],
  "routes": [
    {
      "src": "/api/(.*)",
      "dest": "/api/$1"
    }
  ]
}
```

```toml
# netlify.toml
[build]
  publish = "dist"
  command = "npm run build"

[[redirects]]
  from = "/api/*"
  to = "/.netlify/functions/:splat"
  status = 200
```

### CI/CD

**CI/CD (Continuous Integration/Continuous Deployment)** automates the software development lifecycle from code commit to production deployment. It ensures code quality, reduces manual errors, and enables frequent, reliable releases.

**Continuous Integration (CI):**
- **Automated testing**: Run tests on every code commit
- **Code quality checks**: Linting, security scans, coverage reports
- **Build automation**: Compile and package applications
- **Fast feedback**: Developers know immediately if they broke something

**Continuous Deployment (CD):**
- **Automated deployment**: Deploy to staging/production without manual intervention
- **Environment consistency**: Same deployment process across all environments
- **Rollback capability**: Quick revert if issues are detected
- **Zero-downtime deployments**: Blue-green or rolling deployments

#### GitHub Actions

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm ci
      - run: npm test

  deploy:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Deploy to Heroku
        uses: akhileshns/heroku-deploy@v3.12.12
        with:
          heroku_api_key: ${{secrets.HEROKU_API_KEY}}
          heroku_app_name: "myapp"
          heroku_email: "user@example.com"
```

#### Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'npm install'
                sh 'npm run build'
            }
        }

        stage('Test') {
            steps {
                sh 'npm test'
            }
        }

        stage('Deploy') {
            steps {
                sh 'docker build -t myapp .'
                sh 'docker push myregistry/myapp:latest'
                sh 'kubectl apply -f k8s/'
            }
        }
    }
}
```

#### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - test
  - build
  - deploy

test:
  stage: test
  script:
    - npm ci
    - npm test

build:
  stage: build
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

deploy:
  stage: deploy
  script:
    - kubectl set image deployment/myapp myapp=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  only:
    - main
```

---

## Testing

**Testing** ensures code reliability, prevents bugs, and enables confident refactoring. A good testing strategy combines different types of tests to catch issues at various levels.

**Testing Pyramid:**
- **Unit Tests** (70%): Test individual functions/components in isolation
- **Integration Tests** (20%): Test how components work together
- **E2E Tests** (10%): Test complete user workflows

**Benefits:**
- **Bug prevention**: Catch issues before they reach production
- **Refactoring confidence**: Change code without fear of breaking things
- **Documentation**: Tests show how code should behave
- **Faster debugging**: Pinpoint exactly what broke and where

### Frontend Testing

#### Unit Testing

```javascript
// React Component Test (Jest + Testing Library)
import { render, screen, fireEvent } from '@testing-library/react';
import Button from '../Button';

test('renders button with text', () => {
    render(<Button>Click me</Button>);
    expect(screen.getByText('Click me')).toBeInTheDocument();
});

test('calls onClick when clicked', () => {
    const handleClick = jest.fn();
    render(<Button onClick={handleClick}>Click me</Button>);
    fireEvent.click(screen.getByText('Click me'));
    expect(handleClick).toHaveBeenCalledTimes(1);
});

// Vue Component Test
import { mount } from '@vue/test-utils';
import Counter from '../Counter.vue';

test('increments counter when button is clicked', async () => {
    const wrapper = mount(Counter);
    expect(wrapper.text()).toContain('Count: 0');
    await wrapper.find('button').trigger('click');
    expect(wrapper.text()).toContain('Count: 1');
});
```

#### Integration Testing

```javascript
// React Hook Test
import { renderHook, act } from '@testing-library/react';
import useCounter from '../useCounter';

test('should increment counter', () => {
    const { result } = renderHook(() => useCounter());

    act(() => {
        result.current.increment();
    });

    expect(result.current.count).toBe(1);
});

// API Integration Test
import { render, screen, waitFor } from '@testing-library/react';
import UserList from '../UserList';
import { server } from '../mocks/server';

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

test('displays users from API', async () => {
    render(<UserList />);
    await waitFor(() => {
        expect(screen.getByText('John Doe')).toBeInTheDocument();
    });
});
```

#### E2E Testing

```javascript
// Cypress
describe('User Authentication', () => {
    it('should allow user to login', () => {
        cy.visit('/login');
        cy.get('[data-testid="email"]').type('user@example.com');
        cy.get('[data-testid="password"]').type('password123');
        cy.get('[data-testid="submit"]').click();
        cy.url().should('include', '/dashboard');
        cy.contains('Welcome back!').should('be.visible');
    });
});

// Playwright
import { test, expect } from '@playwright/test';

test('user can create a new post', async ({ page }) => {
    await page.goto('/dashboard');
    await page.click('[data-testid="new-post"]');
    await page.fill('[data-testid="title"]', 'My New Post');
    await page.fill('[data-testid="content"]', 'Post content here');
    await page.click('[data-testid="publish"]');
    await expect(page.locator('.success-message')).toBeVisible();
});
```

### Backend Testing

#### API Testing

```javascript
// Express API Test
const request = require('supertest');
const app = require('../app');

describe('User API', () => {
    beforeEach(async () => {
        await User.deleteMany({});
    });

    test('POST /users creates a new user', async () => {
        const userData = {
            name: 'John Doe',
            email: 'john@example.com'
        };

        const response = await request(app)
            .post('/api/users')
            .send(userData)
            .expect(201);

        expect(response.body.name).toBe(userData.name);
        expect(response.body.email).toBe(userData.email);
    });

    test('GET /users/:id returns user', async () => {
        const user = await User.create({
            name: 'Jane Doe',
            email: 'jane@example.com'
        });

        const response = await request(app)
            .get(`/api/users/${user._id}`)
            .expect(200);

        expect(response.body._id).toBe(user._id.toString());
    });
});
```

#### Database Testing

```javascript
// MongoDB Test Setup
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

let mongoServer;

beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    await mongoose.connect(mongoUri);
});

afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
});

// PostgreSQL Test Setup
const { Pool } = require('pg');

const pool = new Pool({
    host: 'localhost',
    port: 5433,
    database: 'test_db',
    user: 'test_user',
    password: 'test_password'
});

beforeEach(async () => {
    await pool.query('BEGIN');
});

afterEach(async () => {
    await pool.query('ROLLBACK');
});
```

### Testing Tools

#### Jest

```javascript
// jest.config.js
module.exports = {
    testEnvironment: 'jsdom',
    setupFilesAfterEnv: ['<rootDir>/src/setupTests.js'],
    moduleNameMapping: {
        '\\.(css|less|scss|sass)$': 'identity-obj-proxy'
    },
    collectCoverageFrom: [
        'src/**/*.{js,jsx}',
        '!src/index.js'
    ]
};

// Mock functions
const mockFetch = jest.fn();
global.fetch = mockFetch;

// Spy on methods
const consoleSpy = jest.spyOn(console, 'log');
```

#### Cypress

```javascript
// cypress.config.js
module.exports = {
    e2e: {
        baseUrl: 'http://localhost:3000',
        video: false,
        screenshot: false
    }
};

// Custom commands
Cypress.Commands.add('login', (email, password) => {
    cy.request({
        method: 'POST',
        url: '/api/login',
        body: { email, password }
    }).then((response) => {
        window.localStorage.setItem('token', response.body.token);
    });
});
```

#### Selenium

```python
# Python Selenium
from selenium import webdriver
from selenium.webdriver.common.by import By

def test_login():
    driver = webdriver.Chrome()
    driver.get("http://localhost:3000/login")

    email_input = driver.find_element(By.ID, "email")
    password_input = driver.find_element(By.ID, "password")
    submit_button = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")

    email_input.send_keys("user@example.com")
    password_input.send_keys("password123")
    submit_button.click()

    assert "dashboard" in driver.current_url
    driver.quit()
```

---

## Performance Optimization

### Frontend Performance

#### Code Splitting

```javascript
// React Lazy Loading
import { lazy, Suspense } from 'react';

const Dashboard = lazy(() => import('./Dashboard'));
const Profile = lazy(() => import('./Profile'));

function App() {
    return (
        <Router>
            <Suspense fallback={<div>Loading...</div>}>
                <Routes>
                    <Route path="/dashboard" element={<Dashboard />} />
                    <Route path="/profile" element={<Profile />} />
                </Routes>
            </Suspense>
        </Router>
    );
}

// Webpack Bundle Splitting
module.exports = {
    optimization: {
        splitChunks: {
            chunks: 'all',
            cacheGroups: {
                vendor: {
                    test: /[\\/]node_modules[\\/]/,
                    name: 'vendors',
                    chunks: 'all'
                }
            }
        }
    }
};
```

#### Lazy Loading

```javascript
// Image Lazy Loading
import { useState, useEffect, useRef } from 'react';

function LazyImage({ src, alt, placeholder }) {
    const [loaded, setLoaded] = useState(false);
    const imgRef = useRef();

    useEffect(() => {
        const observer = new IntersectionObserver(
            ([entry]) => {
                if (entry.isIntersecting) {
                    setLoaded(true);
                    observer.disconnect();
                }
            },
            { threshold: 0.1 }
        );

        if (imgRef.current) observer.observe(imgRef.current);
        return () => observer.disconnect();
    }, []);

    return (
        <div ref={imgRef}>
            {loaded ? (
                <img src={src} alt={alt} />
            ) : (
                <div className="placeholder">{placeholder}</div>
            )}
        </div>
    );
}

// Route-based Code Splitting
const routes = [
    {
        path: '/dashboard',
        component: () => import('./Dashboard')
    },
    {
        path: '/users',
        component: () => import('./Users')
    }
];
```

#### Image Optimization

```javascript
// Next.js Image Optimization
import Image from 'next/image';

function Gallery() {
    return (
        <Image
            src="/image.jpg"
            alt="Description"
            width={800}
            height={600}
            priority
            placeholder="blur"
            blurDataURL="data:image/jpeg;base64,..."
        />
    );
}

// WebP Format Support
function OptimizedImage({ src, alt }) {
    return (
        <picture>
            <source srcSet={`${src}.webp`} type="image/webp" />
            <source srcSet={`${src}.jpg`} type="image/jpeg" />
            <img src={`${src}.jpg`} alt={alt} loading="lazy" />
        </picture>
    );
}
```

### Backend Performance

#### Caching Strategies

```javascript
// Redis Caching
const redis = require('redis');
const client = redis.createClient();

const cache = (duration = 300) => {
    return async (req, res, next) => {
        const key = req.originalUrl;
        const cached = await client.get(key);

        if (cached) {
            return res.json(JSON.parse(cached));
        }

        res.sendResponse = res.json;
        res.json = (body) => {
            client.setex(key, duration, JSON.stringify(body));
            res.sendResponse(body);
        };

        next();
    };
};

// Memory Caching
const NodeCache = require('node-cache');
const cache = new NodeCache({ stdTTL: 600 });

app.get('/api/users', (req, res) => {
    const cacheKey = 'users';
    const cached = cache.get(cacheKey);

    if (cached) {
        return res.json(cached);
    }

    const users = getUsersFromDB();
    cache.set(cacheKey, users);
    res.json(users);
});
```

#### Database Optimization

```javascript
// Query Optimization
// Bad: N+1 Query
const users = await User.findAll();
for (const user of users) {
    user.posts = await Post.findAll({ where: { userId: user.id } });
}

// Good: Include/Join
const users = await User.findAll({
    include: [{ model: Post }]
});

// Pagination
const { page = 1, limit = 20 } = req.query;
const offset = (page - 1) * limit;

const users = await User.findAndCountAll({
    limit: parseInt(limit),
    offset: parseInt(offset)
});

// Database Indexing
// MongoDB
await User.collection.createIndex({ email: 1 });
await Post.collection.createIndex({ userId: 1, createdAt: -1 });

// SQL
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_posts_user_date ON posts(user_id, created_at);
```

#### Load Balancing

```nginx
# Nginx Load Balancer
upstream backend {
    server localhost:3001;
    server localhost:3002;
    server localhost:3003;
}

server {
    listen 80;
    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```javascript
// Node.js Cluster
const cluster = require('cluster');
const numCPUs = require('os').cpus().length;

if (cluster.isMaster) {
    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker) => {
        console.log(`Worker ${worker.process.pid} died`);
        cluster.fork();
    });
} else {
    require('./app.js');
}
```

---

## Development Tools

### Code Editors

```json
// VS Code Settings
{
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.fixAll.eslint": true
    },
    "emmet.includeLanguages": {
        "javascript": "javascriptreact"
    },
    "files.associations": {
        "*.js": "javascriptreact"
    }
}

// Extensions
// - ES7+ React/Redux/React-Native snippets
// - Prettier - Code formatter
// - ESLint
// - Auto Rename Tag
// - Bracket Pair Colorizer
// - GitLens
```

### Build Tools

```javascript
// Webpack Configuration
module.exports = {
    entry: './src/index.js',
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: '[name].[contenthash].js'
    },
    module: {
        rules: [
            {
                test: /\.jsx?$/,
                exclude: /node_modules/,
                use: 'babel-loader'
            },
            {
                test: /\.css$/,
                use: ['style-loader', 'css-loader', 'postcss-loader']
            }
        ]
    },
    plugins: [
        new HtmlWebpackPlugin({
            template: './public/index.html'
        })
    ]
};

// Vite Configuration
export default {
    build: {
        outDir: 'dist',
        sourcemap: true
    },
    server: {
        port: 3000,
        proxy: {
            '/api': 'http://localhost:8000'
        }
    }
};
```

### Package Managers

```json
// package.json Scripts
{
    "scripts": {
        "dev": "next dev",
        "build": "next build",
        "start": "next start",
        "test": "jest",
        "test:watch": "jest --watch",
        "lint": "eslint . --ext .js,.jsx,.ts,.tsx",
        "lint:fix": "eslint . --ext .js,.jsx,.ts,.tsx --fix"
    }
}
```

```bash
# NPM Commands
npm install package-name
npm install -D package-name
npm update
npm audit
npm run script-name

# Yarn Commands
yarn add package-name
yarn add -D package-name
yarn upgrade
yarn audit
yarn script-name

# PNPM Commands
pnpm add package-name
pnpm add -D package-name
pnpm update
pnpm audit
pnpm script-name
```

### Debugging Tools

```javascript
// Browser DevTools
console.log('Debug info:', data);
console.table(arrayData);
console.time('operation');
console.timeEnd('operation');

// React DevTools
// Component inspection and profiling

// Node.js Debugging
node --inspect app.js
// Use Chrome DevTools: chrome://inspect

// VS Code Debugging
// launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug Node.js",
            "type": "node",
            "request": "launch",
            "program": "${workspaceFolder}/app.js",
            "env": {
                "NODE_ENV": "development"
            }
        }
    ]
}
```