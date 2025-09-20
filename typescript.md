# TypeScript Learning Guide

## Table of Contents

1. [TypeScript Basics](#typescript-basics)
   1. [What is TypeScript](#what-is-typescript)
   2. [Basic Types](#basic-types)
   3. [Type Annotations](#type-annotations)
   4. [Type Inference](#type-inference)
   5. [Union and Intersection Types](#union-and-intersection-types)
2. [Interfaces and Objects](#interfaces-and-objects)
   1. [Interfaces](#interfaces)
   2. [Optional Properties](#optional-properties)
   3. [Readonly Properties](#readonly-properties)
   4. [Index Signatures](#index-signatures)
   5. [Extending Interfaces](#extending-interfaces)
3. [Functions](#functions)
   1. [Function Types](#function-types)
   2. [Optional Parameters](#optional-parameters)
   3. [Default Parameters](#default-parameters)
   4. [Rest Parameters](#rest-parameters)
   5. [Function Overloads](#function-overloads)
4. [Classes](#classes)
   1. [Class Basics](#class-basics)
   2. [Access Modifiers](#access-modifiers)
   3. [Abstract Classes](#abstract-classes)
   4. [Static Members](#static-members)
   5. [Class Inheritance](#class-inheritance)
5. [Generics](#generics)
   1. [Generic Functions](#generic-functions)
   2. [Generic Interfaces](#generic-interfaces)
   3. [Generic Classes](#generic-classes)
   4. [Generic Constraints](#generic-constraints)
   5. [Conditional Types](#conditional-types)
6. [Advanced Types](#advanced-types)
   1. [Utility Types](#utility-types)
   2. [Mapped Types](#mapped-types)
   3. [Template Literal Types](#template-literal-types)
   4. [Type Guards](#type-guards)
   5. [Assertion Functions](#assertion-functions)
7. [Modules and Namespaces](#modules-and-namespaces)
   1. [ES6 Modules](#es6-modules)
   2. [Namespaces](#namespaces)
   3. [Module Resolution](#module-resolution)
   4. [Declaration Files](#declaration-files)
8. [Decorators](#decorators)
   1. [Class Decorators](#class-decorators)
   2. [Method Decorators](#method-decorators)
   3. [Property Decorators](#property-decorators)
   4. [Parameter Decorators](#parameter-decorators)
9. [Configuration and Tooling](#configuration-and-tooling)
   1. [tsconfig.json](#tsconfigjson)
   2. [Compiler Options](#compiler-options)
   3. [Project References](#project-references)
   4. [Type Checking](#type-checking)
10. [Real-World Applications](#real-world-applications)
    1. [React with TypeScript](#react-with-typescript)
    2. [Node.js with TypeScript](#nodejs-with-typescript)
    3. [API Development](#api-development)
    4. [Testing with TypeScript](#testing-with-typescript)

---

## TypeScript Basics

### What is TypeScript

**TypeScript** is a statically typed superset of JavaScript that compiles to plain JavaScript. It adds optional type annotations, interfaces, classes, and other features to help catch errors during development and improve code maintainability.

**Key Benefits:**
- **Static typing**: Catch errors at compile time, not runtime
- **Better IDE support**: Enhanced autocomplete, refactoring, and navigation
- **Self-documenting code**: Types serve as inline documentation
- **Easier refactoring**: Type system helps identify breaking changes
- **Gradual adoption**: Can be introduced incrementally to existing JS projects

**TypeScript vs JavaScript:**
- JavaScript: Dynamic typing, runtime error discovery
- TypeScript: Static typing, compile-time error discovery
- TypeScript code compiles to readable JavaScript
- All valid JavaScript is valid TypeScript

### Basic Types

```typescript
// Primitive types
let name: string = "Alice";
let age: number = 30;
let isActive: boolean = true;
let data: null = null;
let value: undefined = undefined;

// Arrays
let numbers: number[] = [1, 2, 3, 4];
let names: Array<string> = ["Alice", "Bob", "Charlie"];

// Tuples - fixed length arrays with known types
let person: [string, number] = ["Alice", 30];
let coordinates: [number, number, number] = [10, 20, 30];

// Any type (avoid when possible)
let anything: any = "hello";
anything = 42;
anything = true;

// Unknown type (safer than any)
let userInput: unknown = getUserInput();
if (typeof userInput === "string") {
    console.log(userInput.toUpperCase()); // Type guard required
}

// Never type (functions that never return)
function throwError(message: string): never {
    throw new Error(message);
}

function infiniteLoop(): never {
    while (true) {}
}

// Void type (functions that don't return a value)
function logMessage(message: string): void {
    console.log(message);
}

// Object type
let user: object = { name: "Alice", age: 30 };

// Literal types
let direction: "up" | "down" | "left" | "right" = "up";
let status: 200 | 404 | 500 = 200;
```

### Type Annotations

```typescript
// Variable annotations
let message: string = "Hello World";
let count: number = 42;
let isComplete: boolean = false;

// Function parameter and return type annotations
function greet(name: string): string {
    return `Hello, ${name}!`;
}

function add(x: number, y: number): number {
    return x + y;
}

// Arrow function annotations
const multiply = (x: number, y: number): number => x * y;

// Object type annotations
let user: {
    name: string;
    age: number;
    email?: string; // Optional property
} = {
    name: "Alice",
    age: 30
};

// Array type annotations
let scores: number[] = [95, 87, 92];
let users: { name: string; age: number }[] = [
    { name: "Alice", age: 30 },
    { name: "Bob", age: 25 }
];

// Function type annotations
let calculator: (x: number, y: number) => number;
calculator = (a, b) => a + b;
```

### Type Inference

```typescript
// TypeScript can infer types automatically
let message = "Hello"; // inferred as string
let count = 42; // inferred as number
let isActive = true; // inferred as boolean

// Function return type inference
function double(x: number) { // return type inferred as number
    return x * 2;
}

// Array type inference
let numbers = [1, 2, 3]; // inferred as number[]
let mixed = [1, "hello", true]; // inferred as (string | number | boolean)[]

// Object type inference
let person = {
    name: "Alice",
    age: 30
}; // inferred as { name: string; age: number; }

// Contextual typing
const names = ["Alice", "Bob", "Charlie"];
names.forEach(name => {
    console.log(name.toUpperCase()); // name is inferred as string
});

// Best common type
let items = [1, 2, 3, null]; // inferred as (number | null)[]

// When to use explicit types
let value: number; // Uninitialized variables need explicit types
value = 42;

function processData(data: unknown) { // Parameters usually need explicit types
    // ...
}
```

### Union and Intersection Types

```typescript
// Union types (OR)
type StringOrNumber = string | number;

function printId(id: string | number) {
    if (typeof id === "string") {
        console.log(`ID: ${id.toUpperCase()}`);
    } else {
        console.log(`ID: ${id.toFixed(2)}`);
    }
}

// Discriminated unions
type Shape =
    | { kind: "circle"; radius: number }
    | { kind: "rectangle"; width: number; height: number }
    | { kind: "triangle"; base: number; height: number };

function getArea(shape: Shape): number {
    switch (shape.kind) {
        case "circle":
            return Math.PI * shape.radius ** 2;
        case "rectangle":
            return shape.width * shape.height;
        case "triangle":
            return (shape.base * shape.height) / 2;
    }
}

// Intersection types (AND)
type Person = {
    name: string;
    age: number;
};

type Employee = {
    employeeId: number;
    department: string;
};

type EmployeePerson = Person & Employee;

const worker: EmployeePerson = {
    name: "Alice",
    age: 30,
    employeeId: 12345,
    department: "Engineering"
};

// Complex unions and intersections
type Admin = {
    name: string;
    privileges: string[];
};

type User = {
    name: string;
    startDate: Date;
};

type ElevatedUser = Admin & User;

function printUserInfo(user: Admin | User) {
    console.log(`Name: ${user.name}`);

    if ("privileges" in user) {
        console.log(`Privileges: ${user.privileges.join(", ")}`);
    }

    if ("startDate" in user) {
        console.log(`Start Date: ${user.startDate.toDateString()}`);
    }
}
```

---

## Interfaces and Objects

### Interfaces

```typescript
// Basic interface
interface User {
    name: string;
    age: number;
    email: string;
}

const user: User = {
    name: "Alice",
    age: 30,
    email: "alice@example.com"
};

// Interface for functions
interface Calculator {
    (x: number, y: number): number;
}

const add: Calculator = (a, b) => a + b;
const multiply: Calculator = (a, b) => a * b;

// Interface with methods
interface Vehicle {
    brand: string;
    model: string;
    year: number;
    start(): void;
    stop(): void;
    getInfo(): string;
}

class Car implements Vehicle {
    constructor(
        public brand: string,
        public model: string,
        public year: number
    ) {}

    start(): void {
        console.log("Car started");
    }

    stop(): void {
        console.log("Car stopped");
    }

    getInfo(): string {
        return `${this.year} ${this.brand} ${this.model}`;
    }
}

// Generic interfaces
interface Repository<T> {
    findById(id: string): T | undefined;
    findAll(): T[];
    create(item: Omit<T, 'id'>): T;
    update(id: string, item: Partial<T>): T | undefined;
    delete(id: string): boolean;
}

interface UserEntity {
    id: string;
    name: string;
    email: string;
    createdAt: Date;
}

class UserRepository implements Repository<UserEntity> {
    private users: UserEntity[] = [];

    findById(id: string): UserEntity | undefined {
        return this.users.find(user => user.id === id);
    }

    findAll(): UserEntity[] {
        return [...this.users];
    }

    create(userData: Omit<UserEntity, 'id'>): UserEntity {
        const user: UserEntity = {
            id: Math.random().toString(36),
            ...userData
        };
        this.users.push(user);
        return user;
    }

    update(id: string, userData: Partial<UserEntity>): UserEntity | undefined {
        const index = this.users.findIndex(user => user.id === id);
        if (index !== -1) {
            this.users[index] = { ...this.users[index], ...userData };
            return this.users[index];
        }
        return undefined;
    }

    delete(id: string): boolean {
        const index = this.users.findIndex(user => user.id === id);
        if (index !== -1) {
            this.users.splice(index, 1);
            return true;
        }
        return false;
    }
}
```

### Optional Properties

```typescript
// Optional properties with ?
interface Config {
    host: string;
    port?: number; // Optional
    ssl?: boolean; // Optional
    timeout?: number; // Optional
}

const config1: Config = { host: "localhost" }; // Valid
const config2: Config = {
    host: "example.com",
    port: 8080,
    ssl: true
}; // Valid

// Optional method parameters
interface Logger {
    log(message: string, level?: "info" | "warn" | "error"): void;
}

const logger: Logger = {
    log(message, level = "info") {
        console.log(`[${level.toUpperCase()}] ${message}`);
    }
};

// Optional vs undefined
interface User {
    name: string;
    email?: string; // Can be omitted
    phone: string | undefined; // Must be present but can be undefined
}

const user1: User = { name: "Alice", phone: undefined }; // Valid
const user2: User = { name: "Bob", email: "bob@example.com", phone: "123-456-7890" }; // Valid
// const user3: User = { name: "Charlie" }; // Error: phone is required

// Optional chaining with interfaces
interface Address {
    street?: string;
    city?: string;
    country?: string;
}

interface PersonWithAddress {
    name: string;
    address?: Address;
}

function getCity(person: PersonWithAddress): string | undefined {
    return person.address?.city;
}
```

### Readonly Properties

```typescript
// Readonly properties
interface Point {
    readonly x: number;
    readonly y: number;
}

const point: Point = { x: 10, y: 20 };
// point.x = 30; // Error: Cannot assign to 'x' because it is a read-only property

// Readonly arrays
interface Data {
    readonly items: readonly string[];
    readonly count: number;
}

const data: Data = {
    items: ["a", "b", "c"],
    count: 3
};

// data.items.push("d"); // Error: Property 'push' does not exist on type 'readonly string[]'
// data.count = 4; // Error: Cannot assign to 'count' because it is a read-only property

// ReadonlyArray utility type
function processNumbers(numbers: ReadonlyArray<number>): number {
    return numbers.reduce((sum, num) => sum + num, 0);
}

const numbers = [1, 2, 3, 4, 5];
const sum = processNumbers(numbers);
// processNumbers will not modify the array

// Readonly utility type
interface MutableUser {
    name: string;
    age: number;
    email: string;
}

type ReadonlyUser = Readonly<MutableUser>;

const user: ReadonlyUser = {
    name: "Alice",
    age: 30,
    email: "alice@example.com"
};

// user.name = "Bob"; // Error: Cannot assign to 'name' because it is a read-only property

// Deep readonly
type DeepReadonly<T> = {
    readonly [P in keyof T]: T[P] extends object ? DeepReadonly<T[P]> : T[P];
};

interface NestedData {
    user: {
        name: string;
        preferences: {
            theme: string;
            notifications: boolean;
        };
    };
}

type ImmutableNestedData = DeepReadonly<NestedData>;
```

### Index Signatures

```typescript
// String index signature
interface StringDictionary {
    [key: string]: string;
}

const colors: StringDictionary = {
    red: "#FF0000",
    green: "#00FF00",
    blue: "#0000FF"
};

// Number index signature
interface NumberArray {
    [index: number]: string;
}

const fruits: NumberArray = ["apple", "banana", "orange"];

// Mixed index signatures
interface MixedDictionary {
    [key: string]: string | number;
    name: string; // Specific property
    age: number; // Specific property
}

const person: MixedDictionary = {
    name: "Alice",
    age: 30,
    city: "New York",
    zipCode: 10001
};

// Generic index signature
interface Dictionary<T> {
    [key: string]: T;
}

const userRoles: Dictionary<string[]> = {
    alice: ["admin", "user"],
    bob: ["user"],
    charlie: ["moderator", "user"]
};

const settings: Dictionary<boolean> = {
    darkMode: true,
    notifications: false,
    autoSave: true
};

// Conditional index signatures
interface ConditionalDictionary {
    [key: string]: unknown;
    [key: `prefix_${string}`]: string;
    [key: `num_${string}`]: number;
}

const conditionalData: ConditionalDictionary = {
    prefix_name: "Alice", // Must be string
    num_age: 30, // Must be number
    other: "any value"
};

// Record utility type (alternative to index signatures)
type StatusCodes = Record<string, number>;

const httpCodes: StatusCodes = {
    ok: 200,
    notFound: 404,
    serverError: 500
};

// Mapped types with index signatures
type Getters<T> = {
    [K in keyof T as `get${Capitalize<string & K>}`]: () => T[K];
};

interface User {
    name: string;
    age: number;
    email: string;
}

type UserGetters = Getters<User>;
// Result: {
//     getName: () => string;
//     getAge: () => number;
//     getEmail: () => string;
// }
```

### Extending Interfaces

```typescript
// Basic interface extension
interface Animal {
    name: string;
    age: number;
}

interface Dog extends Animal {
    breed: string;
    bark(): void;
}

const myDog: Dog = {
    name: "Buddy",
    age: 3,
    breed: "Golden Retriever",
    bark() {
        console.log("Woof!");
    }
};

// Multiple interface extension
interface Flyable {
    fly(): void;
    altitude: number;
}

interface Swimmable {
    swim(): void;
    depth: number;
}

interface Duck extends Animal, Flyable, Swimmable {
    quack(): void;
}

const duck: Duck = {
    name: "Donald",
    age: 2,
    altitude: 100,
    depth: 5,
    fly() {
        console.log("Flying!");
    },
    swim() {
        console.log("Swimming!");
    },
    quack() {
        console.log("Quack!");
    }
};

// Interface merging (declaration merging)
interface User {
    name: string;
}

interface User {
    age: number;
}

interface User {
    email: string;
}

// All three declarations merge into one
const user: User = {
    name: "Alice",
    age: 30,
    email: "alice@example.com"
};

// Extending interfaces with generics
interface Repository<T> {
    findById(id: string): T | undefined;
    findAll(): T[];
}

interface CacheableRepository<T> extends Repository<T> {
    cache: Map<string, T>;
    clearCache(): void;
}

interface AuditableRepository<T> extends Repository<T> {
    createdBy: string;
    createdAt: Date;
    getAuditLog(): string[];
}

// Conditional interface extension
interface BaseEntity {
    id: string;
    createdAt: Date;
}

interface UserEntity extends BaseEntity {
    name: string;
    email: string;
}

interface AdminUser extends UserEntity {
    permissions: string[];
    lastLogin?: Date;
}

// Interface extending class
class Point {
    constructor(public x: number, public y: number) {}

    distance(other: Point): number {
        return Math.sqrt((this.x - other.x) ** 2 + (this.y - other.y) ** 2);
    }
}

interface Point3D extends Point {
    z: number;
    distanceTo3D(other: Point3D): number;
}

const point3D: Point3D = {
    x: 1,
    y: 2,
    z: 3,
    distance(other) {
        return Math.sqrt((this.x - other.x) ** 2 + (this.y - other.y) ** 2);
    },
    distanceTo3D(other) {
        return Math.sqrt(
            (this.x - other.x) ** 2 +
            (this.y - other.y) ** 2 +
            (this.z - other.z) ** 2
        );
    }
};
```

---

## Functions

### Function Types

```typescript
// Function type syntax
type MathOperation = (x: number, y: number) => number;

const add: MathOperation = (a, b) => a + b;
const subtract: MathOperation = (a, b) => a - b;
const multiply: MathOperation = (a, b) => a * b;

// Function interface
interface Calculator {
    add(x: number, y: number): number;
    subtract(x: number, y: number): number;
    multiply(x: number, y: number): number;
    divide(x: number, y: number): number;
}

const calculator: Calculator = {
    add: (x, y) => x + y,
    subtract: (x, y) => x - y,
    multiply: (x, y) => x * y,
    divide: (x, y) => x / y
};

// Higher-order functions
type Predicate<T> = (item: T) => boolean;
type Transformer<T, U> = (item: T) => U;

function filter<T>(array: T[], predicate: Predicate<T>): T[] {
    return array.filter(predicate);
}

function map<T, U>(array: T[], transformer: Transformer<T, U>): U[] {
    return array.map(transformer);
}

// Callback functions
type EventCallback = (event: { type: string; data: unknown }) => void;

class EventEmitter {
    private listeners: EventCallback[] = [];

    on(callback: EventCallback): void {
        this.listeners.push(callback);
    }

    emit(type: string, data: unknown): void {
        this.listeners.forEach(callback => {
            callback({ type, data });
        });
    }
}

// Async function types
type AsyncOperation<T> = () => Promise<T>;
type AsyncTransformer<T, U> = (item: T) => Promise<U>;

async function processAsync<T, U>(
    items: T[],
    transformer: AsyncTransformer<T, U>
): Promise<U[]> {
    const results: U[] = [];
    for (const item of items) {
        const result = await transformer(item);
        results.push(result);
    }
    return results;
}
```

### Optional Parameters

```typescript
// Optional parameters with ?
function greet(name: string, greeting?: string): string {
    return `${greeting || "Hello"}, ${name}!`;
}

console.log(greet("Alice")); // "Hello, Alice!"
console.log(greet("Bob", "Hi")); // "Hi, Bob!"

// Optional parameters must come after required ones
function createUser(name: string, age?: number, email?: string): object {
    return {
        name,
        age: age ?? 0,
        email: email ?? "no-email@example.com"
    };
}

// Optional callback functions
function fetchData(url: string, onSuccess?: (data: unknown) => void, onError?: (error: Error) => void): void {
    fetch(url)
        .then(response => response.json())
        .then(data => onSuccess?.(data))
        .catch(error => onError?.(error));
}

// Optional method parameters
interface Logger {
    log(message: string, level?: "debug" | "info" | "warn" | "error"): void;
    logWithTimestamp?(message: string): void; // Optional method
}

class ConsoleLogger implements Logger {
    log(message: string, level: "debug" | "info" | "warn" | "error" = "info"): void {
        console.log(`[${level.toUpperCase()}] ${message}`);
    }

    logWithTimestamp(message: string): void {
        console.log(`[${new Date().toISOString()}] ${message}`);
    }
}

// Destructuring with optional properties
interface RequestConfig {
    url: string;
    method?: "GET" | "POST" | "PUT" | "DELETE";
    headers?: Record<string, string>;
    timeout?: number;
}

function makeRequest({ url, method = "GET", headers = {}, timeout = 5000 }: RequestConfig): Promise<Response> {
    return fetch(url, {
        method,
        headers,
        signal: AbortSignal.timeout(timeout)
    });
}
```

### Default Parameters

```typescript
// Default parameters
function createConnection(host: string = "localhost", port: number = 3000, ssl: boolean = false): string {
    const protocol = ssl ? "https" : "http";
    return `${protocol}://${host}:${port}`;
}

console.log(createConnection()); // "http://localhost:3000"
console.log(createConnection("example.com")); // "http://example.com:3000"
console.log(createConnection("example.com", 8080, true)); // "https://example.com:8080"

// Default parameters with complex types
interface DatabaseConfig {
    host: string;
    port: number;
    database: string;
    ssl: boolean;
    poolSize: number;
}

function createDatabaseConnection(
    config: Partial<DatabaseConfig> = {}
): DatabaseConfig {
    return {
        host: config.host ?? "localhost",
        port: config.port ?? 5432,
        database: config.database ?? "myapp",
        ssl: config.ssl ?? false,
        poolSize: config.poolSize ?? 10
    };
}

// Default parameters with functions
type ErrorHandler = (error: Error) => void;

const defaultErrorHandler: ErrorHandler = (error) => {
    console.error("An error occurred:", error.message);
};

function processWithErrorHandling(
    data: unknown[],
    processor: (item: unknown) => unknown,
    onError: ErrorHandler = defaultErrorHandler
): unknown[] {
    return data.map(item => {
        try {
            return processor(item);
        } catch (error) {
            onError(error as Error);
            return null;
        }
    });
}

// Default parameters with destructuring
interface ApiOptions {
    baseUrl?: string;
    timeout?: number;
    retries?: number;
    headers?: Record<string, string>;
}

function createApiClient({
    baseUrl = "https://api.example.com",
    timeout = 10000,
    retries = 3,
    headers = { "Content-Type": "application/json" }
}: ApiOptions = {}): object {
    return {
        baseUrl,
        timeout,
        retries,
        headers,
        get: (endpoint: string) => `GET ${baseUrl}${endpoint}`,
        post: (endpoint: string, data: unknown) => `POST ${baseUrl}${endpoint}`,
    };
}
```

### Rest Parameters

```typescript
// Rest parameters
function sum(...numbers: number[]): number {
    return numbers.reduce((total, num) => total + num, 0);
}

console.log(sum(1, 2, 3, 4, 5)); // 15

// Rest parameters with other parameters
function logMessage(level: string, ...messages: string[]): void {
    messages.forEach(message => {
        console.log(`[${level}] ${message}`);
    });
}

logMessage("INFO", "Application started", "Database connected", "Server listening");

// Rest parameters with tuple types
function processData(id: number, ...args: [string, boolean, Date]): object {
    const [name, isActive, createdAt] = args;
    return { id, name, isActive, createdAt };
}

// Generic rest parameters
function combine<T>(...arrays: T[][]): T[] {
    return arrays.flat();
}

const numbers = combine([1, 2], [3, 4], [5, 6]); // number[]
const strings = combine(["a", "b"], ["c", "d"]); // string[]

// Rest parameters in function types
type LogFunction = (level: string, ...messages: string[]) => void;

const logger: LogFunction = (level, ...messages) => {
    messages.forEach(message => console.log(`[${level}] ${message}`));
};

// Spread operator with rest parameters
function mergeObjects<T extends Record<string, unknown>>(...objects: T[]): T {
    return Object.assign({}, ...objects);
}

const merged = mergeObjects(
    { a: 1, b: 2 },
    { c: 3, d: 4 },
    { e: 5 }
);

// Rest parameters with destructuring
function processRequest(url: string, { method = "GET", ...options }: RequestInit & { method?: string }): void {
    console.log(`${method} ${url}`);
    console.log("Options:", options);
}

// Variadic tuple types
type EventHandler<T extends readonly unknown[]> = (...args: T) => void;

declare function addEventListener<T extends readonly unknown[]>(
    event: string,
    handler: EventHandler<T>
): void;

addEventListener("click", (event: MouseEvent) => {
    console.log(event.clientX, event.clientY);
});

addEventListener("resize", (width: number, height: number) => {
    console.log(`New size: ${width}x${height}`);
});
```

### Function Overloads

```typescript
// Function overloads
function parseValue(value: string): string;
function parseValue(value: number): number;
function parseValue(value: boolean): boolean;
function parseValue(value: string | number | boolean): string | number | boolean {
    if (typeof value === "string") {
        return value.trim().toLowerCase();
    } else if (typeof value === "number") {
        return Math.round(value);
    } else {
        return value;
    }
}

console.log(parseValue("  HELLO  ")); // "hello"
console.log(parseValue(3.14)); // 3
console.log(parseValue(true)); // true

// Method overloads
class DataProcessor {
    process(data: string): string;
    process(data: number): number;
    process(data: string[]): string[];
    process(data: string | number | string[]): string | number | string[] {
        if (typeof data === "string") {
            return data.toUpperCase();
        } else if (typeof data === "number") {
            return data * 2;
        } else {
            return data.map(item => item.toUpperCase());
        }
    }
}

// Constructor overloads
class Point {
    x: number;
    y: number;

    constructor();
    constructor(x: number, y: number);
    constructor(point: { x: number; y: number });
    constructor(xOrPoint?: number | { x: number; y: number }, y?: number) {
        if (typeof xOrPoint === "object") {
            this.x = xOrPoint.x;
            this.y = xOrPoint.y;
        } else {
            this.x = xOrPoint ?? 0;
            this.y = y ?? 0;
        }
    }
}

const point1 = new Point(); // (0, 0)
const point2 = new Point(10, 20); // (10, 20)
const point3 = new Point({ x: 5, y: 15 }); // (5, 15)

// Generic function overloads
interface Repository<T> {
    find(): T[];
    find(id: string): T | undefined;
    find(predicate: (item: T) => boolean): T[];
}

class UserRepository implements Repository<{ id: string; name: string }> {
    private users: { id: string; name: string }[] = [];

    find(): { id: string; name: string }[];
    find(id: string): { id: string; name: string } | undefined;
    find(predicate: (item: { id: string; name: string }) => boolean): { id: string; name: string }[];
    find(
        idOrPredicate?: string | ((item: { id: string; name: string }) => boolean)
    ): { id: string; name: string }[] | { id: string; name: string } | undefined {
        if (!idOrPredicate) {
            return this.users;
        } else if (typeof idOrPredicate === "string") {
            return this.users.find(user => user.id === idOrPredicate);
        } else {
            return this.users.filter(idOrPredicate);
        }
    }
}

// Conditional overloads
function createElement(tag: "div"): HTMLDivElement;
function createElement(tag: "span"): HTMLSpanElement;
function createElement(tag: "input"): HTMLInputElement;
function createElement(tag: string): HTMLElement;
function createElement(tag: string): HTMLElement {
    return document.createElement(tag);
}

const div = createElement("div"); // HTMLDivElement
const span = createElement("span"); // HTMLSpanElement
const input = createElement("input"); // HTMLInputElement
const custom = createElement("custom"); // HTMLElement
```

---

## Classes

### Class Basics

```typescript
// Basic class
class Person {
    // Properties
    name: string;
    age: number;
    private id: string;

    // Constructor
    constructor(name: string, age: number) {
        this.name = name;
        this.age = age;
        this.id = Math.random().toString(36);
    }

    // Methods
    greet(): string {
        return `Hello, I'm ${this.name} and I'm ${this.age} years old.`;
    }

    getAge(): number {
        return this.age;
    }

    private generateId(): string {
        return Math.random().toString(36);
    }
}

const person = new Person("Alice", 30);
console.log(person.greet());

// Parameter properties (shorthand)
class User {
    constructor(
        public name: string,
        public email: string,
        private password: string,
        protected createdAt: Date = new Date()
    ) {}

    getInfo(): string {
        return `${this.name} (${this.email})`;
    }

    protected checkPassword(password: string): boolean {
        return this.password === password;
    }
}

// Getters and setters
class Temperature {
    private _celsius: number = 0;

    get celsius(): number {
        return this._celsius;
    }

    set celsius(value: number) {
        if (value < -273.15) {
            throw new Error("Temperature cannot be below absolute zero");
        }
        this._celsius = value;
    }

    get fahrenheit(): number {
        return (this._celsius * 9/5) + 32;
    }

    set fahrenheit(value: number) {
        this.celsius = (value - 32) * 5/9;
    }

    get kelvin(): number {
        return this._celsius + 273.15;
    }
}

const temp = new Temperature();
temp.celsius = 25;
console.log(temp.fahrenheit); // 77
console.log(temp.kelvin); // 298.15

// Class expressions
const Rectangle = class {
    constructor(public width: number, public height: number) {}

    get area(): number {
        return this.width * this.height;
    }

    get perimeter(): number {
        return 2 * (this.width + this.height);
    }
};

// Class with index signature
class Dictionary {
    [key: string]: unknown;

    constructor(private data: Record<string, unknown> = {}) {
        Object.assign(this, data);
    }

    get(key: string): unknown {
        return this.data[key];
    }

    set(key: string, value: unknown): void {
        this.data[key] = value;
        this[key] = value;
    }
}
```

### Access Modifiers

```typescript
// Access modifiers: public, private, protected
class BankAccount {
    public accountNumber: string;
    private balance: number = 0;
    protected interestRate: number = 0.02;

    constructor(accountNumber: string, initialBalance: number = 0) {
        this.accountNumber = accountNumber;
        this.balance = initialBalance;
    }

    // Public method
    public deposit(amount: number): void {
        if (amount > 0) {
            this.balance += amount;
            this.logTransaction("deposit", amount);
        }
    }

    public withdraw(amount: number): boolean {
        if (amount > 0 && amount <= this.balance) {
            this.balance -= amount;
            this.logTransaction("withdrawal", amount);
            return true;
        }
        return false;
    }

    public getBalance(): number {
        return this.balance;
    }

    // Private method
    private logTransaction(type: string, amount: number): void {
        console.log(`${type}: $${amount} at ${new Date().toISOString()}`);
    }

    // Protected method
    protected calculateInterest(): number {
        return this.balance * this.interestRate;
    }
}

// Inheritance with access modifiers
class SavingsAccount extends BankAccount {
    constructor(accountNumber: string, initialBalance: number = 0) {
        super(accountNumber, initialBalance);
        this.interestRate = 0.05; // Can access protected property
    }

    public addInterest(): void {
        const interest = this.calculateInterest(); // Can access protected method
        this.deposit(interest);
    }

    public getAccountInfo(): string {
        return `Account: ${this.accountNumber}, Balance: $${this.getBalance()}`;
        // Cannot access private balance directly
    }
}

// Readonly modifier
class ImmutablePoint {
    constructor(
        public readonly x: number,
        public readonly y: number
    ) {}

    // Methods can still access readonly properties
    distance(other: ImmutablePoint): number {
        return Math.sqrt((this.x - other.x) ** 2 + (this.y - other.y) ** 2);
    }
}

const point = new ImmutablePoint(10, 20);
// point.x = 30; // Error: Cannot assign to 'x' because it is a read-only property

// Private fields (ES2022 private fields)
class ModernBankAccount {
    #balance: number = 0;
    #transactions: string[] = [];

    constructor(public accountNumber: string) {}

    deposit(amount: number): void {
        if (amount > 0) {
            this.#balance += amount;
            this.#addTransaction(`Deposit: $${amount}`);
        }
    }

    getBalance(): number {
        return this.#balance;
    }

    #addTransaction(transaction: string): void {
        this.#transactions.push(`${new Date().toISOString()}: ${transaction}`);
    }

    getTransactionHistory(): string[] {
        return [...this.#transactions]; // Return copy
    }
}

// Static members with access modifiers
class MathUtils {
    private static readonly PI = 3.14159;
    public static readonly E = 2.71828;

    public static circleArea(radius: number): number {
        return this.PI * radius ** 2; // Can access private static
    }

    private static validateNumber(num: number): boolean {
        return typeof num === "number" && !isNaN(num);
    }

    public static power(base: number, exponent: number): number {
        if (!this.validateNumber(base) || !this.validateNumber(exponent)) {
            throw new Error("Invalid numbers provided");
        }
        return Math.pow(base, exponent);
    }
}
```

### Abstract Classes

```typescript
// Abstract class
abstract class Animal {
    constructor(protected name: string, protected age: number) {}

    // Abstract method - must be implemented by subclasses
    abstract makeSound(): string;
    abstract move(): string;

    // Concrete method - can be used by subclasses
    public getInfo(): string {
        return `${this.name} is ${this.age} years old`;
    }

    public introduce(): string {
        return `${this.getInfo()}. ${this.makeSound()} ${this.move()}`;
    }

    // Protected method for subclasses
    protected sleep(): string {
        return `${this.name} is sleeping`;
    }
}

// Concrete implementation
class Dog extends Animal {
    constructor(name: string, age: number, private breed: string) {
        super(name, age);
    }

    makeSound(): string {
        return "Woof! Woof!";
    }

    move(): string {
        return "Running around happily";
    }

    public getBreed(): string {
        return this.breed;
    }

    public rest(): string {
        return this.sleep(); // Can access protected method
    }
}

class Bird extends Animal {
    constructor(name: string, age: number, private wingspan: number) {
        super(name, age);
    }

    makeSound(): string {
        return "Tweet! Tweet!";
    }

    move(): string {
        return "Flying gracefully";
    }

    public getWingspan(): number {
        return this.wingspan;
    }
}

const dog = new Dog("Buddy", 5, "Golden Retriever");
const bird = new Bird("Robin", 2, 15);

console.log(dog.introduce());
console.log(bird.introduce());

// Abstract class with generic types
abstract class Repository<T> {
    protected items: T[] = [];

    abstract validate(item: T): boolean;
    abstract transform(item: T): T;

    public add(item: T): void {
        if (this.validate(item)) {
            this.items.push(this.transform(item));
        } else {
            throw new Error("Invalid item");
        }
    }

    public findAll(): T[] {
        return [...this.items];
    }

    public findById(predicate: (item: T) => boolean): T | undefined {
        return this.items.find(predicate);
    }

    public count(): number {
        return this.items.length;
    }
}

interface User {
    id: string;
    name: string;
    email: string;
}

class UserRepository extends Repository<User> {
    validate(user: User): boolean {
        return !!(user.id && user.name && user.email && user.email.includes("@"));
    }

    transform(user: User): User {
        return {
            ...user,
            name: user.name.trim(),
            email: user.email.toLowerCase().trim()
        };
    }

    findByEmail(email: string): User | undefined {
        return this.findById(user => user.email === email.toLowerCase());
    }
}

// Abstract class implementing interface
interface Drawable {
    draw(): string;
    getArea(): number;
}

abstract class Shape implements Drawable {
    constructor(protected color: string) {}

    abstract draw(): string;
    abstract getArea(): number;

    public getColor(): string {
        return this.color;
    }

    public describe(): string {
        return `A ${this.color} shape with area ${this.getArea()}`;
    }
}

class Circle extends Shape {
    constructor(color: string, private radius: number) {
        super(color);
    }

    draw(): string {
        return `Drawing a ${this.color} circle with radius ${this.radius}`;
    }

    getArea(): number {
        return Math.PI * this.radius ** 2;
    }
}
```

### Static Members

```typescript
// Static properties and methods
class Counter {
    private static count: number = 0;
    private static instances: Counter[] = [];

    private id: number;

    constructor() {
        this.id = ++Counter.count;
        Counter.instances.push(this);
    }

    public getId(): number {
        return this.id;
    }

    public static getCount(): number {
        return Counter.count;
    }

    public static getAllInstances(): Counter[] {
        return [...Counter.instances];
    }

    public static reset(): void {
        Counter.count = 0;
        Counter.instances = [];
    }
}

const counter1 = new Counter();
const counter2 = new Counter();
console.log(Counter.getCount()); // 2

// Static initialization block
class DatabaseConnection {
    private static instance: DatabaseConnection | null = null;
    private static isInitialized: boolean = false;

    private constructor(private connectionString: string) {}

    static {
        // Static initialization block
        console.log("DatabaseConnection class loaded");
        this.isInitialized = true;
    }

    public static getInstance(connectionString?: string): DatabaseConnection {
        if (!this.instance) {
            if (!connectionString) {
                throw new Error("Connection string required for first instance");
            }
            this.instance = new DatabaseConnection(connectionString);
        }
        return this.instance;
    }

    public static isReady(): boolean {
        return this.isInitialized && this.instance !== null;
    }

    public connect(): string {
        return `Connected to ${this.connectionString}`;
    }
}

// Static factory methods
class User {
    constructor(
        public name: string,
        public email: string,
        public role: string = "user"
    ) {}

    public static createAdmin(name: string, email: string): User {
        return new User(name, email, "admin");
    }

    public static createModerator(name: string, email: string): User {
        return new User(name, email, "moderator");
    }

    public static fromJSON(json: string): User {
        const data = JSON.parse(json);
        return new User(data.name, data.email, data.role);
    }

    public static isValidEmail(email: string): boolean {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }
}

const admin = User.createAdmin("Alice", "alice@example.com");
const isValid = User.isValidEmail("test@example.com");

// Static inheritance
class Animal {
    protected static species: string = "Unknown";

    constructor(protected name: string) {}

    public static getSpecies(): string {
        return this.species;
    }

    public getInfo(): string {
        return `${this.name} is a ${(this.constructor as typeof Animal).getSpecies()}`;
    }
}

class Dog extends Animal {
    protected static species: string = "Canis lupus";

    public static bark(): string {
        return "Woof!";
    }
}

class Cat extends Animal {
    protected static species: string = "Felis catus";

    public static meow(): string {
        return "Meow!";
    }
}

console.log(Dog.getSpecies()); // "Canis lupus"
console.log(Cat.getSpecies()); // "Felis catus"

const dog = new Dog("Buddy");
console.log(dog.getInfo()); // "Buddy is a Canis lupus"

// Static abstract members
abstract class Vehicle {
    public static abstract readonly type: string;

    constructor(protected brand: string) {}

    public static abstract getMaxSpeed(): number;

    public abstract start(): string;

    public getDescription(): string {
        const VehicleClass = this.constructor as typeof Vehicle;
        return `${this.brand} ${VehicleClass.type} (max speed: ${VehicleClass.getMaxSpeed()} mph)`;
    }
}

class Car extends Vehicle {
    public static readonly type: string = "Car";

    public static getMaxSpeed(): number {
        return 200;
    }

    public start(): string {
        return "Car engine started";
    }
}

class Motorcycle extends Vehicle {
    public static readonly type: string = "Motorcycle";

    public static getMaxSpeed(): number {
        return 180;
    }

    public start(): string {
        return "Motorcycle engine started";
    }
}
```

### Class Inheritance

```typescript
// Basic inheritance
class Vehicle {
    constructor(
        protected brand: string,
        protected model: string,
        protected year: number
    ) {}

    public start(): string {
        return "Vehicle started";
    }

    public stop(): string {
        return "Vehicle stopped";
    }

    public getInfo(): string {
        return `${this.year} ${this.brand} ${this.model}`;
    }
}

class Car extends Vehicle {
    constructor(
        brand: string,
        model: string,
        year: number,
        private doors: number
    ) {
        super(brand, model, year);
    }

    // Override parent method
    public start(): string {
        return "Car engine started with ignition";
    }

    // Add new method
    public openDoors(): string {
        return `Opening ${this.doors} doors`;
    }

    // Override with additional logic
    public getInfo(): string {
        return `${super.getInfo()} - ${this.doors} doors`;
    }
}

class ElectricCar extends Car {
    constructor(
        brand: string,
        model: string,
        year: number,
        doors: number,
        private batteryCapacity: number
    ) {
        super(brand, model, year, doors);
    }

    public start(): string {
        return "Electric car started silently";
    }

    public charge(): string {
        return `Charging ${this.batteryCapacity}kWh battery`;
    }

    public getRange(): number {
        return this.batteryCapacity * 3; // Simplified calculation
    }

    public getInfo(): string {
        return `${super.getInfo()} - ${this.batteryCapacity}kWh battery`;
    }
}

// Multiple levels of inheritance
const tesla = new ElectricCar("Tesla", "Model 3", 2023, 4, 75);
console.log(tesla.getInfo());
console.log(tesla.start());
console.log(tesla.charge());

// Interface implementation with inheritance
interface Flyable {
    fly(): string;
    land(): string;
}

interface Swimmable {
    swim(): string;
    dive(): string;
}

class WaterVehicle extends Vehicle implements Swimmable {
    constructor(brand: string, model: string, year: number, private maxDepth: number) {
        super(brand, model, year);
    }

    public swim(): string {
        return "Moving through water";
    }

    public dive(): string {
        return `Diving to depth of ${this.maxDepth} meters`;
    }
}

class Amphibian extends WaterVehicle implements Flyable {
    constructor(
        brand: string,
        model: string,
        year: number,
        maxDepth: number,
        private maxAltitude: number
    ) {
        super(brand, model, year, maxDepth);
    }

    public fly(): string {
        return `Flying at altitude of ${this.maxAltitude} meters`;
    }

    public land(): string {
        return "Landing on ground";
    }

    public start(): string {
        return "Amphibian vehicle started - ready for land, water, or air";
    }
}

// Generic inheritance
abstract class Collection<T> {
    protected items: T[] = [];

    public add(item: T): void {
        this.items.push(item);
    }

    public remove(predicate: (item: T) => boolean): T | undefined {
        const index = this.items.findIndex(predicate);
        if (index !== -1) {
            return this.items.splice(index, 1)[0];
        }
        return undefined;
    }

    public find(predicate: (item: T) => boolean): T | undefined {
        return this.items.find(predicate);
    }

    public abstract filter(predicate: (item: T) => boolean): T[];
    public abstract sort(compareFn?: (a: T, b: T) => number): T[];
}

class NumberCollection extends Collection<number> {
    public filter(predicate: (item: number) => boolean): number[] {
        return this.items.filter(predicate);
    }

    public sort(compareFn?: (a: number, b: number) => number): number[] {
        return [...this.items].sort(compareFn || ((a, b) => a - b));
    }

    public sum(): number {
        return this.items.reduce((total, num) => total + num, 0);
    }

    public average(): number {
        return this.items.length > 0 ? this.sum() / this.items.length : 0;
    }
}

class StringCollection extends Collection<string> {
    public filter(predicate: (item: string) => boolean): string[] {
        return this.items.filter(predicate);
    }

    public sort(compareFn?: (a: string, b: string) => number): string[] {
        return [...this.items].sort(compareFn || ((a, b) => a.localeCompare(b)));
    }

    public join(separator: string = ", "): string {
        return this.items.join(separator);
    }

    public findByPrefix(prefix: string): string[] {
        return this.filter(item => item.startsWith(prefix));
    }
}

// Protected inheritance and method chaining
class QueryBuilder {
    protected query: string = "";
    protected conditions: string[] = [];

    protected addCondition(condition: string): this {
        this.conditions.push(condition);
        return this;
    }

    public build(): string {
        return this.query + (this.conditions.length > 0 ? " WHERE " + this.conditions.join(" AND ") : "");
    }
}

class SelectQueryBuilder extends QueryBuilder {
    private selectedFields: string[] = [];
    private tableName: string = "";

    public select(...fields: string[]): this {
        this.selectedFields = fields;
        return this;
    }

    public from(table: string): this {
        this.tableName = table;
        this.query = `SELECT ${this.selectedFields.join(", ")} FROM ${table}`;
        return this;
    }

    public where(condition: string): this {
        return this.addCondition(condition);
    }

    public and(condition: string): this {
        return this.addCondition(condition);
    }
}

// Usage
const query = new SelectQueryBuilder()
    .select("name", "email", "age")
    .from("users")
    .where("age > 18")
    .and("active = true")
    .build();

console.log(query); // "SELECT name, email, age FROM users WHERE age > 18 AND active = true"
```