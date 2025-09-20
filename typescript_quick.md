# TypeScript Learning Guide

## Table of Contents

1. [TypeScript Basics](#typescript-basics)
   1. [What is TypeScript](#what-is-typescript)
   2. [Basic Types](#basic-types)
   3. [Type Annotations](#type-annotations)
   4. [Type Inference](#type-inference)
   5. [Union Types](#union-types)
2. [Interfaces](#interfaces)
   1. [Basic Interface](#basic-interface)
   2. [Optional Properties](#optional-properties)
   3. [Readonly Properties](#readonly-properties)
   4. [Extending Interfaces](#extending-interfaces)
3. [Functions](#functions)
   1. [Function Types](#function-types)
   2. [Optional Parameters](#optional-parameters)
   3. [Rest Parameters](#rest-parameters)
   4. [Function Overloads](#function-overloads)
4. [Classes](#classes)
   1. [Basic Classes](#basic-classes)
   2. [Access Modifiers](#access-modifiers)
   3. [Abstract Classes](#abstract-classes)
   4. [Static Members](#static-members)
5. [Generics](#generics)
   1. [Generic Functions](#generic-functions)
   2. [Generic Interfaces](#generic-interfaces)
   3. [Generic Classes](#generic-classes)
   4. [Generic Constraints](#generic-constraints)
6. [Advanced Types](#advanced-types)
   1. [Utility Types](#utility-types)
   2. [Mapped Types](#mapped-types)
   3. [Conditional Types](#conditional-types)
   4. [Type Guards](#type-guards)
7. [Modules](#modules)
   1. [ES6 Modules](#es6-modules)
   2. [Namespaces](#namespaces)
   3. [Declaration Files](#declaration-files)
8. [Decorators](#decorators)
   1. [Class Decorators](#class-decorators)
   2. [Method Decorators](#method-decorators)
   3. [Property Decorators](#property-decorators)
9. [Configuration](#configuration)
   1. [tsconfig.json](#tsconfigjson)
   2. [Compiler Options](#compiler-options)
10. [Real-World Usage](#real-world-usage)
    1. [React with TypeScript](#react-with-typescript)
    2. [Node.js with TypeScript](#nodejs-with-typescript)
    3. [API Development](#api-development)

---

## TypeScript Basics

### What is TypeScript

TypeScript = JavaScript + Static Types
- Compiles to plain JavaScript
- Catches errors at compile time
- Better IDE support and refactoring

### Basic Types

```typescript
// Primitives
let name: string = "Alice";
let age: number = 30;
let isActive: boolean = true;

// Arrays
let numbers: number[] = [1, 2, 3];
let names: Array<string> = ["a", "b"];

// Tuples
let person: [string, number] = ["Alice", 30];

// Any (avoid when possible)
let anything: any = "hello";

// Unknown (safer than any)
let value: unknown = getData();
if (typeof value === "string") {
    console.log(value.toUpperCase());
}

// Never (functions that never return)
function error(message: string): never {
    throw new Error(message);
}

// Void
function log(message: string): void {
    console.log(message);
}
```

### Type Annotations

```typescript
// Variables
let message: string = "Hello";
let count: number = 42;

// Functions
function greet(name: string): string {
    return `Hello, ${name}!`;
}

// Arrow functions
const add = (x: number, y: number): number => x + y;

// Objects
let user: { name: string; age: number } = {
    name: "Alice",
    age: 30
};
```

### Type Inference

```typescript
// TypeScript infers types automatically
let message = "Hello"; // string
let count = 42; // number
let items = [1, 2, 3]; // number[]

// Function return type inferred
function double(x: number) { // returns number
    return x * 2;
}

// Contextual typing
const users = ["Alice", "Bob"];
users.forEach(user => {
    console.log(user.toUpperCase()); // user is string
});
```

### Union Types

```typescript
// Basic union
let id: string | number = "abc123";
id = 123; // Also valid

// Union with type guards
function printId(id: string | number) {
    if (typeof id === "string") {
        console.log(id.toUpperCase());
    } else {
        console.log(id.toFixed(2));
    }
}

// Discriminated unions
type Shape =
    | { kind: "circle"; radius: number }
    | { kind: "square"; size: number };

function area(shape: Shape): number {
    switch (shape.kind) {
        case "circle": return Math.PI * shape.radius ** 2;
        case "square": return shape.size ** 2;
    }
}
```

---

## Interfaces

### Basic Interface

```typescript
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
```

### Optional Properties

```typescript
interface Config {
    host: string;
    port?: number; // Optional
    ssl?: boolean;
}

const config: Config = { host: "localhost" }; // Valid
```

### Readonly Properties

```typescript
interface Point {
    readonly x: number;
    readonly y: number;
}

const point: Point = { x: 10, y: 20 };
// point.x = 30; // Error!
```

### Extending Interfaces

```typescript
interface Animal {
    name: string;
    age: number;
}

interface Dog extends Animal {
    breed: string;
    bark(): void;
}

const dog: Dog = {
    name: "Buddy",
    age: 3,
    breed: "Golden Retriever",
    bark() { console.log("Woof!"); }
};
```

---

## Functions

### Function Types

```typescript
// Function type
type MathOp = (x: number, y: number) => number;

const multiply: MathOp = (a, b) => a * b;

// Callback functions
function processData(data: string[], callback: (item: string) => void) {
    data.forEach(callback);
}
```

### Optional Parameters

```typescript
function greet(name: string, greeting?: string): string {
    return `${greeting || "Hello"}, ${name}!`;
}

greet("Alice"); // "Hello, Alice!"
greet("Bob", "Hi"); // "Hi, Bob!"

// Default parameters
function createUser(name: string, role: string = "user") {
    return { name, role };
}
```

### Rest Parameters

```typescript
function sum(...numbers: number[]): number {
    return numbers.reduce((total, num) => total + num, 0);
}

sum(1, 2, 3, 4); // 10
```

### Function Overloads

```typescript
function parse(value: string): string;
function parse(value: number): number;
function parse(value: string | number): string | number {
    if (typeof value === "string") {
        return value.toLowerCase();
    }
    return Math.round(value);
}

parse("HELLO"); // "hello"
parse(3.14); // 3
```

---

## Classes

### Basic Classes

```typescript
class Person {
    name: string;
    age: number;

    constructor(name: string, age: number) {
        this.name = name;
        this.age = age;
    }

    greet(): string {
        return `Hello, I'm ${this.name}`;
    }
}

// Parameter properties (shorthand)
class User {
    constructor(
        public name: string,
        private password: string,
        protected createdAt: Date = new Date()
    ) {}
}
```

### Access Modifiers

```typescript
class BankAccount {
    public accountNumber: string;
    private balance: number = 0;
    protected interestRate: number = 0.02;

    constructor(accountNumber: string) {
        this.accountNumber = accountNumber;
    }

    public deposit(amount: number): void {
        this.balance += amount;
    }

    public getBalance(): number {
        return this.balance;
    }
}
```

### Abstract Classes

```typescript
abstract class Animal {
    constructor(protected name: string) {}

    abstract makeSound(): string;

    move(): string {
        return `${this.name} is moving`;
    }
}

class Dog extends Animal {
    makeSound(): string {
        return "Woof!";
    }
}
```

### Static Members

```typescript
class MathUtils {
    static readonly PI = 3.14159;

    static circleArea(radius: number): number {
        return this.PI * radius ** 2;
    }
}

console.log(MathUtils.circleArea(5));
```

---

## Generics

### Generic Functions

```typescript
function identity<T>(arg: T): T {
    return arg;
}

const num = identity<number>(42);
const str = identity("hello"); // Type inferred

function first<T>(items: T[]): T | undefined {
    return items[0];
}
```

### Generic Interfaces

```typescript
interface Repository<T> {
    findById(id: string): T | undefined;
    findAll(): T[];
    create(item: T): T;
    update(id: string, item: Partial<T>): T | undefined;
}

interface User {
    id: string;
    name: string;
    email: string;
}

class UserRepository implements Repository<User> {
    private users: User[] = [];

    findById(id: string): User | undefined {
        return this.users.find(user => user.id === id);
    }

    findAll(): User[] {
        return [...this.users];
    }

    create(user: User): User {
        this.users.push(user);
        return user;
    }

    update(id: string, userData: Partial<User>): User | undefined {
        const user = this.findById(id);
        if (user) {
            Object.assign(user, userData);
            return user;
        }
        return undefined;
    }
}
```

### Generic Classes

```typescript
class Box<T> {
    private value: T;

    constructor(value: T) {
        this.value = value;
    }

    getValue(): T {
        return this.value;
    }

    setValue(value: T): void {
        this.value = value;
    }
}

const stringBox = new Box<string>("hello");
const numberBox = new Box<number>(42);
```

### Generic Constraints

```typescript
interface Lengthwise {
    length: number;
}

function logLength<T extends Lengthwise>(arg: T): T {
    console.log(arg.length);
    return arg;
}

logLength("hello"); // Works
logLength([1, 2, 3]); // Works
// logLength(42); // Error: no length property

// Using keyof
function getProperty<T, K extends keyof T>(obj: T, key: K): T[K] {
    return obj[key];
}

const person = { name: "Alice", age: 30 };
const name = getProperty(person, "name"); // string
const age = getProperty(person, "age"); // number
```

---

## Advanced Types

### Utility Types

```typescript
interface User {
    id: string;
    name: string;
    email: string;
    age: number;
}

// Partial - all properties optional
function updateUser(id: string, updates: Partial<User>) {
    // Implementation
}

// Pick - select specific properties
type UserSummary = Pick<User, "id" | "name">;

// Omit - exclude specific properties
type CreateUser = Omit<User, "id">;

// Required - all properties required
type RequiredUser = Required<Partial<User>>;

// Record - create object type
type UserRoles = Record<string, string>;
const roles: UserRoles = {
    "admin": "Administrator",
    "user": "Regular User"
};

// Exclude and Extract
type T1 = Exclude<"a" | "b" | "c", "a">; // "b" | "c"
type T2 = Extract<"a" | "b" | "c", "a" | "f">; // "a"
```

### Mapped Types

```typescript
// Make all properties optional
type Partial<T> = {
    [P in keyof T]?: T[P];
};

// Make all properties readonly
type Readonly<T> = {
    readonly [P in keyof T]: T[P];
};

// Custom mapped type
type Getters<T> = {
    [K in keyof T as `get${Capitalize<string & K>}`]: () => T[K];
};

type UserGetters = Getters<User>;
// Result: { getName: () => string; getEmail: () => string; ... }
```

### Conditional Types

```typescript
type NonNullable<T> = T extends null | undefined ? never : T;

type ApiResponse<T> = T extends string
    ? { message: T }
    : { data: T };

type StringResponse = ApiResponse<string>; // { message: string }
type UserResponse = ApiResponse<User>; // { data: User }

// Infer keyword
type ReturnType<T> = T extends (...args: any[]) => infer R ? R : any;

type FuncReturn = ReturnType<() => string>; // string
```

### Type Guards

```typescript
// typeof guards
function padLeft(value: string, padding: string | number) {
    if (typeof padding === "number") {
        return Array(padding + 1).join(" ") + value;
    }
    return padding + value;
}

// instanceof guards
class Bird {
    fly() { console.log("flying"); }
}

class Fish {
    swim() { console.log("swimming"); }
}

function move(animal: Bird | Fish) {
    if (animal instanceof Bird) {
        animal.fly();
    } else {
        animal.swim();
    }
}

// Custom type guards
function isString(value: any): value is string {
    return typeof value === "string";
}

function example(value: string | number) {
    if (isString(value)) {
        // value is string here
        console.log(value.toUpperCase());
    }
}
```

---

## Modules

### ES6 Modules

```typescript
// math.ts
export const PI = 3.14159;
export function add(a: number, b: number): number {
    return a + b;
}

export default class Calculator {
    multiply(a: number, b: number): number {
        return a * b;
    }
}

// main.ts
import Calculator, { PI, add } from './math';
import * as MathUtils from './math';

const calc = new Calculator();
console.log(calc.multiply(5, 3));
console.log(add(2, 3));
```

### Namespaces

```typescript
namespace Utilities {
    export function isNumber(value: any): value is number {
        return typeof value === "number";
    }

    export function isString(value: any): value is string {
        return typeof value === "string";
    }
}

// Usage
if (Utilities.isNumber(value)) {
    console.log(value.toFixed(2));
}
```

### Declaration Files

```typescript
// types.d.ts
declare module "my-library" {
    export function doSomething(value: string): number;
    export interface Config {
        apiKey: string;
        timeout: number;
    }
}

// Global declarations
declare global {
    interface Window {
        myGlobalFunction: () => void;
    }
}
```

---

## Decorators

### Class Decorators

```typescript
function Component(target: any) {
    target.prototype.render = function() {
        return `<${target.name.toLowerCase()}>`;
    };
}

@Component
class Button {
    label: string = "Click me";
}

const button = new Button();
console.log(button.render()); // <button>
```

### Method Decorators

```typescript
function Log(target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;

    descriptor.value = function(...args: any[]) {
        console.log(`Calling ${propertyKey} with:`, args);
        const result = originalMethod.apply(this, args);
        console.log(`Result:`, result);
        return result;
    };
}

class Calculator {
    @Log
    add(a: number, b: number): number {
        return a + b;
    }
}
```

### Property Decorators

```typescript
function MinLength(length: number) {
    return function(target: any, propertyKey: string) {
        let value: string;

        Object.defineProperty(target, propertyKey, {
            get: () => value,
            set: (newValue: string) => {
                if (newValue.length < length) {
                    throw new Error(`${propertyKey} must be at least ${length} characters`);
                }
                value = newValue;
            }
        });
    };
}

class User {
    @MinLength(3)
    username: string;
}
```

---

## Configuration

### tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "sourceMap": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

### Compiler Options

```json
{
  "compilerOptions": {
    // Type Checking
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,

    // Modules
    "module": "commonjs",
    "moduleResolution": "node",
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,

    // Emit
    "outDir": "./dist",
    "removeComments": true,
    "noEmitOnError": true,

    // JavaScript Support
    "allowJs": true,
    "checkJs": true
  }
}
```

---

## Real-World Usage

### React with TypeScript

```typescript
// Component props
interface Props {
    name: string;
    age?: number;
    onClick: (event: React.MouseEvent) => void;
}

const UserCard: React.FC<Props> = ({ name, age, onClick }) => {
    return (
        <div onClick={onClick}>
            <h3>{name}</h3>
            {age && <p>Age: {age}</p>}
        </div>
    );
};

// Hooks with types
const [users, setUsers] = useState<User[]>([]);
const [loading, setLoading] = useState<boolean>(false);

// Event handlers
const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    // Handle form submission
};
```

### Node.js with TypeScript

```typescript
// Express with TypeScript
import express, { Request, Response } from 'express';

interface CreateUserRequest extends Request {
    body: {
        name: string;
        email: string;
    };
}

const app = express();

app.post('/users', (req: CreateUserRequest, res: Response) => {
    const { name, email } = req.body;

    // Create user logic
    const user = { id: '1', name, email };

    res.json(user);
});

app.listen(3000);
```

### API Development

```typescript
// API response types
interface ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: string;
}

interface User {
    id: string;
    name: string;
    email: string;
}

// Service layer
class UserService {
    async getUser(id: string): Promise<ApiResponse<User>> {
        try {
            const user = await this.userRepository.findById(id);
            return { success: true, data: user };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async createUser(userData: Omit<User, 'id'>): Promise<ApiResponse<User>> {
        // Implementation
    }
}

// Controller with proper typing
class UserController {
    constructor(private userService: UserService) {}

    async getUser(req: Request, res: Response): Promise<void> {
        const { id } = req.params;
        const result = await this.userService.getUser(id);

        if (result.success) {
            res.json(result.data);
        } else {
            res.status(404).json({ error: result.error });
        }
    }
}
```