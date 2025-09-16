# Fullstack Development Tech Recap

## Frontend Technologies

### HTML
**Purpose**: Markup language for web structure
```html
<!DOCTYPE html>
<html>
<head><title>Page Title</title></head>
<body>
  <h1>Heading</h1>
  <p>Paragraph</p>
  <div class="container">Content</div>
</body>
</html>
```
**Key Elements**: `div`, `span`, `form`, `input`, `button`, `a`, `img`, `ul/ol/li`
**Semantic HTML**: `header`, `nav`, `main`, `section`, `article`, `aside`, `footer`

### CSS
**Purpose**: Styling and layout
```css
.container {
  display: flex;
  justify-content: center;
  align-items: center;
  background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
}
```
**Key Concepts**: Flexbox, Grid, Box Model, Specificity, Responsive Design
**Units**: `px`, `em`, `rem`, `vh/vw`, `%`
**Selectors**: `.class`, `#id`, `element`, `[attribute]`, `:pseudo`

### JavaScript
**Purpose**: Dynamic behavior and logic
```javascript
// Variables & Functions
const fetchData = async (url) => {
  try {
    const response = await fetch(url);
    return await response.json();
  } catch (error) {
    console.error(error);
  }
};

// DOM Manipulation
document.querySelector('.btn').addEventListener('click', (e) => {
  e.target.textContent = 'Clicked!';
});

// Array Methods
const numbers = [1, 2, 3, 4, 5];
const doubled = numbers.map(n => n * 2);
const evens = numbers.filter(n => n % 2 === 0);
```
**ES6+ Features**: Arrow functions, destructuring, spread operator, template literals, modules

### React
**Purpose**: Component-based UI library
```jsx
import React, { useState, useEffect } from 'react';

const UserComponent = ({ userId }) => {
  const [user, setUser] = useState(null);
  
  useEffect(() => {
    fetch(`/api/users/${userId}`)
      .then(res => res.json())
      .then(setUser);
  }, [userId]);
  
  return (
    <div>
      {user ? <h1>{user.name}</h1> : <div>Loading...</div>}
    </div>
  );
};
```
**Hooks**: `useState`, `useEffect`, `useContext`, `useReducer`, `useMemo`, `useCallback`
**Patterns**: HOCs, Render Props, Compound Components

### Vue.js
**Purpose**: Progressive framework
```vue
<template>
  <div>
    <h1>{{ title }}</h1>
    <button @click="increment">Count: {{ count }}</button>
  </div>
</template>

<script>
export default {
  data() {
    return { count: 0, title: 'Vue App' };
  },
  methods: {
    increment() { this.count++; }
  }
};
</script>
```

### Angular
**Purpose**: Full framework with TypeScript
```typescript
@Component({
  selector: 'app-user',
  template: `
    <h1>{{ user.name }}</h1>
    <button (click)="updateUser()">Update</button>
  `
})
export class UserComponent {
  user: User = { name: 'John' };
  
  updateUser() {
    this.userService.update(this.user);
  }
}
```

## Backend Technologies

### Node.js & Express
**Purpose**: JavaScript runtime and web framework
```javascript
const express = require('express');
const app = express();

app.use(express.json());

app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

### Python (Django/Flask)
```python
# Django
from django.http import JsonResponse
from django.views import View

class UserView(View):
    def get(self, request, user_id):
        user = User.objects.get(id=user_id)
        return JsonResponse({'name': user.name})

# Flask
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify({'name': user.name})
```

### Java (Spring Boot)
```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @GetMapping("/{id}")
    public ResponseEntity<User> getUser(@PathVariable Long id) {
        User user = userService.findById(id);
        return ResponseEntity.ok(user);
    }
}
```

### C# (.NET)
```csharp
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    [HttpGet("{id}")]
    public async Task<ActionResult<User>> GetUser(int id)
    {
        var user = await _userService.GetByIdAsync(id);
        return Ok(user);
    }
}
```

## Databases

### SQL (PostgreSQL/MySQL)
**Purpose**: Relational database management
```sql
-- Create Table
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(255) UNIQUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Queries
SELECT u.name, COUNT(o.id) as order_count 
FROM users u 
LEFT JOIN orders o ON u.id = o.user_id 
GROUP BY u.id 
HAVING COUNT(o.id) > 5;

-- Indexes
CREATE INDEX idx_user_email ON users(email);

-- Transactions
BEGIN;
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
UPDATE accounts SET balance = balance + 100 WHERE id = 2;
COMMIT;
```
**Key Concepts**: ACID, Normalization, Joins, Indexes, Transactions, Views, Stored Procedures

### NoSQL (MongoDB)
**Purpose**: Document-based database
```javascript
// Insert
db.users.insertOne({
  name: "John Doe",
  email: "john@example.com",
  tags: ["developer", "javascript"],
  address: { city: "New York", country: "USA" }
});

// Query
db.users.find({
  "address.city": "New York",
  tags: { $in: ["javascript", "python"] }
}).sort({ created_at: -1 }).limit(10);

// Update
db.users.updateMany(
  { tags: "developer" },
  { $set: { "profile.type": "professional" } }
);

// Aggregation
db.users.aggregate([
  { $match: { tags: "developer" } },
  { $group: { _id: "$address.city", count: { $sum: 1 } } },
  { $sort: { count: -1 } }
]);
```

### Redis
**Purpose**: In-memory key-value store
```bash
# Strings
SET user:1000 "John Doe"
GET user:1000

# Hashes
HSET user:1001 name "Jane" email "jane@example.com"
HGETALL user:1001

# Lists
LPUSH tasks "task1" "task2"
RPOP tasks

# Sets
SADD tags:user:1000 "developer" "javascript"
SMEMBERS tags:user:1000

# Sorted Sets
ZADD leaderboard 100 "player1" 200 "player2"
ZRANGE leaderboard 0 -1 WITHSCORES
```

## DevOps & Deployment

### Docker
**Purpose**: Containerization
```dockerfile
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

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
  db:
    image: postgres:13
    environment:
      POSTGRES_DB: myapp
      POSTGRES_PASSWORD: password
```

### Kubernetes
**Purpose**: Container orchestration
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-deployment
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
      - name: app
        image: myapp:latest
        ports:
        - containerPort: 3000
```

### CI/CD (GitHub Actions)
```yaml
name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup Node
      uses: actions/setup-node@v2
      with:
        node-version: '16'
    - run: npm ci
    - run: npm test
    - run: npm run build
    - name: Deploy
      run: echo "Deploy to production"
```

### AWS Services
- **EC2**: Virtual servers
- **S3**: Object storage
- **RDS**: Managed databases
- **Lambda**: Serverless functions
- **CloudFront**: CDN
- **Route 53**: DNS
- **ELB**: Load balancing

## API Design

### REST
**Principles**: Stateless, cacheable, uniform interface
```javascript
// Express.js REST API
app.get('/api/users', getAllUsers);          // GET collection
app.get('/api/users/:id', getUserById);      // GET resource
app.post('/api/users', createUser);          // CREATE
app.put('/api/users/:id', updateUser);       // UPDATE (full)
app.patch('/api/users/:id', patchUser);      // UPDATE (partial)
app.delete('/api/users/:id', deleteUser);    // DELETE

// HTTP Status Codes
// 200 OK, 201 Created, 204 No Content
// 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found
// 500 Internal Server Error
```

### GraphQL
**Purpose**: Query language for APIs
```graphql
# Schema
type User {
  id: ID!
  name: String!
  email: String!
  posts: [Post!]!
}

type Query {
  user(id: ID!): User
  users: [User!]!
}

# Query
query GetUser($id: ID!) {
  user(id: $id) {
    name
    email
    posts {
      title
      content
    }
  }
}
```

```javascript
// Resolver
const resolvers = {
  Query: {
    user: (parent, args) => User.findById(args.id),
    users: () => User.findAll()
  },
  User: {
    posts: (parent) => Post.findByUserId(parent.id)
  }
};
```

## Testing

### Unit Testing (Jest)
```javascript
// user.test.js
describe('User Service', () => {
  test('should create user with valid data', async () => {
    const userData = { name: 'John', email: 'john@example.com' };
    const user = await userService.create(userData);
    
    expect(user).toHaveProperty('id');
    expect(user.name).toBe('John');
  });
  
  test('should throw error for invalid email', async () => {
    const userData = { name: 'John', email: 'invalid-email' };
    
    await expect(userService.create(userData))
      .rejects.toThrow('Invalid email format');
  });
});
```

### Integration Testing
```javascript
// api.test.js
describe('User API', () => {
  test('GET /api/users should return users list', async () => {
    const response = await request(app)
      .get('/api/users')
      .expect(200);
      
    expect(response.body).toBeInstanceOf(Array);
    expect(response.body[0]).toHaveProperty('name');
  });
});
```

### E2E Testing (Cypress)
```javascript
describe('User Registration', () => {
  it('should register new user', () => {
    cy.visit('/register');
    cy.get('[data-cy=name]').type('John Doe');
    cy.get('[data-cy=email]').type('john@example.com');
    cy.get('[data-cy=password]').type('password123');
    cy.get('[data-cy=submit]').click();
    
    cy.url().should('include', '/dashboard');
    cy.contains('Welcome, John Doe');
  });
});
```

## Security

### Authentication & Authorization
```javascript
// JWT Authentication
const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Usage
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Protected route', user: req.user });
});
```

### Input Validation
```javascript
const { body, validationResult } = require('express-validator');

app.post('/api/users',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
    body('name').trim().isLength({ min: 2, max: 50 })
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // Process valid data
  }
);
```

### SQL Injection Prevention
```javascript
// Good - Parameterized queries
const query = 'SELECT * FROM users WHERE email = $1 AND active = $2';
const result = await db.query(query, [email, true]);

// Bad - String concatenation
// const query = `SELECT * FROM users WHERE email = '${email}'`;
```

## Performance Optimization

### Caching
```javascript
// Redis caching
const redis = require('redis');
const client = redis.createClient();

const getCachedUser = async (userId) => {
  const cached = await client.get(`user:${userId}`);
  if (cached) return JSON.parse(cached);
  
  const user = await User.findById(userId);
  await client.setex(`user:${userId}`, 3600, JSON.stringify(user));
  return user;
};
```

### Database Optimization
```sql
-- Indexing
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_orders_user_date ON orders(user_id, created_at);

-- Query optimization
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'john@example.com';
```

### Frontend Optimization
```javascript
// Code splitting
const LazyComponent = React.lazy(() => import('./LazyComponent'));

// Memoization
const MemoizedComponent = React.memo(({ data }) => {
  return <div>{data.name}</div>;
});

// Virtual scrolling for large lists
import { FixedSizeList } from 'react-window';
```

## Common Interview Questions

### JavaScript
- **Closures**: Functions that retain access to outer scope
- **Promises vs Async/Await**: Promise handling patterns
- **Event Loop**: How JavaScript handles asynchronous operations
- **Prototypal Inheritance**: Object inheritance in JavaScript
- **Hoisting**: Variable and function declaration behavior

### React
- **Virtual DOM**: React's reconciliation algorithm
- **Component Lifecycle**: Mount, update, unmount phases
- **State Management**: Local state vs global state (Redux, Context)
- **Performance**: Memoization, code splitting, lazy loading

### System Design
- **Scalability**: Horizontal vs vertical scaling
- **Load Balancing**: Distributing traffic across servers
- **Caching Strategies**: Browser, CDN, application, database
- **Database Design**: SQL vs NoSQL, sharding, replication
- **Microservices**: Service decomposition, communication patterns

### Algorithms & Data Structures
- **Time/Space Complexity**: Big O notation
- **Arrays/Strings**: Two pointers, sliding window
- **Trees/Graphs**: DFS, BFS, traversal algorithms
- **Dynamic Programming**: Memoization, tabulation
- **Sorting/Searching**: QuickSort, MergeSort, Binary Search

## Tools & Utilities

### Version Control (Git)
```bash
git init
git add .
git commit -m "Initial commit"
git branch feature/new-feature
git checkout feature/new-feature
git merge main
git rebase main
git push origin main
```

### Package Managers
```bash
# npm
npm init
npm install express
npm install --save-dev jest
npm run test

# yarn
yarn init
yarn add express
yarn add --dev jest
yarn test
```

### Build Tools
```javascript
// Webpack
module.exports = {
  entry: './src/index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'bundle.js'
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: 'babel-loader'
      }
    ]
  }
};

// Vite
export default {
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: 'src/main.js'
    }
  }
};
```

This comprehensive guide covers the essential fullstack development concepts with practical examples for quick reference and interview preparation.