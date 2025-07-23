# sakethsirx Backend API

A secure Node.js/Express backend with SQLite database for user authentication.

## Features

- ✅ User registration and authentication
- ✅ JWT token-based security
- ✅ Password hashing with bcrypt
- ✅ Input validation and sanitization
- ✅ Rate limiting for security
- ✅ SQLite database with automatic initialization
- ✅ CORS configuration
- ✅ Error handling and logging

## API Endpoints

### Authentication Routes (`/api/auth`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/signup` | Create new user account | No |
| POST | `/signin` | Sign in user | No |
| GET | `/profile` | Get current user profile | Yes |
| PUT | `/profile` | Update user profile | Yes |
| PUT | `/change-password` | Change user password | Yes |
| POST | `/signout` | Sign out user | Yes |
| GET | `/health` | Health check | No |

### Request/Response Examples

#### Sign Up
```bash
POST /api/auth/signup
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

#### Sign In
```bash
POST /api/auth/signin
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

#### Response Format
```json
{
  "success": true,
  "message": "Operation successful",
  "data": {
    "user": {
      "id": 1,
      "name": "John Doe",
      "email": "john@example.com",
      "created_at": "2024-01-01T00:00:00.000Z"
    },
    "token": "jwt_token_here"
  }
}
```

## Setup Instructions

### 1. Install Dependencies
```bash
npm install
```

### 2. Environment Configuration
Create a `.env` file with:
```env
PORT=3001
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
NODE_ENV=development
DB_PATH=./database/users.db
CORS_ORIGIN=http://localhost:5174
```

### 3. Initialize Database
```bash
npm run init-db
```

### 4. Start Development Server
```bash
npm run dev
```

### 5. Start Production Server
```bash
npm start
```

## Database Schema

### Users Table
```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  is_active BOOLEAN DEFAULT 1,
  last_login DATETIME
);
```

## Security Features

- **Password Hashing**: bcrypt with 12 salt rounds
- **JWT Tokens**: 7-day expiration
- **Rate Limiting**: 5 auth attempts per 15 minutes
- **Input Validation**: Comprehensive validation rules
- **CORS Protection**: Configured for specific origins
- **Helmet**: Security headers
- **SQL Injection Protection**: Parameterized queries

## Password Requirements

- Minimum 8 characters
- Maximum 128 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (@$!%*?&)

## Development

### File Structure
```
server/
├── config/
│   └── database.js          # Database configuration
├── controllers/
│   └── authController.js    # Authentication logic
├── middleware/
│   ├── auth.js             # JWT authentication
│   └── validation.js       # Input validation
├── routes/
│   └── auth.js             # API routes
├── scripts/
│   └── init-db.js          # Database initialization
├── database/
│   └── users.db            # SQLite database (auto-created)
├── .env                    # Environment variables
├── package.json
└── server.js               # Main server file
```

### Available Scripts

- `npm run dev` - Start development server with nodemon
- `npm start` - Start production server
- `npm run init-db` - Initialize database tables

## Error Handling

The API returns consistent error responses:

```json
{
  "success": false,
  "message": "Error description",
  "errors": [
    {
      "field": "email",
      "message": "Please provide a valid email address",
      "value": "invalid-email"
    }
  ]
}
```

## Health Check

Check if the server is running:
```bash
GET /health
GET /api/auth/health
```

Both endpoints return server status and uptime information.