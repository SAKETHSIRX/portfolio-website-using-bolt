import sqlite3 from 'sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Create database directory if it doesn't exist
const dbDir = join(__dirname, '..', 'database');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = join(dbDir, 'users.db');

// Enable verbose mode for debugging
const sqlite = sqlite3.verbose();

// Create database connection
const db = new sqlite.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database at:', dbPath);
  }
});

// Initialize database tables
export const initializeDatabase = () => {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // Create users table
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          is_active BOOLEAN DEFAULT 1,
          last_login DATETIME
        )
      `, (err) => {
        if (err) {
          console.error('Error creating users table:', err.message);
          reject(err);
        } else {
          console.log('Users table created or already exists');
          
          // Create indexes for better performance
          db.run(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`, (err) => {
            if (err) {
              console.error('Error creating email index:', err.message);
              reject(err);
            } else {
              console.log('Database initialization completed');
              resolve();
            }
          });
        }
      });
    });
  });
};

// Database query helpers
export const dbGet = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        reject(err);
      } else {
        resolve(row);
      }
    });
  });
};

export const dbRun = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) {
        reject(err);
      } else {
        resolve({ id: this.lastID, changes: this.changes });
      }
    });
  });
};

export const dbAll = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
      } else {
        resolve(rows);
      }
    });
  });
};

// Health check function
export const checkDatabaseHealth = () => {
  return new Promise((resolve) => {
    db.get('SELECT 1', (err) => {
      if (err) {
        resolve({ healthy: false, message: `Database connection failed: ${err.message}` });
      } else {
        resolve({ healthy: true, message: 'Database connection is healthy' });
      }
    });
  });
};

// Graceful shutdown
export const closeDatabaseConnection = () => {
  return new Promise((resolve) => {
    db.close((err) => {
      if (err) {
        console.error('Error closing database connection:', err);
      } else {
        console.log('🔌 Database connection closed');
      }
      resolve();
    });
  });
};

export default db;