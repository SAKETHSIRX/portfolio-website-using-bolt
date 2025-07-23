// Database manager to switch between SQLite and PostgreSQL
import dotenv from 'dotenv';
dotenv.config();

const DB_TYPE = process.env.DB_TYPE || 'sqlite'; // 'sqlite' or 'postgres'

let dbModule;

if (DB_TYPE === 'postgres') {
  console.log('🐘 Using PostgreSQL database');
  dbModule = await import('./database-postgres.js');
} else {
  console.log('🗃️ Using SQLite database');
  dbModule = await import('./database.js');
}

// Export all database functions
export const {
  initializeDatabase,
  dbGet,
  dbRun,
  dbAll,
  checkDatabaseHealth,
  closeDatabaseConnection
} = dbModule;

export default dbModule.default;