import dotenv from 'dotenv';
import { checkDatabaseHealth } from '../config/database-manager.js';

// Load environment variables
dotenv.config();

console.log('🔧 Testing database connection...');
console.log(`📊 Database type: ${process.env.DB_TYPE || 'sqlite'}`);

if (process.env.DB_TYPE === 'postgres') {
  console.log(`🐘 PostgreSQL Configuration:`);
  console.log(`   Host: ${process.env.DB_HOST || 'Not set'}`);
  console.log(`   Port: ${process.env.DB_PORT || '5432'}`);
  console.log(`   Database: ${process.env.DB_NAME || 'Not set'}`);
  console.log(`   User: ${process.env.DB_USER || 'Not set'}`);
  console.log(`   Password: ${process.env.DB_PASSWORD ? '***' : 'Not set'}`);
} else {
  console.log(`🗃️ SQLite Configuration:`);
  console.log(`   Path: ${process.env.DB_PATH || './database/users.db'}`);
}

try {
  const health = await checkDatabaseHealth();
  
  if (health.healthy) {
    console.log('✅ Database connection successful!');
    console.log(`   Message: ${health.message}`);
  } else {
    console.log('❌ Database connection failed!');
    console.log(`   Error: ${health.message}`);
  }
} catch (error) {
  console.error('❌ Connection test failed:', error.message);
}

process.exit(0);