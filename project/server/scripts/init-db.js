import { initializeDatabase } from '../config/database-manager.js';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

console.log('🔧 Initializing database...');

initializeDatabase()
  .then(() => {
    console.log('✅ Database initialized successfully!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('❌ Database initialization failed:', error);
    process.exit(1);
  });