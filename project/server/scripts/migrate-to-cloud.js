import dotenv from 'dotenv';
import { dbAll } from '../config/database-manager.js';

// Load environment variables
dotenv.config();

console.log('🔄 Database Migration Helper');
console.log('=====================================');

if (process.env.DB_TYPE !== 'sqlite') {
  console.log('❌ This script only works when currently using SQLite');
  console.log('💡 Set DB_TYPE=sqlite in .env to export your current data');
  process.exit(1);
}

try {
  // Export current users from SQLite
  const users = await dbAll('SELECT id, name, email, created_at, updated_at, is_active, last_login FROM users');
  
  console.log(`📊 Found ${users.length} users in SQLite database:`);
  
  if (users.length > 0) {
    console.log('\n👥 Current Users:');
    users.forEach((user, index) => {
      console.log(`   ${index + 1}. ${user.name} (${user.email}) - Created: ${user.created_at}`);
    });
    
    console.log('\n📋 SQL to recreate users in PostgreSQL:');
    console.log('=====================================');
    
    users.forEach(user => {
      // Note: We can't export passwords as they're hashed
      console.log(`INSERT INTO users (name, email, created_at, updated_at, is_active, last_login) VALUES`);
      console.log(`  ('${user.name.replace(/'/g, "''")}', '${user.email}', '${user.created_at}', '${user.updated_at}', ${user.is_active}, ${user.last_login ? `'${user.last_login}'` : 'NULL'});`);
    });
    
    console.log('\n⚠️  Note: Passwords cannot be migrated (they are hashed).');
    console.log('   Users will need to reset their passwords or create new accounts.');
  } else {
    console.log('✅ No users found - clean migration to Cloud SQL!');
  }
  
} catch (error) {
  console.error('❌ Migration helper failed:', error.message);
}

console.log('\n🚀 Next Steps:');
console.log('1. Create your Google Cloud SQL instance');
console.log('2. Update .env with Cloud SQL credentials');
console.log('3. Run: npm run test-db');
console.log('4. Run: npm run init-db');
console.log('5. Start using your Cloud database!');

process.exit(0);