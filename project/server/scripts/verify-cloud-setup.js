import dotenv from 'dotenv';
import { initializeDatabase, checkDatabaseHealth, dbGet, dbRun } from '../config/database-manager.js';
import bcrypt from 'bcryptjs';

// Load environment variables
dotenv.config();

console.log('🔍 Verifying Google Cloud SQL Setup');
console.log('====================================');

if (process.env.DB_TYPE !== 'postgres') {
  console.log('❌ DB_TYPE is not set to "postgres"');
  console.log('💡 Update your .env file to use PostgreSQL');
  process.exit(1);
}

try {
  // Test 1: Connection Health
  console.log('1️⃣ Testing database connection...');
  const health = await checkDatabaseHealth();
  
  if (!health.healthy) {
    console.log('❌ Database connection failed:', health.message);
    process.exit(1);
  }
  console.log('✅ Database connection successful');

  // Test 2: Initialize Tables
  console.log('\n2️⃣ Initializing database tables...');
  await initializeDatabase();
  console.log('✅ Database tables created successfully');

  // Test 3: Insert Test User
  console.log('\n3️⃣ Testing user creation...');
  const testEmail = 'test@sakethsirx.com';
  
  // Check if test user already exists
  const existingUser = await dbGet(
    'SELECT id FROM users WHERE email = $1',
    [testEmail]
  );
  
  if (existingUser) {
    console.log('ℹ️ Test user already exists, skipping creation');
  } else {
    const hashedPassword = await bcrypt.hash('TestPassword123!', 12);
    const result = await dbRun(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id',
      ['Test User', testEmail, hashedPassword]
    );
    
    if (result.rows && result.rows[0]) {
      console.log('✅ Test user created successfully');
    } else {
      console.log('❌ Failed to create test user');
      process.exit(1);
    }
  }

  // Test 4: Query Test User
  console.log('\n4️⃣ Testing user retrieval...');
  const user = await dbGet(
    'SELECT id, name, email, created_at FROM users WHERE email = $1',
    [testEmail]
  );
  
  if (user) {
    console.log('✅ User retrieval successful');
    console.log(`   User: ${user.name} (${user.email})`);
    console.log(`   Created: ${user.created_at}`);
  } else {
    console.log('❌ Failed to retrieve user');
    process.exit(1);
  }

  // Test 5: Count Users
  console.log('\n5️⃣ Checking user count...');
  const countResult = await dbGet('SELECT COUNT(*) as count FROM users');
  console.log(`✅ Total users in database: ${countResult.count}`);

  console.log('\n🎉 All tests passed! Your Google Cloud SQL setup is working perfectly!');
  console.log('\n🚀 Next steps:');
  console.log('   1. Start your backend: npm run dev');
  console.log('   2. Start your frontend: npm run dev (in project root)');
  console.log('   3. Test the authentication flow');
  console.log('   4. Remove the test user when ready');

} catch (error) {
  console.error('❌ Verification failed:', error.message);
  console.error('\n🔧 Troubleshooting tips:');
  console.error('   1. Check your .env configuration');
  console.error('   2. Verify your Cloud SQL instance is running');
  console.error('   3. Ensure your IP is whitelisted');
  console.error('   4. Check database credentials');
  process.exit(1);
}

process.exit(0);