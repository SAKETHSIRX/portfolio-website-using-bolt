import { Client } from 'pg';
import dotenv from 'dotenv';
dotenv.config();

async function detailedTest() {
    console.log('🔍 Detailed PostgreSQL Connection Test');
    console.log('=====================================');
    
    // Check environment variables
    console.log('📋 Environment Variables:');
    console.log(`   DB_TYPE: ${process.env.DB_TYPE}`);
    console.log(`   DB_HOST: ${process.env.DB_HOST}`);
    console.log(`   DB_PORT: ${process.env.DB_PORT}`);
    console.log(`   DB_NAME: ${process.env.DB_NAME}`);
    console.log(`   DB_USER: ${process.env.DB_USER}`);
    console.log(`   DB_PASSWORD: ${process.env.DB_PASSWORD ? '***' : 'NOT SET'}`);
    console.log('');

    // Test 1: Basic connection
    console.log('🧪 Test 1: Basic Connection');
    const client = new Client({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        connectionTimeoutMillis: 10000, // 10 seconds
        query_timeout: 5000, // 5 seconds
    });

    try {
        console.log('   Attempting to connect...');
        await client.connect();
        console.log('   ✅ Connected successfully!');
        
        // Test 2: Simple query
        console.log('🧪 Test 2: Simple Query');
        const result = await client.query('SELECT NOW() as current_time');
        console.log(`   ✅ Query successful: ${result.rows[0].current_time}`);
        
        // Test 3: Check database
        console.log('🧪 Test 3: Database Check');
        const dbResult = await client.query('SELECT current_database()');
        console.log(`   ✅ Current database: ${dbResult.rows[0].current_database}`);
        
        // Test 4: Check user
        console.log('🧪 Test 4: User Check');
        const userResult = await client.query('SELECT current_user');
        console.log(`   ✅ Current user: ${userResult.rows[0].current_user}`);
        
        await client.end();
        console.log('');
        console.log('🎉 All tests passed! Database connection is working perfectly!');
        
    } catch (error) {
        console.log(`   ❌ Connection failed: ${error.message}`);
        console.log('');
        console.log('🔍 Error Analysis:');
        
        if (error.message.includes('timeout')) {
            console.log('   🚨 TIMEOUT ERROR - This means:');
            console.log('      • Your IP is not whitelisted in Google Cloud SQL');
            console.log('      • The instance might be stopped');
            console.log('      • Network/firewall issues');
        } else if (error.message.includes('authentication')) {
            console.log('   🚨 AUTHENTICATION ERROR - This means:');
            console.log('      • Wrong username or password');
            console.log('      • User doesn\'t exist in the database');
        } else if (error.message.includes('database') && error.message.includes('does not exist')) {
            console.log('   🚨 DATABASE ERROR - This means:');
            console.log('      • The database "sakethsirx_auth" doesn\'t exist');
            console.log('      • You need to create it in Google Cloud SQL');
        } else {
            console.log(`   🚨 OTHER ERROR: ${error.message}`);
        }
        
        console.log('');
        console.log('🛠️  Next Steps:');
        console.log('   1. Check Google Cloud SQL Console');
        console.log('   2. Verify your IP is in authorized networks: 157.50.77.73/32');
        console.log('   3. Ensure instance is RUNNABLE');
        console.log('   4. Verify database and user exist');
    }
}

detailedTest();