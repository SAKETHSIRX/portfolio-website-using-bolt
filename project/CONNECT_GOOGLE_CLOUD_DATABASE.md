# Connect Google Cloud SQL Database - Step by Step Guide

## 🚀 Current Status
✅ Your backend is ready to connect to Google Cloud SQL  
✅ PostgreSQL driver installed  
✅ Database abstraction layer configured  
✅ SQLite working as fallback  

## 📋 Prerequisites
- Google Cloud account with billing enabled
- 1TB of space available (as you mentioned)
- Project created in Google Cloud Console

## Step 1: Create Cloud SQL Instance

### 1.1 Access Google Cloud Console
1. Go to https://console.cloud.google.com/
2. Select your project or create a new one
3. Enable the Cloud SQL Admin API if prompted

### 1.2 Create PostgreSQL Instance
1. Navigate to **SQL** in the left sidebar
2. Click **"Create Instance"**
3. Choose **PostgreSQL**
4. Configure your instance:

```
Instance ID: sakethsirx-db
Password: [Create a strong password - save this!]
Database version: PostgreSQL 15
Region: us-central1 (or closest to your users)
Zone: Any
```

### 1.3 Machine Configuration
```
Machine type: Lightweight (1 vCPU, 3.75 GB RAM) - $7-15/month
Storage: 10 GB SSD (can auto-increase)
Enable automatic storage increases: ✅
```

### 1.4 Connections & Security
```
Public IP: ✅ Enable
Private IP: ❌ Disable (for now)
Authorized networks: 0.0.0.0/0 (temporary - we'll secure this)
SSL: Required (default)
```

### 1.5 Backup & Maintenance
```
Automated backups: ✅ Enable
Point-in-time recovery: ✅ Enable
Maintenance window: Choose low-traffic time
```

5. Click **"Create Instance"** (takes 5-10 minutes)

## Step 2: Configure Database

### 2.1 Create Database
1. Click on your instance name
2. Go to **"Databases"** tab
3. Click **"Create Database"**
4. Database name: `sakethsirx_auth`
5. Click **"Create"**

### 2.2 Create User
1. Go to **"Users"** tab
2. Click **"Add User Account"**
3. Username: `sakethsirx_user`
4. Password: [Create strong password - save this!]
5. Click **"Add"**

### 2.3 Get Connection Info
From the **Overview** tab, note down:
- **Public IP address** (e.g., 34.123.45.67)
- **Instance connection name** (e.g., your-project:us-central1:sakethsirx-db)

## Step 3: Update Your Backend Configuration

### 3.1 Update Environment Variables
Edit your `server/.env` file:

```env
PORT=3001
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
NODE_ENV=development
CORS_ORIGIN=http://localhost:5174

# Switch to PostgreSQL
DB_TYPE=postgres

# Google Cloud SQL Configuration
DB_HOST=YOUR_PUBLIC_IP_HERE
DB_PORT=5432
DB_NAME=sakethsirx_auth
DB_USER=sakethsirx_user
DB_PASSWORD=YOUR_DATABASE_PASSWORD_HERE

# Comment out SQLite config
# DB_PATH=./database/users.db
```

### 3.2 Example Configuration
```env
# Replace with your actual values
DB_TYPE=postgres
DB_HOST=34.123.45.67
DB_PORT=5432
DB_NAME=sakethsirx_auth
DB_USER=sakethsirx_user
DB_PASSWORD=YourStrongPassword123!
```

## Step 4: Test Connection

### 4.1 Test Database Connection
```bash
cd server
npm run test-db
```

You should see:
```
🐘 Using PostgreSQL database
🔧 Testing database connection...
📊 Database type: postgres
🐘 PostgreSQL Configuration:
   Host: 34.123.45.67
   Port: 5432
   Database: sakethsirx_auth
   User: sakethsirx_user
   Password: ***
✅ Database connection successful!
```

### 4.2 Initialize Database Tables
```bash
npm run init-db
```

### 4.3 Start Server
```bash
npm run dev
```

## Step 5: Security Hardening

### 5.1 Restrict IP Access
1. Go to Cloud SQL instance → **Connections**
2. Under **Authorized networks**, remove `0.0.0.0/0`
3. Add your current IP address
4. Add your production server IP when deploying

### 5.2 SSL Configuration (Production)
1. Download SSL certificates from Cloud SQL
2. Update `.env` with certificate paths:
```env
DB_SSL_CA=path/to/server-ca.pem
DB_SSL_CERT=path/to/client-cert.pem
DB_SSL_KEY=path/to/client-key.pem
```

## Step 6: Test Your Application

### 6.1 Test Authentication Flow
1. Start your frontend: `npm run dev`
2. Start your backend: `cd server && npm run dev`
3. Go to http://localhost:5174
4. Click "Sign In / Sign Up"
5. Create a new account
6. Verify data is stored in Google Cloud SQL

### 6.2 Verify in Cloud Console
1. Go to Cloud SQL → Your instance → **Query**
2. Run: `SELECT * FROM users;`
3. You should see your test user data

## 🎯 Benefits of Google Cloud SQL

✅ **Scalability**: Auto-scaling storage up to your 1TB limit  
✅ **Reliability**: 99.95% uptime SLA  
✅ **Security**: Encrypted at rest and in transit  
✅ **Backups**: Automatic daily backups + point-in-time recovery  
✅ **Monitoring**: Built-in performance insights  
✅ **Global**: Available in multiple regions  

## 💰 Cost Estimation

**Development Setup:**
- Lightweight instance: ~$7-15/month
- 10GB storage: ~$1.70/month
- Network egress: ~$1-5/month
- **Total: ~$10-20/month**

**Production Setup:**
- Standard instance: ~$25-50/month
- 100GB storage: ~$17/month
- High availability: +100% cost
- **Total: ~$50-150/month**

## 🔧 Troubleshooting

### Connection Issues
1. Check firewall rules in Google Cloud
2. Verify IP whitelist includes your current IP
3. Ensure database user has proper permissions
4. Check SSL requirements

### Performance Issues
1. Monitor query performance in Cloud SQL
2. Add database indexes for frequently queried fields
3. Consider connection pooling optimization

## 🚀 Next Steps After Setup

1. **Test thoroughly** with your authentication flow
2. **Monitor performance** in Cloud SQL console
3. **Set up alerts** for high CPU/memory usage
4. **Plan backup strategy** for production
5. **Consider read replicas** for scaling

---

## 📞 Need Help?

If you encounter any issues:
1. Check the Cloud SQL logs in Google Cloud Console
2. Run `npm run test-db` to verify connection
3. Check your `.env` configuration
4. Ensure your IP is whitelisted

**Ready to proceed?** Follow the steps above and let me know when you've created your Cloud SQL instance!