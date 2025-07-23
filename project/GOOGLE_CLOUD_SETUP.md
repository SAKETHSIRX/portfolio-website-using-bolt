# Google Cloud SQL Database Setup Guide

## Step 1: Create Cloud SQL Instance

1. **Go to Google Cloud Console**
   - Visit: https://console.cloud.google.com/
   - Make sure you're in the correct project

2. **Navigate to Cloud SQL**
   - In the left menu, go to "SQL" or search for "Cloud SQL"
   - Click "Create Instance"

3. **Choose Database Engine**
   - Select "PostgreSQL" (recommended for your use case)
   - Click "Next"

4. **Configure Instance**
   - **Instance ID**: `sakethsirx-db` (or your preferred name)
   - **Password**: Create a strong password for the `postgres` user
   - **Database version**: PostgreSQL 15 (latest stable)
   - **Region**: Choose closest to your users (e.g., us-central1)
   - **Zone**: Any (or specific if you prefer)

5. **Machine Configuration**
   - **Machine type**: Start with "Lightweight" (1 vCPU, 3.75 GB RAM)
   - **Storage**: 10 GB SSD (you can increase later)
   - **Enable automatic storage increases**: ✅ Yes

6. **Connections**
   - **Public IP**: ✅ Enable
   - **Authorized networks**: Add `0.0.0.0/0` for now (we'll secure this later)
   - **Private IP**: Leave disabled for now

7. **Data Protection**
   - **Automated backups**: ✅ Enable
   - **Point-in-time recovery**: ✅ Enable

8. **Maintenance**
   - **Maintenance window**: Choose a time when your app has low traffic

9. **Flags** (Optional)
   - Leave default settings

10. **Click "Create Instance"**
    - This will take 5-10 minutes to complete

## Step 2: Create Database and User

Once your instance is created:

1. **Connect to your instance**
   - Click on your instance name
   - Go to "Databases" tab
   - Click "Create Database"
   - Database name: `sakethsirx_auth`
   - Click "Create"

2. **Create a dedicated user**
   - Go to "Users" tab
   - Click "Add User Account"
   - Username: `sakethsirx_user`
   - Password: Create a strong password
   - Click "Add"

## Step 3: Get Connection Details

From your Cloud SQL instance overview page, note down:
- **Public IP address**
- **Instance connection name** (format: project-id:region:instance-name)
- **Database name**: `sakethsirx_auth`
- **Username**: `sakethsirx_user`
- **Password**: (the one you created)

## Step 4: Security Setup (Important!)

1. **Restrict IP Access**
   - Go to "Connections" tab
   - Under "Authorized networks"
   - Remove `0.0.0.0/0`
   - Add your current IP address
   - Add your server's IP address when you deploy

2. **SSL Configuration**
   - Go to "Connections" tab
   - Under "SSL"
   - Download the server certificate files

## Estimated Costs

For a lightweight instance:
- **Compute**: ~$7-15/month
- **Storage**: ~$0.17/GB/month (10GB = ~$1.70/month)
- **Network**: Minimal for development
- **Total**: ~$10-20/month for development

## Next Steps

After creating the database, I'll help you:
1. Update your backend to connect to PostgreSQL
2. Install necessary dependencies
3. Configure environment variables
4. Migrate your data structure
5. Test the connection

---

**Ready to proceed?** Let me know when you've created the Cloud SQL instance and I'll help you connect it to your backend!