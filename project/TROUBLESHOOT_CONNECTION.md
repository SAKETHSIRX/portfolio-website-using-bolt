# 🔧 Troubleshoot Google Cloud SQL Connection

## Current Status
❌ **Connection timeout to your Cloud SQL instance**  
🔍 **Your IP**: `157.50.77.73`  
🎯 **Cloud SQL IP**: `34.93.190.51`  

## 🚨 Most Common Issues & Solutions

### 1. **IP Not Whitelisted** (Most Likely)
**Fix this first:**

1. Go to [Google Cloud SQL Console](https://console.cloud.google.com/sql)
2. Click your instance: `sakethsirx-db`
3. Go to **"Connections"** tab
4. Under **"Authorized networks"**:
   - Click **"Add Network"**
   - **Name**: `Development IP`
   - **Network**: `157.50.77.73/32`
   - Click **"Done"**
   - Click **"Save"**
5. **Wait 2-3 minutes** for changes to apply

### 2. **Database/User Not Created**
**Verify these exist:**

1. Go to **"Databases"** tab
   - Should see: `sakethsirx_auth`
   - If not, click **"Create Database"**, name it `sakethsirx_auth`

2. Go to **"Users"** tab
   - Should see: `saketh_user`
   - If not, click **"Add User Account"**:
     - Username: `saketh_user`
     - Password: `sakethsirx@200`

### 3. **Instance Not Running**
**Check instance status:**
- In Cloud SQL console, your instance should show **"RUNNABLE"** status
- If it shows "STOPPED", click the instance and click **"Start"**

### 4. **Firewall/Network Issues**
**Try these commands:**

```bash
# Test if you can reach the IP
ping 34.93.190.51

# Test if port 5432 is accessible
telnet 34.93.190.51 5432
```

### 5. **Wrong Region/Project**
**Verify you're in the right:**
- **Project**: Check top of Google Cloud Console
- **Region**: Should match where you created the instance

## 🔍 **Step-by-Step Verification**

### Step 1: Check Cloud SQL Console
1. Go to https://console.cloud.google.com/sql
2. Verify your instance `sakethsirx-db` is **RUNNABLE**
3. Note the **Public IP** matches: `34.93.190.51`

### Step 2: Check Connections
1. Click your instance → **"Connections"** tab
2. Verify **Public IP** is enabled
3. Under **"Authorized networks"**, you should see:
   - `157.50.77.73/32` (your IP)
   - Or `0.0.0.0/0` (allows all - less secure but works for testing)

### Step 3: Check Database & User
1. **"Databases"** tab: Should have `sakethsirx_auth`
2. **"Users"** tab: Should have `saketh_user`

### Step 4: Test Connection
After fixing the above, run:
```bash
npm run test-db
```

## 🆘 **Quick Fix Options**

### Option A: Temporary - Allow All IPs
**For testing only:**
1. Go to Connections → Authorized networks
2. Add network: `0.0.0.0/0` (allows all IPs)
3. **Remember to remove this later for security!**

### Option B: Check Your Current IP
Your IP might have changed. Run:
```bash
# In PowerShell
Invoke-RestMethod -Uri "https://ipinfo.io/ip"
```
Then add the new IP to authorized networks.

### Option C: Use Cloud Shell
1. In Google Cloud Console, click the **Cloud Shell** icon (>_)
2. Run: `gcloud sql connect sakethsirx-db --user=saketh_user`
3. If this works, the issue is with IP whitelisting

## 🎯 **Expected Success Output**
When working, you should see:
```
🐘 Using PostgreSQL database
🔧 Testing database connection...
📊 Database type: postgres
🐘 PostgreSQL Configuration:
   Host: 34.93.190.51
   Port: 5432
   Database: sakethsirx_auth
   User: saketh_user
   Password: ***
✅ Connected to PostgreSQL database
✅ Database connection successful!
   Message: Database connection is healthy
```

## 📞 **Next Steps**
1. **Fix the IP whitelisting** (most likely issue)
2. **Wait 2-3 minutes** after making changes
3. **Run `npm run test-db`** again
4. **If still failing**, check the other items above

**Let me know what you see in the Google Cloud SQL console!** 🚀