# Premium Proxy API - Deploy to Render

## 🚀 Deploy & Forget - No Setup Needed!

### 1. Push to GitHub
```bash
cd c:\Users\proay\OneDrive\Desktop\apiv2\deploy_ready
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPO.git
git push -u origin main
```

### 2. Deploy on Render
- Go to https://dashboard.render.com/
- Click **New** → **Blueprint** (or **Web Service**)
- Connect your GitHub repo
- Render auto-deploys using `render.yaml`
- **Done!** Your app stays awake 24/7 automatically

### 3. That's It!
✅ **Built-in keep-alive** - No UptimeRobot or external services needed  
✅ **Self-pings every 10 minutes** - Automatic, works like a charm  
✅ **Just deploy and forget** - Like your Telegram bot

---

## 🔐 Default Login

**IMPORTANT - Change after deployment!**
```
URL: https://your-app.onrender.com/lund
Username: admin
Password: admin123
```

---

## 📁 What's Inside

- **render.yaml** - Render auto-deploy config
- **main.py** - FastAPI app with built-in keep-alive
- **database.py** - SQLite (persists on Render)
- **auth.py** - Authentication
- **models.py** - Database models
- **static/** - Admin dashboard
- **requirements.txt** - Dependencies

---

## ⭐ Key Features

✅ **Self-contained** - No external monitoring needed  
✅ **Persistent SQLite** - Data survives deploys  
✅ **Auto keep-alive** - Pings itself every 10 min  
✅ **Free hosting** - Render free tier (750hrs/month)  
✅ **1GB storage** - Plenty for database  

---

## 📚 More Info

See **RENDER_DEPLOYMENT_GUIDE.md** for detailed documentation.

---

**Developer Credits**: @AV_AYUSH & @AyushIsInvalid
