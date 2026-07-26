# Deploy SecureShop Demo to a Live Public URL (5 Minutes)

## Recommended: Render.com (Free, No Credit Card Required)

### Step 1: Create a GitHub Repository
1. Go to github.com, sign in (or create a free account)
2. Click "New Repository" -> name it "secureshop-demo" -> Create
3. Upload all files from this folder (app.py, requirements.txt,
   Procfile, render.yaml, templates/, static/) using the
   "uploading an existing file" link on the repo page

### Step 2: Deploy on Render
1. Go to render.com, sign in with your GitHub account (free)
2. Click "New +" -> "Web Service"
3. Connect your "secureshop-demo" repository
4. Render will auto-detect the render.yaml file - just click "Apply"
   (or manually set: Build Command = "pip install -r requirements.txt",
   Start Command = "gunicorn app:app")
5. Click "Create Web Service"
6. Wait ~2-3 minutes for the first deploy

### Step 3: Get Your Live URL
Render will give you a URL like:
    https://secureshop-demo.onrender.com

This is now a REAL, public, HTTPS website you can open on any
device, anywhere - including live in your synopsis meeting.

---

## Alternative: PythonAnywhere (Also Free, Slightly Different Steps)

1. Sign up free at pythonanywhere.com
2. Go to "Files" tab, upload all files from this folder
3. Go to "Web" tab -> "Add a new web app" -> Flask -> Python 3.10
4. Point it to your app.py
5. Click "Reload" - you get a URL like yourusername.pythonanywhere.com

---

## What to Say During Your Demo

"This is a live, publicly deployed version of my framework's checkout
flow. I'll register a test account, select a product, and toggle
whether the checkout page is HTTPS-secure to show RS2C activating
in real time." [Then click through registration -> shop -> checkout,
toggling the security radio button to show both paths]

## Important Reminder

This uses FAKE test card data only (Stripe's standard test number,
4242 4242 4242 4242) - no real payment processing occurs. Mention
this if asked, to be fully transparent about what's being demonstrated.
