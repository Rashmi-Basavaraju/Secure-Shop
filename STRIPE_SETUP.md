# Enabling Real Stripe Sandbox Testing (Option B)

This connects your framework's final "Payment Gateway" step to
Stripe's REAL test-mode infrastructure - genuine HTTPS API calls,
genuine network latency, genuine payment processing logic - with
ZERO real money or real card data involved.

**IMPORTANT: I (Claude) could not test this code with a live Stripe
call, since this environment has no internet access. Please test it
yourself and let me know if anything needs fixing.**

## Step 1: Create a Free Stripe Account

1. Go to https://dashboard.stripe.com/register
2. Sign up (free, no credit card required for test mode)
3. You'll land on your Stripe Dashboard - make sure you're in
   "Test mode" (there's a toggle, usually top-right - it should
   already default to Test mode for a new account)

## Step 2: Get Your Test Secret Key

1. In the Stripe Dashboard, go to "Developers" -> "API keys"
2. Copy the key that starts with `sk_test_...`
   (NOT the one starting with `pk_test_` - that's the publishable key)
3. Keep this secret - don't share it or commit it to a public GitHub repo

## Step 3: Set the Environment Variable

### If running locally:

**Windows (Command Prompt):**
```
set STRIPE_SECRET_KEY=sk_test_your_key_here
python app.py
```

**Windows (PowerShell):**
```
$env:STRIPE_SECRET_KEY="sk_test_your_key_here"
python app.py
```

**Mac/Linux:**
```
export STRIPE_SECRET_KEY=sk_test_your_key_here
python app.py
```

### If deployed on Render:

1. Go to your Web Service on Render
2. Click "Environment" in the left sidebar
3. Click "Add Environment Variable"
4. Key: `STRIPE_SECRET_KEY`
5. Value: your `sk_test_...` key
6. Save - Render will automatically redeploy

## Step 4: Install the Stripe Library

If running locally, this happens automatically via requirements.txt:
```
pip install -r requirements.txt
```

## Step 5: Test It

Run through the checkout flow as normal. The "Payment Gateway" step
should now show something like:

```
Payment Gateway - Stripe (TEST MODE)
PaymentIntent pi_3Xxxxxxx... -> status: succeeded (livemode=False)
```

The `livemode=False` confirms this is genuinely running in Stripe's
safe test environment, not processing anything real.

## If It Doesn't Work

Common issues:
- Key not set correctly -> double check no extra spaces/quotes
- Using the publishable key (pk_test_) instead of secret key (sk_test_)
- Stripe library not installed -> run `pip install stripe`

If you hit an error message you don't understand, copy the exact
"Payment Gateway" line shown on the results page and bring it back
to this conversation - I can help debug it even though I can't run
it myself.

## What This Proves for Your Research

Once working, you can honestly state in your thesis/viva:

"The framework's final payment step was validated against Stripe's
production-grade sandbox API, confirming compatibility with real
payment gateway infrastructure - including genuine HTTPS handshakes,
API latency, and payment processing workflows - without processing
any real financial transactions."
