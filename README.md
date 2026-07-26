# SecureShop Demo - Privacy-Preserving CCT Framework

## What This Is
A local demo web application showing your five objectives running through
a simulated checkout flow, with real timing and real cryptographic math
(toy-scale, for demonstration).

⚠️ ACADEMIC DEMO ONLY — uses fake test card data, no real payment
processing, no real network calls to any bank or gateway.

## How to Run

1. Install Flask (one-time):
   pip install flask

2. Run the app:
   python3 app.py

3. Open your browser to:
   http://127.0.0.1:5000

## What You'll See

1. Register with fake test data (pre-filled for convenience)
2. Browse two sample products, choose whether the checkout page
   is "secure" (HTTPS) or "insecure" (HTTP) to see RS2C activate
3. Click "Buy Now" and watch all five objectives execute live,
   each step showing its actual output and timing in milliseconds
4. See the full pipeline complete with a total time measurement

## Structure

- app.py              - Flask backend with all 5 objectives implemented
- templates/register.html  - Registration page
- templates/shop.html      - Product selection + security toggle
- templates/result.html    - Live transaction breakdown

## For Your Viva

This demonstrates that the mechanisms described in your paper are
genuinely implementable and fast (sub-millisecond for this toy-scale
demo). It is NOT production/PCI-DSS-ready code - see the "Can I run
this in a real e-commerce website" discussion for what would be
needed for actual deployment.
