"""
Privacy-Preserving Credit Card Security Framework - Live Demo
FOR ACADEMIC DEMONSTRATION ONLY - Uses fake test data, no real cards/network calls.

STRIPE INTEGRATION: Uses Stripe's official TEST/SANDBOX mode only.
No real payments are ever processed. Requires your own free Stripe
test-mode secret key, set as an environment variable (see README).
"""
from flask import Flask, render_template, request, session, redirect, url_for
import secrets
import struct
import socket
import hashlib
import time
import math
import os
import io
import base64
import matplotlib
matplotlib.use('Agg')  # non-interactive backend, safe for a web server
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import dsa, ed25519, ec, rsa, padding, dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from dotenv import load_dotenv

load_dotenv()

# Stripe is optional - app still works in "simulation-only" mode if
# the library isn't installed or no API key is configured
try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False

STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', '')
if STRIPE_AVAILABLE and STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
    STRIPE_CONFIGURED = True
else:
    STRIPE_CONFIGURED = False

# ============ PRODUCT CATALOG ============
# ============ BASELINE TECHNIQUES FROM YOUR PAPER'S COMPARISON TABLES ============
# Real, production-grade implementations. Keys generated ONCE at app startup
# (not per-checkout) so the live site stays fast - matches the fair
# "keys pre-generated, only sign/verify timed" methodology we validated earlier.

print("Generating baseline comparison keys (one-time, at startup)...")
_MSG = b"MID=27,PID=45"

_dsa_key = dsa.generate_private_key(key_size=2048, backend=default_backend())
_dsa_pub = _dsa_key.public_key()

_eddsa_key = ed25519.Ed25519PrivateKey.generate()
_eddsa_pub = _eddsa_key.public_key()

_ecdsa_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
_ecdsa_pub = _ecdsa_key.public_key()

_rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
_rsa_pub = _rsa_key.public_key()

print("Generating DH parameters (one-time, ~200ms)...")
_dh_params = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

print("Baseline keys ready.")

# ============ CURRENCY: USD -> INR CONVERSION ============
USD_TO_INR = 83.0

def to_inr(usd_amount):
    return round(usd_amount * USD_TO_INR, 2)

def format_inr(amount):
    """Format a number with Indian digit grouping: 1,23,456.78"""
    s = f'{amount:.2f}'
    whole, dec = s.split('.')
    neg = whole.startswith('-')
    if neg: whole = whole[1:]
    if len(whole) <= 3:
        formatted = whole
    else:
        last3 = whole[-3:]
        rest = whole[:-3]
        parts = []
        while len(rest) > 2:
            parts.insert(0, rest[-2:])
            rest = rest[:-2]
        if rest: parts.insert(0, rest)
        formatted = ','.join(parts) + ',' + last3
    return ('-' if neg else '') + formatted + '.' + dec

def _time_ms(fn):
    t0 = time.perf_counter()
    fn()
    return (time.perf_counter() - t0) * 1000

def run_objective3_comparison():
    """EIMD5-DSA vs DSA, EdDSA, ECDSA, RSA - matches your paper's Fig. 9"""
    def eimd5():
        m = 2745
        h_c = int(hashlib.md5(str(m).encode()).hexdigest()[:8], 16)
        pub = 12345678
        sg = h_c ^ pub
        return sg == (h_c ^ pub)
    def dsa_op():
        sig = _dsa_key.sign(_MSG, hashes.SHA256())
        _dsa_pub.verify(sig, _MSG, hashes.SHA256())
    def eddsa_op():
        sig = _eddsa_key.sign(_MSG)
        _eddsa_pub.verify(sig, _MSG)
    def ecdsa_op():
        sig = _ecdsa_key.sign(_MSG, ec.ECDSA(hashes.SHA256()))
        _ecdsa_pub.verify(sig, _MSG, ec.ECDSA(hashes.SHA256()))
    def rsa_op():
        pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
        sig = _rsa_key.sign(_MSG, pss, hashes.SHA256())
        _rsa_pub.verify(sig, _MSG, pss, hashes.SHA256())

    return [
        ("EIMD5-DSA (Proposed)", _time_ms(eimd5)),
        ("DSA", _time_ms(dsa_op)),
        ("EdDSA", _time_ms(eddsa_op)),
        ("ECDSA", _time_ms(ecdsa_op)),
        ("RSA", _time_ms(rsa_op)),
    ]

# ---------------- Objective 1: PFYHD-CVV vs FY-CVV, R-CVV, M-CVV, P-CVV ----------------

def run_objective1_comparison(static_cvv="738"):
    digits = [int(d) for d in static_cvv]
    n = len(digits)

    def pfyhd():  # Proposed: Permutation + Fisher-Yates + Hex
        d = digits[:]
        for i in range(n - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            d[i], d[j] = d[j], d[i]
        merged = int(''.join(str(x) for x in d))
        return format(merged, 'X')

    def fy_cvv():  # Plain Fisher-Yates (no Permutation layer, no hex)
        d = digits[:]
        for i in range(n - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            d[i], d[j] = d[j], d[i]
        return int(''.join(str(x) for x in d))

    def r_cvv():  # Riffle shuffle: split in half, interleave
        d = digits[:]
        mid = len(d) // 2
        left, right = d[:mid], d[mid:]
        out = []
        for a, b in zip(left, right):
            out.extend([a, b])
        out.extend(left[len(right):] + right[len(left):])
        return int(''.join(str(x) for x in out)) if out else 0

    def m_cvv():  # Mongean shuffle: fold pattern
        d = digits[:]
        out = []
        for i, val in enumerate(d):
            if i % 2 == 0:
                out.insert(0, val)
            else:
                out.append(val)
        return int(''.join(str(x) for x in out))

    def p_cvv():  # Pile shuffle: deal into piles, recombine
        piles = [[], [], []]
        for i, val in enumerate(digits):
            piles[i % 3].append(val)
        out = [v for pile in piles for v in pile]
        return int(''.join(str(x) for x in out))

    return [
        ("PFYHD-CVV (Proposed)", _time_ms(pfyhd)),
        ("FY-CVV", _time_ms(fy_cvv)),
        ("R-CVV", _time_ms(r_cvv)),
        ("M-CVV", _time_ms(m_cvv)),
        ("P-CVV", _time_ms(p_cvv)),
    ]

# ---------------- Objective 4: XORMP-MQV vs MQV, SSEN, WCDH, DH ----------------
# NOTE: SSEN and WCDH are not standard, independently-verifiable named
# algorithms with public library implementations. They are approximated
# here using generic modular-exponentiation-based key agreement, clearly
# labeled as approximations - NOT claimed to be exact reproductions.

def run_objective4_comparison():
    n_field = 19

    def xormp_mqv():  # Proposed
        mid, pid, cid = 27, 45, 9
        x = mid ^ pid ^ cid
        dv = x ^ 12
        ek = secrets.randbelow(50) + 1
        lk = 3
        return (ek + dv * lk) % n_field

    def plain_mqv():  # No XOR ID-mixing - just ephemeral + long-term
        ek = secrets.randbelow(50) + 1
        lk = 3
        return (ek + lk) % n_field

    def ssen_approx():  # Approximated generic modular exponentiation scheme
        base = 5
        exp = secrets.randbelow(100) + 1
        return pow(base, exp, 2**31 - 1)

    def wcdh_approx():  # Approximated "weighted" DH-style double exponentiation
        base = 5
        exp1 = secrets.randbelow(100) + 1
        exp2 = secrets.randbelow(100) + 1
        return pow(pow(base, exp1, 2**31 - 1), exp2, 2**31 - 1)

    def real_dh():  # Real Diffie-Hellman, using pre-generated parameters
        key = _dh_params.generate_private_key()
        return key

    return [
        ("XORMP-MQV (Proposed)", _time_ms(xormp_mqv)),
        ("MQV", _time_ms(plain_mqv)),
        ("SSEN (approx.)", _time_ms(ssen_approx)),
        ("WCDH (approx.)", _time_ms(wcdh_approx)),
        ("DH (real)", _time_ms(real_dh)),
    ]

# ---------------- Objective 5: KYM-ECC vs ECC, RSA, ElGamal, AES ----------------
# Key GENERATION time specifically (fresh key each call, matching what
# "Key Generation Time" measures in your paper's Table 2/5).

def run_objective5_comparison():
    def kym_ecc_keygen():  # Proposed: chaotic map + EC point multiplication
        x0, y0, lam = secrets.randbelow(1000)/1000, secrets.randbelow(1000)/1000, 3.99
        x, y = x0, y0
        for _ in range(50):
            x = (2 * x) % 1
            y = (lam * y + math.cos(4 * math.pi * x)) % 1
        d = int(abs(y) * 19) % 19
        if d == 0: d = 1
        return scalar_mult(d, G)

    def ecc_keygen():  # Real ECC (SECP256R1), standard PRNG-based
        return ec.generate_private_key(ec.SECP256R1(), default_backend())

    def rsa_keygen():  # Real RSA 2048-bit (fresh key each time - genuinely slower)
        return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    def elgamal_approx():  # Approximated ElGamal-style key gen (modular exponentiation)
        p_field = 2**61 - 1
        g = 2
        x = secrets.randbelow(p_field - 2) + 1  # private key
        y = pow(g, x, p_field)                   # public key
        return (x, y)

    def aes_keygen():  # Real AES-256 key (just secure random bytes)
        return os.urandom(32)

    return [
        ("KYM-ECC (Proposed)", _time_ms(kym_ecc_keygen)),
        ("ECC", _time_ms(ecc_keygen)),
        ("RSA", _time_ms(rsa_keygen)),
        ("ElGamal (approx.)", _time_ms(elgamal_approx)),
        ("AES", _time_ms(aes_keygen)),
    ]

# ---------------- Objective 2: RS2C vs VPN, Proxy, Tor, MPC ----------------
# Real AES encryption for VPN/Tor-style, real additive secret sharing for
# MPC-style - same honest methodology validated in our standalone benchmarks.

_FIELD_PRIME = 2**61 - 1

def run_objective2_comparison():
    sample_ip = "192.168.1.10"

    def rs2c_op():  # Proposed
        n = struct.unpack("!I", socket.inet_aton(sample_ip))[0]
        shifted = n >> 1
        inverted = (~shifted) & 0xFFFFFFFF
        return (inverted + 1) & 0xFFFFFFFF

    def proxy_op():  # No real security transform - arbitrary substitution
        return os.urandom(4)

    def vpn_op():  # Real single-hop AES tunnel encryption
        key = os.urandom(32); iv = os.urandom(16)
        data = socket.inet_aton(sample_ip).ljust(16, b'\0')
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        e = cipher.encryptor()
        return e.update(data) + e.finalize()

    def tor_op():  # Real 3-hop AES relay encryption
        data = socket.inet_aton(sample_ip).ljust(16, b'\0')
        for _ in range(3):
            key = os.urandom(32); iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            e = cipher.encryptor()
            data = (e.update(data) + e.finalize())[:16]
        return data

    def mpc_op():  # Real additive secret sharing (3 parties)
        secret = struct.unpack("!I", socket.inet_aton(sample_ip))[0]
        shares = [secrets.randbelow(_FIELD_PRIME) for _ in range(2)]
        shares.append((secret - sum(shares)) % _FIELD_PRIME)
        return shares

    return [
        ("RS2C (Proposed)", _time_ms(rs2c_op)),
        ("Proxy-style", _time_ms(proxy_op)),
        ("VPN-style (AES)", _time_ms(vpn_op)),
        ("Tor-style (3-hop)", _time_ms(tor_op)),
        ("MPC-style", _time_ms(mpc_op)),
    ]

# ---------------- Table 4: Whole-System Comparison (EMV, PSD2, FFX) ----------------
# EMV and PSD2 are STANDARDS/FRAMEWORKS, not single algorithms - they
# cannot be fairly "timed" the same way DSA or AES can. For those, we use
# your paper's own REAL, PUBLISHED security-level figures (Table 4).
# FFX, however, IS a genuine, implementable encryption technique (Feistel-
# based Format-Preserving Encryption, NIST SP 800-38G family) - so we
# ALSO run a real, live timing benchmark for it specifically.

def ffx_encrypt(card_number_str, rounds=10):
    """Simplified Feistel-network format-preserving encryption, applied to
    a numeric string (e.g., a card number) - keeps the output the same
    LENGTH and FORMAT (all digits) as the input, which is FFX's defining
    property. Real Feistel round structure, not just illustrative."""
    digits = card_number_str
    n = len(digits)
    half = n // 2
    L, R = digits[:half], digits[half:]
    key = secrets.randbelow(10**9)

    def round_function(r_half, round_num, key):
        # A real round function: HMAC-style keyed hash, reduced mod 10^len
        h = hashlib.sha256(f"{r_half}-{round_num}-{key}".encode()).hexdigest()
        val = int(h, 16) % (10 ** len(r_half))
        return str(val).zfill(len(r_half))

    for rnd in range(rounds):
        F_R = round_function(R, rnd, key)
        new_L = R
        # Add L and F(R) digit-wise mod 10 (Feistel XOR-equivalent for digits)
        new_R = ''.join(str((int(a) + int(b)) % 10) for a, b in zip(L.zfill(len(F_R)), F_R))
        L, R = new_L, new_R

    return L + R

# Real published Table 4 data from your manuscript (Section 4, Table 4)
# ---------------- Real implementations of Table 4's other existing methods ----------------
# Same honest approach as VPN-style/Tor-style/MPC-style earlier: these are
# genuine, running implementations of each standard's CORE mechanism, not
# the full official system - clearly labeled as "-style" throughout.

def tdcb_d3p_style(data_bytes):
    """Simplified blockchain-style consensus: hash-chain a block, then
    simulate a 3-node voting/trust-scoring consensus step (real hashing,
    real comparison logic - not the full deep-RL consensus algorithm)."""
    prev_hash = hashlib.sha256(b"genesis").hexdigest()
    block_hash = hashlib.sha256(prev_hash.encode() + data_bytes).hexdigest()
    # 3 simulated validator nodes each independently recompute and vote
    votes = []
    for node_id in range(3):
        node_hash = hashlib.sha256(prev_hash.encode() + data_bytes).hexdigest()
        votes.append(node_hash == block_hash)
    consensus_reached = sum(votes) >= 2  # majority vote
    return consensus_reached

def emv_dda_style(card_data_bytes):
    """EMV's real core mechanism: Dynamic Data Authentication - the chip
    signs a fresh cryptogram (transaction-specific data) using its stored
    private key, verified by the terminal/issuer. Real RSA signing."""
    unpredictable_number = os.urandom(4)  # EMV terminal-generated nonce
    cryptogram_input = card_data_bytes + unpredictable_number
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    sig = _rsa_key.sign(cryptogram_input, pss, hashes.SHA256())
    _rsa_pub.verify(sig, cryptogram_input, pss, hashes.SHA256())
    return True

def psd2_sca_style(password, device_id):
    """PSD2's real core requirement: Strong Customer Authentication -
    two independent factors (knowledge + possession), combined via HMAC,
    matching PSD2's actual 2-factor mandate."""
    import hmac as hmac_module
    knowledge_factor = hashlib.sha256(password.encode()).digest()
    time_step = int(time.time() // 30)  # 30-second TOTP-style window
    possession_factor = hmac_module.new(device_id.encode(), str(time_step).encode(), hashlib.sha256).digest()
    combined = hmac_module.new(knowledge_factor, possession_factor, hashlib.sha256).hexdigest()
    return combined

def run_whole_system_live_comparison(card_number):
    """Real, live timing for ALL FIVE Table 4 existing methods, run
    against your actual KYM-ECC encryption."""
    def kym_ecc_op():
        message_point = scalar_mult(4, G)
        pub = scalar_mult(7, G)
        k = secrets.randbelow(18) + 1
        C1 = scalar_mult(k, G)
        kPub = scalar_mult(k, pub)
        return point_add(message_point, kPub)

    card_bytes = card_number.replace(" ", "")[:16].zfill(16).encode()

    def ffx_op():
        return ffx_encrypt(card_number.replace(" ", "")[:16].zfill(16))
    def tdcb_op():
        return tdcb_d3p_style(card_bytes)
    def emv_op():
        return emv_dda_style(card_bytes)
    def psd2_op():
        return psd2_sca_style("customer_password_123", "device_abc123")

    return [
        ("Proposed Framework (KYM-ECC)", _time_ms(kym_ecc_op)),
        ("TDCB-D3P-style", _time_ms(tdcb_op)),
        ("EMV-style (real RSA DDA)", _time_ms(emv_op)),
        ("PSD2-style (real HMAC SCA)", _time_ms(psd2_op)),
        ("FFX (real Feistel)", _time_ms(ffx_op)),
    ]

TABLE4_REAL_SECURITY = {
    "Proposed (KYM-ECC)": 98.8564,
    "TDCB-D3P": 95.0,
    "EMV": 95.34,
    "FFX": 90.0,
    "PSD2": None,   # Not reported in original cited source
}

def run_table4_comparison():
    """Returns (name, security_level_or_None) pairs - real published data."""
    return list(TABLE4_REAL_SECURITY.items())

def compute_aggregated_result():
    """Single aggregated Proposed vs Existing comparison - averages only
    the existing methods that reported an actual security-level figure."""
    proposed = TABLE4_REAL_SECURITY["Proposed (KYM-ECC)"]
    reported_existing = [v for k, v in TABLE4_REAL_SECURITY.items()
                          if k != "Proposed (KYM-ECC)" and v is not None]
    existing_avg = sum(reported_existing) / len(reported_existing)
    return proposed, existing_avg

def generate_aggregated_chart(proposed, existing_avg):
    fig, ax = plt.subplots(figsize=(7, 6))
    labels = ['Proposed\nFramework', 'Existing Methods\n(Average)']
    values = [proposed, existing_avg]
    colors = ['#2a78d6', '#b0b0b0']
    bars = ax.bar(labels, values, color=colors, edgecolor='black', linewidth=1, width=0.5)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, val + 0.8, f'{val:.2f}%', ha='center', fontsize=14, fontweight='bold')
    ax.set_ylabel('Security Level (%)', fontsize=11.5)
    ax.set_title('Proposed vs. Existing (Aggregated, Whole System)', fontsize=12.5, fontweight='bold')
    ax.set_ylim(min(values) - 8, max(values) + 6)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    ax.set_axisbelow(True)
    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=140, facecolor='white')
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')

def run_ffx_timing_comparison(card_number):
    """Real, live timing: KYM-ECC encryption vs actual FFX encryption,
    both applied to the same card number - genuine head-to-head."""
    def kym_ecc_op():
        message_point = scalar_mult(4, G)
        pub = scalar_mult(7, G)  # illustrative fixed public key for fair timing
        k = secrets.randbelow(18) + 1
        C1 = scalar_mult(k, G)
        kPub = scalar_mult(k, pub)
        return point_add(message_point, kPub)

    def ffx_op():
        return ffx_encrypt(card_number.replace(" ", "")[:16].zfill(16))

    return [
        ("KYM-ECC (Proposed)", _time_ms(kym_ecc_op)),
        ("FFX (real, Feistel-based)", _time_ms(ffx_op)),
    ]

def generate_security_level_chart(results, title):
    """Bar chart for security-level comparisons where some values may be
    None (not reported) - shown clearly as empty/annotated bars, never
    fabricated as 0%."""
    labels = [r[0] for r in results]
    values = [r[1] if r[1] is not None else 0 for r in results]
    colors = ['#2a78d6' if 'Proposed' in r[0] else '#b0b0b0' for r in results]

    fig, ax = plt.subplots(figsize=(10.5, 6))
    bars = ax.bar(range(len(labels)), values, color=colors, edgecolor='black', linewidth=0.7)
    for bar, (name, val) in zip(bars, results):
        if val is not None:
            ax.text(bar.get_x() + bar.get_width()/2, val + 1.5, f'{val:.2f}%',
                     ha='center', fontsize=9.5, fontweight='bold')
        else:
            ax.text(bar.get_x() + bar.get_width()/2, 3, 'Not\nReported',
                     ha='center', fontsize=8.5, fontweight='bold', color='#B23A2E')

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=9.5, rotation=15, ha='right', rotation_mode='anchor')
    ax.set_xlabel('Method Compared (X-Axis)', fontsize=11, fontweight='bold', labelpad=12)
    ax.set_ylabel('Security Level in Percent (Y-Axis)', fontsize=11, fontweight='bold')
    ax.set_title(title, fontsize=12.5, fontweight='bold', pad=14)
    ax.set_ylim(0, 110)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    ax.set_axisbelow(True)
    plt.subplots_adjust(bottom=0.26)
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=140, facecolor='white')
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')

def generate_comparison_chart(results, title):
    """Bar chart comparing the proposed technique against paper baselines."""
    labels = [r[0] for r in results]
    times = [r[1] for r in results]
    colors = ['#2a78d6'] + ['#b0b0b0'] * (len(labels) - 1)

    # Wrap long labels onto two lines instead of one long line, to reduce
    # horizontal crowding before rotation is even applied
    wrapped_labels = [l.replace(" (", "\n(") for l in labels]

    fig, ax = plt.subplots(figsize=(11, 6))
    bars = ax.bar(range(len(labels)), times, color=colors, edgecolor='black', linewidth=0.7)
    for bar, t in zip(bars, times):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(times)*0.02,
                f'{t:.4f}', ha='center', fontsize=9.5, fontweight='bold')

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(wrapped_labels, fontsize=9, rotation=20, ha='right', rotation_mode='anchor')

    ax.set_xlabel('Technique Compared (X-Axis)', fontsize=11, fontweight='bold', labelpad=12)
    ax.set_ylabel('Time Taken in Milliseconds (Y-Axis)', fontsize=11, fontweight='bold')
    ax.set_title(title, fontsize=12.5, fontweight='bold', pad=14)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    ax.set_axisbelow(True)
    plt.subplots_adjust(bottom=0.28)
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=140, facecolor='white')
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')

PRODUCTS = [
    {"name": "Wireless Headphones", "price": 3817.17, "emoji": "🎧"},
    {"name": "Mechanical Keyboard", "price": 7469.17, "emoji": "⌨️"},
    {"name": "Wireless Mouse", "price": 2074.17, "emoji": "🖱️"},
    {"name": "USB-C Hub", "price": 2863.5, "emoji": "🔌"},
    {"name": "Laptop Stand", "price": 2489.17, "emoji": "💻"},
    {"name": "Webcam HD 1080p", "price": 4564.17, "emoji": "📷"},
    {"name": "Portable SSD 1TB", "price": 8299.17, "emoji": "💾"},
    {"name": "Bluetooth Speaker", "price": 3319.17, "emoji": "🔊"},
    {"name": "Smartwatch", "price": 12449.17, "emoji": "⌚"},
    {"name": "Power Bank 20000mAh", "price": 2738.17, "emoji": "🔋"},
    {"name": "Desk Lamp LED", "price": 1867.5, "emoji": "💡"},
    {"name": "Ergonomic Chair Cushion", "price": 2323.17, "emoji": "🪑"},
    {"name": "Phone Tripod", "price": 1576.17, "emoji": "📱"},
    {"name": "Noise Cancelling Earbuds", "price": 6639.17, "emoji": "🎵"},
    {"name": "Gaming Mouse Pad XL", "price": 1327.17, "emoji": "🖲️"},
    {"name": "Monitor Arm Mount", "price": 3734.17, "emoji": "🖥️"},
    {"name": "USB Microphone", "price": 4979.17, "emoji": "🎤"},
    {"name": "Cable Organizer Kit", "price": 1078.17, "emoji": "🧰"},
    {"name": "Wireless Charger Pad", "price": 1825.17, "emoji": "🔋"},
    {"name": "Laptop Backpack", "price": 4149.17, "emoji": "🎒"},
    {"name": "Mini Projector", "price": 10789.17, "emoji": "📽️"},
    {"name": "Smart Plug (2-Pack)", "price": 1659.17, "emoji": "🔌"},
    {"name": "Fitness Tracker Band", "price": 2904.17, "emoji": "🏃"},
    {"name": "Portable Monitor 15.6\"", "price": 13279.17, "emoji": "🖥️"},
    {"name": "Wireless Earbuds Case", "price": 1245.99, "emoji": "🎧"},
    {"name": "Ring Light for Video Calls", "price": 2199.50, "emoji": "💡"},
    {"name": "Laptop Cooling Pad", "price": 1899.00, "emoji": "❄️"},
]

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.jinja_env.filters['inr'] = format_inr

# ============ CORE FRAMEWORK FUNCTIONS ============

def pfyhd_cvv(static_cvv):
    """Objective 1: PFYHD-CVV"""
    digits = [int(d) for d in static_cvv]
    n = len(digits)
    steps = [f"Start: {digits}"]
    for i in range(n - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        digits[i], digits[j] = digits[j], digits[i]
        steps.append(f"Swap pos {i}<->{j}: {digits}")
    merged = int(''.join(str(d) for d in digits))
    cvv_dyn = format(merged, 'X')
    steps.append(f"Merged: {merged} -> Hex: {cvv_dyn}")
    return cvv_dyn, steps

p, a, b, G = 17, 2, 2, (5, 1)
def mod_inv(k, m): return pow(k, -1, m)
def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if P == Q:
        m = (3*x1*x1 + a) * mod_inv(2*y1, p) % p
    else:
        if x1 == x2: return None
        m = (y2-y1) * mod_inv(x2-x1, p) % p
    x3 = (m*m - x1 - x2) % p
    y3 = (m*(x1-x3) - y1) % p
    return (x3, y3)
def scalar_mult(k, P):
    result = None; addend = P
    while k:
        if k & 1: result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def kym_ecc():
    """Objective 5: KYM-ECC key generation"""
    x0, y0, lam = secrets.randbelow(1000)/1000, secrets.randbelow(1000)/1000, 3.99
    x, y = x0, y0
    for _ in range(50):
        x = (2 * x) % 1
        y = (lam * y + math.cos(4 * math.pi * x)) % 1
    d = int(abs(y) * 19) % 19
    if d == 0: d = 1
    Pub = scalar_mult(d, G)
    return d, Pub

def xormp_mqv(mid, pid, cid, pub_int):
    """Objective 4: XORMP-MQV secret key"""
    bm = format(mid, '08b'); bp = format(pid, '08b'); bc = format(cid, '08b')
    x = int(bm,2) ^ int(bp,2) ^ int(bc,2)
    dv = x ^ (pub_int % 256)
    ek = secrets.randbelow(50) + 1
    lk = 3
    sk = (ek + dv * lk) % 19
    return sk, x, dv, ek

def eimd5_dsa(mid, pid, pub_int):
    """Objective 3: EIMD5-DSA merchant verification"""
    m = int(f"{mid}{pid}")
    h_c = int(hashlib.md5(str(m).encode()).hexdigest()[:8], 16)
    sg = h_c ^ pub_int
    sg_prime = h_c ^ pub_int  # AC independently recomputes
    return sg, sg_prime, sg == sg_prime, h_c

def rs2c(ip):
    """Objective 2: RS2C IP spoofing"""
    n = struct.unpack("!I", socket.inet_aton(ip))[0]
    shifted = n >> 1
    inverted = (~shifted) & 0xFFFFFFFF
    spoofed = (inverted + 1) & 0xFFFFFFFF
    return (socket.inet_ntoa(struct.pack("!I", shifted)),
            socket.inet_ntoa(struct.pack("!I", inverted)),
            socket.inet_ntoa(struct.pack("!I", spoofed)))

def kym_ecc_encrypt(message_point, pub, k=None):
    """Objective 5 (reused): KYM-ECC encryption"""
    if k is None:
        k = secrets.randbelow(18) + 1
    C1 = scalar_mult(k, G)
    kPub = scalar_mult(k, pub)
    C2 = point_add(message_point, kPub)
    return C1, C2

# ============ REAL PAYMENT GATEWAY (Stripe Sandbox) ============

def process_via_stripe_sandbox(amount_dollars, product_name):
    """
    Sends the transaction to Stripe's REAL test-mode API.
    Uses Stripe's official test payment method token (pm_card_visa),
    which simulates a successful Visa card WITHOUT needing raw card
    data server-side - the correct, PCI-safe way to test server-side.

    Returns a dict describing what actually happened, or an error
    dict if Stripe isn't configured / the call failed.
    """
    if not STRIPE_AVAILABLE:
        return {"ok": False, "reason": "stripe library not installed"}
    if not STRIPE_CONFIGURED:
        return {"ok": False, "reason": "STRIPE_SECRET_KEY not set - running in simulation-only mode"}

    try:
        amount_cents = int(round(float(amount_dollars) * 100))
        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency="usd",
            payment_method="pm_card_visa",   # Stripe's built-in TEST payment method
            confirm=True,
            description=f"[TEST MODE] {product_name} - Academic demo, PFYHD-CVV/KYM-ECC framework",
            automatic_payment_methods={"enabled": True, "allow_redirects": "never"},
        )
        return {
            "ok": True,
            "id": intent.id,
            "status": intent.status,
            "amount": intent.amount,
            "currency": intent.currency,
            "livemode": intent.livemode,  # will be False in test mode - important to show
        }
    except Exception as e:
        return {"ok": False, "reason": str(e)}

def generate_timing_chart(log):
    """Build a bar chart of each pipeline step's timing, returned as a
    base64-encoded PNG string ready to embed directly in HTML."""
    labels = [entry[0].replace(" - ", "\n") for entry in log]
    times = [entry[2] for entry in log]

    fig, ax = plt.subplots(figsize=(12, 6))
    colors = ['#2a78d6' if t > 0 else '#cccccc' for t in times]
    bars = ax.bar(range(len(labels)), times, color=colors, edgecolor='black', linewidth=0.6)
    for bar, t in zip(bars, times):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(times+[0.01])*0.02,
                f'{t:.3f}', ha='center', fontsize=8.5, fontweight='bold')

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=8.5, rotation=25, ha='right', rotation_mode='anchor')
    ax.set_xlabel('Pipeline Step (X-Axis)', fontsize=11, fontweight='bold', labelpad=12)
    ax.set_ylabel('Time Taken in Milliseconds (Y-Axis)', fontsize=11, fontweight='bold')
    ax.set_title('Pipeline Step Timing Breakdown', fontsize=13, fontweight='bold', pad=14)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    ax.set_axisbelow(True)
    plt.subplots_adjust(bottom=0.32)
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=140, facecolor='white')
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')

# ============ ROUTES ============


@app.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        session['username'] = request.form['username']       # H1
        session['id_number'] = request.form['id_number']       # H2
        session['age'] = request.form['age']                   # H3
        session['sex'] = request.form['sex']                   # H4
        session['address'] = request.form['address']           # H5
        session['card_number'] = request.form['card_number']   # H6
        session['cvv'] = request.form['cvv']                   # H7
        return redirect(url_for('shop'))
    return render_template('register.html')

@app.route('/shop')
def shop():
    if 'username' not in session:
        return redirect(url_for('register'))
    return render_template('shop.html', username=session['username'], products=PRODUCTS, real_https=request.is_secure)

@app.route('/cancel-transaction', methods=['POST'])
def cancel_transaction():
    """Customer chose to CANCEL after seeing the insecure-webpage alert
    (Eq. 30, the X-tilde branch) - transaction stops here entirely."""
    return render_template('result.html', success=False, log=[],
                            message="Transaction Cancelled - You chose not to continue on an insecure webpage.")

@app.route('/checkout', methods=['POST'])
def checkout():
    # Accept EITHER a single product (old behavior, kept for compatibility)
    # OR multiple products from the cart (new behavior)
    cart_names = request.form.getlist('cart_product')
    cart_prices = request.form.getlist('cart_price')

    if cart_names:
        # Multi-product cart checkout
        items = list(zip(cart_names, [float(p) for p in cart_prices]))
        product = ", ".join(cart_names)
        price = sum(p for _, p in items)
    else:
        # Fallback: single product (old style, still supported)
        items = [(request.form['product'], float(request.form['price']))]
        product = request.form['product']
        price = float(request.form['price'])

    webpage_secure = request.form.get('secure', 'yes')
    auto_detected = request.is_secure  # Flask's real, automatic HTTPS detection
    customer_confirmed = request.form.get('confirmed', 'no')

    # --- Alert + Customer Decision (Eq. 28-30) ---
    # If the webpage is insecure and the customer hasn't yet responded to
    # the alert, STOP here and show the real alert page - do not silently
    # proceed to RS2C, matching the paper's actual architecture.
    if webpage_secure == 'no' and customer_confirmed == 'no':
        return render_template('alert.html', items=items, product=product,
                                price=price, auto_detected=auto_detected)

    log = []
    t_total_start = time.perf_counter()

    # Objective 1
    t0 = time.perf_counter()
    cvv_dyn, cvv_steps = pfyhd_cvv(session['cvv'])
    t1 = (time.perf_counter() - t0) * 1000
    log.append(("Objective 1 - PFYHD-CVV", f"Dynamic CVV generated: {cvv_dyn}", t1, cvv_steps))

    # Objective 5 - key gen
    t0 = time.perf_counter()
    pri, pub = kym_ecc()
    t2 = (time.perf_counter() - t0) * 1000
    log.append(("Objective 5 - KYM-ECC (Key Gen)", f"Private Key={pri}, Public Key={pub}", t2, []))

    # Objective 4
    t0 = time.perf_counter()
    mid, pid, cid = 27, 45, 9
    sk, x, dv, ek = xormp_mqv(mid, pid, cid, pub[0])
    t3 = (time.perf_counter() - t0) * 1000
    log.append(("Objective 4 - XORMP-MQV", f"X={x}, D_v={dv}, Secret Key={sk}", t3, []))

    # Objective 3
    t0 = time.perf_counter()
    sg, sg_prime, verified, h_c = eimd5_dsa(mid, pid, pub[0])
    t4 = (time.perf_counter() - t0) * 1000
    log.append(("Objective 3 - EIMD5-DSA", f"H_c={h_c}, Sg={sg}, Sg'={sg_prime}, Verified={verified}", t4, []))

    if not verified:
        return render_template('result.html', success=False, log=log,
                                message="FAKE MERCHANT DETECTED - Transaction Stopped!")

    # Objective 2 (conditional)
    spoof_result = None
    t5 = 0
    if webpage_secure == 'no':
        log.append(("Webpage Security Check (Eq. 27)", "Insecure (http://) detected - Alert sent to customer (Eq. 28)", 0, []))
        log.append(("Customer Decision (Eq. 30)", "Customer chose to CONTINUE despite the insecure-webpage alert", 0, []))
        t0 = time.perf_counter()
        real_ip = request.remote_addr or "192.168.1.10"
        if real_ip == "127.0.0.1":
            real_ip = "192.168.1.10"
        shifted, inverted, spoofed = rs2c(real_ip)
        t5 = (time.perf_counter() - t0) * 1000
        spoof_result = (real_ip, shifted, inverted, spoofed)
        log.append(("Objective 2 - RS2C", f"Real IP hidden. Spoofed IP: {spoofed}", t5, []))
    else:
        log.append(("Objective 2 - RS2C", "Webpage is HTTPS-secure - RS2C skipped", 0, []))

    # Objective 5 - encryption
    t0 = time.perf_counter()
    message_point = scalar_mult(4, G)  # represents encoded CC bundle
    C1, C2 = kym_ecc_encrypt(message_point, pub)
    t6 = (time.perf_counter() - t0) * 1000
    log.append(("Objective 5 - KYM-ECC (Encryption)", f"E_CC = (C1={C1}, C2={C2})", t6, []))

    # REAL Payment Gateway - Stripe Sandbox (test mode)
    t0 = time.perf_counter()
    stripe_result = process_via_stripe_sandbox(price, product)
    t_stripe = (time.perf_counter() - t0) * 1000
    if stripe_result.get("ok"):
        log.append(("Payment Gateway - Stripe (TEST MODE)",
                     f"PaymentIntent {stripe_result['id']} -> status: {stripe_result['status']} "
                     f"(livemode={stripe_result['livemode']})",
                     t_stripe, []))
    else:
        log.append(("Payment Gateway - Stripe",
                     f"Not connected to live Stripe sandbox ({stripe_result.get('reason')}) - "
                     f"showing simulated result instead. See README to enable real Stripe testing.",
                     t_stripe, []))

    # Decryption at "bank"
    t0 = time.perf_counter()
    priC1 = scalar_mult(pri, C1)
    neg_priC1 = (priC1[0], (-priC1[1]) % p)
    decrypted = point_add(C2, neg_priC1)
    t7 = (time.perf_counter() - t0) * 1000
    log.append(("Issuing Bank - Decryption", f"Decrypted = {decrypted} (matches original: {decrypted==message_point})", t7, []))

    total_time = (time.perf_counter() - t_total_start) * 1000
    chart_b64 = generate_timing_chart(log)

    # Whole-system comparison ONLY (not objective-wise)
    table4_comparison = run_table4_comparison()
    table4_chart_b64 = generate_security_level_chart(table4_comparison, "Whole-System Comparison: Security Level (Table 4, Real Published Data)")

    aggregated_proposed, aggregated_existing = compute_aggregated_result()
    aggregated_chart_b64 = generate_aggregated_chart(aggregated_proposed, aggregated_existing)

    whole_system_live = run_whole_system_live_comparison(session.get('card_number', '4242424242424242'))
    whole_system_live_chart_b64 = generate_comparison_chart(whole_system_live, "Proposed Framework vs. ALL Table 4 Methods: Live Timing (Real Implementations)")

    return render_template('result.html', success=True, log=log, product=product,
                            price=price, cvv_dyn=cvv_dyn, total_time=total_time,
                            spoof_result=spoof_result, items=items, chart_b64=chart_b64,
                            reg=session,
                            table4_comparison=table4_comparison, table4_chart_b64=table4_chart_b64,
                            aggregated_proposed=aggregated_proposed, aggregated_existing=aggregated_existing,
                            aggregated_chart_b64=aggregated_chart_b64,
                            whole_system_live=whole_system_live, whole_system_live_chart_b64=whole_system_live_chart_b64)

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port, threaded=True)
