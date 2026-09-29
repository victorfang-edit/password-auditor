"""Why password *storage* needs a slow, salted hash: measure the cost of one hash on this machine.
OWASP recommends PBKDF2-SHA256 with 600,000 iterations or scrypt/Argon2; fast hashes like SHA-256 are for files, not passwords."""
import hashlib
import os
import time

import matplotlib.pyplot as plt

salt, pw = os.urandom(16), b"correct horse battery staple"
algos = {
    "MD5 (never)": lambda: hashlib.md5(pw).digest(),
    "SHA-256 (fast, unsalted)": lambda: hashlib.sha256(pw).digest(),
    "PBKDF2-SHA256 100k": lambda: hashlib.pbkdf2_hmac("sha256", pw, salt, 100_000),
    "PBKDF2-SHA256 600k (OWASP)": lambda: hashlib.pbkdf2_hmac("sha256", pw, salt, 600_000),
    "scrypt n=2^15 (OWASP)": lambda: hashlib.scrypt(pw, salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024),
}
per_hash = {}
for name, fn in algos.items():
    reps, start = 0, time.perf_counter()
    while time.perf_counter() - start < 1.0:
        fn(); reps += 1
    per_hash[name] = (time.perf_counter() - start) / reps
    print(f"{name:30s} {per_hash[name] * 1000:12.4f} ms per hash   ({1 / per_hash[name]:>12,.0f} per second)")

fig, ax = plt.subplots(figsize=(9, 4.2))
names = list(per_hash)
bars = ax.barh(names, [per_hash[n] * 1000 for n in names], color=["#e76f51", "#e76f51", "#e9c46a", "#2a9d8f", "#2a9d8f"])
ax.bar_label(bars, labels=[f"{per_hash[n] * 1000:.4f} ms" if per_hash[n] < 0.001 else f"{per_hash[n] * 1000:.0f} ms" for n in names], padding=4)
ax.set_xscale("log")
ax.set(title="Cost of one password hash on a laptop (log scale)\nSlow is good here: it barely affects a real login but multiplies an attacker's cost",
       xlabel="Milliseconds per hash")
ax.invert_yaxis()
fig.tight_layout(); fig.savefig("docs/storage-cost.png", dpi=110)
