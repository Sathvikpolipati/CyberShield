import os

TARGET_DIRS = [
    r"C:\Users\SATHVIK\CyberShield",
    r"C:\Users\SATHVIK\.gemini\antigravity\scratch\CyberShield"
]

def write_in_all(rel, content):
    for base in TARGET_DIRS:
        fp = os.path.join(base, rel)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Updated {fp}")
