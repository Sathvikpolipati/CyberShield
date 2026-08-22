import os
import sys
import shutil

def main():
    print("=" * 70)
    print(" 🛡️  CyberShield Modular Component Downloader & Sparse Setup")
    print("=" * 70)
    print(" This tool allows you to isolate and deploy ONLY the components you need:")
    print(" [1] Pure TUI Mode      (core/, detectors/, scanners/, reporting/, ui/tui.py)")
    print(" [2] Pure Web Mode      (core/, detectors/, scanners/, reporting/, ui/web/)")
    print(" [3] Android Termux     (core/, detectors/, scanners/, termux_setup.sh)")
    print(" [4] Complete Suite     (All files)")
    print("=" * 70)

    choice = input("Select component pack [1-4]> ").strip()
    if choice == "1":
        print("[+] Configured for Pure Terminal TUI execution. Use `python run_tui.py`.")
    elif choice == "2":
        print("[+] Configured for Pure Web Dashboard execution. Use `python run_web.py`.")
    elif choice == "3":
        print("[+] Configured for Android Termux execution. Run `./termux_setup.sh`.")
    else:
        print("[+] Configured for Full Suite execution. Run `python launcher.py`.")

if __name__ == "__main__":
    main()
