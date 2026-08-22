import os
import sys
import subprocess

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def print_banner():
    clear_screen()
    print("\033[1;36m" + "=" * 76 + "\033[0m")
    print("\033[1;32m  🛡️  CYBERSHIELD SOC - MULTI-PLATFORM RUNTIME & DEPLOYMENT SELECTOR\033[0m")
    print("\033[1;33m  Real-Time Network Traffic Analyzer, NIDS & Active Threat Defense System\033[0m")
    print("\033[1;36m" + "=" * 76 + "\033[0m")
    print("  Please select your desired execution mode:")
    print("  \033[1;32m[1]\033[0m \033[1mTerminal TUI SOC Console\033[0m        - Ultra-fast military-grade terminal dashboard")
    print("  \033[1;34m[2]\033[0m \033[1mWeb Browser Dashboard Suite\033[0m     - Full modern Web GUI + REST API + WebSockets")
    print("  \033[1;35m[3]\033[0m \033[1mDual Mode (TUI + Web Server)\033[0m    - Runs live TUI in console + background Web GUI")
    print("  \033[1;33m[4]\033[0m \033[1mAndroid Termux Mobile Shield\033[0m    - Run optimized installer & launcher for Termux")
    print("  \033[1;31m[5]\033[0m \033[1mRun Diagnostic Test Suite\033[0m       - Execute automated pytest security test suite")
    print("  \033[1;37m[6]\033[0m \033[1mExit\033[0m")
    print("\033[1;36m" + "=" * 76 + "\033[0m")

def main():
    while True:
        print_banner()
        try:
            choice = input("\033[1;32mCyberShield-Select [1-6]> \033[0m").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[+] Exiting CyberShield.")
            sys.exit(0)

        if choice == "1":
            print("\n[*] Launching CyberShield Terminal TUI SOC Console...")
            subprocess.run([sys.executable, "main.py", "--ui", "terminal"])
            break
        elif choice == "2":
            print("\n[*] Launching CyberShield Web Browser Dashboard Suite...")
            subprocess.run([sys.executable, "main.py", "--ui", "web"])
            break
        elif choice == "3":
            print("\n[*] Launching CyberShield Dual Mode (TUI + Web Server)...")
            subprocess.run([sys.executable, "main.py", "--ui", "both"])
            break
        elif choice == "4":
            if os.name == "nt":
                print("\n[!] Android Termux setup is designed for Linux/Android environments.")
                print("[*] For Windows, use [1] Terminal TUI or [2] Web Dashboard.")
                input("\nPress Enter to return to menu...")
            else:
                subprocess.run(["bash", "termux_setup.sh"])
                break
        elif choice == "5":
            print("\n[*] Running pytest test suite...")
            subprocess.run([sys.executable, "-m", "pytest", "-v", "tests/"])
            input("\nPress Enter to return to menu...")
        elif choice in ["6", "q", "exit"]:
            print("\n[+] Exiting CyberShield Launcher.")
            sys.exit(0)
        else:
            print("\n[-] Invalid option. Please select 1 through 6.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()
