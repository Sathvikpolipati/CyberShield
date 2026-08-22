import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import main

if __name__ == "__main__":
    sys.argv = [sys.argv[0], "--ui", "terminal"]
    main()
