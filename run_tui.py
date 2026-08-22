import sys
import os

# Set working directory to project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import main
import sys

if __name__ == "__main__":
    sys.argv = [sys.argv[0], "--ui", "terminal"]
    main()
