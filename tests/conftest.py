import sys
from pathlib import Path

# make the ldf package importable when pytest runs from anywhere
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))