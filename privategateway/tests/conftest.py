import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
GATEWAY_ROOT = PROJECT_ROOT / "privategateway"
for path in (PROJECT_ROOT, GATEWAY_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
