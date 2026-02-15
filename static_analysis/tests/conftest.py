import sys
import os
import pytest

@pytest.fixture(scope="session", autouse=True)
def add_src_to_path():
    # Add ../src to sys.path relative to tests/conftest.py
    src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../src"))
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
