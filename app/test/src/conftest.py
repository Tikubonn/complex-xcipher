
import pytest

def pytest_addoption (parser):
  parser.addoption("--executable", action="store", help="Path of executable.")

@pytest.fixture
def executable (request):
  return request.config.getoption("--executable")
