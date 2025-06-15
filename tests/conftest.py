"""Shared pytest fixtures and configuration."""
import os
import tempfile
import shutil
from pathlib import Path
from typing import Generator, Dict, Any
import pytest
import json


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for testing."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path)


@pytest.fixture
def mock_env_vars(monkeypatch) -> Dict[str, str]:
    """Mock environment variables for testing."""
    env_vars = {
        "TEST_API_KEY": "test-api-key-123",
        "TEST_MODE": "true"
    }
    
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)
    
    return env_vars


@pytest.fixture
def sample_api_key() -> str:
    """Provide a sample API key for testing."""
    return "AIzaSyDummyTestKey123456789"


@pytest.fixture
def sample_api_response() -> Dict[str, Any]:
    """Provide sample API response data."""
    return {
        "status": "OK",
        "results": [
            {
                "place_id": "ChIJN1t_tDeuEmsRUsoyG83frY4",
                "formatted_address": "123 Test St, Test City, TC 12345",
                "geometry": {
                    "location": {
                        "lat": -33.8688197,
                        "lng": 151.2092955
                    }
                }
            }
        ]
    }


@pytest.fixture
def mock_config_file(temp_dir: Path) -> Path:
    """Create a mock configuration file."""
    config_path = temp_dir / "config.json"
    config_data = {
        "api_endpoints": {
            "maps": "https://maps.googleapis.com/maps/api",
            "places": "https://places.googleapis.com/v1/places"
        },
        "timeout": 30,
        "retries": 3
    }
    
    with open(config_path, 'w') as f:
        json.dump(config_data, f)
    
    return config_path


@pytest.fixture
def mock_requests_response(mocker):
    """Mock requests library response."""
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "OK"}
    mock_response.text = '{"status": "OK"}'
    mock_response.headers = {"content-type": "application/json"}
    
    return mock_response


@pytest.fixture(autouse=True)
def reset_warnings():
    """Reset warnings before each test."""
    import warnings
    warnings.resetwarnings()


@pytest.fixture
def capture_stdout(monkeypatch):
    """Capture stdout for testing print statements."""
    import io
    import sys
    
    captured_output = io.StringIO()
    monkeypatch.setattr(sys, 'stdout', captured_output)
    
    yield captured_output
    
    captured_output.close()


@pytest.fixture
def api_test_data() -> Dict[str, Any]:
    """Provide comprehensive test data for API testing."""
    return {
        "valid_apis": [
            "staticmap",
            "streetview",
            "embed",
            "directions",
            "geocode",
            "distancematrix",
            "elevation",
            "places",
            "nearbysearch",
            "textsearch",
            "placesdetails",
            "timezone"
        ],
        "error_responses": {
            "REQUEST_DENIED": {"status": "REQUEST_DENIED", "error_message": "API key invalid"},
            "OVER_QUERY_LIMIT": {"status": "OVER_QUERY_LIMIT", "error_message": "Quota exceeded"},
            "ZERO_RESULTS": {"status": "ZERO_RESULTS", "results": []}
        }
    }


@pytest.fixture(scope="session")
def test_resources_dir() -> Path:
    """Path to test resources directory."""
    resources_dir = Path(__file__).parent / "resources"
    resources_dir.mkdir(exist_ok=True)
    return resources_dir


def pytest_configure(config):
    """Configure pytest with custom settings."""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )