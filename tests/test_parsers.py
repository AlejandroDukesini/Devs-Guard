import pytest
from dep_guard.parsers import parse_requirements_txt, parse_package_json

def test_parse_requirements_txt():
    content = """
    # Comentario de prueba
    requests==2.28.1
    flask>=2.0.0
    urllib3!=1.25.0
    """
    results = parse_requirements_txt(content)
    
    assert len(results) == 3
    assert results[0] == {"name": "requests", "version": "2.28.1", "ecosystem": "PyPI"}
    assert results[1] == {"name": "flask", "version": "2.0.0", "ecosystem": "PyPI"}
    assert results[2] == {"name": "urllib3", "version": "1.25.0", "ecosystem": "PyPI"}

def test_parse_package_json():
    content = """
    {
      "name": "sample-project",
      "dependencies": {
        "express": "^4.18.2",
        "lodash": "~4.17.21"
      },
      "devDependencies": {
        "jest": "29.5.0"
      }
    }
    """
    results = parse_package_json(content)
    
    assert len(results) == 3
    assert {"name": "express", "version": "4.18.2", "ecosystem": "npm"} in results
    assert {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"} in results
    assert {"name": "jest", "version": "29.5.0", "ecosystem": "npm"} in results