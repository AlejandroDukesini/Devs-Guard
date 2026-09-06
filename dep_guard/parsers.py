import json
import re
from typing import List, Dict

def parse_requirements_txt(content: str) -> List[Dict[str, str]]:
    """Extrae paquetes y versiones de un archivo requirements.txt"""
    dependencies = []
    lines = content.splitlines()
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Coincide con formatos como: package==1.2.3 o package>=1.2.3
        match = re.match(r'^([a-zA-Z0-9_\-]+)\s*([<>=!~]+)\s*([0-9a-zA-Z\.]+)', line)
        if match:
            pkg, op, ver = match.groups()
            dependencies.append({"name": pkg, "version": ver, "ecosystem": "PyPI"})
    return dependencies

def parse_package_json(content: str) -> List[Dict[str, str]]:
    """Extrae dependencias directas de un archivo package.json"""
    data = json.loads(content)
    dependencies = []
    
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    for pkg, ver in deps.items():
        # Limpia caracteres comunes de semver (~, ^)
        clean_ver = re.sub(r'[^0-9.]', '', ver)
        if clean_ver:
            dependencies.append({"name": pkg, "version": clean_ver, "ecosystem": "npm"})
            
    return dependencies