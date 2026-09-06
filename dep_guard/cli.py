import argparse
import asyncio
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from dep_guard.parsers import parse_requirements_txt, parse_package_json
from dep_guard.scanner import scan_dependencies

console = Console()

def main():
    parser = argparse.ArgumentParser(description="DepGuard - Escáner de Vulnerabilidades de Dependencias OSINT/DevSecOps")
    parser.add_argument("file", help="Ruta al archivo de dependencias (requirements.txt o package.json)")
    args = parser.parse_args()

    file_path = args.file
    if not os.path.exists(file_path):
        console.print(f"[bold red]Error:[/bold red] El archivo '{file_path}' no existe.")
        return

    filename = os.path.basename(file_path)
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Selección de parser según el archivo
    if filename == "requirements.txt":
        deps = parse_requirements_txt(content)
    elif filename == "package.json":
        deps = parse_package_json(content)
    else:
        console.print("[bold red]Error:[/bold red] Formato no soportado. Usa 'requirements.txt' o 'package.json'.")
        return

    console.print(Panel(f"[bold blue]Iniciando escaneo de {len(deps)} dependencias en {filename}...[/bold blue]", title="DepGuard"))

    # Ejecución asíncrona del escáner
    results = asyncio.run(scan_dependencies(deps))

    # Creación de tabla de resultados
    table = Table(title="Reporte de Vulnerabilidades", show_lines=True)
    table.add_column("Paquete", style="cyan", no_wrap=True)
    table.add_column("Versión", style="magenta")
    table.add_column("Ecosistema", style="green")
    table.add_column("Estado / CVEs", style="bold")

    total_vulns = 0

    for res in results:
        vulns = res["vulnerabilities"]
        if vulns:
            total_vulns += len(vulns)
            cve_ids = []
            for v in vulns:
                # Extrae ID de CVE o el ID de OSV si no hay CVE explícito
                cve_id = v.get("id")
                cve_ids.append(cve_id)
            cve_str = ", ".join(cve_ids[:3]) # Mostrar máximo 3 por espacio
            status = f"[bold red]CRÍTICO ({len(vulns)} vulns)[/bold red]\n[dim]{cve_str}[/dim]"
        else:
            status = "[bold green]SEGURO[/bold green]"

        table.add_row(res["name"], res["version"], res["ecosystem"], status)

    console.print(table)
    
    if total_vulns > 0:
        console.print(f"\n[bold red]✖ Escaneo completado: Se encontraron {total_vulns} vulnerabilidades.[/bold red]")
    else:
        console.print("\n[bold green]✔ Escaneo completado: No se encontraron vulnerabilidades conocidas.[/bold green]")

if __name__ == "__main__":
    main()