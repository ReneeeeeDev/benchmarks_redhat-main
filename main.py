import importlib
import os
import pkgutil
import argparse
from classes.compliance_check import ComplianceCheck

def import_submodules(package, recursive=True):
    """ Importa todos los submódulos de un paquete, opcionalmente de manera recursiva """
    if isinstance(package, str):
        package = importlib.import_module(package)
    results = {}
    for loader, name, is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        if '__init__' not in name:
            results[name] = importlib.import_module(name)
            if recursive and is_pkg:
                results.update(import_submodules(name))
    return results

def main():
    parser = argparse.ArgumentParser(description="Run compliance checks and generate reports.")
    parser.add_argument('--reports', nargs='*', help='Specify which report generators to run (e.g., generate_html_report)')
    args = parser.parse_args()

    # Directorio del paquete 'checks'
    checks_package = 'checks'
    checks = []

    # Importar todos los submódulos recursivamente
    modules = import_submodules(checks_package)

    # Obtener todas las clases de verificación de los módulos importados
    for module_name, module in modules.items():
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, ComplianceCheck) and attr is not ComplianceCheck:
                check_instance = attr()
                checks.append(check_instance)

    # Ordenar los checks por el número
    checks.sort(key=lambda x: x.number)

    # Ejecutar y mostrar los checks
    results = []
    for check in checks:
        result = check.check()
        results.append({
            'TITLE': check.title,
            'NUMBER': check.number,
            'COMMANDS': check.command,
            'PROFILE': check.profile,
            'DESCRIPTION': check.description,
            'PASSED': check.passed
        })
        print(f"Compliance check '{check.title}' ({check.number}) passed: {check.passed}")

    # Directorio del paquete 'reports'
    reports_package = 'reports'

    # Importar todos los submódulos recursivamente
    report_modules = import_submodules(reports_package)

    # Mostrar los módulos encontrados en el paquete 'reports'
    print("Módulos encontrados en el paquete 'reports':")
    for module_name in report_modules.keys():
        print(module_name)

    # Ejecutar todos los generadores de reportes o los especificados
    for module_name, module in report_modules.items():
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if callable(attr) and attr_name.startswith('generate_'):
                report_name = attr_name
                if args.reports:
                    # Si se especificaron reportes, ejecutar solo esos
                    if report_name in args.reports:
                        print(f"Executing report: {report_name}")
                        try:
                            attr(results, output_dir='../generados')
                            print(f"Report {report_name} executed successfully.")
                        except Exception as e:
                            print(f"Error executing report {report_name}: {e}")
                else:
                    # Si no se especificaron reportes, ejecutar todos
                    print(f"Executing report: {report_name}")
                    try:
                        attr(results, output_dir='../generados')
                        print(f"Report {report_name} executed successfully.")
                    except Exception as e:
                        print(f"Error executing report {report_name}: {e}")

if __name__ == '__main__':
    main()
