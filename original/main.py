"""
Punto de Entrada Principal - Proyecto Criptografía RSA
MM2015 Matemática Discreta 1 · Grupo 13

Inicia la interfaz gráfica moderna desarrollada íntegramente en Python (CustomTkinter).
Ejecutar con:
    python main.py
O para correr las pruebas unitarias:
    python main.py --test
"""

import os
import sys

# Asegurar importaciones relativas limpias independientemente del directorio actual
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def main():
    """Punto de entrada principal: ejecuta las pruebas con `--test` o inicia la GUI."""
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        import unittest
        import test_rsa
        suite = unittest.defaultTestLoader.loadTestsFromModule(test_rsa)
        runner = unittest.TextTestRunner(verbosity=2)
        res = runner.run(suite)
        sys.exit(0 if res.wasSuccessful() else 1)

    # Iniciar la aplicación gráfica 100% Python
    from gui import main as run_gui
    run_gui()


if __name__ == "__main__":
    main()
