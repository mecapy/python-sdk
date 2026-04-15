"""
Test runner JSON-driven générique pour les packages MecaPy.

Ce module fournit un runner de tests basé sur des fichiers JSON,
permettant aux experts métier d'écrire des cas de test sans code Python.
"""

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any


class Colors:
    """Codes couleur ANSI pour l'affichage dans le terminal."""

    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"


class TestRunner:
    """
    Exécuteur de tests JSON-driven générique pour les packages MecaPy.

    Charge des fichiers ``test_*.json`` depuis un répertoire et exécute
    les cas de test contre les handlers Python définis dans chaque fichier.

    Parameters
    ----------
    tests_dir : Path
        Répertoire contenant les fichiers de test JSON.

    Examples
    --------
    Utilisation programmatique :

    >>> from pathlib import Path
    >>> from mecapy.testing import TestRunner
    >>> runner = TestRunner(Path("tests"))
    >>> runner.run_all_tests()

    Utilisation en ligne de commande :

    .. code-block:: bash

        mecapy-test tests/
    """

    def __init__(self, tests_dir: Path) -> None:
        self.tests_dir = tests_dir
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.errors: list[dict[str, str]] = []

    def load_test_file(self, test_file: Path) -> dict[str, Any]:
        """
        Charge un fichier de test JSON.

        Parameters
        ----------
        test_file : Path
            Chemin vers le fichier de test.

        Returns
        -------
        dict
            Contenu du fichier de test.
        """
        with open(test_file, encoding="utf-8") as f:
            return json.load(f)  # type: ignore[no-any-return]

    def get_params(self, request: dict[str, Any]) -> tuple[Any, ...]:
        """
        Extrait les paramètres d'une requête sous forme de tuple ordonné.

        Parameters
        ----------
        request : dict
            Paramètres de la requête (clés dans l'ordre de déclaration JSON).

        Returns
        -------
        tuple
            Valeurs du dict ``request`` dans l'ordre de déclaration.
        """
        return tuple(request.values())

    def compare_values(self, actual: Any, expected: Any, tolerance: float) -> bool:
        """
        Compare deux valeurs avec une tolérance numérique.

        Parameters
        ----------
        actual : Any
            Valeur obtenue.
        expected : Any
            Valeur attendue.
        tolerance : float
            Tolérance absolue pour la comparaison numérique.

        Returns
        -------
        bool
            ``True`` si les valeurs correspondent.
        """
        if type(actual) != type(expected):  # noqa: E721
            return False

        if isinstance(actual, bool):
            return actual == expected  # type: ignore[no-any-return]

        if isinstance(actual, (int, float)):
            return abs(actual - expected) <= tolerance

        if isinstance(actual, str):
            return actual == expected  # type: ignore[no-any-return]

        if isinstance(actual, dict):
            if set(actual.keys()) != set(expected.keys()):
                return False
            return all(self.compare_values(actual[k], expected[k], tolerance) for k in expected)

        if isinstance(actual, list):
            if len(actual) != len(expected):
                return False
            return all(self.compare_values(a, e, tolerance) for a, e in zip(actual, expected, strict=False))

        return actual == expected  # type: ignore[no-any-return]

    def check_result(
        self,
        actual: dict[str, Any],
        expected: dict[str, Any],
        tolerance: float,
    ) -> tuple[bool, list[str]]:
        """
        Vérifie que le résultat correspond aux attentes (comparaison partielle).

        Seules les clés présentes dans ``expected`` sont vérifiées.

        Parameters
        ----------
        actual : dict
            Résultat obtenu.
        expected : dict
            Résultat attendu (peut être partiel).
        tolerance : float
            Tolérance pour les comparaisons numériques.

        Returns
        -------
        tuple[bool, list[str]]
            ``(succès, liste des messages d'erreur)``.
        """
        errors: list[str] = []

        def check_nested(path: str, act: Any, exp: Any) -> None:
            if isinstance(exp, dict):
                for key, exp_value in exp.items():
                    full_path = f"{path}.{key}" if path else key
                    if key not in act:
                        errors.append(f"{full_path}: clé manquante dans le résultat")
                        continue
                    check_nested(full_path, act[key], exp_value)
            else:
                if not self.compare_values(act, exp, tolerance):
                    errors.append(f"{path}: attendu {exp} (±{tolerance}), obtenu {act}")

        check_nested("", actual, expected)
        return len(errors) == 0, errors

    def run_test_case(
        self,
        test_case: dict[str, Any],
        handler_method: str,
    ) -> tuple[bool, str]:
        """
        Exécute un cas de test.

        Parameters
        ----------
        test_case : dict
            Cas de test à exécuter.
        handler_method : str
            Référence au handler au format ``"module:fonction"``
            ou ``"module.Classe:methode"``.

        Returns
        -------
        tuple[bool, str]
            ``(succès, message d'erreur si échec)``.
        """
        try:
            params = self.get_params(test_case["request"])

            if ":" in handler_method:
                module_path, method_name = handler_method.rsplit(":", 1)
            else:
                module_path = handler_method.rsplit(".", 1)[0]
                method_name = handler_method.rsplit(".", 1)[-1]

            module_name = module_path.split(".")[0]
            module = importlib.import_module(module_name)

            if not hasattr(module, method_name):
                return False, f"Fonction {method_name} introuvable dans {module_name}"

            func = getattr(module, method_name)
            result = func(*params)

            tolerance = test_case.get("tolerance", {}).get("numeric", 0.1)
            success, errors = self.check_result(result, test_case["expected"], tolerance)

            if not success:
                error_msg = "\n    ".join(errors)
                return False, f"Valeurs incorrectes:\n    {error_msg}"

            return True, ""

        except Exception as e:  # noqa: BLE001
            return False, f"Exception: {e}"

    def run_test_file(self, test_file: Path) -> None:
        """
        Exécute tous les tests d'un fichier JSON.

        Parameters
        ----------
        test_file : Path
            Fichier de test à exécuter.
        """
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.END}")
        print(f"{Colors.BOLD}Test File: {test_file.name}{Colors.END}")
        print(f"{Colors.BLUE}{'=' * 80}{Colors.END}\n")

        test_data = self.load_test_file(test_file)

        print(f"{Colors.BOLD}Handler:{Colors.END} {test_data['handler']}")
        print(f"{Colors.BOLD}Description:{Colors.END} {test_data['description']}\n")

        for test_case in test_data["test_cases"]:
            self.total_tests += 1

            test_name = test_case["name"]
            description = test_case.get("description", "")

            print(f"  {Colors.BOLD}Test:{Colors.END} {test_name}")
            if description:
                print(f"  {Colors.BOLD}Description:{Colors.END} {description}")

            success, error_msg = self.run_test_case(test_case, test_data["handler"])

            if success:
                self.passed_tests += 1
                print(f"  {Colors.GREEN}✓ PASSED{Colors.END}\n")
            else:
                self.failed_tests += 1
                print(f"  {Colors.RED}✗ FAILED{Colors.END}")
                print(f"  {Colors.RED}{error_msg}{Colors.END}\n")
                self.errors.append({"file": test_file.name, "test": test_name, "error": error_msg})

    def run_all_tests(self) -> None:
        """Exécute tous les fichiers ``test_*.json`` du répertoire."""
        test_files = sorted(self.tests_dir.glob("test_*.json"))

        if not test_files:
            print(f"{Colors.RED}Aucun fichier de test trouvé dans {self.tests_dir}{Colors.END}")
            return

        print(f"{Colors.BOLD}{Colors.BLUE}")
        print("╔" + "=" * 78 + "╗")
        print("║" + " TEST RUNNER ".center(78) + "║")
        print("╚" + "=" * 78 + "╝")
        print(f"{Colors.END}")

        for test_file in test_files:
            self.run_test_file(test_file)

        self.print_summary()

    def print_summary(self) -> None:
        """Affiche le résumé final des tests et quitte avec le code approprié."""
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 80}{Colors.END}")
        print(f"{Colors.BOLD}RÉSUMÉ DES TESTS{Colors.END}")
        print(f"{Colors.BLUE}{'=' * 80}{Colors.END}\n")

        print(f"  Total de tests : {self.total_tests}")
        print(f"  {Colors.GREEN}Réussis : {self.passed_tests}{Colors.END}")
        print(f"  {Colors.RED}Échoués : {self.failed_tests}{Colors.END}")

        if self.total_tests > 0:
            success_rate = (self.passed_tests / self.total_tests) * 100
            print(f"\n  Taux de réussite : {success_rate:.1f}%")

        if self.errors:
            print(f"\n{Colors.BOLD}{Colors.RED}DÉTAILS DES ÉCHECS :{Colors.END}\n")
            for i, error in enumerate(self.errors, 1):
                print(f"  {i}. {error['file']} - {error['test']}")
                print(f"     {error['error']}\n")

        print(f"{Colors.BLUE}{'=' * 80}{Colors.END}\n")

        sys.exit(0 if self.failed_tests == 0 else 1)


def main() -> None:
    """
    Point d'entrée CLI du test runner MecaPy.

    Utilisation
    -----------
    .. code-block:: bash

        mecapy-test tests/
        mecapy-test tests/ --sys-path /path/to/module
    """
    parser = argparse.ArgumentParser(
        description="MecaPy JSON Test Runner - Exécute des tests définis en JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  mecapy-test tests/
  mecapy-test tests/ --sys-path /path/to/my/handler
        """,
    )
    parser.add_argument(
        "tests_dir",
        nargs="?",
        default="tests",
        help="Répertoire contenant les fichiers test_*.json (défaut: tests/)",
    )
    parser.add_argument(
        "--sys-path",
        dest="sys_path",
        default=None,
        help="Répertoire à ajouter au sys.path pour l'import des modules testés",
    )
    args = parser.parse_args()

    tests_dir = Path(args.tests_dir)
    if not tests_dir.exists():
        print(f"\033[91mErreur: Répertoire '{tests_dir}' introuvable\033[0m")
        sys.exit(1)

    if args.sys_path:
        sys.path.insert(0, str(Path(args.sys_path).resolve()))
    else:
        sys.path.insert(0, str(tests_dir.resolve().parent))

    runner = TestRunner(tests_dir)
    runner.run_all_tests()


if __name__ == "__main__":
    main()
