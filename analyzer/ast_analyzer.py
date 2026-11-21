import ast
from typing import List, Dict, Any, Set

class InjectionASTVisitor(ast.NodeVisitor):
    def __init__(self, code: str):
        self.code = code
        self.lines = code.split("\n")
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.tainted_vars: Set[str] = set()
        self.fstring_vars: Dict[str, int] = {}
        self.allowlist_vars: Set[str] = set()

    def visit_Assign(self, node: ast.Assign):
        # Track f-strings assigned to variables: query = f"..."
        if isinstance(node.value, ast.JoinedStr):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.fstring_vars[target.id] = node.lineno
                    # Check if this f-string contains SQL commands
                    fstring_text = self._extract_joined_str_text(node.value)
                    if any(sql_kw in fstring_text.upper() for sql_kw in ["SELECT ", "INSERT INTO ", "UPDATE ", "DELETE FROM ", "DROP "]):
                        self.vulnerabilities.append({
                            "id": "SQL_INJECTION_FSTRING",
                            "category": "Injection Flaw",
                            "title": "SQL Injection via Formatted String Interpolation",
                            "line": node.lineno,
                            "cwe": "CWE-89",
                            "severity": "CRITICAL",
                            "description": f"Variable '{target.id}' builds a SQL statement using dynamic string interpolation (f-string) without parameterized placeholders.",
                            "snippet": self.lines[node.lineno - 1].strip(),
                            "recommendation": "Use parameterized queries with placeholders `?` or `%s` and pass parameters as a tuple."
                        })
        # Check string concatenation or .format() in SQL assignments
        elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, (ast.Add, ast.Mod)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.fstring_vars[target.id] = node.lineno
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        # Look for validation patterns like: if host not in ALLOWED_HOSTS
        # or if host in ALLOWED_HOSTS
        if isinstance(node.test, ast.Compare):
            for comparator in node.test.comparators:
                if isinstance(comparator, ast.Name) and "ALLOW" in comparator.id.upper():
                    if isinstance(node.test.left, ast.Name):
                        self.allowlist_vars.add(node.test.left.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_func_name(node.func)

        # 1. Dangerous eval / exec (CWE-95)
        if func_name in ("eval", "exec"):
            self.vulnerabilities.append({
                "id": "DANGEROUS_EVAL",
                "category": "Injection Flaw",
                "title": f"Dangerous Code Execution via '{func_name}()'",
                "line": node.lineno,
                "cwe": "CWE-95",
                "severity": "CRITICAL",
                "description": f"Direct execution of untrusted input using '{func_name}' permits Remote Code Execution (RCE).",
                "snippet": self.lines[node.lineno - 1].strip(),
                "recommendation": "Avoid eval(). Use ast.literal_eval() for data literals or a dedicated mathematical expression parser."
            })

        # 2. SQL execute checks (CWE-89)
        if func_name.endswith(".execute"):
            if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.JoinedStr):
                    self.vulnerabilities.append({
                        "id": "SQL_INJECTION_INLINE",
                        "category": "Injection Flaw",
                        "title": "SQL Injection via Inline String Interpolation",
                        "line": node.lineno,
                        "cwe": "CWE-89",
                        "severity": "CRITICAL",
                        "description": "SQL statement passed directly to .execute() contains dynamic f-string formatting.",
                        "snippet": self.lines[node.lineno - 1].strip(),
                        "recommendation": "Use parameterized queries: `cursor.execute('SELECT ... WHERE col = ?', (val,))`."
                    })
                elif isinstance(arg0, ast.Name) and arg0.id in self.fstring_vars:
                    # Already reported at assignment or report here if not duplicate
                    if not any(v["line"] == self.fstring_vars[arg0.id] for v in self.vulnerabilities):
                        self.vulnerabilities.append({
                            "id": "SQL_INJECTION_VAR",
                            "category": "Injection Flaw",
                            "title": "SQL Injection: Execution of Dynamically Interpolated Query",
                            "line": node.lineno,
                            "cwe": "CWE-89",
                            "severity": "CRITICAL",
                            "description": f"Query variable '{arg0.id}' was constructed using unescaped string formatting.",
                            "snippet": self.lines[node.lineno - 1].strip(),
                            "recommendation": "Pass parameters in the second argument of .execute(query, params)."
                        })

        # 3. Subprocess Command Injection (CWE-78)
        if func_name.startswith("subprocess.") or func_name in ("os.system", "os.popen"):
            has_shell_true = any(k.arg == "shell" and getattr(k.value, "value", False) is True for k in node.keywords)
            first_arg = node.args[0] if node.args else None

            is_interpolated = False
            first_arg_str = ""
            if isinstance(first_arg, ast.JoinedStr):
                is_interpolated = True
            elif isinstance(first_arg, ast.Name) and first_arg.id in self.fstring_vars:
                is_interpolated = True
            elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Add, ast.Mod)):
                is_interpolated = True

            if has_shell_true or is_interpolated:
                self.vulnerabilities.append({
                    "id": "COMMAND_INJECTION",
                    "category": "Injection Flaw",
                    "title": "Command Injection via Subprocess / Shell Execution",
                    "line": node.lineno,
                    "cwe": "CWE-78",
                    "severity": "CRITICAL",
                    "description": f"Subprocess invocation '{func_name}' runs with `shell=True` or dynamic string interpolation, enabling arbitrary system command injection.",
                    "snippet": self.lines[node.lineno - 1].strip(),
                    "recommendation": "Pass arguments as a validated list without `shell=True`, and validate input against a strict allowlist."
                })

        # 4. Unsafe YAML Deserialization (CWE-502)
        if func_name in ("yaml.load", "ruamel.yaml.load"):
            is_unsafe = False
            for k in node.keywords:
                if k.arg == "Loader":
                    loader_name = self._get_func_name(k.value)
                    if "Loader" in loader_name and "Safe" not in loader_name:
                        is_unsafe = True
            if not node.keywords or is_unsafe:
                self.vulnerabilities.append({
                    "id": "UNSAFE_DESERIALIZATION_YAML",
                    "category": "Injection Flaw",
                    "title": "Unsafe YAML Deserialization",
                    "line": node.lineno,
                    "cwe": "CWE-502",
                    "severity": "CRITICAL",
                    "description": "Calling `yaml.load()` with unsafe Loader allows arbitrary object instantiation and arbitrary code execution.",
                    "snippet": self.lines[node.lineno - 1].strip(),
                    "recommendation": "Use `yaml.safe_load(raw_yaml)` instead."
                })

        self.generic_visit(node)

    def _get_func_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_func_name(node.value)}.{node.attr}"
        return ""

    def _extract_joined_str_text(self, node: ast.JoinedStr) -> str:
        parts = []
        for val in node.values:
            if isinstance(val, ast.Constant):
                parts.append(str(val.value))
            elif isinstance(val, ast.FormattedValue):
                parts.append("{param}")
        return "".join(parts)

def scan_ast_injections(code: str) -> List[Dict[str, Any]]:
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [{
            "id": "SYNTAX_ERROR",
            "category": "Code Quality",
            "title": "Python Syntax Error in Source",
            "line": e.lineno or 1,
            "cwe": "CWE-20",
            "severity": "MEDIUM",
            "description": f"Could not parse AST: {e.msg}",
            "snippet": "",
            "recommendation": "Ensure code is valid Python."
        }]
    
    visitor = InjectionASTVisitor(code)
    visitor.visit(tree)
    return visitor.vulnerabilities
