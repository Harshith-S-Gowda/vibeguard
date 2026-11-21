import ast
from typing import List, Dict, Any, Set

class AuthASTVisitor(ast.NodeVisitor):
    def __init__(self, code: str):
        self.code = code
        self.lines = code.split("\n")
        self.vulnerabilities: List[Dict[str, Any]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Check decorators for API route definitions (@app.get, @app.post, @app.delete, etc.)
        route_decorator = None
        route_path = ""
        route_method = ""
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                if dec.func.attr in ("get", "post", "put", "delete", "patch"):
                    route_decorator = dec
                    route_method = dec.func.attr.upper()
                    if dec.args and isinstance(dec.args[0], ast.Constant):
                        route_path = str(dec.args[0].value)

        if route_decorator:
            self._analyze_route(node, route_path, route_method)

        self.generic_visit(node)

    def _analyze_route(self, node: ast.FunctionDef, path: str, method: str):
        params = [arg.arg for arg in node.args.args]
        defaults = node.args.defaults
        num_defaults = len(defaults)
        first_default_idx = len(params) - num_defaults

        param_defaults: Dict[str, ast.AST] = {}
        for i, default_node in enumerate(defaults):
            param_name = params[first_default_idx + i]
            param_defaults[param_name] = default_node

        has_auth_dependency = False
        user_identity_var = None

        # Detect Depends() or auth dependencies
        for p in params:
            def_node = param_defaults.get(p)
            if def_node and isinstance(def_node, ast.Call):
                func_name = self._get_name(def_node.func)
                if func_name == "Depends":
                    has_auth_dependency = True
                    user_identity_var = p

        # 1. Detect Client-Supplied Role / Privilege parameter: is_admin: bool = False (CWE-269)
        for p, def_node in param_defaults.items():
            if any(role_kw in p.lower() for role_kw in ["is_admin", "admin", "is_superuser", "role", "privilege"]):
                if isinstance(def_node, ast.Constant):
                    self.vulnerabilities.append({
                        "id": "CLIENT_CONTROLLED_ROLE",
                        "category": "Authorization Issue",
                        "title": f"Client-Controlled Privilege Parameter '{p}'",
                        "line": node.lineno,
                        "cwe": "CWE-269",
                        "severity": "CRITICAL",
                        "description": f"Route '{path}' accepts administrative flag '{p}' directly from client request query/body, allowing trivial privilege escalation.",
                        "snippet": self.lines[node.lineno - 1].strip(),
                        "recommendation": "Derive user permissions securely from a validated server-side session or JWT claims via `Depends(get_current_user)`."
                    })

        # 2. Sensitive / Admin Route Without Authentication (CWE-862)
        is_sensitive_path = any(kw in path.lower() for kw in ["/admin", "/manage", "/internal", "/superuser"])
        is_state_mutation = method in ("DELETE", "PUT", "PATCH")

        if (is_sensitive_path or is_state_mutation) and not has_auth_dependency:
            self.vulnerabilities.append({
                "id": "MISSING_ROUTE_AUTHENTICATION",
                "category": "Authorization Issue",
                "title": f"Missing Authentication on Sensitive Route ({method} {path})",
                "line": node.lineno,
                "cwe": "CWE-862",
                "severity": "HIGH",
                "description": f"Endpoint '{method} {path}' performs sensitive state modification or admin actions without any authentication dependency or token verification.",
                "snippet": self.lines[node.lineno - 1].strip(),
                "recommendation": "Protect route with an authentication dependency: `auth: User = Depends(require_admin_user)`."
            })

        # 3. Broken Object Level Authorization (BOLA / IDOR) (CWE-639)
        # Look for path parameters representing object IDs: e.g. {profile_id}, {target_user_id}, {order_id}
        object_id_params = [p for p in params if any(kw in p.lower() for kw in ["_id", "id_"])]
        
        if object_id_params and has_auth_dependency:
            # Check if function body verifies ownership: e.g. user_id == target_user_id or order['owner_id'] == current_user
            verified_ownership = self._checks_ownership(node, user_identity_var, object_id_params)
            if not verified_ownership:
                obj_param = object_id_params[0]
                self.vulnerabilities.append({
                    "id": "BOLA_IDOR_VULNERABILITY",
                    "category": "Authorization Issue",
                    "title": f"Broken Object Level Authorization (BOLA/IDOR) on '{obj_param}'",
                    "line": node.lineno,
                    "cwe": "CWE-639",
                    "severity": "CRITICAL",
                    "description": f"Endpoint receives object identifier '{obj_param}' and authenticated identity '{user_identity_var}', but never validates that the requester owns or is authorized to access the requested entity.",
                    "snippet": self.lines[node.lineno - 1].strip(),
                    "recommendation": f"Enforce ownership check: `if {obj_param} != {user_identity_var}: raise HTTPException(403, 'Forbidden')` before querying or mutating data."
                })

    def _checks_ownership(self, func_node: ast.FunctionDef, user_var: str, id_params: List[str]) -> bool:
        # Traverse AST within function body looking for comparisons between user_var or ownership fields and id_params
        for sub_node in ast.walk(func_node):
            if isinstance(sub_node, ast.Compare):
                # Check for: target_user_id == user_id or owner_id == current_user
                comp_names = set()
                for child in ast.walk(sub_node):
                    if isinstance(child, ast.Name):
                        comp_names.add(child.id)
                    elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                        comp_names.add(child.value)

                # If user variable and an id param are in comparison
                if user_var and user_var in comp_names:
                    for idp in id_params:
                        if idp in comp_names or any(idp.replace("_id", "") in str(c) for c in comp_names):
                            return True
                # Or comparison with ownership field like owner_id / user_id
                if any("owner" in str(c).lower() or "user" in str(c).lower() for c in comp_names):
                    if user_var in comp_names:
                        return True
        return False

    def _get_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""

def scan_auth_issues(code: str) -> List[Dict[str, Any]]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    visitor = AuthASTVisitor(code)
    visitor.visit(tree)
    return visitor.vulnerabilities
