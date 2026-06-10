import ast
import os
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class KillSwitchAuditor(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "killswitchauditor"

    @property
    def description(self) -> str:
        return "Audits agent configuration and loop structures to ensure kill-switches, cost limits, and human confirmations are enforced"

    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        findings = []
        for file_path in files:
            if not file_path.endswith('.py'):
                continue
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Fast pre-filtering
                if not any(kw in content for kw in ['while', 'def ', 'AgentExecutor', 'ConversableAgent', 'completions', 'messages', 'invoke', 'predict', 'remove', 'rmtree']):
                    continue

                tree = ast.parse(content, filename=file_path)
                visitor = KillSwitchVisitor(file_path)
                visitor.visit(tree)
                findings.extend(visitor.findings)

            except Exception:
                pass
        return findings


class KillSwitchVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []
        self.current_function = None
        self.aliases = {}

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                self.aliases[alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            for alias in node.names:
                full_name = f"{node.module}.{alias.name}"
                if alias.asname:
                    self.aliases[alias.asname] = full_name
                else:
                    self.aliases[alias.name] = full_name
        self.generic_visit(node)

    def _get_full_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            val_name = self._get_full_name(node.value)
            if val_name:
                resolved_val = self.aliases.get(val_name, val_name)
                return f"{resolved_val}.{node.attr}"
        return ""

    def _is_truthy_test(self, test_node) -> bool:
        if isinstance(test_node, ast.Constant):
            return bool(test_node.value)
        elif isinstance(test_node, ast.Name):
            return test_node.id == 'True'
        elif isinstance(test_node, ast.UnaryOp):
            if isinstance(test_node.op, ast.Not):
                if isinstance(test_node.operand, ast.Constant):
                    return not bool(test_node.operand.value)
                elif isinstance(test_node.operand, ast.Name):
                    return test_node.operand.id == 'False'
            elif isinstance(test_node.op, ast.USub):
                return self._is_truthy_test(test_node.operand)
        return False

    def _is_limit_condition(self, test_node) -> bool:
        for node in ast.walk(test_node):
            if isinstance(node, ast.Compare):
                # Check for inequality operators (<, <=, >, >=, !=)
                if any(isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.NotEq)) for op in node.ops):
                    return True
            test_str = ast.dump(node).lower()
            if any(limit_kw in test_str for limit_kw in ['step', 'limit', 'max', 'count', 'iteration', 'token', 'cost', 'budget', 'depth']):
                return True
        return False

    def _is_valid_hitl_for_destructive(self, hitl_call, destructive_name) -> bool:
        func_name = self._get_full_name(hitl_call.func)
        short_name = hitl_call.func.attr if isinstance(hitl_call.func, ast.Attribute) else ""
        matched = (func_name or short_name).lower()
        
        if any(x in matched for x in ['input', 'confirm', 'verify', 'approve', 'ask_user', 'authorize']):
            if 'login' in matched or 'connect' in matched or 'status' in matched:
                return False
                
            prompt_str = ""
            if len(hitl_call.args) > 0:
                prompt_node = hitl_call.args[0]
                if isinstance(prompt_node, ast.Constant) and isinstance(prompt_node.value, str):
                    prompt_str = prompt_node.value.lower()
            
            if not prompt_str:
                return True
                
            if any(kw in prompt_str for kw in ['sure', 'confirm', 'delete', 'remove', 'proceed', 'erase', 'drop', 'yes/no', 'ok']):
                return True
        return False

    def _process_function(self, node):
        self.current_function = node
        
        # Check recursion
        has_recursion = False
        for subnode in ast.walk(node):
            if isinstance(subnode, ast.Call):
                func_name = self._get_full_name(subnode.func)
                short_name = subnode.func.attr if isinstance(subnode.func, ast.Attribute) else ""
                matched_name = func_name or short_name
                if matched_name == node.name:
                    has_recursion = True
                    break

        if has_recursion:
            has_limit = False
            for subnode in ast.walk(node):
                if isinstance(subnode, ast.If):
                    if self._is_limit_condition(subnode.test):
                        has_limit = True
                        break
            if not has_limit:
                self.findings.append({
                    "file": self.file_path,
                    "line": node.lineno,
                    "name": "Missing Recursive Kill-Switch",
                    "severity": "HIGH",
                    "message": f"Recursive function '{node.name}' detected without iteration limits or recursion depth guards. This can lead to runaway recursion and high API costs.",
                    "suggestion": "Add a depth/limit check argument (e.g., depth=0) and abort the recursion if it exceeds a threshold (e.g., if depth > max_depth: return)."
                })

        self.generic_visit(node)
        self.current_function = None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._process_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._process_function(node)

    def visit_While(self, node: ast.While):
        is_infinite = self._is_truthy_test(node.test)
        if is_infinite:
            has_kill_switch = False
            for body_node in ast.walk(node):
                if isinstance(body_node, ast.If):
                    has_break = False
                    for child in ast.walk(body_node):
                        if isinstance(child, ast.Break):
                            has_break = True
                            break
                    if has_break:
                        if self._is_limit_condition(body_node.test):
                            has_kill_switch = True
                            break
            if not has_kill_switch:
                self.findings.append({
                    "file": self.file_path,
                    "line": node.lineno,
                    "name": "Missing Agentic Kill-Switch",
                    "severity": "HIGH",
                    "message": "Infinite loop (while True) detected without a counter-based iteration cap or limit-based break. This can cause runaway agent executions and massive API costs.",
                    "suggestion": "Implement a step counter (e.g. step += 1) and break the loop if it exceeds a maximum threshold (e.g., if step > max_steps: break)."
                })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_full_name(node.func)
        short_name = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        matched_name = func_name or short_name

        # 1. Check Agent Framework limits (bare name or FQCN suffix)
        is_agent_class = False
        target_classes = ['AgentExecutor', 'ConversableAgent', 'Crew']
        if matched_name:
            if matched_name in target_classes:
                is_agent_class = True
            elif any(matched_name.endswith(f".{tc}") for tc in target_classes):
                is_agent_class = True

        if is_agent_class:
            has_limit = False
            for kw in node.keywords:
                if kw.arg in ['max_iterations', 'max_consecutive_auto_reply', 'max_iter', 'max_loops', 'iteration_limit']:
                    has_limit = True
                    break
            if not has_limit:
                self.findings.append({
                    "file": self.file_path,
                    "line": node.lineno,
                    "name": "Missing Agent Framework Limits",
                    "severity": "HIGH",
                    "message": f"Agent class '{matched_name}' is initialized without setting execution limits (e.g., max_iterations or max_consecutive_auto_reply).",
                    "suggestion": f"Specify an iteration limit (e.g., max_iterations=15) during agent initialization."
                })

        # 2. Check OpenAI / Anthropic / LangChain LLM call constraints (max_tokens / timeout)
        is_llm_call = False
        if func_name:
            func_lower = func_name.lower()
            if any(x in func_lower for x in ['completions.create', 'completion.create', 'messages.create', 'invoke', 'predict']):
                is_llm_call = True
        if not is_llm_call and short_name:
            short_lower = short_name.lower()
            if short_lower in ['create', 'invoke', 'predict'] and func_name and any(x in func_name.lower() for x in ['completions', 'messages', 'llm', 'model', 'chat']):
                is_llm_call = True

        if is_llm_call:
            has_tokens = False
            has_timeout = False
            for kw in node.keywords:
                if kw.arg in ['max_tokens', 'max_completion_tokens', 'max_tokens_to_sample']:
                    has_tokens = True
                if kw.arg in ['timeout', 'request_timeout']:
                    has_timeout = True

            missing = []
            if not has_tokens:
                missing.append("max_tokens")
            if not has_timeout:
                missing.append("timeout")

            if missing:
                self.findings.append({
                    "file": self.file_path,
                    "line": node.lineno,
                    "name": "Unconstrained LLM API Call",
                    "severity": "MEDIUM",
                    "message": f"LLM API completion call is missing safety constraints: {', '.join(missing)}.",
                    "suggestion": "Define explicit timeout constraints (e.g., timeout=10) and cost limiters (e.g., max_tokens=1000) for LLM API calls."
                })

        # 3. Check Destructive Tool execution missing human-in-the-loop validation
        if matched_name in ['remove', 'rmtree', 'unlink', 'drop_collection', 'drop', 'shutil.rmtree', 'os.remove', 'os.unlink']:
            has_preceding_hitl = False
            if self.current_function:
                for subnode in ast.walk(self.current_function):
                    if isinstance(subnode, ast.Call) and subnode.lineno < node.lineno:
                        if self._is_valid_hitl_for_destructive(subnode, matched_name):
                            has_preceding_hitl = True
                            break
            
            if not has_preceding_hitl:
                self.findings.append({
                    "file": self.file_path,
                    "line": node.lineno,
                    "name": "Missing Human-in-the-Loop Confirmation",
                    "severity": "HIGH",
                    "message": f"Destructive file or database operation '{matched_name}()' is invoked without preceding human-in-the-loop confirmation.",
                    "suggestion": "Ensure destructive tools prompt the operator for confirmation (e.g., using input() or confirm_action()) before executing."
                })

        self.generic_visit(node)

