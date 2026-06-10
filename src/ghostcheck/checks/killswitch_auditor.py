import ast
import os
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

try:
    import esprima
except ImportError:
    esprima = None


class KillSwitchAuditor(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "killswitch_logic_auditor"

    @property
    def description(self) -> str:
        return "Audits agent configuration and loop structures to ensure kill-switches, cost limits, and human confirmations are enforced"

    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        findings = []
        for file_path in files:
            ext = os.path.splitext(file_path)[1].lower()
            if ext == '.py':
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
            elif ext in ['.js', '.ts', '.jsx', '.tsx'] and esprima is not None:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Fast pre-filtering for JS/TS
                    if not any(kw in content for kw in ['while', 'for', 'function', 'AgentExecutor', 'ConversableAgent', 'completions', 'messages', 'invoke', 'predict', 'unlinkSync', 'rmSync', 'rimraf']):
                        continue

                    try:
                        tree = esprima.parseModule(content, loc=True)
                    except Exception:
                        tree = esprima.parseScript(content, loc=True)

                    visitor = JsKillSwitchVisitor(file_path)
                    visitor.walk(tree)
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
                    has_exit = False
                    for child in ast.walk(body_node):
                        if isinstance(child, (ast.Break, ast.Return)):
                            has_exit = True
                            break
                    if has_exit:
                        if self._is_limit_condition(body_node.test):
                            has_kill_switch = True
                            break
                        # Also accept conditional returns/breaks that check for None/sentinel
                        for comparator in ast.walk(body_node.test):
                            if isinstance(comparator, ast.Constant) and comparator.value is None:
                                has_kill_switch = True
                                break
                        if has_kill_switch:
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

        # 1. Check Agent Framework limits
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
                    "suggestion": "Specify an iteration limit (e.g., max_iterations=15) during agent initialization."
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


class JsKillSwitchVisitor:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []
        self.current_function = None

    def _get_line(self, node) -> int:
        loc = getattr(node, 'loc', None)
        if loc:
            start = getattr(loc, 'start', None)
            if start:
                line_val = getattr(start, 'line', None)
                if line_val is not None:
                    return line_val
        return 1

    def walk(self, node):
        if not node:
            return
        
        node_type = getattr(node, 'type', '')
        line = self._get_line(node)
        
        is_function = node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'MethodDefinition']
        if is_function:
            self.current_function = node

        # 1. Infinite loop verification (while(true) or for(;;))
        if node_type in ['WhileStatement', 'DoWhileStatement']:
            is_infinite = False
            test = getattr(node, 'test', None)
            if test:
                t_type = getattr(test, 'type', '')
                if t_type == 'Literal' and (test.value is True or test.value == 1):
                    is_infinite = True
                elif t_type == 'Identifier' and test.name == 'true':
                    is_infinite = True
                    
            if is_infinite:
                if not self._check_js_loop_has_limit(node.body):
                    self.findings.append({
                        "file": self.file_path,
                        "line": line,
                        "name": "Missing Agentic Kill-Switch",
                        "severity": "HIGH",
                        "message": "Infinite loop detected without a counter-based iteration cap or limit-based break. This can cause runaway agent executions and massive API costs.",
                        "suggestion": "Implement a step counter (e.g. step += 1) and break the loop if it exceeds a maximum threshold (e.g., if (step > max_steps) break;)."
                    })
        elif node_type == 'ForStatement':
            # for (;;) has no test
            if not getattr(node, 'test', None):
                if not self._check_js_loop_has_limit(node.body):
                    self.findings.append({
                        "file": self.file_path,
                        "line": line,
                        "name": "Missing Agentic Kill-Switch",
                        "severity": "HIGH",
                        "message": "Infinite loop (for(;;)) detected without a counter-based iteration cap or limit-based break. This can cause runaway agent executions and massive API costs.",
                        "suggestion": "Implement a step counter and break the loop if it exceeds a maximum threshold."
                    })

        # 2. Check Agent / LLM class initialization or calls
        elif node_type == 'NewExpression':
            callee_str = self._resolve_callee(node.callee)
            if callee_str in ['AgentExecutor', 'ConversableAgent', 'Crew']:
                has_limit = False
                if node.arguments and len(node.arguments) > 0:
                    first_arg = node.arguments[0]
                    if getattr(first_arg, 'type', '') == 'ObjectExpression':
                        for prop in getattr(first_arg, 'properties', []):
                            prop_key = self._resolve_callee(prop.key)
                            if prop_key in ['maxIterations', 'max_iterations', 'maxLoops', 'max_loops', 'maxConsecutiveAutoReply', 'max_consecutive_auto_reply', 'iterationLimit', 'iteration_limit']:
                                has_limit = True
                                break
                if not has_limit:
                    self.findings.append({
                        "file": self.file_path,
                        "line": line,
                        "name": "Missing Agent Framework Limits",
                        "severity": "HIGH",
                        "message": f"Agent class '{callee_str}' is initialized without setting execution limits.",
                        "suggestion": "Specify an iteration limit (e.g. maxIterations: 15) during agent initialization."
                    })

        elif node_type == 'CallExpression':
            callee_str = self._resolve_callee(node.callee)
            
            # Check LLM completions API calls constraints
            if any(x in callee_str for x in ['completions.create', 'messages.create', 'invoke', 'predict']):
                has_tokens = False
                has_timeout = False
                if node.arguments and len(node.arguments) > 0:
                    first_arg = node.arguments[0]
                    if getattr(first_arg, 'type', '') == 'ObjectExpression':
                        for prop in getattr(first_arg, 'properties', []):
                            prop_key = self._resolve_callee(prop.key)
                            if prop_key in ['max_tokens', 'maxTokens', 'maxCompletionTokens', 'max_completion_tokens']:
                                has_tokens = True
                            if prop_key in ['timeout', 'requestTimeout', 'request_timeout']:
                                has_timeout = True
                
                missing = []
                if not has_tokens: missing.append("max_tokens")
                if not has_timeout: missing.append("timeout")
                if missing:
                    self.findings.append({
                        "file": self.file_path,
                        "line": line,
                        "name": "Unconstrained LLM API Call",
                        "severity": "MEDIUM",
                        "message": f"LLM API completion call is missing safety constraints: {', '.join(missing)}.",
                        "suggestion": "Define explicit timeout constraints and cost limiters for LLM API calls."
                    })

            # Check Destructive actions HITL
            elif callee_str in ['fs.unlinkSync', 'fs.rmSync', 'fs.promises.unlink', 'fs.promises.rm', 'rimraf', 'unlinkSync', 'rmSync']:
                has_hitl = False
                if self.current_function:
                    has_hitl = self._check_js_hitl_in_scope(self.current_function, line)
                if not has_hitl:
                    self.findings.append({
                        "file": self.file_path,
                        "line": line,
                        "name": "Missing Human-in-the-Loop Confirmation",
                        "severity": "HIGH",
                        "message": f"Destructive file operation '{callee_str}()' is invoked without preceding human-in-the-loop confirmation.",
                        "suggestion": "Ensure destructive tools prompt the operator for confirmation (e.g., using readline or confirm()) before executing."
                    })

        # Recurse children
        for key, value in node.__dict__.items():
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        self.walk(item)
            elif hasattr(value, 'type'):
                self.walk(value)

        if is_function:
            self.current_function = None

    def _resolve_callee(self, callee) -> str:
        if not callee:
            return ""
        c_type = getattr(callee, 'type', '')
        if c_type == 'Identifier':
            return getattr(callee, 'name', '')
        elif c_type == 'MemberExpression':
            obj_str = self._resolve_callee(callee.object)
            prop_str = self._resolve_callee(callee.property)
            if obj_str and prop_str:
                return f"{obj_str}.{prop_str}"
            return prop_str or obj_str
        return ""

    def _check_js_loop_has_limit(self, body_node) -> bool:
        if not body_node:
            return False
        
        # We search for IfStatement containing BreakStatement with counter comparison
        found_limit = [False]
        
        def traverse(n):
            if not n: return
            nt = getattr(n, 'type', '')
            if nt == 'IfStatement':
                # Check condition
                cond_str = self._dump_js_node(n.test).lower()
                if any(x in cond_str for x in ['step', 'limit', 'max', 'count', 'iteration', 'token', 'cost', 'budget', 'depth', '>', '<', '!=', '==']):
                    # Check if body contains BreakStatement
                    if self._has_js_break(n.consequent) or self._has_js_break(getattr(n, 'alternate', None)):
                        found_limit[0] = True
                        return
            for k, val in n.__dict__.items():
                if isinstance(val, list):
                    for item in val:
                        if hasattr(item, 'type'):
                            traverse(item)
                elif hasattr(val, 'type'):
                    traverse(val)

        traverse(body_node)
        return found_limit[0]

    def _has_js_break(self, node) -> bool:
        if not node:
            return False
        has_brk = [False]
        def traverse(n):
            if not n: return
            if getattr(n, 'type', '') in ['BreakStatement', 'ReturnStatement']:
                has_brk[0] = True
                return
            for k, val in n.__dict__.items():
                if isinstance(val, list):
                    for item in val:
                        if hasattr(item, 'type') and not has_brk[0]:
                            traverse(item)
                elif hasattr(val, 'type') and not has_brk[0]:
                    traverse(val)
        traverse(node)
        return has_brk[0]

    def _dump_js_node(self, node) -> str:
        if not node:
            return ""
        nt = getattr(node, 'type', '')
        if nt == 'Identifier':
            return getattr(node, 'name', '')
        elif nt == 'Literal':
            return str(getattr(node, 'value', ''))
        elif nt == 'BinaryExpression':
            return f"{self._dump_js_node(node.left)} {getattr(node, 'operator', '')} {self._dump_js_node(node.right)}"
        elif nt == 'MemberExpression':
            return f"{self._dump_js_node(node.object)}.{self._dump_js_node(node.property)}"
        return ""

    def _check_js_hitl_in_scope(self, func_node, dest_line) -> bool:
        found = [False]
        def traverse(n):
            if not n: return
            nt = getattr(n, 'type', '')
            if nt == 'CallExpression':
                line = self._get_line(n)
                if line < dest_line:
                    callee_str = self._resolve_callee(n.callee).lower()
                    if any(x in callee_str for x in ['prompt', 'confirm', 'question', 'readline', 'readhost', 'askuser']):
                        if not any(x in callee_str for x in ['login', 'connect', 'status']):
                            found[0] = True
                            return
            for k, val in n.__dict__.items():
                if isinstance(val, list):
                    for item in val:
                        if hasattr(item, 'type') and not found[0]:
                            traverse(item)
                elif hasattr(val, 'type') and not found[0]:
                    traverse(val)
        traverse(func_node)
        return found[0]
