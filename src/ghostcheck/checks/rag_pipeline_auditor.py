import ast
import os
import re
from typing import List, Dict, Any
from ..interfaces import BaseScannerPlugin

class RAGPipelineAuditor(BaseScannerPlugin):

    @property
    def name(self) -> str:
        return "ragpipelineauditor"

    @property
    def description(self) -> str:
        return "Audits RAG pipelines for unsecured database queries, unisolated prompt templates, and missing guardrails"

    def scan(self, files: List[str], config: Any) -> List[Dict[str, Any]]:
        findings = []
        for file_path in files:
            # Only scan Python files for dynamic AST analysis
            if not file_path.endswith('.py'):
                continue
            try:
                # Fast pre-filtering: check for RAG-related terms
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Quick pre-filter to optimize CPU
                rag_keywords = ['langchain', 'llama_index', 'chromadb', 'pinecone', 'qdrant', 'retriev', 'query', 'search', 'prompt', 'template']
                if not any(kw in content.lower() for kw in rag_keywords):
                    continue

                tree = ast.parse(content, filename=file_path)
                visitor = RAGVisitor(file_path)
                visitor.visit(tree)
                findings.extend(visitor.findings)

            except Exception:
                # Silent safety fallback to avoid scan interruption
                pass
        return findings


class RAGVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []
        
        # Track aliases and imports
        self.rag_imported = False
        self.guardrails_imported = False
        
        # Track variables holding retrieved data
        self.retrieved_vars = set()
        
        # Track variables that have been sliced or length-restricted
        self.restricted_vars = set()
        
        # Regex for checking prompt delimiters
        self.delimiter_regex = re.compile(
            r'(?:(?:\[context\]|class="context"|<context>|###\s*Context|"""\s*Context|context:\s*\{).*?\{.*?\})|'
            r'(?:(?:context|retrieved|document).*?within.*?tags)',
            re.IGNORECASE
        )

    def _get_full_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val_name = self._get_full_name(node.value)
            if val_name:
                return f"{val_name}.{node.attr}"
        return ""

    def _extract_target_names(self, node) -> List[str]:
        names = []
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.Attribute):
            names.append(node.attr)
            val_name = self._get_full_name(node.value)
            if val_name:
                names.append(f"{val_name}.{node.attr}")
        elif isinstance(node, (ast.Tuple, ast.List)):
            for elt in node.elts:
                names.extend(self._extract_target_names(elt))
        elif isinstance(node, ast.Subscript):
            names.extend(self._extract_target_names(node.value))
        return names

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if any(pkg in alias.name for pkg in ['chromadb', 'pinecone', 'qdrant_client', 'langchain', 'llama_index']):
                self.rag_imported = True
            if any(pkg in alias.name for pkg in ['guardrails', 'nemo_guardrails', 'llamaguard']):
                self.guardrails_imported = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            if any(pkg in node.module for pkg in ['chromadb', 'pinecone', 'qdrant_client', 'langchain', 'llama_index']):
                self.rag_imported = True
            if any(pkg in node.module for pkg in ['guardrails', 'nemo_guardrails', 'llamaguard']):
                self.guardrails_imported = True
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Extract target names recursively (tuple unpacking, attributes, subscripts)
        target_names = []
        for target in node.targets:
            target_names.extend(self._extract_target_names(target))

        # 1. Detect VDB retrievals and assign returned var names
        if isinstance(node.value, ast.Call):
            func_name = self._get_full_name(node.value.func)
            short_name = node.value.func.attr if isinstance(node.value.func, ast.Attribute) else ""
            matched_name = func_name or short_name
            if matched_name in ['query', 'search', 'retrieve', 'get_relevant_documents', 'retrieve_documents'] or any(x in matched_name for x in ['retrieve', 'query', 'search']):
                for t_name in target_names:
                    self.retrieved_vars.add(t_name)

        # 2. Propagate retrieved vars taint (e.g. context = "\n".join(docs) or context = [d.text for d in docs])
        referenced_retrieved = False
        for subnode in ast.walk(node.value):
            if isinstance(subnode, ast.Name) and subnode.id in self.retrieved_vars:
                referenced_retrieved = True
                break
            elif isinstance(subnode, ast.Attribute):
                full_attr = self._get_full_name(subnode)
                if full_attr in self.retrieved_vars or subnode.attr in self.retrieved_vars:
                    referenced_retrieved = True
                    break

        if referenced_retrieved:
            for t_name in target_names:
                self.retrieved_vars.add(t_name)

        # 3. Track when variables are sliced (e.g. context = docs[:1000] or context = docs.split())
        # e.g., x = retrieved_var[:1000]
        if isinstance(node.value, ast.Subscript):
            sub_names = self._extract_target_names(node.value.value)
            if any(sn in self.retrieved_vars for sn in sub_names):
                for t_name in target_names:
                    self.restricted_vars.add(t_name)
                        
        # e.g., x = retrieved_var.split() or text_splitter.split(retrieved_var)
        elif isinstance(node.value, ast.Call):
            func_name = self._get_full_name(node.value.func)
            short_name = node.value.func.attr if isinstance(node.value.func, ast.Attribute) else ""
            matched_name = func_name or short_name
            
            # check method call on variable e.g., retrieved.split()
            if isinstance(node.value.func, ast.Attribute):
                attr_names = self._extract_target_names(node.value.func.value)
                if any(an in self.retrieved_vars for an in attr_names) and node.value.func.attr in ['split', 'slice', 'substring']:
                    for t_name in target_names:
                        self.restricted_vars.add(t_name)
            # check function call with variable as argument e.g., text_splitter.split(retrieved) or len(retrieved)
            for arg in node.value.args:
                arg_names = self._extract_target_names(arg)
                if any(an in self.retrieved_vars for an in arg_names):
                    if any(x in matched_name.lower() for x in ['split', 'slice', 'len', 'limit', 'truncate']):
                        for t_name in target_names:
                            self.restricted_vars.add(t_name)

        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        # Check if f-string contains any unisolated retrieved variables
        referenced_retrieved_var = None
        for val in node.values:
            if isinstance(val, ast.FormattedValue):
                var_names = self._extract_target_names(val.value)
                for vn in var_names:
                    if vn in self.retrieved_vars and vn not in self.restricted_vars:
                        referenced_retrieved_var = vn
                        break
                if referenced_retrieved_var:
                    break

        if referenced_retrieved_var:
            has_delimiters = False
            for val in node.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    if self.delimiter_regex.search(val.value) or any(x in val.value for x in ['<context>', '</context>', '"""', '###']):
                        has_delimiters = True
                        break
            if not has_delimiters:
                self.findings.append({
                    "file": self.file_path,
                    "line": node.lineno,
                    "name": "RAG Unisolated Context",
                    "severity": "WARNING",
                    "message": f"Prompt template formats retrieved context variable '{referenced_retrieved_var}' within an f-string without strict XML/bracket delimiters.",
                    "suggestion": "Enclose f-string interpolation inside XML tags (e.g. f'<context>{{{referenced_retrieved_var}}}</context>')."
                })
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        # Check percent formatting: template % docs
        if isinstance(node.op, ast.Mod):
            right_names = self._extract_target_names(node.right)
            if isinstance(node.right, ast.Tuple):
                for elt in node.right.elts:
                    right_names.extend(self._extract_target_names(elt))

            referenced_retrieved_var = None
            for rn in right_names:
                if rn in self.retrieved_vars and rn not in self.restricted_vars:
                    referenced_retrieved_var = rn
                    break

            if referenced_retrieved_var:
                has_delimiters = False
                if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                    if self.delimiter_regex.search(node.left.value):
                        has_delimiters = True
                
                if not has_delimiters:
                    self.findings.append({
                        "file": self.file_path,
                        "line": node.lineno,
                        "name": "RAG Unisolated Context",
                        "severity": "WARNING",
                        "message": f"Prompt template formats retrieved context variable '{referenced_retrieved_var}' using Modulo (%) operator without strict delimiters.",
                        "suggestion": "Enclose context formatting inside structured tags."
                    })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_full_name(node.func)
        method_name = node.func.attr if isinstance(node.func, ast.Attribute) else (node.func.id if isinstance(node.func, ast.Name) else "")

        # 1. Detect Vector DB Filter Injections (query/search filters containing dynamic content)
        if method_name in ['query', 'search', 'retrieve']:
            for kw in node.keywords:
                if kw.arg in ['where', 'filter', 'query_filter']:
                    is_insecure = False
                    if isinstance(kw.value, ast.JoinedStr):
                        is_insecure = True
                    elif isinstance(kw.value, ast.BinOp) and isinstance(kw.value.op, ast.Add):
                        is_insecure = True
                    elif isinstance(kw.value, ast.Call):
                        call_name = self._get_full_name(kw.value.func)
                        call_short = kw.value.func.attr if isinstance(kw.value.func, ast.Attribute) else ""
                        matched_call = call_name or call_short
                        if matched_call in ['format', 'join'] or any(x in matched_call for x in ['format', 'join']):
                            is_insecure = True

                    if is_insecure:
                        self.findings.append({
                            "file": self.file_path,
                            "line": node.lineno,
                            "name": "RAG Filter Injection",
                            "severity": "HIGH",
                            "message": f"Vector database search parameter '{kw.arg}' is dynamically constructed. This exposes the application to Metadata/Filter injection.",
                            "suggestion": "Use structured filters or parameters rather than dynamic string construction."
                        })

        # 2. Detect formatting calls using retrieved vars
        if method_name in ['format', 'invoke', 'ainvoke', 'run', 'predict', 'fill_template', 'render']:
            referenced_retrieved_var = None
            for arg in node.args:
                arg_names = self._extract_target_names(arg)
                for an in arg_names:
                    if an in self.retrieved_vars:
                        referenced_retrieved_var = an
                        break
                if referenced_retrieved_var:
                    break
                    
            if not referenced_retrieved_var:
                for kw in node.keywords:
                    kw_names = self._extract_target_names(kw.value)
                    for kn in kw_names:
                        if kn in self.retrieved_vars:
                            referenced_retrieved_var = kn
                            break
                    if referenced_retrieved_var:
                        break

            if referenced_retrieved_var and referenced_retrieved_var not in self.restricted_vars:
                has_delimiters = False
                
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Constant):
                    template_str = str(node.func.value.value)
                    if self.delimiter_regex.search(template_str):
                        has_delimiters = True
                
                if not has_delimiters:
                    self.findings.append({
                        "file": self.file_path,
                        "line": node.lineno,
                        "name": "RAG Unisolated Context",
                        "severity": "WARNING",
                        "message": f"Prompt template formats retrieved context variable '{referenced_retrieved_var}' without strict XML/bracket delimiters or length constraints. This makes the LLM vulnerable to indirect prompt injection.",
                        "suggestion": "Enclose retrieved context inside structured XML tags (e.g., '<context> {context} </context>') and truncate/slice the variable length (e.g. context[:1000])."
                    })

        self.generic_visit(node)

    def visit_Module(self, node: ast.Module):
        self.generic_visit(node)
        if self.rag_imported and not self.guardrails_imported:
            self.findings.append({
                "file": self.file_path,
                "line": 1,
                "name": "RAG Missing Guardrails",
                "severity": "INFO",
                "message": "File imports RAG database or orchestrator libraries but does not import any LLM guardrails (e.g. guardrails, nemo_guardrails, llamaguard).",
                "suggestion": "Integrate LLM validation or guardrails to verify retrieved data and LLM outputs at runtime."
            })
