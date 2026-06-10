import pytest
from ghostcheck.checks.rag_pipeline_auditor import RAGPipelineAuditor

def test_rag_unisolated_context(tmp_path):
    checker = RAGPipelineAuditor()
    f = tmp_path / "rag_unsafe.py"
    f.write_text("""
import langchain
docs = retriever.get_relevant_documents("some query")
# context var retrieved directly without slice/XML isolation
prompt = "Help me with: {docs}".format(docs=docs)
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "RAG Unisolated Context" for fnd in findings)
    assert any(fnd["severity"] == "WARNING" for fnd in findings)

def test_rag_filter_injection(tmp_path):
    checker = RAGPipelineAuditor()
    f = tmp_path / "rag_filter.py"
    f.write_text("""
import chromadb
# Dynamic query construction is unsafe
results = collection.query(
    query_texts=["hello"],
    where="metadata_id == " + user_input
)
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "RAG Filter Injection" for fnd in findings)
    assert any(fnd["severity"] == "HIGH" for fnd in findings)

def test_rag_missing_guardrails(tmp_path):
    checker = RAGPipelineAuditor()
    f = tmp_path / "rag_no_guard.py"
    f.write_text("""
from langchain.vectorstores import Pinecone
# Imports RAG but has no guardrails imports
index = Pinecone.from_existing_index("test", embeddings)
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "RAG Missing Guardrails" for fnd in findings)
    assert any(fnd["severity"] == "INFO" for fnd in findings)

def test_rag_safe_pipeline(tmp_path):
    checker = RAGPipelineAuditor()
    f = tmp_path / "rag_safe.py"
    f.write_text("""
import langchain
import guardrails
docs = retriever.get_relevant_documents("query")
truncated_docs = docs[:1000]
# Safe because of XML isolation delimiters
prompt = "<context>{context}</context>".format(context=truncated_docs)
""")
    
    findings = checker.scan([str(f)], config=None)
    # RAG Missing Guardrails should not be raised since guardrails is imported
    # RAG Unisolated Context should not be raised since it has <context> tags and slice
    assert not any(fnd["name"] in ["RAG Unisolated Context", "RAG Missing Guardrails"] for fnd in findings)

def test_rag_taint_propagation(tmp_path):
    checker = RAGPipelineAuditor()
    f = tmp_path / "rag_taint.py"
    f.write_text("""
import langchain
docs = retriever.retrieve("query")
# Taint propagates from docs -> context
context = "\\n".join([d.text for d in docs])
# context formats here
prompt = "Context: {context}".format(context=context)
""")
    
    findings = checker.scan([str(f)], config=None)
    assert any(fnd["name"] == "RAG Unisolated Context" for fnd in findings)

