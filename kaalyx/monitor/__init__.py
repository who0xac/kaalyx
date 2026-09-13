"""Monitoring & enrichment helpers (Part 6).

Holds the continuous-monitoring diff (what's new since the last run) and the rule-based
enrichment applied to findings/subdomains: interesting-subdomain flagging and
severity/confidence normalisation. All of it is deterministic — no LLM/agentic reasoning
.
"""
