"""Core orchestration primitives for Kaalyx.

This package holds the machinery that every pipeline stage relies on but that is not
itself tied to any particular recon tool: the subprocess runner, the concurrency and
rate-limiting controls, the checkpoint/resume state, target-type detection, the tool
registry, and the orchestrator that sequences stages.
"""
