"""Data layer for Kaalyx.

Owns the normalised record models, the SQLite schema/connection, the repository that
performs all persistence (and the diff queries that power continuous monitoring), and the
raw ``.txt`` file writers. Every stage's output is persisted to *both* SQLite and raw
files — those two sinks live here.
"""
