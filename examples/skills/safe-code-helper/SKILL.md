---
name: safe-code-helper
description: Safe Python code review and refactoring checklist for unit testing, type annotations, and clean error handling.
version: 1.0.0
tags:
  - python
  - code-review
  - refactoring
  - testing
categories:
  - software-development
capabilities:
  - python-refactoring
  - type-checking
platforms:
  - linux
  - macos
  - windows
allowed-tools:
  - Read
  - Grep
  - Glob
---
# Safe Python Code Review & Refactoring Skill

When reviewing or refactoring Python modules:
1. Inspect function signatures and ensure explicit type annotations (`typing` or PEP 604 union syntax).
2. Replace bare `except:` clauses with specific exception types and structured error messages.
3. Check that file handles and database connections use `with` context managers or `try...finally` blocks.
4. Consult [Checklist Reference](references/checklist.md) for unit test coverage guidelines.
