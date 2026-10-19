# Unit Test & Refactoring Checklist

- Verify edge cases for empty inputs, `None`, and boundary integers.
- Use `tempfile.TemporaryDirectory()` for filesystem tests so host directories remain untouched.
- Ensure all subprocess invocations pass argument lists (`["python", "-m", "unittest"]`) with `shell=False` and explicit `timeout` values.
