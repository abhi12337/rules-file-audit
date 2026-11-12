# Copilot instructions

This is a Django 5 project with a React front end.

- Use class-based views only for CRUD; function views elsewhere.
- Database access goes through the ORM; never build SQL with f-strings.
- For new endpoints add a test in `tests/api/`.
- Use the `requests` session in `core/http.py`, which sets timeouts and retries.
