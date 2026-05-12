# Publish Grudarin To PyPI

This is required for users to run:

```bash
pip install grudarin
```

Without publishing, pip will return:
`No matching distribution found for grudarin`.

## 1) Build distributions

```bash
python -m pip install --upgrade pip setuptools wheel twine
python setup.py sdist bdist_wheel
```

Artifacts are created in `dist/`.

## 2) Validate package files

```bash
python -m twine check dist/*
```

## 3) Upload to TestPyPI (recommended first)

```bash
python -m twine upload --repository testpypi dist/*
```

Test install:

```bash
python -m pip install --index-url https://test.pypi.org/simple/ grudarin
```

## 4) Upload to PyPI

```bash
python -m twine upload dist/*
```

## 5) Verify

```bash
python -m pip install --upgrade grudarin
grudarin --help
```

## Notes

- The PyPI package name must be available.
- If `grudarin` is taken on PyPI, publish under a new name (for example `grudarin-osint`) and update README install commands.
