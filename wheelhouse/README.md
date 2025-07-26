# Wheelhouse

This directory is intentionally kept empty in version control. Place prebuilt
Python wheels here when installing the project on a machine without internet
access.

To populate the directory:

```bash
pip download -d wheelhouse -r backend/requirements.txt -r requirements-test.txt
```

Then transfer the `wheelhouse` folder to the target environment and run
`./scripts/install_offline.sh`.
