# Release Checklist

Use this checklist for a normal AigenGuard release.

1. Create a release-prep branch.
2. Bump the package version.
3. Update the changelog.
4. Run validation:

   ```bash
   python -m pytest
   python -m ruff check .
   git diff --check
   ```

5. Open and merge the release-prep PR.
6. Create and push the release tag.
7. Verify the GitHub Actions Release run completed successfully.
8. Verify the PyPI version is available.
9. Run a clean install smoke test:

   ```bash
   python -m pip install aigenguard==X.Y.Z
   aigenguard --version
   aigenguard activate
   aigenguard guard
   ```

If `aigenguard --version` shows an old version after install, run `hash -r` or
`rehash` and retry.
