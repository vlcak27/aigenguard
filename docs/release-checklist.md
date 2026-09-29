# Release Checklist

Use this checklist for a normal AigenGuard release.

1. Create a release-prep branch.
2. Bump the package version.
3. Update the changelog.
4. Run validation:

   ```bash
   python -m pip install -e ".[dev]" twine
   python -m ruff check .
   python -m pytest
   python scripts/precision_corpus.py
   python -m build
   python -m twine check --strict dist/*
   python scripts/verify_release.py --dist dist --tag vX.Y.Z
   git diff --check
   ```

   Use the intended version in `--tag`; this checks agreement without creating a
   tag. Start with an empty `dist/` directory (move any previous artifacts aside).
   Verification requires exactly one wheel and one sdist. It checks metadata,
   source contents, CLI entry points, and a fresh wheel install outside the checkout,
   then runs both aliases, scans, and real blocking/allowed Git commits.

5. Open and merge the release-prep PR.
6. Create and push the release tag.
7. Verify the GitHub Actions Release run completed successfully.
   The validation job checks out the triggering tag's exact commit and runs all
   checks above. PRs and manual workflow runs also validate, but never publish.
   Only the dependent tag-push publish job has `id-token: write`; it uses the
   existing PyPI trusted publisher and downloads the verified artifacts from the
   same run, without rebuilding or checking out different source. Any required
   check failure blocks publication. Confirm trusted-publisher configuration
   still identifies this repository and `release.yml` before the first release.
8. Verify the PyPI version is available.
9. Run a clean install smoke test:

   ```bash
   python -m pip install --upgrade aigenguard==X.Y.Z
   aigenguard --version
   agentbom --version
   aigenguard status
   aigenguard install-hook
   aigenguard status
   ```

   Run hook commands in an existing guarded repository, preserving its intended
   mode and policy. Stage the selected policy before testing a commit. See the
   [upgrade procedure](policy.md#upgrading-an-existing-installation); a package
   upgrade alone does not migrate hooks. Use a disposable repository for first
   installations and choose mode/policy explicitly.

If `aigenguard --version` shows an old version after install, run `hash -r` or
`rehash` and retry.
