# Recorded verification

Current engineering result: PASS. 17 tests passed from the built wheel installed into a dedicated verification environment. Tests ran outside the source directory with PYTHONPATH unset; the recorded imported module path is in site-packages.

Test files: `tests/test_review.py` and `tests/test_cli.py`. These cover supported inputs, malformed/unsupported inputs, resource boundaries, privacy-safe output, input SHA-256/preservation, symlink rejection, read-error privacy and CLI statuses. 600 additional seeded truncation/byte-change/append mutations produced no unexpected exception; mutation checking is crash-resilience evidence, not a proof that every mutation is rejected.

Wheel SHA-256: `25c7d79e1f4c6dbaf0a2c6381943b4fe6b5d73069f1de0ba128e76fe0d70a3b7`. Full build/install/test logs and local environment identity are retained in the private batch validation directory. Absolute machine paths are deliberately absent from this publishable project.

Source/layout checks: Upstream UsnJrnl handles file-like streams and optional NTFS/MFT reconstruction. The new stream validator includes v2/v3/v4 envelopes and excludes volume/path reconstruction.

Cross-source oracle checks where relevant: real SQLite-generated WAL commits, publicly supplied NTFS USN v2/v4 test records, an 800-record multi-level tree emitted by ds-store 1.3.3, a v2 record emitted by mac-alias 2.2.3, a PNG emitted by Pillow 12.3.0 and a DFXML fixture independently checked against the fixed upstream XSD using local imports. Only the applicable fixtures are present in each project. YARA valid/invalid/includes behavior is checked against yara-python 4.5.4.

Complete new runtime files and their current hashes are listed in SOURCE_MANIFEST.json. Their input branches, integer/offset conversions, loops, exception/unsupported paths and output fields were reviewed. No target acquisition, remote fetch, target/sample execution or content recovery is implemented. YARA uses an isolated compilation subprocess; all other runtime analyzers have no process execution path.

Limitations: the recorded tests do not prove full upstream equivalence, all possible input behavior, evidence authenticity, personal authorship or CVP qualification. GitHub publication and Linux CI are separate gates; CVP suitability/approval remains OPEN pending the actual authorized restricted-work and applicant/organization evidence.
