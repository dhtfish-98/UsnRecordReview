# Source and contribution record

Technical source: [fox-it/dissect.ntfs](https://github.com/fox-it/dissect.ntfs) at fixed commit `7f021dd1182eb6f9b6a2dbd19cf2e29143ea654d`. License: `AGPL-3.0-or-later`; the original license text and original copyright notices are preserved.

New implementation author: **dhtfish98**. This project implements the explicitly selected standalone scope below. It is not presented as original ownership of the upstream algorithms or as a full rewrite of an upstream platform. No source files have merely been renamed into the runtime package.

Scope: Extracted USN stream versions 2, 3 and 4: aligned record/page padding, bounded name offsets and UTF-16, signed nonnegative USNs, sequence ordering, v4 extent sizes/ranges and continuation declarations.

The upstream entry points, format layouts and relevant default file/network/execution paths were inspected in the fixed files listed in SOURCE_MANIFEST.json. Complete new runtime files are reviewed separately; this does not imply audit of unselected upstream platform code.

Excluded upstream capabilities: NTFS volume access, MFT resolution, deleted-record carving, path reconstruction and cause/tampering attribution.

The repository owner must verify their actual contribution and authorization before using this record in an application. No CVE, rejected-model task, CVP acceptance or personal identity evidence has been invented.
