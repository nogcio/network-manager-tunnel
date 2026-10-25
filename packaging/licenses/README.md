# Supplementary third-party notices

The AUR build generates `cosmic-notices.txt` and `service-notices.txt` with
cargo-about for the two production dependency graphs. This directory supplies
supplementary asset notices and `SOURCE-AVAILABILITY.md` instructions. BoringSSL's
native license and certificate-data notices are included through the collector's
configuration and locked sources. See `docs/dependency-review.md` in the source
repository for evidence and limitations. Generation is not a legal certification:
review canonical-text fallbacks and material that Cargo metadata does not describe
when inspecting actual package contents.

| Local file | Original source |
| --- | --- |
| `Open-Sans-OFL.txt` | `pop-os/libcosmic@430f3d48a97d8779f9c1985473912e594ccca1ae/res/open-sans/LICENSE` |
| `Noto-OFL.txt` | `pop-os/libcosmic@430f3d48a97d8779f9c1985473912e594ccca1ae/res/noto/LICENSE` |
| `lwIP-COPYING.txt` | `nogcio/meow-rs@fbbb9d23a9fbcba28ac0ed69c18e2aea95e35e21/crates/meow-lwip/COPYING` |

License text is retained with LF line endings (lwIP's final empty line is omitted);
no fonts or native source code are
copied here. The fonts are embedded by the locked toolkit; the selected lwIP
source is compiled by its wrapper. Revisit these notices whenever sources change.

The upstream Noto license file has no copyright line. Both embedded Noto Sans Mono
Regular and Bold fonts' name tables additionally state:

> Copyright 2015 Google LLC. All Rights Reserved.
>
> Noto is a trademark of Google LLC.
>
> Monotype Imaging Inc.
>
> Monotype Design Team
>
> Designed by Monotype design team.

These accompanying notices are retained here, without rewriting the upstream OFL
file or claiming the fonts are modified. The AUR recipe includes this document
alongside the three license texts, generated dependency notices and source
availability information. Publishing these retained notices with workspace source
does not claim that package installation or runtime acceptance has been verified.
