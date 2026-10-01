---
mpp: patch
---

Fixed `TempoSessionProvider::voucher_credential_with_top_up` and `voucher_credential_with_top_up_for_challenge` sizing the top-up from the deposit the server reports while checking the voucher against the provider's own, possibly older, deposit. After a top-up the provider did not make itself, a voucher within the real deposit failed with `voucher cumulative amount exceeds channel deposit`, and a needed top-up was too small. The larger of the two deposits is now used for both, and the local deposit is raised to it.
