---
mpp: patch
alloy-transport-mpp: patch
---

Fixed clients dropping `WWW-Authenticate` values that contain non-ASCII bytes, so challenges from servers that send Latin-1 text raw (as mppx does) could not be paid. Received challenge headers are now decoded as ISO-8859-1 through the new `parse_www_authenticate_all_bytes`.
