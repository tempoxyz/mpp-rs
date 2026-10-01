---
mpp: patch
---

Fixed zero-amount Tempo proof challenges not being single-use: the replay marker was keyed by the proof signature, so a second account or a second signature could reuse the same challenge. The marker is now keyed by challenge id (`mpp:charge:proof:{id}`), as in mppx.
