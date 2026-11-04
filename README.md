# NoteScope price file

The AI price file read by the NoteScope app (coldWork). US$ per million tokens, standard tier, as published by each
provider on the date in `issued`. The app shows a price only until `show_until`; after that it points you to your
provider's own pricing page.

- `prices.json` - the prices, the model for each size (small, mid, large) and the size each AI action uses.
- `prices.json.sig` - its Ed25519 signature (hex). The app checks it against `public-key.txt` before using the file.
- `ed25519.py` - the verification code (RFC 8032 reference implementation): `python ed25519.py verify prices.json <public key> <signature>`.

Sources are the providers' own pricing pages, named in `prices.json`. Not affiliated with any provider.
