# appcast

Public, signed information that coldWork's apps read: AI prices, each app's settings for its AI actions, and (as each
app adopts it) its newest version and change log. Every `.json` file has a `.sig` beside it: an Ed25519 signature
(hex) that the apps check against `public-key.txt` before using the file. Apps read this repository only at moments
the user starts; nothing here is fetched in the background.

- `ai/prices.json` - models, prices (US$ per million tokens, standard tier) and model sizes, shared by every app.
  Shown only until `show_until`; after that an app points the user to the provider's own pricing page.
- `notescope/ai-acts.json` - which model size each NoteScope AI action uses.
- `public-key.txt`, `ed25519.py` - the public key and the verification code (RFC 8032 reference implementation):
  `python ed25519.py verify <file> <public key> <signature>`.

Sources are the providers' own pricing pages, named in `ai/prices.json`. Not affiliated with any provider.
