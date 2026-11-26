# Guard pack signing keys

sensr-guard accepts a pack delivered between releases only if its detached
minisign signature verifies against a key in this list. The built-in `core`
pack ships in the image and is trusted without a signature.

- One minisign public key per `*.pub` file (the two-line `minisign.pub`
  format, as written by `minisign -G`). Files without a `.pub` extension are
  ignored.
- The image ships them under `share/sensr-guard/keys`; the daemon loads every
  `*.pub` file in that directory.
- The release signing secret key is the GitHub Actions secret
  `GUARD_PACK_KEY`; its public half is added here as a `.pub` file.
- To rotate, add the new `.pub` first and release, sign with the new key,
  then remove the old file in a later release. To revoke a key, delete its
  file and release.
- No production key is committed yet. With an empty list no signed pack can
  be installed and only the built-in packs run.
- Pack archives are `.tar.zst` containing exactly `manifest.json`, one
  `*.bpf.o` and `rules.json`; sign the archive bytes (`minisign -S -m pack.tar.zst`).
