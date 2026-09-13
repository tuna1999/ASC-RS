# Corpus — APK and DEX fixtures

All artifacts under this directory are immutable inputs to the differential
harness. SHA-256 hashes are recorded below; if any of them change the
golden outputs in `tests/fixtures/golden/` are no longer valid and the
capture script must be re-run.

## APKs

Three APKs cover the matrix:

| Path                       | Source                                                    | Bytes     | SHA-256                                                          | DEX layout           |
|----------------------------|-----------------------------------------------------------|-----------|------------------------------------------------------------------|----------------------|
| `apk/com.aurora.store_60.apk`   | F-Droid mirror, https://f-droid.org/repo/com.aurora.store_60.apk | 7,046,295 | `5a5c56f59194d973d335a534b0e359659e1bf49a8ecb8188bf8c2f8d6c68ffaa` | multidex (2 entries) |
| `apk/org.fdroid.fdroid_1016000.apk` | F-Droid mirror, https://f-droid.org/repo/org.fdroid.fdroid_1016000.apk | 10,358,056 | `da57e6652aa8dd4d6daa40bda233f44cb41811aefd84157390e12017cddf4644` | multidex (2 entries) |
| `apk/workload.apk`         | Built locally from `reference/asc/tests/fixtures/reference-workload.zip` | 9,577,748 | `9054028d75e1a80a60c52e38de3d4c0e6c0e0320ff973491f293de14d3fa70c9` | single-dex           |

`workload.apk` is a deterministic synthetic ZIP (`ZIP_STORED`) that wraps the
`classes.dex` extracted from the reference oracle's own
`reference-workload.zip`. It exists so we have a single-dex fixture whose
contents are tied to the oracle's own test corpus — the differential harness
can then test both single-dex and multidex paths.

The two F-Droid APKs were downloaded on 2026-09-13 over HTTPS from the F-Droid
CDN; the bundle listed above is what was actually retrieved. They give
real-world multidex coverage (one `classes.dex`, one `classes2.dex`,
deflate-compressed) and exercise the per-DEX iteration as well as inflate
performance.

## Extracted DEX files

The `.dex` files for each APK are extracted into `corpus/dex/` so that
`tinydex` / `asc-rs` can also consume them directly without paying the
inflate cost.

| Path                          | Bytes     | Magic           | SHA-256                                                          |
|-------------------------------|-----------|-----------------|------------------------------------------------------------------|
| `dex/aurora_classes.dex`      | 6,312,544 | `dex\n035\x00`  | `0ac2dae4b0219cde77aa8928cc438cdeec4fda5b4f617d2fac04f32669fa6585` |
| `dex/aurora_classes2.dex`     | 2,648,164 | `dex\n035\x00`  | `28dfc76e99f4a0bb57e6bcbab0218db19fb119c059520f31583ec4c21af707a7` |
| `dex/fdroid_classes.dex`      |10,144,264 | `dex\n035\x00`  | `2a0a73129d23717f84baf45f6e9929d33490bf9a7f1572ff3ccd4ab9db95dddf` |
| `dex/fdroid_classes2.dex`     | 4,563,456 | `dex\n035\x00`  | `67d8863c9e15e506ce204287a0f751dde8b17c6efcc1dbf192bd73bea5fc6730` |
| `dex/workload_classes.dex`    | 9,577,628 | `dex\n039\x00`  | `5cd2401e9ec9a41fc5f78d06acb10d9f334a973bb82df9af381d3e5024aee337` |

The `aurora_*` and `fdroid_*` files are extracted from the corresponding
APK; the `workload_*` file is extracted from the reference workload zip and
has its own magic (`dex\n039\x00` instead of `dex\n035\x00`).

## Reproduction

To re-download the F-Droid APKs (must produce the same SHA-256 to keep
golden outputs valid):

```bash
curl -fL -A 'curl/8' -o corpus/apk/com.aurora.store_60.apk \
  https://f-droid.org/repo/com.aurora.store_60.apk
curl -fL -A 'curl/8' -o corpus/apk/org.fdroid.fdroid_1016000.apk \
  https://f-droid.org/repo/org.fdroid.fdroid_1016000.apk
```

To re-extract the dex files from those APKs:

```bash
python -c "
import zipfile, os
for apk, prefix in [
    ('corpus/apk/com.aurora.store_60.apk', 'aurora'),
    ('corpus/apk/org.fdroid.fdroid_1016000.apk', 'fdroid'),
]:
    z = zipfile.ZipFile(apk)
    for n in [x for x in z.namelist() if x.endswith('.dex')]:
        data = z.read(n)
        out = f'corpus/dex/{prefix}_{n}'
        with open(out,'wb') as f: f.write(data)
        print(out, len(data))
"
```

To rebuild `workload.apk`:

```bash
python -c "
import zipfile
with zipfile.ZipFile('reference/asc/tests/fixtures/reference-workload.zip') as z:
    data = z.read('classes.dex')
with zipfile.ZipFile('corpus/apk/workload.apk','w',compression=zipfile.ZIP_STORED) as z:
    z.writestr('classes.dex', data)
with open('corpus/dex/workload_classes.dex','wb') as f: f.write(data)
"
```

## Why these fixtures

The fixture mix was chosen to give the differential harness three different
shapes:

1. **Synthetic single-dex** (`workload.apk`): exercises the simplest path
   (one `classes.dex` per APK) and lets us pin behavior against a corpus
   the oracle itself was tested against.
2. **Multidex, deflate** (Aurora Store): exercises the central-directory
   scan ordering, inflate path, and per-DEX iteration over two real-world
   DEX files.
3. **Multidex, larger** (F-Droid): same shape as Aurora but with
   approximately 2x the bytecode size — useful for catching O(n²) mistakes
   and for measuring scaling.

All three are stable: the SHA-256 of the extracted DEX files is identical
to what the oracle would see during `findrefs` / `getclass` execution.
