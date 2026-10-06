# SGAIL playground

Click-and-try pages for SGAIL's open-source security tools. Each runs the real code in your browser,
compiled to WebAssembly. Nothing you type is sent anywhere.

| page | what you do | what runs |
|---|---|---|
| **[Hidden Text X-Ray](https://bigblue-r4.github.io/sgail-playground/)** | paste text, see hidden characters, look-alike letters and encoded instructions | deobfuscate + unicode-interference |
| **[Tamper-Evident Farm Log](https://bigblue-r4.github.io/sgail-playground/witness/)** | try to change a poultry house's log and see what the witness catches | the kiss-protocol witness |

# Hidden Text X-Ray

Text can look harmless to a person and carry something else to an AI model: look-alike letters from
another alphabet, invisible characters, encoded instructions. Paste anything into the page and it shows
what's really there, what each step of the clean-up undid, and what a model would receive.

It runs entirely in your browser. Nothing you type is sent anywhere.

## What runs

The page runs the real detectors, compiled to WebAssembly, not a mock-up:

| crate | version | job on this page |
|---|---|---|
| [deobfuscate](https://github.com/bigblue-r4/deobfuscate-rs) | 1.18.1 | undoes the hiding step by step; gives the verdict (clean / flag / block) |
| [unicode-interference](https://github.com/bigblue-r4/unicode-interference) | 1.0.0 | labels each character's alphabet; finds letters from another alphabet |

Both come from crates.io at exactly those versions. `xray/` is a thin wrapper that runs both over the
same input and returns JSON for the page. It adds no detection of its own. Two things it does only for
display: it names invisible characters so they can be drawn, and it labels a Cyrillic or Greek
look-alike as a disguise only inside an otherwise-Latin word.

## Where it stops

These are on the page too, under **Where it stops**:

- **It finds hidden text, not harmful meaning.** "Ignore all previous instructions" written in plain
  words passes clean. In a real system this is one layer among several.
- **Known false alarm:** everyday text mixing Russian and English is flagged for review even though
  nothing is hidden.

## Build and test

```sh
cd xray && cargo test                       # the example buttons are the test fixture
wasm-pack build --release --target web --no-typescript --out-dir ../site/pkg
cd .. && node scripts/smoke.mjs             # the browser build gives the same answers
python3 -m http.server -d site 8000         # open http://127.0.0.1:8000
```

`site/examples.json` holds the example buttons and the verdict and steps each one promises. The Rust
tests and the smoke test both fail if the detectors stop matching what the page says. A link like
`…/#tags` opens straight onto an example.

CI runs the tests, builds the page and deploys it to GitHub Pages on every push to `main`.

# Tamper-Evident Farm Log

`site/witness/`, built from `witness/`. One night in a poultry house, recorded by the Harborlight witness
([kiss-protocol](https://github.com/bigblue-r4/kiss-protocol) v3.3.3). Visitors try to change the
record: edit an entry, delete one, cut off the end, delete the signed head, sign a fresh head with a different key, or do a full cover-up that
re-signs the head with the machine's own keys. Two verdicts update live (`witness verify` on the
machine, `witness audit` against a mirror), and a Merkle tree diagram shows the changed hashes in red
from the edited entry up to the root.

**What runs.** `witness/internal/` is copied unchanged from kiss-protocol by
`witness/scripts/sync-from-kiss.sh` (merkle, store, encrypt, signer). The browser has no disk, so
`witness/demo` ports the store's head checks and the audit comparison with only the file I/O removed.
`demo/port_test.go` writes logs to disk with the real `store.Append`, tampers with the files, and
requires the real `store.Open` and the port to reach the same verdict with the same error. A
deliberately broken port fails those tests.

**Where it stops.** It detects and records; it doesn't prevent anything or control the house. The
head is signed on the same machine, so full control of that machine lets someone re-sign a rewritten
log and pass the local check. The page shows exactly that, and the mirror catching it. Encryption at
rest isn't shown.

```sh
cd witness && go test ./...
GOOS=js GOARCH=wasm go build -o ../site/witness/witness.wasm ./cmd/wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" ../site/witness/
```

After a kiss-protocol release: `witness/scripts/sync-from-kiss.sh <kiss checkout>`, then `go test ./...`.

## License

MIT. SGAIL Labs.
