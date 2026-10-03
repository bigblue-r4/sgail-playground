# Hidden Text X-Ray

**Try it: https://bigblue-r4.github.io/sgail-playground/**

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

## License

MIT. SGAIL Labs.
