# Fuzzing

The three targets of this crate cover the surfaces where `stenoxide` reads
input somebody else produced. Everything else — the cover, the payload, the
passphrase — is put there by whoever runs the binary. These three are not:

| Target | Stands where | Feeds | Checks |
|---|---|---|---|
| `loader` | an eavesdropper | arbitrary bytes | `load_and_validate` and `probe_geometry` |
| `extract` | an eavesdropper | an arbitrary container | the whole pipeline under one password |
| `decompress` | the *sender* | arbitrary authenticated content | the decompressor past the tag |

The value of a campaign is not the crashes — this crate denies `unsafe` and
routes every fallible operation through `Result`, so a campaign may well find
nothing — but the regression tests it produces. **Anything a campaign finds is
translated into a test in the ordinary suite, on stable Rust, on every CI;
that test is the deliverable, not the campaign.**

## Running a campaign

`cargo-fuzz` needs a nightly toolchain and libFuzzer. On Windows its support is
poor — the AddressSanitizer runtime is linked as `asan_dynamic-x86_64.dll`, which
the MSVC toolchain does not ship, and a build without it (`--sanitizer=none`)
fails to link the sanitizer-coverage symbols the runtime normally provides. A
campaign is a Linux job: WSL, a container, or `workflow_dispatch`. The targets
are written and versioned the same either way.

```text
# one time, on the machine that will run campaigns
rustup toolchain install nightly
cargo install cargo-fuzz

# seed the corpus once per checkout (a release build: the cover is a 2000x2000
# image drawn a pixel at a time and then judged by the hash and texture gates)
cargo run --release --bin seed_corpus

# a short smoke run to confirm the target starts and finishes executions
cargo +nightly fuzz run decompress -- -runs=1000

# the real thing. Two hours, both cores, and stop on the first finding.
# Note the omission of -runs: 0 means "no runs" and ends the campaign after the
# corpus; omitting it (or -runs=-1) runs until -max_total_time expires.
cargo +nightly fuzz run loader -- -max_total_time=7200 -jobs=2
cargo +nightly fuzz run extract -- -max_total_time=7200 -jobs=2
cargo +nightly fuzz run decompress -- -max_total_time=7200 -jobs=2
```

`decompress` is the target the decompression ceiling in `crypto::aead` was
written for. Before that ceiling existed, a campaign against it was expected to
end with the machine swapping rather than with a report; with it, the same
input comes back as an error and `-rss_limit_mb` is what says so.

## How the seeds are built

`seed_corpus` produces, under `fuzz/corpus/` (gitignored):

- **loader** — a container that clears every gate of layer 1, plus three
  refused inputs: a bare PNG signature, a JPEG signature, and an empty file.
- **extract** — the same plain container and a *stego* container embedding a
  message under the target's own password, so the fuzzer starts on the far side
  of every gate instead of spending its budget rediscovering the PNG format.
- **decompress** — an ordinary Zstandard frame and one that expands eight
  thousand times past its own size.

## What the targets assert

All three treat a panic as a crash; that is libFuzzer's job, not theirs.
`extract` additionally asserts the observable contract of the extraction
surface: a wrong password, an image with nothing in it and a damaged payload
are one error on purpose, and an input that splits them apart is a finding.
`decompress` checks once, at process start, that its copy of the associated
data really opens through the crate's own entry point, so a green run means
the target was measuring the decompressor and not the AEAD.
