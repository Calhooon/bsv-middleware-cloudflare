# The single-use stores' conformance kit on workerd's D1

One test Worker (`src/lib.rs`) exposes `bsv_middleware_core::store::conformance`
over HTTP against the adapter's `D1PrefixStore` and `D1ClaimStore` on a local D1
binding; `run.mjs` drives it in Miniflare (no port left open, no deploy):
the kit's laws in the isolate, a read-await-write store on the same D1 failing
both concurrent prefix laws, and N = 2, 8, 32 simultaneous requests per law.

    cargo install --locked worker-build@0.8.4   # once
    worker-build --release                      # in this directory; writes build/
    npm ci && node run.mjs                      # exits nonzero on any failed law
