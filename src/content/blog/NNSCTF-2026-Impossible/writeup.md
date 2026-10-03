---
author: ch1ko1
title: "NNSCTF 2026 / Crypto / Impossible"
description: "In the ashes of a ceremony held long ago, you found a secret that was not hidden nearly well enough."
pubDate: "Oct 01 2026"
heroImage: "/writeups/ch1ko1.jpg"
---

## Challenge

We are given a Rust crate (`impossible-player`) built on `bellman 0.1.0` / `pairing 0.14.2`, a `vk.bin`, a `secret` file, and a remote service. The service greets us with:

```
impossible
authorized balance: 100
requested mint: 1000000000
submit <ceremony_id>:<proof>
>
```

So we have to submit a Groth16 proof (BLS12-381) that convinces the verifier we are allowed to mint **1,000,000,000** when our authorized balance is only **100**.

The circuit lives in `src/lib.rs`:

```rust
impl Circuit<Bls12> for MintCircuit {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let amount = cs.alloc_input(|| "public mint amount", ...)?;
        let balance = cs.alloc(|| "authorized balance", ...)?;
        cs.enforce(
            || "mint cannot exceed balance",
            |lc| lc + balance,
            |lc| lc + CS::one(),
            |lc| lc + amount,
        );
        cs.enforce(
            || "fixed authorized balance",
            |lc| lc + balance,
            |lc| lc + CS::one(),
            |lc| lc + (fr(100), CS::one()),
        );
        Ok(())
    }
}
```

and the verifier only ever checks the one public input we care about:

```rust
pub const CLAIM: u64 = 1_000_000_000;

pub fn verify(vk: &Public, proof: &Proof) -> bool {
    if proof.ceremony_id != vk.ceremony_id || proof.claim != CLAIM {
        return false;
    }
    let pvk = prepare_verifying_key(&vk.vk);
    verify_proof(&pvk, &proof.inner, &[fr(proof.claim)]).unwrap_or(false)
}
```

## Explanation

The name of the challenge is a hint in itself: the circuit makes the task **impossible** for an honest prover. The two constraints say `balance == amount` and `balance == 100`, so the only satisfiable public input is `amount = 100`. Every honest witness for `amount = 1_000_000_000` fails, so I can't just run the prover.

Since Groth16 is sound as long as nobody knows the setup trapdoor, a forged proof should be impossible too. So the question becomes: **does anyone know the trapdoor?**

### Reading the library

Normally a Groth16 setup samples random `alpha, beta, gamma, delta, tau` and throws them away ("[toxic waste](https://neti-soft.com/blockchain-glossary/toxic-waste)"). The verifying key is only the group elements built from them. Looking at `lib.rs`, this setup is not random at all:

```rust
pub fn derive(tau: Fr) -> [Fr; 6] {
    ...
    [
        one(tau, b"alpha"),
        one(tau, b"beta"),
        one(tau, b"gamma"),
        one(tau, b"delta"),
        one(tau, b"g1-scale"),
        one(tau, b"g2-scale"),
    ]
}
```

So every piece of toxic waste is just `BLAKE2b-256(key = label, msg = tau || counter)` with a rejection-sampling counter, so the **whole setup is a deterministic function of a single scalar `tau`**. The same goes for the IC points of the verifying key, which `mint_ic_scalars(tau, alpha, beta, gamma)` computes from the Lagrange basis of the 4th roots of unity evaluated at `tau`:

```
ic0 = (L2*beta + (L0 + L1)*alpha + L1*100) / gamma
ic1 = (L3*beta + L0) / gamma
```

So if we get hold of `tau`, we can recompute `alpha, beta, gamma, delta` and the IC scalars. Learning `tau` is therefore equivalent to learning the whole trapdoor.

### Finding tau

The distribution folder also contains a file called `secret`:

```
PRERZBAL_VQ=3p311q9qso7735r42643s394qp2p10ns
GNH=3894627051107121998319229043008213446770981528672674568925122813412699817
```

The key names look scrambled, but it remains digits and letters with and obvious format of `variable=literal`. Its everyone's favourite: **ROT13!!**

```
CEREMONY_ID=3c311d9dfb7735e42643f394dc2c10af
TAU=3894627051107121998319229043008213446770981528672674568925122813412699817
```

So the ceremony ID that the server expects and the `tau` the whole ceremony was derived from are shipped with the challenge, so the ceremony was never "toxic waste" to begin with.

Before building on that assumption, I re-derived the setup from this `tau` and compared it with `vk.bin`. Checking `alpha*g1s*G1`, `beta*g2s*G2`, `gamma*g2s*G2`, `delta*g1s*G1`, `delta*g2s*G2`, and both IC points against the points in the file all matched, so the leaked `tau` is the real one.

### Forging a proof

The Groth16 verification equation that `bellman` checks, for public inputs `x`, is:

```
e(A, B) = e(alpha_G1, beta_G2) * e(IC0 + x*IC1, gamma_G2) * e(C, delta_G2)
```

Normally nobody can solve this for `(A, B, C)` without a witness, because every group element in the verifying key has an unknown discrete log. Here we know all of them. Write every point as a scalar times its generator (`g1s`, `g2s` are the two "scale" values from `derive`):

```
ALPHA = alpha * g1s	(G1)
BETA  = beta  * g2s	(G2)
GAMMA = gamma * g2s	(G2)
DELTA = delta * g2s	(G2)
ACC   = (ic0 + x*ic1) * g1s     with x = 1_000_000_000   (G1)
```

Then, taking discrete logs on both sides of the pairing equation, it becomes plain arithmetic in the scalar field:

```
a * b = ALPHA*BETA + ACC*GAMMA + c*DELTA	(mod r)
```

where `A = a*G1`, `B = b*G2`, `C = c*G1`. We can pick any `a` and `b` at random and solve for `c`:

```
c = (a*b - ALPHA*BETA - ACC*GAMMA) / DELTA	(mod r)
```

This gives a proof that satisfies the verifier for **any** public input, including `1_000_000_000`, without ever satisfying `balance == 100` or touching the circuit. The constraints only matter to someone who doesn't know the trapdoor.

### Encoding

`decode_proof` expects `<ceremony_id>:<hex>` where the hex is `bellman`'s `Proof::write` output: compressed `A` (G1, 48 bytes) || compressed `B` (G2, 96 bytes) || compressed `C` (G1, 48 bytes), so 192 bytes total. The compressed form is the ZCash BLS12-381 one: the top bit marks compression, the next marks infinity, and the third marks the lexicographically larger `y`. For G2 the `x` coordinate is serialized as `c1 || c0`, and the sign comparison is done on `(c1, c0)`.

The rest is plumbing: the instance is behind TLS (the stub `solve.rs` in the README uses plain TCP, which is only a placeholder), so I connected with `ssl` without certificate verification, read the banner, sent the line, and read until EOF.

## Solution

The full solver is in Python with only `py_ecc` as a dependency. The important part is:

```python
alpha, beta, gamma, delta, g1s, g2s = derive(TAU)
ic0, ic1 = mint_ic_scalars(TAU, alpha, beta, gamma)
...
ALPHA    = alpha * g1s % r
BETA_G2  = beta  * g2s % r
GAMMA_G2 = gamma * g2s % r
DELTA_G2 = delta * g2s % r
acc      = (ic0 * g1s + CLAIM * ic1 * g1s) % r
...
a = random.randrange(1, r)
b = random.randrange(1, r)
c = (a * b - ALPHA * BETA_G2 - acc * GAMMA_G2) * pow(DELTA_G2, -1, r) % r
A, B, C = g1_mul(a), g2_mul(b), g1_mul(c)
...
proof_bytes = enc_g1_compressed(A) + enc_g2_compressed(B) + enc_g1_compressed(C)
```

`derive` and `mint_ic_scalars` are practically ports of the Rust versions (BLAKE2b with the label as the key, rejection sampling `value < r`, Lagrange basis over `omega = root_of_unity^(2^30)`).

```
$ python3 solve.py
[+] Deriving toxic waste from TAU for ceremony 3c311d9dfb7735e42643f394dc2c10af ...
[+] vk.bin sanity check: PASS
[+] Forged proof passes local pairing check.
[+] Proof: 3c311d9dfb7735e42643f394dc2c10af:8271b378...eb26f13c...f2
[+] Submitting to impossible-2b69d6631500.chall.nnsc.tf:1337 (TLS) ...
[+] Server banner (93 bytes):
impossible
authorized balance: 100
requested mint: 1000000000
submit <ceremony_id>:<proof>
>
[+] Server response (52 bytes):
    text: accepted
NNS{1MP05s1B13_PR00fs_Fr0m_c3r3m0NY_4sh35}
```

The flag is `NNS{1MP05s1B13_PR00fs_Fr0m_c3r3m0NY_4sh35}`. The proof was **impossible** only for those who don't know the ceremony's ashes!

# Files
[Solution Python Script](NNS26/solve.py)
[Challenge Archive](NNS26/crypto_impossible.tar.gz)
