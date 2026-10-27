# adkg_zk_lib

A project that includes multiple Rust libraries, designed to provide efficient zero-knowledge proof tools and polynomial commitment functionalities.

The project consists of two main libraries: `bi_polynomial` and `zk_tool`, along with integrated tests.

## Install Rust

First, ensure that you have Rust installed on your system. If not, follow these steps to install it:

- Go to the [official Rust website](https://rust-lang.org/tools/install/) to download and install Rust.

After installation, verify that Rust was installed successfully:

```bash
rustc --version
```

If you already have Rust installed, you can update it to the latest version with:

```bash
rustup update
```

## Clone the Project

Clone the project to your local machine using `git`:

```bash
git clone https://github.com/MuZeRoFso/adkg_zk_lib.git
cd adkg_zk_lib
```

## Build and Test the Project

### 1. Build the Project
Building the project is straightforward with Cargo:
```bash
cargo build
```
This will build the entire project and its dependencies.

### 2. Run Tests

To run all the tests, use:
```bash
cargo test --release -- --nocapture
```
This command will automatically run all tests in the project.

### 3. Run Specific Module Tests
```bash
cargo test --test test_adkg -- --nocapture
```
Here, `test_adkg` is the name of the integration test file. Modify it according to your actual file name.

## Manuscript algorithms

`bi_polynomial::gen_polynomial_with_secret(t, f, n, &secrets)` now encodes
`secrets[l] = Phi(0, -l)`, for `1 <= secrets.len() <= f + 1` and `f <= t`.
It calls `interpolate_poly_scalar` on exactly `f + 1` points at
`Y = 0, -1, ..., -f`, filling unused evaluations with independent random
scalars. Since `matrix[y_degree][x_degree]` represents `Phi(X, Y)`, the
resulting coefficients belong in the **first column**. All other coefficients
and the masking polynomial remain random. The manuscript's references to
the first row and to an upper interpolation index of `f + 1` are interpreted
according to its constraint `Phi(0, -l) = secrets[l]` and its stated count of
`f + 1` points (upper index `f`).

The following methods are available on `zk_tool::KzgCrs`:

| Method | Inputs and result |
| --- | --- |
| `eval_beta(accept, targets)` | `accept: &[(Scalar, G1Projective)]` contains exactly `f + 1` verified alpha proofs at distinct source Y coordinates, all opening at the same X coordinate in the same sharing instance. Uses `interpolate_poly_g1` to recover the proof polynomial and returns `Vec<G1Affine>` evaluated at `targets: &[Scalar]`, in the supplied order. |
| `verify_exp(cm, i, j, g_p, hat_g_hat_p, pi)` | Checks exponent evaluations against `cm[j]` at `X = i`, with the same indices as `verify`. Returns `false` for an absent commitment index. |
| `divide_com_at(com, y)` | Evaluates the `f + 1` bivariate row commitments at any `y: &Scalar`, returning the commitment to `Phi(X, y)` and its masking polynomial. Supports `Y = 0, -1, ...` for packed secrets. |
| `verify_exp_at(commitment, x, g_p, hat_g_hat_p, pi)` | Accepts a single selected commitment and `x: &Scalar`, checking `e(commitment - g_p - hat_g_hat_p, h) = e(pi, h_tau - x*h)`. |

Convert proofs returned by `eval` to `G1Projective` before passing them to
`eval_beta`. For sharing, pass target coordinates `1, ..., n`; for secret
reconstruction and key derivation, pass `-Scalar::from(l as u64)`.
`eval_beta` requires previously verified proofs; it cannot check the common
sharing instance or common X coordinate from proof elements alone.
Its outputs are alpha-opening proofs transferred along Y, as specified in
the manuscript, and must be checked against the receiver's sub-commitment.

For key derivation, add the evaluations, proofs, and selected commitments
across dealers before verification. Inputs `g_p` and `hat_g_hat_p` must use
the PCS generators `g` and `hat_g`. When these inputs come from
`schnorr_prove`, use the same `msg` and `dst` setup arguments for PCS and
Schnorr so both generator pairs agree.

The functional tests cover helper-proof interpolation, negative secret
coordinates, rejection of altered openings, and reconstruction of packed
secrets and public keys aggregated across dealers:

```bash
cargo test --offline --release --test test_manuscript
```
