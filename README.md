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
cargo test
```
This command will automatically run all tests in the project.

### 3. Run Specific Module Tests
```bash
cargo test --test test_avss
```
Here, `test_avss` is the name of the integration test file. Modify it according to your actual file name.
