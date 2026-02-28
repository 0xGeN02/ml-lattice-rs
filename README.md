# ml-lattice-rs

## Introduction

`ml-lattice-rs` is a Rust-based library for implementing post-quantum cryptographic primitives, specifically **Kyber** and **Dilithium**, which are part of the NIST Post-Quantum Cryptography Standardization. This library is designed to provide secure and efficient implementations of these algorithms for use in post-quantum blockchain systems and other cryptographic applications.

---

## Features

- **Kyber**: A lattice-based key encapsulation mechanism (KEM) for secure key exchange.
- **Dilithium**: A lattice-based digital signature scheme for secure and efficient authentication.

---

## Installation

To get started with `ml-lattice-rs`, clone the repository and build the project:

```bash
# Clone the repository
$ git clone https://github.com/0xGeN02/ml-lattice-rs.git

# Navigate to the project directory
$ cd ml-lattice-rs

# Build the project
$ cargo build --release
```

---

## Usage

Here is a basic example of how to use the Kyber and Dilithium implementations:

```rust
use ml_lattice_rs::kyber;
use ml_lattice_rs::dilithium;

fn main() {
    // Example: Key generation with Kyber
    let (public_key, secret_key) = kyber::keygen();
    println!("Kyber Public Key: {:?}", public_key);

    // Example: Digital signature with Dilithium
    let message = b"Hello, Post-Quantum World!";
    let signature = dilithium::sign(message, &secret_key);
    let is_valid = dilithium::verify(message, &signature, &public_key);
    println!("Signature valid: {}", is_valid);
}
```
