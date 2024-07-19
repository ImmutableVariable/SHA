# SHA

This is my implementations of the SHA-1 and SHA-256 hashing algorithms in Rust. DO NOT USE THIS CODE FOR ANYTHING IMPORTANT. This is just a learning exercise for me. 
I might add more sha algorithms in the future.

## Usage

## Sha 1 (or sha256)
```rust
use sha::sha1::hash; // or sha::sha256::hash

fn main() {
    let message = b"hello world";
    let hash = hash(message);    
    println!("{:?}", hash);

    // print the hash as a hex string
    for h in hash.iter() {
        print!("{:x}", h);
    }
    println!();
}
```