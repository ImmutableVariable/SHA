# SHA 1

This is my implementation of the sha1 algorithm, it is pretty simple and not optimized at all, but it works. 
Don't use this in production, it probably has a lot of security vulnerabilities.

## Usage
```rust
use sha1::hash;

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