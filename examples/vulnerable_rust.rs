use std::process::Command;
use std::fs;
use std::ptr;
use std::ffi::CString;
use std::os::raw::c_char;

// 1. Unsafe memory operations
unsafe fn buffer_overflow() {
    let mut buffer: [u8; 10] = [0; 10];
    let src = b"This is a very long string that will overflow";
    // Potential buffer overflow
    ptr::copy_nonoverlapping(src.as_ptr(), buffer.as_mut_ptr(), src.len());
}

// 2. Use after free (simulated with raw pointers)
unsafe fn use_after_free() {
    let layout = std::alloc::Layout::from_size_align(100, 1).unwrap();
    let ptr = std::alloc::alloc(layout);
    std::alloc::dealloc(ptr, layout);
    // Using freed memory
    *ptr = 42;
}

// 3. Command injection
fn command_injection(filename: &str) {
    // User input directly passed to shell command
    let output = Command::new("cat")
        .arg(filename)
        .output()
        .expect("Failed to execute command");

    println!("{}", String::from_utf8_lossy(&output.stdout));
}

// 4. Path traversal
fn path_traversal(filename: &str) {
    // No validation of filename - allows directory traversal
    let path = format!("/uploads/{}", filename);
    match fs::read_to_string(&path) {
        Ok(content) => println!("{}", content),
        Err(e) => eprintln!("Error: {}", e),
    }
}

// 5. Hardcoded credentials
const DATABASE_PASSWORD: &str = "admin123";
const API_KEY: &str = "sk-1234567890abcdef";
const JWT_SECRET: &str = "super_secret_key";

// 6. Weak cryptography
fn weak_crypto(password: &str) -> String {
    // Using MD5 (would require external crate, simulated here)
    format!("md5_hash_of_{}", password) // Placeholder for actual MD5
}

// 7. Insecure random number generation
fn insecure_random() -> u32 {
    // Using system time as seed (predictable)
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    // Simple LCG (not cryptographically secure)
    seed.wrapping_mul(1103515245).wrapping_add(12345)
}

// 8. Integer overflow (when compiled without overflow checks)
fn integer_overflow(size: usize) {
    // Potential integer overflow
    let total_size = size * 1000000;
    println!("Allocating {} bytes", total_size);
    // In unsafe context, this could lead to buffer overflows
}

// 9. Race condition (using unsafe static)
static mut COUNTER: i32 = 0;

unsafe fn race_condition() {
    // Concurrent access to static without synchronization
    for _ in 0..1000 {
        COUNTER += 1; // Not thread-safe
    }
}

// 10. Null pointer dereference
unsafe fn null_pointer_deref() {
    let null_ptr: *mut i32 = ptr::null_mut();
    // Dereferencing null pointer
    *null_ptr = 42;
}

// 11. Double free (simulated)
unsafe fn double_free() {
    let layout = std::alloc::Layout::from_size_align(100, 1).unwrap();
    let ptr = std::alloc::alloc(layout);
    std::alloc::dealloc(ptr, layout);
    std::alloc::dealloc(ptr, layout); // Double free
}

// 12. Uninitialized memory access
unsafe fn uninitialized_memory() {
    let mut uninit: std::mem::MaybeUninit<[u8; 100]> = std::mem::MaybeUninit::uninit();
    let ptr = uninit.as_mut_ptr() as *mut u8;
    // Reading uninitialized memory
    let value = *ptr;
    println!("Uninitialized value: {}", value);
}

// 13. Format string vulnerability (simulated)
fn format_string_vuln(user_input: &str) {
    // Direct use of user input in format string (conceptual in Rust)
    println!("{}", user_input); // In C, this would be printf(user_input)
}

// 14. Information disclosure
fn information_disclosure(input: &str) {
    match input.parse::<i32>() {
        Ok(_) => println!("Valid number"),
        Err(e) => {
            // Exposing sensitive information in error messages
            println!("Parse error: {}", e);
            println!("Internal database path: /var/lib/app/prod.db");
            println!("Secret key location: {}", JWT_SECRET);
        }
    }
}

// 15. Unsafe transmute
unsafe fn unsafe_transmute(value: u64) -> &'static str {
    // Unsafe transmutation that could lead to memory safety issues
    std::mem::transmute(value)
}

// 16. Memory leak (intentional)
fn memory_leak() {
    for _ in 0..1000 {
        let leaked = Box::new([0u8; 1024]);
        Box::leak(leaked); // Intentionally leak memory
    }
}

// 17. Unsafe slice creation
unsafe fn unsafe_slice_creation(ptr: *const u8, len: usize) -> &'static [u8] {
    // Creating slice from raw pointer without validation
    std::slice::from_raw_parts(ptr, len)
}

// 18. Time-of-check to time-of-use (TOCTOU)
fn toctou_vulnerability(filename: &str) {
    // Check if file exists
    if fs::metadata(filename).is_ok() {
        // Time gap here - file could be changed/deleted
        std::thread::sleep(std::time::Duration::from_millis(100));
        // Use file (could fail or access different file)
        let _ = fs::read_to_string(filename);
    }
}

// 19. Unsafe FFI
extern "C" {
    fn dangerous_c_function(input: *const c_char) -> i32;
}

unsafe fn unsafe_ffi(user_input: &str) {
    let c_string = CString::new(user_input).unwrap();
    // Calling unsafe C function with user input
    dangerous_c_function(c_string.as_ptr());
}

// 20. Concurrent modification
use std::sync::Arc;

fn concurrent_modification() {
    let data = Arc::new(vec![1, 2, 3, 4, 5]);

    for _ in 0..10 {
        let data_clone = Arc::clone(&data);
        std::thread::spawn(move || {
            // This would be unsafe if we could modify the Vec
            // Simulating unsafe concurrent access
            unsafe {
                let ptr = data_clone.as_ptr() as *mut i32;
                *ptr = 999; // Undefined behavior in concurrent context
            }
        });
    }
}

fn main() {
    println!("Vulnerable Rust examples compiled successfully");

    // Example usage (commented to prevent actual unsafe execution)
    // unsafe { buffer_overflow(); }
    // command_injection("file.txt; rm -rf /");
    // path_traversal("../../../etc/passwd");

    println!("Note: Many examples require 'unsafe' blocks and may cause undefined behavior");
}
