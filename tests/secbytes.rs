extern crate sarkara;
#[cfg(unix)] extern crate nix;

use std::{ slice, thread };
use std::sync::Arc;
use std::time::Duration;
use sarkara::utils::SecBytes;


#[test]
fn thread_shared_secbytes_test() {
    let secbytes = Arc::new(SecBytes::new(&[1; 8]).unwrap());
    let secbytes_clone = secbytes.clone();

    thread::spawn(move || {
        secbytes_clone.map_write(|bs| {
            thread::sleep(Duration::from_millis(300));
            bs.clone_from_slice(&[3; 8]);
        });
    });

    let result = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        secbytes.map_read(|bs| {
            assert_eq!(bs, [3; 8]);
            true
        })
    }).join().unwrap();

    assert!(result);
}

#[cfg(unix)]
#[should_panic]
#[test]
fn protect_secbytes_test() {
    use nix::sys::signal;
    extern fn sigsegv(_: i32) { panic!() }
    let sigaction = signal::SigAction::new(
        signal::SigHandler::Handler(sigsegv),
        signal::SA_SIGINFO,
        signal::SigSet::empty(),
    );
    unsafe { signal::sigaction(signal::SIGSEGV, &sigaction).ok() };

    let secbytes = SecBytes::new(&[1; 8]).unwrap();

    let (bs_ptr, bs_len) = secbytes.map_write(|bs| (bs.as_mut_ptr(), bs.len())); // violence get secbytes ptr
    let bs_bytes = unsafe { slice::from_raw_parts_mut(bs_ptr, bs_len) };
    bs_bytes[0] = 0; // SIGSEGV !
}
