use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

// RTLD_NOW from dlfcn.h on macOS.
const RTLD_NOW: c_int = 0x2;

#[link(name = "System")]
unsafe extern "C" {
    fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
    fn dlerror() -> *const c_char;
    fn dlclose(handle: *mut c_void) -> c_int;
}

pub fn try_dlopen_external_library() {
    let path = match std::env::var("TEST_DYLIB_PATH") {
        Ok(value) if !value.is_empty() => value,
        _ => {
            eprintln!("[probe] TEST_DYLIB_PATH not set; skipping dlopen test");
            return;
        }
    };

    let c_path = match CString::new(path.as_bytes()) {
        Ok(value) => value,
        Err(_) => {
            eprintln!("[probe] TEST_DYLIB_PATH contains NUL; skipping dlopen test");
            return;
        }
    };

    unsafe {
        dlerror();
        let handle = dlopen(c_path.as_ptr(), RTLD_NOW);
        if !handle.is_null() {
            eprintln!("[probe] dlopen succeeded: {}", path);
            dlclose(handle);
            return;
        }

        let err = dlerror();
        if !err.is_null() {
            let msg = CStr::from_ptr(err).to_string_lossy();
            eprintln!("[probe] dlopen failed: {}", msg);
        } else {
            eprintln!("[probe] dlopen failed: unknown error");
        }
    }
}
