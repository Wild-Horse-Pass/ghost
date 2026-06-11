//! iOS-specific FFI bindings
//!
//! Provides C-callable functions for iOS Keychain access and biometric
//! checks.  These are called from Swift via the bridging header.
//!
//! On iOS builds (`target_os = "ios"`), the functions use Apple's
//! Security.framework through the `security-framework` crate.
//! On non-iOS builds the functions are omitted.

/// iOS Keychain integration callback type.
///
/// `success` indicates whether the operation succeeded.
/// `data` + `len` point to the returned bytes (only valid when success is true).
pub type KeychainCallback = extern "C" fn(success: bool, data: *const u8, len: usize);

// ---------------------------------------------------------------------------
// Keychain store / retrieve
// ---------------------------------------------------------------------------

/// Store data in iOS Keychain.
///
/// Uses `kSecClassGenericPassword` with the given service + key (account).
/// Accessibility is set to `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
///
/// # Safety
/// Called from Swift — raw C string and byte pointers must be valid for the
/// duration of the call.
#[no_mangle]
#[cfg(target_os = "ios")]
pub unsafe extern "C" fn ghost_keychain_store(
    service: *const std::os::raw::c_char,
    key: *const std::os::raw::c_char,
    data: *const u8,
    data_len: usize,
) -> bool {
    use std::ffi::CStr;

    if service.is_null() || key.is_null() || data.is_null() {
        return false;
    }
    let service_str = match CStr::from_ptr(service).to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let key_str = match CStr::from_ptr(key).to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let bytes = std::slice::from_raw_parts(data, data_len);

    keychain_store_impl(service_str, key_str, bytes)
}

/// Retrieve data from iOS Keychain.
///
/// The result is delivered via `callback` to avoid returning heap-allocated
/// data across the FFI boundary.
///
/// # Safety
/// Called from Swift — raw C string pointers must be valid.
#[no_mangle]
#[cfg(target_os = "ios")]
pub unsafe extern "C" fn ghost_keychain_retrieve(
    service: *const std::os::raw::c_char,
    key: *const std::os::raw::c_char,
    callback: KeychainCallback,
) {
    use std::ffi::CStr;

    if service.is_null() || key.is_null() {
        callback(false, std::ptr::null(), 0);
        return;
    }

    let service_str = match CStr::from_ptr(service).to_str() {
        Ok(s) => s,
        Err(_) => {
            callback(false, std::ptr::null(), 0);
            return;
        }
    };
    let key_str = match CStr::from_ptr(key).to_str() {
        Ok(s) => s,
        Err(_) => {
            callback(false, std::ptr::null(), 0);
            return;
        }
    };

    match keychain_retrieve_impl(service_str, key_str) {
        // SAFETY: The callback is invoked synchronously while `data` is alive
        // on the stack. The caller (Swift) must copy the data within the callback
        // — the pointer is invalid after the callback returns.
        Some(data) => callback(true, data.as_ptr(), data.len()),
        None => callback(false, std::ptr::null(), 0),
    }
}

/// Delete an entry from iOS Keychain.
///
/// # Safety
/// Called from Swift — raw C string pointers must be valid.
#[no_mangle]
#[cfg(target_os = "ios")]
pub unsafe extern "C" fn ghost_keychain_delete(
    service: *const std::os::raw::c_char,
    key: *const std::os::raw::c_char,
) -> bool {
    use std::ffi::CStr;

    if service.is_null() || key.is_null() {
        return false;
    }

    let service_str = match CStr::from_ptr(service).to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let key_str = match CStr::from_ptr(key).to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    keychain_delete_impl(service_str, key_str)
}

// ---------------------------------------------------------------------------
// Biometric availability
// ---------------------------------------------------------------------------

/// Check if Face ID / Touch ID is available on this device.
///
/// Uses `LAContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`.
#[no_mangle]
#[cfg(target_os = "ios")]
pub extern "C" fn ghost_biometric_available() -> bool {
    biometric_available_impl()
}

// ---------------------------------------------------------------------------
// Implementation (iOS)
// ---------------------------------------------------------------------------
//
// Uses Core Foundation / Security.framework via `core-foundation` and
// `security-framework` crates which are available on iOS targets.

#[cfg(target_os = "ios")]
fn keychain_store_impl(service: &str, key: &str, data: &[u8]) -> bool {
    use security_framework::passwords::{delete_generic_password, set_generic_password};

    // Delete any existing entry first to avoid errSecDuplicateItem.
    let _ = delete_generic_password(service, key);

    set_generic_password(service, key, data).is_ok()
}

#[cfg(target_os = "ios")]
fn keychain_retrieve_impl(service: &str, key: &str) -> Option<Vec<u8>> {
    use security_framework::passwords::get_generic_password;

    get_generic_password(service, key).ok()
}

#[cfg(target_os = "ios")]
fn keychain_delete_impl(service: &str, key: &str) -> bool {
    use security_framework::passwords::delete_generic_password;

    delete_generic_password(service, key).is_ok()
}

#[cfg(target_os = "ios")]
fn biometric_available_impl() -> bool {
    // LAContext is only available at runtime on a real device.
    // We use the objc crate to call into LocalAuthentication.framework.
    //
    // ```objc
    //   LAContext *ctx = [[LAContext alloc] init];
    //   BOOL ok = [ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
    //                              error:nil];
    // ```
    #[cfg(target_os = "ios")]
    {
        use objc::runtime::Object;
        use objc::{class, msg_send, sel, sel_impl};

        unsafe {
            let la_context_class = class!(LAContext);
            let ctx: *mut Object = msg_send![la_context_class, alloc];
            let ctx: *mut Object = msg_send![ctx, init];
            if ctx.is_null() {
                return false;
            }
            // LAPolicyDeviceOwnerAuthenticationWithBiometrics = 1
            let policy: i64 = 1;
            let null_ptr: *mut Object = std::ptr::null_mut();
            let ok: bool = msg_send![ctx, canEvaluatePolicy:policy error:null_ptr];
            let _: () = msg_send![ctx, release];
            ok
        }
    }
    #[cfg(not(target_os = "ios"))]
    {
        false
    }
}
