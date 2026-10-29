//! macOS: quitting from outside the app asks first too.
//!
//! Cmd+Q in the app's menu and the window's close button go through main.rs
//! and ask. Quit from the Dock or the app switcher, from AppleScript, at log
//! out or restart, AppKit asks the app's delegate instead, with
//! applicationShouldTerminate:. The delegate is tao's, and tao does not
//! answer that question, so AppKit quits at once and every shell ends
//! unasked. This gives tao's delegate class that answer: quit now when no
//! terminal is open, otherwise no, and the question of main.rs on screen.
//! The app's own quit (tao stops its event loop) does not come this way.

use objc2::ffi;
use objc2::runtime::{AnyClass, AnyObject, Imp, Sel};
use objc2::{msg_send, sel};
use std::sync::OnceLock;
use tauri::AppHandle;

static HANDLE: OnceLock<AppHandle> = OnceLock::new();

/// NSApplicationTerminateReply.
const TERMINATE_CANCEL: usize = 0;
const TERMINATE_NOW: usize = 1;

extern "C-unwind" fn should_terminate(_this: *mut AnyObject, _cmd: Sel, _sender: *mut AnyObject) -> usize {
    match HANDLE.get() {
        Some(handle) if !crate::may_quit_now(handle) => TERMINATE_CANCEL,
        _ => TERMINATE_NOW,
    }
}

/// Adds the answer to tao's delegate class. Runs once, on the main thread,
/// after tao has set its delegate up (Tauri's setup, which runs while
/// AppKit delivers applicationDidFinishLaunching:).
pub fn install(handle: &AppHandle) {
    if HANDLE.set(handle.clone()).is_err() {
        return;
    }
    let Some(class) = AnyClass::get(c"TaoAppDelegateParent") else { return };
    let added = unsafe {
        let imp: Imp = std::mem::transmute::<extern "C-unwind" fn(*mut AnyObject, Sel, *mut AnyObject) -> usize, Imp>(should_terminate);
        // Returns NSUInteger (Q); self (@), the selector (:), the sender (@).
        ffi::class_addMethod(class as *const AnyClass as *mut AnyClass, sel!(applicationShouldTerminate:), imp, c"Q@:@".as_ptr()).as_bool()
    };
    if added {
        // Once the launch is over, not while AppKit is still telling the
        // delegate about it.
        let _ = handle.run_on_main_thread(set_delegate_again);
    }
}

/// AppKit may have noted what the delegate answers when the delegate was
/// set: set it again, now that it answers this too. tao keeps the delegate
/// alive itself, so a moment without it costs nothing.
fn set_delegate_again() {
    unsafe {
        let Some(application) = AnyClass::get(c"NSApplication") else { return };
        let app: *mut AnyObject = msg_send![application, sharedApplication];
        if app.is_null() {
            return;
        }
        let delegate: *mut AnyObject = msg_send![app, delegate];
        if !delegate.is_null() {
            let _: () = msg_send![app, setDelegate: std::ptr::null_mut::<AnyObject>()];
            let _: () = msg_send![app, setDelegate: delegate];
        }
    }
}

/// While this computer is opened from tTerm Web (background.rs), the app
/// says it does work the person asked for, so that App Nap does not slow
/// its timers with the window closed, and with them the link's signs of
/// life (the agent, a launchd job, was never napped). The system may still
/// sleep when idle. On the main thread.
pub fn stay_awake(on: bool) {
    /// NSActivityUserInitiatedAllowingIdleSystemSleep: NSActivityUserInitiated
    /// (0x00FFFFFF) without NSActivityIdleSystemSleepDisabled (1 << 20).
    const OPTIONS: u64 = 0x00FF_FFFF & !(1 << 20);
    static ACTIVITY: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
    let mut activity = ACTIVITY.lock().unwrap();
    unsafe {
        let Some(class) = AnyClass::get(c"NSProcessInfo") else { return };
        let info: *mut AnyObject = msg_send![class, processInfo];
        if info.is_null() {
            return;
        }
        if on && *activity == 0 {
            let Some(string) = AnyClass::get(c"NSString") else { return };
            let reason: *mut AnyObject = msg_send![string, stringWithUTF8String: c"This computer is opened from tTerm Web".as_ptr()];
            let token: *mut AnyObject = msg_send![info, beginActivityWithOptions: OPTIONS, reason: reason];
            if !token.is_null() {
                *activity = ffi::objc_retain(token.cast()) as usize;
            }
        } else if !on && *activity != 0 {
            let token = *activity as *mut AnyObject;
            let _: () = msg_send![info, endActivity: token];
            ffi::objc_release(token.cast());
            *activity = 0;
        }
    }
}
