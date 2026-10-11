// Re-export configuration types that are now defined in platform_traits so
// existing `use kernel_runtime::{BackendMode, ...}` paths keep working.
pub use platform_traits::{
    AppArmorConfig, AutoEnrollRule, BackendMode, EnrollmentMode, FilesystemBackend,
    KernelRuntimeConfig, UnmatchedHostMode,
};

// On non-Linux targets the crate is a thin re-export shell.  Everything below
// (the eBPF runtime, kernel probing helpers, etc.) only compiles on Linux.
#[cfg(target_os = "linux")]
mod linux_impl;
#[cfg(target_os = "linux")]
pub use linux_impl::*;

// ---------------------------------------------------------------------------
// Cross-platform fallback stubs
// ---------------------------------------------------------------------------

/// Read process start time.  On Linux this reads /proc/<pid>/stat field 22.
/// On other platforms, returns a constant so PID-reuse detection is
/// conservative (never expires).
#[cfg(not(target_os = "linux"))]
pub fn read_proc_start_time(_pid: u32) -> Option<u64> {
    Some(0)
}
