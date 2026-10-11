pub const PROGRAM_VERSION_EBPF_LSM: &str = "kernel-ebpf-v30-ebpf-lsm";
pub const PROGRAM_VERSION_APPARMOR: &str = "kernel-ebpf-v30-apparmor";

pub const PROGRAM_OBJECT_EBPF_LSM: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/mercury_kern.o"));
pub const PROGRAM_OBJECT_APPARMOR: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/mercury_kern_apparmor.o"));

pub const PROGRAM_VERSION: &str = PROGRAM_VERSION_EBPF_LSM;
pub const PROGRAM_OBJECT: &[u8] = PROGRAM_OBJECT_EBPF_LSM;

pub const EVENTS_MAP_NAME: &str = "mercury_events";
pub const ENROLLED_PIDS_MAP_NAME: &str = "mercury_enrolled_pids";
pub const IGNORED_PIDS_MAP_NAME: &str = "mercury_ignored_pids";
pub const STATS_MAP_NAME: &str = "mercury_stats";
pub const PROFILES_MAP_NAME: &str = "mercury_profiles";
pub const FILE_RULES_MAP_NAME: &str = "mercury_file_rules";
pub const EXEC_RULES_MAP_NAME: &str = "mercury_exec_rules";
pub const NET_RULES_MAP_NAME: &str = "mercury_net_rules";
pub const OFFSETS_MAP_NAME: &str = "mercury_offsets";
pub const STATS_UNENROLLED_SUPPRESSED_INDEX: u32 = 0;
pub const STATS_RINGBUF_DROPPED_INDEX: u32 = 1;
pub const STATS_RATE_LIMITED_INDEX: u32 = 2;
pub const STATS_DENY_DROPPED_INDEX: u32 = 3;

pub const MAX_PROFILES: u32 = 128;
pub const MAX_PATH_RULES: u32 = 1 << 17;
pub const MAX_NET_RULES: u32 = 1 << 16;
pub const MAX_RULE_PATTERN_BYTES: usize = 256;
/// Must match MAX_RULES_PER_CLASS in mercury_kern.c.
pub const MAX_RULES_PER_CLASS: usize = 32;
pub const MAX_WORKSPACE_ROOTS: usize = 64;
pub const PROFILE_NAME_BYTES: usize = 32;

pub const PROG_FILE_OPEN: &str = "mercury_file_open";
pub const PROG_INODE_UNLINK: &str = "mercury_inode_unlink";
pub const PROG_BPRM_CHECK_SECURITY: &str = "mercury_bprm_check_security";
pub const PROG_SOCKET_CONNECT: &str = "mercury_socket_connect";
pub const PROG_MMAP_FILE: &str = "mercury_mmap_file";
pub const PROG_SOCKET_SENDMSG: &str = "mercury_socket_sendmsg";
pub const PROG_SCHED_FORK: &str = "mercury_sched_process_fork";
pub const PROG_SCHED_EXEC: &str = "mercury_sched_process_exec";
pub const PROG_SCHED_EXIT: &str = "mercury_sched_process_exit";
/* File-mutation hooks */
pub const PROG_PATH_RENAME: &str = "mercury_path_rename";
pub const PROG_PATH_LINK: &str = "mercury_path_link";
pub const PROG_PATH_SYMLINK: &str = "mercury_path_symlink";
pub const PROG_PATH_MKDIR: &str = "mercury_path_mkdir";
pub const PROG_PATH_RMDIR: &str = "mercury_path_rmdir";
/// Attached to lsm/path_mknod (full destination path; replaced inode_create).
pub const PROG_PATH_MKNOD: &str = "mercury_path_mknod";
pub const PROG_PATH_CHMOD: &str = "mercury_path_chmod";
pub const PROG_PATH_CHOWN: &str = "mercury_path_chown";
pub const PROG_PATH_TRUNCATE: &str = "mercury_path_truncate";
/* Network server-side hooks */
pub const PROG_SOCKET_BIND: &str = "mercury_socket_bind";
pub const PROG_SOCKET_LISTEN: &str = "mercury_socket_listen";
pub const PROG_SOCKET_ACCEPT: &str = "mercury_socket_accept";
pub const PROG_SOCKET_CREATE: &str = "mercury_socket_create";
/* Process supervision hooks */
pub const PROG_PTRACE_ACCESS_CHECK: &str = "mercury_ptrace_access_check";
pub const PROG_PTRACE_TRACEME: &str = "mercury_ptrace_traceme";
pub const PROG_TASK_KILL: &str = "mercury_task_kill";
pub const PROG_CAPABLE: &str = "mercury_capable";
/* Privileged / tamper-relevant hooks (attached when the kernel offers them) */
pub const PROG_BPF: &str = "mercury_bpf";
pub const PROG_KERNEL_READ_FILE: &str = "mercury_kernel_read_file";
pub const PROG_KERNEL_LOAD_DATA: &str = "mercury_kernel_load_data";
pub const PROG_SB_MOUNT: &str = "mercury_sb_mount";
pub const PROG_MOVE_MOUNT: &str = "mercury_move_mount";
pub const PROG_USERNS_CREATE: &str = "mercury_userns_create";

/// Hooks whose absence degrades coverage but must not stop the daemon
/// (program name, LSM hook name).
pub const OPTIONAL_LSM_HOOKS: [(&str, &str); 6] = [
    (PROG_BPF, "bpf"),
    (PROG_KERNEL_READ_FILE, "kernel_read_file"),
    (PROG_KERNEL_LOAD_DATA, "kernel_load_data"),
    (PROG_SB_MOUNT, "sb_mount"),
    (PROG_MOVE_MOUNT, "move_mount"),
    (PROG_USERNS_CREATE, "userns_create"),
];

pub const REQUIRED_HOOKS: [&str; 6] = [
    "lsm/file_open",
    "lsm/path_unlink",
    "lsm/bprm_check_security",
    "lsm/socket_connect",
    "lsm/mmap_file",
    "lsm/socket_sendmsg",
];
