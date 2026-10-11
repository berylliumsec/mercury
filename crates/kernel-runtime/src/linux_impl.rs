#[cfg(test)]
pub use super::AutoEnrollRule;
use super::{
    BackendMode, EnrollmentMode, FilesystemBackend, KernelRuntimeConfig, UnmatchedHostMode,
};

use std::borrow::{Borrow, BorrowMut};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use aya::Pod;
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, MapError, RingBuf};
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, Ebpf};
use chrono::Utc;
use core_types::{
    ActionType, AuditEvent, Decision, DecisionReason, DefaultDecision, EnforcementMode,
    ExecResource, FileOp, FileResource, NetworkProtocol, NetworkResource, Resource, SystemResource,
};
use globset::Glob;
use kernel_ebpf::{
    ENROLLED_PIDS_MAP_NAME, EVENTS_MAP_NAME, EXEC_RULES_MAP_NAME, FILE_RULES_MAP_NAME,
    IGNORED_PIDS_MAP_NAME, MAX_NET_RULES, MAX_PATH_RULES, MAX_PROFILES, NET_RULES_MAP_NAME,
    OFFSETS_MAP_NAME, OPTIONAL_LSM_HOOKS, PROFILE_NAME_BYTES, PROFILES_MAP_NAME,
    PROG_BPRM_CHECK_SECURITY, PROG_CAPABLE, PROG_FILE_OPEN, PROG_INODE_UNLINK, PROG_MMAP_FILE,
    PROG_PATH_CHMOD, PROG_PATH_CHOWN, PROG_PATH_LINK, PROG_PATH_MKDIR, PROG_PATH_MKNOD,
    PROG_PATH_RENAME, PROG_PATH_RMDIR, PROG_PATH_SYMLINK, PROG_PATH_TRUNCATE,
    PROG_PTRACE_ACCESS_CHECK, PROG_PTRACE_TRACEME, PROG_SCHED_EXEC, PROG_SCHED_EXIT,
    PROG_SCHED_FORK, PROG_SOCKET_ACCEPT, PROG_SOCKET_BIND, PROG_SOCKET_CONNECT, PROG_SOCKET_CREATE,
    PROG_SOCKET_LISTEN, PROG_SOCKET_SENDMSG, PROG_TASK_KILL, PROGRAM_OBJECT_APPARMOR,
    PROGRAM_OBJECT_EBPF_LSM, PROGRAM_VERSION_APPARMOR, PROGRAM_VERSION_EBPF_LSM,
    STATS_DENY_DROPPED_INDEX, STATS_MAP_NAME, STATS_RATE_LIMITED_INDEX,
    STATS_RINGBUF_DROPPED_INDEX, STATS_UNENROLLED_SUPPRESSED_INDEX,
};
use libc::{CLOCK_MONOTONIC, CLOCK_REALTIME, ENOENT, clock_gettime, timespec};
use parking_lot::RwLock;
use policy_engine::{
    CompiledPolicy, FilesystemPolicyBackend, KernelPolicyIr, compile_kernel_ir_for_backend,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HookBackend {
    EbpfLsm,
    EbpfCgroup,
    AppArmor,
    ObserveOnly,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HookStatus {
    pub exec_hook: HookBackend,
    pub network_hook: HookBackend,
    pub filesystem_hook: HookBackend,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelCapabilityReport {
    pub kernel_release: String,
    pub kernel_version_ok: bool,
    pub bpf_fs_present: bool,
    pub bpf_lsm_available: bool,
    pub cgroup_v2: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelRuntimeHealth {
    pub backend_mode: BackendMode,
    pub kernel_ready: bool,
    pub kernel_program_version: String,
    pub auto_enroll_active_rules: usize,
    pub unmatched_mode: UnmatchedHostMode,
    pub hook_status: HookStatus,
    pub unenrolled_events_suppressed_total: u64,
    pub events_dropped_ringbuf_total: u64,
    pub events_rate_limited_total: u64,
    pub deny_events_dropped_total: u64,
    /// Optional LSM hooks (bpf, module load, mount, userns) the kernel lacked.
    #[serde(default)]
    pub unavailable_hooks: Vec<String>,
    pub enrollment_sync_error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentSource {
    AiRun,
    AutoEnroll,
    /// Re-enrolled from persisted state after a daemon restart.
    Restored,
}

#[derive(Debug, Clone)]
pub struct PidEnrollment {
    pub agent_id: Uuid,
    pub profile: String,
    pub uid: u32,
    pub proc_start_time: u64,
    pub source: EnrollmentSource,
    pub mode: EnrollmentMode,
    pub cgroup_id: String,
    /// Kernel-side id inherited by every descendant; 0 until assigned.
    pub enrollment_id: u32,
}

pub struct KernelRuntime {
    config: KernelRuntimeConfig,
    filesystem_backend: FilesystemBackend,
    capabilities: KernelCapabilityReport,
    state: RwLock<KernelRuntimeState>,
}

impl fmt::Debug for KernelRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelRuntime")
            .field("config", &self.config)
            .field("filesystem_backend", &self.filesystem_backend)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

struct KernelRuntimeState {
    started: bool,
    hook_status: HookStatus,
    active_epoch: u64,
    next_epoch: u64,
    policy_epochs: HashMap<u64, KernelPolicyEpoch>,
    enrollments: HashMap<u32, PidEnrollment>,
    enrollment_identities: HashMap<u32, EnrollmentIdentity>,
    next_enrollment_id: u32,
    ignored_pids: HashSet<u32>,
    active_auto_rules: usize,
    unenrolled_events_suppressed_total: u64,
    events_dropped_ringbuf_total: u64,
    events_rate_limited_total: u64,
    deny_events_dropped_total: u64,
    unavailable_hooks: Vec<String>,
    last_enrollment_sync_error: Option<String>,
    bpf: Option<Ebpf>,
    ring_buf: Option<RingBuf<MapData>>,
}

#[derive(Debug, Clone)]
struct KernelPolicyEpoch {
    ir: KernelPolicyIr,
    compiled: CompiledPolicy,
    profile_indices: HashMap<String, u32>,
    default_profile_index: u32,
    /// rule_ref (kind << 24 | map key) -> policy rule id, for decoding events.
    rule_ids: Arc<HashMap<u32, String>>,
}

/// What an enrollment id (carried by every kernel event and inherited across
/// fork) refers to. Kept for a while after the root exits so descendants'
/// events still resolve to the agent run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentIdentity {
    pub agent_id: Uuid,
    pub root_pid: u32,
    pub profile: String,
    pub cgroup_id: String,
    retired: bool,
}

/// Retired identities kept for descendants that outlive the enrollment root.
const MAX_RETIRED_IDENTITIES: usize = 4096;

const ENFORCEMENT_ENFORCE: u8 = 0;
const ENFORCEMENT_OBSERVE: u8 = 1;
const DEFAULT_DECISION_ALLOW: u8 = 0;
const DEFAULT_DECISION_DENY: u8 = 1;
const REASON_ALLOW_BY_DEFAULT: u32 = 5;

const NET_PROTOCOL_ANY: u8 = 0;
const NET_PROTOCOL_TCP: u8 = 1;
const NET_PROTOCOL_UDP: u8 = 2;
const NET_FAMILY_UNSPEC: u8 = 0;
const NET_FAMILY_INET4: u8 = 2;
const NET_FAMILY_INET6: u8 = 10;
const MAX_KERNEL_RULES_PER_CLASS: usize = kernel_ebpf::MAX_RULES_PER_CLASS;
const MAX_KERNEL_WORKSPACE_ROOTS: usize = kernel_ebpf::MAX_WORKSPACE_ROOTS;
const PATH_RULE_KIND_EXACT: u8 = 0;
const PATH_RULE_KIND_PREFIX_DIR: u8 = 1;
const PATH_RULE_KIND_PREFIX_IMMEDIATE: u8 = 2;

fn program_artifact_for_backend(
    filesystem_backend: FilesystemBackend,
) -> (&'static [u8], &'static str) {
    match filesystem_backend {
        FilesystemBackend::EbpfLsm => (PROGRAM_OBJECT_EBPF_LSM, PROGRAM_VERSION_EBPF_LSM),
        FilesystemBackend::AppArmor => (PROGRAM_OBJECT_APPARMOR, PROGRAM_VERSION_APPARMOR),
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct EnrolledPidValue {
    profile_index: u32,
    mode: u8,
    launch_exec_bypass: u8,
    _pad: [u8; 2],
    enrollment_id: u32,
}

unsafe impl Pod for EnrolledPidValue {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct KernelProfileValue {
    name: [u8; PROFILE_NAME_BYTES],
    file_mode: u8,
    process_mode: u8,
    network_mode: u8,
    url_enforce: u8,
    url_proxy_port: u16,
    _pad0: u16,
    file_allow_offset: u32,
    file_allow_count: u32,
    file_deny_offset: u32,
    file_deny_count: u32,
    exec_allow_offset: u32,
    exec_allow_count: u32,
    exec_deny_offset: u32,
    exec_deny_count: u32,
    net_allow_offset: u32,
    net_allow_count: u32,
    net_deny_offset: u32,
    net_deny_count: u32,
    workspace_offset: u32,
    workspace_count: u32,
}

unsafe impl Pod for KernelProfileValue {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct KernelPathRuleValue {
    kind: u8,
    _pad0: u8,
    len: u16,
    pattern: [u8; kernel_ebpf::MAX_RULE_PATTERN_BYTES],
}

unsafe impl Pod for KernelPathRuleValue {}

impl Default for KernelPathRuleValue {
    fn default() -> Self {
        Self {
            kind: 0,
            _pad0: 0,
            len: 0,
            pattern: [0; kernel_ebpf::MAX_RULE_PATTERN_BYTES],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct KernelNetRuleValue {
    protocol: u8,
    has_port: u8,
    has_cidr: u8,
    cidr_prefix: u8,
    port: u16,
    family: u8,
    has_host_glob: u8,
    addr: [u8; 16],
}

unsafe impl Pod for KernelNetRuleValue {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct KernelOffsetsValue {
    default_decision: u8,
    policy_loaded: u8,
    _pad: u16,
    profile_count: u32,
    realtime_offset_ns: i64,
    rate_limit_per_sec: u32,
    policy_epoch: u32,
}

unsafe impl Pod for KernelOffsetsValue {}

impl KernelRuntime {
    pub fn new(config: KernelRuntimeConfig, filesystem_backend: FilesystemBackend) -> Self {
        let capabilities =
            detect_capabilities(config.bpffs_path.as_str(), config.cgroup_root.as_str());
        Self {
            config,
            filesystem_backend,
            capabilities,
            state: RwLock::new(KernelRuntimeState {
                started: false,
                hook_status: HookStatus {
                    exec_hook: HookBackend::Unavailable,
                    network_hook: HookBackend::Unavailable,
                    filesystem_hook: HookBackend::Unavailable,
                },
                active_epoch: 0,
                next_epoch: 1,
                policy_epochs: HashMap::new(),
                enrollments: HashMap::new(),
                enrollment_identities: HashMap::new(),
                next_enrollment_id: 1,
                ignored_pids: HashSet::new(),
                active_auto_rules: 0,
                unenrolled_events_suppressed_total: 0,
                events_dropped_ringbuf_total: 0,
                events_rate_limited_total: 0,
                deny_events_dropped_total: 0,
                unavailable_hooks: Vec::new(),
                last_enrollment_sync_error: None,
                bpf: None,
                ring_buf: None,
            }),
        }
    }

    pub fn start(&self) -> Result<(), KernelRuntimeError> {
        let _online_cpus = aya::util::online_cpus().map_err(|err| {
            KernelRuntimeError::Unavailable(format!("failed to initialize aya runtime: {err:?}"))
        })?;

        if !self.capabilities.kernel_version_ok {
            return Err(KernelRuntimeError::Unavailable(
                "kernel 6.1+ is required for kernel_strict mode".to_string(),
            ));
        }
        if !self.capabilities.bpf_fs_present {
            return Err(KernelRuntimeError::Unavailable(
                "bpffs is required at configured path".to_string(),
            ));
        }
        if !self.capabilities.bpf_lsm_available {
            return Err(KernelRuntimeError::Unavailable(
                "BPF LSM support is required".to_string(),
            ));
        }
        if !self.capabilities.cgroup_v2 {
            return Err(KernelRuntimeError::Unavailable(
                "cgroup v2 mount is required".to_string(),
            ));
        }

        fs::create_dir_all(&self.config.cgroup_root)
            .with_context(|| format!("ensure cgroup root {}", self.config.cgroup_root))
            .map_err(KernelRuntimeError::Other)?;

        let (program_object, _) = program_artifact_for_backend(self.filesystem_backend);

        if program_object.is_empty() {
            return Err(KernelRuntimeError::Unavailable(
                "embedded kernel eBPF object is empty".to_string(),
            ));
        }

        let btf = Btf::from_sys_fs().map_err(|err| {
            KernelRuntimeError::Unavailable(format!("failed to load system BTF metadata: {err}"))
        })?;
        let program_bytes = program_object.to_vec();
        let mut bpf = Ebpf::load(&program_bytes).map_err(|err| {
            KernelRuntimeError::Unavailable(format!("failed to load eBPF object: {err}"))
        })?;

        if self.filesystem_backend == FilesystemBackend::EbpfLsm {
            attach_lsm_program(&mut bpf, PROG_FILE_OPEN, "file_open", &btf)?;
            attach_lsm_program(&mut bpf, PROG_INODE_UNLINK, "path_unlink", &btf)?;
        }
        if self.filesystem_backend == FilesystemBackend::EbpfLsm {
            attach_lsm_program(
                &mut bpf,
                PROG_BPRM_CHECK_SECURITY,
                "bprm_check_security",
                &btf,
            )?;
        }
        attach_lsm_program(&mut bpf, PROG_SOCKET_CONNECT, "socket_connect", &btf)?;
        attach_lsm_program(&mut bpf, PROG_SOCKET_SENDMSG, "socket_sendmsg", &btf)?;
        if self.filesystem_backend == FilesystemBackend::EbpfLsm {
            attach_lsm_program(&mut bpf, PROG_MMAP_FILE, "mmap_file", &btf)?;
            /* File-mutation hooks */
            attach_lsm_program(&mut bpf, PROG_PATH_RENAME, "path_rename", &btf)?;
            attach_lsm_program(&mut bpf, PROG_PATH_LINK, "path_link", &btf)?;
            attach_lsm_program(&mut bpf, PROG_PATH_SYMLINK, "path_symlink", &btf)?;
            attach_lsm_program(&mut bpf, PROG_PATH_MKDIR, "path_mkdir", &btf)?;
            attach_lsm_program(&mut bpf, PROG_PATH_RMDIR, "path_rmdir", &btf)?;
            attach_lsm_program(&mut bpf, PROG_PATH_MKNOD, "path_mknod", &btf)?;
            attach_lsm_program(&mut bpf, PROG_PATH_CHMOD, "path_chmod", &btf)?;
            attach_lsm_program(&mut bpf, PROG_PATH_CHOWN, "path_chown", &btf)?;
            attach_lsm_program(&mut bpf, PROG_PATH_TRUNCATE, "path_truncate", &btf)?;
        }
        /* Network server-side hooks */
        attach_lsm_program(&mut bpf, PROG_SOCKET_BIND, "socket_bind", &btf)?;
        attach_lsm_program(&mut bpf, PROG_SOCKET_LISTEN, "socket_listen", &btf)?;
        attach_lsm_program(&mut bpf, PROG_SOCKET_ACCEPT, "socket_accept", &btf)?;
        attach_lsm_program(&mut bpf, PROG_SOCKET_CREATE, "socket_create", &btf)?;
        /* Process supervision hooks */
        attach_lsm_program(
            &mut bpf,
            PROG_PTRACE_ACCESS_CHECK,
            "ptrace_access_check",
            &btf,
        )?;
        attach_lsm_program(&mut bpf, PROG_PTRACE_TRACEME, "ptrace_traceme", &btf)?;
        attach_lsm_program(&mut bpf, PROG_TASK_KILL, "task_kill", &btf)?;
        attach_lsm_program(&mut bpf, PROG_CAPABLE, "capable", &btf)?;
        let mut unavailable_hooks = Vec::new();
        for (program, hook) in OPTIONAL_LSM_HOOKS {
            if let Err(err) = attach_lsm_program(&mut bpf, program, hook, &btf) {
                warn!(hook, error = %err, "optional LSM hook unavailable; coverage reduced");
                unavailable_hooks.push(hook.to_string());
            }
        }
        attach_tracepoint_program(&mut bpf, PROG_SCHED_FORK, "sched", "sched_process_fork")?;
        attach_tracepoint_program(&mut bpf, PROG_SCHED_EXEC, "sched", "sched_process_exec")?;
        attach_tracepoint_program(&mut bpf, PROG_SCHED_EXIT, "sched", "sched_process_exit")?;

        let ring_buf_map = bpf.take_map(EVENTS_MAP_NAME).ok_or_else(|| {
            KernelRuntimeError::Unavailable(format!(
                "ring buffer map '{EVENTS_MAP_NAME}' not found"
            ))
        })?;
        let ring_buf = RingBuf::try_from(ring_buf_map).map_err(|err| {
            KernelRuntimeError::Other(anyhow::anyhow!("open ring buffer map: {err}"))
        })?;

        let mut state = self.state.write();
        state.started = true;
        state.hook_status = HookStatus {
            exec_hook: match self.filesystem_backend {
                FilesystemBackend::EbpfLsm => HookBackend::EbpfLsm,
                FilesystemBackend::AppArmor => HookBackend::AppArmor,
            },
            network_hook: HookBackend::EbpfLsm,
            filesystem_hook: match self.filesystem_backend {
                FilesystemBackend::EbpfLsm => HookBackend::EbpfLsm,
                FilesystemBackend::AppArmor => HookBackend::AppArmor,
            },
        };
        state.active_auto_rules = self.config.auto_enroll_rules.len();
        state.unavailable_hooks = unavailable_hooks;
        state.bpf = Some(bpf);
        state.ring_buf = Some(ring_buf);
        initialize_kernel_offsets(&mut state)?;
        sync_all_pid_maps(&mut state)?;
        Ok(())
    }

    pub fn load_policy(&self, policy: &CompiledPolicy) -> Result<(), KernelRuntimeError> {
        let ir = compile_kernel_ir_for_backend(
            policy,
            match self.filesystem_backend {
                FilesystemBackend::EbpfLsm => FilesystemPolicyBackend::EbpfLsm,
                FilesystemBackend::AppArmor => FilesystemPolicyBackend::AppArmor,
            },
        )
        .map_err(|e| KernelRuntimeError::Policy(e.to_string()))?;
        let mut state = self.state.write();

        let mut compiled_epoch =
            compile_epoch_maps(&ir, self.config.url_proxy_port, self.filesystem_backend)?;
        let epoch = state.next_epoch;
        compiled_epoch.offsets.rate_limit_per_sec = self.config.rate_limit_per_sec;
        compiled_epoch.offsets.policy_epoch = epoch as u32;
        apply_epoch_maps(&mut state, &compiled_epoch, self.filesystem_backend)?;

        state.next_epoch += 1;
        state.policy_epochs.insert(
            epoch,
            KernelPolicyEpoch {
                ir,
                compiled: policy.clone(),
                profile_indices: compiled_epoch.profile_indices.clone(),
                default_profile_index: compiled_epoch.default_profile_index,
                rule_ids: Arc::new(compiled_epoch.rule_ids),
            },
        );

        let previous = state.active_epoch;
        state.active_epoch = epoch;

        // Keep only active and previous epoch to model atomic swap + bounded retention.
        if previous != 0 {
            let active = state.active_epoch;
            state
                .policy_epochs
                .retain(|k, _| *k == active || *k == previous);
        }

        sync_enrollment_map(&mut state).map_err(|err| {
            warn!(error = %err, "failed to sync enrolled PID map after policy reload");
            err
        })?;

        Ok(())
    }

    pub fn register_ai_run_pid(
        &self,
        pid: u32,
        agent_id: Uuid,
        profile: &str,
        uid: u32,
        cgroup_id: &str,
    ) -> Result<(), KernelRuntimeError> {
        let proc_start_time = read_proc_start_time(pid).ok_or_else(|| {
            KernelRuntimeError::Unavailable(format!(
                "read process start time for pid {pid} from /proc/{pid}/stat"
            ))
        })?;
        let mut state = self.state.write();
        insert_enrollment(
            &mut state,
            pid,
            PidEnrollment {
                agent_id,
                profile: profile.to_string(),
                uid,
                proc_start_time,
                source: EnrollmentSource::AiRun,
                mode: EnrollmentMode::Enforce,
                cgroup_id: cgroup_id.to_string(),
                enrollment_id: 0,
            },
        );
        /*
         * Processes forked by mercuryd (dashboard launches) inherit the ignored
         * marker; an explicit registration must win over it.
         */
        if state.ignored_pids.remove(&pid)
            && let Err(err) = sync_ignored_pid(&mut state, pid, false)
        {
            warn!(error = %err, pid, "failed to clear ignored marker for registered pid");
        }
        if let Err(err) = sync_enrollment_pid(&mut state, pid, true) {
            state.last_enrollment_sync_error = Some(err.to_string());
            warn!(error = %err, pid, "failed to sync enrolled PID map for mercury-run registration");
            return Err(err);
        } else {
            state.last_enrollment_sync_error = None;
        }
        Ok(())
    }

    /// Re-enrolls a surviving agent after a daemon restart: `root_pid` is
    /// tracked like a fresh registration (without the launch bypass) and every
    /// other live member of the agent's cgroup is written to the kernel map
    /// under the same enrollment id. Returns the enrollment id.
    pub fn restore_enrollment(
        &self,
        root_pid: u32,
        agent_id: Uuid,
        profile: &str,
        uid: u32,
        cgroup_id: &str,
        members: &[u32],
    ) -> Result<u32, KernelRuntimeError> {
        let proc_start_time = read_proc_start_time(root_pid).ok_or_else(|| {
            KernelRuntimeError::Unavailable(format!("restore: pid {root_pid} is not running"))
        })?;
        let mut state = self.state.write();
        insert_enrollment(
            &mut state,
            root_pid,
            PidEnrollment {
                agent_id,
                profile: profile.to_string(),
                uid,
                proc_start_time,
                source: EnrollmentSource::Restored,
                mode: EnrollmentMode::Enforce,
                cgroup_id: cgroup_id.to_string(),
                enrollment_id: 0,
            },
        );
        if state.ignored_pids.remove(&root_pid) {
            let _ = sync_ignored_pid(&mut state, root_pid, false);
        }
        sync_enrollment_pid(&mut state, root_pid, true)?;
        let root = state.enrollments[&root_pid].clone();
        let value = EnrolledPidValue {
            profile_index: resolve_profile_index(&state, profile),
            mode: enrollment_mode_to_u8(root.mode),
            launch_exec_bypass: 0,
            _pad: [0; 2],
            enrollment_id: root.enrollment_id,
        };
        if let Some(bpf) = state.bpf.as_mut() {
            let map = bpf.map_mut(ENROLLED_PIDS_MAP_NAME).ok_or_else(|| {
                KernelRuntimeError::Unavailable(format!(
                    "enrolled pid map '{ENROLLED_PIDS_MAP_NAME}' not found in eBPF object"
                ))
            })?;
            let mut pid_map =
                AyaHashMap::<_, u32, EnrolledPidValue>::try_from(map).map_err(|err| {
                    KernelRuntimeError::Unavailable(format!(
                        "open enrolled pid map '{ENROLLED_PIDS_MAP_NAME}': {err}"
                    ))
                })?;
            for pid in members.iter().copied().filter(|pid| *pid != root_pid) {
                pid_map.insert(pid, value, 0).map_err(|err| {
                    KernelRuntimeError::Unavailable(format!(
                        "restore: insert member pid {pid} into '{ENROLLED_PIDS_MAP_NAME}': {err}"
                    ))
                })?;
            }
        }
        Ok(root.enrollment_id)
    }

    pub fn ignore_pid(&self, pid: u32) {
        let mut state = self.state.write();
        state.ignored_pids.insert(pid);
        if let Err(err) = sync_ignored_pid(&mut state, pid, true) {
            state.last_enrollment_sync_error = Some(err.to_string());
            warn!(error = %err, pid, "failed to sync ignored PID map");
        } else {
            state.last_enrollment_sync_error = None;
        }
    }

    pub fn scan_auto_enroll(&self) -> Result<usize, KernelRuntimeError> {
        let root = Path::new(&self.config.cgroup_root);
        if !root.exists() {
            return Ok(0);
        }

        let mut loaded = 0usize;
        for rule in &self.config.auto_enroll_rules {
            let glob = Glob::new(rule.cgroup_pattern.as_str()).map_err(|err| {
                KernelRuntimeError::Config(format!(
                    "invalid auto-enroll cgroup pattern '{}' for rule '{}': {err}",
                    rule.cgroup_pattern, rule.id
                ))
            })?;
            let matcher = glob.compile_matcher();

            for path in walk_cgroup_procs(root) {
                let display = path.to_string_lossy();
                if !matcher.is_match(display.as_ref()) {
                    continue;
                }

                let content = fs::read_to_string(&path).map_err(KernelRuntimeError::Io)?;
                for line in content.lines() {
                    let parsed = line.trim().parse::<u32>();
                    let Ok(pid) = parsed else {
                        continue;
                    };
                    let Some(proc_start_time) = read_proc_start_time(pid) else {
                        continue;
                    };
                    let Some(uid) = read_proc_uid(pid) else {
                        continue;
                    };

                    let cgroup_id = path
                        .parent()
                        .and_then(Path::file_name)
                        .map(|v| v.to_string_lossy().to_string())
                        .unwrap_or_else(|| "auto".to_string());

                    let mut guard = self.state.write();
                    if !guard.enrollments.contains_key(&pid) {
                        insert_enrollment(
                            &mut guard,
                            pid,
                            PidEnrollment {
                                agent_id: Uuid::new_v4(),
                                profile: rule.profile.clone(),
                                uid,
                                proc_start_time,
                                source: EnrollmentSource::AutoEnroll,
                                mode: rule.mode,
                                cgroup_id,
                                enrollment_id: 0,
                            },
                        );
                    }
                    if let Err(err) = sync_enrollment_pid(&mut guard, pid, true) {
                        guard.last_enrollment_sync_error = Some(err.to_string());
                        warn!(
                            error = %err,
                            pid,
                            rule_id = %rule.id,
                            "failed to sync enrolled PID map for auto-enroll"
                        );
                    }
                    loaded += 1;
                }
            }
        }

        if loaded > 0 {
            self.state.write().active_auto_rules = self.config.auto_enroll_rules.len();
        }

        Ok(loaded)
    }

    pub fn is_pid_enrolled(&self, pid: u32) -> bool {
        self.state.read().enrollments.contains_key(&pid)
    }

    /// Resolves the enrollment id carried by kernel events (also for
    /// descendants whose root already exited).
    pub fn enrollment_identity(&self, enrollment_id: u32) -> Option<EnrollmentIdentity> {
        self.state
            .read()
            .enrollment_identities
            .get(&enrollment_id)
            .cloned()
    }

    pub fn enrollment_for_pid(&self, pid: u32) -> Option<PidEnrollment> {
        self.state.read().enrollments.get(&pid).cloned()
    }

    pub fn list_enrollments(&self) -> Vec<(u32, PidEnrollment)> {
        let state = self.state.read();
        let mut entries: Vec<(u32, PidEnrollment)> = state
            .enrollments
            .iter()
            .map(|(pid, enrollment)| (*pid, enrollment.clone()))
            .collect();
        entries.sort_by_key(|(pid, _)| *pid);
        entries
    }

    pub fn remove_pid_enrollment(&self, pid: u32) -> Result<bool, KernelRuntimeError> {
        let mut state = self.state.write();
        let Some(removed) = state.enrollments.remove(&pid) else {
            return Ok(false);
        };
        retire_identity(&mut state, removed.enrollment_id);

        if let Err(err) = sync_enrollment_pid(&mut state, pid, false) {
            state.last_enrollment_sync_error = Some(err.to_string());
            warn!(error = %err, pid, "failed to remove stale enrolled PID map entry");
            return Err(err);
        }

        state.last_enrollment_sync_error = None;
        Ok(true)
    }

    pub fn prune_stale_enrollments(&self) -> Result<usize, KernelRuntimeError> {
        let stale_pids: Vec<u32> = {
            let state = self.state.read();
            state
                .enrollments
                .iter()
                .filter_map(|(pid, enrollment)| {
                    let current = read_proc_start_time(*pid);
                    if current == Some(enrollment.proc_start_time) {
                        None
                    } else {
                        Some(*pid)
                    }
                })
                .collect()
        };

        let mut removed = 0usize;
        for pid in stale_pids {
            if self.remove_pid_enrollment(pid)? {
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub fn drain_audit_events(&self) -> Result<Vec<AuditEvent>, KernelRuntimeError> {
        self.drain_audit_events_limited(usize::MAX)
    }

    pub fn drain_audit_events_limited(
        &self,
        max_events: usize,
    ) -> Result<Vec<AuditEvent>, KernelRuntimeError> {
        let mut raw_events: Vec<Vec<u8>> = Vec::new();
        let decode_ctx;
        {
            let mut state = self.state.write();
            decode_ctx = DecodeContext {
                epochs: state
                    .policy_epochs
                    .iter()
                    .map(|(id, epoch)| {
                        (
                            *id as u32,
                            (epoch.compiled.version.clone(), Arc::clone(&epoch.rule_ids)),
                        )
                    })
                    .collect(),
                identities: state.enrollment_identities.clone(),
            };

            let Some(ring_buf) = state.ring_buf.as_mut() else {
                return Ok(Vec::new());
            };

            while raw_events.len() < max_events {
                let Some(item) = ring_buf.next() else {
                    break;
                };
                let bytes: &[u8] = item.as_ref();
                raw_events.push(bytes.to_vec());
            }
        }

        let mut out = Vec::with_capacity(raw_events.len());
        for raw in raw_events {
            if let Some(event) = decode_kernel_event(raw.as_slice(), &decode_ctx) {
                out.push(event);
            }
        }

        Ok(out)
    }

    pub fn unmatched_reason(&self) -> DecisionReason {
        match self.config.unmatched_host_mode {
            UnmatchedHostMode::Observe => DecisionReason::AllowUnenrolledObserve,
        }
    }

    pub fn hook_status(&self) -> HookStatus {
        self.state.read().hook_status.clone()
    }

    pub fn health(&self) -> KernelRuntimeHealth {
        let mut state = self.state.write();
        if let Err(err) = refresh_runtime_stats(&mut state) {
            state.last_enrollment_sync_error = Some(err.to_string());
            warn!(error = %err, "failed to refresh kernel runtime counters");
        }
        KernelRuntimeHealth {
            backend_mode: BackendMode::KernelStrict,
            kernel_ready: state.started,
            kernel_program_version: program_artifact_for_backend(self.filesystem_backend)
                .1
                .to_string(),
            auto_enroll_active_rules: state.active_auto_rules,
            unmatched_mode: self.config.unmatched_host_mode,
            hook_status: state.hook_status.clone(),
            unenrolled_events_suppressed_total: state.unenrolled_events_suppressed_total,
            events_dropped_ringbuf_total: state.events_dropped_ringbuf_total,
            events_rate_limited_total: state.events_rate_limited_total,
            deny_events_dropped_total: state.deny_events_dropped_total,
            unavailable_hooks: state.unavailable_hooks.clone(),
            enrollment_sync_error: state.last_enrollment_sync_error.clone(),
        }
    }

    pub fn check_capabilities(&self) -> KernelCapabilityReport {
        self.capabilities.clone()
    }

    pub fn active_epoch(&self) -> u64 {
        self.state.read().active_epoch
    }

    pub fn active_rule_counts(&self) -> Option<(usize, usize)> {
        let state = self.state.read();
        state.policy_epochs.get(&state.active_epoch).map(|epoch| {
            (
                epoch.ir.profile_count as usize,
                epoch.compiled.profiles.len(),
            )
        })
    }
}

#[derive(Debug, Clone)]
struct CompiledEpochMaps {
    profile_indices: HashMap<String, u32>,
    default_profile_index: u32,
    profiles: Vec<(u32, KernelProfileValue)>,
    file_rules: Vec<(u32, KernelPathRuleValue)>,
    exec_rules: Vec<(u32, KernelPathRuleValue)>,
    net_rules: Vec<(u32, KernelNetRuleValue)>,
    rule_ids: HashMap<u32, String>,
    offsets: KernelOffsetsValue,
}

#[derive(Debug, Clone, Copy, Default)]
struct EpochMapCounts {
    profiles: u32,
    file_rules: u32,
    exec_rules: u32,
    net_rules: u32,
}

fn compile_epoch_maps(
    ir: &KernelPolicyIr,
    url_proxy_port: u16,
    filesystem_backend: FilesystemBackend,
) -> Result<CompiledEpochMaps, KernelRuntimeError> {
    let mut profile_names: Vec<String> = ir.profiles.keys().cloned().collect();
    profile_names.sort();

    if profile_names.len() > MAX_PROFILES as usize {
        return Err(KernelRuntimeError::Policy(format!(
            "profile count {} exceeds kernel map capacity {}",
            profile_names.len(),
            MAX_PROFILES
        )));
    }

    let mut profile_indices = HashMap::with_capacity(profile_names.len());
    let mut profiles = Vec::with_capacity(profile_names.len());
    let mut file_rules = Vec::new();
    let mut exec_rules = Vec::new();
    let mut net_rules = Vec::new();
    let mut rule_ids = HashMap::new();
    let mut file_cursor = 0u32;
    let mut exec_cursor = 0u32;
    let mut net_cursor = 0u32;

    for (idx, profile_name) in profile_names.iter().enumerate() {
        let idx_u32 = idx as u32;
        profile_indices.insert(profile_name.clone(), idx_u32);
        let profile = ir.profiles.get(profile_name).ok_or_else(|| {
            KernelRuntimeError::Policy(format!("missing profile '{profile_name}' while compiling"))
        })?;

        if filesystem_backend == FilesystemBackend::EbpfLsm {
            ensure_rule_count(
                profile_name,
                "file_allow",
                profile.file_allow.len(),
                MAX_KERNEL_RULES_PER_CLASS,
            )?;
            ensure_rule_count(
                profile_name,
                "file_deny",
                profile.file_deny.len(),
                MAX_KERNEL_RULES_PER_CLASS,
            )?;
        }
        ensure_rule_count(
            profile_name,
            "exec_allow",
            profile.exec_allow.len(),
            MAX_KERNEL_RULES_PER_CLASS,
        )?;
        ensure_rule_count(
            profile_name,
            "exec_deny",
            profile.exec_deny.len(),
            MAX_KERNEL_RULES_PER_CLASS,
        )?;
        ensure_rule_count(
            profile_name,
            "network_allow",
            profile.network_allow.len(),
            MAX_KERNEL_RULES_PER_CLASS,
        )?;
        ensure_rule_count(
            profile_name,
            "network_deny",
            profile.network_deny.len(),
            MAX_KERNEL_RULES_PER_CLASS,
        )?;
        let (
            file_allow_offset,
            file_allow_count,
            file_deny_offset,
            file_deny_count,
            workspace_offset,
            workspace_count,
        ) = if filesystem_backend == FilesystemBackend::EbpfLsm {
            ensure_rule_count(
                profile_name,
                "workspace_roots",
                profile.workspace_roots.len(),
                MAX_KERNEL_WORKSPACE_ROOTS,
            )?;

            let file_allow_offset = file_cursor;
            for rule in &profile.file_allow {
                let compiled_rule = compile_path_rule(
                    profile_name,
                    "file_allow.pattern",
                    rule.pattern.as_str(),
                    false,
                )?;
                file_rules.push((file_cursor, compiled_rule));
                rule_ids.insert(rule_ref(RULE_KIND_FILE, file_cursor), rule.id.clone());
                file_cursor = file_cursor.saturating_add(1);
            }
            let file_allow_count = file_cursor.saturating_sub(file_allow_offset);

            let file_deny_offset = file_cursor;
            for rule in &profile.file_deny {
                let compiled_rule = compile_path_rule(
                    profile_name,
                    "file_deny.pattern",
                    rule.pattern.as_str(),
                    false,
                )?;
                file_rules.push((file_cursor, compiled_rule));
                rule_ids.insert(rule_ref(RULE_KIND_FILE, file_cursor), rule.id.clone());
                file_cursor = file_cursor.saturating_add(1);
            }
            let file_deny_count = file_cursor.saturating_sub(file_deny_offset);

            let workspace_offset = file_cursor;
            for root in &profile.workspace_roots {
                let compiled_rule =
                    compile_path_rule(profile_name, "workspace_root", root.as_str(), true)?;
                file_rules.push((file_cursor, compiled_rule));
                rule_ids.insert(
                    rule_ref(RULE_KIND_WORKSPACE, file_cursor),
                    format!("workspace_root:{root}"),
                );
                file_cursor = file_cursor.saturating_add(1);
            }
            let workspace_count = file_cursor.saturating_sub(workspace_offset);

            (
                file_allow_offset,
                file_allow_count,
                file_deny_offset,
                file_deny_count,
                workspace_offset,
                workspace_count,
            )
        } else {
            (0, 0, 0, 0, 0, 0)
        };

        let exec_allow_offset = exec_cursor;
        for rule in &profile.exec_allow {
            if !should_compile_kernel_exec_rule(rule.path.as_str(), filesystem_backend) {
                continue;
            }
            let compiled_rule =
                compile_path_rule(profile_name, "exec_allow.path", rule.path.as_str(), false)?;
            exec_rules.push((exec_cursor, compiled_rule));
            rule_ids.insert(rule_ref(RULE_KIND_EXEC, exec_cursor), rule.id.clone());
            exec_cursor = exec_cursor.saturating_add(1);
        }
        let exec_allow_count = exec_cursor.saturating_sub(exec_allow_offset);

        let exec_deny_offset = exec_cursor;
        for rule in &profile.exec_deny {
            if !should_compile_kernel_exec_rule(rule.path.as_str(), filesystem_backend) {
                continue;
            }
            let compiled_rule =
                compile_path_rule(profile_name, "exec_deny.path", rule.path.as_str(), false)?;
            exec_rules.push((exec_cursor, compiled_rule));
            rule_ids.insert(rule_ref(RULE_KIND_EXEC, exec_cursor), rule.id.clone());
            exec_cursor = exec_cursor.saturating_add(1);
        }
        let exec_deny_count = exec_cursor.saturating_sub(exec_deny_offset);

        let net_allow_offset = net_cursor;
        for rule in &profile.network_allow {
            net_rules.push((net_cursor, compile_net_rule(rule)));
            rule_ids.insert(rule_ref(RULE_KIND_NET, net_cursor), rule.id.clone());
            net_cursor = net_cursor.saturating_add(1);
        }
        let net_allow_count = net_cursor.saturating_sub(net_allow_offset);

        let net_deny_offset = net_cursor;
        for rule in &profile.network_deny {
            net_rules.push((net_cursor, compile_net_rule(rule)));
            rule_ids.insert(rule_ref(RULE_KIND_NET, net_cursor), rule.id.clone());
            net_cursor = net_cursor.saturating_add(1);
        }
        let net_deny_count = net_cursor.saturating_sub(net_deny_offset);

        profiles.push((
            idx_u32,
            KernelProfileValue {
                name: {
                    ensure_string_fits(
                        profile_name,
                        "profile_name",
                        profile_name.as_str(),
                        PROFILE_NAME_BYTES,
                    )?;
                    copy_bytes(profile_name.as_str())
                },
                file_mode: enforcement_mode_to_u8(profile.enforcement.file),
                process_mode: enforcement_mode_to_u8(profile.enforcement.process),
                network_mode: enforcement_mode_to_u8(profile.enforcement.network),
                url_enforce: u8::from(
                    !profile.url_allow.is_empty() || !profile.url_deny.is_empty(),
                ),
                url_proxy_port,
                _pad0: 0,
                file_allow_offset,
                file_allow_count,
                file_deny_offset,
                file_deny_count,
                exec_allow_offset,
                exec_allow_count,
                exec_deny_offset,
                exec_deny_count,
                net_allow_offset,
                net_allow_count,
                net_deny_offset,
                net_deny_count,
                workspace_offset,
                workspace_count,
            },
        ));
    }

    if file_cursor > MAX_PATH_RULES {
        return Err(KernelRuntimeError::Policy(format!(
            "file/workspace rule count {} exceeds kernel map capacity {}",
            file_cursor, MAX_PATH_RULES
        )));
    }
    if exec_cursor > MAX_PATH_RULES {
        return Err(KernelRuntimeError::Policy(format!(
            "exec rule count {} exceeds kernel map capacity {}",
            exec_cursor, MAX_PATH_RULES
        )));
    }
    if net_cursor > MAX_NET_RULES {
        return Err(KernelRuntimeError::Policy(format!(
            "network rule count {} exceeds kernel map capacity {}",
            net_cursor, MAX_NET_RULES
        )));
    }

    let default_profile_index = profile_indices
        .get("default")
        .copied()
        .or_else(|| profiles.first().map(|(index, _)| *index))
        .unwrap_or(0);
    let realtime_offset_ns = realtime_offset_ns()?;
    let default_decision = match ir.defaults.decision {
        DefaultDecision::Allow => DEFAULT_DECISION_ALLOW,
        DefaultDecision::Deny => DEFAULT_DECISION_DENY,
    };

    Ok(CompiledEpochMaps {
        profile_indices,
        default_profile_index,
        profiles,
        file_rules,
        exec_rules,
        net_rules,
        rule_ids,
        offsets: KernelOffsetsValue {
            default_decision,
            policy_loaded: 1,
            _pad: 0,
            profile_count: profile_names.len() as u32,
            realtime_offset_ns,
            rate_limit_per_sec: 0, /* set by caller from config */
            policy_epoch: 0,
        },
    })
}

fn compile_net_rule(rule: &core_types::NetworkRule) -> KernelNetRuleValue {
    let mut compiled = KernelNetRuleValue {
        protocol: match rule.protocol {
            Some(NetworkProtocol::Tcp) => NET_PROTOCOL_TCP,
            Some(NetworkProtocol::Udp) => NET_PROTOCOL_UDP,
            None => NET_PROTOCOL_ANY,
        },
        has_port: u8::from(rule.port.is_some()),
        has_cidr: u8::from(rule.cidr.is_some()),
        cidr_prefix: 0,
        port: rule.port.unwrap_or(0),
        family: NET_FAMILY_UNSPEC,
        has_host_glob: u8::from(
            rule.host_glob
                .as_ref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false),
        ),
        addr: [0; 16],
    };

    if let Some(cidr) = &rule.cidr {
        compiled.cidr_prefix = cidr.prefix_len();
        match cidr.addr() {
            IpAddr::V4(v4) => {
                compiled.family = NET_FAMILY_INET4;
                compiled.addr[..4].copy_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                compiled.family = NET_FAMILY_INET6;
                compiled.addr.copy_from_slice(&v6.octets());
            }
        }
    }

    compiled
}

fn should_compile_kernel_exec_rule(path: &str, filesystem_backend: FilesystemBackend) -> bool {
    match filesystem_backend {
        FilesystemBackend::EbpfLsm => true,
        FilesystemBackend::AppArmor => is_kernel_process_sentinel_rule(path),
    }
}

fn is_kernel_process_sentinel_rule(path: &str) -> bool {
    path.starts_with('<') && path.ends_with('>')
}

fn enforcement_mode_to_u8(mode: EnforcementMode) -> u8 {
    match mode {
        EnforcementMode::Enforce => ENFORCEMENT_ENFORCE,
        EnforcementMode::Observe => ENFORCEMENT_OBSERVE,
    }
}

fn enrollment_mode_to_u8(mode: EnrollmentMode) -> u8 {
    match mode {
        EnrollmentMode::Enforce => ENFORCEMENT_ENFORCE,
        EnrollmentMode::Observe => ENFORCEMENT_OBSERVE,
    }
}

fn ensure_rule_count(
    profile_name: &str,
    class: &str,
    actual: usize,
    max_allowed: usize,
) -> Result<(), KernelRuntimeError> {
    if actual > max_allowed {
        return Err(KernelRuntimeError::Policy(format!(
            "profile '{profile_name}' has {actual} {class} entries; kernel backend limit is {max_allowed}"
        )));
    }
    Ok(())
}

fn ensure_string_fits(
    profile_name: &str,
    field: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), KernelRuntimeError> {
    if max_bytes == 0 {
        return Err(KernelRuntimeError::Policy(format!(
            "invalid zero-sized bound for {field}"
        )));
    }
    if value.len() >= max_bytes {
        return Err(KernelRuntimeError::Policy(format!(
            "profile '{profile_name}' {field} length {} exceeds kernel byte limit {}",
            value.len(),
            max_bytes.saturating_sub(1)
        )));
    }
    Ok(())
}

fn compile_path_rule(
    profile_name: &str,
    field: &str,
    raw_pattern: &str,
    workspace_root: bool,
) -> Result<KernelPathRuleValue, KernelRuntimeError> {
    if workspace_root {
        ensure_string_fits(
            profile_name,
            field,
            raw_pattern,
            kernel_ebpf::MAX_RULE_PATTERN_BYTES,
        )?;
        return Ok(KernelPathRuleValue {
            kind: PATH_RULE_KIND_EXACT,
            _pad0: 0,
            len: raw_pattern.len() as u16,
            pattern: copy_bytes(raw_pattern),
        });
    }

    if raw_pattern.contains('?') {
        return Err(KernelRuntimeError::Policy(format!(
            "profile '{profile_name}' {field}='{raw_pattern}' is unsupported by kernel matcher ('?' wildcard)"
        )));
    }

    if let Some(prefix_raw) = raw_pattern.strip_suffix("/**") {
        if prefix_raw.contains('*') {
            return Err(KernelRuntimeError::Policy(format!(
                "profile '{profile_name}' {field}='{raw_pattern}' has unsupported wildcard placement"
            )));
        }
        let prefix = prefix_raw.trim_end_matches('/');
        ensure_string_fits(
            profile_name,
            field,
            prefix,
            kernel_ebpf::MAX_RULE_PATTERN_BYTES,
        )?;
        return Ok(KernelPathRuleValue {
            kind: PATH_RULE_KIND_PREFIX_DIR,
            _pad0: 0,
            len: prefix.len() as u16,
            pattern: copy_bytes(prefix),
        });
    }

    if let Some(prefix_raw) = raw_pattern.strip_suffix("/*") {
        if prefix_raw.contains('*') {
            return Err(KernelRuntimeError::Policy(format!(
                "profile '{profile_name}' {field}='{raw_pattern}' has unsupported wildcard placement"
            )));
        }
        let prefix = prefix_raw.trim_end_matches('/');
        ensure_string_fits(
            profile_name,
            field,
            prefix,
            kernel_ebpf::MAX_RULE_PATTERN_BYTES,
        )?;
        return Ok(KernelPathRuleValue {
            kind: PATH_RULE_KIND_PREFIX_IMMEDIATE,
            _pad0: 0,
            len: prefix.len() as u16,
            pattern: copy_bytes(prefix),
        });
    }

    if raw_pattern.contains('*') {
        return Err(KernelRuntimeError::Policy(format!(
            "profile '{profile_name}' {field}='{raw_pattern}' has unsupported wildcard placement"
        )));
    }

    ensure_string_fits(
        profile_name,
        field,
        raw_pattern,
        kernel_ebpf::MAX_RULE_PATTERN_BYTES,
    )?;
    Ok(KernelPathRuleValue {
        kind: PATH_RULE_KIND_EXACT,
        _pad0: 0,
        len: raw_pattern.len() as u16,
        pattern: copy_bytes(raw_pattern),
    })
}

fn copy_bytes<const N: usize>(value: &str) -> [u8; N] {
    let mut out = [0u8; N];
    if N == 0 {
        return out;
    }
    let bytes = value.as_bytes();
    let copy_len = bytes.len().min(N.saturating_sub(1));
    out[..copy_len].copy_from_slice(&bytes[..copy_len]);
    out
}

fn realtime_offset_ns() -> Result<i64, KernelRuntimeError> {
    let mut realtime = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut monotonic = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    let realtime_rc = unsafe { clock_gettime(CLOCK_REALTIME, &mut realtime) };
    if realtime_rc != 0 {
        return Err(KernelRuntimeError::Unavailable(format!(
            "clock_gettime(CLOCK_REALTIME) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let monotonic_rc = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut monotonic) };
    if monotonic_rc != 0 {
        return Err(KernelRuntimeError::Unavailable(format!(
            "clock_gettime(CLOCK_MONOTONIC) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let realtime_ns = realtime.tv_sec as i128 * 1_000_000_000i128 + realtime.tv_nsec as i128;
    let monotonic_ns = monotonic.tv_sec as i128 * 1_000_000_000i128 + monotonic.tv_nsec as i128;
    let offset = realtime_ns.saturating_sub(monotonic_ns);
    let clamped = offset.clamp(i64::MIN as i128, i64::MAX as i128);
    Ok(clamped as i64)
}

fn initialize_kernel_offsets(state: &mut KernelRuntimeState) -> Result<(), KernelRuntimeError> {
    let Some(bpf) = state.bpf.as_mut() else {
        return Ok(());
    };
    let map = bpf.map_mut(OFFSETS_MAP_NAME).ok_or_else(|| {
        KernelRuntimeError::Unavailable(format!(
            "offsets map '{OFFSETS_MAP_NAME}' not found in eBPF object"
        ))
    })?;
    let mut offsets = AyaArray::<_, KernelOffsetsValue>::try_from(map).map_err(|err| {
        KernelRuntimeError::Unavailable(format!("open offsets map '{OFFSETS_MAP_NAME}': {err}"))
    })?;
    offsets
        .set(
            0,
            KernelOffsetsValue {
                default_decision: DEFAULT_DECISION_DENY,
                policy_loaded: 0,
                _pad: 0,
                profile_count: 0,
                realtime_offset_ns: realtime_offset_ns()?,
                rate_limit_per_sec: 0,
                policy_epoch: 0,
            },
            0,
        )
        .map_err(|err| {
            KernelRuntimeError::Unavailable(format!(
                "initialize offsets map '{OFFSETS_MAP_NAME}': {err}"
            ))
        })?;
    Ok(())
}

fn apply_epoch_maps(
    state: &mut KernelRuntimeState,
    compiled: &CompiledEpochMaps,
    filesystem_backend: FilesystemBackend,
) -> Result<(), KernelRuntimeError> {
    let Some(bpf) = state.bpf.as_mut() else {
        return Ok(());
    };

    let previous_counts = state
        .policy_epochs
        .get(&state.active_epoch)
        .map(|epoch| epoch_map_counts(&epoch.ir))
        .unwrap_or_default();

    {
        let map = bpf.map_mut(PROFILES_MAP_NAME).ok_or_else(|| {
            KernelRuntimeError::Unavailable(format!(
                "profiles map '{PROFILES_MAP_NAME}' not found in eBPF object"
            ))
        })?;
        let mut profile_map =
            AyaHashMap::<_, u32, KernelProfileValue>::try_from(map).map_err(|err| {
                KernelRuntimeError::Unavailable(format!(
                    "open profiles map '{PROFILES_MAP_NAME}': {err}"
                ))
            })?;
        sync_indexed_hash_map(
            &mut profile_map,
            previous_counts.profiles,
            compiled.profiles.as_slice(),
            PROFILES_MAP_NAME,
        )?;
    }

    if filesystem_backend == FilesystemBackend::EbpfLsm {
        let map = bpf.map_mut(FILE_RULES_MAP_NAME).ok_or_else(|| {
            KernelRuntimeError::Unavailable(format!(
                "file rules map '{FILE_RULES_MAP_NAME}' not found in eBPF object"
            ))
        })?;
        let mut file_rule_map =
            AyaHashMap::<_, u32, KernelPathRuleValue>::try_from(map).map_err(|err| {
                KernelRuntimeError::Unavailable(format!(
                    "open file rules map '{FILE_RULES_MAP_NAME}': {err}"
                ))
            })?;
        sync_indexed_hash_map(
            &mut file_rule_map,
            previous_counts.file_rules,
            compiled.file_rules.as_slice(),
            FILE_RULES_MAP_NAME,
        )?;
    }

    {
        let map = bpf.map_mut(EXEC_RULES_MAP_NAME).ok_or_else(|| {
            KernelRuntimeError::Unavailable(format!(
                "exec rules map '{EXEC_RULES_MAP_NAME}' not found in eBPF object"
            ))
        })?;
        let mut exec_rule_map =
            AyaHashMap::<_, u32, KernelPathRuleValue>::try_from(map).map_err(|err| {
                KernelRuntimeError::Unavailable(format!(
                    "open exec rules map '{EXEC_RULES_MAP_NAME}': {err}"
                ))
            })?;
        sync_indexed_hash_map(
            &mut exec_rule_map,
            previous_counts.exec_rules,
            compiled.exec_rules.as_slice(),
            EXEC_RULES_MAP_NAME,
        )?;
    }

    {
        let map = bpf.map_mut(NET_RULES_MAP_NAME).ok_or_else(|| {
            KernelRuntimeError::Unavailable(format!(
                "network rules map '{NET_RULES_MAP_NAME}' not found in eBPF object"
            ))
        })?;
        let mut net_rule_map =
            AyaHashMap::<_, u32, KernelNetRuleValue>::try_from(map).map_err(|err| {
                KernelRuntimeError::Unavailable(format!(
                    "open network rules map '{NET_RULES_MAP_NAME}': {err}"
                ))
            })?;
        sync_indexed_hash_map(
            &mut net_rule_map,
            previous_counts.net_rules,
            compiled.net_rules.as_slice(),
            NET_RULES_MAP_NAME,
        )?;
    }

    {
        let map = bpf.map_mut(OFFSETS_MAP_NAME).ok_or_else(|| {
            KernelRuntimeError::Unavailable(format!(
                "offsets map '{OFFSETS_MAP_NAME}' not found in eBPF object"
            ))
        })?;
        let mut offsets = AyaArray::<_, KernelOffsetsValue>::try_from(map).map_err(|err| {
            KernelRuntimeError::Unavailable(format!("open offsets map '{OFFSETS_MAP_NAME}': {err}"))
        })?;
        offsets.set(0, compiled.offsets, 0).map_err(|err| {
            KernelRuntimeError::Unavailable(format!(
                "write offsets map '{OFFSETS_MAP_NAME}': {err}"
            ))
        })?;
    }

    Ok(())
}

fn sync_indexed_hash_map<M, V: Pod + Copy>(
    map: &mut AyaHashMap<M, u32, V>,
    previous_count: u32,
    entries: &[(u32, V)],
    map_name: &str,
) -> Result<(), KernelRuntimeError>
where
    M: BorrowMut<MapData>,
{
    for (key, value) in entries {
        map.insert(*key, *value, 0).map_err(|err| {
            KernelRuntimeError::Unavailable(format!("insert key {key} into '{map_name}': {err}"))
        })?;
    }

    let new_count = entries.len() as u32;
    if previous_count > new_count {
        for key in new_count..previous_count {
            match map.remove(&key) {
                Ok(()) => {}
                Err(err) if is_missing_map_entry_error(&err) => {}
                Err(err) => {
                    return Err(KernelRuntimeError::Unavailable(format!(
                        "remove stale key {key} from '{map_name}': {err}"
                    )));
                }
            }
        }
    }

    Ok(())
}

fn is_missing_map_entry_error(err: &MapError) -> bool {
    match err {
        MapError::KeyNotFound | MapError::ElementNotFound => true,
        MapError::SyscallError(syscall) => syscall.io_error.raw_os_error() == Some(ENOENT),
        _ => false,
    }
}

fn epoch_map_counts(ir: &KernelPolicyIr) -> EpochMapCounts {
    let mut counts = EpochMapCounts {
        profiles: ir.profile_count,
        ..EpochMapCounts::default()
    };

    for profile in ir.profiles.values() {
        counts.file_rules = counts
            .file_rules
            .saturating_add(profile.file_allow.len() as u32)
            .saturating_add(profile.file_deny.len() as u32)
            .saturating_add(profile.workspace_roots.len() as u32);
        counts.exec_rules = counts
            .exec_rules
            .saturating_add(profile.exec_allow.len() as u32)
            .saturating_add(profile.exec_deny.len() as u32);
        counts.net_rules = counts
            .net_rules
            .saturating_add(profile.network_allow.len() as u32)
            .saturating_add(profile.network_deny.len() as u32);
    }

    counts
}

fn sync_all_pid_maps(state: &mut KernelRuntimeState) -> Result<(), KernelRuntimeError> {
    let (reclaimed_enrolled, reclaimed_ignored) = prune_dead_kernel_pid_maps(state)?;
    if reclaimed_enrolled > 0 || reclaimed_ignored > 0 {
        warn!(
            reclaimed_enrolled,
            reclaimed_ignored, "reclaimed dead kernel PID map entries during runtime sync"
        );
    }
    sync_enrollment_map(state)?;
    let ignored: Vec<u32> = state.ignored_pids.iter().copied().collect();
    for pid in ignored {
        sync_ignored_pid(state, pid, true)?;
    }
    Ok(())
}

/// Assigns a fresh kernel enrollment id and records what it refers to.
fn insert_enrollment(state: &mut KernelRuntimeState, pid: u32, mut enrollment: PidEnrollment) {
    let enrollment_id = state.next_enrollment_id;
    state.next_enrollment_id = state.next_enrollment_id.checked_add(1).unwrap_or(1);
    enrollment.enrollment_id = enrollment_id;
    state.enrollment_identities.insert(
        enrollment_id,
        EnrollmentIdentity {
            agent_id: enrollment.agent_id,
            root_pid: pid,
            profile: enrollment.profile.clone(),
            cgroup_id: enrollment.cgroup_id.clone(),
            retired: false,
        },
    );
    if let Some(previous) = state.enrollments.insert(pid, enrollment) {
        retire_identity(state, previous.enrollment_id);
    }
}

/// Marks an identity retired and bounds how many retired ones are kept.
fn retire_identity(state: &mut KernelRuntimeState, enrollment_id: u32) {
    if let Some(identity) = state.enrollment_identities.get_mut(&enrollment_id) {
        identity.retired = true;
    }
    let retired: Vec<u32> = state
        .enrollment_identities
        .iter()
        .filter(|(_, identity)| identity.retired)
        .map(|(id, _)| *id)
        .collect();
    if retired.len() > MAX_RETIRED_IDENTITIES {
        let mut retired = retired;
        retired.sort_unstable();
        for id in retired.iter().take(retired.len() - MAX_RETIRED_IDENTITIES) {
            state.enrollment_identities.remove(id);
        }
    }
}

fn sync_enrollment_map(state: &mut KernelRuntimeState) -> Result<(), KernelRuntimeError> {
    let pids: Vec<u32> = state.enrollments.keys().copied().collect();
    for pid in pids {
        sync_enrollment_pid(state, pid, true)?;
    }
    remap_member_profiles(state)
}

/*
 * Descendants (fork-inherited or restored entries) are not tracked in
 * `state.enrollments`, and their map values carry a profile *index*. Profile
 * indices are reassigned on every policy load (sorted names), so without this
 * a reload that adds or removes a profile left descendants enforcing some
 * other profile. Re-resolve them through their enrollment identity.
 */
fn remap_member_profiles(state: &mut KernelRuntimeState) -> Result<(), KernelRuntimeError> {
    let identities: HashMap<u32, u32> = state
        .enrollment_identities
        .iter()
        .map(|(id, identity)| (*id, resolve_profile_index(state, identity.profile.as_str())))
        .collect();
    let Some(bpf) = state.bpf.as_mut() else {
        return Ok(());
    };
    let map = bpf.map_mut(ENROLLED_PIDS_MAP_NAME).ok_or_else(|| {
        KernelRuntimeError::Unavailable(format!(
            "enrolled pid map '{ENROLLED_PIDS_MAP_NAME}' not found in eBPF object"
        ))
    })?;
    let mut pid_map = AyaHashMap::<_, u32, EnrolledPidValue>::try_from(map).map_err(|err| {
        KernelRuntimeError::Unavailable(format!(
            "open enrolled pid map '{ENROLLED_PIDS_MAP_NAME}': {err}"
        ))
    })?;
    let updates: Vec<(u32, EnrolledPidValue)> = pid_map
        .iter()
        .filter_map(Result::ok)
        .filter_map(|(pid, mut value)| {
            let index = *identities.get(&value.enrollment_id)?;
            (value.profile_index != index).then(|| {
                value.profile_index = index;
                (pid, value)
            })
        })
        .collect();
    for (pid, value) in updates {
        if let Err(err) = pid_map.insert(pid, value, 0) {
            warn!(pid, error = %err, "failed to remap descendant profile after policy load");
        }
    }
    Ok(())
}

fn resolve_profile_index(state: &KernelRuntimeState, profile: &str) -> u32 {
    let Some(active) = state.policy_epochs.get(&state.active_epoch) else {
        return 0;
    };
    active
        .profile_indices
        .get(profile)
        .copied()
        .or_else(|| active.profile_indices.get("default").copied())
        .unwrap_or(active.default_profile_index)
}

fn sync_enrollment_pid(
    state: &mut KernelRuntimeState,
    pid: u32,
    present: bool,
) -> Result<(), KernelRuntimeError> {
    let value = if present {
        let enrollment = state.enrollments.get(&pid).ok_or_else(|| {
            KernelRuntimeError::Unavailable(format!("missing enrollment record for pid {pid}"))
        })?;
        Some(EnrolledPidValue {
            profile_index: resolve_profile_index(state, enrollment.profile.as_str()),
            mode: enrollment_mode_to_u8(enrollment.mode),
            launch_exec_bypass: u8::from(matches!(enrollment.source, EnrollmentSource::AiRun)),
            _pad: [0; 2],
            enrollment_id: enrollment.enrollment_id,
        })
    } else {
        None
    };

    let Some(bpf) = state.bpf.as_mut() else {
        return Ok(());
    };
    let map = bpf.map_mut(ENROLLED_PIDS_MAP_NAME).ok_or_else(|| {
        KernelRuntimeError::Unavailable(format!(
            "enrolled pid map '{ENROLLED_PIDS_MAP_NAME}' not found in eBPF object"
        ))
    })?;
    let mut pid_map = AyaHashMap::<_, u32, EnrolledPidValue>::try_from(map).map_err(|err| {
        KernelRuntimeError::Unavailable(format!(
            "open enrolled pid map '{ENROLLED_PIDS_MAP_NAME}': {err}"
        ))
    })?;

    if let Some(mut value) = value {
        /*
         * The launch bypass is armed once, at registration, and cleared by the
         * kernel when the launcher execs the agent. Re-syncs (policy reloads)
         * must keep the kernel's current value: re-arming it handed every
         * running agent root unrestricted file access until its next exec.
         */
        if let Ok(existing) = pid_map.get(&pid, 0) {
            value.launch_exec_bypass = existing.launch_exec_bypass.min(value.launch_exec_bypass);
        }
        if let Err(err) = pid_map.insert(pid, value, 0) {
            let reclaimed = prune_dead_pid_entries_from_map(&mut pid_map, ENROLLED_PIDS_MAP_NAME)?;
            if reclaimed == 0 {
                return Err(KernelRuntimeError::Unavailable(format!(
                    "insert pid {pid} into map '{ENROLLED_PIDS_MAP_NAME}': {err}"
                )));
            }
            warn!(
                pid,
                reclaimed,
                "reclaimed dead enrolled PID entries after insert failure; retrying update"
            );
            pid_map.insert(pid, value, 0).map_err(|retry_err| {
                KernelRuntimeError::Unavailable(format!(
                    "insert pid {pid} into map '{ENROLLED_PIDS_MAP_NAME}' after reclaiming {reclaimed} dead entries: {retry_err}"
                ))
            })?;
        }
    } else {
        match pid_map.remove(&pid) {
            Ok(()) => {}
            Err(err) if is_missing_map_entry_error(&err) => {}
            Err(err) => {
                return Err(KernelRuntimeError::Unavailable(format!(
                    "remove pid {pid} from map '{ENROLLED_PIDS_MAP_NAME}': {err}"
                )));
            }
        }
    }

    Ok(())
}

fn sync_ignored_pid(
    state: &mut KernelRuntimeState,
    pid: u32,
    present: bool,
) -> Result<(), KernelRuntimeError> {
    let Some(bpf) = state.bpf.as_mut() else {
        return Ok(());
    };
    let map = bpf.map_mut(IGNORED_PIDS_MAP_NAME).ok_or_else(|| {
        KernelRuntimeError::Unavailable(format!(
            "ignored pid map '{IGNORED_PIDS_MAP_NAME}' not found in eBPF object"
        ))
    })?;
    let mut pid_map = AyaHashMap::<_, u32, u8>::try_from(map).map_err(|err| {
        KernelRuntimeError::Unavailable(format!(
            "open ignored pid map '{IGNORED_PIDS_MAP_NAME}': {err}"
        ))
    })?;

    if present {
        if let Err(err) = pid_map.insert(pid, 1, 0) {
            let reclaimed = prune_dead_pid_entries_from_map(&mut pid_map, IGNORED_PIDS_MAP_NAME)?;
            if reclaimed == 0 {
                return Err(KernelRuntimeError::Unavailable(format!(
                    "insert pid {pid} into map '{IGNORED_PIDS_MAP_NAME}': {err}"
                )));
            }
            warn!(
                pid,
                reclaimed,
                "reclaimed dead ignored PID entries after insert failure; retrying update"
            );
            pid_map.insert(pid, 1, 0).map_err(|retry_err| {
                KernelRuntimeError::Unavailable(format!(
                    "insert pid {pid} into map '{IGNORED_PIDS_MAP_NAME}' after reclaiming {reclaimed} dead entries: {retry_err}"
                ))
            })?;
        }
    } else {
        match pid_map.remove(&pid) {
            Ok(()) => {}
            Err(err) if is_missing_map_entry_error(&err) => {}
            Err(err) => {
                return Err(KernelRuntimeError::Unavailable(format!(
                    "remove pid {pid} from map '{IGNORED_PIDS_MAP_NAME}': {err}"
                )));
            }
        }
    }
    Ok(())
}

fn prune_dead_kernel_pid_maps(
    state: &mut KernelRuntimeState,
) -> Result<(usize, usize), KernelRuntimeError> {
    let Some(bpf) = state.bpf.as_mut() else {
        return Ok((0, 0));
    };

    let enrolled_removed = {
        let map = bpf.map_mut(ENROLLED_PIDS_MAP_NAME).ok_or_else(|| {
            KernelRuntimeError::Unavailable(format!(
                "enrolled pid map '{ENROLLED_PIDS_MAP_NAME}' not found in eBPF object"
            ))
        })?;
        let mut pid_map = AyaHashMap::<_, u32, EnrolledPidValue>::try_from(map).map_err(|err| {
            KernelRuntimeError::Unavailable(format!(
                "open enrolled pid map '{ENROLLED_PIDS_MAP_NAME}': {err}"
            ))
        })?;
        prune_dead_pid_entries_from_map(&mut pid_map, ENROLLED_PIDS_MAP_NAME)?
    };

    let ignored_removed = {
        let map = bpf.map_mut(IGNORED_PIDS_MAP_NAME).ok_or_else(|| {
            KernelRuntimeError::Unavailable(format!(
                "ignored pid map '{IGNORED_PIDS_MAP_NAME}' not found in eBPF object"
            ))
        })?;
        let mut pid_map = AyaHashMap::<_, u32, u8>::try_from(map).map_err(|err| {
            KernelRuntimeError::Unavailable(format!(
                "open ignored pid map '{IGNORED_PIDS_MAP_NAME}': {err}"
            ))
        })?;
        prune_dead_pid_entries_from_map(&mut pid_map, IGNORED_PIDS_MAP_NAME)?
    };

    Ok((enrolled_removed, ignored_removed))
}

fn prune_dead_pid_entries_from_map<M, V: Pod>(
    map: &mut AyaHashMap<M, u32, V>,
    map_name: &str,
) -> Result<usize, KernelRuntimeError>
where
    M: Borrow<MapData> + BorrowMut<MapData>,
{
    let stale_pids: Vec<u32> = map
        .keys()
        .filter_map(|entry| match entry {
            Ok(pid) => read_proc_start_time(pid).is_none().then_some(Ok(pid)),
            Err(err) => Some(Err(KernelRuntimeError::Unavailable(format!(
                "iterate keys in '{map_name}': {err}"
            )))),
        })
        .collect::<Result<_, _>>()?;

    let mut removed = 0usize;
    for pid in stale_pids {
        match map.remove(&pid) {
            Ok(()) => removed += 1,
            Err(err) if is_missing_map_entry_error(&err) => {}
            Err(err) => {
                return Err(KernelRuntimeError::Unavailable(format!(
                    "remove dead pid {pid} from map '{map_name}': {err}"
                )));
            }
        }
    }
    Ok(removed)
}

fn refresh_runtime_stats(state: &mut KernelRuntimeState) -> Result<(), KernelRuntimeError> {
    let Some(bpf) = state.bpf.as_mut() else {
        return Ok(());
    };

    let map = bpf.map_mut(STATS_MAP_NAME).ok_or_else(|| {
        KernelRuntimeError::Unavailable(format!("stats map '{STATS_MAP_NAME}' not found"))
    })?;
    let stats_map = AyaArray::<_, u64>::try_from(map).map_err(|err| {
        KernelRuntimeError::Unavailable(format!("open stats map '{STATS_MAP_NAME}': {err}"))
    })?;
    let read = |index| {
        stats_map.get(&index, 0).map_err(|err| {
            KernelRuntimeError::Unavailable(format!(
                "read counter {index} from map '{STATS_MAP_NAME}': {err}"
            ))
        })
    };
    state.unenrolled_events_suppressed_total = read(STATS_UNENROLLED_SUPPRESSED_INDEX)?;
    state.events_dropped_ringbuf_total = read(STATS_RINGBUF_DROPPED_INDEX)?;
    state.events_rate_limited_total = read(STATS_RATE_LIMITED_INDEX)?;
    state.deny_events_dropped_total = read(STATS_DENY_DROPPED_INDEX)?;
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawKernelEvent {
    timestamp_ns: u64,
    seq: u64,
    cgroup_id: u64,
    _reserved: u64,
    pid: u32,
    tid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    action: u32,
    decision: u32,
    reason: u32,
    enrollment_id: u32,
    policy_epoch: u32,
    rule_ref: u32,
    target_pid: u32,
    aux: u32,
    port: u16,
    flags: u8,
    protocol: u8,
    family: u8,
    _pad: [u8; 3],
    ip: [u8; 16],
    comm: [u8; 16],
    profile: [u8; 32],
    resource: [u8; 256],
    resource2: [u8; 512],
}

const _: () = assert!(std::mem::size_of::<RawKernelEvent>() == 928);

impl Default for RawKernelEvent {
    fn default() -> Self {
        // The kernel initializes the record before submission. Tests need the
        // same all-zero layout without spelling every wire field.
        unsafe { std::mem::zeroed() }
    }
}

fn attach_lsm_program(
    bpf: &mut Ebpf,
    program_name: &str,
    hook_name: &str,
    btf: &Btf,
) -> Result<(), KernelRuntimeError> {
    let program: &mut Lsm = bpf
        .program_mut(program_name)
        .ok_or_else(|| {
            KernelRuntimeError::Unavailable(format!("missing LSM program '{program_name}'"))
        })?
        .try_into()
        .map_err(|err| {
            KernelRuntimeError::Unavailable(format!(
                "program '{program_name}' is not an LSM program: {err}"
            ))
        })?;
    program.load(hook_name, btf).map_err(|err| {
        KernelRuntimeError::Unavailable(format!(
            "failed to load LSM program '{program_name}' for hook '{hook_name}': {err}"
        ))
    })?;
    program.attach().map_err(|err| {
        KernelRuntimeError::Unavailable(format!(
            "failed to attach LSM program '{program_name}': {err}"
        ))
    })?;
    Ok(())
}

fn attach_tracepoint_program(
    bpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    name: &str,
) -> Result<(), KernelRuntimeError> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| {
            KernelRuntimeError::Unavailable(format!("missing tracepoint program '{program_name}'"))
        })?
        .try_into()
        .map_err(|err| {
            KernelRuntimeError::Unavailable(format!(
                "program '{program_name}' is not a tracepoint program: {err}"
            ))
        })?;
    program.load().map_err(|err| {
        KernelRuntimeError::Unavailable(format!(
            "failed to load tracepoint program '{program_name}': {err}"
        ))
    })?;
    program.attach(category, name).map_err(|err| {
        KernelRuntimeError::Unavailable(format!(
            "failed to attach tracepoint program '{program_name}' to {category}/{name}: {err}"
        ))
    })?;
    Ok(())
}

/// Rule-ref kinds written by the eBPF evaluators (see RULE_KIND_* in mercury_kern.c).
const RULE_KIND_FILE: u32 = 1;
const RULE_KIND_EXEC: u32 = 2;
const RULE_KIND_NET: u32 = 3;
const RULE_KIND_WORKSPACE: u32 = 4;
const RULE_KIND_SYNTHETIC: u32 = 5;

const EVENT_FLAG_PATH_UNRESOLVED: u8 = 0x01;
const EVENT_FLAG_ARGV_TRUNCATED: u8 = 0x02;
const EVENT_FLAG_SOURCE_UNRESOLVED: u8 = 0x04;
const EVENT_FLAG_EXEC_FROM_THREAD: u8 = 0x08;

const ACTION_TELEMETRY_SUPPRESSED: u32 = 30;

fn rule_ref(kind: u32, key: u32) -> u32 {
    (kind << 24) | (key & 0x00FF_FFFF)
}

/// Built-in kernel decisions that are not backed by a policy rule.
fn synthetic_rule_id(id: u32) -> Option<&'static str> {
    match id {
        1 => Some("builtin:url-enforcement-direct-egress"),
        2 => Some("builtin:ptrace-outside-enrollment"),
        3 => Some("builtin:signal-to-mercury"),
        4 => Some("builtin:bpf-requires-explicit-allow"),
        5 => Some("builtin:kernel-module-requires-explicit-allow"),
        _ => None,
    }
}

/// Snapshot of runtime state needed to decode ring buffer records, taken
/// under the state lock once per drain.
struct DecodeContext {
    epochs: HashMap<u32, (String, Arc<HashMap<u32, String>>)>,
    identities: HashMap<u32, EnrollmentIdentity>,
}

fn family_name(family: u8) -> Option<String> {
    match family {
        0 => None,
        1 => Some("unix".to_string()),
        2 => Some("inet".to_string()),
        10 => Some("inet6".to_string()),
        other => Some(other.to_string()),
    }
}

/// Splits the NUL-separated argv block read from mm->arg_start.
fn parse_argv(bytes: &[u8]) -> Vec<String> {
    let end = bytes
        .iter()
        .rposition(|b| *b != 0)
        .map(|idx| idx + 1)
        .unwrap_or(0);
    bytes[..end]
        .split(|b| *b == 0)
        .map(|arg| String::from_utf8_lossy(arg).to_string())
        .collect()
}

/// `task->exit_code`: low 7 bits are the terminating signal, bits 8-15 the status.
fn decode_exit_code(raw: u32) -> (Option<i32>, Option<u32>) {
    let signal = raw & 0x7f;
    if signal == 0 {
        (Some(((raw >> 8) & 0xff) as i32), None)
    } else {
        (None, Some(signal))
    }
}

fn decode_kernel_event(data: &[u8], ctx: &DecodeContext) -> Option<AuditEvent> {
    if data.len() < std::mem::size_of::<RawKernelEvent>() {
        return None;
    }

    let raw = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RawKernelEvent) };
    let timestamp = if raw.timestamp_ns >= 1_000_000_000_000_000 {
        chrono::DateTime::<Utc>::from_timestamp(
            (raw.timestamp_ns / 1_000_000_000) as i64,
            (raw.timestamp_ns % 1_000_000_000) as u32,
        )
        .unwrap_or_else(Utc::now)
    } else {
        Utc::now()
    };

    let profile = parse_cstr(&raw.profile);
    let profile = if profile.is_empty() {
        "default".to_string()
    } else {
        profile
    };
    let (policy_version, rule_ids) = match ctx.epochs.get(&raw.policy_epoch) {
        Some((version, rules)) => (version.clone(), Some(rules)),
        None => ("unloaded".to_string(), None),
    };
    let identity = ctx.identities.get(&raw.enrollment_id);
    let agent_id = identity
        .map(|identity| identity.agent_id.to_string())
        .unwrap_or_else(|| format!("kernel-pid-{}", raw.pid));

    let resource_path = parse_cstr(&raw.resource);
    let resource2 = parse_cstr(&raw.resource2);
    let path_or = |fallback: &str| {
        if resource_path.is_empty() {
            fallback.to_string()
        } else {
            resource_path.clone()
        }
    };
    let file = |op: FileOp, source_path: Option<String>| {
        Resource::File(FileResource {
            path: path_or("<kernel>"),
            resolved_path: None,
            op,
            source_path,
        })
    };
    let family = family_name(raw.family);
    let protocol = if raw.protocol == 2 {
        NetworkProtocol::Udp
    } else {
        NetworkProtocol::Tcp
    };
    let socket_path = (raw.family == 1 && !resource2.is_empty()).then(|| resource2.clone());
    let network = |dest_ip: Option<String>, dest_port: u16, protocol: NetworkProtocol| {
        Resource::Network(NetworkResource {
            dest_host: None,
            dest_ip,
            dest_port,
            protocol,
            full_url: None,
            scheme: None,
            method: None,
            path: None,
            query: None,
            socket_path: socket_path.clone(),
            family: family.clone(),
        })
    };
    let exec = |path: String, argv: Vec<String>, argv_truncated: bool| {
        Resource::Exec(ExecResource {
            path,
            argv_hash: None,
            cwd: String::new(),
            argv,
            argv_truncated,
        })
    };
    let non_empty = |value: &String| (!value.is_empty()).then(|| value.clone());

    let (action_type, resource) = match raw.action {
        1 => (ActionType::FileRead, file(FileOp::Read, None)),
        2 => (ActionType::FileDelete, file(FileOp::Delete, None)),
        3 => (
            ActionType::ProcExec,
            exec(path_or("<kernel>"), Vec::new(), false),
        ),
        4 => (
            ActionType::NetConnect,
            network(parse_ip(&raw.ip), raw.port, protocol),
        ),
        5 => (ActionType::FileWrite, file(FileOp::Write, None)),
        6 => (ActionType::FileMmap, file(FileOp::Write, None)),
        7 => (
            ActionType::NetSendmsg,
            network(parse_ip(&raw.ip), raw.port, NetworkProtocol::Udp),
        ),
        8 => (
            ActionType::FileRename,
            file(FileOp::Rename, non_empty(&resource2)),
        ),
        9 => (
            ActionType::FileLink,
            file(FileOp::Link, non_empty(&resource2)),
        ),
        10 => (ActionType::FileSymlink, file(FileOp::Symlink, None)),
        11 => (ActionType::FileMkdir, file(FileOp::Mkdir, None)),
        12 => (ActionType::FileRmdir, file(FileOp::Rmdir, None)),
        13 => (ActionType::FileCreate, file(FileOp::Create, None)),
        14 => (ActionType::FileChmod, file(FileOp::Chmod, None)),
        15 => (ActionType::FileChown, file(FileOp::Chown, None)),
        16 => (ActionType::FileTruncate, file(FileOp::Truncate, None)),
        17 => (
            ActionType::NetBind,
            network(parse_ip(&raw.ip), raw.port, protocol),
        ),
        18 => (ActionType::NetListen, network(None, raw.port, protocol)),
        19 => (ActionType::NetAccept, network(None, raw.port, protocol)),
        20 => (ActionType::NetCreate, network(None, 0, protocol)),
        21 => (
            ActionType::ProcPtrace,
            exec(path_or("<ptrace>"), Vec::new(), false),
        ),
        22 => (
            ActionType::ProcKill,
            exec("<task-kill>".to_string(), Vec::new(), false),
        ),
        23 => (
            ActionType::ProcCapable,
            exec("<capable>".to_string(), Vec::new(), false),
        ),
        24 => (
            ActionType::ProcStart,
            exec(
                path_or("<unknown>"),
                parse_argv(&raw.resource2),
                raw.flags & EVENT_FLAG_ARGV_TRUNCATED != 0,
            ),
        ),
        25 => (
            ActionType::ProcExit,
            exec(parse_cstr(&raw.comm), Vec::new(), false),
        ),
        26 => (
            ActionType::ProcBpf,
            exec("<bpf>".to_string(), Vec::new(), false),
        ),
        27 => (
            ActionType::ProcModuleLoad,
            exec("<kernel-module>".to_string(), Vec::new(), false),
        ),
        28 => (
            ActionType::ProcMount,
            exec(
                "<mount>".to_string(),
                non_empty(&resource2).into_iter().collect(),
                false,
            ),
        ),
        29 => (
            ActionType::ProcUserns,
            exec("<userns>".to_string(), Vec::new(), false),
        ),
        ACTION_TELEMETRY_SUPPRESSED => {
            let mut event = AuditEvent::system(
                "kernel-ebpf",
                SystemResource::new("telemetry_loss")
                    .detail("per-process rate limit suppressed allow events")
                    .attr("cause", "rate_limit")
                    .attr("suppressed", raw.aux)
                    .attr("pid", raw.pid),
                policy_version,
                format!(
                    "kernel rate limit suppressed {} allow events for pid {}",
                    raw.aux, raw.pid
                ),
            );
            event.timestamp = timestamp;
            event.agent_id = agent_id;
            event.pid = Some(raw.pid);
            event.profile = profile;
            event.kernel_seq = Some(raw.seq);
            event.context.comm = non_empty(&parse_cstr(&raw.comm));
            return Some(event);
        }
        _ => return None,
    };

    let decision = if raw.decision == 1 {
        Decision::Deny
    } else {
        Decision::Allow
    };
    let reason = match raw.reason {
        0 => DecisionReason::AllowByRule,
        1 => DecisionReason::DenyByRule,
        2 => DecisionReason::AllowUnenrolledObserve,
        3 => DecisionReason::AllowByObserveMode,
        4 => DecisionReason::DenyByDefault,
        REASON_ALLOW_BY_DEFAULT => DecisionReason::AllowByDefault,
        _ if decision == Decision::Deny => DecisionReason::DenyByRule,
        _ => DecisionReason::AllowByRule,
    };
    let rule_id = match raw.rule_ref >> 24 {
        0 => None,
        RULE_KIND_SYNTHETIC => synthetic_rule_id(raw.rule_ref & 0x00FF_FFFF).map(str::to_string),
        _ => rule_ids.and_then(|rules| rules.get(&raw.rule_ref).cloned()),
    };

    let (exit_code, exit_signal) = if raw.action == 25 {
        decode_exit_code(raw.aux)
    } else {
        (None, None)
    };
    let mut context = core_types::EventContext {
        source: Some("kernel-ebpf".to_string()),
        tid: Some(raw.tid),
        gid: Some(raw.gid),
        comm: non_empty(&parse_cstr(&raw.comm)),
        cgroup_id: (raw.cgroup_id != 0).then_some(raw.cgroup_id),
        root_pid: identity.map(|identity| identity.root_pid),
        policy_epoch: (raw.policy_epoch != 0).then_some(u64::from(raw.policy_epoch)),
        exit_code,
        exit_signal,
        ..Default::default()
    };
    match raw.action {
        21 => {
            context.target_pid = (raw.target_pid != 0).then_some(raw.target_pid);
        }
        22 => {
            context.target_pid = (raw.target_pid != 0).then_some(raw.target_pid);
            context.signal = Some(raw.aux);
        }
        23 => context.capability = Some(raw.aux),
        24 if raw.flags & EVENT_FLAG_EXEC_FROM_THREAD != 0 => {
            context.target_pid = Some(raw.target_pid);
        }
        _ => {}
    }
    if raw.flags & (EVENT_FLAG_PATH_UNRESOLVED | EVENT_FLAG_SOURCE_UNRESOLVED) != 0 {
        context.truncated = Some(true);
    }

    Some(AuditEvent {
        timestamp,
        agent_id,
        pid: Some(raw.pid),
        ppid: (raw.ppid != 0).then_some(raw.ppid),
        uid: Some(raw.uid),
        action_type,
        decision,
        reason,
        rule_id,
        resource,
        profile,
        policy_version,
        message: format!(
            "source=kernel-ebpf pid={} tid={} uid={} action={} decision={:?}",
            raw.pid, raw.tid, raw.uid, raw.action, decision
        ),
        mcp: None,
        kernel_seq: Some(raw.seq),
        events_dropped: None,
        model: None,
        context,
    })
}

fn parse_cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

fn parse_ip(bytes: &[u8; 16]) -> Option<String> {
    if bytes.iter().all(|b| *b == 0) {
        return None;
    }
    if bytes[4..].iter().all(|b| *b == 0) {
        return Some(format!(
            "{}.{}.{}.{}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        ));
    }
    Some(format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        u16::from_be_bytes([bytes[0], bytes[1]]),
        u16::from_be_bytes([bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u16::from_be_bytes([bytes[10], bytes[11]]),
        u16::from_be_bytes([bytes[12], bytes[13]]),
        u16::from_be_bytes([bytes[14], bytes[15]]),
    ))
}

pub fn read_proc_start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_proc_start_time_from_stat(stat.as_str())
}

pub fn read_proc_uid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_proc_uid_from_status(status.as_str())
}

fn parse_proc_start_time_from_stat(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    let rest = stat.get(close + 2..)?;
    let mut fields = rest.split_whitespace();
    for _ in 0..19 {
        fields.next()?;
    }
    fields.next()?.parse::<u64>().ok()
}

fn parse_proc_uid_from_status(status: &str) -> Option<u32> {
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace().nth(1)?.parse::<u32>().ok()
}

fn detect_capabilities(bpffs_path: &str, cgroup_root: &str) -> KernelCapabilityReport {
    let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    let kernel_version_ok = is_kernel_6_1_or_newer(kernel_release.as_str());
    let bpf_fs_present = Path::new(bpffs_path).exists();
    let bpf_lsm_available = fs::read_to_string("/sys/kernel/security/lsm")
        .map(|lsm| lsm.split(',').any(|token| token.trim() == "bpf"))
        .unwrap_or(false);

    let cgroup_root_path = Path::new(cgroup_root);
    let cgroup_v2 = cgroup_root_path.join("cgroup.controllers").exists();

    KernelCapabilityReport {
        kernel_release,
        kernel_version_ok,
        bpf_fs_present,
        bpf_lsm_available,
        cgroup_v2,
    }
}

fn is_kernel_6_1_or_newer(release: &str) -> bool {
    let mut parts = release.split(['.', '-']);
    let major = parts
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    major > 6 || (major == 6 && minor >= 1)
}

fn walk_cgroup_procs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir);
        let Ok(entries) = entries else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path
                .file_name()
                .map(|name| name == "cgroup.procs")
                .unwrap_or(false)
            {
                out.push(path);
            }
        }
    }

    out
}

#[derive(Debug, Error)]
pub enum KernelRuntimeError {
    #[error("kernel backend unavailable: {0}")]
    Unavailable(String),
    #[error("policy compile: {0}")]
    Policy(String),
    #[error("invalid config: {0}")]
    Config(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("internal: {0}")]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn kernel_version_parser_handles_common_release() {
        assert!(is_kernel_6_1_or_newer("6.1.0"));
        assert!(is_kernel_6_1_or_newer("6.6.12-arch1-1"));
        assert!(!is_kernel_6_1_or_newer("5.15.0"));
    }

    #[test]
    fn auto_enroll_scan_detects_matching_cgroup() {
        let tmp = tempdir().expect("tempdir");
        let bpffs = tmp.path().join("bpffs");
        let cgroup = tmp.path().join("cgroup");
        let grp = cgroup.join("system.slice/my-agent.service");
        fs::create_dir_all(&bpffs).expect("bpffs");
        fs::create_dir_all(&grp).expect("group");
        fs::write(cgroup.join("cgroup.controllers"), "cpu memory").expect("controllers");
        fs::write(
            grp.join("cgroup.procs"),
            format!("{}\n", std::process::id()),
        )
        .expect("procs");

        let runtime = KernelRuntime::new(
            KernelRuntimeConfig {
                bpffs_path: bpffs.to_string_lossy().to_string(),
                cgroup_root: cgroup.to_string_lossy().to_string(),
                auto_enroll_rules: vec![AutoEnrollRule {
                    id: "r1".to_string(),
                    cgroup_pattern: "**/my-agent.service/cgroup.procs".to_string(),
                    profile: "default".to_string(),
                    mode: EnrollmentMode::Enforce,
                }],
                ..KernelRuntimeConfig::default()
            },
            FilesystemBackend::EbpfLsm,
        );

        // Force-start not required for scanner behavior.
        let loaded = runtime.scan_auto_enroll().expect("scan");
        assert!(loaded >= 1);
        assert!(runtime.is_pid_enrolled(std::process::id()));
        let enrollment = runtime
            .enrollment_for_pid(std::process::id())
            .expect("enrollment");
        assert_eq!(enrollment.uid, unsafe { libc::getuid() as u32 });
    }

    #[test]
    fn embedded_ebpf_ebpf_lsm_object_contains_expected_programs_and_map() {
        let bytes = PROGRAM_OBJECT_EBPF_LSM.to_vec();
        let object = aya_obj::Object::parse(&bytes).expect("parse embedded ebpf object");
        assert!(object.programs.contains_key(PROG_FILE_OPEN));
        assert!(object.programs.contains_key(PROG_INODE_UNLINK));
        assert!(object.programs.contains_key(PROG_BPRM_CHECK_SECURITY));
        assert!(object.programs.contains_key(PROG_SOCKET_CONNECT));
        assert!(object.programs.contains_key(PROG_MMAP_FILE));
        assert!(object.programs.contains_key(PROG_SOCKET_SENDMSG));
        assert!(object.programs.contains_key(PROG_SCHED_FORK));
        assert!(object.programs.contains_key(PROG_SCHED_EXIT));
        assert!(object.maps.contains_key(EVENTS_MAP_NAME));
        assert!(object.maps.contains_key(FILE_RULES_MAP_NAME));
    }

    #[test]
    fn embedded_ebpf_apparmor_object_excludes_filesystem_programs() {
        let bytes = PROGRAM_OBJECT_APPARMOR.to_vec();
        let object = aya_obj::Object::parse(&bytes).expect("parse embedded ebpf object");
        assert!(!object.programs.contains_key(PROG_FILE_OPEN));
        assert!(!object.programs.contains_key(PROG_INODE_UNLINK));
        assert!(!object.programs.contains_key(PROG_MMAP_FILE));
        assert!(!object.programs.contains_key(PROG_BPRM_CHECK_SECURITY));
        assert!(object.programs.contains_key(PROG_SOCKET_CONNECT));
        assert!(object.programs.contains_key(PROG_SCHED_FORK));
        assert!(object.maps.contains_key(EVENTS_MAP_NAME));
        assert!(!object.maps.contains_key(FILE_RULES_MAP_NAME));
    }

    #[test]
    fn apparmor_backend_keeps_only_synthetic_exec_rules_in_kernel() {
        assert!(should_compile_kernel_exec_rule(
            "<ptrace>",
            FilesystemBackend::AppArmor
        ));
        assert!(should_compile_kernel_exec_rule(
            "<task-kill>",
            FilesystemBackend::AppArmor
        ));
        assert!(!should_compile_kernel_exec_rule(
            "/usr/bin/echo",
            FilesystemBackend::AppArmor
        ));
        assert!(should_compile_kernel_exec_rule(
            "/usr/bin/echo",
            FilesystemBackend::EbpfLsm
        ));
    }

    #[test]
    fn parse_proc_start_time_handles_comm_with_spaces() {
        let stat = "1234 (mercury run) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 21";
        assert_eq!(parse_proc_start_time_from_stat(stat), Some(424242));
    }

    #[test]
    fn parse_proc_uid_reads_real_uid_field() {
        let status = "Name:\tmercuryd\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_proc_uid_from_status(status), Some(1000));
    }

    #[test]
    fn compile_path_rule_distinguishes_immediate_and_recursive_prefixes() {
        let immediate =
            compile_path_rule("default", "exec_allow.path", "/usr/bin/*", false).expect("rule");
        let recursive =
            compile_path_rule("default", "exec_allow.path", "/usr/bin/**", false).expect("rule");

        assert_eq!(immediate.kind, PATH_RULE_KIND_PREFIX_IMMEDIATE);
        assert_eq!(recursive.kind, PATH_RULE_KIND_PREFIX_DIR);
        assert_ne!(immediate.kind, recursive.kind);
    }

    #[test]
    fn compiled_path_rule_semantics_match_immediate_and_recursive_expectations() {
        let immediate =
            compile_path_rule("default", "exec_allow.path", "/usr/bin/*", false).expect("rule");
        let recursive =
            compile_path_rule("default", "exec_allow.path", "/usr/bin/**", false).expect("rule");

        assert!(test_path_rule_matches(&immediate, "/usr/bin/python"));
        assert!(!test_path_rule_matches(
            &immediate,
            "/usr/bin/subdir/python"
        ));
        assert!(test_path_rule_matches(&recursive, "/usr/bin/python"));
        assert!(test_path_rule_matches(&recursive, "/usr/bin/subdir/python"));
    }

    fn raw_event(action: u32) -> RawKernelEvent {
        // SAFETY: RawKernelEvent is plain old data; all-zero is a valid value.
        let mut raw: RawKernelEvent = unsafe { std::mem::zeroed() };
        raw.timestamp_ns = 1_700_000_000_000_000_000;
        raw.pid = 42;
        raw.tid = 43;
        raw.ppid = 7;
        raw.uid = 1000;
        raw.gid = 1000;
        raw.action = action;
        raw.policy_epoch = 1;
        raw.enrollment_id = 9;
        raw.cgroup_id = 555;
        raw.profile[..7].copy_from_slice(b"default");
        raw.comm[..4].copy_from_slice(b"bash");
        raw
    }

    fn decode(raw: &RawKernelEvent, ctx: &DecodeContext) -> Option<AuditEvent> {
        // SAFETY: reading the bytes of a repr(C) POD value.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (raw as *const RawKernelEvent).cast::<u8>(),
                std::mem::size_of::<RawKernelEvent>(),
            )
        };
        decode_kernel_event(bytes, ctx)
    }

    fn decode_ctx() -> DecodeContext {
        let rules = HashMap::from([
            (rule_ref(RULE_KIND_FILE, 3), "deny-ssh".to_string()),
            (
                rule_ref(RULE_KIND_WORKSPACE, 4),
                "workspace_root:/work".to_string(),
            ),
        ]);
        DecodeContext {
            epochs: HashMap::from([(1, ("v1".to_string(), Arc::new(rules)))]),
            identities: HashMap::from([(
                9,
                EnrollmentIdentity {
                    agent_id: Uuid::nil(),
                    root_pid: 40,
                    profile: "default".to_string(),
                    cgroup_id: "ai-test".to_string(),
                    retired: true,
                },
            )]),
        }
    }

    fn set_cstr<const N: usize>(field: &mut [u8; N], value: &[u8]) {
        field[..value.len()].copy_from_slice(value);
    }

    #[test]
    fn raw_kernel_event_layout_matches_ebpf() {
        assert_eq!(std::mem::size_of::<RawKernelEvent>(), 928);
        assert_eq!(std::mem::offset_of!(RawKernelEvent, pid), 32);
        assert_eq!(std::mem::offset_of!(RawKernelEvent, port), 84);
        assert_eq!(std::mem::offset_of!(RawKernelEvent, ip), 92);
        assert_eq!(std::mem::offset_of!(RawKernelEvent, comm), 108);
        assert_eq!(std::mem::offset_of!(RawKernelEvent, resource), 156);
        assert_eq!(std::mem::offset_of!(RawKernelEvent, resource2), 412);
    }

    #[test]
    fn decode_kernel_event_carries_process_context_and_drops_unknown_actions() {
        let ctx = decode_ctx();
        let mut raw = raw_event(1);
        raw.reason = REASON_ALLOW_BY_DEFAULT;
        set_cstr(&mut raw.resource, b"/tmp/input");

        let event = decode(&raw, &ctx).expect("decode");
        assert_eq!(event.action_type, ActionType::FileRead);
        assert_eq!(event.reason, DecisionReason::AllowByDefault);
        assert_eq!(event.agent_id, Uuid::nil().to_string());
        assert_eq!(event.ppid, Some(7));
        assert_eq!(event.policy_version, "v1");
        assert_eq!(event.context.root_pid, Some(40));
        assert_eq!(event.context.tid, Some(43));
        assert_eq!(event.context.comm.as_deref(), Some("bash"));
        assert_eq!(event.context.cgroup_id, Some(555));
        assert_eq!(event.context.source.as_deref(), Some("kernel-ebpf"));

        raw.enrollment_id = 77;
        let event = decode(&raw, &ctx).expect("decode");
        assert_eq!(event.agent_id, "kernel-pid-42");
        assert_eq!(event.context.root_pid, None);

        raw.action = 99;
        assert!(decode(&raw, &ctx).is_none());
    }

    #[test]
    fn decode_kernel_event_resolves_rule_ids() {
        let ctx = decode_ctx();
        let mut raw = raw_event(8);
        raw.decision = 1;
        raw.reason = 1;
        raw.rule_ref = rule_ref(RULE_KIND_FILE, 3);
        set_cstr(&mut raw.resource, b"/tmp/x");
        set_cstr(&mut raw.resource2, b"/home/u/.ssh/id_rsa");
        let event = decode(&raw, &ctx).expect("decode");
        assert_eq!(event.decision, Decision::Deny);
        assert_eq!(event.rule_id.as_deref(), Some("deny-ssh"));
        match &event.resource {
            Resource::File(file) => {
                assert_eq!(file.path, "/tmp/x");
                assert_eq!(file.source_path.as_deref(), Some("/home/u/.ssh/id_rsa"));
            }
            other => panic!("unexpected resource {other:?}"),
        }

        raw.rule_ref = rule_ref(RULE_KIND_SYNTHETIC, 2);
        let event = decode(&raw, &ctx).expect("decode");
        assert_eq!(
            event.rule_id.as_deref(),
            Some("builtin:ptrace-outside-enrollment")
        );

        raw.policy_epoch = 5;
        raw.rule_ref = rule_ref(RULE_KIND_FILE, 3);
        let event = decode(&raw, &ctx).expect("decode");
        assert_eq!(event.rule_id, None, "unknown epoch must not guess a rule");
        assert_eq!(event.policy_version, "unloaded");
    }

    #[test]
    fn decode_kernel_event_process_lifecycle() {
        let ctx = decode_ctx();
        let mut raw = raw_event(24);
        set_cstr(&mut raw.resource, b"/usr/bin/curl");
        set_cstr(&mut raw.resource2, b"curl\0-sS\0https://example.com\0");
        raw.flags = EVENT_FLAG_ARGV_TRUNCATED;
        let event = decode(&raw, &ctx).expect("decode");
        assert_eq!(event.action_type, ActionType::ProcStart);
        match &event.resource {
            Resource::Exec(exec) => {
                assert_eq!(exec.path, "/usr/bin/curl");
                assert_eq!(exec.argv, vec!["curl", "-sS", "https://example.com"]);
                assert!(exec.argv_truncated);
            }
            other => panic!("unexpected resource {other:?}"),
        }

        let mut raw = raw_event(25);
        raw.aux = 3 << 8;
        let event = decode(&raw, &ctx).expect("decode");
        assert_eq!(event.action_type, ActionType::ProcExit);
        assert_eq!(event.context.exit_code, Some(3));
        assert_eq!(event.context.exit_signal, None);
        raw.aux = 9;
        let event = decode(&raw, &ctx).expect("decode");
        assert_eq!(event.context.exit_code, None);
        assert_eq!(event.context.exit_signal, Some(9));
    }

    #[test]
    fn decode_kernel_event_targets_sockets_and_telemetry_loss() {
        let ctx = decode_ctx();
        let mut raw = raw_event(22);
        raw.decision = 1;
        raw.target_pid = 1234;
        raw.aux = 9;
        let event = decode(&raw, &ctx).expect("decode");
        assert_eq!(event.context.target_pid, Some(1234));
        assert_eq!(event.context.signal, Some(9));

        let mut raw = raw_event(4);
        raw.family = 1;
        set_cstr(&mut raw.resource, b"<socket_connect>");
        set_cstr(&mut raw.resource2, b"/var/run/docker.sock");
        let event = decode(&raw, &ctx).expect("decode");
        match &event.resource {
            Resource::Network(net) => {
                assert_eq!(net.socket_path.as_deref(), Some("/var/run/docker.sock"));
                assert_eq!(net.family.as_deref(), Some("unix"));
            }
            other => panic!("unexpected resource {other:?}"),
        }

        let mut raw = raw_event(ACTION_TELEMETRY_SUPPRESSED);
        raw.aux = 250;
        let event = decode(&raw, &ctx).expect("decode");
        assert_eq!(event.action_type, ActionType::SystemEvent);
        assert_eq!(event.reason, DecisionReason::Informational);
        match &event.resource {
            Resource::System(system) => {
                assert_eq!(system.event, "telemetry_loss");
                assert_eq!(system.attributes["suppressed"], 250);
            }
            other => panic!("unexpected resource {other:?}"),
        }
    }

    #[test]
    fn enrollment_ids_are_unique_and_retired_identities_are_bounded() {
        let runtime =
            KernelRuntime::new(KernelRuntimeConfig::default(), FilesystemBackend::EbpfLsm);
        let enrollment = |cgroup: &str| PidEnrollment {
            agent_id: Uuid::new_v4(),
            profile: "default".to_string(),
            uid: 1000,
            proc_start_time: 1,
            source: EnrollmentSource::AiRun,
            mode: EnrollmentMode::Enforce,
            cgroup_id: cgroup.to_string(),
            enrollment_id: 0,
        };
        let mut state = runtime.state.write();
        insert_enrollment(&mut state, 100, enrollment("a"));
        insert_enrollment(&mut state, 200, enrollment("b"));
        let first = state.enrollments[&100].enrollment_id;
        let second = state.enrollments[&200].enrollment_id;
        assert_ne!(first, 0);
        assert_ne!(first, second);
        assert_eq!(state.enrollment_identities[&first].root_pid, 100);

        // Re-registering a pid retires the old identity but keeps it resolvable.
        insert_enrollment(&mut state, 100, enrollment("c"));
        assert!(state.enrollment_identities[&first].retired);
        assert_ne!(state.enrollments[&100].enrollment_id, first);

        for pid in 0..(MAX_RETIRED_IDENTITIES as u32 + 10) {
            insert_enrollment(&mut state, 1000 + pid, enrollment("x"));
            let id = state.enrollments[&(1000 + pid)].enrollment_id;
            retire_identity(&mut state, id);
        }
        let retired = state
            .enrollment_identities
            .values()
            .filter(|identity| identity.retired)
            .count();
        assert_eq!(retired, MAX_RETIRED_IDENTITIES);
    }

    #[test]
    fn prune_stale_enrollments_removes_dead_pid_entries() {
        let runtime =
            KernelRuntime::new(KernelRuntimeConfig::default(), FilesystemBackend::EbpfLsm);
        let pid = std::process::id();
        let proc_start_time = read_proc_start_time(pid).expect("proc start time");
        runtime.state.write().enrollments.insert(
            pid,
            PidEnrollment {
                agent_id: Uuid::nil(),
                profile: "default".to_string(),
                uid: 1000,
                proc_start_time,
                source: EnrollmentSource::AiRun,
                mode: EnrollmentMode::Enforce,
                cgroup_id: "ai-test".to_string(),
                enrollment_id: 0,
            },
        );
        runtime.state.write().enrollments.insert(
            pid + 10_000,
            PidEnrollment {
                agent_id: Uuid::nil(),
                profile: "default".to_string(),
                uid: 1000,
                proc_start_time: 0,
                source: EnrollmentSource::AiRun,
                mode: EnrollmentMode::Enforce,
                cgroup_id: "ai-stale".to_string(),
                enrollment_id: 0,
            },
        );

        let removed = runtime.prune_stale_enrollments().expect("prune");
        assert_eq!(removed, 1);
        assert!(runtime.enrollment_for_pid(pid).is_some());
        assert!(runtime.enrollment_for_pid(pid + 10_000).is_none());
    }

    fn test_path_rule_matches(rule: &KernelPathRuleValue, candidate: &str) -> bool {
        let pattern = parse_cstr(&rule.pattern[..usize::from(rule.len)]);
        match rule.kind {
            PATH_RULE_KIND_EXACT => candidate == pattern,
            PATH_RULE_KIND_PREFIX_DIR => {
                candidate == pattern
                    || candidate
                        .strip_prefix(pattern.as_str())
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }
            PATH_RULE_KIND_PREFIX_IMMEDIATE => {
                let Some(suffix) = candidate.strip_prefix(pattern.as_str()) else {
                    return false;
                };
                let Some(remainder) = suffix.strip_prefix('/') else {
                    return false;
                };
                !remainder.is_empty() && !remainder.contains('/')
            }
            _ => false,
        }
    }
}
