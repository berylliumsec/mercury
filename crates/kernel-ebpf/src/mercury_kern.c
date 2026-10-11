#include "vmlinux.h"

#define SEC(NAME) __attribute__((section(NAME), used))
#define __noinline __attribute__((noinline))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

#ifndef ___bpf_concat
#define ___bpf_concat(a, b) a##b
#endif
#ifndef ___bpf_apply
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#endif
#ifndef ___bpf_nth
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#endif
#ifndef ___bpf_narg
#define ___bpf_narg(...) ___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#endif

#define ___bpf_ctx_cast0() ctx
#define ___bpf_ctx_cast1(x) ___bpf_ctx_cast0(), (void *)ctx[0]
#define ___bpf_ctx_cast2(x, args...) ___bpf_ctx_cast1(args), (void *)ctx[1]
#define ___bpf_ctx_cast3(x, args...) ___bpf_ctx_cast2(args), (void *)ctx[2]
#define ___bpf_ctx_cast4(x, args...) ___bpf_ctx_cast3(args), (void *)ctx[3]
#define ___bpf_ctx_cast(args...) ___bpf_apply(___bpf_ctx_cast, ___bpf_narg(args))(args)

#define BPF_PROG(name, args...)                                                                     \
    name(unsigned long long *ctx);                                                                  \
    static __always_inline typeof(name(0)) ____##name(unsigned long long *ctx, ##args);            \
    typeof(name(0)) name(unsigned long long *ctx)                                                   \
    {                                                                                                \
        _Pragma("GCC diagnostic push")                                                              \
        _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")                                      \
        return ____##name(___bpf_ctx_cast(args));                                                   \
        _Pragma("GCC diagnostic pop")                                                               \
    }                                                                                                \
    static __always_inline typeof(name(0)) ____##name(unsigned long long *ctx, ##args)

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_RINGBUF 27

#define BPF_ANY 0
#define BPF_F_NO_PREALLOC 1
#define BPF_F_RDONLY_PROG (1U << 7)

#define AF_INET 2
#define AF_INET6 10
#define AF_UNIX 1
#define SOCK_DGRAM 2
#define EPERM 1

#define ACTION_FILE_OPEN      1
#define ACTION_FILE_DELETE    2
#define ACTION_EXEC           3
#define ACTION_NET_CONNECT    4
#define ACTION_FILE_WRITE     5
#define ACTION_FILE_MMAP      6   /* writable MAP_SHARED mmap — writes are flushed to the file */
#define ACTION_NET_SENDMSG    7   /* UDP send without prior connect */
/* File-mutation hooks */
#define ACTION_FILE_RENAME    8
#define ACTION_FILE_LINK      9
#define ACTION_FILE_SYMLINK  10
#define ACTION_FILE_MKDIR    11
#define ACTION_FILE_RMDIR    12
#define ACTION_FILE_CREATE   13
#define ACTION_FILE_CHMOD    14
#define ACTION_FILE_CHOWN    15
#define ACTION_FILE_TRUNCATE 16
/* Network server-side hooks */
#define ACTION_NET_BIND      17
#define ACTION_NET_LISTEN    18
#define ACTION_NET_ACCEPT    19
#define ACTION_NET_CREATE    20
/* Process supervision hooks */
#define ACTION_PROC_PTRACE   21
#define ACTION_PROC_KILL     22
#define ACTION_PROC_CAPABLE  23
/* process lifecycle (tracepoints) */
#define ACTION_PROC_START    24   /* execve committed; resource=filename, resource2=argv */
#define ACTION_PROC_EXIT     25   /* thread group dead; aux=exit_code */
/* privileged / tamper-relevant operations */
#define ACTION_PROC_BPF      26   /* bpf(2); aux=cmd */
#define ACTION_PROC_MODULE   27   /* kernel module load; aux=read-file/load-data id */
#define ACTION_PROC_MOUNT    28   /* mount(2)/move_mount(2); resource=target, resource2=source */
#define ACTION_PROC_USERNS   29   /* user namespace creation */
/* telemetry health */
#define ACTION_TELEMETRY_SUPPRESSED 30 /* per-pid rate-limit summary; aux=suppressed count */

#define PROT_WRITE  0x2
#define MAP_SHARED  0x01
#define MAP_PRIVATE 0x02


#define DECISION_ALLOW 0
#define DECISION_DENY 1

#define REASON_ALLOW_BY_RULE 0
#define REASON_DENY_BY_RULE 1
#define REASON_ALLOW_UNENROLLED_OBSERVE 2
#define REASON_ALLOW_BY_OBSERVE_MODE 3
#define REASON_DENY_BY_DEFAULT 4
#define REASON_ALLOW_BY_DEFAULT 5

#define ENFORCEMENT_ENFORCE 0
#define ENFORCEMENT_OBSERVE 1

/*
 * rule_ref identifies the rule that produced a decision: kind in the top
 * byte, the key into the kind's rule map (or a SYNTH_* id) in the low 24 bits.
 * Userspace maps it back to the policy rule id for the event's policy epoch.
 */
#define RULE_KIND_NONE      0
#define RULE_KIND_FILE      1
#define RULE_KIND_EXEC      2
#define RULE_KIND_NET       3
#define RULE_KIND_WORKSPACE 4
#define RULE_KIND_SYNTHETIC 5
#define RULE_REF(kind, key) ((((u32)(kind)) << 24) | (((u32)(key)) & 0xFFFFFF))

#define SYNTH_URL_DIRECT_EGRESS   1  /* URL-enforced profile, non-proxy egress */
#define SYNTH_PTRACE_UNENROLLED   2  /* ptrace of a task outside the enrollment */
#define SYNTH_SIGNAL_PROTECTED    3  /* signal to a Mercury-owned (ignored) task */
#define SYNTH_BPF_DEFAULT_DENY    4  /* bpf(2) without an explicit exec_allow "<bpf>" */
#define SYNTH_MODULE_DEFAULT_DENY 5  /* module load without exec_allow "<kernel-module>" */

/* include/linux/ptrace.h */
#define PTRACE_MODE_READ    0x01
#define PTRACE_MODE_ATTACH  0x02
#define PTRACE_MODE_NOAUDIT 0x04

#define EVENT_FLAG_PATH_UNRESOLVED   0x01
#define EVENT_FLAG_ARGV_TRUNCATED    0x02
#define EVENT_FLAG_SOURCE_UNRESOLVED 0x04
#define EVENT_FLAG_EXEC_FROM_THREAD  0x08

/* mercury_stats indexes — all monotonic, read by userspace */
#define STAT_UNENROLLED_SUPPRESSED 0
#define STAT_RINGBUF_DROPPED       1  /* allow/observe events lost to a full ring buffer */
#define STAT_RATE_LIMITED          2  /* allow/observe events suppressed by the per-pid limiter */
#define STAT_DENY_DROPPED          3  /* DENY events lost to a full ring buffer */
#define STAT_ENTRIES               8

#define MAX_PROFILE_NAME_BYTES 32
#define MAX_RESOURCE_BYTES 256
#define SCRATCH_RESOURCE_BYTES (MAX_RESOURCE_BYTES + 1)
#define MAX_RESOURCE2_BYTES 512   /* argv / rename source / mount source; power of two */
#define TASK_COMM_BYTES 16
#define MAX_RULE_PATTERN_BYTES 256
#define MAX_RULES_PER_CLASS 32
#define MAX_WORKSPACE_ROOTS 64
#define MATCH_CHUNK_BYTES 32

#ifndef MERCURY_DISABLE_FILESYSTEM_LSM
#define MERCURY_DISABLE_FILESYSTEM_LSM 0
#endif

#ifndef MERCURY_DISABLE_EXEC_PATH_LSM
#define MERCURY_DISABLE_EXEC_PATH_LSM 0
#endif

#if MERCURY_DISABLE_FILESYSTEM_LSM
#define MERCURY_ENABLE_FILESYSTEM_LSM 0
#else
#define MERCURY_ENABLE_FILESYSTEM_LSM 1
#endif

#if MERCURY_DISABLE_EXEC_PATH_LSM
#define MERCURY_ENABLE_EXEC_PATH_LSM 0
#else
#define MERCURY_ENABLE_EXEC_PATH_LSM 1
#endif

#define PATH_RULE_KIND_EXACT 0
#define PATH_RULE_KIND_PREFIX_DIR 1
#define PATH_RULE_KIND_PREFIX_IMMEDIATE 2

static void *(*bpf_ringbuf_reserve)(void *ringbuf, u64 size, u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, u64 flags) = (void *)132;
static u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, u64 flags) =
    (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_probe_read_kernel)(void *dst, u32 size, const void *unsafe_ptr) = (void *)113;
static long (*bpf_probe_read_kernel_str)(void *dst, u32 size, const void *unsafe_ptr) = (void *)115;
static long (*bpf_d_path)(struct path *path, char *buf, u32 sz) __attribute__((unused)) =
    (void *)147;
static u32 (*bpf_get_smp_processor_id)(void) = (void *)8;
static long (*bpf_get_current_comm)(void *buf, u32 size) = (void *)16;
static u64 (*bpf_get_current_task)(void) = (void *)35;
static u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static long (*bpf_probe_read_user)(void *dst, u32 size, const void *unsafe_ptr) = (void *)112;

#define BPF_CORE_READ(src, field)                                                                      \
    ({                                                                                                  \
        typeof((src)->field) __val;                                                                    \
        __builtin_memset(&__val, 0, sizeof(__val));                                                    \
        bpf_probe_read_kernel(                                                                          \
            &__val,                                                                                     \
            sizeof(__val),                                                                              \
            (const void *)__builtin_preserve_access_index(&(src)->field));                             \
        __val;                                                                                          \
    })

/*
 * Ring buffer record. Layout must match RawKernelEvent in
 * crates/kernel-runtime/src/linux_impl.rs (checked by a size assertion there).
 */
struct mercury_event {
    u64 timestamp_ns;
    u64 seq;            /* (cpu << 48) | per-cpu counter; gaps mean ring buffer loss */
    u64 cgroup_id;
    u64 _reserved;
    u32 pid;            /* tgid */
    u32 tid;
    u32 ppid;           /* real_parent tgid */
    u32 uid;
    u32 gid;
    u32 action;
    u32 decision;
    u32 reason;
    u32 enrollment_id;
    u32 policy_epoch;
    u32 rule_ref;
    u32 target_pid;
    u32 aux;            /* signal / capability / exit code / bpf cmd / suppressed count */
    u16 port;
    u8 flags;
    u8 protocol;
    u8 family;
    u8 _pad[3];
    u8 ip[16];
    char comm[TASK_COMM_BYTES];
    char profile[MAX_PROFILE_NAME_BYTES];
    char resource[MAX_RESOURCE_BYTES];
    char resource2[MAX_RESOURCE2_BYTES];
};

_Static_assert(sizeof(struct mercury_event) == 928, "mercury_event layout changed");

struct mercury_enrollment {
    u32 profile_index;
    u8 mode;
    u8 launch_exec_bypass;
    u8 _pad[2];
    u32 enrollment_id;  /* assigned by userspace; inherited across fork */
};

struct mercury_profile {
    char name[MAX_PROFILE_NAME_BYTES];
    u8 file_mode;
    u8 process_mode;
    u8 network_mode;
    u8 url_enforce;
    u16 url_proxy_port;
    u16 _pad0;

    u32 file_allow_offset;
    u32 file_allow_count;
    u32 file_deny_offset;
    u32 file_deny_count;

    u32 exec_allow_offset;
    u32 exec_allow_count;
    u32 exec_deny_offset;
    u32 exec_deny_count;

    u32 net_allow_offset;
    u32 net_allow_count;
    u32 net_deny_offset;
    u32 net_deny_count;

    u32 workspace_offset;
    u32 workspace_count;
};

struct mercury_path_rule {
    u8 kind;
    u8 _pad0;
    u16 len;
    char pattern[MAX_RULE_PATTERN_BYTES];
};

struct mercury_net_rule {
    u8 protocol;
    u8 has_port;
    u8 has_cidr;
    u8 cidr_prefix;
    u16 port;
    u8 family;
    u8 has_host_glob;
    u8 addr[16];
};

struct mercury_offsets {
    u8 default_decision;
    u8 policy_loaded;
    u16 _pad;
    u32 profile_count;
    s64 realtime_offset_ns;
    u32 rate_limit_per_sec;  /* 0 = disabled; never applied to DENY events */
    u32 policy_epoch;        /* epoch of the rules currently in the maps */
};

struct mercury_net_dest {
    u8 family;
    u8 protocol;
    u16 port;
    u8 has_addr;
    u8 addr[16];
};

struct mercury_scratch {
    char resource[SCRATCH_RESOURCE_BYTES];
    char resource2[MAX_RESOURCE2_BYTES * 2];  /* doubled so masked offsets stay in bounds */
};

struct mercury_emit_ctx {
    u32 action;
    u32 pid;
    u32 uid;
    u32 decision;
    u32 reason;
    const char *profile;
    const char *resource;
    const char *resource2;       /* optional kernel string */
    const void *resource2_user;  /* optional user memory (argv), resource2_len bytes */
    u32 resource2_len;
    u16 port;
    const u8 *ip;
    u32 rule_ref;
    u32 target_pid;
    u32 aux;
    u32 enrollment_id;
    u8 flags;
    u8 protocol;
    u8 family;
};

struct mercury_decision_ctx {
    u32 action;
    u32 decision;
    u32 reason;
    struct mercury_profile *profile;
    struct mercury_enrollment *enrollment;
    u8 class_mode;
    const char *resource;
    const char *resource2;
    u16 port;
    const u8 *ip;
    u32 rule_ref;
    u32 target_pid;
    u32 aux;
    u8 flags;
    u8 protocol;
    u8 family;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} mercury_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 18);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, struct mercury_enrollment);
} mercury_enrolled_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, u8);
} mercury_ignored_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct mercury_scratch);
} mercury_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} mercury_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} mercury_seq SEC(".maps");

struct mercury_rate_state {
    u64 window_start_ns;
    u32 count;
    u32 suppressed;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 18);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, struct mercury_rate_state);
} mercury_rate_limit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, struct mercury_profile);
} mercury_profiles SEC(".maps");

#if MERCURY_ENABLE_FILESYSTEM_LSM
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 17);
    __uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG);
    __type(key, u32);
    __type(value, struct mercury_path_rule);
} mercury_file_rules SEC(".maps");
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 17);
    __uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG);
    __type(key, u32);
    __type(value, struct mercury_path_rule);
} mercury_exec_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 16);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, struct mercury_net_rule);
} mercury_net_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct mercury_offsets);
} mercury_offsets SEC(".maps");

static __inline u16 ntohs(u16 value)
{
    return (value >> 8) | (value << 8);
}

static __inline int pid_in_map(void *map, u32 pid)
{
    u8 *value = bpf_map_lookup_elem(map, &pid);
    return value != (void *)0;
}

static __inline void bump_unenrolled_suppressed(void)
{
    u32 index = STAT_UNENROLLED_SUPPRESSED;
    u64 *counter = bpf_map_lookup_elem(&mercury_stats, &index);
    if (!counter) {
        return;
    }
    __sync_fetch_and_add(counter, 1);
}

static __noinline void copy_cstr(char *dst, int dst_len, const char *src)
{
    int i;
    if (dst_len <= 0) {
        return;
    }

    for (i = 0; i < dst_len - 1; i++) {
        char c = src[i];
        dst[i] = c;
        if (c == '\0') {
            return;
        }
    }
    dst[dst_len - 1] = '\0';
}

static __noinline int exact_match(
    const char *candidate,
    const char *pattern,
    u32 len);

static __noinline int prefix_dir_match(
    const char *candidate,
    const char *pattern,
    u32 len);

#if MERCURY_ENABLE_FILESYSTEM_LSM
static __noinline int workspace_rule_matches(
    const struct mercury_path_rule *rule,
    const char *candidate)
{
    u32 len;

    if (!rule || !candidate) {
        return 0;
    }

    len = rule->len;
    if (len >= MAX_RULE_PATTERN_BYTES) {
        return 0;
    }

    if (len == 0) {
        return 1;
    }

    return prefix_dir_match(candidate, rule->pattern, len);
}
#endif

/*
 * Compare candidate against pattern for exactly len bytes, then check
 * for a null terminator.  Uses bpf_probe_read_kernel in a bounded loop
 * of 32-byte chunks — no noinline sub-calls — so the BPF verifier
 * explores a single linear path per invocation.
 */
static __noinline int exact_match(
    const char *candidate,
    const char *pattern,
    u32 len)
{
    u64 cand_words[4];
    u64 pat_words[4];
    char suffix = '\0';
    u32 offset;

    if (len == 0) {
        bpf_probe_read_kernel(&suffix, sizeof(suffix), candidate);
        return suffix == '\0';
    }

    /* Full 32-byte chunks — constant-size reads, verifier-friendly. */
#pragma clang loop unroll(disable)
    for (offset = 0; offset < MAX_RULE_PATTERN_BYTES; offset += MATCH_CHUNK_BYTES) {
        if (offset + MATCH_CHUNK_BYTES > len) {
            break;
        }
        __builtin_memset(cand_words, 0, sizeof(cand_words));
        __builtin_memset(pat_words, 0, sizeof(pat_words));
        bpf_probe_read_kernel(cand_words, MATCH_CHUNK_BYTES, candidate + offset);
        bpf_probe_read_kernel(pat_words, MATCH_CHUNK_BYTES, pattern + offset);
        if (cand_words[0] != pat_words[0]) return 0;
        if (cand_words[1] != pat_words[1]) return 0;
        if (cand_words[2] != pat_words[2]) return 0;
        if (cand_words[3] != pat_words[3]) return 0;
    }

    /* Remaining 0-31 bytes — variable-size read with verifier hint. */
    {
        unsigned long remaining = len - offset;
        asm volatile("%0 &= 31" : "+r"(remaining));
        if (remaining > 0) {
            __builtin_memset(cand_words, 0, sizeof(cand_words));
            __builtin_memset(pat_words, 0, sizeof(pat_words));
            bpf_probe_read_kernel(cand_words, remaining, candidate + offset);
            bpf_probe_read_kernel(pat_words, remaining, pattern + offset);
            if (cand_words[0] != pat_words[0]) return 0;
            if (cand_words[1] != pat_words[1]) return 0;
            if (cand_words[2] != pat_words[2]) return 0;
            if (cand_words[3] != pat_words[3]) return 0;
        }
    }

    bpf_probe_read_kernel(&suffix, sizeof(suffix), candidate + len);
    return suffix == '\0';
}

/*
 * Compare candidate against pattern for len bytes, then check that the
 * next character is '\0' or '/'.
 */
static __noinline int prefix_dir_match(
    const char *candidate,
    const char *pattern,
    u32 len)
{
    u64 cand_words[4];
    u64 pat_words[4];
    char suffix = '\0';
    u32 offset;

    if (len == 0) {
        return 1;
    }

#pragma clang loop unroll(disable)
    for (offset = 0; offset < MAX_RULE_PATTERN_BYTES; offset += MATCH_CHUNK_BYTES) {
        if (offset + MATCH_CHUNK_BYTES > len) {
            break;
        }
        __builtin_memset(cand_words, 0, sizeof(cand_words));
        __builtin_memset(pat_words, 0, sizeof(pat_words));
        bpf_probe_read_kernel(cand_words, MATCH_CHUNK_BYTES, candidate + offset);
        bpf_probe_read_kernel(pat_words, MATCH_CHUNK_BYTES, pattern + offset);
        if (cand_words[0] != pat_words[0]) return 0;
        if (cand_words[1] != pat_words[1]) return 0;
        if (cand_words[2] != pat_words[2]) return 0;
        if (cand_words[3] != pat_words[3]) return 0;
    }

    {
        unsigned long remaining = len - offset;
        asm volatile("%0 &= 31" : "+r"(remaining));
        if (remaining > 0) {
            __builtin_memset(cand_words, 0, sizeof(cand_words));
            __builtin_memset(pat_words, 0, sizeof(pat_words));
            bpf_probe_read_kernel(cand_words, remaining, candidate + offset);
            bpf_probe_read_kernel(pat_words, remaining, pattern + offset);
            if (cand_words[0] != pat_words[0]) return 0;
            if (cand_words[1] != pat_words[1]) return 0;
            if (cand_words[2] != pat_words[2]) return 0;
            if (cand_words[3] != pat_words[3]) return 0;
        }
    }

    bpf_probe_read_kernel(&suffix, sizeof(suffix), candidate + len);
    return suffix == '\0' || suffix == '/';
}

/*
 * Scan the path component immediately after a prefix slash.  Returns 1 if
 * at least one character was found before a '\0' (and no '/' appeared),
 * i.e. the candidate has exactly one more component after the prefix.
 *
 * Extracted as a __noinline subprogram so the BPF verifier analyses the
 * bounded 255-iteration loop with a single, clean entry context instead
 * of inheriting the accumulated state from the callers.
 */
static __noinline int scan_immediate_component(const char *src)
{
    char rem_buf[MAX_RULE_PATTERN_BYTES];
    int remainder_started = 0;
    u32 i;

    __builtin_memset(rem_buf, 0, sizeof(rem_buf));
    bpf_probe_read_kernel(rem_buf, sizeof(rem_buf), src);

#pragma clang loop unroll(disable)
    for (i = 0; i < MAX_RULE_PATTERN_BYTES - 1; i++) {
        char ch = rem_buf[i];   /* stack access: verifier knows bounds */
        if (ch == '\0') {
            return remainder_started;
        }
        if (ch == '/') {
            return 0;
        }
        remainder_started = 1;
    }

    return 0;
}

static __noinline int path_rule_matches(const struct mercury_path_rule *rule, const char *candidate)
{
    u32 len;

    if (!rule || !candidate) {
        return 0;
    }

    len = rule->len;
    if (len >= MAX_RULE_PATTERN_BYTES) {
        return 0;
    }

    if (rule->kind == PATH_RULE_KIND_EXACT) {
        return exact_match(candidate, rule->pattern, len);
    }

    if (rule->kind == PATH_RULE_KIND_PREFIX_DIR) {
        return prefix_dir_match(candidate, rule->pattern, len);
    }

    if (rule->kind == PATH_RULE_KIND_PREFIX_IMMEDIATE) {
        char suffix = '\0';

        if (len >= MAX_RULE_PATTERN_BYTES - 1) {
            return 0;
        }

        bpf_probe_read_kernel(&suffix, sizeof(suffix), candidate + len);
        if (!prefix_dir_match(candidate, rule->pattern, len) || suffix != '/') {
            return 0;
        }

        return scan_immediate_component(candidate + len + 1);
    }

    return 0;
}

static __noinline int path_rules_match(void *map, u32 offset, u32 count, const char *path)
{
    u32 i;
    u32 limit = count;

    if (limit > MAX_RULES_PER_CLASS) {
        limit = MAX_RULES_PER_CLASS;
    }

#pragma clang loop unroll(disable)
    for (i = 0; i < MAX_RULES_PER_CLASS; i++) {
        u32 key;
        struct mercury_path_rule *rule;

        if (i >= limit) {
            break;
        }

        key = offset + i;
        rule = bpf_map_lookup_elem(map, &key);
        if (!rule) {
            continue;
        }

        if (path_rule_matches(rule, path)) {
            return (int)i + 1;  /* 1-based so 0 still means "no match" */
        }
    }

    return 0;
}

#if MERCURY_ENABLE_FILESYSTEM_LSM
static __noinline int workspace_match(struct mercury_profile *profile, const char *path)
{
    u32 i;
    u32 workspace_count = profile->workspace_count;

    if (workspace_count > MAX_WORKSPACE_ROOTS) {
        workspace_count = MAX_WORKSPACE_ROOTS;
    }

#pragma clang loop unroll(disable)
    for (i = 0; i < MAX_WORKSPACE_ROOTS; i++) {
        u32 key;
        struct mercury_path_rule *rule;

        if (i >= workspace_count) {
            break;
        }

        key = profile->workspace_offset + i;
        rule = bpf_map_lookup_elem(&mercury_file_rules, &key);
        if (!rule) {
            continue;
        }

        if (workspace_rule_matches(rule, path)) {
            return (int)i + 1;
        }
    }

    return 0;
}
#endif

static __inline u8 load_idx4(const u8 *p, u32 idx)
{
    switch (idx) {
    case 0:
        return p[0];
    case 1:
        return p[1];
    case 2:
        return p[2];
    case 3:
        return p[3];
    default:
        return 0;
    }
}

static __inline u8 load_idx16(const u8 *p, u32 idx)
{
    switch (idx) {
    case 0:
        return p[0];
    case 1:
        return p[1];
    case 2:
        return p[2];
    case 3:
        return p[3];
    case 4:
        return p[4];
    case 5:
        return p[5];
    case 6:
        return p[6];
    case 7:
        return p[7];
    case 8:
        return p[8];
    case 9:
        return p[9];
    case 10:
        return p[10];
    case 11:
        return p[11];
    case 12:
        return p[12];
    case 13:
        return p[13];
    case 14:
        return p[14];
    case 15:
        return p[15];
    default:
        return 0;
    }
}

static __inline int ipv4_prefix_match(const u8 *a, const u8 *b, u8 prefix)
{
    u32 rem;
    u32 full;
    u8 av;
    u8 bv;

    if (prefix > 32) {
        return 0;
    }

    if (prefix >= 8 && a[0] != b[0]) {
        return 0;
    }
    if (prefix >= 16 && a[1] != b[1]) {
        return 0;
    }
    if (prefix >= 24 && a[2] != b[2]) {
        return 0;
    }
    if (prefix >= 32 && a[3] != b[3]) {
        return 0;
    }

    rem = ((u32)prefix) & 7;
    if (rem == 0) {
        return 1;
    }

    full = ((u32)prefix) >> 3;
    av = load_idx4(a, full);
    bv = load_idx4(b, full);
    return (av & (u8)(0xFF << (8 - (u8)rem))) == (bv & (u8)(0xFF << (8 - (u8)rem)));
}

static __inline int ipv6_prefix_match(const u8 *a, const u8 *b, u8 prefix)
{
    u32 rem;
    u32 full;
    u8 av;
    u8 bv;

    if (prefix > 128) {
        return 0;
    }

    if (prefix >= 8 && a[0] != b[0]) {
        return 0;
    }
    if (prefix >= 16 && a[1] != b[1]) {
        return 0;
    }
    if (prefix >= 24 && a[2] != b[2]) {
        return 0;
    }
    if (prefix >= 32 && a[3] != b[3]) {
        return 0;
    }
    if (prefix >= 40 && a[4] != b[4]) {
        return 0;
    }
    if (prefix >= 48 && a[5] != b[5]) {
        return 0;
    }
    if (prefix >= 56 && a[6] != b[6]) {
        return 0;
    }
    if (prefix >= 64 && a[7] != b[7]) {
        return 0;
    }
    if (prefix >= 72 && a[8] != b[8]) {
        return 0;
    }
    if (prefix >= 80 && a[9] != b[9]) {
        return 0;
    }
    if (prefix >= 88 && a[10] != b[10]) {
        return 0;
    }
    if (prefix >= 96 && a[11] != b[11]) {
        return 0;
    }
    if (prefix >= 104 && a[12] != b[12]) {
        return 0;
    }
    if (prefix >= 112 && a[13] != b[13]) {
        return 0;
    }
    if (prefix >= 120 && a[14] != b[14]) {
        return 0;
    }
    if (prefix >= 128 && a[15] != b[15]) {
        return 0;
    }

    rem = ((u32)prefix) & 7;
    if (rem == 0) {
        return 1;
    }

    full = ((u32)prefix) >> 3;
    av = load_idx16(a, full);
    bv = load_idx16(b, full);
    return (av & (u8)(0xFF << (8 - (u8)rem))) == (bv & (u8)(0xFF << (8 - (u8)rem)));
}

static __inline int net_rule_matches(
    struct mercury_net_rule *rule,
    const struct mercury_net_dest *dest,
    int for_deny)
{
    if (rule->has_host_glob) {
        /*
         * The kernel cannot evaluate host-glob rules (hostname is not available
         * in the network hook).  Only the userspace URL gateway resolves these.
         * Safe-fail semantics:
         *   - A host_glob deny rule  → treat as matching so the deny fires,
         *     preventing traffic that the operator intended to block.
         *   - A host_glob allow rule → treat as non-matching so the allow
         *     does not silently pass traffic the kernel cannot validate.
         */
        return for_deny ? 1 : 0;
    }

    if (rule->protocol != 0 && rule->protocol != dest->protocol) {
        return 0;
    }

    if (rule->has_port && rule->port != dest->port) {
        return 0;
    }

    if (rule->has_cidr) {
        if (!dest->has_addr || rule->family != dest->family) {
            return 0;
        }

        if (dest->family == AF_INET) {
            if (!ipv4_prefix_match(rule->addr, dest->addr, rule->cidr_prefix)) {
                return 0;
            }
        } else if (dest->family == AF_INET6) {
            if (!ipv6_prefix_match(rule->addr, dest->addr, rule->cidr_prefix)) {
                return 0;
            }
        } else {
            return 0;
        }
    }

    return 1;
}

static __inline int is_proxy_loopback_target(
    const struct mercury_net_dest *dest,
    u16 proxy_port)
{
    if (!dest || !dest->has_addr) {
        return 0;
    }

    if (dest->protocol != 1) {
        return 0;
    }

    if (dest->port != proxy_port) {
        return 0;
    }

    if (dest->family == AF_INET) {
        return dest->addr[0] == 127 &&
               dest->addr[1] == 0 &&
               dest->addr[2] == 0 &&
               dest->addr[3] == 1;
    }

    if (dest->family == AF_INET6) {
        return dest->addr[0] == 0 &&
               dest->addr[1] == 0 &&
               dest->addr[2] == 0 &&
               dest->addr[3] == 0 &&
               dest->addr[4] == 0 &&
               dest->addr[5] == 0 &&
               dest->addr[6] == 0 &&
               dest->addr[7] == 0 &&
               dest->addr[8] == 0 &&
               dest->addr[9] == 0 &&
               dest->addr[10] == 0 &&
               dest->addr[11] == 0 &&
               dest->addr[12] == 0 &&
               dest->addr[13] == 0 &&
               dest->addr[14] == 0 &&
               dest->addr[15] == 1;
    }

    return 0;
}

static __inline int is_proxy_socket_create_allowed(int family)
{
    return family == AF_INET || family == AF_INET6;
}

static __inline int is_local_socket_family(int family)
{
    return family == AF_UNIX;
}

static __inline u8 default_decision(void)
{
    u32 key = 0;
    struct mercury_offsets *offsets = bpf_map_lookup_elem(&mercury_offsets, &key);
    if (!offsets || !offsets->policy_loaded) {
        return DECISION_ALLOW;
    }
    return offsets->default_decision;
}

static __inline u64 effective_timestamp_ns(void)
{
    u64 now = bpf_ktime_get_ns();
    u32 key = 0;
    struct mercury_offsets *offsets = bpf_map_lookup_elem(&mercury_offsets, &key);

    if (!offsets) {
        return now;
    }

    if (offsets->realtime_offset_ns > 0) {
        return now + (u64)offsets->realtime_offset_ns;
    }

    return now;
}

#if MERCURY_ENABLE_FILESYSTEM_LSM
static __noinline int evaluate_file(
    struct mercury_profile *profile,
    const char *path,
    u32 *reason_out,
    u32 *rule_out)
{
    int hit;

    hit = path_rules_match(&mercury_file_rules, profile->file_deny_offset, profile->file_deny_count, path);
    if (hit) {
        *reason_out = REASON_DENY_BY_RULE;
        *rule_out = RULE_REF(RULE_KIND_FILE, profile->file_deny_offset + (u32)(hit - 1));
        return DECISION_DENY;
    }

    hit = path_rules_match(
        &mercury_file_rules,
        profile->file_allow_offset,
        profile->file_allow_count,
        path);
    if (hit) {
        *reason_out = REASON_ALLOW_BY_RULE;
        *rule_out = RULE_REF(RULE_KIND_FILE, profile->file_allow_offset + (u32)(hit - 1));
        return DECISION_ALLOW;
    }

    hit = workspace_match(profile, path);
    if (hit) {
        *reason_out = REASON_ALLOW_BY_RULE;
        *rule_out = RULE_REF(RULE_KIND_WORKSPACE, profile->workspace_offset + (u32)(hit - 1));
        return DECISION_ALLOW;
    }

    if (default_decision() == DECISION_DENY) {
        *reason_out = REASON_DENY_BY_DEFAULT;
        return DECISION_DENY;
    }

    *reason_out = REASON_ALLOW_BY_DEFAULT;
    return DECISION_ALLOW;
}
#endif

static __noinline int evaluate_exec(
    struct mercury_profile *profile,
    const char *path,
    u32 *reason_out,
    u32 *rule_out)
{
    int hit;

    hit = path_rules_match(&mercury_exec_rules, profile->exec_deny_offset, profile->exec_deny_count, path);
    if (hit) {
        *reason_out = REASON_DENY_BY_RULE;
        *rule_out = RULE_REF(RULE_KIND_EXEC, profile->exec_deny_offset + (u32)(hit - 1));
        return DECISION_DENY;
    }

    hit = path_rules_match(
        &mercury_exec_rules,
        profile->exec_allow_offset,
        profile->exec_allow_count,
        path);
    if (hit) {
        *reason_out = REASON_ALLOW_BY_RULE;
        *rule_out = RULE_REF(RULE_KIND_EXEC, profile->exec_allow_offset + (u32)(hit - 1));
        return DECISION_ALLOW;
    }

    if (default_decision() == DECISION_DENY) {
        *reason_out = REASON_DENY_BY_DEFAULT;
        return DECISION_DENY;
    }

    *reason_out = REASON_ALLOW_BY_DEFAULT;
    return DECISION_ALLOW;
}

static __inline int evaluate_network(
    struct mercury_profile *profile,
    const struct mercury_net_dest *dest,
    u32 *reason_out,
    u32 *rule_out)
{
    u32 i;
    u32 net_deny_count = profile->net_deny_count;
    u32 net_allow_count = profile->net_allow_count;

    if (net_deny_count > MAX_RULES_PER_CLASS) {
        net_deny_count = MAX_RULES_PER_CLASS;
    }
    if (net_allow_count > MAX_RULES_PER_CLASS) {
        net_allow_count = MAX_RULES_PER_CLASS;
    }

    if (profile->url_enforce) {
        /*
         * The proxy loopback is the internal mechanism that lets enrolled processes
         * reach the URL gateway. It must be allowed BEFORE any network_deny rules are
         * evaluated, so that a broad CIDR deny rule (e.g. 0.0.0.0/0) cannot
         * inadvertently block the proxy connection and break URL enforcement.
         */
        if (is_proxy_loopback_target(dest, profile->url_proxy_port)) {
            *reason_out = REASON_ALLOW_BY_RULE;
            return DECISION_ALLOW;
        }

        for (i = 0; i < MAX_RULES_PER_CLASS; i++) {
            u32 key;
            struct mercury_net_rule *rule;

            if (i >= net_deny_count) {
                break;
            }

            key = profile->net_deny_offset + i;
            rule = bpf_map_lookup_elem(&mercury_net_rules, &key);
            if (!rule) {
                continue;
            }

            if (net_rule_matches(rule, dest, 1)) {
                *reason_out = REASON_DENY_BY_RULE;
                *rule_out = RULE_REF(RULE_KIND_NET, key);
                return DECISION_DENY;
            }
        }

        for (i = 0; i < MAX_RULES_PER_CLASS; i++) {
            u32 key;
            struct mercury_net_rule *rule;

            if (i >= net_allow_count) {
                break;
            }

            key = profile->net_allow_offset + i;
            rule = bpf_map_lookup_elem(&mercury_net_rules, &key);
            if (!rule) {
                continue;
            }

            if (net_rule_matches(rule, dest, 0)) {
                *reason_out = REASON_ALLOW_BY_RULE;
                *rule_out = RULE_REF(RULE_KIND_NET, key);
                return DECISION_ALLOW;
            }
        }

        *reason_out = REASON_DENY_BY_RULE;
        *rule_out = RULE_REF(RULE_KIND_SYNTHETIC, SYNTH_URL_DIRECT_EGRESS);
        return DECISION_DENY;
    }

    for (i = 0; i < MAX_RULES_PER_CLASS; i++) {
        u32 key;
        struct mercury_net_rule *rule;

        if (i >= net_deny_count) {
            break;
        }

        key = profile->net_deny_offset + i;
        rule = bpf_map_lookup_elem(&mercury_net_rules, &key);
        if (!rule) {
            continue;
        }

        if (net_rule_matches(rule, dest, 1)) {
            *reason_out = REASON_DENY_BY_RULE;
            *rule_out = RULE_REF(RULE_KIND_NET, key);
            return DECISION_DENY;
        }
    }

    for (i = 0; i < MAX_RULES_PER_CLASS; i++) {
        u32 key;
        struct mercury_net_rule *rule;

        if (i >= net_allow_count) {
            break;
        }

        key = profile->net_allow_offset + i;
        rule = bpf_map_lookup_elem(&mercury_net_rules, &key);
        if (!rule) {
            continue;
        }

        if (net_rule_matches(rule, dest, 0)) {
            *reason_out = REASON_ALLOW_BY_RULE;
            *rule_out = RULE_REF(RULE_KIND_NET, key);
            return DECISION_ALLOW;
        }
    }

    if (default_decision() == DECISION_DENY) {
        *reason_out = REASON_DENY_BY_DEFAULT;
        return DECISION_DENY;
    }

    *reason_out = REASON_ALLOW_BY_DEFAULT;
    return DECISION_ALLOW;
}

static __inline int should_enforce_deny(u8 profile_mode, u8 enrollment_mode)
{
    if (profile_mode == ENFORCEMENT_OBSERVE || enrollment_mode == ENFORCEMENT_OBSERVE) {
        return 0;
    }
    return 1;
}

static __inline struct mercury_scratch *scratch_slot(void)
{
    u32 key = 0;
    struct mercury_scratch *scratch = bpf_map_lookup_elem(&mercury_scratch, &key);
    if (!scratch) {
        return (void *)0;
    }
    return scratch;
}

static __inline char *scratch_resource(void)
{
    struct mercury_scratch *scratch = scratch_slot();
    if (!scratch) {
        return (char *)0;
    }
    scratch->resource[0] = '\0';
    scratch->resource[MAX_RESOURCE_BYTES] = '\0';
    return scratch->resource;
}

/* Second per-CPU buffer for a related path (rename source, socket path). */
static __inline char *scratch_resource2(void)
{
    struct mercury_scratch *scratch = scratch_slot();
    if (!scratch) {
        return (char *)0;
    }
    scratch->resource2[0] = '\0';
    scratch->resource2[MAX_RESOURCE_BYTES] = '\0';
    return scratch->resource2;
}

static __inline void bump_stat(u32 index)
{
    u64 *counter = bpf_map_lookup_elem(&mercury_stats, &index);
    if (!counter) {
        return;
    }
    __sync_fetch_and_add(counter, 1);
}

static __inline u32 current_policy_epoch(void)
{
    u32 key = 0;
    struct mercury_offsets *offsets = bpf_map_lookup_elem(&mercury_offsets, &key);
    return offsets ? offsets->policy_epoch : 0;
}

/*
 * Lifecycle, tamper-relevant and DENY events are never rate limited: an agent
 * must not be able to hide a blocked action behind a burst of allowed ones.
 */
static __inline int rate_limit_exempt(const struct mercury_emit_ctx *ctx)
{
    if (ctx->decision == DECISION_DENY) {
        return 1;
    }
    switch (ctx->action) {
    case ACTION_PROC_START:
    case ACTION_PROC_EXIT:
    case ACTION_PROC_BPF:
    case ACTION_PROC_MODULE:
    case ACTION_PROC_MOUNT:
    case ACTION_PROC_USERNS:
    case ACTION_TELEMETRY_SUPPRESSED:
        return 1;
    case ACTION_PROC_PTRACE:
        /* READ-mode checks come from ps/lsof style /proc access; limit those. */
        return (ctx->aux & PTRACE_MODE_ATTACH) != 0;
    default:
        return 0;
    }
}

/*
 * Returns 1 when the event must be suppressed. When a new window opens after a
 * window that suppressed events, *suppressed_out receives that count so the
 * caller can emit a per-pid summary.
 */
static __inline int rate_limit_check(u32 pid, u32 *suppressed_out)
{
    u32 offsets_key = 0;
    struct mercury_offsets *offsets = bpf_map_lookup_elem(&mercury_offsets, &offsets_key);
    if (!offsets || offsets->rate_limit_per_sec == 0) {
        return 0;  /* disabled */
    }

    u64 now = bpf_ktime_get_ns();
    struct mercury_rate_state *state = bpf_map_lookup_elem(&mercury_rate_limit, &pid);
    if (state) {
        if ((now - state->window_start_ns) >= 1000000000ULL) {
            /* new window */
            *suppressed_out = state->suppressed;
            state->window_start_ns = now;
            state->count = 1;
            state->suppressed = 0;
            return 0;
        }
        if (state->count >= offsets->rate_limit_per_sec) {
            state->suppressed += 1;
            return 1;  /* suppress */
        }
        state->count += 1;
        return 0;
    }

    /* first event for this PID */
    struct mercury_rate_state new_state = {
        .window_start_ns = now,
        .count = 1,
        .suppressed = 0,
    };
    bpf_map_update_elem(&mercury_rate_limit, &pid, &new_state, BPF_ANY);
    return 0;
}

/* Fills the identity/process fields shared by every record. */
static __inline void fill_event_header(struct mercury_event *evt, u32 action, u32 pid)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    u32 cpu = bpf_get_smp_processor_id();
    u32 seq_key = 0;
    u64 seq_val = 0;
    u64 *seq_ptr = bpf_map_lookup_elem(&mercury_seq, &seq_key);

    if (seq_ptr) {
        seq_val = *seq_ptr;
        *seq_ptr = seq_val + 1;
    }

    evt->timestamp_ns = effective_timestamp_ns();
    evt->seq = (((u64)cpu) << 48) | (seq_val & 0xFFFFFFFFFFFFULL);
    evt->cgroup_id = bpf_get_current_cgroup_id();
    evt->_reserved = 0;
    evt->pid = pid;
    evt->tid = (u32)pid_tgid;
    evt->ppid = 0;
    if (task) {
        parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            evt->ppid = (u32)BPF_CORE_READ(parent, tgid);
        }
    }
    evt->uid = (u32)uid_gid;
    evt->gid = (u32)(uid_gid >> 32);
    evt->action = action;
    evt->policy_epoch = current_policy_epoch();
    if (bpf_get_current_comm(evt->comm, sizeof(evt->comm)) != 0) {
        evt->comm[0] = '\0';
    }
    evt->_pad[0] = 0;
    evt->_pad[1] = 0;
    evt->_pad[2] = 0;
}

static __noinline void emit_suppression_summary(u32 pid, u32 suppressed, const char *profile)
{
    struct mercury_event *evt;
    int i;

    evt = bpf_ringbuf_reserve(&mercury_events, sizeof(*evt), 0);
    if (!evt) {
        bump_stat(STAT_RINGBUF_DROPPED);
        return;
    }
    fill_event_header(evt, ACTION_TELEMETRY_SUPPRESSED, pid);
    evt->decision = DECISION_ALLOW;
    evt->reason = REASON_ALLOW_BY_DEFAULT;
    evt->enrollment_id = 0;
    evt->rule_ref = 0;
    evt->target_pid = 0;
    evt->aux = suppressed;
    evt->port = 0;
    evt->flags = 0;
    evt->protocol = 0;
    evt->family = 0;
    for (i = 0; i < 16; i++) {
        evt->ip[i] = 0;
    }
    if (profile) {
        copy_cstr(evt->profile, sizeof(evt->profile), profile);
    } else {
        evt->profile[0] = '\0';
    }
    copy_cstr(evt->resource, sizeof(evt->resource), "<rate-limited>");
    evt->resource2[0] = '\0';
    bpf_ringbuf_submit(evt, 0);
}

static __noinline int emit_event(const struct mercury_emit_ctx *ctx)
{
    struct mercury_event *evt;
    int i;

    if (!ctx) {
        return 0;
    }

    /* Per-PID rate limiting (never for DENY / lifecycle / tamper events). */
    if (!rate_limit_exempt(ctx)) {
        u32 suppressed = 0;
        int limited = rate_limit_check(ctx->pid, &suppressed);
        if (suppressed) {
            emit_suppression_summary(ctx->pid, suppressed, ctx->profile);
        }
        if (limited) {
            bump_stat(STAT_RATE_LIMITED);
            return 0;
        }
    }

    evt = bpf_ringbuf_reserve(&mercury_events, sizeof(*evt), 0);
    if (!evt) {
        bump_stat(ctx->decision == DECISION_DENY ? STAT_DENY_DROPPED : STAT_RINGBUF_DROPPED);
        return 0;
    }

    fill_event_header(evt, ctx->action, ctx->pid);
    evt->decision = ctx->decision;
    evt->reason = ctx->reason;
    evt->enrollment_id = ctx->enrollment_id;
    evt->rule_ref = ctx->rule_ref;
    evt->target_pid = ctx->target_pid;
    evt->aux = ctx->aux;
    evt->port = ctx->port;
    evt->flags = ctx->flags;
    evt->protocol = ctx->protocol;
    evt->family = ctx->family;

    if (ctx->profile) {
        copy_cstr(evt->profile, sizeof(evt->profile), ctx->profile);
    } else {
        evt->profile[0] = '\0';
    }
    if (ctx->resource) {
        copy_cstr(evt->resource, sizeof(evt->resource), ctx->resource);
    } else {
        evt->resource[0] = '\0';
    }

    evt->resource2[0] = '\0';
    if (ctx->resource2_user && ctx->resource2_len > 0) {
        u32 len = ctx->resource2_len;
        if (len > MAX_RESOURCE2_BYTES - 1) {
            len = MAX_RESOURCE2_BYTES - 1;
        }
        len &= (MAX_RESOURCE2_BYTES - 1);
        if (len > 0 && bpf_probe_read_user(evt->resource2, len, ctx->resource2_user) == 0) {
            evt->resource2[len & (MAX_RESOURCE2_BYTES - 1)] = '\0';
        } else {
            evt->resource2[0] = '\0';
        }
    } else if (ctx->resource2) {
        if (bpf_probe_read_kernel_str(evt->resource2, sizeof(evt->resource2), ctx->resource2) < 0) {
            evt->resource2[0] = '\0';
        }
    }

    if (ctx->ip) {
        for (i = 0; i < 16; i++) {
            evt->ip[i] = ctx->ip[i];
        }
    } else {
        for (i = 0; i < 16; i++) {
            evt->ip[i] = 0;
        }
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

static __noinline int handle_decision(const struct mercury_decision_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 uid = (u32)uid_gid;
    struct mercury_emit_ctx emit = {};
    u32 decision;
    u32 reason;

    if (!ctx || !ctx->enrollment) {
        return 0;
    }

    decision = ctx->decision;
    reason = ctx->reason;

    if (decision == DECISION_DENY &&
        !should_enforce_deny(ctx->class_mode, ctx->enrollment->mode)) {
        decision = DECISION_ALLOW;
        reason = REASON_ALLOW_BY_OBSERVE_MODE;
    }

    emit.action = ctx->action;
    emit.pid = pid;
    emit.uid = uid;
    emit.decision = decision;
    emit.reason = reason;
    emit.profile = ctx->profile ? ctx->profile->name : "default";
    emit.resource = ctx->resource;
    emit.resource2 = ctx->resource2;
    emit.port = ctx->port;
    emit.ip = ctx->ip;
    emit.rule_ref = ctx->rule_ref;
    emit.target_pid = ctx->target_pid;
    emit.aux = ctx->aux;
    emit.enrollment_id = ctx->enrollment->enrollment_id;
    emit.flags = ctx->flags;
    emit.protocol = ctx->protocol;
    emit.family = ctx->family;

    emit_event(&emit);

    if (decision == DECISION_DENY) {
        return -EPERM;
    }

    return 0;
}

/*
 * An explicit enrollment always wins over the "ignored" marker: processes the
 * daemon forks (e.g. dashboard launches) inherit the marker at fork time and
 * must still be governed once mercury-run registers them.
 */
static __inline struct mercury_enrollment *lookup_enrollment(u32 pid)
{
    struct mercury_enrollment *enrollment;

    enrollment = bpf_map_lookup_elem(&mercury_enrolled_pids, &pid);
    if (!enrollment) {
        if (!pid_in_map(&mercury_ignored_pids, pid)) {
            bump_unenrolled_suppressed();
        }
        return (void *)0;
    }

    return enrollment;
}

#if MERCURY_ENABLE_EXEC_PATH_LSM
static __inline int load_exec_path(struct linux_binprm *bprm, char *buffer, u32 buffer_len)
{
    const char *filename;

    if (!bprm || !buffer || buffer_len == 0) {
        return -1;
    }

    filename = BPF_CORE_READ(bprm, filename);
    if (!filename) {
        return -1;
    }

    return bpf_probe_read_kernel_str(buffer, buffer_len, filename);
}
#endif

#if MERCURY_ENABLE_FILESYSTEM_LSM
static __inline int load_file_path(struct file *file, char *buffer, u32 buffer_len)
{
    if (!file || !buffer || buffer_len == 0) {
        return -1;
    }

    return bpf_d_path(&file->f_path, buffer, buffer_len);
}

static __inline int load_unlink_path(
    struct path *dir,
    struct dentry *dentry,
    char *buffer,
    u32 buffer_len)
{
    const unsigned char *name;
    int i;
    int len;

    if (!dir || !dentry || !buffer || buffer_len == 0) {
        return -1;
    }

    /*
     * Use bpf_d_path to obtain the full directory path (e.g. "/home/user/project").
     * The previous implementation read only dir->dentry->d_name.name, which is the
     * last path component, producing truncated paths for nested directories.
     */
    if (bpf_d_path(dir, buffer, buffer_len) < 0) {
        /* Fall back to "/" so we always have a valid absolute path. */
        buffer[0] = '/';
        if (buffer_len > 1) {
            buffer[1] = '\0';
        }
    }

    /*
     * Scan forward from index 1 (buffer[0] is always '/') to find the null
     * terminator that bpf_d_path wrote, giving us the current string length.
     */
    len = 1;
#pragma clang loop unroll(disable)
    for (i = 1; i < MAX_RESOURCE_BYTES - 1; i++) {
        if (buffer[i] == '\0') {
            len = i;
            break;
        }
    }

    /* Append a '/' separator between the directory path and the filename. */
    if (len > 0 && buffer[len - 1] != '/' && len < (int)buffer_len - 1) {
        buffer[len] = '/';
        len++;
        buffer[len] = '\0';
    }

    /* Append the filename from the dentry. */
    name = BPF_CORE_READ(dentry, d_name.name);
    if (!name || len >= (int)buffer_len - 1) {
        return 0;
    }

    bpf_probe_read_kernel_str(buffer + len, buffer_len - (u32)len, name);

    return 0;
}
#endif

static __inline void init_net_dest_from_sockaddr(
    struct socket *sock,
    struct sockaddr *address,
    int addrlen,
    struct mercury_net_dest *dest)
{
    int sock_type = 0;

    if (!dest) {
        return;
    }

    __builtin_memset(dest, 0, sizeof(*dest));

    if (!sock || !address || addrlen < (int)sizeof(sa_family_t)) {
        return;
    }

    sock_type = BPF_CORE_READ(sock, type);
    dest->protocol = (sock_type == SOCK_DGRAM) ? 2 : 1;

    {
        sa_family_t family = 0;
        bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
        dest->family = (u8)family;

        if (family == AF_INET && addrlen >= (int)sizeof(struct sockaddr_in)) {
            struct sockaddr_in in4 = {};
            bpf_probe_read_kernel(&in4, sizeof(in4), address);
            dest->port = ntohs(in4.sin_port);
            dest->has_addr = 1;
            bpf_probe_read_kernel(dest->addr, 4, &in4.sin_addr.s_addr);
            return;
        }

        if (family == AF_INET6 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 in6 = {};
            bpf_probe_read_kernel(&in6, sizeof(in6), address);
            dest->port = ntohs(in6.sin6_port);
            dest->has_addr = 1;
            bpf_probe_read_kernel(dest->addr, 16, &in6.sin6_addr.in6_u.u6_addr8);
            return;
        }
    }
}

/*
 * Copies an AF_UNIX sun_path into buffer. Returns 1 for a filesystem socket,
 * 2 for an abstract socket (rendered as "@name"), 0 otherwise.
 */
static __inline int load_unix_path(struct sockaddr *address, int addrlen, char *buffer)
{
    char first = '\0';
    const char *sun_path;

    if (!address || !buffer || addrlen <= (int)sizeof(sa_family_t)) {
        return 0;
    }
    sun_path = (const char *)address + sizeof(sa_family_t);
    bpf_probe_read_kernel(&first, sizeof(first), sun_path);
    if (first == '\0') {
        buffer[0] = '@';
        if (bpf_probe_read_kernel_str(buffer + 1, 108, sun_path + 1) < 0) {
            buffer[1] = '\0';
        }
        return 2;
    }
    if (bpf_probe_read_kernel_str(buffer, 109, sun_path) < 0) {
        buffer[0] = '\0';
        return 0;
    }
    return 1;
}

/*
 * Connecting to a filesystem socket (docker.sock, a systemd/D-Bus bus, an
 * ssh-agent) never goes through file_open, so file_deny rules on the socket
 * path were not enforced. Apply explicit file_deny rules to the socket path.
 * Returns the 1-based matching rule index or 0.
 */
static __inline int unix_socket_denied(struct mercury_profile *profile, const char *path)
{
#if MERCURY_ENABLE_FILESYSTEM_LSM
    return path_rules_match(
        &mercury_file_rules, profile->file_deny_offset, profile->file_deny_count, path);
#else
    (void)profile;
    (void)path;
    return 0;
#endif
}

#if MERCURY_ENABLE_FILESYSTEM_LSM
/* ─── Helper: resolve a struct path * into scratch buffer ─────────────── */
static __inline int load_path(const struct path *p, char *buffer, u32 buffer_len)
{
    if (!p || !buffer || buffer_len == 0) {
        return -1;
    }
    return bpf_d_path((struct path *)p, buffer, buffer_len);
}

/* ─── Helper: read just the final name component from a dentry ─────────── */
static __inline int load_dentry_name(struct dentry *dentry, char *buffer, u32 buffer_len)
{
    const unsigned char *name;

    if (!dentry || !buffer || buffer_len == 0) {
        return -1;
    }
    name = BPF_CORE_READ(dentry, d_name.name);
    if (!name) {
        if (buffer_len > 0) buffer[0] = '\0';
        return 0;
    }
    return bpf_probe_read_kernel_str(buffer, buffer_len, name);
}

/* ─── Helper: build full path from (dir path, target dentry) ────────────  */
/*     Identical in spirit to load_unlink_path. Reuse it via casting.       */

/* ─── File-mutation hooks ─────────────────────────────────────────────── */
SEC("lsm/path_rename")
int BPF_PROG(mercury_path_rename,
             const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    int source_hit;
    char *path;
    char *source;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    if (enrollment->launch_exec_bypass) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    path = scratch_resource();
    if (!path) {
        return 0;
    }
    /* Evaluate destination path (the target that gets overwritten/created). */
    if (load_unlink_path((struct path *)new_dir, new_dentry, path, MAX_RESOURCE_BYTES) < 0) {
        copy_cstr(path, MAX_RESOURCE_BYTES, "<unknown>");
        decision_ctx.flags |= EVENT_FLAG_PATH_UNRESOLVED;
    }
    decision = evaluate_file(profile, path, &reason, &decision_ctx.rule_ref);

    /*
     * Also check the source against file_deny: renaming a denied file into an
     * allowed location and reading it there would otherwise bypass the rule.
     * Only explicit deny rules are applied to the source (not the full
     * allow/workspace/default evaluation) to bound verifier complexity.
     */
    source = scratch_resource2();
    if (source) {
        if (load_unlink_path((struct path *)old_dir, old_dentry, source, MAX_RESOURCE_BYTES) < 0) {
            copy_cstr(source, MAX_RESOURCE_BYTES, "<unknown>");
            decision_ctx.flags |= EVENT_FLAG_SOURCE_UNRESOLVED;
        } else if (decision != DECISION_DENY) {
            source_hit = path_rules_match(
                &mercury_file_rules, profile->file_deny_offset, profile->file_deny_count, source);
            if (source_hit) {
                decision = DECISION_DENY;
                reason = REASON_DENY_BY_RULE;
                decision_ctx.rule_ref = RULE_REF(
                    RULE_KIND_FILE, profile->file_deny_offset + (u32)(source_hit - 1));
            }
        }
        decision_ctx.resource2 = source;
    }
    decision_ctx.action = ACTION_FILE_RENAME;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->file_mode;
    decision_ctx.resource = path;
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}

SEC("lsm/path_link")
int BPF_PROG(mercury_path_link,
             struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    char *path;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    if (enrollment->launch_exec_bypass) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    path = scratch_resource();
    if (!path) {
        return 0;
    }
    /* Evaluate the new link destination. */
    if (load_unlink_path((struct path *)new_dir, new_dentry, path, MAX_RESOURCE_BYTES) < 0) {
        copy_cstr(path, MAX_RESOURCE_BYTES, "<unknown>");
        decision_ctx.flags |= EVENT_FLAG_PATH_UNRESOLVED;
    }
    /*
     * The source is a bare dentry (no vfsmount), so bpf_d_path cannot resolve
     * it; record its name for visibility. Source-side policy for hard links is
     * a documented limitation (see docs/observability/kernel.md).
     */
    {
        char *source = scratch_resource2();
        if (source) {
            if (load_dentry_name(old_dentry, source, MAX_RESOURCE_BYTES) < 0) {
                source[0] = '\0';
            }
            decision_ctx.resource2 = source;
            decision_ctx.flags |= EVENT_FLAG_SOURCE_UNRESOLVED;
        }
    }
    decision = evaluate_file(profile, path, &reason, &decision_ctx.rule_ref);
    decision_ctx.action = ACTION_FILE_LINK;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->file_mode;
    decision_ctx.resource = path;
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}

SEC("lsm/path_symlink")
int BPF_PROG(mercury_path_symlink,
             const struct path *dir, struct dentry *dentry, const char *old_name)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    char *path;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    if (enrollment->launch_exec_bypass) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    path = scratch_resource();
    if (!path) {
        return 0;
    }
    /* Evaluate the path where the symlink will be created. */
    if (load_unlink_path((struct path *)dir, dentry, path, MAX_RESOURCE_BYTES) < 0) {
        copy_cstr(path, MAX_RESOURCE_BYTES, "<unknown>");
        decision_ctx.flags |= EVENT_FLAG_PATH_UNRESOLVED;
    }
    decision = evaluate_file(profile, path, &reason, &decision_ctx.rule_ref);
    decision_ctx.action = ACTION_FILE_SYMLINK;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->file_mode;
    decision_ctx.resource = path;
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}

SEC("lsm/path_mkdir")
int BPF_PROG(mercury_path_mkdir,
             const struct path *dir, struct dentry *dentry, umode_t mode)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    char *path;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    if (enrollment->launch_exec_bypass) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    path = scratch_resource();
    if (!path) {
        return 0;
    }
    if (load_unlink_path((struct path *)dir, dentry, path, MAX_RESOURCE_BYTES) < 0) {
        copy_cstr(path, MAX_RESOURCE_BYTES, "<unknown>");
        decision_ctx.flags |= EVENT_FLAG_PATH_UNRESOLVED;
    }
    decision = evaluate_file(profile, path, &reason, &decision_ctx.rule_ref);
    decision_ctx.action = ACTION_FILE_MKDIR;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->file_mode;
    decision_ctx.resource = path;
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}

SEC("lsm/path_rmdir")
int BPF_PROG(mercury_path_rmdir,
             const struct path *dir, struct dentry *dentry)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    char *path;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    if (enrollment->launch_exec_bypass) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    path = scratch_resource();
    if (!path) {
        return 0;
    }
    if (load_unlink_path((struct path *)dir, dentry, path, MAX_RESOURCE_BYTES) < 0) {
        copy_cstr(path, MAX_RESOURCE_BYTES, "<unknown>");
        decision_ctx.flags |= EVENT_FLAG_PATH_UNRESOLVED;
    }
    decision = evaluate_file(profile, path, &reason, &decision_ctx.rule_ref);
    decision_ctx.action = ACTION_FILE_RMDIR;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->file_mode;
    decision_ctx.resource = path;
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}

/*
 * path_mknod: called before a file is created by open(O_CREAT) (may_o_create)
 * or mknod(2). Unlike inode_create it carries the parent struct path, so the
 * full destination path is evaluated and the create is refused before the
 * inode exists (inode_create only saw the bare name, so exact and prefix
 * rules could never match).
 */
SEC("lsm/path_mknod")
int BPF_PROG(mercury_path_mknod,
             const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    char *path;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    if (enrollment->launch_exec_bypass) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    path = scratch_resource();
    if (!path) {
        return 0;
    }
    if (load_unlink_path((struct path *)dir, dentry, path, MAX_RESOURCE_BYTES) < 0) {
        copy_cstr(path, MAX_RESOURCE_BYTES, "<unknown>");
        decision_ctx.flags |= EVENT_FLAG_PATH_UNRESOLVED;
    }
    decision = evaluate_file(profile, path, &reason, &decision_ctx.rule_ref);
    decision_ctx.aux = mode;
    decision_ctx.action = ACTION_FILE_CREATE;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->file_mode;
    decision_ctx.resource = path;
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}

SEC("lsm/path_chmod")
int BPF_PROG(mercury_path_chmod,
             const struct path *path, umode_t mode)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    char *resource;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    resource = scratch_resource();
    if (!resource) {
        return 0;
    }
    if (load_path(path, resource, MAX_RESOURCE_BYTES) < 0) {
        copy_cstr(resource, MAX_RESOURCE_BYTES, "<unknown>");
        decision_ctx.flags |= EVENT_FLAG_PATH_UNRESOLVED;
    }
    decision = evaluate_file(profile, resource, &reason, &decision_ctx.rule_ref);
    decision_ctx.action = ACTION_FILE_CHMOD;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->file_mode;
    decision_ctx.resource = resource;
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}

SEC("lsm/path_chown")
int BPF_PROG(mercury_path_chown, const struct path *path)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    char *resource;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    resource = scratch_resource();
    if (!resource) {
        return 0;
    }
    if (load_path(path, resource, MAX_RESOURCE_BYTES) < 0) {
        copy_cstr(resource, MAX_RESOURCE_BYTES, "<unknown>");
        decision_ctx.flags |= EVENT_FLAG_PATH_UNRESOLVED;
    }
    decision = evaluate_file(profile, resource, &reason, &decision_ctx.rule_ref);
    decision_ctx.action = ACTION_FILE_CHOWN;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->file_mode;
    decision_ctx.resource = resource;
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}

SEC("lsm/path_truncate")
int BPF_PROG(mercury_path_truncate, const struct path *path)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    char *resource;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    resource = scratch_resource();
    if (!resource) {
        return 0;
    }
    if (load_path(path, resource, MAX_RESOURCE_BYTES) < 0) {
        copy_cstr(resource, MAX_RESOURCE_BYTES, "<unknown>");
        decision_ctx.flags |= EVENT_FLAG_PATH_UNRESOLVED;
    }
    decision = evaluate_file(profile, resource, &reason, &decision_ctx.rule_ref);
    decision_ctx.action = ACTION_FILE_TRUNCATE;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->file_mode;
    decision_ctx.resource = resource;
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}
#endif

/* ─── Network server-side hooks ───────────────────────────────────────── */

SEC("lsm/socket_bind")
int BPF_PROG(mercury_socket_bind,
             struct socket *sock, struct sockaddr *address, int addrlen)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    struct mercury_net_dest dest = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    init_net_dest_from_sockaddr(sock, address, addrlen, &dest);
    decision = evaluate_network(profile, &dest, &reason, &decision_ctx.rule_ref);
    decision_ctx.action = ACTION_NET_BIND;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->network_mode;
    decision_ctx.resource = "<socket_bind>";
    decision_ctx.port = dest.port;
    decision_ctx.ip = dest.has_addr ? dest.addr : (const u8 *)0;
    decision_ctx.family = dest.family;
    decision_ctx.protocol = dest.protocol;
    return handle_decision(&decision_ctx);
}

/*
 * socket_listen / socket_accept: audit-only hooks that emit events but always
 * allow.  The enrolled process is already listening/accepting; enforcement would
 * need to be at bind-time. We emit the local port via sk_num (host byte order).
 */
SEC("lsm/socket_listen")
int BPF_PROG(mercury_socket_listen, struct socket *sock, int backlog)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_emit_ctx emit = {};
    u32 uid = (u32)bpf_get_current_uid_gid();
    u16 local_port = 0;
    u8 local_family = 0;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    {
        struct sock *s = BPF_CORE_READ(sock, sk);
        if (s) {
            bpf_probe_read_kernel(
                &local_port, sizeof(local_port),
                (const void *)__builtin_preserve_access_index(
                    &s->__sk_common.skc_num));
            local_family = (u8)BPF_CORE_READ(s, __sk_common.skc_family);
        }
    }
    emit.action = ACTION_NET_LISTEN;
    emit.pid = pid;
    emit.uid = uid;
    emit.decision = DECISION_ALLOW;
    emit.reason = REASON_ALLOW_BY_DEFAULT;
    emit.profile = profile->name;
    emit.resource = "<socket_listen>";
    emit.port = local_port;
    emit.ip = (const u8 *)0;
    emit.enrollment_id = enrollment->enrollment_id;
    emit.family = local_family;
    emit_event(&emit);
    return 0;
}

SEC("lsm/socket_accept")
int BPF_PROG(mercury_socket_accept, struct socket *sock, struct socket *newsock)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_emit_ctx emit = {};
    u32 uid = (u32)bpf_get_current_uid_gid();
    u16 local_port = 0;
    u8 local_family = 0;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    {
        struct sock *s = BPF_CORE_READ(sock, sk);
        if (s) {
            bpf_probe_read_kernel(
                &local_port, sizeof(local_port),
                (const void *)__builtin_preserve_access_index(
                    &s->__sk_common.skc_num));
            local_family = (u8)BPF_CORE_READ(s, __sk_common.skc_family);
        }
    }
    emit.action = ACTION_NET_ACCEPT;
    emit.pid = pid;
    emit.uid = uid;
    emit.decision = DECISION_ALLOW;
    emit.reason = REASON_ALLOW_BY_DEFAULT;
    emit.profile = profile->name;
    emit.resource = "<socket_accept>";
    emit.port = local_port;
    emit.ip = (const u8 *)0;
    emit.enrollment_id = enrollment->enrollment_id;
    emit.family = local_family;
    emit_event(&emit);
    return 0;
}

/*
 * socket_create: called before the socket descriptor is created.
 * family is stored in the port field; type in ip[0]; protocol in ip[1].
 * Evaluate against network policy; unusual families/types may be blocked by
 * network_deny rules that match any destination (port=0, no addr).
 */
SEC("lsm/socket_create")
int BPF_PROG(mercury_socket_create, int family, int type, int protocol, int kern)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    struct mercury_net_dest dest = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    static const u8 no_addr[16] = {};

    /* Kernel-internal socket creation is not an agent action. */
    if (kern) {
        return 0;
    }
    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }

    /*
     * URL-enforced profiles rely on later socket_connect/socket_sendmsg hooks to
     * decide whether a concrete destination is allowed. The socket_create hook has
     * no destination yet, so default-deny here would block the proxy path before a
     * loopback connect can even be attempted.
     */
    if (profile->url_enforce
        && (is_proxy_socket_create_allowed(family) || is_local_socket_family(family))) {
        decision_ctx.action = ACTION_NET_CREATE;
        decision_ctx.decision = DECISION_ALLOW;
        decision_ctx.reason = REASON_ALLOW_BY_RULE;
        decision_ctx.profile = profile;
        decision_ctx.enrollment = enrollment;
        decision_ctx.class_mode = profile->network_mode;
        decision_ctx.resource = "<socket_create>";
        decision_ctx.port = 0;
        decision_ctx.family = (u8)family;
        decision_ctx.protocol = (u8)type;
        decision_ctx.aux = (u32)protocol;
        decision_ctx.ip = no_addr;
        return handle_decision(&decision_ctx);
    }

    /* Build a minimal dest from the socket family and type. */
    dest.family = (u8)family;
    dest.protocol = (type == SOCK_DGRAM) ? 2 : 1;
    dest.port = 0;
    dest.has_addr = 0;

    decision = evaluate_network(profile, &dest, &reason, &decision_ctx.rule_ref);
    decision_ctx.action = ACTION_NET_CREATE;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->network_mode;
    decision_ctx.resource = "<socket_create>";
    decision_ctx.port = 0;
    decision_ctx.family = (u8)family;
    decision_ctx.protocol = (u8)type;  /* SOCK_STREAM / SOCK_DGRAM / SOCK_RAW ... */
    decision_ctx.aux = (u32)protocol;
    decision_ctx.ip = no_addr;
    return handle_decision(&decision_ctx);
}

/* ─── Process supervision hooks ───────────────────────────────────────── */

/*
 * ptrace_access_check: fires when an enrolled process tries to attach a tracer.
 * Evaluated against process (exec) policy using the synthetic path "<ptrace>".
 * Operators can deny ptrace by adding exec_deny: ["<ptrace>"] to the profile.
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(mercury_ptrace_access_check,
             struct task_struct *child, unsigned int mode)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    decision = evaluate_exec(profile, "<ptrace>", &reason, &decision_ctx.rule_ref);

    /*
     * Attaching to (or writing the memory of) a task outside this enrollment
     * would let the agent run code in an unconfined process. Refuse ATTACH-mode
     * access across the enrollment boundary regardless of policy.
     */
    if ((mode & PTRACE_MODE_ATTACH) && child) {
        u32 target = (u32)BPF_CORE_READ(child, tgid);
        struct mercury_enrollment *target_enrollment =
            bpf_map_lookup_elem(&mercury_enrolled_pids, &target);
        if (!target_enrollment ||
            (enrollment->enrollment_id != 0 &&
             target_enrollment->enrollment_id != enrollment->enrollment_id)) {
            decision = DECISION_DENY;
            reason = REASON_DENY_BY_RULE;
            decision_ctx.rule_ref = RULE_REF(RULE_KIND_SYNTHETIC, SYNTH_PTRACE_UNENROLLED);
        }
    }
    /* READ-mode checks marked NOAUDIT (e.g. /proc field visibility) are noise. */
    if (decision == DECISION_ALLOW && (mode & PTRACE_MODE_NOAUDIT)) {
        return 0;
    }

    decision_ctx.action = ACTION_PROC_PTRACE;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->process_mode;
    decision_ctx.resource = "<ptrace>";
    decision_ctx.port = 0;
    decision_ctx.aux = mode;
    decision_ctx.target_pid = child ? (u32)BPF_CORE_READ(child, tgid) : 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}

/*
 * ptrace_traceme: fires when the enrolled process calls PTRACE_TRACEME.
 * Same policy evaluation as ptrace_access_check.
 */
SEC("lsm/ptrace_traceme")
int BPF_PROG(mercury_ptrace_traceme)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    decision = evaluate_exec(profile, "<ptrace>", &reason, &decision_ctx.rule_ref);
    decision_ctx.action = ACTION_PROC_PTRACE;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->process_mode;
    decision_ctx.resource = "<ptrace-traceme>";
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}

/*
 * task_kill: fires when an enrolled process tries to send a signal.
 * Evaluated against process policy using "<task-kill>".
 * The signal number is stored in the port field of the event.
 */
SEC("lsm/task_kill")
int BPF_PROG(mercury_task_kill,
             struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    decision = evaluate_exec(profile, "<task-kill>", &reason, &decision_ctx.rule_ref);

    /*
     * Killing mercuryd would detach every hook (programs are not pinned), so
     * signals from an enrolled task to a Mercury-owned (ignored, unenrolled)
     * task are refused. Signal 0 (existence probe) stays allowed.
     */
    if (sig != 0 && p) {
        u32 target = (u32)BPF_CORE_READ(p, tgid);
        if (pid_in_map(&mercury_ignored_pids, target) &&
            !bpf_map_lookup_elem(&mercury_enrolled_pids, &target)) {
            decision = DECISION_DENY;
            reason = REASON_DENY_BY_RULE;
            decision_ctx.rule_ref = RULE_REF(RULE_KIND_SYNTHETIC, SYNTH_SIGNAL_PROTECTED);
        }
    }
    decision_ctx.action = ACTION_PROC_KILL;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->process_mode;
    decision_ctx.resource = "<task-kill>";
    decision_ctx.port = 0;
    decision_ctx.aux = (u32)sig;
    decision_ctx.target_pid = p ? (u32)BPF_CORE_READ(p, tgid) : 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}

/*
 * capable: audit-only hook. Always allows; emits an event so operators can
 * observe what capabilities enrolled agents are requesting.
 * The capability number is encoded in the port field.
 */
SEC("lsm/capable")
int BPF_PROG(mercury_capable,
             const struct cred *cred, struct user_namespace *ns,
             int cap, unsigned int opts)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_emit_ctx emit = {};
    u32 uid = (u32)bpf_get_current_uid_gid();

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    emit.action = ACTION_PROC_CAPABLE;
    emit.pid = pid;
    emit.uid = uid;
    emit.decision = DECISION_ALLOW;
    emit.reason = REASON_ALLOW_BY_DEFAULT;
    emit.profile = profile->name;
    emit.resource = "<capable>";
    emit.port = 0;
    emit.aux = (u32)cap;   /* capability number; the grant decision is not visible here */
    emit.ip = (const u8 *)0;
    emit.enrollment_id = enrollment->enrollment_id;
    emit_event(&emit);
    return 0;
}

#if MERCURY_ENABLE_FILESYSTEM_LSM
SEC("lsm/file_open")
int BPF_PROG(mercury_file_open, struct file *file)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    char *path;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }

    {
        if (enrollment->launch_exec_bypass) {
            /*
             * Launch handoff: allow all file opens so the exec machinery can open
             * interpreter binaries, shared libraries, and dynamic linker before
             * sched_process_exec clears launch_exec_bypass.  Any attempt to
             * mmap those files MAP_SHARED|PROT_WRITE is still blocked by the
             * separate mercury_mmap_file hook which does NOT honour exec_bypass.
             */
            return 0;
        }

        profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
        if (!profile) {
            return 0;
        }

        path = scratch_resource();
        if (!path) {
            return 0;
        }

        if (load_file_path(file, path, MAX_RESOURCE_BYTES) < 0) {
            copy_cstr(path, MAX_RESOURCE_BYTES, "<unknown>");
        decision_ctx.flags |= EVENT_FLAG_PATH_UNRESOLVED;
        }
        decision = evaluate_file(profile, path, &reason, &decision_ctx.rule_ref);

        /* Read f_flags after all path-matching is done to minimise verifier state growth. */
        /* O_ACCMODE = 0x3: 0=RDONLY, 1=WRONLY, 2=RDWR — any non-zero value is a write */
        {
            u32 f_flags = BPF_CORE_READ(file, f_flags);
            decision_ctx.action = (f_flags & 3) ? ACTION_FILE_WRITE : ACTION_FILE_OPEN;
        }
    }
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->file_mode;
    decision_ctx.resource = path;
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}

SEC("lsm/path_unlink")
int BPF_PROG(mercury_inode_unlink, const struct path *dir, struct dentry *dentry)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    char *path;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }

    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }

    path = scratch_resource();
    if (!path) {
        return 0;
    }

    if (load_unlink_path((struct path *)dir, dentry, path, MAX_RESOURCE_BYTES) < 0) {
        copy_cstr(path, MAX_RESOURCE_BYTES, "<unknown>");
        decision_ctx.flags |= EVENT_FLAG_PATH_UNRESOLVED;
    }
    decision = evaluate_file(profile, path, &reason, &decision_ctx.rule_ref);

    decision_ctx.action = ACTION_FILE_DELETE;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->file_mode;
    decision_ctx.resource = path;
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}
#endif

#if MERCURY_ENABLE_EXEC_PATH_LSM
SEC("lsm/bprm_check_security")
int BPF_PROG(mercury_bprm_check_security, struct linux_binprm *bprm)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    char *path;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }

    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }

    path = scratch_resource();
    if (!path) {
        return 0;
    }

    if (load_exec_path(bprm, path, MAX_RESOURCE_BYTES) < 0) {
        copy_cstr(path, MAX_RESOURCE_BYTES, "<unknown>");
        decision_ctx.flags |= EVENT_FLAG_PATH_UNRESOLVED;
    }

    decision = evaluate_exec(profile, path, &reason, &decision_ctx.rule_ref);

    decision_ctx.action = ACTION_EXEC;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->process_mode;
    decision_ctx.resource = path;
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}
#endif

SEC("lsm/socket_connect")
int BPF_PROG(mercury_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    struct mercury_net_dest dest = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }

    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }

    init_net_dest_from_sockaddr(sock, address, addrlen, &dest);
    if (is_local_socket_family(dest.family)) {
        char *socket_path = scratch_resource2();
        int kind = socket_path ? load_unix_path(address, addrlen, socket_path) : 0;
        int hit = (kind == 1) ? unix_socket_denied(profile, socket_path) : 0;

        if (kind) {
            decision_ctx.resource2 = socket_path;
        }
        if (hit) {
            decision_ctx.action = ACTION_NET_CONNECT;
            decision_ctx.decision = DECISION_DENY;
            decision_ctx.reason = REASON_DENY_BY_RULE;
            decision_ctx.rule_ref =
                RULE_REF(RULE_KIND_FILE, profile->file_deny_offset + (u32)(hit - 1));
            decision_ctx.profile = profile;
            decision_ctx.enrollment = enrollment;
            decision_ctx.class_mode = profile->file_mode;
            decision_ctx.resource = "<socket_connect>";
            decision_ctx.family = dest.family;
            decision_ctx.ip = (const u8 *)0;
            return handle_decision(&decision_ctx);
        }
    }
    if (profile->url_enforce && is_local_socket_family(dest.family)) {
        decision_ctx.action = ACTION_NET_CONNECT;
        decision_ctx.decision = DECISION_ALLOW;
        decision_ctx.reason = REASON_ALLOW_BY_RULE;
        decision_ctx.profile = profile;
        decision_ctx.enrollment = enrollment;
        decision_ctx.class_mode = profile->network_mode;
        decision_ctx.resource = "<socket_connect>";
        decision_ctx.port = dest.port;
        decision_ctx.family = dest.family;
        decision_ctx.ip = (const u8 *)0;
        return handle_decision(&decision_ctx);
    }
    decision = evaluate_network(profile, &dest, &reason, &decision_ctx.rule_ref);

    decision_ctx.action = ACTION_NET_CONNECT;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->network_mode;
    decision_ctx.resource = "<socket_connect>";
    decision_ctx.port = dest.port;
    decision_ctx.ip = dest.has_addr ? dest.addr : (const u8 *)0;
    decision_ctx.family = dest.family;
    decision_ctx.protocol = dest.protocol;
    return handle_decision(&decision_ctx);
}

/*
 * Catch writable MAP_SHARED file-backed mappings.  MAP_PRIVATE is copy-on-write
 * and does not modify the underlying file, so we skip it.  Anonymous mappings
 * (file == NULL) are also skipped.
 */
#if MERCURY_ENABLE_FILESYSTEM_LSM
SEC("lsm/mmap_file")
int BPF_PROG(mercury_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;
    char *path;

    if (!file || !(prot & PROT_WRITE) || (flags & MAP_PRIVATE)) {
        return 0;
    }

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }

    /* mmap-write is never part of the exec handoff path — bypass does not apply. */

    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }

    path = scratch_resource();
    if (!path) {
        return 0;
    }

    if (load_file_path(file, path, MAX_RESOURCE_BYTES) < 0) {
        copy_cstr(path, MAX_RESOURCE_BYTES, "<unknown>");
        decision_ctx.flags |= EVENT_FLAG_PATH_UNRESOLVED;
    }

    decision = evaluate_file(profile, path, &reason, &decision_ctx.rule_ref);
    decision_ctx.action = ACTION_FILE_MMAP;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->file_mode;
    decision_ctx.resource = path;
    decision_ctx.port = 0;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}
#endif

/*
 * Catch UDP sendto / sendmsg calls that supply a destination address directly
 * (msg_name != NULL) rather than using a prior socket_connect.  Connected sends
 * are already evaluated at socket_connect time and return early here.
 */
SEC("lsm/socket_sendmsg")
int BPF_PROG(mercury_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
    (void)ctx;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    struct mercury_net_dest dest = {};
    void *msg_name_raw = (void *)0;
    int name_len = 0;
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }

    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }

    /*
     * Only handle sends that carry an explicit destination address.
     * Connected-socket sends (msg_name == NULL) were already evaluated
     * when the socket was connected via socket_connect.
     */
    bpf_probe_read_kernel(&msg_name_raw, sizeof(msg_name_raw),
                          (const void *)__builtin_preserve_access_index(&msg->msg_name));
    if (!msg_name_raw) {
        return 0;
    }
    bpf_probe_read_kernel(&name_len, sizeof(name_len),
                          (const void *)__builtin_preserve_access_index(&msg->msg_namelen));

    init_net_dest_from_sockaddr(sock, (struct sockaddr *)msg_name_raw, name_len, &dest);
    if (is_local_socket_family(dest.family)) {
        char *socket_path = scratch_resource2();
        int kind = socket_path
            ? load_unix_path((struct sockaddr *)msg_name_raw, name_len, socket_path)
            : 0;
        int hit = (kind == 1) ? unix_socket_denied(profile, socket_path) : 0;

        if (kind) {
            decision_ctx.resource2 = socket_path;
        }
        if (hit) {
            decision_ctx.action = ACTION_NET_SENDMSG;
            decision_ctx.decision = DECISION_DENY;
            decision_ctx.reason = REASON_DENY_BY_RULE;
            decision_ctx.rule_ref =
                RULE_REF(RULE_KIND_FILE, profile->file_deny_offset + (u32)(hit - 1));
            decision_ctx.profile = profile;
            decision_ctx.enrollment = enrollment;
            decision_ctx.class_mode = profile->file_mode;
            decision_ctx.resource = "<socket_sendmsg>";
            decision_ctx.family = dest.family;
            decision_ctx.ip = (const u8 *)0;
            return handle_decision(&decision_ctx);
        }
    }

    decision = evaluate_network(profile, &dest, &reason, &decision_ctx.rule_ref);
    decision_ctx.action = ACTION_NET_SENDMSG;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->network_mode;
    decision_ctx.resource = "<socket_sendmsg>";
    decision_ctx.port = dest.port;
    decision_ctx.ip = dest.has_addr ? dest.addr : (const u8 *)0;
    decision_ctx.family = dest.family;
    decision_ctx.protocol = dest.protocol;
    return handle_decision(&decision_ctx);
}

/* ─── Privileged / tamper-relevant operations ─────────────────────────── */

/*
 * Shared tail for the synthetic-path privileged hooks. `strict` means an
 * explicit exec_allow entry for `synthetic` is required: the policy default
 * decision is not enough to load BPF programs or kernel code.
 */
static __always_inline int handle_privileged_op(
    u32 action,
    const char *synthetic,
    const char *resource2,
    u32 aux,
    u32 strict_synth_id)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_decision_ctx decision_ctx = {};
    u32 reason = REASON_ALLOW_BY_RULE;
    int decision;

    enrollment = lookup_enrollment(pid);
    if (!enrollment) {
        return 0;
    }
    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    if (!profile) {
        return 0;
    }
    decision = evaluate_exec(profile, synthetic, &reason, &decision_ctx.rule_ref);
    if (strict_synth_id && decision == DECISION_ALLOW && reason != REASON_ALLOW_BY_RULE) {
        decision = DECISION_DENY;
        reason = REASON_DENY_BY_DEFAULT;
        decision_ctx.rule_ref = RULE_REF(RULE_KIND_SYNTHETIC, strict_synth_id);
    }
    decision_ctx.action = action;
    decision_ctx.decision = decision;
    decision_ctx.reason = reason;
    decision_ctx.profile = profile;
    decision_ctx.enrollment = enrollment;
    decision_ctx.class_mode = profile->process_mode;
    decision_ctx.resource = synthetic;
    decision_ctx.resource2 = resource2;
    decision_ctx.aux = aux;
    decision_ctx.ip = (const u8 *)0;
    return handle_decision(&decision_ctx);
}

/*
 * bpf(2): an enrolled root/CAP_BPF process could otherwise open Mercury's own
 * maps by id and delete its enrollment. Denied unless exec_allow lists "<bpf>".
 */
SEC("lsm/bpf")
int BPF_PROG(mercury_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    (void)ctx;
    return handle_privileged_op(
        ACTION_PROC_BPF, "<bpf>", (const char *)0, (u32)cmd, SYNTH_BPF_DEFAULT_DENY);
}

/* finit_module / kexec_file_load. Denied unless exec_allow lists "<kernel-module>". */
SEC("lsm/kernel_read_file")
int BPF_PROG(mercury_kernel_read_file, struct file *file, enum kernel_read_file_id id, bool contents)
{
    (void)ctx;
    if (id != READING_MODULE && id != READING_KEXEC_IMAGE && id != READING_KEXEC_INITRAMFS) {
        return 0;
    }
    return handle_privileged_op(
        ACTION_PROC_MODULE, "<kernel-module>", (const char *)0, (u32)id, SYNTH_MODULE_DEFAULT_DENY);
}

/* init_module / kexec_load. */
SEC("lsm/kernel_load_data")
int BPF_PROG(mercury_kernel_load_data, enum kernel_load_data_id id, bool contents)
{
    (void)ctx;
    if (id != LOADING_MODULE && id != LOADING_KEXEC_IMAGE) {
        return 0;
    }
    return handle_privileged_op(
        ACTION_PROC_MODULE, "<kernel-module>", (const char *)0, (u32)id, SYNTH_MODULE_DEFAULT_DENY);
}

/*
 * mount(2): a bind mount can re-expose a denied tree under an allowed path,
 * and path rules only ever see the post-mount path. Evaluated as "<mount>"
 * under normal policy semantics (sandboxes such as bubblewrap mount inside
 * their own namespaces, so default-allow policies keep working).
 */
SEC("lsm/sb_mount")
int BPF_PROG(mercury_sb_mount, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags)  /* trailing `data` arg unused */
{
    (void)ctx;
    return handle_privileged_op(ACTION_PROC_MOUNT, "<mount>", dev_name, (u32)flags, 0);
}

SEC("lsm/move_mount")
int BPF_PROG(mercury_move_mount, const struct path *from_path, const struct path *to_path)
{
    (void)ctx;
    return handle_privileged_op(ACTION_PROC_MOUNT, "<mount>", (const char *)0, 0, 0);
}

/* unshare(CLONE_NEWUSER) / clone(CLONE_NEWUSER): the entry point to unprivileged mounts. */
SEC("lsm/userns_create")
int BPF_PROG(mercury_userns_create, const struct cred *cred)
{
    (void)ctx;
    return handle_privileged_op(ACTION_PROC_USERNS, "<userns>", (const char *)0, 0, 0);
}

SEC("tracepoint/sched/sched_process_fork")
int mercury_sched_process_fork(void *ctx)
{
    struct trace_event_raw_sched_process_fork *event = ctx;
    u32 parent_tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
    u32 parent = (u32)event->parent_pid;
    u32 child = (u32)event->child_pid;
    struct mercury_enrollment *parent_enrollment;
    struct mercury_enrollment copied = {};
    u8 ignored = 1;

    /*
     * Enrollment is keyed by tgid, so look the parent up by its thread group
     * first. Keying only on the forking thread's tid let children of threads
     * created before enrollment (e.g. an auto-enrolled multi-threaded process)
     * escape enrollment entirely.
     */
    parent_enrollment = bpf_map_lookup_elem(&mercury_enrolled_pids, &parent_tgid);
    if (!parent_enrollment) {
        parent_enrollment = bpf_map_lookup_elem(&mercury_enrolled_pids, &parent);
    }
    if (parent_enrollment) {
        copied = *parent_enrollment;
        copied.launch_exec_bypass = 0;
        bpf_map_update_elem(&mercury_enrolled_pids, &child, &copied, BPF_ANY);
    }

    if (pid_in_map(&mercury_ignored_pids, parent_tgid) || pid_in_map(&mercury_ignored_pids, parent)) {
        bpf_map_update_elem(&mercury_ignored_pids, &child, &ignored, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int mercury_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 old_pid = (u32)ctx->old_pid;
    struct mercury_enrollment *enrollment;
    struct mercury_profile *profile;
    struct mercury_emit_ctx emit = {};
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long arg_start = 0;
    unsigned long arg_end = 0;
    char *filename;
    u32 fname_off;

    /*
     * An exec from a non-leader thread takes over the tgid; the thread's old
     * tid entry is now stale and must not be inherited by a future pid reuse.
     */
    if (old_pid != pid) {
        bpf_map_delete_elem(&mercury_enrolled_pids, &old_pid);
    }

    enrollment = bpf_map_lookup_elem(&mercury_enrolled_pids, &pid);
    if (!enrollment) {
        return 0;
    }
    enrollment->launch_exec_bypass = 0;

    profile = bpf_map_lookup_elem(&mercury_profiles, &enrollment->profile_index);
    filename = scratch_resource();
    if (!filename) {
        return 0;
    }
    fname_off = ctx->__data_loc_filename & 0xFFFF;
    if (bpf_probe_read_kernel_str(filename, MAX_RESOURCE_BYTES, (void *)ctx + fname_off) < 0) {
        copy_cstr(filename, MAX_RESOURCE_BYTES, "<unknown>");
        emit.flags |= EVENT_FLAG_PATH_UNRESOLVED;
    }

    task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        mm = BPF_CORE_READ(task, mm);
        if (mm) {
            arg_start = BPF_CORE_READ(mm, arg_start);
            arg_end = BPF_CORE_READ(mm, arg_end);
        }
    }

    emit.action = ACTION_PROC_START;
    emit.pid = pid;
    emit.uid = (u32)bpf_get_current_uid_gid();
    emit.decision = DECISION_ALLOW;
    emit.reason = REASON_ALLOW_BY_RULE;
    emit.profile = profile ? profile->name : "default";
    emit.resource = filename;
    emit.enrollment_id = enrollment->enrollment_id;
    emit.target_pid = old_pid;
    if (old_pid != pid) {
        emit.flags |= EVENT_FLAG_EXEC_FROM_THREAD;
    }
    if (arg_end > arg_start) {
        unsigned long len = arg_end - arg_start;
        if (len > MAX_RESOURCE2_BYTES - 1) {
            len = MAX_RESOURCE2_BYTES - 1;
            emit.flags |= EVENT_FLAG_ARGV_TRUNCATED;
        }
        emit.resource2_user = (const void *)arg_start;
        emit.resource2_len = (u32)len;
    }
    emit_event(&emit);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int mercury_sched_process_exit(void *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid = (u32)pid_tgid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct signal_struct *signal;
    struct mercury_enrollment *enrollment;
    struct mercury_enrollment snapshot = {};
    struct mercury_profile *profile;
    struct mercury_emit_ctx emit = {};
    int live = 0;
    int was_enrolled = 0;
    (void)ctx;

    /*
     * sched_process_fork also observes thread clones, so per-thread entries
     * exist; drop them as each thread exits. The thread-group entry (tgid) is
     * only removed once the whole group is dead — deleting it when the leader
     * thread exits first (pthread_exit in main, or an exec from another
     * thread) silently un-enrolled the still-running process.
     */
    if (tid != tgid) {
        bpf_map_delete_elem(&mercury_enrolled_pids, &tid);
        bpf_map_delete_elem(&mercury_ignored_pids, &tid);
    }

    if (task) {
        signal = BPF_CORE_READ(task, signal);
        if (signal) {
            live = BPF_CORE_READ(signal, live.counter);
        }
    }
    if (live > 0) {
        return 0;
    }

    enrollment = bpf_map_lookup_elem(&mercury_enrolled_pids, &tgid);
    if (enrollment) {
        snapshot = *enrollment;
        was_enrolled = 1;
    }
    /* Only the thread whose delete succeeds reports the exit (dedupes races). */
    if (bpf_map_delete_elem(&mercury_enrolled_pids, &tgid) != 0) {
        was_enrolled = 0;
    }
    bpf_map_delete_elem(&mercury_ignored_pids, &tgid);
    bpf_map_delete_elem(&mercury_rate_limit, &tgid);

    if (!was_enrolled) {
        return 0;
    }

    profile = bpf_map_lookup_elem(&mercury_profiles, &snapshot.profile_index);
    emit.action = ACTION_PROC_EXIT;
    emit.pid = tgid;
    emit.uid = (u32)bpf_get_current_uid_gid();
    emit.decision = DECISION_ALLOW;
    emit.reason = REASON_ALLOW_BY_RULE;
    emit.profile = profile ? profile->name : "default";
    emit.resource = "<exit>";
    emit.enrollment_id = snapshot.enrollment_id;
    emit.aux = task ? (u32)BPF_CORE_READ(task, exit_code) : 0;
    emit_event(&emit);
    return 0;
}

char _license[] SEC("license") = "GPL";
