use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn kernel_release() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn append_bpftool_paths_from(base_dir: &str, candidates: &mut Vec<PathBuf>) {
    if let Ok(output) = Command::new("find")
        .arg(base_dir)
        .arg("-name")
        .arg("bpftool")
        .arg("-type")
        .arg("f")
        .output()
        && output.status.success()
    {
        let mut discovered = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        discovered.sort();
        candidates.extend(discovered);
    }
}

fn bpftool_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(path) = env::var("BPFTOOL") {
        candidates.push(PathBuf::from(path));
    }

    candidates.push(PathBuf::from("bpftool"));
    candidates.push(PathBuf::from("/usr/sbin/bpftool"));
    candidates.push(PathBuf::from("/usr/bin/bpftool"));

    if let Some(release) = kernel_release() {
        candidates.push(PathBuf::from(format!(
            "/usr/lib/linux-tools/{release}/bpftool"
        )));
        candidates.push(PathBuf::from(format!(
            "/usr/lib/linux-tools-{release}/bpftool"
        )));
    }

    if let Ok(entries) = fs::read_dir("/usr/lib/linux-tools") {
        let mut discovered = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("bpftool"))
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        discovered.sort();
        candidates.extend(discovered);
    }

    append_bpftool_paths_from("/usr/lib", &mut candidates);
    append_bpftool_paths_from("/usr/libexec", &mut candidates);

    let mut deduped = Vec::new();
    for candidate in candidates {
        if !deduped.contains(&candidate) {
            deduped.push(candidate);
        }
    }
    deduped
}

fn generate_vmlinux_header(out_vmlinux: &PathBuf) {
    let mut failures = Vec::new();

    for candidate in bpftool_candidates() {
        let output = Command::new(&candidate)
            .arg("btf")
            .arg("dump")
            .arg("file")
            .arg("/sys/kernel/btf/vmlinux")
            .arg("format")
            .arg("c")
            .output();

        match output {
            Ok(output) if output.status.success() => {
                println!("cargo:warning=using bpftool at {}", candidate.display());
                fs::write(out_vmlinux, output.stdout).expect("write generated vmlinux.h");
                return;
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let wrapper_missing_kernel_tools =
                    candidate == Path::new("bpftool") && stderr.contains("not found for kernel");
                failures.push(format!(
                    "{} -> status={} stderr={}",
                    candidate.display(),
                    output.status,
                    stderr
                ));
                if wrapper_missing_kernel_tools {
                    continue;
                }
            }
            Err(err) => {
                failures.push(format!("{} -> {}", candidate.display(), err));
            }
        }
    }

    panic!(
        "bpftool failed generating vmlinux.h; tried: {}",
        failures.join(" | ")
    );
}

fn compile_bpf_object(src: &PathBuf, out_dir: &PathBuf, out_obj: &PathBuf, extra_args: &[&str]) {
    let mut command = Command::new("clang");
    command
        .arg("-O2")
        .arg("-g")
        .arg("-target")
        .arg("bpf")
        .arg("-D__TARGET_ARCH_x86")
        .arg("-I")
        .arg(out_dir)
        .arg("-Wall")
        .arg("-Werror");
    for arg in extra_args {
        command.arg(arg);
    }
    command.arg("-c").arg(src).arg("-o").arg(out_obj);

    let status = command.status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => panic!(
            "clang failed building eBPF object {} with exit code: {s}",
            out_obj.display()
        ),
        Err(err) => panic!(
            "failed to run clang for eBPF build {}: {err}",
            out_obj.display()
        ),
    }
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let target = env::var("TARGET").unwrap_or_default();
    let src = PathBuf::from("src/mercury_kern.c");
    let out_obj = out_dir.join("mercury_kern.o");
    let out_apparmor_obj = out_dir.join("mercury_kern_apparmor.o");
    let out_vmlinux = out_dir.join("vmlinux.h");

    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-env-changed=BPFTOOL");

    if !target.contains("linux") {
        fs::write(&out_obj, []).expect("write empty non-linux object placeholder");
        fs::write(&out_apparmor_obj, []).expect("write empty non-linux object placeholder");
        return;
    }

    generate_vmlinux_header(&out_vmlinux);

    compile_bpf_object(&src, &out_dir, &out_obj, &[]);
    compile_bpf_object(
        &src,
        &out_dir,
        &out_apparmor_obj,
        &[
            "-DMERCURY_DISABLE_FILESYSTEM_LSM=1",
            "-DMERCURY_DISABLE_EXEC_PATH_LSM=1",
        ],
    );
}
