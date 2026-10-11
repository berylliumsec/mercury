#![no_std]

pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_RULES_PER_CLASS: usize = 1024;
pub const MAX_PROFILES: usize = 128;
pub const MAX_ENROLLED_PIDS: usize = 262_144;

// Deterministic glob matcher with kernel-friendly behavior:
// - '*' matches a run without '/'
// - '**' matches across '/'
// - '?' matches a single char except '/'
pub fn matches_path_glob(pattern: &str, candidate: &str) -> bool {
    let p = pattern.as_bytes();
    let s = candidate.as_bytes();
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star_pi, mut star_si, mut star_cross) = (None, 0usize, false);

    while si < s.len() {
        if pi < p.len() {
            if p[pi] == b'*' {
                let mut cross = false;
                let next = pi + 1;
                if next < p.len() && p[next] == b'*' {
                    cross = true;
                    pi += 1;
                }
                star_pi = Some(pi);
                star_si = si;
                star_cross = cross;
                pi += 1;
                continue;
            }

            if p[pi] == b'?' {
                if s[si] != b'/' {
                    pi += 1;
                    si += 1;
                    continue;
                }
            } else if p[pi] == s[si] {
                pi += 1;
                si += 1;
                continue;
            }
        }

        if let Some(saved_pi) = star_pi {
            if !star_cross && s[star_si] == b'/' {
                return false;
            }
            star_si += 1;
            si = star_si;
            pi = saved_pi + 1;
            if star_si > s.len() {
                return false;
            }
            continue;
        }

        return false;
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }

    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::matches_path_glob;

    #[test]
    fn matches_simple_patterns() {
        assert!(matches_path_glob("/workspace/**", "/workspace/a/b"));
        assert!(matches_path_glob("/bin/*", "/bin/ls"));
        assert!(!matches_path_glob("/bin/*", "/bin/a/b"));
        assert!(matches_path_glob("/usr/bin/?h", "/usr/bin/sh"));
    }
}
