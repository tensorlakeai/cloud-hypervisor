// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use block::{BLKDISCARD, BLKZEROOUT};
use libc::{FIONBIO, TIOCGWINSZ, TUNSETOFFLOAD};
use seccompiler::SeccompCmpOp::Eq;
use seccompiler::{
    BpfProgram, Error, SeccompAction, SeccompCmpArgLen as ArgLen, SeccompCondition as Cond,
    SeccompFilter, SeccompRule,
};

#[derive(Clone, Copy)]
pub enum Thread {
    VirtioBalloon,
    VirtioBlock,
    VirtioConsole,
    VirtioIommu,
    VirtioMem,
    VirtioNet,
    VirtioNetCtl,
    VirtioPmem,
    VirtioRng,
    VirtioRtc,
    VirtioVhostBlock,
    VirtioVhostFs,
    VirtioGenericVhostUser,
    VirtioVhostNet,
    VirtioVhostNetCtl,
    VirtioVsock,
    VirtioWatchdog,
}

/// Shorthand for chaining `SeccompCondition`s with the `and` operator  in a `SeccompRule`.
/// The rule will take the `Allow` action if _all_ the conditions are true.
///
/// [`SeccompCondition`]: struct.SeccompCondition.html
/// [`SeccompRule`]: struct.SeccompRule.html
macro_rules! and {
    ($($x:expr),*) => (SeccompRule::new(vec![$($x),*]).unwrap())
}

/// Shorthand for chaining `SeccompRule`s with the `or` operator in a `SeccompFilter`.
///
/// [`SeccompFilter`]: struct.SeccompFilter.html
/// [`SeccompRule`]: struct.SeccompRule.html
macro_rules! or {
    ($($x:expr,)*) => (vec![$($x),*]);
    ($($x:expr),*) => (vec![$($x),*])
}

// See include/uapi/linux/vfio.h in the kernel code.
const VFIO_IOMMU_MAP_DMA: u64 = 0x3b71;
const VFIO_IOMMU_UNMAP_DMA: u64 = 0x3b72;

// See include/uapi/linux/iommufd.h in the kernel code.
const IOMMU_IOAS_MAP: u64 = 0x3b85;
const IOMMU_IOAS_UNMAP: u64 = 0x3b86;

#[cfg(feature = "sev_snp")]
fn mshv_sev_snp_ioctl_seccomp_rule() -> SeccompRule {
    and![
        Cond::new(
            1,
            ArgLen::Dword,
            Eq,
            mshv_ioctls::MSHV_MODIFY_GPA_HOST_ACCESS()
        )
        .unwrap()
    ]
}

#[cfg(feature = "sev_snp")]
fn create_mshv_sev_snp_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![mshv_sev_snp_ioctl_seccomp_rule()]
}

fn create_virtio_console_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, TIOCGWINSZ as _).unwrap()],
        #[cfg(feature = "sev_snp")]
        mshv_sev_snp_ioctl_seccomp_rule(),
    ]
}

fn create_virtio_iommu_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_MAP_DMA).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_UNMAP_DMA).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, IOMMU_IOAS_MAP).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, IOMMU_IOAS_UNMAP).unwrap()],
    ]
}

fn create_virtio_mem_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_MAP_DMA).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, VFIO_IOMMU_UNMAP_DMA).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, IOMMU_IOAS_MAP).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, IOMMU_IOAS_UNMAP).unwrap()],
    ]
}

fn virtio_balloon_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_fallocate, vec![])]
}

fn virtio_block_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_fallocate, vec![]),
        (libc::SYS_fcntl, vec![]),
        (libc::SYS_fdatasync, vec![]),
        (libc::SYS_fsync, vec![]),
        (libc::SYS_ftruncate, vec![]),
        (libc::SYS_getrandom, vec![]),
        (libc::SYS_ioctl, create_virtio_block_ioctl_seccomp_rule()),
        (libc::SYS_io_destroy, vec![]),
        (libc::SYS_io_getevents, vec![]),
        (libc::SYS_io_submit, vec![]),
        (libc::SYS_io_uring_enter, vec![]),
        (libc::SYS_lseek, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_mkdir, vec![]),
        (libc::SYS_mkdirat, vec![]),
        (libc::SYS_newfstatat, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_open, vec![]),
        (libc::SYS_pread64, vec![]),
        (libc::SYS_preadv, vec![]),
        (libc::SYS_pwritev, vec![]),
        (libc::SYS_pwrite64, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_rename, vec![]),
        (libc::SYS_renameat, vec![]),
        (libc::SYS_renameat2, vec![]),
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_sched_setaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_stat, vec![]),
        (libc::SYS_statx, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_unlink, vec![]),
        #[cfg(target_arch = "aarch64")]
        (libc::SYS_unlinkat, vec![]),
    ]
}

fn create_virtio_block_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, BLKDISCARD as _).unwrap()],
        and![Cond::new(1, ArgLen::Dword, Eq, BLKZEROOUT as _).unwrap()],
        #[cfg(feature = "sev_snp")]
        mshv_sev_snp_ioctl_seccomp_rule(),
    ]
}

fn virtio_console_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_ioctl, create_virtio_console_ioctl_seccomp_rule()),
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
    ]
}

fn virtio_iommu_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_ioctl, create_virtio_iommu_ioctl_seccomp_rule())]
}

fn virtio_mem_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_fallocate, vec![]),
        (libc::SYS_ioctl, create_virtio_mem_ioctl_seccomp_rule()),
        (libc::SYS_recvfrom, vec![]),
        (libc::SYS_sendmsg, vec![]),
    ]
}

fn virtio_net_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        #[cfg(feature = "sev_snp")]
        (libc::SYS_ioctl, create_mshv_sev_snp_ioctl_seccomp_rule()),
        (libc::SYS_readv, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
        (libc::SYS_writev, vec![]),
    ]
}

fn create_virtio_net_ctl_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, TUNSETOFFLOAD as _).unwrap()],
        #[cfg(feature = "sev_snp")]
        mshv_sev_snp_ioctl_seccomp_rule(),
    ]
}

fn virtio_net_ctl_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_ioctl, create_virtio_net_ctl_ioctl_seccomp_rule())]
}

fn virtio_pmem_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![(libc::SYS_fsync, vec![])]
}

fn virtio_rng_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        #[cfg(feature = "sev_snp")]
        (libc::SYS_ioctl, create_mshv_sev_snp_ioctl_seccomp_rule()),
    ]
}

fn virtio_rtc_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        #[cfg(feature = "sev_snp")]
        (libc::SYS_ioctl, create_mshv_sev_snp_ioctl_seccomp_rule()),
    ]
}

fn virtio_vhost_fs_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_clock_nanosleep, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_nanosleep, vec![]),
        (libc::SYS_pread64, vec![]),
        (libc::SYS_pwrite64, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_sendto, vec![]),
        (libc::SYS_socket, vec![]),
        (libc::SYS_timerfd_create, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

fn virtio_generic_vhost_user_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_clock_nanosleep, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_nanosleep, vec![]),
        (libc::SYS_pread64, vec![]),
        (libc::SYS_pwrite64, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_sendto, vec![]),
        (libc::SYS_socket, vec![]),
        (libc::SYS_timerfd_create, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

fn virtio_vhost_net_ctl_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![]
}

fn virtio_vhost_net_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_accept4, vec![]),
        (libc::SYS_bind, vec![]),
        (libc::SYS_clock_nanosleep, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_getcwd, vec![]),
        (libc::SYS_listen, vec![]),
        (libc::SYS_nanosleep, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_sendto, vec![]),
        (libc::SYS_socket, vec![]),
        (libc::SYS_timerfd_create, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_unlink, vec![]),
        #[cfg(target_arch = "aarch64")]
        (libc::SYS_unlinkat, vec![]),
    ]
}

fn virtio_vhost_block_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_clock_nanosleep, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_nanosleep, vec![]),
        (libc::SYS_recvmsg, vec![]),
        (libc::SYS_sendmsg, vec![]),
        (libc::SYS_socket, vec![]),
        (libc::SYS_timerfd_create, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

fn create_vsock_ioctl_seccomp_rule() -> Vec<SeccompRule> {
    or![
        and![Cond::new(1, ArgLen::Dword, Eq, FIONBIO as _).unwrap()],
        #[cfg(feature = "sev_snp")]
        mshv_sev_snp_ioctl_seccomp_rule(),
    ]
}

fn virtio_vsock_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_accept4, vec![]),
        (libc::SYS_connect, vec![]),
        (libc::SYS_fcntl, vec![]),
        (libc::SYS_ioctl, create_vsock_ioctl_seccomp_rule()),
        (libc::SYS_recvfrom, vec![]),
        (libc::SYS_sendto, vec![]),
        (libc::SYS_socket, vec![]),
    ]
}

fn virtio_watchdog_thread_rules() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_sched_getaffinity, vec![]),
        (libc::SYS_set_robust_list, vec![]),
        (libc::SYS_timerfd_settime, vec![]),
    ]
}

fn get_seccomp_rules(thread_type: Thread) -> Vec<(i64, Vec<SeccompRule>)> {
    let mut rules = match thread_type {
        Thread::VirtioBalloon => virtio_balloon_thread_rules(),
        Thread::VirtioBlock => virtio_block_thread_rules(),
        Thread::VirtioConsole => virtio_console_thread_rules(),
        Thread::VirtioIommu => virtio_iommu_thread_rules(),
        Thread::VirtioMem => virtio_mem_thread_rules(),
        Thread::VirtioNet => virtio_net_thread_rules(),
        Thread::VirtioNetCtl => virtio_net_ctl_thread_rules(),
        Thread::VirtioPmem => virtio_pmem_thread_rules(),
        Thread::VirtioRng => virtio_rng_thread_rules(),
        Thread::VirtioRtc => virtio_rtc_thread_rules(),
        Thread::VirtioVhostBlock => virtio_vhost_block_thread_rules(),
        Thread::VirtioVhostFs => virtio_vhost_fs_thread_rules(),
        Thread::VirtioGenericVhostUser => virtio_generic_vhost_user_thread_rules(),
        Thread::VirtioVhostNet => virtio_vhost_net_thread_rules(),
        Thread::VirtioVhostNetCtl => virtio_vhost_net_ctl_thread_rules(),
        Thread::VirtioVsock => virtio_vsock_thread_rules(),
        Thread::VirtioWatchdog => virtio_watchdog_thread_rules(),
    };
    rules.append(&mut virtio_thread_common());
    rules
}

fn virtio_thread_common() -> Vec<(i64, Vec<SeccompRule>)> {
    vec![
        (libc::SYS_brk, vec![]),
        (libc::SYS_clock_gettime, vec![]),
        (libc::SYS_close, vec![]),
        (libc::SYS_dup, vec![]),
        (libc::SYS_epoll_create1, vec![]),
        (libc::SYS_epoll_ctl, vec![]),
        (libc::SYS_epoll_pwait, vec![]),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_epoll_wait, vec![]),
        (libc::SYS_exit, vec![]),
        (libc::SYS_fcntl, vec![]),
        (libc::SYS_futex, vec![]),
        (libc::SYS_gettid, vec![]),
        (libc::SYS_madvise, vec![]),
        (libc::SYS_mmap, vec![]),
        (libc::SYS_mprotect, vec![]),
        (libc::SYS_mremap, vec![]),
        (libc::SYS_munmap, vec![]),
        (libc::SYS_openat, vec![]),
        (libc::SYS_read, vec![]),
        (libc::SYS_rt_sigprocmask, vec![]),
        (libc::SYS_rt_sigreturn, vec![]),
        (libc::SYS_sigaltstack, vec![]),
        (libc::SYS_write, vec![]),
    ]
}

/// Generate a BPF program based on the seccomp_action value
pub fn get_seccomp_filter(
    seccomp_action: &SeccompAction,
    thread_type: Thread,
) -> Result<BpfProgram, Error> {
    match seccomp_action {
        SeccompAction::Allow => Ok(vec![]),
        SeccompAction::Log => SeccompFilter::new(
            get_seccomp_rules(thread_type).into_iter().collect(),
            SeccompAction::Log,
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().unwrap(),
        )
        .and_then(|filter| filter.try_into())
        .map_err(Error::Backend),
        _ => SeccompFilter::new(
            get_seccomp_rules(thread_type).into_iter().collect(),
            SeccompAction::Trap,
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().unwrap(),
        )
        .and_then(|filter| filter.try_into())
        .map_err(Error::Backend),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::path::Path;

    use seccompiler::{SeccompAction, apply_filter};

    use super::*;

    #[test]
    fn virtio_block_filter_allows_tensorlake_live_index_syscalls() {
        let rules: BTreeMap<_, _> = get_seccomp_rules(Thread::VirtioBlock).into_iter().collect();

        #[cfg(target_arch = "x86_64")]
        {
            assert!(rules.contains_key(&libc::SYS_mkdir));
            assert!(rules.contains_key(&libc::SYS_rename));
            assert!(rules.contains_key(&libc::SYS_stat));
            assert!(rules.contains_key(&libc::SYS_unlink));
        }
        assert!(rules.contains_key(&libc::SYS_mkdirat));
        assert!(rules.contains_key(&libc::SYS_newfstatat));
        #[cfg(target_arch = "x86_64")]
        assert!(rules.contains_key(&libc::SYS_open));
        assert!(rules.contains_key(&libc::SYS_renameat));
        assert!(rules.contains_key(&libc::SYS_renameat2));
        assert!(rules.contains_key(&libc::SYS_statx));
    }

    #[test]
    fn virtio_block_compiled_filter_allows_tensorlake_live_index_syscalls() {
        let filter = get_seccomp_filter(&SeccompAction::Trap, Thread::VirtioBlock)
            .expect("build virtio-block seccomp filter");
        let sandbox = std::env::temp_dir().join(format!("ch-seccomp-test-{}", std::process::id()));

        // SAFETY: fork is used to apply an irreversible seccomp filter in the child.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            if let Err(error) = apply_filter(&filter) {
                eprintln!("apply_filter failed: {error:?}");
                exit_child(100);
            }

            let dir = c_path(&sandbox);
            // SAFETY: dir is a valid C string and mode is a plain value.
            let mkdir_result = unsafe { libc::mkdir(dir.as_ptr(), 0o700) };
            if mkdir_result != 0 {
                eprintln!("mkdir failed: {}", std::io::Error::last_os_error());
                exit_child(101);
            }

            let source = sandbox.join("source");
            let dest = sandbox.join("dest");
            std::fs::write(&source, b"data").expect("write source file");

            let source_c = c_path(&source);
            let dest_c = c_path(&dest);
            // SAFETY: paths are valid C strings.
            let rename_result = unsafe { libc::rename(source_c.as_ptr(), dest_c.as_ptr()) };
            if rename_result != 0 {
                eprintln!("rename failed: {}", std::io::Error::last_os_error());
                exit_child(102);
            }

            verify_open_is_allowed(&dest_c);
            verify_statx_is_allowed(&dest_c);
            verify_stat_is_allowed(&dest_c);

            // SAFETY: path is a valid C string.
            let unlink_result = unsafe { libc::unlink(dest_c.as_ptr()) };
            if unlink_result != 0 {
                eprintln!("unlink failed: {}", std::io::Error::last_os_error());
                exit_child(104);
            }

            exit_child(0);
        }

        let mut status = 0;
        // SAFETY: pid is a live child process.
        let wait_result = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(wait_result, pid, "waitpid failed");
        let _ = std::fs::remove_dir_all(&sandbox);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child failed: status={status}"
        );
    }

    fn c_path(path: &Path) -> CString {
        CString::new(path.to_string_lossy().as_bytes()).expect("path contains no nul bytes")
    }

    #[cfg(target_arch = "x86_64")]
    fn verify_statx_is_allowed(path: &CString) {
        // SAFETY: Intentionally pass a null statx buffer. When the syscall is
        // allowed, the kernel returns EFAULT; if seccomp blocks it, the child
        // exits due to SIGSYS before reaching this check.
        let statx_result = unsafe {
            libc::syscall(
                libc::SYS_statx,
                libc::AT_FDCWD,
                path.as_ptr(),
                0,
                0,
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        let error = std::io::Error::last_os_error();
        if statx_result != -1 || error.raw_os_error() != Some(libc::EFAULT) {
            eprintln!("statx failed unexpectedly: {error}");
            exit_child(103);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn verify_statx_is_allowed(_path: &CString) {}

    #[cfg(target_arch = "x86_64")]
    fn verify_open_is_allowed(path: &CString) {
        // SAFETY: path is a valid C string. Use the raw syscall so this test
        // covers musl's SYS_open path even when the test binary is linked with
        // a libc that implements open() through openat().
        let fd = unsafe { libc::syscall(libc::SYS_open, path.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            eprintln!("open syscall failed: {}", std::io::Error::last_os_error());
            exit_child(106);
        }
        // SAFETY: fd was returned by open and is owned by this child.
        unsafe {
            libc::close(fd as libc::c_int);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn verify_open_is_allowed(_path: &CString) {}

    #[cfg(target_arch = "x86_64")]
    fn verify_stat_is_allowed(path: &CString) {
        let mut stat_buf = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: path is a valid C string and stat_buf points to writable memory.
        let stat_result = unsafe { libc::stat(path.as_ptr(), stat_buf.as_mut_ptr()) };
        if stat_result != 0 {
            eprintln!("stat failed: {}", std::io::Error::last_os_error());
            exit_child(105);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn verify_stat_is_allowed(_path: &CString) {}

    fn exit_child(status: i32) -> ! {
        // SAFETY: invoke the per-thread exit syscall so this test does not require
        // permitting process-wide exit_group in the virtio-block seccomp policy.
        unsafe {
            libc::syscall(libc::SYS_exit, status);
        }
        unreachable!("SYS_exit returned")
    }
}
