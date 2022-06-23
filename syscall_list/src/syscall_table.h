#pragma once

#include <sys/syscall.h>
#include <string>
#include <optional>

#define syscode_case(x) case x: return #x

static inline const char* syscall_name_(const auto nbr) {
    switch(nbr) {
#ifdef SYS_FAST_atomic_update
        syscode_case(SYS_FAST_atomic_update);
#endif
#ifdef SYS_FAST_cmpxchg
        syscode_case(SYS_FAST_cmpxchg);
#endif
#ifdef SYS_FAST_cmpxchg64
        syscode_case(SYS_FAST_cmpxchg64);
#endif
#ifdef SYS__llseek
        syscode_case(SYS__llseek);
#endif
#ifdef SYS__newselect
        syscode_case(SYS__newselect);
#endif
#ifdef SYS__sysctl
        syscode_case(SYS__sysctl);
#endif
#ifdef SYS_accept
        syscode_case(SYS_accept);
#endif
#ifdef SYS_accept4
        syscode_case(SYS_accept4);
#endif
#ifdef SYS_access
        syscode_case(SYS_access);
#endif
#ifdef SYS_acct
        syscode_case(SYS_acct);
#endif
#ifdef SYS_acl_get
        syscode_case(SYS_acl_get);
#endif
#ifdef SYS_acl_set
        syscode_case(SYS_acl_set);
#endif
#ifdef SYS_add_key
        syscode_case(SYS_add_key);
#endif
#ifdef SYS_adjtimex
        syscode_case(SYS_adjtimex);
#endif
#ifdef SYS_afs_syscall
        syscode_case(SYS_afs_syscall);
#endif
#ifdef SYS_alarm
        syscode_case(SYS_alarm);
#endif
#ifdef SYS_alloc_hugepages
        syscode_case(SYS_alloc_hugepages);
#endif
#ifdef SYS_arc_gettls
        syscode_case(SYS_arc_gettls);
#endif
#ifdef SYS_arc_settls
        syscode_case(SYS_arc_settls);
#endif
#ifdef SYS_arc_usr_cmpxchg
        syscode_case(SYS_arc_usr_cmpxchg);
#endif
#ifdef SYS_arch_prctl
        syscode_case(SYS_arch_prctl);
#endif
#ifdef SYS_arm_fadvise64_64
        syscode_case(SYS_arm_fadvise64_64);
#endif
#ifdef SYS_arm_sync_file_range
        syscode_case(SYS_arm_sync_file_range);
#endif
#ifdef SYS_atomic_barrier
        syscode_case(SYS_atomic_barrier);
#endif
#ifdef SYS_atomic_cmpxchg_32
        syscode_case(SYS_atomic_cmpxchg_32);
#endif
#ifdef SYS_attrctl
        syscode_case(SYS_attrctl);
#endif
#ifdef SYS_bdflush
        syscode_case(SYS_bdflush);
#endif
#ifdef SYS_bind
        syscode_case(SYS_bind);
#endif
#ifdef SYS_bpf
        syscode_case(SYS_bpf);
#endif
#ifdef SYS_break
        syscode_case(SYS_break);
#endif
#ifdef SYS_breakpoint
        syscode_case(SYS_breakpoint);
#endif
#ifdef SYS_brk
        syscode_case(SYS_brk);
#endif
#ifdef SYS_cachectl
        syscode_case(SYS_cachectl);
#endif
#ifdef SYS_cacheflush
        syscode_case(SYS_cacheflush);
#endif
#ifdef SYS_capget
        syscode_case(SYS_capget);
#endif
#ifdef SYS_capset
        syscode_case(SYS_capset);
#endif
#ifdef SYS_chdir
        syscode_case(SYS_chdir);
#endif
#ifdef SYS_chmod
        syscode_case(SYS_chmod);
#endif
#ifdef SYS_chown
        syscode_case(SYS_chown);
#endif
#ifdef SYS_chown32
        syscode_case(SYS_chown32);
#endif
#ifdef SYS_chroot
        syscode_case(SYS_chroot);
#endif
#ifdef SYS_clock_adjtime
        syscode_case(SYS_clock_adjtime);
#endif
#ifdef SYS_clock_adjtime64
        syscode_case(SYS_clock_adjtime64);
#endif
#ifdef SYS_clock_getres
        syscode_case(SYS_clock_getres);
#endif
#ifdef SYS_clock_getres_time64
        syscode_case(SYS_clock_getres_time64);
#endif
#ifdef SYS_clock_gettime
        syscode_case(SYS_clock_gettime);
#endif
#ifdef SYS_clock_gettime64
        syscode_case(SYS_clock_gettime64);
#endif
#ifdef SYS_clock_nanosleep
        syscode_case(SYS_clock_nanosleep);
#endif
#ifdef SYS_clock_nanosleep_time64
        syscode_case(SYS_clock_nanosleep_time64);
#endif
#ifdef SYS_clock_settime
        syscode_case(SYS_clock_settime);
#endif
#ifdef SYS_clock_settime64
        syscode_case(SYS_clock_settime64);
#endif
#ifdef SYS_clone
        syscode_case(SYS_clone);
#endif
#ifdef SYS_clone2
        syscode_case(SYS_clone2);
#endif
#ifdef SYS_clone3
        syscode_case(SYS_clone3);
#endif
#ifdef SYS_close
        syscode_case(SYS_close);
#endif
#ifdef SYS_close_range
        syscode_case(SYS_close_range);
#endif
#ifdef SYS_cmpxchg_badaddr
        syscode_case(SYS_cmpxchg_badaddr);
#endif
#ifdef SYS_connect
        syscode_case(SYS_connect);
#endif
#ifdef SYS_copy_file_range
        syscode_case(SYS_copy_file_range);
#endif
#ifdef SYS_creat
        syscode_case(SYS_creat);
#endif
#ifdef SYS_create_module
        syscode_case(SYS_create_module);
#endif
#ifdef SYS_delete_module
        syscode_case(SYS_delete_module);
#endif
#ifdef SYS_dipc
        syscode_case(SYS_dipc);
#endif
#ifdef SYS_dup
        syscode_case(SYS_dup);
#endif
#ifdef SYS_dup2
        syscode_case(SYS_dup2);
#endif
#ifdef SYS_dup3
        syscode_case(SYS_dup3);
#endif
#ifdef SYS_epoll_create
        syscode_case(SYS_epoll_create);
#endif
#ifdef SYS_epoll_create1
        syscode_case(SYS_epoll_create1);
#endif
#ifdef SYS_epoll_ctl
        syscode_case(SYS_epoll_ctl);
#endif
#ifdef SYS_epoll_ctl_old
        syscode_case(SYS_epoll_ctl_old);
#endif
#ifdef SYS_epoll_pwait
        syscode_case(SYS_epoll_pwait);
#endif
#ifdef SYS_epoll_pwait2
        syscode_case(SYS_epoll_pwait2);
#endif
#ifdef SYS_epoll_wait
        syscode_case(SYS_epoll_wait);
#endif
#ifdef SYS_epoll_wait_old
        syscode_case(SYS_epoll_wait_old);
#endif
#ifdef SYS_eventfd
        syscode_case(SYS_eventfd);
#endif
#ifdef SYS_eventfd2
        syscode_case(SYS_eventfd2);
#endif
#ifdef SYS_exec_with_loader
        syscode_case(SYS_exec_with_loader);
#endif
#ifdef SYS_execv
        syscode_case(SYS_execv);
#endif
#ifdef SYS_execve
        syscode_case(SYS_execve);
#endif
#ifdef SYS_execveat
        syscode_case(SYS_execveat);
#endif
#ifdef SYS_exit
        syscode_case(SYS_exit);
#endif
#ifdef SYS_exit_group
        syscode_case(SYS_exit_group);
#endif
#ifdef SYS_faccessat
        syscode_case(SYS_faccessat);
#endif
#ifdef SYS_faccessat2
        syscode_case(SYS_faccessat2);
#endif
#ifdef SYS_fadvise64
        syscode_case(SYS_fadvise64);
#endif
#ifdef SYS_fadvise64_64
        syscode_case(SYS_fadvise64_64);
#endif
#ifdef SYS_fallocate
        syscode_case(SYS_fallocate);
#endif
#ifdef SYS_fanotify_init
        syscode_case(SYS_fanotify_init);
#endif
#ifdef SYS_fanotify_mark
        syscode_case(SYS_fanotify_mark);
#endif
#ifdef SYS_fchdir
        syscode_case(SYS_fchdir);
#endif
#ifdef SYS_fchmod
        syscode_case(SYS_fchmod);
#endif
#ifdef SYS_fchmodat
        syscode_case(SYS_fchmodat);
#endif
#ifdef SYS_fchown
        syscode_case(SYS_fchown);
#endif
#ifdef SYS_fchown32
        syscode_case(SYS_fchown32);
#endif
#ifdef SYS_fchownat
        syscode_case(SYS_fchownat);
#endif
#ifdef SYS_fcntl
        syscode_case(SYS_fcntl);
#endif
#ifdef SYS_fcntl64
        syscode_case(SYS_fcntl64);
#endif
#ifdef SYS_fdatasync
        syscode_case(SYS_fdatasync);
#endif
#ifdef SYS_fgetxattr
        syscode_case(SYS_fgetxattr);
#endif
#ifdef SYS_finit_module
        syscode_case(SYS_finit_module);
#endif
#ifdef SYS_flistxattr
        syscode_case(SYS_flistxattr);
#endif
#ifdef SYS_flock
        syscode_case(SYS_flock);
#endif
#ifdef SYS_fork
        syscode_case(SYS_fork);
#endif
#ifdef SYS_fp_udfiex_crtl
        syscode_case(SYS_fp_udfiex_crtl);
#endif
#ifdef SYS_free_hugepages
        syscode_case(SYS_free_hugepages);
#endif
#ifdef SYS_fremovexattr
        syscode_case(SYS_fremovexattr);
#endif
#ifdef SYS_fsconfig
        syscode_case(SYS_fsconfig);
#endif
#ifdef SYS_fsetxattr
        syscode_case(SYS_fsetxattr);
#endif
#ifdef SYS_fsmount
        syscode_case(SYS_fsmount);
#endif
#ifdef SYS_fsopen
        syscode_case(SYS_fsopen);
#endif
#ifdef SYS_fspick
        syscode_case(SYS_fspick);
#endif
#ifdef SYS_fstat
        syscode_case(SYS_fstat);
#endif
#ifdef SYS_fstat64
        syscode_case(SYS_fstat64);
#endif
#ifdef SYS_fstatat64
        syscode_case(SYS_fstatat64);
#endif
#ifdef SYS_fstatfs
        syscode_case(SYS_fstatfs);
#endif
#ifdef SYS_fstatfs64
        syscode_case(SYS_fstatfs64);
#endif
#ifdef SYS_fsync
        syscode_case(SYS_fsync);
#endif
#ifdef SYS_ftime
        syscode_case(SYS_ftime);
#endif
#ifdef SYS_ftruncate
        syscode_case(SYS_ftruncate);
#endif
#ifdef SYS_ftruncate64
        syscode_case(SYS_ftruncate64);
#endif
#ifdef SYS_futex
        syscode_case(SYS_futex);
#endif
#ifdef SYS_futex_time64
        syscode_case(SYS_futex_time64);
#endif
#ifdef SYS_futex_waitv
        syscode_case(SYS_futex_waitv);
#endif
#ifdef SYS_futimesat
        syscode_case(SYS_futimesat);
#endif
#ifdef SYS_get_kernel_syms
        syscode_case(SYS_get_kernel_syms);
#endif
#ifdef SYS_get_mempolicy
        syscode_case(SYS_get_mempolicy);
#endif
#ifdef SYS_get_robust_list
        syscode_case(SYS_get_robust_list);
#endif
#ifdef SYS_get_thread_area
        syscode_case(SYS_get_thread_area);
#endif
#ifdef SYS_get_tls
        syscode_case(SYS_get_tls);
#endif
#ifdef SYS_getcpu
        syscode_case(SYS_getcpu);
#endif
#ifdef SYS_getcwd
        syscode_case(SYS_getcwd);
#endif
#ifdef SYS_getdents
        syscode_case(SYS_getdents);
#endif
#ifdef SYS_getdents64
        syscode_case(SYS_getdents64);
#endif
#ifdef SYS_getdomainname
        syscode_case(SYS_getdomainname);
#endif
#ifdef SYS_getdtablesize
        syscode_case(SYS_getdtablesize);
#endif
#ifdef SYS_getegid
        syscode_case(SYS_getegid);
#endif
#ifdef SYS_getegid32
        syscode_case(SYS_getegid32);
#endif
#ifdef SYS_geteuid
        syscode_case(SYS_geteuid);
#endif
#ifdef SYS_geteuid32
        syscode_case(SYS_geteuid32);
#endif
#ifdef SYS_getgid
        syscode_case(SYS_getgid);
#endif
#ifdef SYS_getgid32
        syscode_case(SYS_getgid32);
#endif
#ifdef SYS_getgroups
        syscode_case(SYS_getgroups);
#endif
#ifdef SYS_getgroups32
        syscode_case(SYS_getgroups32);
#endif
#ifdef SYS_gethostname
        syscode_case(SYS_gethostname);
#endif
#ifdef SYS_getitimer
        syscode_case(SYS_getitimer);
#endif
#ifdef SYS_getpagesize
        syscode_case(SYS_getpagesize);
#endif
#ifdef SYS_getpeername
        syscode_case(SYS_getpeername);
#endif
#ifdef SYS_getpgid
        syscode_case(SYS_getpgid);
#endif
#ifdef SYS_getpgrp
        syscode_case(SYS_getpgrp);
#endif
#ifdef SYS_getpid
        syscode_case(SYS_getpid);
#endif
#ifdef SYS_getpmsg
        syscode_case(SYS_getpmsg);
#endif
#ifdef SYS_getppid
        syscode_case(SYS_getppid);
#endif
#ifdef SYS_getpriority
        syscode_case(SYS_getpriority);
#endif
#ifdef SYS_getrandom
        syscode_case(SYS_getrandom);
#endif
#ifdef SYS_getresgid
        syscode_case(SYS_getresgid);
#endif
#ifdef SYS_getresgid32
        syscode_case(SYS_getresgid32);
#endif
#ifdef SYS_getresuid
        syscode_case(SYS_getresuid);
#endif
#ifdef SYS_getresuid32
        syscode_case(SYS_getresuid32);
#endif
#ifdef SYS_getrlimit
        syscode_case(SYS_getrlimit);
#endif
#ifdef SYS_getrusage
        syscode_case(SYS_getrusage);
#endif
#ifdef SYS_getsid
        syscode_case(SYS_getsid);
#endif
#ifdef SYS_getsockname
        syscode_case(SYS_getsockname);
#endif
#ifdef SYS_getsockopt
        syscode_case(SYS_getsockopt);
#endif
#ifdef SYS_gettid
        syscode_case(SYS_gettid);
#endif
#ifdef SYS_gettimeofday
        syscode_case(SYS_gettimeofday);
#endif
#ifdef SYS_getuid
        syscode_case(SYS_getuid);
#endif
#ifdef SYS_getuid32
        syscode_case(SYS_getuid32);
#endif
#ifdef SYS_getunwind
        syscode_case(SYS_getunwind);
#endif
#ifdef SYS_getxattr
        syscode_case(SYS_getxattr);
#endif
#ifdef SYS_getxgid
        syscode_case(SYS_getxgid);
#endif
#ifdef SYS_getxpid
        syscode_case(SYS_getxpid);
#endif
#ifdef SYS_getxuid
        syscode_case(SYS_getxuid);
#endif
#ifdef SYS_gtty
        syscode_case(SYS_gtty);
#endif
#ifdef SYS_idle
        syscode_case(SYS_idle);
#endif
#ifdef SYS_init_module
        syscode_case(SYS_init_module);
#endif
#ifdef SYS_inotify_add_watch
        syscode_case(SYS_inotify_add_watch);
#endif
#ifdef SYS_inotify_init
        syscode_case(SYS_inotify_init);
#endif
#ifdef SYS_inotify_init1
        syscode_case(SYS_inotify_init1);
#endif
#ifdef SYS_inotify_rm_watch
        syscode_case(SYS_inotify_rm_watch);
#endif
#ifdef SYS_io_cancel
        syscode_case(SYS_io_cancel);
#endif
#ifdef SYS_io_destroy
        syscode_case(SYS_io_destroy);
#endif
#ifdef SYS_io_getevents
        syscode_case(SYS_io_getevents);
#endif
#ifdef SYS_io_pgetevents
        syscode_case(SYS_io_pgetevents);
#endif
#ifdef SYS_io_pgetevents_time64
        syscode_case(SYS_io_pgetevents_time64);
#endif
#ifdef SYS_io_setup
        syscode_case(SYS_io_setup);
#endif
#ifdef SYS_io_submit
        syscode_case(SYS_io_submit);
#endif
#ifdef SYS_io_uring_enter
        syscode_case(SYS_io_uring_enter);
#endif
#ifdef SYS_io_uring_register
        syscode_case(SYS_io_uring_register);
#endif
#ifdef SYS_io_uring_setup
        syscode_case(SYS_io_uring_setup);
#endif
#ifdef SYS_ioctl
        syscode_case(SYS_ioctl);
#endif
#ifdef SYS_ioperm
        syscode_case(SYS_ioperm);
#endif
#ifdef SYS_iopl
        syscode_case(SYS_iopl);
#endif
#ifdef SYS_ioprio_get
        syscode_case(SYS_ioprio_get);
#endif
#ifdef SYS_ioprio_set
        syscode_case(SYS_ioprio_set);
#endif
#ifdef SYS_ipc
        syscode_case(SYS_ipc);
#endif
#ifdef SYS_kcmp
        syscode_case(SYS_kcmp);
#endif
#ifdef SYS_kern_features
        syscode_case(SYS_kern_features);
#endif
#ifdef SYS_kexec_file_load
        syscode_case(SYS_kexec_file_load);
#endif
#ifdef SYS_kexec_load
        syscode_case(SYS_kexec_load);
#endif
#ifdef SYS_keyctl
        syscode_case(SYS_keyctl);
#endif
#ifdef SYS_kill
        syscode_case(SYS_kill);
#endif
#ifdef SYS_landlock_add_rule
        syscode_case(SYS_landlock_add_rule);
#endif
#ifdef SYS_landlock_create_ruleset
        syscode_case(SYS_landlock_create_ruleset);
#endif
#ifdef SYS_landlock_restrict_self
        syscode_case(SYS_landlock_restrict_self);
#endif
#ifdef SYS_lchown
        syscode_case(SYS_lchown);
#endif
#ifdef SYS_lchown32
        syscode_case(SYS_lchown32);
#endif
#ifdef SYS_lgetxattr
        syscode_case(SYS_lgetxattr);
#endif
#ifdef SYS_link
        syscode_case(SYS_link);
#endif
#ifdef SYS_linkat
        syscode_case(SYS_linkat);
#endif
#ifdef SYS_listen
        syscode_case(SYS_listen);
#endif
#ifdef SYS_listxattr
        syscode_case(SYS_listxattr);
#endif
#ifdef SYS_llistxattr
        syscode_case(SYS_llistxattr);
#endif
#ifdef SYS_llseek
        syscode_case(SYS_llseek);
#endif
#ifdef SYS_lock
        syscode_case(SYS_lock);
#endif
#ifdef SYS_lookup_dcookie
        syscode_case(SYS_lookup_dcookie);
#endif
#ifdef SYS_lremovexattr
        syscode_case(SYS_lremovexattr);
#endif
#ifdef SYS_lseek
        syscode_case(SYS_lseek);
#endif
#ifdef SYS_lsetxattr
        syscode_case(SYS_lsetxattr);
#endif
#ifdef SYS_lstat
        syscode_case(SYS_lstat);
#endif
#ifdef SYS_lstat64
        syscode_case(SYS_lstat64);
#endif
#ifdef SYS_madvise
        syscode_case(SYS_madvise);
#endif
#ifdef SYS_mbind
        syscode_case(SYS_mbind);
#endif
#ifdef SYS_membarrier
        syscode_case(SYS_membarrier);
#endif
#ifdef SYS_memfd_create
        syscode_case(SYS_memfd_create);
#endif
#ifdef SYS_memfd_secret
        syscode_case(SYS_memfd_secret);
#endif
#ifdef SYS_memory_ordering
        syscode_case(SYS_memory_ordering);
#endif
#ifdef SYS_migrate_pages
        syscode_case(SYS_migrate_pages);
#endif
#ifdef SYS_mincore
        syscode_case(SYS_mincore);
#endif
#ifdef SYS_mkdir
        syscode_case(SYS_mkdir);
#endif
#ifdef SYS_mkdirat
        syscode_case(SYS_mkdirat);
#endif
#ifdef SYS_mknod
        syscode_case(SYS_mknod);
#endif
#ifdef SYS_mknodat
        syscode_case(SYS_mknodat);
#endif
#ifdef SYS_mlock
        syscode_case(SYS_mlock);
#endif
#ifdef SYS_mlock2
        syscode_case(SYS_mlock2);
#endif
#ifdef SYS_mlockall
        syscode_case(SYS_mlockall);
#endif
#ifdef SYS_mmap
        syscode_case(SYS_mmap);
#endif
#ifdef SYS_mmap2
        syscode_case(SYS_mmap2);
#endif
#ifdef SYS_modify_ldt
        syscode_case(SYS_modify_ldt);
#endif
#ifdef SYS_mount
        syscode_case(SYS_mount);
#endif
#ifdef SYS_mount_setattr
        syscode_case(SYS_mount_setattr);
#endif
#ifdef SYS_move_mount
        syscode_case(SYS_move_mount);
#endif
#ifdef SYS_move_pages
        syscode_case(SYS_move_pages);
#endif
#ifdef SYS_mprotect
        syscode_case(SYS_mprotect);
#endif
#ifdef SYS_mpx
        syscode_case(SYS_mpx);
#endif
#ifdef SYS_mq_getsetattr
        syscode_case(SYS_mq_getsetattr);
#endif
#ifdef SYS_mq_notify
        syscode_case(SYS_mq_notify);
#endif
#ifdef SYS_mq_open
        syscode_case(SYS_mq_open);
#endif
#ifdef SYS_mq_timedreceive
        syscode_case(SYS_mq_timedreceive);
#endif
#ifdef SYS_mq_timedreceive_time64
        syscode_case(SYS_mq_timedreceive_time64);
#endif
#ifdef SYS_mq_timedsend
        syscode_case(SYS_mq_timedsend);
#endif
#ifdef SYS_mq_timedsend_time64
        syscode_case(SYS_mq_timedsend_time64);
#endif
#ifdef SYS_mq_unlink
        syscode_case(SYS_mq_unlink);
#endif
#ifdef SYS_mremap
        syscode_case(SYS_mremap);
#endif
#ifdef SYS_msgctl
        syscode_case(SYS_msgctl);
#endif
#ifdef SYS_msgget
        syscode_case(SYS_msgget);
#endif
#ifdef SYS_msgrcv
        syscode_case(SYS_msgrcv);
#endif
#ifdef SYS_msgsnd
        syscode_case(SYS_msgsnd);
#endif
#ifdef SYS_msync
        syscode_case(SYS_msync);
#endif
#ifdef SYS_multiplexer
        syscode_case(SYS_multiplexer);
#endif
#ifdef SYS_munlock
        syscode_case(SYS_munlock);
#endif
#ifdef SYS_munlockall
        syscode_case(SYS_munlockall);
#endif
#ifdef SYS_munmap
        syscode_case(SYS_munmap);
#endif
#ifdef SYS_name_to_handle_at
        syscode_case(SYS_name_to_handle_at);
#endif
#ifdef SYS_nanosleep
        syscode_case(SYS_nanosleep);
#endif
#ifdef SYS_newfstatat
        syscode_case(SYS_newfstatat);
#endif
#ifdef SYS_nfsservctl
        syscode_case(SYS_nfsservctl);
#endif
#ifdef SYS_ni_syscall
        syscode_case(SYS_ni_syscall);
#endif
#ifdef SYS_nice
        syscode_case(SYS_nice);
#endif
#ifdef SYS_old_adjtimex
        syscode_case(SYS_old_adjtimex);
#endif
#ifdef SYS_old_getpagesize
        syscode_case(SYS_old_getpagesize);
#endif
#ifdef SYS_oldfstat
        syscode_case(SYS_oldfstat);
#endif
#ifdef SYS_oldlstat
        syscode_case(SYS_oldlstat);
#endif
#ifdef SYS_oldolduname
        syscode_case(SYS_oldolduname);
#endif
#ifdef SYS_oldstat
        syscode_case(SYS_oldstat);
#endif
#ifdef SYS_oldumount
        syscode_case(SYS_oldumount);
#endif
#ifdef SYS_olduname
        syscode_case(SYS_olduname);
#endif
#ifdef SYS_open
        syscode_case(SYS_open);
#endif
#ifdef SYS_open_by_handle_at
        syscode_case(SYS_open_by_handle_at);
#endif
#ifdef SYS_open_tree
        syscode_case(SYS_open_tree);
#endif
#ifdef SYS_openat
        syscode_case(SYS_openat);
#endif
#ifdef SYS_openat2
        syscode_case(SYS_openat2);
#endif
#ifdef SYS_or1k_atomic
        syscode_case(SYS_or1k_atomic);
#endif
#ifdef SYS_osf_adjtime
        syscode_case(SYS_osf_adjtime);
#endif
#ifdef SYS_osf_afs_syscall
        syscode_case(SYS_osf_afs_syscall);
#endif
#ifdef SYS_osf_alt_plock
        syscode_case(SYS_osf_alt_plock);
#endif
#ifdef SYS_osf_alt_setsid
        syscode_case(SYS_osf_alt_setsid);
#endif
#ifdef SYS_osf_alt_sigpending
        syscode_case(SYS_osf_alt_sigpending);
#endif
#ifdef SYS_osf_asynch_daemon
        syscode_case(SYS_osf_asynch_daemon);
#endif
#ifdef SYS_osf_audcntl
        syscode_case(SYS_osf_audcntl);
#endif
#ifdef SYS_osf_audgen
        syscode_case(SYS_osf_audgen);
#endif
#ifdef SYS_osf_chflags
        syscode_case(SYS_osf_chflags);
#endif
#ifdef SYS_osf_execve
        syscode_case(SYS_osf_execve);
#endif
#ifdef SYS_osf_exportfs
        syscode_case(SYS_osf_exportfs);
#endif
#ifdef SYS_osf_fchflags
        syscode_case(SYS_osf_fchflags);
#endif
#ifdef SYS_osf_fdatasync
        syscode_case(SYS_osf_fdatasync);
#endif
#ifdef SYS_osf_fpathconf
        syscode_case(SYS_osf_fpathconf);
#endif
#ifdef SYS_osf_fstat
        syscode_case(SYS_osf_fstat);
#endif
#ifdef SYS_osf_fstatfs
        syscode_case(SYS_osf_fstatfs);
#endif
#ifdef SYS_osf_fstatfs64
        syscode_case(SYS_osf_fstatfs64);
#endif
#ifdef SYS_osf_fuser
        syscode_case(SYS_osf_fuser);
#endif
#ifdef SYS_osf_getaddressconf
        syscode_case(SYS_osf_getaddressconf);
#endif
#ifdef SYS_osf_getdirentries
        syscode_case(SYS_osf_getdirentries);
#endif
#ifdef SYS_osf_getdomainname
        syscode_case(SYS_osf_getdomainname);
#endif
#ifdef SYS_osf_getfh
        syscode_case(SYS_osf_getfh);
#endif
#ifdef SYS_osf_getfsstat
        syscode_case(SYS_osf_getfsstat);
#endif
#ifdef SYS_osf_gethostid
        syscode_case(SYS_osf_gethostid);
#endif
#ifdef SYS_osf_getitimer
        syscode_case(SYS_osf_getitimer);
#endif
#ifdef SYS_osf_getlogin
        syscode_case(SYS_osf_getlogin);
#endif
#ifdef SYS_osf_getmnt
        syscode_case(SYS_osf_getmnt);
#endif
#ifdef SYS_osf_getrusage
        syscode_case(SYS_osf_getrusage);
#endif
#ifdef SYS_osf_getsysinfo
        syscode_case(SYS_osf_getsysinfo);
#endif
#ifdef SYS_osf_gettimeofday
        syscode_case(SYS_osf_gettimeofday);
#endif
#ifdef SYS_osf_kloadcall
        syscode_case(SYS_osf_kloadcall);
#endif
#ifdef SYS_osf_kmodcall
        syscode_case(SYS_osf_kmodcall);
#endif
#ifdef SYS_osf_lstat
        syscode_case(SYS_osf_lstat);
#endif
#ifdef SYS_osf_memcntl
        syscode_case(SYS_osf_memcntl);
#endif
#ifdef SYS_osf_mincore
        syscode_case(SYS_osf_mincore);
#endif
#ifdef SYS_osf_mount
        syscode_case(SYS_osf_mount);
#endif
#ifdef SYS_osf_mremap
        syscode_case(SYS_osf_mremap);
#endif
#ifdef SYS_osf_msfs_syscall
        syscode_case(SYS_osf_msfs_syscall);
#endif
#ifdef SYS_osf_msleep
        syscode_case(SYS_osf_msleep);
#endif
#ifdef SYS_osf_mvalid
        syscode_case(SYS_osf_mvalid);
#endif
#ifdef SYS_osf_mwakeup
        syscode_case(SYS_osf_mwakeup);
#endif
#ifdef SYS_osf_naccept
        syscode_case(SYS_osf_naccept);
#endif
#ifdef SYS_osf_nfssvc
        syscode_case(SYS_osf_nfssvc);
#endif
#ifdef SYS_osf_ngetpeername
        syscode_case(SYS_osf_ngetpeername);
#endif
#ifdef SYS_osf_ngetsockname
        syscode_case(SYS_osf_ngetsockname);
#endif
#ifdef SYS_osf_nrecvfrom
        syscode_case(SYS_osf_nrecvfrom);
#endif
#ifdef SYS_osf_nrecvmsg
        syscode_case(SYS_osf_nrecvmsg);
#endif
#ifdef SYS_osf_nsendmsg
        syscode_case(SYS_osf_nsendmsg);
#endif
#ifdef SYS_osf_ntp_adjtime
        syscode_case(SYS_osf_ntp_adjtime);
#endif
#ifdef SYS_osf_ntp_gettime
        syscode_case(SYS_osf_ntp_gettime);
#endif
#ifdef SYS_osf_old_creat
        syscode_case(SYS_osf_old_creat);
#endif
#ifdef SYS_osf_old_fstat
        syscode_case(SYS_osf_old_fstat);
#endif
#ifdef SYS_osf_old_getpgrp
        syscode_case(SYS_osf_old_getpgrp);
#endif
#ifdef SYS_osf_old_killpg
        syscode_case(SYS_osf_old_killpg);
#endif
#ifdef SYS_osf_old_lstat
        syscode_case(SYS_osf_old_lstat);
#endif
#ifdef SYS_osf_old_open
        syscode_case(SYS_osf_old_open);
#endif
#ifdef SYS_osf_old_sigaction
        syscode_case(SYS_osf_old_sigaction);
#endif
#ifdef SYS_osf_old_sigblock
        syscode_case(SYS_osf_old_sigblock);
#endif
#ifdef SYS_osf_old_sigreturn
        syscode_case(SYS_osf_old_sigreturn);
#endif
#ifdef SYS_osf_old_sigsetmask
        syscode_case(SYS_osf_old_sigsetmask);
#endif
#ifdef SYS_osf_old_sigvec
        syscode_case(SYS_osf_old_sigvec);
#endif
#ifdef SYS_osf_old_stat
        syscode_case(SYS_osf_old_stat);
#endif
#ifdef SYS_osf_old_vadvise
        syscode_case(SYS_osf_old_vadvise);
#endif
#ifdef SYS_osf_old_vtrace
        syscode_case(SYS_osf_old_vtrace);
#endif
#ifdef SYS_osf_old_wait
        syscode_case(SYS_osf_old_wait);
#endif
#ifdef SYS_osf_oldquota
        syscode_case(SYS_osf_oldquota);
#endif
#ifdef SYS_osf_pathconf
        syscode_case(SYS_osf_pathconf);
#endif
#ifdef SYS_osf_pid_block
        syscode_case(SYS_osf_pid_block);
#endif
#ifdef SYS_osf_pid_unblock
        syscode_case(SYS_osf_pid_unblock);
#endif
#ifdef SYS_osf_plock
        syscode_case(SYS_osf_plock);
#endif
#ifdef SYS_osf_priocntlset
        syscode_case(SYS_osf_priocntlset);
#endif
#ifdef SYS_osf_profil
        syscode_case(SYS_osf_profil);
#endif
#ifdef SYS_osf_proplist_syscall
        syscode_case(SYS_osf_proplist_syscall);
#endif
#ifdef SYS_osf_reboot
        syscode_case(SYS_osf_reboot);
#endif
#ifdef SYS_osf_revoke
        syscode_case(SYS_osf_revoke);
#endif
#ifdef SYS_osf_sbrk
        syscode_case(SYS_osf_sbrk);
#endif
#ifdef SYS_osf_security
        syscode_case(SYS_osf_security);
#endif
#ifdef SYS_osf_select
        syscode_case(SYS_osf_select);
#endif
#ifdef SYS_osf_set_program_attributes
        syscode_case(SYS_osf_set_program_attributes);
#endif
#ifdef SYS_osf_set_speculative
        syscode_case(SYS_osf_set_speculative);
#endif
#ifdef SYS_osf_sethostid
        syscode_case(SYS_osf_sethostid);
#endif
#ifdef SYS_osf_setitimer
        syscode_case(SYS_osf_setitimer);
#endif
#ifdef SYS_osf_setlogin
        syscode_case(SYS_osf_setlogin);
#endif
#ifdef SYS_osf_setsysinfo
        syscode_case(SYS_osf_setsysinfo);
#endif
#ifdef SYS_osf_settimeofday
        syscode_case(SYS_osf_settimeofday);
#endif
#ifdef SYS_osf_shmat
        syscode_case(SYS_osf_shmat);
#endif
#ifdef SYS_osf_signal
        syscode_case(SYS_osf_signal);
#endif
#ifdef SYS_osf_sigprocmask
        syscode_case(SYS_osf_sigprocmask);
#endif
#ifdef SYS_osf_sigsendset
        syscode_case(SYS_osf_sigsendset);
#endif
#ifdef SYS_osf_sigstack
        syscode_case(SYS_osf_sigstack);
#endif
#ifdef SYS_osf_sigwaitprim
        syscode_case(SYS_osf_sigwaitprim);
#endif
#ifdef SYS_osf_sstk
        syscode_case(SYS_osf_sstk);
#endif
#ifdef SYS_osf_stat
        syscode_case(SYS_osf_stat);
#endif
#ifdef SYS_osf_statfs
        syscode_case(SYS_osf_statfs);
#endif
#ifdef SYS_osf_statfs64
        syscode_case(SYS_osf_statfs64);
#endif
#ifdef SYS_osf_subsys_info
        syscode_case(SYS_osf_subsys_info);
#endif
#ifdef SYS_osf_swapctl
        syscode_case(SYS_osf_swapctl);
#endif
#ifdef SYS_osf_swapon
        syscode_case(SYS_osf_swapon);
#endif
#ifdef SYS_osf_syscall
        syscode_case(SYS_osf_syscall);
#endif
#ifdef SYS_osf_sysinfo
        syscode_case(SYS_osf_sysinfo);
#endif
#ifdef SYS_osf_table
        syscode_case(SYS_osf_table);
#endif
#ifdef SYS_osf_uadmin
        syscode_case(SYS_osf_uadmin);
#endif
#ifdef SYS_osf_usleep_thread
        syscode_case(SYS_osf_usleep_thread);
#endif
#ifdef SYS_osf_uswitch
        syscode_case(SYS_osf_uswitch);
#endif
#ifdef SYS_osf_utc_adjtime
        syscode_case(SYS_osf_utc_adjtime);
#endif
#ifdef SYS_osf_utc_gettime
        syscode_case(SYS_osf_utc_gettime);
#endif
#ifdef SYS_osf_utimes
        syscode_case(SYS_osf_utimes);
#endif
#ifdef SYS_osf_utsname
        syscode_case(SYS_osf_utsname);
#endif
#ifdef SYS_osf_wait4
        syscode_case(SYS_osf_wait4);
#endif
#ifdef SYS_osf_waitid
        syscode_case(SYS_osf_waitid);
#endif
#ifdef SYS_pause
        syscode_case(SYS_pause);
#endif
#ifdef SYS_pciconfig_iobase
        syscode_case(SYS_pciconfig_iobase);
#endif
#ifdef SYS_pciconfig_read
        syscode_case(SYS_pciconfig_read);
#endif
#ifdef SYS_pciconfig_write
        syscode_case(SYS_pciconfig_write);
#endif
#ifdef SYS_perf_event_open
        syscode_case(SYS_perf_event_open);
#endif
#ifdef SYS_perfctr
        syscode_case(SYS_perfctr);
#endif
#ifdef SYS_perfmonctl
        syscode_case(SYS_perfmonctl);
#endif
#ifdef SYS_personality
        syscode_case(SYS_personality);
#endif
#ifdef SYS_pidfd_getfd
        syscode_case(SYS_pidfd_getfd);
#endif
#ifdef SYS_pidfd_open
        syscode_case(SYS_pidfd_open);
#endif
#ifdef SYS_pidfd_send_signal
        syscode_case(SYS_pidfd_send_signal);
#endif
#ifdef SYS_pipe
        syscode_case(SYS_pipe);
#endif
#ifdef SYS_pipe2
        syscode_case(SYS_pipe2);
#endif
#ifdef SYS_pivot_root
        syscode_case(SYS_pivot_root);
#endif
#ifdef SYS_pkey_alloc
        syscode_case(SYS_pkey_alloc);
#endif
#ifdef SYS_pkey_free
        syscode_case(SYS_pkey_free);
#endif
#ifdef SYS_pkey_mprotect
        syscode_case(SYS_pkey_mprotect);
#endif
#ifdef SYS_poll
        syscode_case(SYS_poll);
#endif
#ifdef SYS_ppoll
        syscode_case(SYS_ppoll);
#endif
#ifdef SYS_ppoll_time64
        syscode_case(SYS_ppoll_time64);
#endif
#ifdef SYS_prctl
        syscode_case(SYS_prctl);
#endif
#ifdef SYS_pread64
        syscode_case(SYS_pread64);
#endif
#ifdef SYS_preadv
        syscode_case(SYS_preadv);
#endif
#ifdef SYS_preadv2
        syscode_case(SYS_preadv2);
#endif
#ifdef SYS_prlimit64
        syscode_case(SYS_prlimit64);
#endif
#ifdef SYS_process_madvise
        syscode_case(SYS_process_madvise);
#endif
#ifdef SYS_process_mrelease
        syscode_case(SYS_process_mrelease);
#endif
#ifdef SYS_process_vm_readv
        syscode_case(SYS_process_vm_readv);
#endif
#ifdef SYS_process_vm_writev
        syscode_case(SYS_process_vm_writev);
#endif
#ifdef SYS_prof
        syscode_case(SYS_prof);
#endif
#ifdef SYS_profil
        syscode_case(SYS_profil);
#endif
#ifdef SYS_pselect6
        syscode_case(SYS_pselect6);
#endif
#ifdef SYS_pselect6_time64
        syscode_case(SYS_pselect6_time64);
#endif
#ifdef SYS_ptrace
        syscode_case(SYS_ptrace);
#endif
#ifdef SYS_putpmsg
        syscode_case(SYS_putpmsg);
#endif
#ifdef SYS_pwrite64
        syscode_case(SYS_pwrite64);
#endif
#ifdef SYS_pwritev
        syscode_case(SYS_pwritev);
#endif
#ifdef SYS_pwritev2
        syscode_case(SYS_pwritev2);
#endif
#ifdef SYS_query_module
        syscode_case(SYS_query_module);
#endif
#ifdef SYS_quotactl
        syscode_case(SYS_quotactl);
#endif
#ifdef SYS_quotactl_fd
        syscode_case(SYS_quotactl_fd);
#endif
#ifdef SYS_read
        syscode_case(SYS_read);
#endif
#ifdef SYS_readahead
        syscode_case(SYS_readahead);
#endif
#ifdef SYS_readdir
        syscode_case(SYS_readdir);
#endif
#ifdef SYS_readlink
        syscode_case(SYS_readlink);
#endif
#ifdef SYS_readlinkat
        syscode_case(SYS_readlinkat);
#endif
#ifdef SYS_readv
        syscode_case(SYS_readv);
#endif
#ifdef SYS_reboot
        syscode_case(SYS_reboot);
#endif
#ifdef SYS_recv
        syscode_case(SYS_recv);
#endif
#ifdef SYS_recvfrom
        syscode_case(SYS_recvfrom);
#endif
#ifdef SYS_recvmmsg
        syscode_case(SYS_recvmmsg);
#endif
#ifdef SYS_recvmmsg_time64
        syscode_case(SYS_recvmmsg_time64);
#endif
#ifdef SYS_recvmsg
        syscode_case(SYS_recvmsg);
#endif
#ifdef SYS_remap_file_pages
        syscode_case(SYS_remap_file_pages);
#endif
#ifdef SYS_removexattr
        syscode_case(SYS_removexattr);
#endif
#ifdef SYS_rename
        syscode_case(SYS_rename);
#endif
#ifdef SYS_renameat
        syscode_case(SYS_renameat);
#endif
#ifdef SYS_renameat2
        syscode_case(SYS_renameat2);
#endif
#ifdef SYS_request_key
        syscode_case(SYS_request_key);
#endif
#ifdef SYS_restart_syscall
        syscode_case(SYS_restart_syscall);
#endif
#ifdef SYS_riscv_flush_icache
        syscode_case(SYS_riscv_flush_icache);
#endif
#ifdef SYS_rmdir
        syscode_case(SYS_rmdir);
#endif
#ifdef SYS_rseq
        syscode_case(SYS_rseq);
#endif
#ifdef SYS_rt_sigaction
        syscode_case(SYS_rt_sigaction);
#endif
#ifdef SYS_rt_sigpending
        syscode_case(SYS_rt_sigpending);
#endif
#ifdef SYS_rt_sigprocmask
        syscode_case(SYS_rt_sigprocmask);
#endif
#ifdef SYS_rt_sigqueueinfo
        syscode_case(SYS_rt_sigqueueinfo);
#endif
#ifdef SYS_rt_sigreturn
        syscode_case(SYS_rt_sigreturn);
#endif
#ifdef SYS_rt_sigsuspend
        syscode_case(SYS_rt_sigsuspend);
#endif
#ifdef SYS_rt_sigtimedwait
        syscode_case(SYS_rt_sigtimedwait);
#endif
#ifdef SYS_rt_sigtimedwait_time64
        syscode_case(SYS_rt_sigtimedwait_time64);
#endif
#ifdef SYS_rt_tgsigqueueinfo
        syscode_case(SYS_rt_tgsigqueueinfo);
#endif
#ifdef SYS_rtas
        syscode_case(SYS_rtas);
#endif
#ifdef SYS_s390_guarded_storage
        syscode_case(SYS_s390_guarded_storage);
#endif
#ifdef SYS_s390_pci_mmio_read
        syscode_case(SYS_s390_pci_mmio_read);
#endif
#ifdef SYS_s390_pci_mmio_write
        syscode_case(SYS_s390_pci_mmio_write);
#endif
#ifdef SYS_s390_runtime_instr
        syscode_case(SYS_s390_runtime_instr);
#endif
#ifdef SYS_s390_sthyi
        syscode_case(SYS_s390_sthyi);
#endif
#ifdef SYS_sched_get_affinity
        syscode_case(SYS_sched_get_affinity);
#endif
#ifdef SYS_sched_get_priority_max
        syscode_case(SYS_sched_get_priority_max);
#endif
#ifdef SYS_sched_get_priority_min
        syscode_case(SYS_sched_get_priority_min);
#endif
#ifdef SYS_sched_getaffinity
        syscode_case(SYS_sched_getaffinity);
#endif
#ifdef SYS_sched_getattr
        syscode_case(SYS_sched_getattr);
#endif
#ifdef SYS_sched_getparam
        syscode_case(SYS_sched_getparam);
#endif
#ifdef SYS_sched_getscheduler
        syscode_case(SYS_sched_getscheduler);
#endif
#ifdef SYS_sched_rr_get_interval
        syscode_case(SYS_sched_rr_get_interval);
#endif
#ifdef SYS_sched_rr_get_interval_time64
        syscode_case(SYS_sched_rr_get_interval_time64);
#endif
#ifdef SYS_sched_set_affinity
        syscode_case(SYS_sched_set_affinity);
#endif
#ifdef SYS_sched_setaffinity
        syscode_case(SYS_sched_setaffinity);
#endif
#ifdef SYS_sched_setattr
        syscode_case(SYS_sched_setattr);
#endif
#ifdef SYS_sched_setparam
        syscode_case(SYS_sched_setparam);
#endif
#ifdef SYS_sched_setscheduler
        syscode_case(SYS_sched_setscheduler);
#endif
#ifdef SYS_sched_yield
        syscode_case(SYS_sched_yield);
#endif
#ifdef SYS_seccomp
        syscode_case(SYS_seccomp);
#endif
#ifdef SYS_security
        syscode_case(SYS_security);
#endif
#ifdef SYS_select
        syscode_case(SYS_select);
#endif
#ifdef SYS_semctl
        syscode_case(SYS_semctl);
#endif
#ifdef SYS_semget
        syscode_case(SYS_semget);
#endif
#ifdef SYS_semop
        syscode_case(SYS_semop);
#endif
#ifdef SYS_semtimedop
        syscode_case(SYS_semtimedop);
#endif
#ifdef SYS_semtimedop_time64
        syscode_case(SYS_semtimedop_time64);
#endif
#ifdef SYS_send
        syscode_case(SYS_send);
#endif
#ifdef SYS_sendfile
        syscode_case(SYS_sendfile);
#endif
#ifdef SYS_sendfile64
        syscode_case(SYS_sendfile64);
#endif
#ifdef SYS_sendmmsg
        syscode_case(SYS_sendmmsg);
#endif
#ifdef SYS_sendmsg
        syscode_case(SYS_sendmsg);
#endif
#ifdef SYS_sendto
        syscode_case(SYS_sendto);
#endif
#ifdef SYS_set_mempolicy
        syscode_case(SYS_set_mempolicy);
#endif
#ifdef SYS_set_mempolicy_home_node
        syscode_case(SYS_set_mempolicy_home_node);
#endif
#ifdef SYS_set_robust_list
        syscode_case(SYS_set_robust_list);
#endif
#ifdef SYS_set_thread_area
        syscode_case(SYS_set_thread_area);
#endif
#ifdef SYS_set_tid_address
        syscode_case(SYS_set_tid_address);
#endif
#ifdef SYS_set_tls
        syscode_case(SYS_set_tls);
#endif
#ifdef SYS_setdomainname
        syscode_case(SYS_setdomainname);
#endif
#ifdef SYS_setfsgid
        syscode_case(SYS_setfsgid);
#endif
#ifdef SYS_setfsgid32
        syscode_case(SYS_setfsgid32);
#endif
#ifdef SYS_setfsuid
        syscode_case(SYS_setfsuid);
#endif
#ifdef SYS_setfsuid32
        syscode_case(SYS_setfsuid32);
#endif
#ifdef SYS_setgid
        syscode_case(SYS_setgid);
#endif
#ifdef SYS_setgid32
        syscode_case(SYS_setgid32);
#endif
#ifdef SYS_setgroups
        syscode_case(SYS_setgroups);
#endif
#ifdef SYS_setgroups32
        syscode_case(SYS_setgroups32);
#endif
#ifdef SYS_sethae
        syscode_case(SYS_sethae);
#endif
#ifdef SYS_sethostname
        syscode_case(SYS_sethostname);
#endif
#ifdef SYS_setitimer
        syscode_case(SYS_setitimer);
#endif
#ifdef SYS_setns
        syscode_case(SYS_setns);
#endif
#ifdef SYS_setpgid
        syscode_case(SYS_setpgid);
#endif
#ifdef SYS_setpgrp
        syscode_case(SYS_setpgrp);
#endif
#ifdef SYS_setpriority
        syscode_case(SYS_setpriority);
#endif
#ifdef SYS_setregid
        syscode_case(SYS_setregid);
#endif
#ifdef SYS_setregid32
        syscode_case(SYS_setregid32);
#endif
#ifdef SYS_setresgid
        syscode_case(SYS_setresgid);
#endif
#ifdef SYS_setresgid32
        syscode_case(SYS_setresgid32);
#endif
#ifdef SYS_setresuid
        syscode_case(SYS_setresuid);
#endif
#ifdef SYS_setresuid32
        syscode_case(SYS_setresuid32);
#endif
#ifdef SYS_setreuid
        syscode_case(SYS_setreuid);
#endif
#ifdef SYS_setreuid32
        syscode_case(SYS_setreuid32);
#endif
#ifdef SYS_setrlimit
        syscode_case(SYS_setrlimit);
#endif
#ifdef SYS_setsid
        syscode_case(SYS_setsid);
#endif
#ifdef SYS_setsockopt
        syscode_case(SYS_setsockopt);
#endif
#ifdef SYS_settimeofday
        syscode_case(SYS_settimeofday);
#endif
#ifdef SYS_setuid
        syscode_case(SYS_setuid);
#endif
#ifdef SYS_setuid32
        syscode_case(SYS_setuid32);
#endif
#ifdef SYS_setxattr
        syscode_case(SYS_setxattr);
#endif
#ifdef SYS_sgetmask
        syscode_case(SYS_sgetmask);
#endif
#ifdef SYS_shmat
        syscode_case(SYS_shmat);
#endif
#ifdef SYS_shmctl
        syscode_case(SYS_shmctl);
#endif
#ifdef SYS_shmdt
        syscode_case(SYS_shmdt);
#endif
#ifdef SYS_shmget
        syscode_case(SYS_shmget);
#endif
#ifdef SYS_shutdown
        syscode_case(SYS_shutdown);
#endif
#ifdef SYS_sigaction
        syscode_case(SYS_sigaction);
#endif
#ifdef SYS_sigaltstack
        syscode_case(SYS_sigaltstack);
#endif
#ifdef SYS_signal
        syscode_case(SYS_signal);
#endif
#ifdef SYS_signalfd
        syscode_case(SYS_signalfd);
#endif
#ifdef SYS_signalfd4
        syscode_case(SYS_signalfd4);
#endif
#ifdef SYS_sigpending
        syscode_case(SYS_sigpending);
#endif
#ifdef SYS_sigprocmask
        syscode_case(SYS_sigprocmask);
#endif
#ifdef SYS_sigreturn
        syscode_case(SYS_sigreturn);
#endif
#ifdef SYS_sigsuspend
        syscode_case(SYS_sigsuspend);
#endif
#ifdef SYS_socket
        syscode_case(SYS_socket);
#endif
#ifdef SYS_socketcall
        syscode_case(SYS_socketcall);
#endif
#ifdef SYS_socketpair
        syscode_case(SYS_socketpair);
#endif
#ifdef SYS_splice
        syscode_case(SYS_splice);
#endif
#ifdef SYS_spu_create
        syscode_case(SYS_spu_create);
#endif
#ifdef SYS_spu_run
        syscode_case(SYS_spu_run);
#endif
#ifdef SYS_ssetmask
        syscode_case(SYS_ssetmask);
#endif
#ifdef SYS_stat
        syscode_case(SYS_stat);
#endif
#ifdef SYS_stat64
        syscode_case(SYS_stat64);
#endif
#ifdef SYS_statfs
        syscode_case(SYS_statfs);
#endif
#ifdef SYS_statfs64
        syscode_case(SYS_statfs64);
#endif
#ifdef SYS_statx
        syscode_case(SYS_statx);
#endif
#ifdef SYS_stime
        syscode_case(SYS_stime);
#endif
#ifdef SYS_stty
        syscode_case(SYS_stty);
#endif
#ifdef SYS_subpage_prot
        syscode_case(SYS_subpage_prot);
#endif
#ifdef SYS_swapcontext
        syscode_case(SYS_swapcontext);
#endif
#ifdef SYS_swapoff
        syscode_case(SYS_swapoff);
#endif
#ifdef SYS_swapon
        syscode_case(SYS_swapon);
#endif
#ifdef SYS_switch_endian
        syscode_case(SYS_switch_endian);
#endif
#ifdef SYS_symlink
        syscode_case(SYS_symlink);
#endif
#ifdef SYS_symlinkat
        syscode_case(SYS_symlinkat);
#endif
#ifdef SYS_sync
        syscode_case(SYS_sync);
#endif
#ifdef SYS_sync_file_range
        syscode_case(SYS_sync_file_range);
#endif
#ifdef SYS_sync_file_range2
        syscode_case(SYS_sync_file_range2);
#endif
#ifdef SYS_syncfs
        syscode_case(SYS_syncfs);
#endif
#ifdef SYS_sys_debug_setcontext
        syscode_case(SYS_sys_debug_setcontext);
#endif
#ifdef SYS_sys_epoll_create
        syscode_case(SYS_sys_epoll_create);
#endif
#ifdef SYS_sys_epoll_ctl
        syscode_case(SYS_sys_epoll_ctl);
#endif
#ifdef SYS_sys_epoll_wait
        syscode_case(SYS_sys_epoll_wait);
#endif
#ifdef SYS_syscall
        syscode_case(SYS_syscall);
#endif
#ifdef SYS_sysfs
        syscode_case(SYS_sysfs);
#endif
#ifdef SYS_sysinfo
        syscode_case(SYS_sysinfo);
#endif
#ifdef SYS_syslog
        syscode_case(SYS_syslog);
#endif
#ifdef SYS_sysmips
        syscode_case(SYS_sysmips);
#endif
#ifdef SYS_tee
        syscode_case(SYS_tee);
#endif
#ifdef SYS_tgkill
        syscode_case(SYS_tgkill);
#endif
#ifdef SYS_time
        syscode_case(SYS_time);
#endif
#ifdef SYS_timer_create
        syscode_case(SYS_timer_create);
#endif
#ifdef SYS_timer_delete
        syscode_case(SYS_timer_delete);
#endif
#ifdef SYS_timer_getoverrun
        syscode_case(SYS_timer_getoverrun);
#endif
#ifdef SYS_timer_gettime
        syscode_case(SYS_timer_gettime);
#endif
#ifdef SYS_timer_gettime64
        syscode_case(SYS_timer_gettime64);
#endif
#ifdef SYS_timer_settime
        syscode_case(SYS_timer_settime);
#endif
#ifdef SYS_timer_settime64
        syscode_case(SYS_timer_settime64);
#endif
#ifdef SYS_timerfd
        syscode_case(SYS_timerfd);
#endif
#ifdef SYS_timerfd_create
        syscode_case(SYS_timerfd_create);
#endif
#ifdef SYS_timerfd_gettime
        syscode_case(SYS_timerfd_gettime);
#endif
#ifdef SYS_timerfd_gettime64
        syscode_case(SYS_timerfd_gettime64);
#endif
#ifdef SYS_timerfd_settime
        syscode_case(SYS_timerfd_settime);
#endif
#ifdef SYS_timerfd_settime64
        syscode_case(SYS_timerfd_settime64);
#endif
#ifdef SYS_times
        syscode_case(SYS_times);
#endif
#ifdef SYS_tkill
        syscode_case(SYS_tkill);
#endif
#ifdef SYS_truncate
        syscode_case(SYS_truncate);
#endif
#ifdef SYS_truncate64
        syscode_case(SYS_truncate64);
#endif
#ifdef SYS_tuxcall
        syscode_case(SYS_tuxcall);
#endif
#ifdef SYS_udftrap
        syscode_case(SYS_udftrap);
#endif
#ifdef SYS_ugetrlimit
        syscode_case(SYS_ugetrlimit);
#endif
#ifdef SYS_ulimit
        syscode_case(SYS_ulimit);
#endif
#ifdef SYS_umask
        syscode_case(SYS_umask);
#endif
#ifdef SYS_umount
        syscode_case(SYS_umount);
#endif
#ifdef SYS_umount2
        syscode_case(SYS_umount2);
#endif
#ifdef SYS_uname
        syscode_case(SYS_uname);
#endif
#ifdef SYS_unlink
        syscode_case(SYS_unlink);
#endif
#ifdef SYS_unlinkat
        syscode_case(SYS_unlinkat);
#endif
#ifdef SYS_unshare
        syscode_case(SYS_unshare);
#endif
#ifdef SYS_uselib
        syscode_case(SYS_uselib);
#endif
#ifdef SYS_userfaultfd
        syscode_case(SYS_userfaultfd);
#endif
#ifdef SYS_usr26
        syscode_case(SYS_usr26);
#endif
#ifdef SYS_usr32
        syscode_case(SYS_usr32);
#endif
#ifdef SYS_ustat
        syscode_case(SYS_ustat);
#endif
#ifdef SYS_utime
        syscode_case(SYS_utime);
#endif
#ifdef SYS_utimensat
        syscode_case(SYS_utimensat);
#endif
#ifdef SYS_utimensat_time64
        syscode_case(SYS_utimensat_time64);
#endif
#ifdef SYS_utimes
        syscode_case(SYS_utimes);
#endif
#ifdef SYS_utrap_install
        syscode_case(SYS_utrap_install);
#endif
#ifdef SYS_vfork
        syscode_case(SYS_vfork);
#endif
#ifdef SYS_vhangup
        syscode_case(SYS_vhangup);
#endif
#ifdef SYS_vm86
        syscode_case(SYS_vm86);
#endif
#ifdef SYS_vm86old
        syscode_case(SYS_vm86old);
#endif
#ifdef SYS_vmsplice
        syscode_case(SYS_vmsplice);
#endif
#ifdef SYS_vserver
        syscode_case(SYS_vserver);
#endif
#ifdef SYS_wait4
        syscode_case(SYS_wait4);
#endif
#ifdef SYS_waitid
        syscode_case(SYS_waitid);
#endif
#ifdef SYS_waitpid
        syscode_case(SYS_waitpid);
#endif
#ifdef SYS_write
        syscode_case(SYS_write);
#endif
#ifdef SYS_writev
        syscode_case(SYS_writev);
#endif
        default:
            return nullptr;
    }
}

static inline auto syscall_name(const auto nbr) -> std::optional<const char*> {
    const auto str = syscall_name_(nbr);
    if (str) {
        return str + 4;
    } else {
        return {};
    }
}
