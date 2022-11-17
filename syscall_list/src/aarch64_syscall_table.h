#pragma once

#include <string>
#include <optional>

#define AARCH64__NR_io_setup 0
#define AARCH64__NR_io_destroy 1
#define AARCH64__NR_io_submit 2
#define AARCH64__NR_io_cancel 3
#define AARCH64__NR_io_getevents 4
#define AARCH64__NR_setxattr 5
#define AARCH64__NR_lsetxattr 6
#define AARCH64__NR_fsetxattr 7
#define AARCH64__NR_getxattr 8
#define AARCH64__NR_lgetxattr 9
#define AARCH64__NR_fgetxattr 10
#define AARCH64__NR_listxattr 11
#define AARCH64__NR_llistxattr 12
#define AARCH64__NR_flistxattr 13
#define AARCH64__NR_removexattr 14
#define AARCH64__NR_lremovexattr 15
#define AARCH64__NR_fremovexattr 16
#define AARCH64__NR_getcwd 17
#define AARCH64__NR_lookup_dcookie 18
#define AARCH64__NR_eventfd2 19
#define AARCH64__NR_epoll_create1 20
#define AARCH64__NR_epoll_ctl 21
#define AARCH64__NR_epoll_pwait 22
#define AARCH64__NR_dup 23
#define AARCH64__NR_dup3 24
#define AARCH64__NR_fcntl 25
#define AARCH64__NR_inotify_init1 26
#define AARCH64__NR_inotify_add_watch 27
#define AARCH64__NR_inotify_rm_watch 28
#define AARCH64__NR_ioctl 29
#define AARCH64__NR_ioprio_set 30
#define AARCH64__NR_ioprio_get 31
#define AARCH64__NR_flock 32
#define AARCH64__NR_mknodat 33
#define AARCH64__NR_mkdirat 34
#define AARCH64__NR_unlinkat 35
#define AARCH64__NR_symlinkat 36
#define AARCH64__NR_linkat 37
#define AARCH64__NR_renameat 38
#define AARCH64__NR_umount2 39
#define AARCH64__NR_mount 40
#define AARCH64__NR_pivot_root 41
#define AARCH64__NR_nfsservctl 42
#define AARCH64__NR_statfs 43
#define AARCH64__NR_fstatfs 44
#define AARCH64__NR_truncate 45
#define AARCH64__NR_ftruncate 46
#define AARCH64__NR_fallocate 47
#define AARCH64__NR_faccessat 48
#define AARCH64__NR_chdir 49
#define AARCH64__NR_fchdir 50
#define AARCH64__NR_chroot 51
#define AARCH64__NR_fchmod 52
#define AARCH64__NR_fchmodat 53
#define AARCH64__NR_fchownat 54
#define AARCH64__NR_fchown 55
#define AARCH64__NR_openat 56
#define AARCH64__NR_close 57
#define AARCH64__NR_vhangup 58
#define AARCH64__NR_pipe2 59
#define AARCH64__NR_quotactl 60
#define AARCH64__NR_getdents64 61
#define AARCH64__NR_lseek 62
#define AARCH64__NR_read 63
#define AARCH64__NR_write 64
#define AARCH64__NR_readv 65
#define AARCH64__NR_writev 66
#define AARCH64__NR_pread64 67
#define AARCH64__NR_pwrite64 68
#define AARCH64__NR_preadv 69
#define AARCH64__NR_pwritev 70
#define AARCH64__NR_sendfile 71
#define AARCH64__NR_pselect6 72
#define AARCH64__NR_ppoll 73
#define AARCH64__NR_signalfd4 74
#define AARCH64__NR_vmsplice 75
#define AARCH64__NR_splice 76
#define AARCH64__NR_tee 77
#define AARCH64__NR_readlinkat 78
#define AARCH64__NR_fstatat 79
#define AARCH64__NR_fstat 80
#define AARCH64__NR_sync 81
#define AARCH64__NR_fsync 82
#define AARCH64__NR_fdatasync 83
#define AARCH64__NR_sync_file_range 84
#define AARCH64__NR_timerfd_create 85
#define AARCH64__NR_timerfd_settime 86
#define AARCH64__NR_timerfd_gettime 87
#define AARCH64__NR_utimensat 88
#define AARCH64__NR_acct 89
#define AARCH64__NR_capget 90
#define AARCH64__NR_capset 91
#define AARCH64__NR_personality 92
#define AARCH64__NR_exit 93
#define AARCH64__NR_exit_group 94
#define AARCH64__NR_waitid 95
#define AARCH64__NR_set_tid_address 96
#define AARCH64__NR_unshare 97
#define AARCH64__NR_futex 98
#define AARCH64__NR_set_robust_list 99
#define AARCH64__NR_get_robust_list 100
#define AARCH64__NR_nanosleep 101
#define AARCH64__NR_getitimer 102
#define AARCH64__NR_setitimer 103
#define AARCH64__NR_kexec_load 104
#define AARCH64__NR_init_module 105
#define AARCH64__NR_delete_module 106
#define AARCH64__NR_timer_create 107
#define AARCH64__NR_timer_gettime 108
#define AARCH64__NR_timer_getoverrun 109
#define AARCH64__NR_timer_settime 110
#define AARCH64__NR_timer_delete 111
#define AARCH64__NR_clock_settime 112
#define AARCH64__NR_clock_gettime 113
#define AARCH64__NR_clock_getres 114
#define AARCH64__NR_clock_nanosleep 115
#define AARCH64__NR_syslog 116
#define AARCH64__NR_ptrace 117
#define AARCH64__NR_sched_setparam 118
#define AARCH64__NR_sched_setscheduler 119
#define AARCH64__NR_sched_getscheduler 120
#define AARCH64__NR_sched_getparam 121
#define AARCH64__NR_sched_setaffinity 122
#define AARCH64__NR_sched_getaffinity 123
#define AARCH64__NR_sched_yield 124
#define AARCH64__NR_sched_get_priority_max 125
#define AARCH64__NR_sched_get_priority_min 126
#define AARCH64__NR_sched_rr_get_interval 127
#define AARCH64__NR_restart_syscall 128
#define AARCH64__NR_kill 129
#define AARCH64__NR_tkill 130
#define AARCH64__NR_tgkill 131
#define AARCH64__NR_sigaltstack 132
#define AARCH64__NR_rt_sigsuspend 133
#define AARCH64__NR_rt_sigaction 134
#define AARCH64__NR_rt_sigprocmask 135
#define AARCH64__NR_rt_sigpending 136
#define AARCH64__NR_rt_sigtimedwait 137
#define AARCH64__NR_rt_sigqueueinfo 138
#define AARCH64__NR_rt_sigreturn 139
#define AARCH64__NR_setpriority 140
#define AARCH64__NR_getpriority 141
#define AARCH64__NR_reboot 142
#define AARCH64__NR_setregid 143
#define AARCH64__NR_setgid 144
#define AARCH64__NR_setreuid 145
#define AARCH64__NR_setuid 146
#define AARCH64__NR_setresuid 147
#define AARCH64__NR_getresuid 148
#define AARCH64__NR_setresgid 149
#define AARCH64__NR_getresgid 150
#define AARCH64__NR_setfsuid 151
#define AARCH64__NR_setfsgid 152
#define AARCH64__NR_times 153
#define AARCH64__NR_setpgid 154
#define AARCH64__NR_getpgid 155
#define AARCH64__NR_getsid 156
#define AARCH64__NR_setsid 157
#define AARCH64__NR_getgroups 158
#define AARCH64__NR_setgroups 159
#define AARCH64__NR_uname 160
#define AARCH64__NR_sethostname 161
#define AARCH64__NR_setdomainname 162
#define AARCH64__NR_getrlimit 163
#define AARCH64__NR_setrlimit 164
#define AARCH64__NR_getrusage 165
#define AARCH64__NR_umask 166
#define AARCH64__NR_prctl 167
#define AARCH64__NR_getcpu 168
#define AARCH64__NR_gettimeofday 169
#define AARCH64__NR_settimeofday 170
#define AARCH64__NR_adjtimex 171
#define AARCH64__NR_getpid 172
#define AARCH64__NR_getppid 173
#define AARCH64__NR_getuid 174
#define AARCH64__NR_geteuid 175
#define AARCH64__NR_getgid 176
#define AARCH64__NR_getegid 177
#define AARCH64__NR_gettid 178
#define AARCH64__NR_sysinfo 179
#define AARCH64__NR_mq_open 180
#define AARCH64__NR_mq_unlink 181
#define AARCH64__NR_mq_timedsend 182
#define AARCH64__NR_mq_timedreceive 183
#define AARCH64__NR_mq_notify 184
#define AARCH64__NR_mq_getsetattr 185
#define AARCH64__NR_msgget 186
#define AARCH64__NR_msgctl 187
#define AARCH64__NR_msgrcv 188
#define AARCH64__NR_msgsnd 189
#define AARCH64__NR_semget 190
#define AARCH64__NR_semctl 191
#define AARCH64__NR_semtimedop 192
#define AARCH64__NR_semop 193
#define AARCH64__NR_shmget 194
#define AARCH64__NR_shmctl 195
#define AARCH64__NR_shmat 196
#define AARCH64__NR_shmdt 197
#define AARCH64__NR_socket 198
#define AARCH64__NR_socketpair 199
#define AARCH64__NR_bind 200
#define AARCH64__NR_listen 201
#define AARCH64__NR_accept 202
#define AARCH64__NR_connect 203
#define AARCH64__NR_getsockname 204
#define AARCH64__NR_getpeername 205
#define AARCH64__NR_sendto 206
#define AARCH64__NR_recvfrom 207
#define AARCH64__NR_setsockopt 208
#define AARCH64__NR_getsockopt 209
#define AARCH64__NR_shutdown 210
#define AARCH64__NR_sendmsg 211
#define AARCH64__NR_recvmsg 212
#define AARCH64__NR_readahead 213
#define AARCH64__NR_brk 214
#define AARCH64__NR_munmap 215
#define AARCH64__NR_mremap 216
#define AARCH64__NR_add_key 217
#define AARCH64__NR_request_key 218
#define AARCH64__NR_keyctl 219
#define AARCH64__NR_clone 220
#define AARCH64__NR_execve 221
#define AARCH64__NR_mmap 222
#define AARCH64__NR_fadvise64 223
#define AARCH64__NR_swapon 224
#define AARCH64__NR_swapoff 225
#define AARCH64__NR_mprotect 226
#define AARCH64__NR_msync 227
#define AARCH64__NR_mlock 228
#define AARCH64__NR_munlock 229
#define AARCH64__NR_mlockall 230
#define AARCH64__NR_munlockall 231
#define AARCH64__NR_mincore 232
#define AARCH64__NR_madvise 233
#define AARCH64__NR_remap_file_pages 234
#define AARCH64__NR_mbind 235
#define AARCH64__NR_get_mempolicy 236
#define AARCH64__NR_set_mempolicy 237
#define AARCH64__NR_migrate_pages 238
#define AARCH64__NR_move_pages 239
#define AARCH64__NR_rt_tgsigqueueinfo 240
#define AARCH64__NR_perf_event_open 241
#define AARCH64__NR_accept4 242
#define AARCH64__NR_recvmmsg 243
#define AARCH64__NR_arch_specific_syscall 244
#define AARCH64__NR_wait4 260
#define AARCH64__NR_prlimit64 261
#define AARCH64__NR_fanotify_init 262
#define AARCH64__NR_fanotify_mark 263
#define AARCH64__NR_name_to_handle_at         264
#define AARCH64__NR_open_by_handle_at         265
#define AARCH64__NR_clock_adjtime 266
#define AARCH64__NR_syncfs 267
#define AARCH64__NR_setns 268
#define AARCH64__NR_sendmmsg 269
#define AARCH64__NR_process_vm_readv 270
#define AARCH64__NR_process_vm_writev 271
#define AARCH64__NR_kcmp 272
#define AARCH64__NR_finit_module 273
#define AARCH64__NR_sched_setattr 274
#define AARCH64__NR_sched_getattr 275
#define AARCH64__NR_renameat2 276
#define AARCH64__NR_seccomp 277
#define AARCH64__NR_getrandom 278
#define AARCH64__NR_memfd_create 279
#define AARCH64__NR_bpf 280
#define AARCH64__NR_execveat 281
#define AARCH64__NR_userfaultfd 282
#define AARCH64__NR_membarrier 283
#define AARCH64__NR_mlock2 284
#define AARCH64__NR_copy_file_range 285
#define AARCH64__NR_preadv2 286
#define AARCH64__NR_pwritev2 287
#define AARCH64__NR_pkey_mprotect 288
#define AARCH64__NR_pkey_alloc 289
#define AARCH64__NR_pkey_free 290
#define AARCH64__NR_statx 291
#define AARCH64__NR_io_pgetevents 292
#define AARCH64__NR_rseq 293
#define AARCH64__NR_kexec_file_load 294
#define AARCH64__NR_clock_gettime64 403
#define AARCH64__NR_clock_settime64 404
#define AARCH64__NR_clock_adjtime64 405
#define AARCH64__NR_clock_getres_time64 406
#define AARCH64__NR_clock_nanosleep_time64 407
#define AARCH64__NR_timer_gettime64 408
#define AARCH64__NR_timer_settime64 409
#define AARCH64__NR_timerfd_gettime64 410
#define AARCH64__NR_timerfd_settime64 411
#define AARCH64__NR_utimensat_time64 412
#define AARCH64__NR_pselect6_time64 413
#define AARCH64__NR_ppoll_time64 414
#define AARCH64__NR_io_pgetevents_time64 416
#define AARCH64__NR_recvmmsg_time64 417
#define AARCH64__NR_mq_timedsend_time64 418
#define AARCH64__NR_mq_timedreceive_time64 419
#define AARCH64__NR_semtimedop_time64 420
#define AARCH64__NR_rt_sigtimedwait_time64 421
#define AARCH64__NR_futex_time64 422
#define AARCH64__NR_sched_rr_get_interval_time64 423
#define AARCH64__NR_pidfd_send_signal 424
#define AARCH64__NR_io_uring_setup 425
#define AARCH64__NR_io_uring_enter 426
#define AARCH64__NR_io_uring_register 427
#define AARCH64__NR_open_tree 428
#define AARCH64__NR_move_mount 429
#define AARCH64__NR_fsopen 430
#define AARCH64__NR_fsconfig 431
#define AARCH64__NR_fsmount 432
#define AARCH64__NR_fspick 433
#define AARCH64__NR_pidfd_open 434
#define AARCH64__NR_clone3 435
#define AARCH64__NR_close_range 436
#define AARCH64__NR_openat2 437
#define AARCH64__NR_pidfd_getfd 438
#define AARCH64__NR_faccessat2 439

#define syscode_case(x) case x: return #x

static inline const char* aarch64_syscall_name(const auto nbr) {
    const auto ret = [&]() -> const char* {
        switch(nbr) {
            syscode_case(AARCH64__NR_io_setup);
            syscode_case(AARCH64__NR_io_destroy);
            syscode_case(AARCH64__NR_io_submit);
            syscode_case(AARCH64__NR_io_cancel);
            syscode_case(AARCH64__NR_io_getevents);
            syscode_case(AARCH64__NR_setxattr);
            syscode_case(AARCH64__NR_lsetxattr);
            syscode_case(AARCH64__NR_fsetxattr);
            syscode_case(AARCH64__NR_getxattr);
            syscode_case(AARCH64__NR_lgetxattr);
            syscode_case(AARCH64__NR_fgetxattr);
            syscode_case(AARCH64__NR_listxattr);
            syscode_case(AARCH64__NR_llistxattr);
            syscode_case(AARCH64__NR_flistxattr);
            syscode_case(AARCH64__NR_removexattr);
            syscode_case(AARCH64__NR_lremovexattr);
            syscode_case(AARCH64__NR_fremovexattr);
            syscode_case(AARCH64__NR_getcwd);
            syscode_case(AARCH64__NR_lookup_dcookie);
            syscode_case(AARCH64__NR_eventfd2);
            syscode_case(AARCH64__NR_epoll_create1);
            syscode_case(AARCH64__NR_epoll_ctl);
            syscode_case(AARCH64__NR_epoll_pwait);
            syscode_case(AARCH64__NR_dup);
            syscode_case(AARCH64__NR_dup3);
            syscode_case(AARCH64__NR_fcntl);
            syscode_case(AARCH64__NR_inotify_init1);
            syscode_case(AARCH64__NR_inotify_add_watch);
            syscode_case(AARCH64__NR_inotify_rm_watch);
            syscode_case(AARCH64__NR_ioctl);
            syscode_case(AARCH64__NR_ioprio_set);
            syscode_case(AARCH64__NR_ioprio_get);
            syscode_case(AARCH64__NR_flock);
            syscode_case(AARCH64__NR_mknodat);
            syscode_case(AARCH64__NR_mkdirat);
            syscode_case(AARCH64__NR_unlinkat);
            syscode_case(AARCH64__NR_symlinkat);
            syscode_case(AARCH64__NR_linkat);
            syscode_case(AARCH64__NR_renameat);
            syscode_case(AARCH64__NR_umount2);
            syscode_case(AARCH64__NR_mount);
            syscode_case(AARCH64__NR_pivot_root);
            syscode_case(AARCH64__NR_nfsservctl);
            syscode_case(AARCH64__NR_statfs);
            syscode_case(AARCH64__NR_fstatfs);
            syscode_case(AARCH64__NR_truncate);
            syscode_case(AARCH64__NR_ftruncate);
            syscode_case(AARCH64__NR_fallocate);
            syscode_case(AARCH64__NR_faccessat);
            syscode_case(AARCH64__NR_chdir);
            syscode_case(AARCH64__NR_fchdir);
            syscode_case(AARCH64__NR_chroot);
            syscode_case(AARCH64__NR_fchmod);
            syscode_case(AARCH64__NR_fchmodat);
            syscode_case(AARCH64__NR_fchownat);
            syscode_case(AARCH64__NR_fchown);
            syscode_case(AARCH64__NR_openat);
            syscode_case(AARCH64__NR_close);
            syscode_case(AARCH64__NR_vhangup);
            syscode_case(AARCH64__NR_pipe2);
            syscode_case(AARCH64__NR_quotactl);
            syscode_case(AARCH64__NR_getdents64);
            syscode_case(AARCH64__NR_lseek);
            syscode_case(AARCH64__NR_read);
            syscode_case(AARCH64__NR_write);
            syscode_case(AARCH64__NR_readv);
            syscode_case(AARCH64__NR_writev);
            syscode_case(AARCH64__NR_pread64);
            syscode_case(AARCH64__NR_pwrite64);
            syscode_case(AARCH64__NR_preadv);
            syscode_case(AARCH64__NR_pwritev);
            syscode_case(AARCH64__NR_sendfile);
            syscode_case(AARCH64__NR_pselect6);
            syscode_case(AARCH64__NR_ppoll);
            syscode_case(AARCH64__NR_signalfd4);
            syscode_case(AARCH64__NR_vmsplice);
            syscode_case(AARCH64__NR_splice);
            syscode_case(AARCH64__NR_tee);
            syscode_case(AARCH64__NR_readlinkat);
            syscode_case(AARCH64__NR_fstatat);
            syscode_case(AARCH64__NR_fstat);
            syscode_case(AARCH64__NR_sync);
            syscode_case(AARCH64__NR_fsync);
            syscode_case(AARCH64__NR_fdatasync);
            syscode_case(AARCH64__NR_sync_file_range);
            syscode_case(AARCH64__NR_timerfd_create);
            syscode_case(AARCH64__NR_timerfd_settime);
            syscode_case(AARCH64__NR_timerfd_gettime);
            syscode_case(AARCH64__NR_utimensat);
            syscode_case(AARCH64__NR_acct);
            syscode_case(AARCH64__NR_capget);
            syscode_case(AARCH64__NR_capset);
            syscode_case(AARCH64__NR_personality);
            syscode_case(AARCH64__NR_exit);
            syscode_case(AARCH64__NR_exit_group);
            syscode_case(AARCH64__NR_waitid);
            syscode_case(AARCH64__NR_set_tid_address);
            syscode_case(AARCH64__NR_unshare);
            syscode_case(AARCH64__NR_futex);
            syscode_case(AARCH64__NR_set_robust_list);
            syscode_case(AARCH64__NR_get_robust_list);
            syscode_case(AARCH64__NR_nanosleep);
            syscode_case(AARCH64__NR_getitimer);
            syscode_case(AARCH64__NR_setitimer);
            syscode_case(AARCH64__NR_kexec_load);
            syscode_case(AARCH64__NR_init_module);
            syscode_case(AARCH64__NR_delete_module);
            syscode_case(AARCH64__NR_timer_create);
            syscode_case(AARCH64__NR_timer_gettime);
            syscode_case(AARCH64__NR_timer_getoverrun);
            syscode_case(AARCH64__NR_timer_settime);
            syscode_case(AARCH64__NR_timer_delete);
            syscode_case(AARCH64__NR_clock_settime);
            syscode_case(AARCH64__NR_clock_gettime);
            syscode_case(AARCH64__NR_clock_getres);
            syscode_case(AARCH64__NR_clock_nanosleep);
            syscode_case(AARCH64__NR_syslog);
            syscode_case(AARCH64__NR_ptrace);
            syscode_case(AARCH64__NR_sched_setparam);
            syscode_case(AARCH64__NR_sched_setscheduler);
            syscode_case(AARCH64__NR_sched_getscheduler);
            syscode_case(AARCH64__NR_sched_getparam);
            syscode_case(AARCH64__NR_sched_setaffinity);
            syscode_case(AARCH64__NR_sched_getaffinity);
            syscode_case(AARCH64__NR_sched_yield);
            syscode_case(AARCH64__NR_sched_get_priority_max);
            syscode_case(AARCH64__NR_sched_get_priority_min);
            syscode_case(AARCH64__NR_sched_rr_get_interval);
            syscode_case(AARCH64__NR_restart_syscall);
            syscode_case(AARCH64__NR_kill);
            syscode_case(AARCH64__NR_tkill);
            syscode_case(AARCH64__NR_tgkill);
            syscode_case(AARCH64__NR_sigaltstack);
            syscode_case(AARCH64__NR_rt_sigsuspend);
            syscode_case(AARCH64__NR_rt_sigaction);
            syscode_case(AARCH64__NR_rt_sigprocmask);
            syscode_case(AARCH64__NR_rt_sigpending);
            syscode_case(AARCH64__NR_rt_sigtimedwait);
            syscode_case(AARCH64__NR_rt_sigqueueinfo);
            syscode_case(AARCH64__NR_rt_sigreturn);
            syscode_case(AARCH64__NR_setpriority);
            syscode_case(AARCH64__NR_getpriority);
            syscode_case(AARCH64__NR_reboot);
            syscode_case(AARCH64__NR_setregid);
            syscode_case(AARCH64__NR_setgid);
            syscode_case(AARCH64__NR_setreuid);
            syscode_case(AARCH64__NR_setuid);
            syscode_case(AARCH64__NR_setresuid);
            syscode_case(AARCH64__NR_getresuid);
            syscode_case(AARCH64__NR_setresgid);
            syscode_case(AARCH64__NR_getresgid);
            syscode_case(AARCH64__NR_setfsuid);
            syscode_case(AARCH64__NR_setfsgid);
            syscode_case(AARCH64__NR_times);
            syscode_case(AARCH64__NR_setpgid);
            syscode_case(AARCH64__NR_getpgid);
            syscode_case(AARCH64__NR_getsid);
            syscode_case(AARCH64__NR_setsid);
            syscode_case(AARCH64__NR_getgroups);
            syscode_case(AARCH64__NR_setgroups);
            syscode_case(AARCH64__NR_uname);
            syscode_case(AARCH64__NR_sethostname);
            syscode_case(AARCH64__NR_setdomainname);
            syscode_case(AARCH64__NR_getrlimit);
            syscode_case(AARCH64__NR_setrlimit);
            syscode_case(AARCH64__NR_getrusage);
            syscode_case(AARCH64__NR_umask);
            syscode_case(AARCH64__NR_prctl);
            syscode_case(AARCH64__NR_getcpu);
            syscode_case(AARCH64__NR_gettimeofday);
            syscode_case(AARCH64__NR_settimeofday);
            syscode_case(AARCH64__NR_adjtimex);
            syscode_case(AARCH64__NR_getpid);
            syscode_case(AARCH64__NR_getppid);
            syscode_case(AARCH64__NR_getuid);
            syscode_case(AARCH64__NR_geteuid);
            syscode_case(AARCH64__NR_getgid);
            syscode_case(AARCH64__NR_getegid);
            syscode_case(AARCH64__NR_gettid);
            syscode_case(AARCH64__NR_sysinfo);
            syscode_case(AARCH64__NR_mq_open);
            syscode_case(AARCH64__NR_mq_unlink);
            syscode_case(AARCH64__NR_mq_timedsend);
            syscode_case(AARCH64__NR_mq_timedreceive);
            syscode_case(AARCH64__NR_mq_notify);
            syscode_case(AARCH64__NR_mq_getsetattr);
            syscode_case(AARCH64__NR_msgget);
            syscode_case(AARCH64__NR_msgctl);
            syscode_case(AARCH64__NR_msgrcv);
            syscode_case(AARCH64__NR_msgsnd);
            syscode_case(AARCH64__NR_semget);
            syscode_case(AARCH64__NR_semctl);
            syscode_case(AARCH64__NR_semtimedop);
            syscode_case(AARCH64__NR_semop);
            syscode_case(AARCH64__NR_shmget);
            syscode_case(AARCH64__NR_shmctl);
            syscode_case(AARCH64__NR_shmat);
            syscode_case(AARCH64__NR_shmdt);
            syscode_case(AARCH64__NR_socket);
            syscode_case(AARCH64__NR_socketpair);
            syscode_case(AARCH64__NR_bind);
            syscode_case(AARCH64__NR_listen);
            syscode_case(AARCH64__NR_accept);
            syscode_case(AARCH64__NR_connect);
            syscode_case(AARCH64__NR_getsockname);
            syscode_case(AARCH64__NR_getpeername);
            syscode_case(AARCH64__NR_sendto);
            syscode_case(AARCH64__NR_recvfrom);
            syscode_case(AARCH64__NR_setsockopt);
            syscode_case(AARCH64__NR_getsockopt);
            syscode_case(AARCH64__NR_shutdown);
            syscode_case(AARCH64__NR_sendmsg);
            syscode_case(AARCH64__NR_recvmsg);
            syscode_case(AARCH64__NR_readahead);
            syscode_case(AARCH64__NR_brk);
            syscode_case(AARCH64__NR_munmap);
            syscode_case(AARCH64__NR_mremap);
            syscode_case(AARCH64__NR_add_key);
            syscode_case(AARCH64__NR_request_key);
            syscode_case(AARCH64__NR_keyctl);
            syscode_case(AARCH64__NR_clone);
            syscode_case(AARCH64__NR_execve);
            syscode_case(AARCH64__NR_mmap);
            syscode_case(AARCH64__NR_fadvise64);
            syscode_case(AARCH64__NR_swapon);
            syscode_case(AARCH64__NR_swapoff);
            syscode_case(AARCH64__NR_mprotect);
            syscode_case(AARCH64__NR_msync);
            syscode_case(AARCH64__NR_mlock);
            syscode_case(AARCH64__NR_munlock);
            syscode_case(AARCH64__NR_mlockall);
            syscode_case(AARCH64__NR_munlockall);
            syscode_case(AARCH64__NR_mincore);
            syscode_case(AARCH64__NR_madvise);
            syscode_case(AARCH64__NR_remap_file_pages);
            syscode_case(AARCH64__NR_mbind);
            syscode_case(AARCH64__NR_get_mempolicy);
            syscode_case(AARCH64__NR_set_mempolicy);
            syscode_case(AARCH64__NR_migrate_pages);
            syscode_case(AARCH64__NR_move_pages);
            syscode_case(AARCH64__NR_rt_tgsigqueueinfo);
            syscode_case(AARCH64__NR_perf_event_open);
            syscode_case(AARCH64__NR_accept4);
            syscode_case(AARCH64__NR_recvmmsg);
            syscode_case(AARCH64__NR_arch_specific_syscall);
            syscode_case(AARCH64__NR_wait4);
            syscode_case(AARCH64__NR_prlimit64);
            syscode_case(AARCH64__NR_fanotify_init);
            syscode_case(AARCH64__NR_fanotify_mark);
            syscode_case(AARCH64__NR_name_to_handle_at);
            syscode_case(AARCH64__NR_open_by_handle_at);
            syscode_case(AARCH64__NR_clock_adjtime);
            syscode_case(AARCH64__NR_syncfs);
            syscode_case(AARCH64__NR_setns);
            syscode_case(AARCH64__NR_sendmmsg);
            syscode_case(AARCH64__NR_process_vm_readv);
            syscode_case(AARCH64__NR_process_vm_writev);
            syscode_case(AARCH64__NR_kcmp);
            syscode_case(AARCH64__NR_finit_module);
            syscode_case(AARCH64__NR_sched_setattr);
            syscode_case(AARCH64__NR_sched_getattr);
            syscode_case(AARCH64__NR_renameat2);
            syscode_case(AARCH64__NR_seccomp);
            syscode_case(AARCH64__NR_getrandom);
            syscode_case(AARCH64__NR_memfd_create);
            syscode_case(AARCH64__NR_bpf);
            syscode_case(AARCH64__NR_execveat);
            syscode_case(AARCH64__NR_userfaultfd);
            syscode_case(AARCH64__NR_membarrier);
            syscode_case(AARCH64__NR_mlock2);
            syscode_case(AARCH64__NR_copy_file_range);
            syscode_case(AARCH64__NR_preadv2);
            syscode_case(AARCH64__NR_pwritev2);
            syscode_case(AARCH64__NR_pkey_mprotect);
            syscode_case(AARCH64__NR_pkey_alloc);
            syscode_case(AARCH64__NR_pkey_free);
            syscode_case(AARCH64__NR_statx);
            syscode_case(AARCH64__NR_io_pgetevents);
            syscode_case(AARCH64__NR_rseq);
            syscode_case(AARCH64__NR_kexec_file_load);
            syscode_case(AARCH64__NR_clock_gettime64);
            syscode_case(AARCH64__NR_clock_settime64);
            syscode_case(AARCH64__NR_clock_adjtime64);
            syscode_case(AARCH64__NR_clock_getres_time64);
            syscode_case(AARCH64__NR_clock_nanosleep_time64);
            syscode_case(AARCH64__NR_timer_gettime64);
            syscode_case(AARCH64__NR_timer_settime64);
            syscode_case(AARCH64__NR_timerfd_gettime64);
            syscode_case(AARCH64__NR_timerfd_settime64);
            syscode_case(AARCH64__NR_utimensat_time64);
            syscode_case(AARCH64__NR_pselect6_time64);
            syscode_case(AARCH64__NR_ppoll_time64);
            syscode_case(AARCH64__NR_io_pgetevents_time64);
            syscode_case(AARCH64__NR_recvmmsg_time64);
            syscode_case(AARCH64__NR_mq_timedsend_time64);
            syscode_case(AARCH64__NR_mq_timedreceive_time64);
            syscode_case(AARCH64__NR_semtimedop_time64);
            syscode_case(AARCH64__NR_rt_sigtimedwait_time64);
            syscode_case(AARCH64__NR_futex_time64);
            syscode_case(AARCH64__NR_sched_rr_get_interval_time64);
            syscode_case(AARCH64__NR_pidfd_send_signal);
            syscode_case(AARCH64__NR_io_uring_setup);
            syscode_case(AARCH64__NR_io_uring_enter);
            syscode_case(AARCH64__NR_io_uring_register);
            syscode_case(AARCH64__NR_open_tree);
            syscode_case(AARCH64__NR_move_mount);
            syscode_case(AARCH64__NR_fsopen);
            syscode_case(AARCH64__NR_fsconfig);
            syscode_case(AARCH64__NR_fsmount);
            syscode_case(AARCH64__NR_fspick);
            syscode_case(AARCH64__NR_pidfd_open);
            syscode_case(AARCH64__NR_clone3);
            syscode_case(AARCH64__NR_close_range);
            syscode_case(AARCH64__NR_openat2);
            syscode_case(AARCH64__NR_pidfd_getfd);
            syscode_case(AARCH64__NR_faccessat2);
            default:
                return nullptr;
        }
    }();
    if (ret == nullptr) {
        return nullptr;
    } else {
        return ret + 12;
    }
}

#undef syscode_case
