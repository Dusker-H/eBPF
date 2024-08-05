# Example 7 - Caputring Process Execution, Output with perf event array

---

- This article is the seventh part of the eBPF Tutorial by Ecample and mainly introduces how to capture process exectuion events in the Linux kernel and print output to the user command line via a perf event array
    - 이렇게 하면 `/sys/kernel/debug/tracing/trace_pipe` 파일을 확인하여 eBPF 프로그램의 출력을 볼 필요가 없음
    - `perf` 이벤트 배열을 통해 사용자 공간으로 정보를 전송한 후 복잡한 데이터 처리 및 분석을 수행할 수 있음

### perf buffer

- eBPF는 eBPF 프로그램에서 사용자 공간 컨트롤러로 정보를 전송하기 위해 두 개의 원형 버퍼를 제공
    1. perf circular buffer
    2. BPF curcular buffer

### execsnoop

- To print output to the user command line via the perf event array, a header file and a C source file need to be written
- Header file: execsnoop.h
    
    ```c
    #ifndef __EXECSNOOP_H
    #define __EXECSNOOP_H
    
    #define TASK_COMM_LEN 16
    
    struct event {
        int pid;
        int ppid;
        int uid;
        int retval;
        bool is_exit;
        char comm[TASK_COMM_LEN];
    };
    
    #endif /* __EXECSNOOP_H */
    ```
    
- Source file : execsnoop.bpf.c
    
    ```c
    // SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
    #include <vmlinux.h>
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_core_read.h>
    #include "execsnoop.h"
    
    struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u32));
    } events SEC(".maps");
    
    SEC("tracepoint/syscalls/sys_enter_execve")
    int tracepoint_syscalls_sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
    {
        u64 id;
        pid_t pid, tgid;
        struct event event={0};
        struct task_struct *task;
    
        uid_t uid = (u32)bpf_get_current_uid_gid();
        id = bpf_get_current_pid_tgid();
        tgid = id >> 32;
    
        event.pid = tgid;
        event.uid = uid;
        task = (struct task_struct*)bpf_get_current_task();
        event.ppid = BPF_CORE_READ(task, real_parent, tgid);
        char *cmd_ptr = (char *) BPF_CORE_READ(ctx, args[0]);
        bpf_probe_read_str(&event.comm, sizeof(event.comm), cmd_ptr);
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        return 0;
    }
    
    char LICENSE[] SEC("license") = "GPL";
    ```
    
- This code defines an eBPF program for capturing the entry of the `execve` system call.
    - In the entry program, 먼저 현재 프로세스의 프로세스 ID와 사용자 ID를 구한 다음, `bpf_get_current_task` 함수를 사용하여 현재 프로세스의 `task_struct` 구조를 구함
    - `bpf_probe_read_str` 함수를 사용하여 프로세스 이름을 읽음
    - 마지막으로, 프로세스 실행 이벤트를 perf 버퍼에 출력하기 위해 `bpf_perf_event_output` 함수를 사용
    - 이 코드를 사용하면 Linux 커널에서 프로세스 실행 이벤트를 캡처하고 프로세스 실행 상태를 분석할 수 있음
- Or compile using ecc:
    
    `ecc execsnoop.bpf.c execsnoop.h`
    
- Run:
    
    ```c
    $ sudo ./ecli run package.json 
    TIME     PID     PPID    UID     COMM    
    21:28:30  40747  3517    1000    node
    21:28:30  40748  40747   1000    sh
    21:28:30  40749  3517    1000    node
    21:28:30  40750  40749   1000    sh
    21:28:30  40751  3517    1000    node
    21:28:30  40752  40751   1000    sh
    21:28:30  40753  40752   1000    cpuUsage.sh
    ```
    

### Summary

- This article introduces how to caputre events of processes running in the Linux kernel and print ouput to the user command-line using the perf event array.
- After sending information to the user space via the perf event array, complex data processing and analysis can be performed
- 해당 커널 코드의 `libbpf` 에서 구조체와 해당 헤더 파일을 다음과 같이 정의할 수 있음
    - 이를 통해 사용자 공간에 직접 정보를 보낼 수 있음

```c
struct {
 __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
 __uint(key_size, sizeof(u32));
 __uint(value_size, sizeof(u32));
} events SEC(".maps");
```