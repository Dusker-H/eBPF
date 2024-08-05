# Example 11 - Develop User-Space Programs with libbpf and Trace exec() and exit()

---

- In this tutorial, we will learn how kernel-space and user-space eBPF programs work together.
- We will also learn how to use the native libbpf to develop user-space programs, package eBPF applications into executable files, and distribute them across different kernel versions.

### The libbpf Library and Why We Need to Use it

- `libbpf` is a C language library that is distributed with the kernel version to assist in loading and running eBPF programs.
- It provides a set of C APIs for interacting with the eBPF system, allowing developers to write user-space programs more easilty to load and manage eBPF programs.
- These user-space programs are typically used for system performance analysis, monitoring, or optimization.
- 라이브러리를 사용하면 다음과 같은 몇 가지 장점이 있음
    - eBPF 프로그램을 로드, 업데이트 및 실행하는 프로세스가 간소화
    - 사용하기 쉬운 API 세트를 제공하여 개발자가 낮은 수준의 세부 사항을 처리하는 대신 핵심 로직 작성에 집중할 수 있음
    - 커널의 eBPF 하위 시스템과의 호환성을 보장하여 유지 관리 비용을 절감할 수 있음
- 동시에 `libbpf` 와 BTF (BPF Type Format) 는 eBPF 생태계에서 중요한 구성 요소
    - 이들은 서로 다른 커널 버전 간에 호환성을 확보하는 데 중요한 역할을 함
- `BTF` 는 eBPF 프로그램에서 유형 정보를 설명하는 데 사용되는 메타데이터 형식
- `BTF` 의 주요 목적은 커널에서 데이터 구조를 설명하는 구조화된 방법을 제공하여 eBPF 프로그램이 데이터 구조에 더 쉽게 액세스하고 조작할 수 있도록 하는 것임
- The key of roles of BTF in achieving compatibility across different kernel versions are as follows
    - BTF allow eBPF programs to access detailed type information of kernel data structures without hardcoding specific kernel versions.
        - This enables eBPF programs to adapt to different kernel versions, achieving compatibility across kernel versions.
    - By using BPF `CO-RE` (Compile Once, Run Everywhere) technology, eBPF programs can leverage BTF to parse the type information of kernel data structures during compilation, thereby generating eBPF programs that can run on different kernel versions.
- `libbpf` 와 `BTF` 를 결합하면 커널 버전마다 별도로 컴파일할 필요 없이 다양한 커널 버전에서 eBPF 프로그램을 실행할 수 있음
- 이를 통해 eBPF 에코시스템의 이식성과 호환성이 크게 향상되고 개발 및 유지 관리의 어려움이 줄어듬

### What is Bootstrap

- `Bootstrap` 은 `libbpf` 를 활용한 완전한 애플리케이션
    - 이 애플리케이션은 주로 새로운 프로세스의 생성에 해당하는 커널의 `exec()` 시스템 콜`(handled by the SEC(”tp/sched/sched_process_exec”) handle_exec BPF program), 을 추적하기 위해 eBPF 프로그램을 사용(`fork() 부분 제외` )
    - 또한 각 프로세스가 종료되는 시점을 파악하기 위해 프로세스의 `exit()` 시스템 콜 (handled by the SEC(”tp/sched/sched_process_exit”) handle_exit BPF program)도 추적함
- 이 두 BPF 프로그램은 함께 작동하여 바이너리 파일 이름과 같은 새 프로세스에 대한 흥미로운 정보를 캡처하고 프로세스의 수명 주기를 측정
    - 또한 프로세스가 종료될 때 종료 코드나 리소스 소비량과 같은 흥미로운 통계도 수집
    - 이는 커널의 내부 작동을 더 깊이 이해하고 실제로 어떻게 작동하는지 관찰할 수 있는 좋은 출발점
    - `Bootstrap` 은 또한 command-line arguement parsing에 argp API(part of libc)를 사용하므로 사용자가 command-line 옵션을 통해 애플리케이션의 동작을 구성할 수 있음
    - 이를 통해 유연성을 제공하고 사용자가 특정 요구 사항에 따라 프로그램 동작을 사용자 지정할 수 있음

### Bootstrap

- 부트스트랩은 커널 공간과 사용자 공간의 두 부분으로 구성
    - 커널 공간 부분은 `exec()` and `exit()` 시스템 콜을 추적하는 eBPF 프로그램
    - 사용자 공간 부분은 커널 공간 프로그램을 로드 및 실행하고 커널 공간 프로그램에서 수집한 데이터를 처리하기 위해 `libbpf` 라이브러리를 사용하는 C언어 프로그램
- Kenrel-space eBPF Program bootstrap.bpf.c
    - 이 코드는 `exec()` and `exit()` 시스템 콜을 추적하는 데 사용되는 커널 수준의 eBPF 프로그램
    - 이 코드는 eBPF 프로그램을 사용하여 프로세스 생성 및 종료 이벤트를 캡처하고 관련 정보를 사용자 공간 프로그램으로 전송하여 처리함
    
    ```c
    // SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
    /* Copyright (c) 2020 Facebook */
    #include "vmlinux.h"
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_tracing.h>
    #include <bpf/bpf_core_read.h>
    #include "bootstrap.h"
    
    char LICENSE[] SEC("license") = "Dual BSD/GPL";
    
    struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8192);
        __type(key, pid_t);
        __type(value, u64);
    } exec_start SEC(".maps");
    
    struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
    } rb SEC(".maps");
    
    const volatile unsigned long long min_duration_ns = 0;
    
    SEC("tp/sched/sched_process_exec")
    int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
    {
        struct task_struct *task;
        unsigned fname_off;
        struct event *e;
        pid_t pid;
        u64 ts;
    
        /* remember time exec() was executed for this PID */
        pid = bpf_get_current_pid_tgid() >> 32;
        ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);
    
        /* don't emit exec events when minimum duration is specified */
        if (min_duration_ns)
            return 0;
    
        /* reserve sample from BPF ringbuf */
        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e)
            return 0;
    
        /* fill out the sample with data */
        task = (struct task_struct *)bpf_get_current_task();
    
        e->exit_event = false;
        e->pid = pid;
        e->ppid = BPF_CORE_READ(task, real_parent, tgid);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
        fname_off = ctx->__data_loc_filename & 0xFFFF;
        bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);
    
        /* successfully submit it to user-space for post-processing */
        bpf_ringbuf_submit(e, 0);
        return 0;
    }
    
    SEC("tp/sched/sched_process_exit")
    int handle_exit(struct trace_event_raw_sched_process_template* ctx)
    {
        struct task_struct *task;
        struct event *e;
        pid_t pid, tid;
        u64 id, ts, *start_ts, duration_ns = 0;
    
        /* get PID and TID of exiting thread/process */
        id = bpf_get_current_pid_tgid();
        pid = id >> 32;
        tid = (u32)id;
    
        /* ignore thread exits */
        if (pid != tid)
            return 0;
    
        /* if we recorded start of the process, calculate lifetime duration */
        start_ts = bpf_map_lookup_elem(&exec_start, &pid);
        if (start_ts)duration_ns = bpf_ktime_get_ns() - *start_ts;
        else if (min_duration_ns)
            return 0;
        bpf_map_delete_elem(&exec_start, &pid);
    
        /* if process didn't live long enough, return early */
        if (min_duration_ns && duration_ns < min_duration_ns)
            return 0;
    
        /* reserve sample from BPF ringbuf */
        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e)
            return 0;
    
        /* fill out the sample with data */
        task = (struct task_struct *)bpf_get_current_task();
    
        e->exit_event = true;
        e->duration_ns = duration_ns;
        e->pid = pid;
        e->ppid = BPF_CORE_READ(task, real_parent, tgid);
        e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
        /* send data to user-space for post-processing */
        bpf_ringbuf_submit(e, 0);
        return 0;
    }
    ```
    
- 먼저, 필요한 헤더를 포함하고 eBPF 프로그램에 대한 라이선스를 정의
- 또한 `exec_start` 와 `rb` 라는 두 개의 eBPF 맵을 정의
    - `exec_start` 는 프로세스가 실행을 시작할 때 타임스탬프를 저장하는 데 사용되는 해시 유형 eBPF 맵
    - `rb` 는 캡처된 이벤트 데이터를 저장하고 사용자 공간 프로그램으로 전송하는 데 사용되는 `ring buffer` 유형의 eBPF 맵
    
    ```c
    #include "vmlinux.h"
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_tracing.h>
    #include <bpf/bpf_core_read.h>
    #include "bootstrap.h"
    
    char LICENSE[] SEC("license") = "Dual BSD/GPL";
    
    struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8192);
        __type(key, pid_t);
        __type(value, u64);
    } exec_start SEC(".maps");
    
    struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
    } rb SEC(".maps");
    
    const volatile unsigned long long min_duration_ns = 0;
    ```
    
- 다음으로, 프로세스가 `exec()` 시스템 콜을 실행할 때 트리거되는 `handle_exec` 라는 이름의 eBPF 프로그램을 정의
    - 먼저 현재 프로세스에서 PID를 검색하고 프로세스가 실행을 시작할 때 타임스탬프를 기록한 후 `exec_start` 맵에 저장
    
    ```c
    SEC("tp/sched/sched_process_exec")
    int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
    {
        // ...
        pid = bpf_get_current_pid_tgid() >> 32;
        ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);
    
        // ...
    }
    ```
    
- 그런 다음 `circular buffer map` `rb` 에서 이벤트 구조를 예약하고 프로세스 ID, 상위 프로세스 ID, 프로세스 이름 등 관련 데이터를 입력
    - 이 후 이 데이터를 user-mode program으로 전송하여 처리
    
    ```c
        // reserve sample from BPF ringbuf
        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e)
            return 0;
    
        // fill out the sample with data
        task = (struct task_struct *)bpf_get_current_task();
    
        e->exit_event = false;
        e->pid = pid;
        e->ppid = BPF_CORE_READ(task, real_parent, tgid);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
        fname_off = ctx->__data_loc_filename & 0xFFFF;
        bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);
    
        // successfully submit it to user-space for post-processing
        bpf_ringbuf_submit(e, 0);
        return 0;
    ```
    
- 마지막으로 프로세스가 `exit()` 시스템 콜을 실행할 때 트리거되는 `handle_exit` 라는 이름의 eBPF 프로그램을 정의
    - 먼저 현재 프로세스에서 PID와 TID(Thread ID)를 검색
    - PID와 TID가 같지 않으면, 스레드 종료라는 의미이므로 이 이벤트를 무시
    
    ```c
    SEC("tp/sched/sched_process_exit")
    int handle_exit(struct trace_event_raw_sched_process_template* ctx)
    {
        // ...
        id = bpf_get_current_pid_tgid();
        pid = id >> 32;
        tid = (u32)id;
    
        /* ignore thread exits */
        if (pid != tid)
            return 0;
    
        // ...
    }
    ```
    
- 다음으로, 이전에 `exec_start` 맵에 저장되어 있던 프로세스가 실행을 시작한 시점의 타임 스탬프를 조회
    - 타임스탬프가 발견되면 프로세스의 수명 기간을 계산한 다음 `exec_start` 맵에서 레코드를 제거
    - 타임스탬프를 찾을 수 없고, 최소 기간을 지정하면 바로 반환
    
    ```c
        // if we recorded start of the process, calculate lifetime duration
        start_ts = bpf_map_lookup_elem(&exec_start, &pid);
        if (start_ts)
            duration_ns = bpf_ktime_get_ns() - *start_ts;
        else if (min_duration_ns)
            return 0;
        bpf_map_delete_elem(&exec_start, &pid);
    
        // if process didn't live long enough, return early
        if (min_duration_ns && duration_ns < min_duration_ns)
            return 0;
    ```
    
- 그런 다음 circular buffer map `rb` 에서 이벤트 구조를 예약하고 프로세스 ID, 상위 프로세스 ID,  프로세스 이름 및 프로세스 기간과 같은 관련 데이터를 입력
    - 마지막으로 이 데이터를 사용자 모드 프로그램으로 전송하여 처리
    
    ```c
        /* reserve sample from BPF ringbuf */
        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e)
            return 0;
    
        /* fill out the sample with data */
        task = (struct task_struct *)bpf_get_current_task();
    
        e->exit_event = true;
        e->duration_ns = duration_ns;```
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
    }
    
    ```
    
- 이렇게 하면 프로세스가 `exec()` 또는 `exit()` 시스템 콜을 실행하면 eBPF 프로그램이 해당 이벤트를 캡처하고 추가 처리를 위해 사용자 공간 프로그램에 자세한 정보를 전송
- 이를 통해 프로세스 생성 및 종료를 쉽게 모니터링하고 프로세스에 대한 자세한 정보를 얻을 수 있음
- 또한 bootstrap.h 파일에서는 사용자 공간과의 상호 작용을 위한 데이터 구조도 정의
    
    ```c
    /* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
    /* Copyright (c) 2020 Facebook */
    #ifndef __BOOTSTRAP_H
    #define __BOOTSTRAP_H
    
    #define TASK_COMM_LEN 16
    #define MAX_FILENAME_LEN 127
    
    struct event {
        int pid;
        int ppid;
        unsigned exit_code;
        unsigned long long duration_ns;
        char comm[TASK_COMM_LEN];
        char filename[MAX_FILENAME_LEN];
        bool exit_event;
    };
    
    #endif /* __BOOTSTRAP_H */
    ```
    

### User space, bootstrap.c

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"

static struct env {
    bool verbose;
    long min_duration_ms;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF bootstrap demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'v':
        env.verbose = true;
        break;
    case 'd':
        errno = 0;
        env.min_duration_ms = strtol(arg, NULL, 10);
    if (errno || env.min_duration_ms <= 0) {
    fprintf(stderr, "Invalid duration: %s\n", arg);
    argp_usage(state);
}
break;
case ARGP_KEY_ARG:
    argp_usage(state);
    break;
default:
    return ARGP_ERR_UNKNOWN;
}
return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    if (e->exit_event) {
        printf("%-8s %-5s %-16s %-7d %-7d [%u]",
               ts, "EXIT", e->comm, e->pid, e->ppid, e->exit_code);
        if (e->duration_ns)
            printf(" (%llums)", e->duration_ns / 1000000);
        printf("\n");
    } else {
        printf("%-8s %-5s %-16s %-7d %-7d %s\n",
               ts, "EXEC", e->comm, e->pid, e->ppid, e->filename);
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct bootstrap_bpf *skel;
    int err;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
    skel = bootstrap_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Parameterize BPF code with minimum duration parameter */
    skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

    /* Load & verify BPF programs */
    err = bootstrap_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = bootstrap_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Process events */
    printf("%-8s %-5s %-16s %-7s %-7s %s\n",
        "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    /* Clean up */
    ring_buffer__free(rb);
    bootstrap_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
```

- This user-level program is mainly used to load, verify, attach eBPF programs, and receive event data collected by eBPF programs and print it out.
1. Define an env structure to store command line arguments:
    
    ```c
    static struct env {
    		bool verbose;
    		long min_duration_ms;
    } env;
    ```
    
2. Use the argp library to parse command line arguements:
    
    ```c
    static const struct argp_option opts[] = {
        { "verbose", 'v', NULL, 0, "Verbose debug output" },
        { "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
        {},
    };
    
    static error_t parse_arg(int key, char *arg, struct argp_state *state)
    {
        // ...
    }
    
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    ```
    
    - main() 함수에서 먼저 coomand line arguements를 분석한 다음, 필요할 때 디버그 정보를 출력하도록 libbpf print 콜백 함수 `libbpf_print_fn` 을 설정
    
    ```c
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;
    libbpf_set_print(libbpf_print_fn);
    ```
    
3. 다음으로 eBPF 스켈레톤 파일을 열고 최소 지속 시간 파라미터를 eBPF 프로그램에 전달한 후 eBPF 프로그램을 로드하여 첨부
    
    ```c
    skel = bootstrap_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }
    
    skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;
    
    err = bootstrap_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }
    
    err = bootstrap_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }
    ```
    
4. 그런 다음 링 버퍼를 생성하여 eBPF 프로그램에서 전송한 이벤트 데이터를 수신
    
    ```c
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    ```
    
- `handle_event()` 함수는 eBPF 프로그램에서 수신한 이벤트를 처리
    - 이벤트 유형 (프로세스 실행 또는 종료)에 따라 타임 스탬프, 프로세스 이름, 프로세스 ID, 상위 프로세스 ID, 파일 이름 또는 종료 코드 등의 이벤트 정보를 추출하여 출력
1. 마지막으로 `ring_buffer_poll()` 함수를 사용하여 링 버퍼를 폴링하고 수신한 이벤트 데이터를 처리
    
    ```c
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        // ...
    }
    ```
    
- 프로그램이 `SIGINT` 또는 `SIGTERM` 신호를 수신하면 최종 정리 및 종료 작업을 완료하고 eBPF 프로그램을 닫고 언로드 함
    
    ```c
    cleanup:
     /* Clean up */
     ring_buffer__free(rb);
     bootstrap_bpf__destroy(skel);
    
     return err < 0 ? -err : 0;
    }
    ```