# Example 12 - Using eBPF Program Profile for Performance Analysis

---

- We will leverage the perf mechanism in the kernel to learn how to capture the execution time of functions and view performance data.
- `libbpf` is a C library for interacting with eBPF.
    - It provides the basic functionality for creating, loading. and using eBPF programs.
    - In this tutorial, we will mainly use libbpf for development.
    - `Perf` is a performance analysis tool in the Linux kernel that allows users to measure and analyze the performance of kernel and user space programs, as well as obtain corresponding call stacks.
    - It collects performance data using hardware counters and software events in the kernel.

### eBPF Tool : profile Performance Analysis Example

- `profile` 도구는 eBPF를 기반으로 구현되며 성능 분석을 위해 Linux 커널의 `perf` 이벤트를 활용함
- 프로파일 도구는 주기적으로 각 프로세서를 샘플링하여 커널 및 사용자 공간 함수의 실행을 캡처
- 스택 traces에 대해 다음과 같은 정보를 제공
    - Address : memorty address of the function call
    - Symbol : function name
    - File Name : name of the source code file
    - Line Number : line number in the source code
- 해당 정보는 개발자가 성능 병목 지점을 찾아 코드를 최적화하는 데 도움이 됨
- 또한 이 정보를 기반으로 flame 그래프를 생성하여 성능 데이터를 보다 직관적으로 볼 수 있음

### Implementation Principle

- The `profile` tool consist of two parts
    - 커널 공간에 있는 eBPF 프로그램과 사용자 공간에 있는 `profile` 심볼 핸들링 프로그램이 있음
    - `profile` 심볼 핸들링 프로그램은 eBPF 프로그램을 로드하고 프로그램에서 출력된 데이터를 처리하는 역할을 함

### Kernel Space Part

- 커널 공간에서 eBPF 프로그램의 구현 로직은 주로 `perf` 이벤트에 의존하여 프로그램의 스택을 주기적으로 샘플링하여 실행 흐름을 캡처함

```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "profile.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("perf_event")
int profile(void *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    int cpu_id = bpf_get_smp_processor_id();
    struct stacktrace_event *event;
    int cp;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 1;

    event->pid = pid;
    event->cpu_id = cpu_id;

    if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
        event->comm[0] = 0;

    event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);

    event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

    bpf_ringbuf_submit(event, 0);

    return 0;
}
```

1. Define eBPF maps `events` :
    - `BPF_MAP_TYPE_RINGBUF` 타입의 eBPF 맵이 정의
    - Ringg Buffer는 커널과 사용자 공간 간에 데이터를 전송하는 데 사용되는 고성능 원형 버퍼
    - `max_entries` 는 링 버퍼의 최대 크기를 설정
    
    ```c
    struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
    } events SEC(".maps");
    ```
    
2. Define `perf_event` eBPF program:
    - eBPF program named `profile` is defined, which will be executed when a perf event is triggerd.
    
    ```c
    SEC("perf_event")
    int profile(void *ctx)
    ```
    
3. Get process ID and CPU ID:
    - `bpf_get_current_pid_tgid()` 함수는 현재 프로세스의 PID와 TID를 반환
        - 32비트를 오른쪽으로 이동하면 PID를 얻음
        - `bpf_get_smp_processor_id()` 함수는 현재 CPU의 ID를 반환
    
    ```c
    int pid = bpf_get_current_pid_tgid() >> 32;
    int cpu_id = bpf_get_smp_processor_id();
    ```
    
4. Reserve space in the Ring Buffer:
    - 수집된 스택 정보를 저장할 링 버퍼의 공간을 예약하려면 `bpf_ringbuf_reserve()` 함수를 사용
        - 예약에 실패하면 오류를 반환
    
    ```c
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
    	return 1;
    ```
    
5. Get the current process name:
    - `evnet->comm` 에 프로세스 네임을 구하고 저장하려면 `bpf_get_current_comm()` 함수를 사용
    
    ```c
    if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
        event->comm[0] = 0;
    ```
    
6. Get kernel stack information:
    - `bpf_get_stack()` 함수를 사용하여 커널 스택 정보를 가져옴
    - 결과는 `event->kstack` 에 크기는 `event->kstack_sz` 에 저장
    
    ```c
    event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);
    ```
    
7. Get user space stack information:
    - `bpf_get_stack()` 함수를 `BPF_F_USER_STACK` 플래그와 함께 사용하면 사용자 공간 스택에 대한 정보를 검색
    - 결과는 `event->ustack` 에 크기는 `event->ustack_sz` 에 저장
8. Submit the event to the Ring Buffer:
    - 마지막으로 사용자 공간 프로그램이 읽고 처리할 수 있도록 이벤트를 링 버퍼로 전송하기 위해 `bpf_ringbuf_submit()` 함수를 사용
- 이 커널 모드 eBPF 프로그램은 프로그램의 커널 스택과 사용자 공간 스택을 주기적으로 샘플링하여 프로그램의 실행 흐름을 캡처
- 이러한 데이터는 사용자 모드 `profile` 프로그램이 읽을 수 있도록 Ring Buffer에 저장 됨

### User Mode Section

- 이 코드는 주로 온라인 CPU 에 대한 perf 이벤트를 설정하고 eBPF 프로그램을 첨부하는 역할을 함
    
    ```c
    static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                    int cpu, int group_fd, unsigned long flags)
    {
        int ret;
    
        ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
        return ret;
    }
    
    int main(){
        ...
        for (cpu = 0; cpu < num_cpus; cpu++) {
            /* skip offline/not present CPUs */
            if (cpu >= num_online_cpus || !online_mask[cpu])
                continue;
    
            /* Set up performance monitoring on a CPU/Core */
            pefd = perf_event_open(&attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
            if (pefd < 0) {
                fprintf(stderr, "Fail to set up performance monitor on a CPU/Core\n");
                err = -1;
                goto cleanup;
            }
            pefds[cpu] = pefd;
    
            /* Attach a BPF program on a CPU */
            links[cpu] = bpf_program__attach_perf_event(skel->progs.profile, pefd);
            if (!links[cpu]) {
                err = -1;
                goto cleanup;
            }
        }
        ...
    }
    ```
    
    - `perf_event_open` 함수는 `perf_event_open` 시스템 콜을 위한 wrapper.
        - 이 함수는 `perf` 이벤트의 유형과 속성을 지정하기 위해 `perf_event_attr` 구조체에 대한 포인터를 받음
        - `pid` 매개변수는 모니터링할 프로세스 ID를 지정하는 데 사용되며 (모든 프로세스를 모니터링하는 경우 -1), `CPU` 매개변수는 모니터링할 CPU를 지정하는 데 사용
        - `group_fd` 매개변수는 `perf` 이벤트를 그룹화하는 데 사용되며, 여기서는 그룹화가 필요하지 않음을 나타내기 위해 -1을 사용
        - `flags` 매개변수는 일부 플래그를 설정하는데 사용되며, exec system calls를 실행할 때 파일 설명자가 닫히도록 하기 위해 `PERF_FLAG_FD_CLOEXEC` 를 사용
- In the main function:
    - 해당 루프는 `perf` 이벤트를 설정하고 각 온라인 CPU에 대해 eBPF 프로그램을 첨부
        - 먼저 현재 CPU가 온라인 상태인지 확인하고 그렇지 않은 경우 건너뜀
        - 그런 다음 `perf_event_open()` 함수를 사용해 현재 CPU에 대한 `perf` 이벤트에 첨부
        - 링크 배열은 프로그램 종료 시 삭제될 수 있도록 각 CPU에 대한 BPF 링크를 저장하는 데 사용되며, 이를 통해 사용자 모드 프로그램은 각 온라인 CPU에 대한 `perf` 이벤트를 설정하고 이러한 `perf` 이벤트에 eBPF 프로그램을 첨부하여 시스템의 모든 온라인 CPU를 모니터링 함
    
    ```c
    for (cpu = 0; cpu < num_cpus; cpu++) {
        // ...
    }
    ```
    
- The following two functions are used to display stack traces and handle events received from the ring buffer.
    - `show_stack_trace()` 함수는 커널 또는 사용자 공간의 스택 추적을 표시하는 데 사용
        - 커널 또는 사용자 공간 스택에 대한 포인터인 `stack` 매개변수와 스택의 크기를 나타내는 `stack_sz` 매개변수를 받음
        - `pid` 매개변수에 따라 스택의 소스(커널 또는 사용자 공간)가 결정된 다음 `blazesym_symbolize()` 함수를 호출하여 스택의 주소를 심볼 이름과 소스 코드 위치로 resolve(해석)
        - 마지막으로, 확인된 결과를 트래버스하고 심볼 이름과 소스 코드 위치 정보를 출력
    - `event_handler()` 함수는 ring buffer에서 수신한 이벤트를 처리하는 데 사용
        - 함수는 링 버퍼의 데이터를 가리키는 `data` 매개변수와 데이터의 크기를 나타내는 `size` 매개변수를 받음
        - 함수는 먼저 `data` 포인터를 `stracktrace_event` 타입의 포인터로 변환한 다음 커널 및 사용자 공간 스택의 크기를 확인
        - 스택이 비어 있으면 바로 반환
        - 다음으로, 이 함수는 프로세스 이름, 프로세스 ID, CPU ID 정보를 출력
        - 그런 다음 커널과 사용자 공간의 스택 추적을 각각 표시
        - `show_stack_trace()` 함수를 호출할 때 커널과 사용자 공간 스택의 주소, 크기, 프로세스 ID가 별도로 전달 됨
    
    ```c
    static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
    {
        const struct blazesym_result *result;
        const struct blazesym_csym *sym;
        sym_src_cfg src;
        int i, j;
    
        if (pid) {
            src.src_type = SRC_T_PROCESS;
            src.params.process.pid = pid;
        } else {
            src.src_type = SRC_T_KERNEL;
            src.params.kernel.kallsyms = NULL;
            src.params.kernel.kernel_image = NULL;
        }
    
        result = blazesym_symbolize(symbolizer, &src, 1, (const uint64_t *)stack, stack_sz);
    
        for (i = 0; i < stack_sz; i++) {
            if (!result || result->size <= i || !result->entries[i].size) {
                printf("  %d [<%016llx>]\n", i, stack[i]);
                continue;
            }
    
            if (result->entries[i].size == 1) {
                sym = &result->entries[i].syms[0];
                if (sym->path && sym->path[0]) {
                    printf("  %d [<%016llx>] %s+0x%llx %s:%ld\n",
                           i, stack[i], sym->symbol,
                           stack[i] - sym->start_address,
                           sym->path, sym->line_no);
                } else {
                    printf("  %d [<%016llx>] %s+0x%llx\n",
                           i, stack[i], sym->symbol,
                           stack[i] - sym->start_address);
                }
                continue;
            }
    
            printf("  %d [<%016llx>]\n", i, stack[i]);
            for (j = 0; j < result->entries[i].size; j++) {
                sym = &result->entries[i].syms[j];
                if (sym->path && sym->path[0]) {
                    printf("        %s+0x%llx %s:%ld\n",
                           sym->symbol, stack[i] - sym->start_address,
                           sym->path, sym->line_no);
                } else {
                    printf("        %s+0x%llx\n", sym->symbol,
                           stack[i] - sym->start_address);
                }
            }
        }
    
        blazesym_result_free(result);
    }
    
    /* Receive events from the ring buffer. */
    static int event_handler(void *_ctx, void *data, size_t size)
    {
        struct stacktrace_event *event = data;
    
        if (event->kstack_sz <= 0 && event->ustack_sz <= 0)
            return 1;
    
        printf("COMM: %s (pid=%d) @ CPU %d\n", event->comm, event->pid, event->cpu_id);
    
        if (event->kstack_sz > 0) {
            printf("Kernel:\n");
            show_stack_trace(event->kstack, event->kstack_sz / sizeof(__u64), 0);
        } else {
            printf("No Kernel Stack\n");
        }
    
        if (event->ustack_sz > 0) {
            printf("Userspace:\n");
            show_stack_trace(event->ustack, event->ustack_sz / sizeof(__u64), event->pid);
        } else {
            printf("No Userspace Stack\n");
        }
    
        printf("\n");
        return 0;
    }
    ```