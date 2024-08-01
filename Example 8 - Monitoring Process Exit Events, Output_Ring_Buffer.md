# Example 8 - Monitoring Process Exit Events, Output with Ring Buffer

---

- This article is the eighth part of the eBPF Tutorial by Example, focusing on monitoring process exit events with eBPF.

### Ring Buffer

- 새로운 BPF 데이터 구조
- 현재 커널에서 사용자 공간으로 데이터를 전송하는 사실상 표준인 `BPF perf` 버퍼의 메모리 효율성 및 이벤트 재정렬 문제를 해결
- 쉬운 마이그레이션을 위해 `perf 버퍼` 와의 호환성을 제공하는 동시에 새로운 예약/커밋 API를 도입하여 사용성을 개선함
- 또한 가상 및 실제 벤치마크 테스트 결과 거의 모든 경우에 BPF 프로그램에서 사용자 공간으로 데이터를 전송할 때 eBPF 링 버퍼를 기본으로 선택해야 하는 것으로 나타났음

### eBPF Ring Buffer vs eBPF Perf Buffer

- BPF 프로그램은 수집된 데이터를 사후 처리 및 로깅을 위해 사용자 공간으로 보내야 할 때마다 일반적으로 BPF 퍼프 버퍼(`perfbuf` )를 사용
- `perfbuf` 는 커널과 사용자 공간간에 효율적인 데이터 교환을 가능하게 하는 per-CPU 순환 버퍼의 모음
- 실제로는 잘 동작하지만 비효율적인 메모리 사용과 이벤트 재정렬이라는 불편한 두 가지 주요 단점이 있음
    - 이러한 문제를 해결하기 위해 BPF는 `BPF ring buffer` 라는 새로운 BPF 데이터 구조를 도입
    - 이는 여러 CPU에서 안전하게 공유할 수 있는 MPSC(다중 생산자, 단일 소비자) 큐
- The BPF ring buffer supports familiar features from BPF perf buffer
    - 가변 길이 데이터 레코드
    - 추가 메모리 복사나 커널 시스템 콜 입력 없이 메모리 매핑된 영역을 통해 사용자 공간에서 데이터를 효율적으로 읽기
    - 지연 시간을 최소화한 epoll 알림 및 바쁜 루프 작업 지원
- 동시에 BPF ring buffer가 해결한 BPF perf buffer의 문제들
    - Memory overhead.
    - Data ordering
    - Unnecessary work and additional data copying.

### exitsnoop

- focusing on monitoring process exit events with eBPF and using the ring buffer to print output to user space.
- Header File : exitsnoop.h

```python
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
};

#endif /* __BOOTSTRAP_H */
```

- Source File : exitsnoop.bpf.c

```python
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "exitsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, tid;
    u64 id, ts, *start_ts, start_time = 0;

    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task();
    start_time = BPF_CORE_READ(task, start_time);

    e->duration_ns = bpf_ktime_get_ns() - start_time;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

- 이 코드는 `exitsnoop`을 사용하여 프로세스 종료 이벤트를 모니터링하고 `ring buffer`를 사용하여 사용자 공간에 출력을 인쇄하는 방법을 보여줌
    1. 먼저, 필요한 헤더를 포함(`exitsnoop.h`)
    2. eBPF 프로그램의 라이선스 요구 사항인 “Dual BSD/GPL” 을 내용으로 하는 `LICENSE` 라는 전역 변수를 정의
    3. 커널 공간에서 사용자 공간으로 데이터를 전송하는 데 사용되는 `BPF_MAP_TYPE_RINGBUF` 타입의 `rb`라는 매핑을 정의
        1. `ring buffer` 의 최대 용량을 나타내는 max_entries를 256 * 1024로 지정
    4. 프로세스 종료 이벤트가 트리거될 때 실행될 `handle_exit` 라는 이름의 eBPF 프로그램을 정의
        1. 이 프로그램은 ctx라는 이름의 `trace_event_raw_sched_process_template` 구조체 포인터를 매개변수로 받음
    5. `bpf_get_current_pid_tgid()` 함수를 사용하여 현재 작업의 PID와 TID를 가져옴
        1. 메인 스레드의 경우 PID와 TID는 동일하지만, 자식 스레드의 경우 다름
        2. 프로세스(메인 스레드)의 종료에만 관심이 있으므로 PID와 TID가 다르면 0을 반환하고 자식 스레드의 종료 이벤트는 무시
    6. `bpf_ringbuf_reserve` 함수를 사용하여 링 버퍼에 이벤트 구조체 e를 위한 공간을 예약 → 예약에 실패하면 0을 반환
    7. `bpf_get_current_task()` 함수를 사용하여 현재 태스크의 `task_struxt` 구조체 포인터를 얻음
    8. 프로세스 기간, PID, PPID, 종료 코드, 프로세스 이름 등 프로세스 관련 정보를 예약된 이벤트 구조체 `e` 에 입력
    9. 마지막으로 `bpf_ringbug_submit` 함수를 사용하여 사용자 공간에서 추가 처리 및 출력을 위해 링 버퍼로 채워진 이벤트 구조체 e를 전송
- 이 예에서는 eBPF 프로그램에서 `exitsnoop` 과 링 버퍼를 사용하여 프로세스 종료 이벤트를 캡처하고 관련 정보를 사용자 공간으로 전송하는 방법을 설명
- 이는 프로세스 종료 이유를 분석하고 시스템 동작을 모니터링하는 데 유용