# Example 1 - Hello World

---

### Hello World - minimal eBPF program

- `eunomia-bpf` 컴파일러 툴체인을 사용하여 BPF 바이트코드 파일로 컴파일한 다음 `ecli` 도구를 사용하여 프로그램을 로드하고 실행
- 예제에서는 사용자 공간 프로그램을 일시적으로 무시할 수 있음

```c
/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
 pid_t pid = bpf_get_current_pid_tgid() >> 32;
 if (pid_filter && pid != pid_filter)
  return 0;
 bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);
 return 0;
}
```

- 이 프로그램은 `handle_tp` 함수를 정의하고 SEC 매크로를 사용하여 `sys_enter_write` 트레이스 포인트에 첨부(즉, 쓰기 시스템 콜이 입력 될때 실행 됨)
- `handle_tp` 함수는 `bpf_get_current_pid_tgid` 및 `bpf_printk` 함수를 사용하여 쓰기 시스템 콜의 호출의 PID를 검색하고 커널 로그에 출력
    - `bpf_trace_printk()` :
        - `trace_pipe(/sys/kernel/debug/tracing/trace_pipe)`에 정보를 출력하는 간단한 메커니즘
        - limitations:
            - 최대 3개의 매개변수
            - 첫 매개변수는 `%s` 여야 한다는 점
            - `trace_pipe` 는 커널에서 전역으로 공유되므로 `trace_pipe` 를 동시에 사용하는 다른 프로그램이 출력을 발행할 수 있음
    - `void *ctx` : `ctx` 는 원래 특정 유형의 매개 변수이지만 여기서는 사용하지 않음
    - `return 0` : 이 함수는 0을 반환하는 데 필요

## Basic Framework of eBPF Program

As mentioned above, the basic framework of an eBPF program includes:

- Including header files: You need to include and header files, among others.
- Defining a license: You need to define a license, typically using "Dual BSD/GPL".
- Defining a BPF function: You need to define a BPF function, for example, named `handle_tp`, which takes void *ctx as a parameter and returns int. This is usually written in the C language.
- Using BPF helper functions: In the BPF function, you can use BPF helper functions such as `bpf_get_current_pid_tgid()` and `bpf_printk()`.
- Return value

### Tracepoints

- 트레이스 포인트는 커널 정적 계측 기법으로, 기술적으로는 커널 소스 코드에 배치된 트레이싱 함수이며, 본질적으로 소스 코드에 삽입된 제어 조건이 있는 프로브 포인트이므로 추가 처리 기능으로 사후 처리를 할 수 있음
    - 커널에서 가장 일반적인 정적 추적 방법은 로그 메시지를 출력하는 `printk` 임
    - 시스템 호출, 스케줄러 이벤트, 파일 시스템 작업 및 디스크 I/O 의 시작과 끝에는 트레이스 포인트가 있음