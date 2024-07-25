# Example 2 - Monitoring unlink System Calls with kprobe

---

## Background of kprobes Technology

- 개발자는 커널 또는 모듈의 디버깅 과정에서 특정 함수가 호출되었는지, 언제 호출되었는지, 실행이 올바른지, 함수의 입력 및 반환 값이 무엇인지 알아야 하는 경우가 종종 있습니다.
- kprobes 기술을 사용하면 사용자가 직접 콜백 함수를 정의하고 커널 또는 모듈의 거의 모든 함수에 프로브를 동적으로 삽입할 수 있습니다.
- 커널 실행 흐름이 지정된 프로브 함수에 도달하면 콜백 함수를 호출하여 사용자가 원하는 정보를 수집할 수 있습니다.
    - 그런다음 커널은 정상적인 실행 흐름으로 돌아갑니다.
- 사용자가 충분한 정보를 수집하여 더이상 프로빙을 계속할 필요가 없는 경우 프로브를 동적으로 제거할 수 있습니다.
- 따라서 kprobes 기술은 커널 실행 흐름에 미치는 영향을 최소화하고 조작이 쉽다는 장점이 있습니다.
- kprobe에 세 가지 detection methods
    - `kprobe, jprobe, kretprobe`
    - `kprobe` : 가장 기본적인 detection method 이며, 다른 두 가지 방법의 기초
        - 해당 메서드를 사용하면 프로브를 함수 내를 포함한 모든 위치에 배치할 수 있음
        - 프로브에 대한 세 가지 콜백 모드를 제공
            - `pre_handler` , `post_handler`, `fault_handler`
                - `pre_handler` 함수는 프로브 명령이 실행되기 전에 호출
                - `post_handler` 함수는 프로브 명령이 완료된 후 호출
                - `fault_handler` 함수는 메모리 액세스 오류가 발생할 때 호출
    - `jprobe` : `kprobe` 를 기반으로 하며 프로브 함수의 이력값을 가져오는데 사용
    - `kretprobe` : `kprobe` 를 기반으로 하며 프로브 함수의 반환값을 얻는 데 사용
- kprobes 특징 및 사용 제한
    1. `kprobes` 는 여러 `kprobe` 가 동일한 프로브 위치에 등록되도록 허용하지만 `jprobe` 는 현재 이를 지원하지 않은

### kprobe 예제

```python
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}
```

- 이 코드는 Linux 커널에서 실행되는 `unlink` 시스템 콜을 모니터링하고 캡처하는 데 사용되는 간단한 eBPF 프로그램임
    - `unlink` 시스템 콜은 파일을 삭제하는 데 사용
    - 이 eBPF 프로그램은 `do_unlinkat` kprobe를 사용하여 함수의 진입점과 종료점에 훅을 배치하여 이 시스템 호출을 추적함

- 먼저, `vmlinux.h`, `bpf_helpers.h`, `bpf_tracing.h`, `bpf_core_read.h`와 같은 필요한 헤더 파일을 가져옵니다. 그런 다음, 프로그램이 커널에서 실행될 수 있도록 라이선스를 정의합니다.

```python
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

- `BPF_KPROBE(do_unlinkat)` 다음으로, 함수가 입력되면 트리거되는 krpobe를 정의
    - `dfd(파일 설명자)` `name(파일 이름 구조 포인터)` 두 개의 매개변수를 사용
- 이 kprobe에서 현재 프로세스의 PID를 검색한 다음 파일 이름을 읽음
- 마지막으로 함수를 사용하여 `bpf_printk` 커널 로그에 PID와 파일 이름을 인쇄

```python
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}
```

- 다음으로 `do_unlinkat` 함수를 종료할 때 트리거되는 `BPF_KRETPROBE(do_unlinkat_exit)` 라는 이름의 `kretprobe` 를 정의
- 이 `kretprobe` 의 목적은 함수의 반환값(ret)을 캡처하는 것
- 다시 현재 프로세스의 PID를 구하고 `bpf_printk` 함수를 사용하여 커널 로그에 PID와 반환값을 인쇄

```python
SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}

```

To compile this program, use the ecc tool:

```python
$ ecc kprobe-link.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
```

Then run:

```python
sudo ecli run package.json
```

In another window:

```python
touch test1
rm test1
touch test2
rm test2
```

You should see kprobe demo output similar to the following in the /sys/kernel/debug/tracing/trace_pipe file:

```python
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9346    [005] d..3  4710.951696: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test1
              rm-9346    [005] d..4  4710.951819: bpf_trace_printk: KPROBE EXIT: ret = 0
              rm-9346    [005] d..3  4710.951852: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test2
              rm-9346    [005] d..4  4710.951895: bpf_trace_printk: KPROBE EXIT: ret = 0
```