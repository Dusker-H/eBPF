# Example 4 - Capturing Opening Files and Filter with Global Variables

---

- This article is the fourth part of the eBPF Tutorial by Example, mainly focusing on how to capture the system call collection of process oepning files and filtering process PIDs using global variables in eBPF.
- Linux 시스템에서 프로세스와 파일 간의 상호 작용은 시스템 콜을 통해 이루어짐
- 시스템 콜은 사용자 공간 프로그램과 커널 공간 프로그램 간의 인터페이스 역할을 하며, 사용자 프로그램이 커널에 특정 작업을 요청할 수 있게 해줌
- 이 튜토리얼에서는 파일을 여는 데 사용되는 `sys_oenat` 시스템 콜에 중점을 둠
- 프로세스가 파일을 열면 커널에 `sys_openat` 시스템 콜을 실행하고 관련 매개변수(파일 경로, 열기 모드 등)을 전달
- 커널은 해당 요청을 처리하고 후속 파일 작업의 참조로 사용되는 file descriptor를 반환
- `sys_openat` 시스템 콜을 캡처하면 프로세스가 파일을 여는 시기와 방법을 파악할 수 있음

## Caputuring the System Call Collection of Process Opening Files in eBPF

- 먼저, 파일을 여는 프로세스의 시스템 콜을 캡처하는 eBPF 프로그램을 작성해야 함

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/// @description "Process ID to trace"
const volatile int pid_target = 0;

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (pid_target && pid_target != pid)
        return false;

    // Use bpf_printk to print the process information
    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}

/// "Trace open family syscalls."
char LICENSE[] SEC("license") = "GPL";
```

- 해당 eBPF 프로그램은 다음과 같이 동작
    1. 헤더 파일 포함
        1. 커널 데이터 구조의 정의를 포함하며, eBPF 프로그램에 필요한 헬퍼 함수를 포함
    2. 지정된 프로세스 ID 를 필터링하기 위한 전역 변수 `pid_target` 을 정의. 0으로 설정하면 모든 프로세스에서 `sys_oepnat` 콜을 캡처
    3. `SEC` 매그로를 사용하여 트레이스 포인트 `tracepoint/syscalls/sys_enter_openat` 와 연결된 eBPF 프로그램을 정의
        1. 해당 트레이스 포인트는 프로세스가 `sys_openat` 시스템 콜을 시작할 때 트리거 됨
    4. `struct trace_event_raw_sys_enter` 유형의 매개변수 `ctx` 를 취하는 eBPF 프로그램 `tracepoint_syscalls_sys_enter_openat` 를 구현
        1. 해당 구조체는 시스템 콜에 대한 정보가 포함되어 있음
    5. 현재 프로세스의 PID와 TID(Thread ID)를 검색하려면 `bpf_get_current_pid_tgid()` 함수를 사용
        1. 여기서는 PID만 중요하므로 값을 오른쪽으로 32비트 이동하여 u32타입의 변수 pid에 할당
    6. `pid_target` 변수가 현재 프로세스의 PID와 동일한지 확인
        1. `pid_target` 이 0이 아니고 현재 프로세스의 PID와 같지 않으면 false를 반환하여 해당 프로세스의 `sys_openat` 콜 캡처를 건너뜀
    7. `bpf_printk()` 함수를 사용하여 캡처된 프로세스 ID와 `sys_openat` 콜에 대한 관련 정보를 인쇄
        1. 이러한 정보는 BPF 도구를 사용하여 사용자 공간에서 볼 수 있음
    8. 프로그램 라이선스를 eBPF 프로그램 실행에 필요한 조건인 “GPL” 로 설정
- 이 프로그램은 지정된 프로세스(또는 모든 프로세스)의 `sys_openat` 시스템 콜을 캡처하고 관련 정보를 사용자 공간에 출력
- Compile and run the above code:
    
    ```c
    $ ecc opensnoop.bpf.c
    Compiling bpf object...
    Packing ebpf object and config into package.json...
    $ sudo ecli run package.json
    Running eBPF program...
    ```
    
- After running this program, you can view the output of the eBPF program by viewing the `/sys/kernel/debug/tracing/trace_pipe` file
    
    ```c
    $ sudo cat /sys/kernel/debug/tracing/trace_pipe
    ```
    

### Filtering Process PID in eBPF using Global Variables

- 전역 변수는 eBPF 프로그램에서 데이터 공유 메커니즘으로 작동하여 사용자 공간 프로그램과 eBPF 프로그램 간의 데이터 상호 작용을 허용
- 이는 특정 조건을 필터링하거나 eBPF 프로그램의 동작을 수정할 때 매우 유용
- 이 설계를 통해 사용자 공간 프로그램은 런타임에 eBPF 프로그램의 동작을 동적으로 제어할 수 있음
- 이 예제에서는 전역 변수 `pid_target` 이 프로세스 PID를 필터링하는 데 사용
- 사용자 공간 프로그램은 이 변수의 값을 설정하여 eBPF 프로그램에서 지정된 PID와 관련된 `sys_openat` 시스템 콜만 캡처할 수 있음
- 전역 변수 사용의 원칙은 eBPF 프로그램의 데이터 섹션에 정의 및 저장하는 것임
- eBPF 프로그램이 커널에 로드되어 실행되면 이러한 전역 변수는 커널에 유지되며 BPF 시스템 콜을 통해 액세스 할 수 있음
- 사용자 공간 프로그램은 `bpf_obj_get_info_by_fd` 및 `bpf_obj_get_info` 와 같은 BPF 시스템 콜의 특정 기능을 사용하여 전역 변수의 위치 및 값을 비롯한 eBPF 객체에 대한 정보를 얻을 수 있음
- 예를 들어 `—pid_target` 옵션을 사용하여 캡처할 프로세스의 PID를 지정할 수 있음
    
    ```c
    $ sudo ./ecli run package.json  --pid_target 618
    Running eBPF program...
    ```
    
    ```c
    $ sudo cat /sys/kernel/debug/tracing/trace_pipe".\-3840345 [010] d... 3220701.101179: bpf_trace_printk: Process ID: 618 enter sys openat
    \-3840345 [010] d... 3220702.158000: bpf_trace_printk: Process ID: 618 enter sys openat
    ```