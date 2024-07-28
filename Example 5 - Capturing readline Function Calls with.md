# Example 5 - Capturing readline Function Calls with Uprobe

---

### What is uprobe

- 사용자 공간 프로그램에서 동적 계측을 허용하는 user-space 프로브
    - 프로브 위치에는 함수 입력, 특정 오프셋 및 함수 리턴이 포함됨
- `uprobe` 를 정의하면 커널은 첨부된 명령어에 빠른 중단점 명령어(x86 시스템의 경우 int3 명령어)를 생성
- 프로그램이 이 명령어를 실행하면 커널이 이벤트를 트리거하여 프로그램이 커널 모드로 전환되고 콜백 함수를 통해 프로브 함수를 호출
- 프로브 함수를 실행한 후 프로그램은 사용자 모드로 돌아가 후속 명령을 계속 실행
- `uprobe` 는 파일 베이스
- 바이너리 파일의 함수를 추적하면 아직 시작되지 않은 프로세스를 포함하여 파일을 사용하는 모든 프로세스가 계측되므로 시스템 콜을 시스템 전체에서 추적할 수 있음
- `uprobe` 는 HTTP/2 트래픽(헤더가 인코딩되어 커널에서 디코딩할 수 없는 경우) 및 HTTPS 트래픽(암호화되어 커널에서 해독할 수 없는 경우) 등 커널 모드 프로브에서 확인할 수 없는 User-mode의 일부 트래픽을 분석하는데 적합함
- 커널 모드 eBPF 런타임에서 `Uprobe` 는 상대적으로 큰 오버헤드가 발생할 수 있음
    - 이 경우 `bpftime` 과 같은 사용자 모드 eBPF 런타임을 사용하는 것도 고려해 볼 수 있음
    - `bpftime` 은 LLVM JIT/AOT 기반의 사용자 모드 eBPF 런타임임
    - 사용자 모드에서 eBPF 프로그램을 실행할 수 있으며 커널 모드 eBPF와 호환되므로 커널 모드와 사용자 모드 간의 Context switching을 방지하여 eBPF 프로그램의 실행 효율을 10배 향상 시킬 수 있음

### Capturing readline Function Calls in bash using uprobe

- `uprobe` 는 사용자 공간 함수 호출을 캡처하는 데 사용되는 eBPF 프로브로, 사용자 공간 프로그램에서 호출하는 시스템 함수를 캡처할 수 있음
- 예를 들어 `uprobe` 를 사용하여 bash에서 readline 함수 호출을 캡처하고 사용자로부터 명령줄 입력을 가져올 수 있음
- 예제 코드

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const void *ret)
{
 char str[MAX_LINE_SIZE];
 char comm[TASK_COMM_LEN];
 u32 pid;

 if (!ret)
  return 0;

 bpf_get_current_comm(&comm, sizeof(comm));

 pid = bpf_get_current_pid_tgid() >> 32;
 bpf_probe_read_user_str(str, sizeof(str), ret);

 bpf_printk("PID %d (%s) read: %s ", pid, comm, str);

 return 0;
};

char LICENSE[] SEC("license") = "GPL";
```

- 이 코드의 목적은 bash의 `readline` 함수가 반환될 때 지정된 `BPF_PROBE 함수 (printret 함수)` 를 실행하는 것임
    - `printret` 함수에서는 먼저 `readline` 함수를 호출하는 프로세스의 프로세스 이름과 프로세스 ID를 가져옴
    - 그런 다음 `bpf_probe_read_user_str` 함수를 사용하여 사용자 입력 명령줄 문자열을 읽음
    - 마지막으로 `bpf_printk` 함수를 사용하여 프로세스 ID, 프로세스 이름 및 입력 명령줄 문자열을 인쇄함
- 또한, `SEC` 매크로를 사용하여 `Uprobe` 프로브를 정의하고, `BPF_KRETPROBE` 매크로를 사용하여 프로브 함수를 정의해야함
    - 위 코드의 `SEC` 매코르에서는 업로드의 유형, 캡처할 바이너리 파일의 경로, 캡처할 함수 이름을 지정해야 함
    - 해당 코드가 나타내는 것은 `/bin/bash` 바이너리 파일에서 `readline` 함수를 캡처하고 싶다는 것을 나타냄
    
    ```c
    SEC("uretprobe//bin/bash:readline")
    ```
    
- 다음으로 `BPF_KRETPROBE` 매크로를 사용하여 프로브 함수를 정의해야함
    - Then, `bpf_get_currnet_comm` 함수를 사용하여 현재 작업의 이름을 가져와서 커맨드 배열에 저장
    
    ```c
    bpf_get_current_comm(&comm, sizeof(comm));
    ```
    
- 현재 프로세스의 PID를 가져와 pid 변수에 저장하기 위해 `bpf_get_current_pid_tgid` 함수를 사용
    
    ```c
    pid = bpf_get_current_pid_tgid() >> 32;
    ```
    
- 사용자 공간에서 `readline` 함수의 반환 값을 읽어 str 배열에 저장하기 위해 `bpf_probe_read_user_str` 함수를 사용
    
    ```c
    bpf_probe_read_user_str(str, sizeof(str), ret);
    ```
    
- `bpf_print` 함수를 사용하여 PID, 작업 이름, 사용자 입력 문자열을 출력
    
    ```c
    bpf_print("PID %d (%s) read: %s ", pid, comm, str);
    ```
    
- Compile and run the above code:

```c
$ ecc bashreadline.bpf.c
Compiling bpf object...
Packing ebpf object and config into package.json...
$ sudo ecli run package.json
Running eBPF program...
```

- After running this program, you can view the output of the eBPF program by checking the file `/sys/kernel/debug/tracing/trace_pipe`:

```c
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            bash-32969   [000] d..31 64001.375748: bpf_trace_printk: PID 32969 (bash) read: fff 
            bash-32969   [000] d..31 64002.056951: bpf_trace_printk: PID 32969 (bash) read: fff
```

- You can see that we have successfully captured the `readline` function call of `bash` and obtained the command line entered by the user in `bash` .