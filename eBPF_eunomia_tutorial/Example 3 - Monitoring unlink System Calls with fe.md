# Example 3 - Monitoring unlink System Calls with fentry

---

- This article is third part of the eBPF Tutorial by Example, focusing on capturing unlink system calls using fentry in eBPF.

### Fentry

- fentry (function entry) and fexit(function exit) are two types of probes in eBPF used for tracing at the entry and exit points of Linux kernel functions.
    - 이를 통해 개발자는 커널 함수 실행의 특정 단계에서 정보를 수집하고, 매개변수를 수정하거나, 반환값을 관찰할 수 있음
    - 이 추적 및 모니터링 기능은 성능 분석, 문제 해결 및 보안 분석 시나리오에서 매우 유용함
- Compared to kprobes,
    - `fentry`와 `fexit` 프로그램은 성능과 가용성이 더 높음
    - 이 예제에서는 다양한 read helpers 없이도 일반 C 코드처럼 함수의 매개변수에 대한 포인터에 직접 액세스 할 수 있음
        - `read_helpers` eBPF 프로그램이 안전하게 메모리에 접근하여 데이터를 읽어올 수 있도록 도와주는 함수들
- `fexit` 프로그램과 `kretprobe` 프로그램의 주요 차이점
    - `fexit` 프로그램은 함수의 입력 매개변수와 반환 값에 모두 액세스 할 수 있는 반면, `kretprobe` 프로그램은 반환 값에만 액세스할 수 있다는 차이가 있음
    
    ```c
    #include "vmlinux.h"
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_tracing.h>
    
    char LICENSE[] SEC("license") = "Dual BSD/GPL";
    
    SEC("fentry/do_unlinkat")
    int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
    {
        pid_t pid;
    
        pid = bpf_get_current_pid_tgid() >> 32;
        bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
        return 0;
    }
    
    SEC("fexit/do_unlinkat")
    int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
    {
        pid_t pid;
    
        pid = bpf_get_current_pid_tgid() >> 32;
        bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
        return 0;
    }
    ```
    
- 해당 프로그램은 BPF `fentry` 와 `fexit` 프로브를 사용하여 Linux 커널 함수 `do_unlinkat` 을 추적합니다.
- 이 프로그램은 다음 부분으로 구성 됨
    1. 헤더 파일 포함
        - `vmlinux.h(커널 데이터 구조에 액세스하기 위함)` , `bpf/bpf_helpers.h(eBPF helper fuctions가 포함)`, `bpf/bpf_tracing.h(eBPF 추적 관련 기능 포함)`
    2. 라이선스 정의
        - `"Dual BSD/GPL"`  라이서는 정보가 포함된 문자 배열 정의
    3. `fentry 프로브 정의`
        - `do_unlinkat` 함수의 진입 지점에서 트리거되는 `BPF_PROG(do_unlinkat)` 라는 이름의 펜트리 프로브를 정의
        - 이 프로브는 현재 프로세스의 PID를 검색하여 파일 이름과 함께 커널 로그에 출력
    4. `fexit 프로브 정의`
        - `do_unlinkat` 함수의 종료 지점에서 트리거되는 `BPF_PROG(do_unlinkat_exit)` 라는 이름의 종료 프로브도 정의
        - `fentry` 프로브와 마찬가지로 이 프로브도 현재 프로세스의 PID를 검색하여 파일 이름 및 반환 값과 함께 커널 로그에 출력
- To compile and run the above code:
    
    ```c
    $ ecc fentry-link.bpf.c
    Compiling bpf object...
    Packing ebpf object and config into package.json...
    $ sudo ecli run package.json
    Running eBPF program...
    ```
    

- In another window:
    
    ```c
    touch test_file
    rm test_file
    touch test_file2
    rm test_file2
    ```
    

- After running this program, you can view the output of the eBPF program by examing the `/sys/kernel/debug/tracing/trace_pipe` file:
    
    ```c
    $ sudo cat /sys/kernel/debug/tracing/trace_pipe
    ```