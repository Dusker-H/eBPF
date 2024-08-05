# Example 6 - Capturing Signal Sending and Store State with Hash Maps

---

- It mainly introduces how to implement an eBPF tool that captures a collection of system calls that send signals to processes and uses a hash map to store state.

### Code

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

struct event {
 unsigned int pid;
 unsigned int tpid;
 int sig;
 int ret;
 char comm[TASK_COMM_LEN];
};

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, __u32);
 __type(value, struct event);
} values SEC(".maps");

static int probe_entry(pid_t tpid, int sig)
{
 struct event event = {};
 __u64 pid_tgid;
 __u32 tid;

 pid_tgid = bpf_get_current_pid_tgid();
 tid = (__u32)pid_tgid;
 event.pid = pid_tgid >> 32;
 event.tpid = tpid;
 event.sig = sig;
 bpf_get_current_comm(event.comm, sizeof(event.comm));
 bpf_map_update_elem(&values, &tid, &event, BPF_ANY);
 return 0;
}

static int probe_exit(void *ctx, int ret)
{
 __u64 pid_tgid = bpf_get_current_pid_tgid();
 __u32 tid = (__u32)pid_tgid;
 struct event *eventp;

 eventp = bpf_map_lookup_elem(&values, &tid);
 if (!eventp)
  return 0;

 eventp->ret = ret;
 bpf_printk("PID %d (%s) sent signal %d ",
           eventp->pid, eventp->comm, eventp->sig);
 bpf_printk("to PID %d, ret = %d",
           eventp->tpid, ret);

cleanup:
 bpf_map_delete_elem(&values, &tid);
 return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter *ctx)
{
 pid_t tpid = (pid_t)ctx->args[0];
 int sig = (int)ctx->args[1];

 return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit *ctx)
{
 return probe_exit(ctx, ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

- 위 코드는 프로세스에 신호를 보내는 시스템 콜(`kill`, `tkill`, `tgkill` 포함)을 캡처하는 eBPF 프로그램을 정의
    - 해당 프로그램은 트레이스포인트를 사용하여 시스템 콜의 진입 및 종료 이벤트를 캡처하고, 이러한 이벤트가 발생하면 `probe_etry` 및 `probe_exit` 와 같은 지정된 프로브 함수를 실행
- Instructions: 프로브 함수에서는 `bpf_map` 을 사용하여 송신 신호의 프로세스 ID, 수신 신호의 프로세스 ID, 신호 값, 현재 작업의 실행 파일 이름 등 캡처한 이벤트 정보를 저장
- 시스템 콜이 종료되면 `bpf_map` 에 저장된 이벤트 정보를 검색하고 `bpf_printk` 를 사용하여 프로세스 ID, 프로세스 이름, 전송된 신호, 시스템 콜의 반환 값을 인쇄
- 마지막으로 `SEC` 매크로를 사용하여 프로브를 정의하고 캡처할 시스템 콜의 이름과 실행할 프로브 함수를 지정해야 함

### Summary

- 해당 예제에서는 주로 프로세스가 신호를 사용하여 전송한 시스템 콜 모음을 캡처하고 해시 맵을 사용하여 상태를 저장하는 eBPF 도구를 구현하는 방법을 소개
- 해시 맵을 사용하려면 구조체를 정의해야 함
    
    ```c
    struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, MAX_ENTRIES);
     __type(key, __u32);
     __type(value, struct event);
    } values SEC(".maps");
    ```
    
- 그리고 액세스에는 해당 API(`bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem`  등)을 사용