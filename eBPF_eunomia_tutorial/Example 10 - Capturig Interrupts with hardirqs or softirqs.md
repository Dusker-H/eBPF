# Example 10 - Capturig Interrupts with hardirqs or softriqs

---

- This article is the tenth part of the eBPF Tutorial by Example, focusing on capturing interrupt events using hardirqs or softirqs in eBPF
- `hardirqs` 와 `softirqs` 는 리눅스 커널에서 서로 다른 두 가지 유형의 인터럽트 처리기
- 이들은 하드웨어 장치에서 생성된 인터럽트 요청과 커널의 비동기 이벤트를 처리하는데 사용
- eBPF 에서는 eBPF 도구인 `hardirqs` 와 `softirqs` 를 사용하여 커널의 인터럽트 처리와 관련된 정보를 캡처하고 분석할 수 있음

### What are hardirqs and softirqs?

- `hardirqs` 는 하드웨어 인터럽트 핸들러
    - 하드웨어 장치가 인터럽트 요청을 생성하면 커널은 이를 특정 인터럽트 벡터에 매핑하고 관련 하드웨어 인터럽트 핸들러를 실행
    - 하드웨어 인터럽트 핸들러는 일반적으로 장치 데이터 전송 완료 또는 장치 오류와 같은 장치 드라이버의 이벤트를 처리하는데 사용
- `softirqs` 는 소프트웨어 인터럽트 핸들러
    - 커널에서 우선순위가 높은 작업을 처리하는 데 사용되는 커널의 저수준 비동기 이벤트 처리 메커니즘
    - 일반적으로 네트워크 프로토콜 스택, 디스크 하위 시스템 및 기타 커널 구성 요소의 이벤트를 처리하는 데 사용
- 하드웨어 인터럽트 핸들러에 비해 소프트웨어 인터럽트 핸들러는 구성 가능성과 유연성이 더 뛰어남

### Implementation Details

- eBPF 에서는 특정 `kprobe` 또는 tracepoint 를 첨부하여 `hardirqs` 와 `softirqs` 를 캡처하고 분석할 수 있음
- `hardirqs` 와 `softirqs` 를 캡처하려면 관련 커널 함수에 eBPF 프로그램을 배치해야함
    - For hardirqs : `irq_handler_entry` and `irq_handler_exit`
    - For softirqs : `softirq_entry` and `softirq_exit`
- 커널이 `hardirq` 또는 `softirq` 를 처리할 때 이러한 eBPF 프로그램이 실행되어 인터럽트 벡터, 인터럽트 핸들러의 실행 시간 등과 같은 관령 정보를 수집
    - 수집된 정보는 커널의 성능 문제 및 기타 인터럽트 처리 관련 문제를 분석하는 데 사용할 수 있음
- 다음 단계에 따라 `hardirqs` 와 `softirqs` 를 캡처할 수 있음
    1. 인터럽트 정보를 저장하기 위한 데이터 구조와 맵을 eBPF 프로그램에 정의
    2. eBPF 프로그램을 작성하고 해당 커널 함수에 첨부하여 `hardirq` 또는 `softirqs` 를 캡처
    3. eBPF 프로그램에서 인터럽트 핸들러와 관련된 정보를 수집하고 이 정보를 맵에 저장
    4. 사용자 공간 애플리케이션에서는 맵에서 데이터를 읽어 인터럽트 처리 정보를 분석하고 표시
- 위 접근 방식에 따라 eBPF 에서 `hardirqs` 와 `softirqs`를 사용하여 커널의 인터럽트 이벤트를 캡처하고 분석하여 잠재적인 성능 문제와 인터럽트 처리 관련 문제를 파악할 수 있음

### Implementation of hardirqs Code

- `hardirqs` 프로그램의 주요 목적은 인터럽트 핸들러의 이름, 실행 횟수, 실행 시간을 구하고 실행 시간 분포를 히스토그램 형태로 표시하는 것

```c
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "hardirqs.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES 256

const volatile bool filter_cg = false;
const volatile bool targ_dist = false;
const volatile bool targ_ns = false;
const volatile bool do_count = false;

struct {
 __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
 __type(key, u32);
 __type(value, u32);
 __uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 __uint(max_entries, 1);
 __type(key, u32);
 __type(value, u64);
} start SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, struct irq_key);
 __type(value, struct info);
} infos SEC(".maps");

static struct info zero;

static int handle_entry(int irq, struct irqaction *action)
{
 if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
  return 0;

 if (do_count) {
  struct irq_key key = {};
  struct info *info;

  bpf_probe_read_kernel_str(&key.name, sizeof(key.name), BPF_CORE_READ(action, name));
  info = bpf_map_lookup_or_try_init(&infos, &key, &zero);
  if (!info)
   return 0;
  info->count += 1;
  return 0;
 } else {
  u64 ts = bpf_ktime_get_ns();
  u32 key = 0;

  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
   return 0;

  bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
  return 0;
 }
}

static int handle_exit(int irq, struct irqaction *action)
{
 struct irq_key ikey = {};
 struct info *info;
 u32 key = 0;
 u64 delta;
 u64 *tsp;

 if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
  return 0;

 tsp = bpf_map_lookup_elem(&start, &key);
 if (!tsp)
  return 0;

 delta = bpf_ktime_get_ns() - *tsp;
 if (!targ_ns)
  delta /= 1000U;

 bpf_probe_read_kernel_str(&ikey.name, sizeof(ikey.name), BPF_CORE_READ(action, name));
 info = bpf_map_lookup_or_try_init(&infos, &ikey, &zero);
 if (!info)
  return 0;

 if (!targ_dist) {
  info->count += delta;
 } else {
  u64 slot;

  slot = log2(delta);
  if (slot >= MAX_SLOTS)
   slot = MAX_SLOTS - 1;
  info->slots[slot]++;
 }

 return 0;
}

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(irq_handler_entry_btf, int irq, struct irqaction *action)
{
 return handle_entry(irq, action);
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(irq_handler_exit_btf, int irq, struct irqaction *action)
{
 return handle_exit(irq, action);
}

SEC("raw_tp/irq_handler_entry")
int BPF_PROG(irq_handler_entry, int irq, struct irqaction *action)
{
 return handle_entry(irq, action);
}

SEC("raw_tp/irq_handler_exit")
int BPF_PROG(irq_handler_exit, int irq, struct irqaction *action)
{
 return handle_exit(irq, action);
}

char LICENSE[] SEC("license") = "GPL";
```

- 이 프로그램의 주요 목적은 인터럽트 핸들러의 이름, 실행 횟수, 실행 시간을 얻고 실행 시간의 분포를 히스토그램 형태로 표시하는 것
1. Include necessary header files and define data structures:
    
    ```c
     	  #include <vmlinux.h>
        #include <bpf/bpf_core_read.h>
        #include <bpf/bpf_helpers.h>
        #include <bpf/bpf_tracing.h>
        #include "hardirqs.h"
        #include "bits.bpf.h"
        #include "maps.bpf.h
    ```
    
2. Define global variables and maps:
- 이 프로그램은 프로그램의 동작을 구성하는 데 사용되는 몇 가지 전역 변수를 정의
- 예를 들어, `filter_cg` 는 `cgroups` 를 필터링할지 여부를 제어하고, `tag_dist` 는 실행 시간 분포를 표시할지 여부 등을 제어
- 또한 이프로그램은 `cgroup` 정보, 시작 타임스탬프, 인터럽트 핸들러 정보를 저정하기 위한 세 가지 맵을 정의

```c
    #define MAX_ENTRIES 256

    const volatile bool filter_cg = false;
    const volatile bool targ_dist = false;
    const volatile bool targ_ns = false;
    const volatile bool do_count = false;
```

1. 핸들러의 진입 지점과 종료 지점에서 호출되는 두 개의 헬퍼 함수 `handle_entry` 와 `handle_exit` 정의
    1. 이 두 함수는 인터럽트 핸들러의 시작과 종료 지점에서 호출 됨
    2. `handle_entry` 는 시작 타임스탬프를 기록하거나 인터럽트 수를 업데이트하고, `handle_exit` 는 인터럽트 핸들러의 실행 시간을 계산하여 결과를 해당 정보 맵에 저장
2. Define the entry points of the eBPF program
- 인터럽트 핸들러의 진입 및 종료 이벤트를 캡처하는 데 사용되는 eBPF 프로그램의 네 가지 진입점이 정의
    - `tp_btf` 와 `raw_tp` 는 각각 BPF 유형 형식과 원시 트레이스 포인트를 사용하여 이벤트를 캡처하는 것을 나타냄
    - 이렇게 하면 프로그램을 다른 커널 버전에서 포팅하고 실행할 수 있음