#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES 10240
#define MAX_URL_LEN 256

// 网络连接统计结构
struct network_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u64 bytes;
    __u64 timestamp;
    char url[MAX_URL_LEN];
};

// IP连接计数结构
struct ip_stats {
    __u32 connection_count;
    __u64 bytes_sent;
    __u64 bytes_received;
    __u64 last_seen;
};

// 系统资源事件结构
struct system_event {
    __u32 pid;
    __u32 cpu_usage;
    __u64 memory_usage;
    __u64 disk_io;
    __u64 timestamp;
    char comm[16];
};

// Maps定义
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);  // IP地址
    __type(value, struct ip_stats);
} ip_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} network_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} system_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);  // IP地址
    __type(value, __u8); // 1表示被封禁
} banned_ips SEC(".maps");

// 网络数据包监控
SEC("xdp")
int monitor_network(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    __u32 src_ip = bpf_ntohl(ip->saddr);
    __u32 dst_ip = bpf_ntohl(ip->daddr);
    
    // 检查是否为被封禁的IP
    __u8 *banned = bpf_map_lookup_elem(&banned_ips, &src_ip);
    if (banned && *banned == 1) {
        return XDP_DROP;  // 丢弃被封禁IP的数据包
    }
    
    // 更新IP统计信息
    struct ip_stats *stats = bpf_map_lookup_elem(&ip_stats_map, &src_ip);
    if (!stats) {
        struct ip_stats new_stats = {
            .connection_count = 1,
            .bytes_sent = bpf_ntohs(ip->tot_len),
            .bytes_received = 0,
            .last_seen = bpf_ktime_get_ns()
        };
        bpf_map_update_elem(&ip_stats_map, &src_ip, &new_stats, BPF_ANY);
    } else {
        stats->connection_count++;
        stats->bytes_sent += bpf_ntohs(ip->tot_len);
        stats->last_seen = bpf_ktime_get_ns();
    }
    
    // 发送网络事件到用户空间
    struct network_event *event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event)
        return XDP_PASS;
    
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->protocol = ip->protocol;
    event->bytes = bpf_ntohs(ip->tot_len);
    event->timestamp = bpf_ktime_get_ns();
    
    // 解析TCP/UDP端口
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) <= data_end) {
            event->src_port = bpf_ntohs(tcp->source);
            event->dst_port = bpf_ntohs(tcp->dest);
            
            // 尝试解析HTTP请求中的URL
            if (event->dst_port == 80 || event->dst_port == 8080) {
                char *payload = (char *)(tcp + 1);
                int payload_len = data_end - (void *)payload;
                
                // 简单的HTTP GET请求解析
                if (payload_len > 4 && payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') {
                    int url_start = 4;
                    int url_len = 0;
                    
                    for (int i = url_start; i < payload_len && i < (url_start + MAX_URL_LEN - 1); i++) {
                        if (payload[i] == ' ' || payload[i] == '\r' || payload[i] == '\n')
                            break;
                        if (i - url_start < MAX_URL_LEN - 1) {
                            event->url[i - url_start] = payload[i];
                            url_len++;
                        }
                    }
                    event->url[url_len] = '\0';
                }
            }
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) <= data_end) {
            event->src_port = bpf_ntohs(udp->source);
            event->dst_port = bpf_ntohs(udp->dest);
        }
    }
    
    bpf_ringbuf_submit(event, 0);
    
    return XDP_PASS;
}

// 系统资源监控
SEC("tracepoint/sched/sched_process_exec")
int monitor_process_exec(void *ctx) {
    struct system_event *event = bpf_ringbuf_reserve(&system_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // 这里可以添加更多的系统资源监控逻辑
    // 由于eBPF的限制，一些系统资源信息需要在用户空间获取
    
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

// CPU使用率监控
SEC("perf_event")
int monitor_cpu_usage(struct bpf_perf_event_data *ctx) {
    struct system_event *event = bpf_ringbuf_reserve(&system_events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // CPU使用率需要在用户空间计算
    event->cpu_usage = 0;
    
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

char _license[] SEC("license") = "GPL";