/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * BPF program to set base_rtt to 80us when host is running TCP-NV and
 * both hosts are in the same datacenter (as determined by IPv6 prefix).
 *
 * Use load_sock_ops to load this BPF program.
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <linux/socket.h>
#include <linux/string.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define DEBUG 1
#define bpf_printk(fmt, ...)                       \
	({                                             \
		char ____fmt[] = fmt;                      \
		bpf_trace_printk(____fmt, sizeof(____fmt), \
						 ##__VA_ARGS__);           \
	})
struct bpf_map_def SEC("maps") cong_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(long),
	.value_size = 10,
	.max_entries = 100,
	.map_flags = BPF_F_NO_PREALLOC,
};
struct bpf_map_def SEC("maps") ip_cong_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(long),
	.value_size = 10,
	.max_entries = 100,
	.map_flags = BPF_F_NO_PREALLOC,
};

static inline void init_map()
{
	long key0 = 0;
	char a[] = "illinois";
	bpf_map_update_elem(&cong_map, &key0, a, BPF_ANY);
	//本ip对应的数字
	long ikey = 3232252746;
	char b[] = "dctcp";
	bpf_map_update_elem(&ip_cong_map, &ikey, b, BPF_ANY);
}
SEC("sockops")
int bpf_basertt(struct bpf_sock_ops *skops)
{
	init_map();
	int op = (int)skops->op;
	// 计算出key值,ip使用了inet_aton将ip转化成了long
	long dport = (long)bpf_ntohl(skops->remote_port);
	long lport = (long)skops->local_port;
	long nlip = (long)bpf_ntohl(skops->local_ip4);
	long ndip = (long)bpf_ntohl(skops->remote_ip4);
	bpf_printk("dport :%ld lport:%ld\n", dport, lport);
	bpf_printk("nlip :%ld ndip:%ld\n", nlip, ndip);
	switch (op)
	{
	//接收到ack:
	case BPF_SOCK_OPS_TCP_ACK_CB:
		bpf_printk("enter BPF_SOCK_OPS_TCP_ACK_CB\n");
		//看看是否需要进行拥塞算法更新
		long cc_id = dport;

		char *con_str = bpf_map_lookup_elem(&cong_map, &cc_id);
		bpf_printk("constr: %s\n", con_str);
		char cong[20];
		bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION,
					   cong, sizeof(cong));
		bpf_printk("before cc:%s\n", cong);

		if (con_str == NULL)
		{
			return 1;
		}

		bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, con_str, 10);
		bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cong, sizeof(cong));
		//int r = bpf_map_delete_elem(&cong_map, &cc_id);
		//if (r == 0)
			//bpf_printk("Element deleted from the map\n");
		//else
		//	bpf_printk("Failed to delete element from the map: %d\n", r);
		//break;

		bpf_printk("after cc:%s\n", cong);

		break;

	// 连接初始化
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		bpf_printk("enter BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB\n");
		//看看是否需要进行拥塞算法更新
		long ip_cc_id = ndip;
		bpf_printk("ip_cc_id %ld\n", ip_cc_id);

		char *ip_con_str = bpf_map_lookup_elem(&ip_cong_map, &ip_cc_id);
		bpf_printk("constr: %s\n", ip_con_str);
		char ip_cong[20];
		bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION,
					   ip_cong, sizeof(ip_cong));
		bpf_printk("before cc:%s\n", ip_cong);

		if (ip_con_str == NULL)
		{
			return 1;
		}

		bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, ip_con_str, 10);
		bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, ip_cong, sizeof(ip_cong));

		bpf_printk("after cc:%s\n", ip_cong);
		break;

	//连接关闭:
	case BPF_SOCK_OPS_TCL_CLOSE_CB:
		bpf_printk("enter BPF_SOCK_OPS_TCL_CLOSE_CB\n");
		// 将key值从map中去除
		int res = bpf_map_delete_elem(&cong_map, &dport);
		if (res == 0)
			bpf_printk("Element deleted from the map\n");
		else
			bpf_printk("Failed to delete element from the map: %d\n", res);
		break;
	default:
		bpf_printk("enter default\n");
		//看看是否需要进行拥塞算法更新
		break;
	}
	char nv[] = "nv";
	int rv = 0, n;
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
