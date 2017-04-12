/* DataCenter TCP (DCTCP) congestion control.
 *
 * http://simula.stanford.edu/~alizade/Site/DCTCP.html
 *
 * This is an implementation of DCTCP over Reno, an enhancement to the
 * TCP congestion control algorithm designed for data centers. DCTCP
 * leverages Explicit Congestion Notification (ECN) in the network to
 * provide multi-bit feedback to the end hosts. DCTCP's goal is to meet
 * the following three data center transport requirements:
 *
 *  - High burst tolerance (incast due to partition/aggregate)
 *  - Low latency (short flows, queries)
 *  - High throughput (continuous data updates, large file transfers)
 *    with commodity shallow buffered switches
 *
 * The algorithm is described in detail in the following two papers:
 *
 * 1) Mohammad Alizadeh, Albert Greenberg, David A. Maltz, Jitendra Padhye,
 *    Parveen Patel, Balaji Prabhakar, Sudipta Sengupta, and Murari Sridharan:
 *      "Data Center TCP (DCTCP)", Data Center Networks session
 *      Proc. ACM SIGCOMM, New Delhi, 2010.
 *   http://simula.stanford.edu/~alizade/Site/DCTCP_files/dctcp-final.pdf
 *
 * 2) Mohammad Alizadeh, Adel Javanmard, and Balaji Prabhakar:
 *      "Analysis of DCTCP: Stability, Convergence, and Fairness"
 *      Proc. ACM SIGMETRICS, San Jose, 2011.
 *   http://simula.stanford.edu/~alizade/Site/DCTCP_files/dctcp_analysis-full.pdf
 *
 * Initial prototype from Abdul Kabbani, Masato Yasuda and Mohammad Alizadeh.
 *
 * Authors:
 *
 *	Daniel Borkmann <dborkman@redhat.com>
 *	Florian Westphal <fw@strlen.de>
 *	Glenn Judd <glenn.judd@morganstanley.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#include <linux/hashtable.h>
#include <linux/inet_diag.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "crc_table.h"
#include "exp_table.h"

#define DCTCP_MAX_ALPHA	1024U
#define NETLINK_D2TCP 31

struct dctcp {
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 dctcp_alpha;
	u32 next_seq;
	u32 ce_state;
	u32 delayed_ack_reserved;
};

struct ctrl_msg {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 size;
	u32 time_to_ddl;
};

struct flow_info {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 curr_seq;
	u32 target_seq;
	ktime_t end_time;
	struct hlist_node hash_list;
};

static unsigned int dctcp_shift_g __read_mostly = 4; /* g = 1/2^4 */
module_param(dctcp_shift_g, uint, 0644);
MODULE_PARM_DESC(dctcp_shift_g, "parameter g for updating dctcp_alpha");

static unsigned int dctcp_alpha_on_init __read_mostly = DCTCP_MAX_ALPHA;
module_param(dctcp_alpha_on_init, uint, 0644);
MODULE_PARM_DESC(dctcp_alpha_on_init, "parameter for initial alpha value");

static unsigned int dctcp_clamp_alpha_on_loss __read_mostly;
module_param(dctcp_clamp_alpha_on_loss, uint, 0644);
MODULE_PARM_DESC(dctcp_clamp_alpha_on_loss,
		 "parameter for clamping alpha on loss");

static unsigned short param_port __read_mostly = 0;
MODULE_PARM_DESC(param_port, "Port to match (0=all)");
module_param(param_port, ushort, 0);

static struct tcp_congestion_ops dctcp_reno;

DEFINE_HASHTABLE(hash_table, 8);

static struct sock *nl_sk = NULL;

static int seq_after(u32 seq1, u32 seq2)
{
	return (s32) (seq1 - seq2) > 0;
}

static u16 crc16(u32 saddr, u32 daddr, u16 sport, u16 dport)
{
	u16 id_segments[6] = {saddr >> 16, saddr & 0xffff, sport,
			      daddr >> 16, daddr & 0xffff, dport};
	unsigned char *byte_ptr = (unsigned char*) id_segments;
	u16 hash_code = 0;
	int i;
	for (i = 0; i < 12; i++)
		hash_code = (hash_code << 8) ^
			    CRC_HASH_TABLE[(hash_code >> 8) ^ byte_ptr[i]];
	return hash_code;
}

#ifdef D2TCP_DEBUG
static void print_table(void)
{
	int last_bkt = -1;
	int curr_bkt;
	struct flow_info *object;

	hash_for_each(hash_table, curr_bkt, object, hash_list) {
		if (curr_bkt != last_bkt) {
			printk(KERN_INFO "In bucket %d:\n", curr_bkt);
			last_bkt = curr_bkt;
		}
		printk(KERN_INFO "%pI4h:%hu to %pI4h:%hu, curr seq is %u\n",
		       &(object->saddr), object->sport,
		       &(object->daddr), object->dport, object->curr_seq);
	}
}
#endif

static void insert_to_table(u32 saddr, u32 daddr,
			    u16 sport, u16 dport, u32 curr_seq)
{
	u16 hash_key = crc16(saddr, daddr, sport, dport);
	struct flow_info *object;

	hash_for_each_possible(hash_table, object, hash_list, hash_key) {
		if (object->saddr == saddr && object->daddr == daddr &&
		    object->sport == sport && object->dport == dport &&
		    seq_after(curr_seq, object->curr_seq)) {
			object->curr_seq = curr_seq;
			return;
		}
	}

	object = kmalloc(sizeof(struct flow_info), GFP_ATOMIC);
	if (likely(object)) {
		object->saddr = saddr;
		object->daddr = daddr;
		object->sport = sport;
		object->dport = dport;
		object->curr_seq = curr_seq;
		hash_add(hash_table, &(object->hash_list), hash_key); 
	}
}

static void delete_from_table(u32 saddr, u32 daddr, u16 sport, u16 dport)
{
	u16 hash_key = crc16(saddr, daddr, sport, dport);
	struct flow_info *object;

	hash_for_each_possible(hash_table, object, hash_list, hash_key) {
		if (object->saddr == saddr && object->daddr == daddr &&
		    object->sport == sport && object->dport == dport) {
			hash_del(&(object->hash_list));
			kfree(object);
			return;
		}
	}
}

static void update_table(u32 saddr, u32 daddr,
			 u16 sport, u16 dport, u32 curr_seq)
{
	u16 hash_key = crc16(saddr, daddr, sport, dport);
	struct flow_info *object;

	hash_for_each_possible(hash_table, object, hash_list, hash_key) {
		if (object->saddr == saddr && object->daddr == daddr &&
		    object->sport == sport && object->dport == dport &&
		    seq_after(curr_seq, object->curr_seq)) {
			object->curr_seq = curr_seq;
			return;
		}
	}
}

static unsigned int
inspect_sequence(unsigned int hooknum, struct sk_buff *skb,
		 const struct net_device* in, const struct net_device *out,
		 int (*okfn) (struct sk_buff*))
{
	struct iphdr *ip_header = (struct iphdr*) skb_network_header(skb);
	if (unlikely(!ip_header) || ip_header->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	struct tcphdr *tcp_header = (struct tcphdr*) skb_transport_header(skb);
	u16 sport = be16_to_cpu(tcp_header->source);
	u16 dport = be16_to_cpu(tcp_header->dest);
	if (param_port && sport != param_port && dport != param_port)
		return NF_ACCEPT;

	u32 saddr = be32_to_cpu(ip_header->saddr);
	u32 daddr = be32_to_cpu(ip_header->daddr);
	u32 seq = be32_to_cpu(tcp_header->seq);

	if (tcp_header->syn) {
	#ifdef D2TCP_DEBUG
		printk(KERN_INFO "Before SYN:\n");
		print_table();
	#endif
		insert_to_table(saddr, daddr, sport, dport, seq);
	#ifdef D2TCP_DEBUG
		printk(KERN_INFO "After SYN:\n");
		print_table();
	#endif
	} else if (tcp_header->fin) {
	#ifdef D2TCP_DEBUG
		printk(KERN_INFO "Before FIN:\n");
		print_table();
	#endif
		delete_from_table(saddr, daddr, sport, dport);
	#ifdef D2TCP_DEBUG
		printk(KERN_INFO "After FIN:\n");
		print_table();
	#endif
	} else {
		update_table(saddr, daddr, sport, dport, seq);
	}

	return NF_ACCEPT;
}

static void recv_d2tcp_ctrl_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	struct ctrl_msg *recv_payload;
	struct ctrl_msg echo_payload;

	nlh = (struct nlmsghdr*) skb->data;
	recv_payload = (struct ctrl_msg*) nlmsg_data(nlh);
#ifdef D2TCP_DEBUG
	printk(KERN_INFO "Before netlink update:\n");
	print_table();
#endif
	u16 hash_key = crc16(recv_payload->saddr, recv_payload->daddr,
			     recv_payload->sport, recv_payload->dport);
	struct flow_info *object;
	hash_for_each_possible(hash_table, object, hash_list, hash_key) {
		if (object->saddr == recv_payload->saddr &&
		    object->daddr == recv_payload->daddr &&
		    object->sport == recv_payload->sport &&
		    object->dport == recv_payload->dport) {
			object->target_seq = object->curr_seq + recv_payload->size;
			object->end_time = ktime_add_us(ktime_get(), recv_payload->time_to_ddl); // TODO: handle netlink delay here??
		#ifdef D2TCP_DEBUG
			printk(KERN_INFO "end_seq: %u; end_time: %lld\n", object->target_seq, ktime_to_us(object->end_time));
		#endif
			break;
		}
	}
#ifdef D2TCP_DEBUG
	printk(KERN_INFO "After netlink update:\n");
	print_table();
#endif
	echo_payload = *recv_payload;
	pid = nlh->nlmsg_pid;
	skb_out = nlmsg_new(sizeof(echo_payload), 0);
	if(unlikely(!skb_out))
		return;
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sizeof(echo_payload), 0);
	NETLINK_CB(skb_out).dst_group = 0;
	memcpy(nlmsg_data(nlh), &echo_payload, sizeof(echo_payload));
	nlmsg_unicast(nl_sk, skb_out, pid);
}

static void dctcp_reset(const struct tcp_sock *tp, struct dctcp *ca)
{
	ca->next_seq = tp->snd_nxt;

	ca->acked_bytes_ecn = 0;
	ca->acked_bytes_total = 0;
}

static void dctcp_init(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if ((tp->ecn_flags & TCP_ECN_OK) ||
	    (sk->sk_state == TCP_LISTEN ||
	     sk->sk_state == TCP_CLOSE)) {
		struct dctcp *ca = inet_csk_ca(sk);

		ca->prior_snd_una = tp->snd_una;
		ca->prior_rcv_nxt = tp->rcv_nxt;

		ca->dctcp_alpha = min(dctcp_alpha_on_init, DCTCP_MAX_ALPHA);

		ca->delayed_ack_reserved = 0;
		ca->ce_state = 0;

		dctcp_reset(tp, ca);
		return;
	}

	/* No ECN support? Fall back to Reno. Also need to clear
	 * ECT from sk since it is set during 3WHS for DCTCP.
	 */
	inet_csk(sk)->icsk_ca_ops = &dctcp_reno;
	INET_ECN_dontxmit(sk);
}

/* Calculates p = alpha ^ d in D2TCP.
 *
 * alpha should be in [0, 1024], corresponding to [0, 1] in D2TCP.
 * d should be in [64, 256], corresponding to [0.5, 2] in D2TCP.
 *
 * The 1-D exp_results array stores the results, in which every consecutive
 * 193 elements, starting at the indices that are multiple of 193,
 * correspond to one value of alpha and 193 values of d (64 to 256).
 * So exp(alpha, d) = exp_results[193 * alpha + d - 64].
 *
 * Return value is in [0, 1024], corresponding to [0, 1] in D2TCP.
 */
static inline u32 d2tcp_exp(u32 alpha, u16 d)
{
	return exp_results[(alpha << 7) + (alpha << 6) + alpha + d - 64];
}

static u32 dctcp_ssthresh(struct sock *sk)
{
	const struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);

	u32 saddr = be32_to_cpu(inet->inet_saddr);
	u32 daddr = be32_to_cpu(inet->inet_daddr);
	u16 sport = be16_to_cpu(inet->inet_sport);
	u16 dport = be16_to_cpu(inet->inet_dport);

	u16 hash_key = crc16(saddr, daddr, sport, dport);
	struct flow_info *object;
	u16 d = 128; // If hashed object not found, 128 is the default fall-back.

	hash_for_each_possible(hash_table, object, hash_list, hash_key) {
		if (object->saddr == saddr && object->daddr == daddr &&
		    object->sport == sport && object->dport == dport) {
			s64 remaining_time = ktime_us_delta(object->end_time, ktime_get());
			if (remaining_time <= 0)
				break;
			u32 remaining_num_bytes = object->target_seq - ca->next_seq;
			d = ((tp->srtt_us * remaining_num_bytes) << 7) /
			    (1125U * tp->snd_cwnd * remaining_time); // TODO: handle multiplication overflow?
			d = (d < 64) ? 64 : ((d > 256) ? 256 : d);
		#ifdef D2TCP_DEBUG
			printk(KERN_INFO "ssthresh of %pI4h:%hu to %pI4h:%hu\n",
			       &saddr, sport, &daddr, dport);
			printk(KERN_INFO "time(end:now:left): %lld, %lld, %lld\n",
			       ktime_to_us(object->end_time),
			       ktime_to_us(ktime_get()), remaining_time);
			printk(KERN_INFO "seq(end:now:left): %u, %u, %u\n",
				object->target_seq, ca->next_seq,
				remaining_num_bytes);
			printk(KERN_INFO "cwnd: %u, rtt: %u\n",
			       tp->snd_cwnd, tp->srtt_us);
		#endif
			break;
		}
	}

	u32 p = d2tcp_exp(ca->dctcp_alpha, d);
#ifdef D2TCP_DEBUG
	printk(KERN_INFO "d: %hu, p: %u\n", d, p);
#endif
	return max(tp->snd_cwnd - ((tp->snd_cwnd * p) >> 11U), 2U);
	//return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->dctcp_alpha) >> 11U), 2U);
}

/* Minimal DCTP CE state machine:
 *
 * S:	0 <- last pkt was non-CE
 *	1 <- last pkt was CE
 */

static void dctcp_ce_state_0_to_1(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=0 to CE=1 and delayed
	 * ACK has not sent yet.
	 */
	if (!ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=0. */
		tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 1;

	tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
}

static void dctcp_ce_state_1_to_0(struct sock *sk)
{
	struct dctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=1 to CE=0 and delayed
	 * ACK has not sent yet.
	 */
	if (ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=1. */
		tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 0;

	tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
}

static void dctcp_update_alpha(struct sock *sk, u32 flags)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);
	u32 acked_bytes = tp->snd_una - ca->prior_snd_una;

	/* If ack did not advance snd_una, count dupack as MSS size.
	 * If ack did update window, do not count it at all.
	 */
	if (acked_bytes == 0 && !(flags & CA_ACK_WIN_UPDATE))
		acked_bytes = inet_csk(sk)->icsk_ack.rcv_mss;
	if (acked_bytes) {
		ca->acked_bytes_total += acked_bytes;
		ca->prior_snd_una = tp->snd_una;

		if (flags & CA_ACK_ECE)
			ca->acked_bytes_ecn += acked_bytes;
	}

	/* Expired RTT */
	if (!before(tp->snd_una, ca->next_seq)) {
		/* For avoiding denominator == 1. */
		if (ca->acked_bytes_total == 0)
			ca->acked_bytes_total = 1;

		/* alpha = (1 - g) * alpha + g * F */
		ca->dctcp_alpha = ca->dctcp_alpha -
				  (ca->dctcp_alpha >> dctcp_shift_g) +
				  (ca->acked_bytes_ecn << (10U - dctcp_shift_g)) /
				  ca->acked_bytes_total;

		if (ca->dctcp_alpha > DCTCP_MAX_ALPHA)
			/* Clamp dctcp_alpha to max. */
			ca->dctcp_alpha = DCTCP_MAX_ALPHA;

		dctcp_reset(tp, ca);
	}
}

static void dctcp_state(struct sock *sk, u8 new_state)
{
	if (dctcp_clamp_alpha_on_loss && new_state == TCP_CA_Loss) {
		struct dctcp *ca = inet_csk_ca(sk);

		/* If this extension is enabled, we clamp dctcp_alpha to
		 * max on packet loss; the motivation is that dctcp_alpha
		 * is an indicator to the extend of congestion and packet
		 * loss is an indicator of extreme congestion; setting
		 * this in practice turned out to be beneficial, and
		 * effectively assumes total congestion which reduces the
		 * window by half.
		 */
		ca->dctcp_alpha = DCTCP_MAX_ALPHA;
	}
}

static void dctcp_update_ack_reserved(struct sock *sk, enum tcp_ca_event ev)
{
	struct dctcp *ca = inet_csk_ca(sk);

	switch (ev) {
	case CA_EVENT_DELAYED_ACK:
		if (!ca->delayed_ack_reserved)
			ca->delayed_ack_reserved = 1;
		break;
	case CA_EVENT_NON_DELAYED_ACK:
		if (ca->delayed_ack_reserved)
			ca->delayed_ack_reserved = 0;
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}

static void dctcp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	switch (ev) {
	case CA_EVENT_ECN_IS_CE:
		dctcp_ce_state_0_to_1(sk);
		break;
	case CA_EVENT_ECN_NO_CE:
		dctcp_ce_state_1_to_0(sk);
		break;
	case CA_EVENT_DELAYED_ACK:
	case CA_EVENT_NON_DELAYED_ACK:
		dctcp_update_ack_reserved(sk, ev);
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}

static void dctcp_get_info(struct sock *sk, u32 ext, struct sk_buff *skb)
{
	const struct dctcp *ca = inet_csk_ca(sk);

	/* Fill it also in case of VEGASINFO due to req struct limits.
	 * We can still correctly retrieve it later.
	 */
	if (ext & (1 << (INET_DIAG_DCTCPINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcp_dctcp_info info;

		memset(&info, 0, sizeof(info));
		if (inet_csk(sk)->icsk_ca_ops != &dctcp_reno) {
			info.dctcp_enabled = 1;
			info.dctcp_ce_state = (u16) ca->ce_state;
			info.dctcp_alpha = ca->dctcp_alpha;
			info.dctcp_ab_ecn = ca->acked_bytes_ecn;
			info.dctcp_ab_tot = ca->acked_bytes_total;
		}

		nla_put(skb, INET_DIAG_DCTCPINFO, sizeof(info), &info);
	}
}

static struct tcp_congestion_ops dctcp __read_mostly = {
	.init		= dctcp_init,
	.in_ack_event   = dctcp_update_alpha,
	.cwnd_event	= dctcp_cwnd_event,
	.ssthresh	= dctcp_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.set_state	= dctcp_state,
	.get_info	= dctcp_get_info,
	.flags		= TCP_CONG_NEEDS_ECN,
	.owner		= THIS_MODULE,
	.name		= "d2tcp",
};

static struct tcp_congestion_ops dctcp_reno __read_mostly = {
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.get_info	= dctcp_get_info,
	.owner		= THIS_MODULE,
	.name		= "d2tcp-reno",
};

static struct nf_hook_ops nfho = {
        .hook = inspect_sequence,
        .hooknum = 3, // NF_IP_LOCAL_OUT,
        .pf = PF_INET,
        .priority = NF_IP_PRI_FIRST,
};

static int __init dctcp_register(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = recv_d2tcp_ctrl_msg,
	};
	nl_sk = netlink_kernel_create(&init_net, NETLINK_D2TCP, &cfg);
	if (!nl_sk) {
		printk(KERN_ALERT "Error creating socket.\n");
	}

	nf_register_hook(&nfho);

	BUILD_BUG_ON(sizeof(struct dctcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&dctcp);
}

static void __exit dctcp_unregister(void)
{
	netlink_kernel_release(nl_sk);
	nf_unregister_hook(&nfho);
	tcp_unregister_congestion_control(&dctcp);
}

module_init(dctcp_register);
module_exit(dctcp_unregister);

MODULE_AUTHOR("Daniel Borkmann <dborkman@redhat.com>");
MODULE_AUTHOR("Florian Westphal <fw@strlen.de>");
MODULE_AUTHOR("Glenn Judd <glenn.judd@morganstanley.com>");

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("D2TCP (incomplete)");
