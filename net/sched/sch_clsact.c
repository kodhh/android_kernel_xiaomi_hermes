/* net/sched/sch_clsact.c - clsact qdisc
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Jamal Hadi Salim 1999
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>

#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

struct clsact_qdisc_data {
	struct tcf_proto	*ingress_filter_list;
	struct tcf_proto	*egress_filter_list;
};

static struct Qdisc *clsact_leaf(struct Qdisc *sch, unsigned long arg)
{
	return NULL;
}

static unsigned long clsact_get(struct Qdisc *sch, u32 classid)
{
	switch (TC_H_MIN(classid)) {
	case TC_H_MIN_INGRESS:
	case TC_H_MIN_EGRESS:
		return TC_H_MIN(classid);
	default:
		return 0;
	}
}

static unsigned long clsact_bind_filter(struct Qdisc *sch,
					unsigned long parent, u32 classid)
{
	return clsact_get(sch, classid);
}

static void clsact_put(struct Qdisc *sch, unsigned long cl)
{
}

static void clsact_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
}

static struct tcf_proto **clsact_find_tcf(struct Qdisc *sch, unsigned long cl)
{
	struct clsact_qdisc_data *p = qdisc_priv(sch);

	switch (cl) {
	case TC_H_MIN_INGRESS:
		return &p->ingress_filter_list;
	case TC_H_MIN_EGRESS:
		return &p->egress_filter_list;
	default:
		return NULL;
	}
}

static int clsact_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct clsact_qdisc_data *p = qdisc_priv(sch);
	struct tcf_result res;
	int result;

	result = tc_classify(skb, p->ingress_filter_list, &res);

	qdisc_bstats_update(sch, skb);
	switch (result) {
	case TC_ACT_SHOT:
		result = TC_ACT_SHOT;
		sch->qstats.drops++;
		break;
	case TC_ACT_STOLEN:
	case TC_ACT_QUEUED:
		result = TC_ACT_STOLEN;
		break;
	case TC_ACT_RECLASSIFY:
	case TC_ACT_OK:
		skb->tc_index = TC_H_MIN(res.classid);
	default:
		result = TC_ACT_OK;
		break;
	}

	return result;
}

static int clsact_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct nlattr *nest;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;
	nla_nest_end(skb, nest);
	return skb->len;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static const struct Qdisc_class_ops clsact_class_ops = {
	.leaf		=	clsact_leaf,
	.get		=	clsact_get,
	.put		=	clsact_put,
	.walk		=	clsact_walk,
	.tcf_chain	=	clsact_find_tcf,
	.bind_tcf	=	clsact_bind_filter,
	.unbind_tcf	=	clsact_put,
};

static int clsact_init(struct Qdisc *sch, struct nlattr *opt)
{
	sch->flags |= TCQ_F_INGRESS | TCQ_F_EGRESS;
	return 0;
}

static void clsact_destroy(struct Qdisc *sch)
{
	struct clsact_qdisc_data *p = qdisc_priv(sch);

	tcf_destroy_chain(&p->ingress_filter_list);
	tcf_destroy_chain(&p->egress_filter_list);
}

static struct Qdisc_ops clsact_qdisc_ops __read_mostly = {
	.cl_ops		=	&clsact_class_ops,
	.id		=	"clsact",
	.priv_size	=	sizeof(struct clsact_qdisc_data),
	.init		=	clsact_init,
	.enqueue	=	clsact_enqueue,
	.destroy	=	clsact_destroy,
	.dump		=	clsact_dump,
	.owner		=	THIS_MODULE,
};

static int __init clsact_module_init(void)
{
	return register_qdisc(&clsact_qdisc_ops);
}

static void __exit clsact_module_exit(void)
{
	unregister_qdisc(&clsact_qdisc_ops);
}

module_init(clsact_module_init);
module_exit(clsact_module_exit);
MODULE_LICENSE("GPL");
