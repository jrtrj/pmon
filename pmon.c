#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <net/sock.h>
#include <linux/fs.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

static struct nf_hook_ops nfho;

static unsigned int hook_func(void *priv,
                              struct sk_buff *skb,
                              const struct nf_hook_state *state)
{
    if (!skb)
        return NF_ACCEPT;

    printk(KERN_INFO "PMON: PID %d sent a packet\n", current->pid);

    return NF_ACCEPT;
}

static int __init pmon_init(void)
{
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);

    printk(KERN_INFO "PMON: Hook registered\n");
    return 0;
}

static void __exit pmon_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "PMON: Hook unregistered\n");
}

module_init(pmon_init);
module_exit(pmon_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jerit");
MODULE_DESCRIPTION("Packet Monitor Module");
