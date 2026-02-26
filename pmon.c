#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <net/sock.h>
#include <linux/fs.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

static struct nf_hook_ops nfho;

/* Forward declarations */
static int pmon_open(struct inode *inode, struct file *file);
static int pmon_show(struct seq_file *m, void *v);

/* Proc file ops */
static const struct proc_ops pmon_fops = {
    .proc_open = pmon_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/* PID tracking structure */
struct pid_stat {
    pid_t pid;
    u64 bytes;
    struct hlist_node node;
};

DEFINE_HASHTABLE(pid_table, 8);

/* Netfilter hook */
static unsigned int hook_func(void *priv,
                              struct sk_buff *skb,
                              const struct nf_hook_state *state)
{
    struct pid_stat *entry;
    pid_t pid = current->pid;

    if (!skb || pid == 0)
        return NF_ACCEPT;

    hash_for_each_possible(pid_table, entry, node, pid) {
        if (entry->pid == pid) {
            entry->bytes += skb->len;
            return NF_ACCEPT;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return NF_ACCEPT;

    entry->pid = pid;
    entry->bytes = skb->len;

    hash_add(pid_table, &entry->node, pid);

    return NF_ACCEPT;
}

/* Proc show */
static int pmon_show(struct seq_file *m, void *v)
{
    struct pid_stat *entry;
    int bkt;

    seq_printf(m, "PID\tBYTES\n");

    hash_for_each(pid_table, bkt, entry, node) {
        seq_printf(m, "%d\t%llu\n", entry->pid, entry->bytes);
    }

    return 0;
}

/* Proc open */
static int pmon_open(struct inode *inode, struct file *file)
{
    return single_open(file, pmon_show, NULL);
}

/* Module load */
static int __init pmon_init(void)
{
    hash_init(pid_table);

    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);

    proc_create("pmon", 0, init_net.proc_net, &pmon_fops);

    printk(KERN_INFO "PMON: Hook registered\n");
    return 0;
}

/* Module unload */
static void __exit pmon_exit(void)
{
    struct pid_stat *entry;
    struct hlist_node *tmp;
    int bkt;

    remove_proc_entry("pmon", init_net.proc_net);

    hash_for_each_safe(pid_table, bkt, tmp, entry, node) {
        hash_del(&entry->node);
        kfree(entry);
    }

    nf_unregister_net_hook(&init_net, &nfho);

    printk(KERN_INFO "PMON: Hook unregistered\n");
}

module_init(pmon_init);
module_exit(pmon_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jerit");
MODULE_DESCRIPTION("Per-PID Network Usage Tracker");
