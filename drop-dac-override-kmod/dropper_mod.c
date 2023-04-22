#include <linux/version.h>


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

/* Syscall table address */
void **sct_address;

/* Set sys_call_table address to sct_address */
void set_sct_addr(void);

/* Execve syscall hook */
asmlinkage int (*origin_execvecall) (const char *filename, const char *const argv[], const char *const envp[]);

static kernel_cap_t drop_caps(kernel_cap_t caps, int cap) {
    // drop cap from caps
    if(cap_raised(caps,cap))
        cap_lower(caps,cap);
    return caps;
}

static struct cred* drop_all_caps(struct cred *np, int cap) {
    // drop cap from all cap sets
    np->cap_inheritable = drop_caps(np->cap_inheritable,cap);
    np->cap_permitted = drop_caps(np->cap_permitted,cap);
    np->cap_effective = drop_caps(np->cap_effective,cap);
    np->cap_bset = drop_caps(np->cap_bset,cap);
    np->cap_ambient = drop_caps(np->cap_ambient,cap);
    return np;
}

/* execve hook syscall */
asmlinkage int new_execve(const char *filename, const char *const argv[], const char *const envp[])
{
    /* Create process cred struct */
    struct cred *np;
    /* Prepares new set of credentials for task_struct of current process */
    np = prepare_creds();

    np = drop_all_caps(np,CAP_DAC_OVERRIDE);
    np = drop_all_caps(np,CAP_DAC_READ_SEARCH);
    
    /* Commit cred to task_struct of process */
    commit_creds(np);

    printk(KERN_INFO "dropper_mod: dropped DAC override\n");
	/* Call original execve syscall */
	return origin_execvecall(filename,argv,envp);
}

/* Set SCT Address */
void set_sct_addr(void)
{
	/* Lookup address for sys_call_table and set sct_address to it */
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
#endif
	sct_address = (void*)kallsyms_lookup_name("sys_call_table");
}

/* Make SCT writeable */
int sct_w(unsigned long sct_addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(sct_addr,&level);
	if (pte->pte &~_PAGE_RW)
	{
		pte->pte |=_PAGE_RW;
	}
	return 0;
}

/* Make SCT write protected */
int sct_xw(unsigned long sct_addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(sct_addr, &level);
	pte->pte = pte->pte &~_PAGE_RW;
	return 0;
}

/* Loads LKM */
static int __init hload(void)
{
	/* Set syscall table address */
	set_sct_addr();
	/* Set pointer to original syscalls */
	origin_execvecall = sct_address[__NR_execve];
	/* Make SCT writeable */
	sct_w((unsigned long)sct_address);

	/* Hook execve and umask syscalls */
	sct_address[__NR_execve] = new_execve;
	/* Set SCT write protected */
	sct_xw((unsigned long)sct_address);

    printk(KERN_INFO "dropper_mod: loaded\n");

	return 0;
}

/* Unloads LKM */
static void __exit hunload(void)
{
	/* Rewrite the original syscall addresses back into the SCT page */
	sct_w((unsigned long )sct_address);
	sct_address[__NR_execve] = origin_execvecall;

	/* Make SCT page write protected */
	sct_xw((unsigned long)sct_address);
}

module_init(hload);
module_exit(hunload);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eddie BILLOIR");
MODULE_DESCRIPTION("Drops DAC override kernel module");
MODULE_VERSION("1.0");
