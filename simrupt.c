/* simrupt: A device that simulates interrupts */

#include <linux/cdev.h>
#include <linux/circ_buf.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kfifo.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");
MODULE_DESCRIPTION("A device that simulates interrupts");

/* Macro DECLARE_TASKLET_OLD exists for compatibiity.
 * See https://lwn.net/Articles/830964/
 */
#ifndef DECLARE_TASKLET_OLD
#define DECLARE_TASKLET_OLD(arg1, arg2) DECLARE_TASKLET(arg1, arg2, 0L)
#endif

#define DEV_NAME "simrupt"

#define NR_SIMRUPT 1

static int delay = 100; /* time (in ms) to generate an event */

/* Data produced by the simulated device */
static int simrupt_data;

/* Timer to simulate a periodic IRQ */
static struct timer_list timer;

/* Character device stuff */
static int major;
static struct class *simrupt_class;
static struct cdev simrupt_cdev;

/* Data are stored into a kfifo buffer before passing them to the userspace */
static struct kfifo rx_fifo;

/* NOTE: the usage of kfifo is safe (no need for extra locking), until there is
 * only one concurrent reader and one concurrent writer. Writes are serialized
 * from the interrupt context, readers are serialized using this mutex.
 */
static DEFINE_MUTEX(read_lock);

/* Wait queue to implement blocking I/O from userspace */
static DECLARE_WAIT_QUEUE_HEAD(rx_wait);

/* Generate new data from the simulated device */
static inline int update_simrupt_data(void)
{
    simrupt_data = max((simrupt_data + 1) % 0x7f, 0x20);
    return simrupt_data;
}

/* Insert a value into the kfifo buffer */
static void produce_data(unsigned char val)
{
    /* Implement a kind of circular FIFO here (skip oldest element if kfifo
     * buffer is full).
     */
    unsigned int len = kfifo_in(&rx_fifo, &val, sizeof(val));
    if (unlikely(len < sizeof(val)) && printk_ratelimit())
        pr_warn("%s: %zu bytes dropped\n", __func__, sizeof(val) - len);

    pr_debug("simrupt: %s: in %u/%u bytes\n", __func__, len,
             kfifo_len(&rx_fifo));
}

/* Mutex to serialize kfifo writers within the workqueue handler */
static DEFINE_MUTEX(producer_lock);

/* Mutex to serialize fast_buf consumers: we can use a mutex because consumers
 * run in workqueue handler (kernel thread context).
 */
static DEFINE_MUTEX(consumer_lock);

/* We use an additional "faster" circular buffer to quickly store data from
 * interrupt context, before adding them to the kfifo.
 */
static struct circ_buf fast_buf;

static int fast_buf_get(void)
{
    struct circ_buf *ring = &fast_buf;

    /* prevent the compiler from merging or refetching accesses for tail */
    unsigned long head = READ_ONCE(ring->head), tail = ring->tail;
    int ret;

    if (unlikely(!CIRC_CNT(head, tail, PAGE_SIZE)))
        return -ENOENT;

    /* read index before reading contents at that index */
    smp_rmb();

    /* extract item from the buffer */
    ret = ring->buf[tail];

    /* finish reading descriptor before incrementing tail */
    smp_mb();

    /* increment the tail pointer */
    ring->tail = (tail + 1) & (PAGE_SIZE - 1);

    return ret;
}

static int fast_buf_put(unsigned char val)
{
    struct circ_buf *ring = &fast_buf;
    unsigned long head = ring->head;

    /* prevent the compiler from merging or refetching accesses for tail */
    unsigned long tail = READ_ONCE(ring->tail);

    /* is circular buffer full? */
    if (unlikely(!CIRC_SPACE(head, tail, PAGE_SIZE)))
        return -ENOMEM;

    ring->buf[ring->head] = val;

    /* commit the item before incrementing the head */
    smp_wmb();

    /* update header pointer */
    ring->head = (ring->head + 1) & (PAGE_SIZE - 1);

    return 0;
}

/* Clear all data from the circular buffer fast_buf */
static void fast_buf_clear(void)
{
    fast_buf.head = fast_buf.tail = 0;
}

/* Workqueue handler: executed by a kernel thread */
static void simrupt_work_func(struct work_struct *w)
{
    int val, cpu;

    /* This code runs from a kernel thread, so softirqs and hard-irqs must
     * be enabled.
     */
    WARN_ON_ONCE(in_softirq());
    WARN_ON_ONCE(in_interrupt());

    /* Pretend to simulate access to per-CPU data, disabling preemption
     * during the pr_info().
     */
    cpu = get_cpu();
    pr_info("simrupt: [CPU#%d] %s\n", cpu, __func__);
    put_cpu();

    while (1) {
        /* Consume data from the circular buffer */
        mutex_lock(&consumer_lock);
        val = fast_buf_get();
        mutex_unlock(&consumer_lock);

        if (val < 0)
            break;

        /* Store data to the kfifo buffer */
        mutex_lock(&producer_lock);
        produce_data(val);
        mutex_unlock(&producer_lock);
    }
    wake_up_interruptible(&rx_wait);
}

/* Workqueue for asynchronous bottom-half processing */
static struct workqueue_struct *simrupt_workqueue;

/* Work item: holds a pointer to the function that is going to be executed
 * asynchronously.
 */
static DECLARE_WORK(work, simrupt_work_func);

/* Tasklet handler.
 *
 * NOTE: different tasklets can run concurrently on different processors, but
 * two of the same type of tasklet cannot run simultaneously. Moreover, a
 * tasklet always runs on the same CPU that schedules it.
 */
static void simrupt_tasklet_func(unsigned long __data)
{
    ktime_t tv_start, tv_end;
    s64 nsecs;

    WARN_ON_ONCE(!in_interrupt());
    WARN_ON_ONCE(!in_softirq());

    tv_start = ktime_get();
    queue_work(simrupt_workqueue, &work);
    tv_end = ktime_get();

    nsecs = (s64) ktime_to_ns(ktime_sub(tv_end, tv_start));

    pr_info("simrupt: [CPU#%d] %s in_softirq: %llu usec\n", smp_processor_id(),
            __func__, (unsigned long long) nsecs >> 10);
}

/* Tasklet for asynchronous bottom-half processing in softirq context */
static DECLARE_TASKLET_OLD(simrupt_tasklet, simrupt_tasklet_func);

static void process_data(void)
{
    WARN_ON_ONCE(!irqs_disabled());

    pr_info("simrupt: [CPU#%d] produce data\n", smp_processor_id());
    fast_buf_put(update_simrupt_data());

    pr_info("simrupt: [CPU#%d] scheduling tasklet\n", smp_processor_id());
    tasklet_schedule(&simrupt_tasklet);
}

static void timer_handler(struct timer_list *__timer)
{
    ktime_t tv_start, tv_end;
    s64 nsecs;

    pr_info("simrupt: [CPU#%d] enter %s\n", smp_processor_id(), __func__);
    /* We are using a kernel timer to simulate a hard-irq, so we must expect
     * to be in softirq context here.
     */
    WARN_ON_ONCE(!in_softirq());

    /* Disable interrupts for this CPU to simulate real interrupt context */
    local_irq_disable();

    tv_start = ktime_get();
    process_data();
    tv_end = ktime_get();

    nsecs = (s64) ktime_to_ns(ktime_sub(tv_end, tv_start));

    pr_info("simrupt: [CPU#%d] %s in_irq: %llu usec\n", smp_processor_id(),
            __func__, (unsigned long long) nsecs >> 10);
    mod_timer(&timer, jiffies + msecs_to_jiffies(delay));

    local_irq_enable();
}

static ssize_t simrupt_read(struct file *file,
                            char __user *buf,
                            size_t count,
                            loff_t *ppos)
{
    unsigned int read;
    int ret;

    pr_debug("simrupt: %s(%p, %zd, %lld)\n", __func__, buf, count, *ppos);

    if (unlikely(!access_ok(buf, count)))
        return -EFAULT;

    if (mutex_lock_interruptible(&read_lock))
        return -ERESTARTSYS;

    do {
        ret = kfifo_to_user(&rx_fifo, buf, count, &read);
        if (unlikely(ret < 0))
            break;
        if (read)
            break;
        if (file->f_flags & O_NONBLOCK) {
            ret = -EAGAIN;
            break;
        }
        ret = wait_event_interruptible(rx_wait, kfifo_len(&rx_fifo));
    } while (ret == 0);
    pr_debug("simrupt: %s: out %u/%u bytes\n", __func__, read,
             kfifo_len(&rx_fifo));

    mutex_unlock(&read_lock);

    return ret ? ret : read;
}

static int simrupt_open(struct inode *inode, struct file *filp)
{
    pr_debug("simrupt: %s\n", __func__);
    mod_timer(&timer, jiffies + msecs_to_jiffies(delay));
    return 0;
}

static int simrupt_release(struct inode *inode, struct file *filp)
{
    pr_debug("simrupt: %s\n", __func__);
    del_timer_sync(&timer);
    flush_workqueue(simrupt_workqueue);
    fast_buf_clear();

    return 0;
}

static const struct file_operations simrupt_fops = {
    .read = simrupt_read,
    .llseek = no_llseek,
    .open = simrupt_open,
    .release = simrupt_release,
    .owner = THIS_MODULE,
};

static int __init simrupt_init(void)
{
    dev_t dev_id;
    int ret;

    if (kfifo_alloc(&rx_fifo, PAGE_SIZE, GFP_KERNEL) < 0)
        return -ENOMEM;

    /* Register major/minor numbers */
    ret = alloc_chrdev_region(&dev_id, 0, NR_SIMRUPT, DEV_NAME);
    if (ret)
        goto error_alloc;
    major = MAJOR(dev_id);

    /* Add the character device to the system */
    cdev_init(&simrupt_cdev, &simrupt_fops);
    ret = cdev_add(&simrupt_cdev, dev_id, NR_SIMRUPT);
    if (ret) {
        kobject_put(&simrupt_cdev.kobj);
        goto error_region;
    }

    /* Create a class structure */
    simrupt_class = class_create(THIS_MODULE, DEV_NAME);
    if (IS_ERR(simrupt_class)) {
        printk(KERN_ERR "error creating simrupt class\n");
        ret = PTR_ERR(simrupt_class);
        goto error_cdev;
    }

    /* Register the device with sysfs */
    device_create(simrupt_class, NULL, MKDEV(major, 0), NULL, DEV_NAME);

    /* Allocate fast circular buffer */
    fast_buf.buf = vmalloc(PAGE_SIZE);
    if (!fast_buf.buf) {
        device_destroy(simrupt_class, dev_id);
        class_destroy(simrupt_class);
        ret = -ENOMEM;
        goto error_cdev;
    }

    /* Create the workqueue */
    simrupt_workqueue = alloc_workqueue("simruptd", WQ_UNBOUND, WQ_MAX_ACTIVE);
    if (!simrupt_workqueue) {
        vfree(fast_buf.buf);
        device_destroy(simrupt_class, dev_id);
        class_destroy(simrupt_class);
        ret = -ENOMEM;
        goto error_cdev;
    }

    /* Setup the timer */
    timer_setup(&timer, timer_handler, 0);

    pr_info("simrupt: registered new simrupt device: %d,%d\n", major, 0);
out:
    return ret;
error_cdev:
    cdev_del(&simrupt_cdev);
error_region:
    unregister_chrdev_region(dev_id, NR_SIMRUPT);
error_alloc:
    kfifo_free(&rx_fifo);
    goto out;
}

static void __exit simrupt_exit(void)
{
    dev_t dev_id = MKDEV(major, 0);

    del_timer_sync(&timer);
    tasklet_kill(&simrupt_tasklet);
    flush_workqueue(simrupt_workqueue);
    destroy_workqueue(simrupt_workqueue);
    vfree(fast_buf.buf);
    device_destroy(simrupt_class, dev_id);
    class_destroy(simrupt_class);
    cdev_del(&simrupt_cdev);
    unregister_chrdev_region(dev_id, NR_SIMRUPT);

    kfifo_free(&rx_fifo);
    pr_info("simrupt: unloaded\n");
}

module_init(simrupt_init);
module_exit(simrupt_exit);
