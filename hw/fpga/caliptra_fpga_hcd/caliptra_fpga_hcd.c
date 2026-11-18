// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
// Licensed under the Apache-2.0 license
/*
 * caliptra_fpga_hcd.c - Linux USB Host Controller Driver for the Caliptra FPGA
 * wrapper's in-fabric USB 2.0 High-Speed host engine (`caliptra_fpga_ulpi_host`,
 * "Architecture B") on the VCK-190. The engine talks ULPI to the Caliptra 2.2
 * USB device; from Linux's point of view this module is simply a host
 * controller, hence the name.
 *
 * The hardware is a token-level USB 2.0 host: software loads up to 64 bytes
 * into TX_BUF, writes one CMD (BUS_RESET_HS / SETUP / IN / OUT), and polls
 * STATUS for completion and the device handshake PID.  This driver sits that
 * engine underneath Linux `usbcore` as a single-port High-Speed root hub, so
 * the Caliptra 2.2 USB device enumerates with the stock kernel USB stack and
 * is visible to lsusb / libusb / usbmon exactly like any physical device.
 *
 * Scope: control, bulk and interrupt transfers, PIO (no DMA), polled
 * completion from a dedicated worker (the engine has no interrupt line yet).
 * Modelled on drivers/usb/host/max3421-hcd.c.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/jiffies.h>
#include <linux/slab.h>

#define DRIVER_DESC "Caliptra FPGA USB 2.0 host"
#define DRIVER_NAME "caliptra-fpga-hcd"

/* Default physical base: S_AXI_WRAPPER + 0x4000 on the VCK-190 image. */
#define CFHCD_DEFAULT_BASE	0xA4014000UL
#define CFHCD_REG_SIZE		0x1000

/* ---- Register map (see hw/latest/fpga/src/caliptra_fpga_ulpi_host.sv) ---- */
#define CFHCD_MAGIC		0x00
#define  CFHCD_MAGIC_VALUE	0x55534248	/* "USBH" */
#define CFHCD_CTRL		0x04
#define  CTRL_VBUS_VALID	BIT(0)
#define  CTRL_AUTO_SOF_EN	BIT(1)
#define  CTRL_SOFT_RESET	BIT(2)
#define CFHCD_STATUS		0x08
#define  ST_BUSY		BIT(0)
#define  ST_DONE		BIT(1)
#define  ST_TIMEOUT		BIT(2)
#define  ST_ULPI_INIT_DONE	BIT(3)
#define  ST_DEV_CONNECTED	BIT(4)
#define  ST_HS_ACTIVE		BIT(5)
#define  ST_RX_PID(s)		(((s) >> 8) & 0xF)
#define  ST_RX_LEN(s)		(((s) >> 12) & 0xFF)
#define CFHCD_CMD		0x0C
#define  CMD_OP_BUS_RESET_HS	1
#define  CMD_OP_SETUP		2
#define  CMD_OP_OUT		3
#define  CMD_OP_IN		4
#define  CMD_TOGGLE		BIT(3)
#define  CMD_ADDR(a)		(((u32)(a) & 0x7F) << 8)
#define  CMD_EP(e)		(((u32)(e) & 0x0F) << 16)
#define  CMD_TXLEN(l)		(((u32)(l) & 0x7F) << 20)
#define CFHCD_TIMEOUT		0x10
#define CFHCD_DIAG		0x14
#define CFHCD_TX_BUF		0x40
#define CFHCD_RX_BUF		0x80

/* USB handshake / data PID nibbles reported in STATUS.rx_pid */
#define PID_ACK			0x2
#define PID_DATA0		0x3
#define PID_NYET		0x6
#define PID_NAK			0xA
#define PID_DATA1		0xB
#define PID_STALL		0xE

#define CFHCD_MAX_PKT		64
/* Engine response timeout, in 60 MHz ULPI clock cycles (~3.3 ms). */
#define CFHCD_HW_TIMEOUT_CYC	200000
/* How long to wait for the engine to finish one command before giving up. */
#define CFHCD_CMD_POLL_US	2
#define CFHCD_CMD_TIMEOUT_US	50000
/* Per-packet retry budget on bus-level errors (USB 2.0 ch. 8.6.4: 3 tries). */
#define CFHCD_ERR_RETRIES	3
/* Give up on a stage that keeps getting NAKed after this long. */
#define CFHCD_NAK_TIMEOUT_MS	5000
/* Worst case HS detection handshake with spec timers (~3.6 ms); allow more. */
#define CFHCD_RESET_TIMEOUT_MS	100

static unsigned long base_addr = CFHCD_DEFAULT_BASE;
module_param(base_addr, ulong, 0444);
MODULE_PARM_DESC(base_addr, "Physical base address of caliptra_fpga_ulpi_host");

/* Queue entry: usbcore owns urb->urb_list, so keep our own node. */
struct cfhcd_qe {
	struct list_head	node;
	struct urb		*urb;
};

struct cfhcd {
	void __iomem		*regs;
	struct usb_hcd		*hcd;
	spinlock_t		lock;		/* protects the fields below */
	struct list_head	urb_queue;	/* URBs waiting for the worker */
	struct urb		*active_urb;	/* URB the worker is executing */
	u32			port_status;	/* wPortStatus | wPortChange << 16 */
	bool			reset_requested;
	bool			powered;
	struct workqueue_struct	*wq;
	struct work_struct	work;
	struct timer_list	rh_timer;	/* connection polling */
};

static inline struct cfhcd *hcd_to_cfhcd(struct usb_hcd *hcd)
{
	return (struct cfhcd *)hcd->hcd_priv;
}

static inline u32 cfhcd_rd(struct cfhcd *c, u32 off)
{
	return readl(c->regs + off);
}

static inline void cfhcd_wr(struct cfhcd *c, u32 off, u32 val)
{
	writel(val, c->regs + off);
}

/* ------------------------------------------------------------------------ */
/* Low-level engine access (worker context only; may sleep)                 */
/* ------------------------------------------------------------------------ */

static void cfhcd_load_tx(struct cfhcd *c, const u8 *buf, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i += 4) {
		u32 w = 0;
		unsigned int n = min(4u, len - i);

		memcpy(&w, buf + i, n);	/* little-endian byte lanes */
		cfhcd_wr(c, CFHCD_TX_BUF + i, le32_to_cpu((__force __le32)w));
	}
}

static void cfhcd_read_rx(struct cfhcd *c, u8 *buf, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i += 4) {
		u32 w = (__force u32)cpu_to_le32(cfhcd_rd(c, CFHCD_RX_BUF + i));
		unsigned int n = min(4u, len - i);

		memcpy(buf + i, &w, n);
	}
}

/*
 * Issue one command and wait for the engine to go idle again.  Returns the
 * final STATUS word, or -ETIMEDOUT if the engine itself never completed
 * (which indicates a hardware problem, not a bus timeout; bus timeouts are
 * reported in STATUS.timeout_err).
 */
static int cfhcd_exec(struct cfhcd *c, u32 cmd, u32 *status_out)
{
	u32 st;
	int ret;

	ret = readl_poll_timeout(c->regs + CFHCD_STATUS, st, !(st & ST_BUSY),
				 CFHCD_CMD_POLL_US, CFHCD_CMD_TIMEOUT_US);
	if (ret) {
		dev_err(c->hcd->self.controller,
			"engine stuck busy before cmd %08x (status %08x)\n", cmd, st);
		return ret;
	}
	cfhcd_wr(c, CFHCD_CMD, cmd);
	ret = readl_poll_timeout(c->regs + CFHCD_STATUS, st,
				 !(st & ST_BUSY) && (st & ST_DONE),
				 CFHCD_CMD_POLL_US, CFHCD_CMD_TIMEOUT_US);
	if (ret) {
		dev_err(c->hcd->self.controller,
			"engine did not complete cmd %08x (status %08x)\n", cmd, st);
		return ret;
	}
	*status_out = st;
	return 0;
}

/* ------------------------------------------------------------------------ */
/* Transfer execution                                                        */
/* ------------------------------------------------------------------------ */

enum cfhcd_pkt_result {
	PKT_OK,		/* ACK (OUT/SETUP) or DATAx received (IN) */
	PKT_NAK,	/* device busy, retry later */
	PKT_STALL,	/* -EPIPE */
	PKT_ERR,	/* bus timeout / unexpected PID, retry up to budget */
	PKT_HWERR,	/* engine failure, abort */
};

struct cfhcd_pkt {
	u8 op;
	u8 addr;
	u8 ep;
	bool toggle;
	const u8 *tx;
	unsigned int tx_len;
	u8 *rx;
	unsigned int rx_len;		/* out: bytes received */
	u8 rx_pid;			/* out */
};

static enum cfhcd_pkt_result cfhcd_do_pkt(struct cfhcd *c, struct cfhcd_pkt *p)
{
	u32 cmd, st;

	if (p->op == CMD_OP_SETUP || p->op == CMD_OP_OUT)
		cfhcd_load_tx(c, p->tx, p->tx_len);

	cmd = p->op | CMD_ADDR(p->addr) | CMD_EP(p->ep) | CMD_TXLEN(p->tx_len);
	if (p->toggle)
		cmd |= CMD_TOGGLE;

	if (cfhcd_exec(c, cmd, &st))
		return PKT_HWERR;
	if (st & ST_TIMEOUT)
		return PKT_ERR;

	p->rx_pid = ST_RX_PID(st);
	p->rx_len = 0;
	switch (p->rx_pid) {
	case PID_ACK:
	case PID_NYET:
		return (p->op == CMD_OP_IN) ? PKT_ERR : PKT_OK;
	case PID_NAK:
		return PKT_NAK;
	case PID_STALL:
		return PKT_STALL;
	case PID_DATA0:
	case PID_DATA1:
		if (p->op != CMD_OP_IN)
			return PKT_ERR;
		p->rx_len = min_t(unsigned int, ST_RX_LEN(st), CFHCD_MAX_PKT);
		if (p->rx && p->rx_len)
			cfhcd_read_rx(c, p->rx, p->rx_len);
		return PKT_OK;
	default:
		return PKT_ERR;
	}
}

static bool cfhcd_urb_unlinked(struct cfhcd *c, struct urb *urb)
{
	unsigned long flags;
	bool unlinked;

	spin_lock_irqsave(&c->lock, flags);
	unlinked = urb->unlinked != 0 || c->reset_requested;
	spin_unlock_irqrestore(&c->lock, flags);
	return unlinked;
}

/*
 * Run one packet with NAK/error retry policy.  Returns 0, -EPIPE, -EPROTO,
 * -ETIMEDOUT, -ECONNRESET (unlinked) or -EIO (engine failure).
 */
static int cfhcd_pkt_retry(struct cfhcd *c, struct urb *urb, struct cfhcd_pkt *p,
			   unsigned int nak_sleep_us)
{
	unsigned long nak_deadline = jiffies + msecs_to_jiffies(CFHCD_NAK_TIMEOUT_MS);
	int errs = 0;

	for (;;) {
		switch (cfhcd_do_pkt(c, p)) {
		case PKT_OK:
			return 0;
		case PKT_STALL:
			return -EPIPE;
		case PKT_HWERR:
			return -EIO;
		case PKT_ERR:
			if (++errs >= CFHCD_ERR_RETRIES)
				return -EPROTO;
			usleep_range(50, 100);
			break;
		case PKT_NAK:
			errs = 0;
			if (time_after(jiffies, nak_deadline))
				return -ETIMEDOUT;
			usleep_range(nak_sleep_us, nak_sleep_us * 2);
			break;
		}
		if (cfhcd_urb_unlinked(c, urb))
			return -ECONNRESET;
	}
}

/*
 * Data phase shared by control DATA stage, bulk and interrupt URBs.
 * `toggle` is read/updated by the caller.  Returns 0 or a negative status;
 * urb->actual_length is advanced in place.
 */
static int cfhcd_data_phase(struct cfhcd *c, struct urb *urb, u8 addr, u8 ep,
			    bool is_in, bool *toggle, unsigned int maxp,
			    unsigned int nak_sleep_us)
{
	u8 *buf = urb->transfer_buffer;
	unsigned int total = urb->transfer_buffer_length;
	int ret;

	maxp = min_t(unsigned int, maxp ? maxp : CFHCD_MAX_PKT, CFHCD_MAX_PKT);

	if (is_in) {
		unsigned int toggle_errs = 0;

		while (urb->actual_length < total) {
			unsigned int room = total - urb->actual_length;
			u8 tmp[CFHCD_MAX_PKT];
			struct cfhcd_pkt p = {
				.op = CMD_OP_IN, .addr = addr, .ep = ep,
				.toggle = *toggle, .rx = tmp,
			};

			ret = cfhcd_pkt_retry(c, urb, &p, nak_sleep_us);
			if (ret)
				return ret;

			/*
			 * Data toggle check. A strict host would drop a packet carrying
			 * the previous toggle as a retransmission; but the engine ACKs
			 * every DATAx it receives, so on this fabric a mismatch can only
			 * mean the device's toggle state differs from ours (e.g. after a
			 * device-side EP0 restart). Dropping would then spin forever and
			 * lose data, so accept the packet and resynchronise to what the
			 * device actually sent -- this matches the proven behaviour of
			 * the raw hw-model driver, which never checked toggles.
			 */
			if ((p.rx_pid == PID_DATA1) != *toggle) {
				if (++toggle_errs <= 3) {
					const u8 *sp = urb->setup_packet;

					dev_info_ratelimited(c->hcd->self.controller,
						"ep%u IN toggle resync: got DATA%u len %u, expected DATA%u (setup %*phN, actual %u/%u)\n",
						ep, p.rx_pid == PID_DATA1, p.rx_len, *toggle,
						sp ? 8 : 0, sp, urb->actual_length, total);
				}
				*toggle = (p.rx_pid == PID_DATA1);
			}

			if (p.rx_len > room) {
				memcpy(buf + urb->actual_length, tmp, room);
				urb->actual_length += room;
				return -EOVERFLOW;
			}
			memcpy(buf + urb->actual_length, tmp, p.rx_len);
			urb->actual_length += p.rx_len;
			*toggle = !*toggle;
			if (p.rx_len < maxp) {
				if (urb->actual_length < total &&
				    (urb->transfer_flags & URB_SHORT_NOT_OK))
					return -EREMOTEIO;
				break;	/* short packet terminates */
			}
		}
	} else {
		bool need_zlp = (urb->transfer_flags & URB_ZERO_PACKET) &&
				total && (total % maxp == 0);

		while (urb->actual_length < total || need_zlp) {
			unsigned int n = min(maxp, total - urb->actual_length);
			struct cfhcd_pkt p = {
				.op = CMD_OP_OUT, .addr = addr, .ep = ep,
				.toggle = *toggle, .tx = buf + urb->actual_length,
				.tx_len = n,
			};

			if (urb->actual_length >= total)
				need_zlp = false;	/* this is the ZLP */

			ret = cfhcd_pkt_retry(c, urb, &p, nak_sleep_us);
			if (ret)
				return ret;
			urb->actual_length += n;
			*toggle = !*toggle;
		}
	}
	return 0;
}

static int cfhcd_run_control(struct cfhcd *c, struct urb *urb)
{
	struct usb_ctrlrequest *req = (struct usb_ctrlrequest *)urb->setup_packet;
	u8 addr = usb_pipedevice(urb->pipe);
	unsigned int maxp = usb_maxpacket(urb->dev, urb->pipe);
	bool data_in = !!(req->bRequestType & USB_DIR_IN);
	bool toggle;
	int ret;

	/* SETUP stage (DATA0; cannot be NAKed) */
	{
		struct cfhcd_pkt p = {
			.op = CMD_OP_SETUP, .addr = addr, .ep = 0,
			.tx = urb->setup_packet, .tx_len = 8,
		};
		ret = cfhcd_pkt_retry(c, urb, &p, 20);
		if (ret)
			return ret;
	}

	/* DATA stage (starts with DATA1) */
	toggle = true;
	if (urb->transfer_buffer_length) {
		ret = cfhcd_data_phase(c, urb, addr, 0, data_in, &toggle, maxp, 20);
		if (ret)
			return ret;
	}

	/* STATUS stage: opposite direction, zero-length, always DATA1 */
	if (urb->transfer_buffer_length && data_in) {
		struct cfhcd_pkt p = {
			.op = CMD_OP_OUT, .addr = addr, .ep = 0, .toggle = true,
			.tx = NULL, .tx_len = 0,
		};
		ret = cfhcd_pkt_retry(c, urb, &p, 20);
	} else {
		u8 tmp[CFHCD_MAX_PKT];
		struct cfhcd_pkt p = {
			.op = CMD_OP_IN, .addr = addr, .ep = 0, .toggle = true,
			.rx = tmp,
		};
		ret = cfhcd_pkt_retry(c, urb, &p, 20);
		if (!ret && p.rx_len)
			ret = -EPROTO;	/* STATUS IN must be a ZLP */
	}
	return ret;
}

static int cfhcd_run_bulk_int(struct cfhcd *c, struct urb *urb)
{
	u8 addr = usb_pipedevice(urb->pipe);
	u8 ep = usb_pipeendpoint(urb->pipe);
	bool is_in = usb_pipein(urb->pipe);
	unsigned int maxp = usb_maxpacket(urb->dev, urb->pipe);
	bool toggle = usb_gettoggle(urb->dev, ep, !is_in);
	unsigned int nak_us = usb_pipeint(urb->pipe) ?
			      max(125u, 125u * urb->interval) : 20;
	int ret;

	ret = cfhcd_data_phase(c, urb, addr, ep, is_in, &toggle, maxp, nak_us);
	usb_settoggle(urb->dev, ep, !is_in, toggle);
	return ret;
}

/* ------------------------------------------------------------------------ */
/* Root hub port reset (worker context)                                      */
/* ------------------------------------------------------------------------ */

static void cfhcd_do_port_reset(struct cfhcd *c)
{
	struct usb_hcd *hcd = c->hcd;
	unsigned long flags;
	u32 st = 0;
	int ret;

	/* Drop keep-alive SOFs while the bus is reset; VBUS stays valid. */
	cfhcd_wr(c, CFHCD_CTRL, CTRL_VBUS_VALID);
	cfhcd_wr(c, CFHCD_TIMEOUT, CFHCD_HW_TIMEOUT_CYC);

	ret = readl_poll_timeout(c->regs + CFHCD_STATUS, st, !(st & ST_BUSY),
				 CFHCD_CMD_POLL_US, CFHCD_CMD_TIMEOUT_US);
	if (!ret) {
		cfhcd_wr(c, CFHCD_CMD, CMD_OP_BUS_RESET_HS);
		ret = readl_poll_timeout(c->regs + CFHCD_STATUS, st,
					 !(st & ST_BUSY) && (st & ST_DONE),
					 100, CFHCD_RESET_TIMEOUT_MS * 1000);
	}

	spin_lock_irqsave(&c->lock, flags);
	c->reset_requested = false;
	c->port_status &= ~USB_PORT_STAT_RESET;
	c->port_status &= ~(USB_PORT_STAT_ENABLE | USB_PORT_STAT_HIGH_SPEED |
			    USB_PORT_STAT_LOW_SPEED);
	if (!ret && !(st & ST_TIMEOUT) && (st & ST_DEV_CONNECTED)) {
		c->port_status |= USB_PORT_STAT_ENABLE;
		if (st & ST_HS_ACTIVE)
			c->port_status |= USB_PORT_STAT_HIGH_SPEED;
		dev_info(hcd->self.controller,
			 "port reset done: %s-speed device (status %08x)\n",
			 (st & ST_HS_ACTIVE) ? "high" : "full", st);
	} else {
		dev_warn(hcd->self.controller,
			 "port reset failed (ret=%d status %08x)\n", ret, st);
	}
	c->port_status |= USB_PORT_STAT_C_RESET << 16;
	spin_unlock_irqrestore(&c->lock, flags);

	/* Keep the device out of HS suspend between host transactions. */
	if (st & ST_HS_ACTIVE)
		cfhcd_wr(c, CFHCD_CTRL, CTRL_VBUS_VALID | CTRL_AUTO_SOF_EN);

	usb_hcd_poll_rh_status(hcd);
}

/* ------------------------------------------------------------------------ */
/* Worker                                                                    */
/* ------------------------------------------------------------------------ */

static void cfhcd_giveback(struct cfhcd *c, struct urb *urb, int status)
{
	struct usb_hcd *hcd = c->hcd;
	unsigned long flags;

	struct cfhcd_qe *qe;

	spin_lock_irqsave(&c->lock, flags);
	if (urb->unlinked)
		status = urb->unlinked;
	usb_hcd_unlink_urb_from_ep(hcd, urb);
	qe = urb->hcpriv;
	urb->hcpriv = NULL;
	c->active_urb = NULL;
	spin_unlock_irqrestore(&c->lock, flags);

	kfree(qe);
	usb_hcd_giveback_urb(hcd, urb, status);
}

static void cfhcd_work(struct work_struct *work)
{
	struct cfhcd *c = container_of(work, struct cfhcd, work);
	unsigned long flags;

	for (;;) {
		struct urb *urb;
		bool do_reset;
		int status;

		spin_lock_irqsave(&c->lock, flags);
		do_reset = c->reset_requested;
		urb = NULL;
		if (!do_reset && !list_empty(&c->urb_queue)) {
			struct cfhcd_qe *qe = list_first_entry(&c->urb_queue,
							       struct cfhcd_qe, node);
			list_del_init(&qe->node);
			urb = qe->urb;
			c->active_urb = urb;
		}
		spin_unlock_irqrestore(&c->lock, flags);

		if (do_reset) {
			cfhcd_do_port_reset(c);
			continue;
		}
		if (!urb)
			break;

		if (urb->unlinked) {
			cfhcd_giveback(c, urb, urb->unlinked);
			continue;
		}

		switch (usb_pipetype(urb->pipe)) {
		case PIPE_CONTROL:
			status = cfhcd_run_control(c, urb);
			break;
		case PIPE_BULK:
		case PIPE_INTERRUPT:
			status = cfhcd_run_bulk_int(c, urb);
			break;
		default:
			status = -ENOSYS;
			break;
		}

		/* A NAKed interrupt pipe is normal: park it behind other work. */
		if (status == -ETIMEDOUT && usb_pipeint(urb->pipe) && !urb->unlinked) {
			struct cfhcd_qe *qe = urb->hcpriv;

			spin_lock_irqsave(&c->lock, flags);
			c->active_urb = NULL;
			list_add_tail(&qe->node, &c->urb_queue);
			spin_unlock_irqrestore(&c->lock, flags);
			usleep_range(1000, 2000);
			continue;
		}
		cfhcd_giveback(c, urb, status);
	}
}

/* ------------------------------------------------------------------------ */
/* hc_driver callbacks                                                       */
/* ------------------------------------------------------------------------ */

static int cfhcd_urb_enqueue(struct usb_hcd *hcd, struct urb *urb, gfp_t mem_flags)
{
	struct cfhcd *c = hcd_to_cfhcd(hcd);
	struct cfhcd_qe *qe;
	unsigned long flags;
	int ret;

	switch (usb_pipetype(urb->pipe)) {
	case PIPE_CONTROL:
	case PIPE_BULK:
	case PIPE_INTERRUPT:
		break;
	default:
		return -ENOSYS;	/* no isochronous support */
	}
	if (usb_maxpacket(urb->dev, urb->pipe) > CFHCD_MAX_PKT)
		return -EINVAL;

	qe = kzalloc(sizeof(*qe), mem_flags);
	if (!qe)
		return -ENOMEM;
	qe->urb = urb;

	spin_lock_irqsave(&c->lock, flags);
	ret = usb_hcd_link_urb_to_ep(hcd, urb);
	if (!ret) {
		urb->hcpriv = qe;
		list_add_tail(&qe->node, &c->urb_queue);
	}
	spin_unlock_irqrestore(&c->lock, flags);
	if (ret)
		kfree(qe);
	else
		queue_work(c->wq, &c->work);
	return ret;
}

static int cfhcd_urb_dequeue(struct usb_hcd *hcd, struct urb *urb, int status)
{
	struct cfhcd *c = hcd_to_cfhcd(hcd);
	struct cfhcd_qe *qe = NULL;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&c->lock, flags);
	ret = usb_hcd_check_unlink_urb(hcd, urb, status);
	if (!ret && urb != c->active_urb) {
		qe = urb->hcpriv;
		list_del_init(&qe->node);
		usb_hcd_unlink_urb_from_ep(hcd, urb);
		urb->hcpriv = NULL;
	}
	spin_unlock_irqrestore(&c->lock, flags);

	if (ret)
		return ret;
	if (qe) {
		kfree(qe);
		usb_hcd_giveback_urb(hcd, urb, status);
	}
	/* else: the worker sees urb->unlinked between packets and gives it back */
	return 0;
}

static void cfhcd_endpoint_disable(struct usb_hcd *hcd, struct usb_host_endpoint *ep)
{
	struct cfhcd *c = hcd_to_cfhcd(hcd);

	/* Wait for anything on this endpoint to drain through the worker. */
	flush_work(&c->work);
}

static int cfhcd_get_frame_number(struct usb_hcd *hcd)
{
	struct cfhcd *c = hcd_to_cfhcd(hcd);

	return cfhcd_rd(c, CFHCD_DIAG) & 0x7FF;	/* sof_count low bits */
}

static void cfhcd_rh_poll(struct timer_list *t)
{
	struct cfhcd *c = from_timer(c, t, rh_timer);

	usb_hcd_poll_rh_status(c->hcd);
	mod_timer(&c->rh_timer, jiffies + msecs_to_jiffies(100));
}

static int cfhcd_hub_status_data(struct usb_hcd *hcd, char *buf)
{
	struct cfhcd *c = hcd_to_cfhcd(hcd);
	unsigned long flags;
	u32 st = cfhcd_rd(c, CFHCD_STATUS);
	bool connected = c->powered && (st & ST_DEV_CONNECTED);
	int ret = 0;

	spin_lock_irqsave(&c->lock, flags);
	if (connected != !!(c->port_status & USB_PORT_STAT_CONNECTION)) {
		if (connected)
			c->port_status |= USB_PORT_STAT_CONNECTION;
		else
			c->port_status &= ~(USB_PORT_STAT_CONNECTION |
					    USB_PORT_STAT_ENABLE |
					    USB_PORT_STAT_HIGH_SPEED);
		c->port_status |= USB_PORT_STAT_C_CONNECTION << 16;
	}
	if (c->port_status >> 16) {
		buf[0] = 1 << 1;	/* port 1 changed */
		ret = 1;
	}
	spin_unlock_irqrestore(&c->lock, flags);
	return ret;
}

static void cfhcd_hub_descriptor(struct usb_hub_descriptor *desc)
{
	memset(desc, 0, sizeof(*desc));
	desc->bDescriptorType = USB_DT_HUB;
	desc->bDescLength = 9;
	desc->bNbrPorts = 1;
	desc->wHubCharacteristics = cpu_to_le16(HUB_CHAR_INDV_PORT_LPSM |
						HUB_CHAR_NO_OCPM);
	desc->bPwrOn2PwrGood = 1;	/* 2 ms */
	desc->bHubContrCurrent = 0;
	desc->u.hs.DeviceRemovable[0] = 0;
	desc->u.hs.DeviceRemovable[1] = 0xFF; /* PortPwrCtrlMask */
}

static int cfhcd_hub_control(struct usb_hcd *hcd, u16 typeReq, u16 wValue,
			     u16 wIndex, char *buf, u16 wLength)
{
	struct cfhcd *c = hcd_to_cfhcd(hcd);
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&c->lock, flags);
	switch (typeReq) {
	case GetHubDescriptor:
		cfhcd_hub_descriptor((struct usb_hub_descriptor *)buf);
		break;
	case GetHubStatus:
		*(__le32 *)buf = cpu_to_le32(0);
		break;
	case GetPortStatus:
		if (wIndex != 1) {
			ret = -EPIPE;
			break;
		}
		*(__le32 *)buf = cpu_to_le32(c->port_status);
		break;
	case SetPortFeature:
		if (wIndex != 1) {
			ret = -EPIPE;
			break;
		}
		switch (wValue) {
		case USB_PORT_FEAT_POWER:
			c->powered = true;
			c->port_status |= USB_PORT_STAT_POWER;
			cfhcd_wr(c, CFHCD_CTRL, CTRL_VBUS_VALID);
			break;
		case USB_PORT_FEAT_RESET:
			if (!(c->port_status & USB_PORT_STAT_CONNECTION)) {
				ret = -EPIPE;
				break;
			}
			c->port_status |= USB_PORT_STAT_RESET;
			c->port_status &= ~USB_PORT_STAT_ENABLE;
			c->reset_requested = true;
			queue_work(c->wq, &c->work);
			break;
		case USB_PORT_FEAT_SUSPEND:
			/* Not supported; report success and stay awake. */
			break;
		default:
			ret = -EPIPE;
		}
		break;
	case ClearPortFeature:
		if (wIndex != 1) {
			ret = -EPIPE;
			break;
		}
		switch (wValue) {
		case USB_PORT_FEAT_ENABLE:
			c->port_status &= ~USB_PORT_STAT_ENABLE;
			break;
		case USB_PORT_FEAT_POWER:
			c->powered = false;
			c->port_status &= ~(USB_PORT_STAT_POWER |
					    USB_PORT_STAT_CONNECTION |
					    USB_PORT_STAT_ENABLE |
					    USB_PORT_STAT_HIGH_SPEED);
			cfhcd_wr(c, CFHCD_CTRL, 0);
			break;
		case USB_PORT_FEAT_C_CONNECTION:
			c->port_status &= ~(USB_PORT_STAT_C_CONNECTION << 16);
			break;
		case USB_PORT_FEAT_C_RESET:
			c->port_status &= ~(USB_PORT_STAT_C_RESET << 16);
			break;
		case USB_PORT_FEAT_C_ENABLE:
			c->port_status &= ~(USB_PORT_STAT_C_ENABLE << 16);
			break;
		case USB_PORT_FEAT_SUSPEND:
		case USB_PORT_FEAT_C_SUSPEND:
		case USB_PORT_FEAT_C_OVER_CURRENT:
			break;
		default:
			ret = -EPIPE;
		}
		break;
	case ClearHubFeature:
	case SetHubFeature:
		break;
	default:
		ret = -EPIPE;
	}
	spin_unlock_irqrestore(&c->lock, flags);
	return ret;
}

static int cfhcd_reset(struct usb_hcd *hcd)
{
	struct cfhcd *c = hcd_to_cfhcd(hcd);

	hcd->uses_new_polling = 1;
	hcd->self.sg_tablesize = 0;
	cfhcd_wr(c, CFHCD_CTRL, CTRL_VBUS_VALID | CTRL_SOFT_RESET);
	udelay(10);
	cfhcd_wr(c, CFHCD_CTRL, 0);
	cfhcd_wr(c, CFHCD_TIMEOUT, CFHCD_HW_TIMEOUT_CYC);
	return 0;
}

static int cfhcd_start(struct usb_hcd *hcd)
{
	struct cfhcd *c = hcd_to_cfhcd(hcd);

	hcd->state = HC_STATE_RUNNING;
	mod_timer(&c->rh_timer, jiffies + msecs_to_jiffies(100));
	return 0;
}

static void cfhcd_stop(struct usb_hcd *hcd)
{
	struct cfhcd *c = hcd_to_cfhcd(hcd);

	del_timer_sync(&c->rh_timer);
	flush_work(&c->work);
	cfhcd_wr(c, CFHCD_CTRL, 0);
}

static const struct hc_driver cfhcd_hc_driver = {
	.description		= DRIVER_NAME,
	.product_desc		= DRIVER_DESC,
	.hcd_priv_size		= sizeof(struct cfhcd),
	.flags			= HCD_USB2 | HCD_MEMORY,

	.reset			= cfhcd_reset,
	.start			= cfhcd_start,
	.stop			= cfhcd_stop,
	.get_frame_number	= cfhcd_get_frame_number,

	.urb_enqueue		= cfhcd_urb_enqueue,
	.urb_dequeue		= cfhcd_urb_dequeue,
	.endpoint_disable	= cfhcd_endpoint_disable,

	.hub_status_data	= cfhcd_hub_status_data,
	.hub_control		= cfhcd_hub_control,
};

/* ------------------------------------------------------------------------ */
/* Platform glue                                                             */
/* ------------------------------------------------------------------------ */

static int cfhcd_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct usb_hcd *hcd;
	struct cfhcd *c;
	struct resource *res;
	u32 magic;
	int ret;

	hcd = usb_create_hcd(&cfhcd_hc_driver, dev, dev_name(dev));
	if (!hcd)
		return -ENOMEM;
	c = hcd_to_cfhcd(hcd);
	c->hcd = hcd;
	spin_lock_init(&c->lock);
	INIT_LIST_HEAD(&c->urb_queue);
	INIT_WORK(&c->work, cfhcd_work);
	timer_setup(&c->rh_timer, cfhcd_rh_poll, 0);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	c->regs = devm_ioremap_resource(dev, res);
	if (IS_ERR(c->regs)) {
		ret = PTR_ERR(c->regs);
		goto err_put;
	}
	hcd->rsrc_start = res->start;
	hcd->rsrc_len = resource_size(res);
	hcd->regs = c->regs;

	magic = cfhcd_rd(c, CFHCD_MAGIC);
	if (magic != CFHCD_MAGIC_VALUE) {
		dev_err(dev, "no caliptra_fpga_ulpi_host at %pR (magic %08x)\n",
			res, magic);
		ret = -ENODEV;
		goto err_put;
	}

	c->wq = alloc_ordered_workqueue(DRIVER_NAME, WQ_HIGHPRI);
	if (!c->wq) {
		ret = -ENOMEM;
		goto err_put;
	}

	ret = usb_add_hcd(hcd, 0, 0);
	if (ret)
		goto err_wq;
	platform_set_drvdata(pdev, hcd);
	dev_info(dev, "registered %s at %pR (diag %08x)\n", DRIVER_DESC, res,
		 cfhcd_rd(c, CFHCD_DIAG));
	return 0;

err_wq:
	destroy_workqueue(c->wq);
err_put:
	usb_put_hcd(hcd);
	return ret;
}

static int cfhcd_remove(struct platform_device *pdev)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);
	struct cfhcd *c = hcd_to_cfhcd(hcd);

	usb_remove_hcd(hcd);
	destroy_workqueue(c->wq);
	usb_put_hcd(hcd);
	return 0;
}

static struct platform_driver cfhcd_driver = {
	.probe	= cfhcd_probe,
	.remove	= cfhcd_remove,
	.driver	= {
		.name = DRIVER_NAME,
	},
};

/*
 * The VCK-190 image has no device-tree node for the wrapper (io_module uses
 * fixed physical addresses the same way), so register a platform device here.
 */
static struct platform_device *cfhcd_pdev;

static int __init cfhcd_init(void)
{
	struct resource res = {
		.start = base_addr,
		.end = base_addr + CFHCD_REG_SIZE - 1,
		.flags = IORESOURCE_MEM,
		.name = DRIVER_NAME,
	};
	int ret;

	if (usb_disabled())
		return -ENODEV;

	ret = platform_driver_register(&cfhcd_driver);
	if (ret)
		return ret;

	cfhcd_pdev = platform_device_register_simple(DRIVER_NAME, -1, &res, 1);
	if (IS_ERR(cfhcd_pdev)) {
		platform_driver_unregister(&cfhcd_driver);
		return PTR_ERR(cfhcd_pdev);
	}
	return 0;
}

static void __exit cfhcd_exit(void)
{
	platform_device_unregister(cfhcd_pdev);
	platform_driver_unregister(&cfhcd_driver);
}

module_init(cfhcd_init);
module_exit(cfhcd_exit);

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_AUTHOR("Carl Lundin <clundin@google.com>");
MODULE_LICENSE("GPL");
