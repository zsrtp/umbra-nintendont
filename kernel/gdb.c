#include "global.h"
#include "common.h"
#include "string.h"
#include "net.h"
#include "ipc.h"
#include "gdb.h"
#include "syscalls.h"
#include "debug.h"

#define GDB_PKT_BUF_SIZE 4096
#define GDB_MAX_BREAKPOINTS 32
#define GDB_POLL_TIMEOUT_MS 50

static s32 gdb_listen_sock = -1;
static s32 gdb_fd = -1;  /* separate fd to avoid IOS RM contention with UDP listener */
static const char gdb_top_name[15] ALIGNED(32) = "/dev/net/ip/top";

/* PPC trap instruction: tw 31,0,0 */
#define PPC_TRAP_INSN 0x7FE00008

/* GDB PPC register numbering: r0-r31 (0-31), f0-f31 (32-63),
 * pc (64), msr (65), cr (66), lr (67), ctr (68), xer (69), fpscr (70),
 * padding (71-104), vr0-vr31 (105-136), vscr (137), vrsave (138) */
#define GDB_REG_PC   64
#define GDB_REG_MSR  65
#define GDB_REG_CR   66
#define GDB_REG_LR   67
#define GDB_REG_CTR  68
#define GDB_REG_XER  69
#define GDB_REG_FPSCR 70
#define GDB_NUM_REGS 71

/* Altivec/VMX register range — we don't have these but must return
 * zeros so VSCode's register panel doesn't abort on E01. */
#define GDB_REG_VR0     105
#define GDB_REG_VR31    136
#define GDB_REG_VSCR    137
#define GDB_REG_VRSAVE  138
#define GDB_REG_MAX     139  /* highest known + 1 */

static const char hexchars[] = "0123456789abcdef";

static int hex_val(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static u32 hex2u32(const char *hex, int nchars)
{
	u32 val = 0;
	int i;
	for (i = 0; i < nchars; i++)
	{
		int h = hex_val(hex[i]);
		if (h < 0) break;
		val = (val << 4) | h;
	}
	return val;
}

static int mem2hex(const u8 *mem, char *hex, int count)
{
	int i;
	for (i = 0; i < count; i++)
	{
		*hex++ = hexchars[(mem[i] >> 4) & 0xF];
		*hex++ = hexchars[mem[i] & 0xF];
	}
	*hex = 0;
	return count * 2;
}

static int hex2mem(const char *hex, u8 *mem, int count)
{
	int i;
	for (i = 0; i < count; i++)
	{
		int hi = hex_val(*hex++);
		int lo = hex_val(*hex++);
		if (hi < 0 || lo < 0) return i;
		mem[i] = (hi << 4) | lo;
	}
	return count;
}

/* ARM BE-32 word order matches PPC — no bswap needed for shared memory */

static inline u32 shm_read32(u32 offset)
{
	sync_before_read((void*)(GDB_SHM_ADDR_ARM + offset), 4);
	return read32(GDB_SHM_ADDR_ARM + offset);
}

static inline void shm_write32(u32 offset, u32 val)
{
	write32(GDB_SHM_ADDR_ARM + offset, val);
	sync_after_write((void*)(GDB_SHM_ADDR_ARM + offset), 4);
}

static inline u64 shm_read64(u32 offset)
{
	sync_before_read((void*)(GDB_SHM_ADDR_ARM + offset), 8);
	u32 hi = read32(GDB_SHM_ADDR_ARM + offset);
	u32 lo = read32(GDB_SHM_ADDR_ARM + offset + 4);
	return ((u64)hi << 32) | lo;
}

static inline void shm_write64(u32 offset, u64 val)
{
	write32(GDB_SHM_ADDR_ARM + offset, (u32)(val >> 32));
	write32(GDB_SHM_ADDR_ARM + offset + 4, (u32)val);
	sync_after_write((void*)(GDB_SHM_ADDR_ARM + offset), 8);
}

static void ic_inval_add(u32 ppc_addr)
{
	u32 cnt = shm_read32(GDB_SHM_OFF_IC_INVAL_CNT);
	if (cnt >= 8) return;
	shm_write32(GDB_SHM_OFF_IC_INVAL_ADDR + cnt * 4, ppc_addr);
	shm_write32(GDB_SHM_OFF_IC_INVAL_CNT, cnt + 1);
}

struct breakpoint {
	u32 addr;
	u32 orig_insn;
	int active;
};

static struct breakpoint bp_table[GDB_MAX_BREAKPOINTS];
static int bp_count = 0;

/* PPC BAT mapping: 0x80/0xC0 → MEM1, 0x90/0xD0 → MEM2.
 * ARM uses physical addresses; PPC uses virtual.
 * physical = addr & 0x3FFFFFFF for all BAT-mapped ranges. */
static inline u32 ppc_to_phys(u32 addr)
{
	if (addr >= 0x80000000)
		return addr & 0x3FFFFFFF;
	return addr;
}

static int bp_insert(u32 addr)
{
	int i;

	for (i = 0; i < bp_count; i++)
	{
		if (bp_table[i].active && bp_table[i].addr == addr)
			return 0;
	}

	int slot = -1;
	for (i = 0; i < bp_count; i++)
	{
		if (!bp_table[i].active)
		{
			slot = i;
			break;
		}
	}
	if (slot < 0)
	{
		if (bp_count >= GDB_MAX_BREAKPOINTS)
			return -1;
		slot = bp_count++;
	}

	u32 pa = ppc_to_phys(addr);
	sync_before_read((void*)pa, 4);
	bp_table[slot].orig_insn = read32(pa);
	bp_table[slot].addr = addr;
	bp_table[slot].active = 1;

	write32(pa, PPC_TRAP_INSN);
	sync_after_write((void*)pa, 4);
	ic_inval_add(addr);

	return 0;
}

static int bp_remove(u32 addr)
{
	int i;
	for (i = 0; i < bp_count; i++)
	{
		if (bp_table[i].active && bp_table[i].addr == addr)
		{
			u32 pa = ppc_to_phys(addr);
			write32(pa, bp_table[i].orig_insn);
			sync_after_write((void*)pa, 4);
			ic_inval_add(addr);
			bp_table[i].active = 0;
			return 0;
		}
	}
	return -1;
}

static void bp_remove_all(void)
{
	int i;
	for (i = 0; i < bp_count; i++)
	{
		if (bp_table[i].active)
		{
			u32 pa = ppc_to_phys(bp_table[i].addr);
			write32(pa, bp_table[i].orig_insn);
			sync_after_write((void*)pa, 4);
			ic_inval_add(bp_table[i].addr);
			bp_table[i].active = 0;
		}
	}
	bp_count = 0;
}

static int bp_at_addr(u32 addr, u32 *orig_insn)
{
	int i;
	for (i = 0; i < bp_count; i++)
	{
		if (bp_table[i].active && bp_table[i].addr == addr)
		{
			if (orig_insn)
				*orig_insn = bp_table[i].orig_insn;
			return 1;
		}
	}
	return 0;
}

static s32 gdb_client_sock = -1;

#define TCP_RECV_BUF_SIZE 256
#define IOS_EAGAIN (-6)
static u8  tcp_rbuf[TCP_RECV_BUF_SIZE] ALIGNED(32);
static int tcp_rbuf_pos = 0;
static int tcp_rbuf_len = 0;
static s32 tcp_last_err = 0;
static s32 tcp_last_recv_n = 0;

static void tcp_rbuf_reset(void)
{
	tcp_rbuf_pos = 0;
	tcp_rbuf_len = 0;
}

static int tcp_recv_byte(u8 *out)
{
	if (tcp_rbuf_pos >= tcp_rbuf_len)
	{
		/* Never block — IOS RM is single-threaded */
		struct pollsd psd;
		psd.socket = gdb_client_sock;
		psd.events = POLLIN;
		psd.revents = 0;
		s32 pr = net_poll(gdb_fd, &psd, 1, 100);
		if (pr < 0) { tcp_last_err = pr; return -1; }
		if (pr == 0 || !(psd.revents & POLLIN))
			return -2;
		/* Inline recvfrom: no sync_before_read after DMA.
		 * IOS writes through cache (same VA on ARM926EJ-S);
		 * invalidating would discard the new data. */
		{
			STACK_ALIGN(u32, rparams, 2, 32);
			STACK_ALIGN(ioctlv, rvec, 3, 32);
			rparams[0] = gdb_client_sock;
			rparams[1] = 0;
			rvec[0].data = rparams;
			rvec[0].len = 8;
			rvec[1].data = tcp_rbuf;
			rvec[1].len = TCP_RECV_BUF_SIZE;
			rvec[2].data = NULL;
			rvec[2].len = 0;
			sync_after_write(rparams, 8);
			sync_after_write(tcp_rbuf, TCP_RECV_BUF_SIZE);
			s32 n = IOS_Ioctlv(gdb_fd, IOCTLV_SO_RECVFROM,
					   1, 2, rvec);
			if (n == IOS_EAGAIN) return -2;
			if (n == 0) { tcp_last_err = 0; return -1; }
			if (n < 0) { tcp_last_err = n; return -1; }
			/* NO sync_before_read — data is in cache from IOS */
			tcp_last_recv_n = n;
			tcp_rbuf_pos = 0;
			tcp_rbuf_len = n;
		}
	}
	*out = tcp_rbuf[tcp_rbuf_pos++];
	return 0;
}

static int tcp_send(const void *data, int len)
{
	s32 res = net_sendto(gdb_fd, gdb_client_sock, (void *)data, len, 0);
	gdb_dbg_client_err = res;
	if (res < 0) return res;
	return len;
}

static char pkt_buf[GDB_PKT_BUF_SIZE];

/* ACK combined with next response to avoid 1-byte IOS TCP sends */
static int pending_ack = 0;

/* NoAck avoids mourn_inferior bugs in GDB 8.2.1-17.1 on exit */
static int noack_mode = 0;

static void flush_pending_ack(void)
{
	if (pending_ack && !noack_mode)
	{
		u8 ack = '+';
		tcp_send(&ack, 1);
	}
	pending_ack = 0;
}

static int gdb_recv_packet(void)
{
	u8 c;
	int len = 0;
	u8 cksum = 0;
	int rc;

	while (1)
	{
		rc = tcp_recv_byte(&c);
		if (rc == -2) return 0;
		if (rc < 0) return -1;
		if (c == '$') break;
		if (c == 0x03)
		{
			pkt_buf[0] = 0x03;
			return 1;
		}
	}

	/* Retry on EAGAIN: TCP fragmentation common on WiFi */
	while (len < GDB_PKT_BUF_SIZE - 1)
	{
		rc = tcp_recv_byte(&c);
		if (rc == -2) { mdelay(1); continue; }
		if (rc < 0) return -1;
		if (c == '#') break;
		pkt_buf[len++] = c;
		cksum += c;
	}
	pkt_buf[len] = 0;

	u8 c1, c2;
	do { rc = tcp_recv_byte(&c1); if (rc == -2) mdelay(1); } while (rc == -2);
	if (rc < 0) return -1;
	do { rc = tcp_recv_byte(&c2); if (rc == -2) mdelay(1); } while (rc == -2);
	if (rc < 0) return -1;

	u8 recv_cksum = (hex_val(c1) << 4) | hex_val(c2);
	if (recv_cksum != cksum)
	{
		u8 nakbuf[25];
		int ni = 0, bi;
		nakbuf[ni++] = '-';
		nakbuf[ni++] = hexchars[(tcp_last_recv_n >> 4) & 0xF];
		nakbuf[ni++] = hexchars[tcp_last_recv_n & 0xF];
		nakbuf[ni++] = hexchars[(len >> 4) & 0xF];
		nakbuf[ni++] = hexchars[len & 0xF];
		for (bi = 0; bi < 8; bi++)
		{
			u8 b = (bi < len) ? (u8)pkt_buf[bi] : 0;
			nakbuf[ni++] = hexchars[(b >> 4) & 0xF];
			nakbuf[ni++] = hexchars[b & 0xF];
		}
		nakbuf[ni++] = hexchars[(cksum >> 4) & 0xF];
		nakbuf[ni++] = hexchars[cksum & 0xF];
		nakbuf[ni++] = hexchars[(recv_cksum >> 4) & 0xF];
		nakbuf[ni++] = hexchars[recv_cksum & 0xF];
		tcp_send(nakbuf, ni);
		return 0;
	}

	if (!noack_mode)
		pending_ack = 1;

	return len;
}

static void gdb_send_packet(const char *data, int len)
{
	static u8 buf[GDB_PKT_BUF_SIZE + 5]; /* +1 ACK, +4 framing */
	u8 cksum = 0;
	int off = 0;
	int i;

	if (pending_ack && !noack_mode)
	{
		buf[0] = '+';
		off = 1;
		pending_ack = 0;
	}
	else
	{
		pending_ack = 0;
	}

	buf[off] = '$';
	for (i = 0; i < len && i < GDB_PKT_BUF_SIZE; i++)
	{
		buf[off + i + 1] = data[i];
		cksum += data[i];
	}
	buf[off + i + 1] = '#';
	buf[off + i + 2] = hexchars[(cksum >> 4) & 0xF];
	buf[off + i + 3] = hexchars[cksum & 0xF];

	tcp_send(buf, off + i + 4);
}

static void gdb_send_str(const char *str)
{
	int len = 0;
	while (str[len]) len++;
	gdb_send_packet(str, len);
}

static void reg32_to_hex(u32 offset, char *hex)
{
	u32 val = shm_read32(offset);
	hex[0] = hexchars[(val >> 28) & 0xF];
	hex[1] = hexchars[(val >> 24) & 0xF];
	hex[2] = hexchars[(val >> 20) & 0xF];
	hex[3] = hexchars[(val >> 16) & 0xF];
	hex[4] = hexchars[(val >> 12) & 0xF];
	hex[5] = hexchars[(val >> 8) & 0xF];
	hex[6] = hexchars[(val >> 4) & 0xF];
	hex[7] = hexchars[val & 0xF];
}

static void hex_to_reg32(const char *hex, u32 offset)
{
	u32 val = hex2u32(hex, 8);
	shm_write32(offset, val);
}

static void reg64_to_hex(u32 offset, char *hex)
{
	u64 val = shm_read64(offset);
	int i;
	for (i = 0; i < 16; i++)
	{
		hex[i] = hexchars[(val >> (60 - i * 4)) & 0xF];
	}
}

static void hex_to_reg64(const char *hex, u32 offset)
{
	u32 hi = hex2u32(hex, 8);
	u32 lo = hex2u32(hex + 8, 8);
	u64 val = ((u64)hi << 32) | lo;
	shm_write64(offset, val);
}

static int build_all_regs(char *buf)
{
	char *p = buf;
	int i;

	for (i = 0; i < 32; i++)
	{
		reg32_to_hex(GDB_SHM_OFF_GPR + i * 4, p);
		p += 8;
	}

	for (i = 0; i < 32; i++)
	{
		reg64_to_hex(GDB_SHM_OFF_FPR + i * 8, p);
		p += 16;
	}

	reg32_to_hex(GDB_SHM_OFF_PC, p); p += 8;
	reg32_to_hex(GDB_SHM_OFF_MSR, p); p += 8;
	reg32_to_hex(GDB_SHM_OFF_CR, p); p += 8;
	reg32_to_hex(GDB_SHM_OFF_LR, p); p += 8;
	reg32_to_hex(GDB_SHM_OFF_CTR, p); p += 8;
	reg32_to_hex(GDB_SHM_OFF_XER, p); p += 8;
	{
		u64 fpscr = shm_read64(GDB_SHM_OFF_FPSCR);
		u32 fpscr32 = (u32)fpscr;
		p[0] = hexchars[(fpscr32 >> 28) & 0xF];
		p[1] = hexchars[(fpscr32 >> 24) & 0xF];
		p[2] = hexchars[(fpscr32 >> 20) & 0xF];
		p[3] = hexchars[(fpscr32 >> 16) & 0xF];
		p[4] = hexchars[(fpscr32 >> 12) & 0xF];
		p[5] = hexchars[(fpscr32 >> 8) & 0xF];
		p[6] = hexchars[(fpscr32 >> 4) & 0xF];
		p[7] = hexchars[fpscr32 & 0xF];
		p += 8;
	}

	*p = 0;
	return (int)(p - buf);
}

static int read_single_reg(int regnum, char *buf)
{
	if (regnum < 32)
	{
		reg32_to_hex(GDB_SHM_OFF_GPR + regnum * 4, buf);
		return 8;
	}
	else if (regnum < 64)
	{
		reg64_to_hex(GDB_SHM_OFF_FPR + (regnum - 32) * 8, buf);
		return 16;
	}
	else switch (regnum)
	{
	case GDB_REG_PC:  reg32_to_hex(GDB_SHM_OFF_PC, buf);  return 8;
	case GDB_REG_MSR: reg32_to_hex(GDB_SHM_OFF_MSR, buf); return 8;
	case GDB_REG_CR:  reg32_to_hex(GDB_SHM_OFF_CR, buf);  return 8;
	case GDB_REG_LR:  reg32_to_hex(GDB_SHM_OFF_LR, buf);  return 8;
	case GDB_REG_CTR: reg32_to_hex(GDB_SHM_OFF_CTR, buf); return 8;
	case GDB_REG_XER: reg32_to_hex(GDB_SHM_OFF_XER, buf); return 8;
	case GDB_REG_FPSCR:
	{
		u64 fpscr = shm_read64(GDB_SHM_OFF_FPSCR);
		u32 fpscr32 = (u32)fpscr;
		buf[0] = hexchars[(fpscr32 >> 28) & 0xF];
		buf[1] = hexchars[(fpscr32 >> 24) & 0xF];
		buf[2] = hexchars[(fpscr32 >> 20) & 0xF];
		buf[3] = hexchars[(fpscr32 >> 16) & 0xF];
		buf[4] = hexchars[(fpscr32 >> 12) & 0xF];
		buf[5] = hexchars[(fpscr32 >> 8) & 0xF];
		buf[6] = hexchars[(fpscr32 >> 4) & 0xF];
		buf[7] = hexchars[fpscr32 & 0xF];
		return 8;
	}
	default:
		/* Unsupported registers: return zeros sized to match GDB's
		 * target description so VSCode doesn't abort register display.
		 * vr0-vr31 + vscr are 128-bit; padding/vrsave are 32-bit. */
		if (regnum < GDB_REG_MAX)
		{
			int nchars;
			int i;
			if (regnum >= GDB_REG_VR0 && regnum <= GDB_REG_VSCR)
				nchars = 32;  /* 128-bit */
			else
				nchars = 8;   /* 32-bit */
			for (i = 0; i < nchars; i++)
				buf[i] = '0';
			return nchars;
		}
		return 0;
	}
}

static int write_single_reg(int regnum, const char *hex)
{
	if (regnum < 32)
	{
		hex_to_reg32(hex, GDB_SHM_OFF_GPR + regnum * 4);
		return 0;
	}
	else if (regnum < 64)
	{
		hex_to_reg64(hex, GDB_SHM_OFF_FPR + (regnum - 32) * 8);
		return 0;
	}
	else switch (regnum)
	{
	case GDB_REG_PC:  hex_to_reg32(hex, GDB_SHM_OFF_PC);  return 0;
	case GDB_REG_MSR: hex_to_reg32(hex, GDB_SHM_OFF_MSR); return 0;
	case GDB_REG_CR:  hex_to_reg32(hex, GDB_SHM_OFF_CR);  return 0;
	case GDB_REG_LR:  hex_to_reg32(hex, GDB_SHM_OFF_LR);  return 0;
	case GDB_REG_CTR: hex_to_reg32(hex, GDB_SHM_OFF_CTR); return 0;
	case GDB_REG_XER: hex_to_reg32(hex, GDB_SHM_OFF_XER); return 0;
	case GDB_REG_FPSCR:
	{
		u32 val = hex2u32(hex, 8);
		shm_write64(GDB_SHM_OFF_FPSCR, (u64)val);
		return 0;
	}
	default:
		/* Accept writes to unsupported registers silently */
		if (regnum < GDB_REG_MAX)
			return 0;
		return -1;
	}
}

static int gdb_read_mem(u32 addr, int len, char *hex)
{
	int i;
	u32 pa = ppc_to_phys(addr);
	sync_before_read((void*)pa, len);
	for (i = 0; i < len; i++)
	{
		u32 aligned = (pa + i) & ~3;
		u32 word = read32(aligned);
		int shift = (3 - ((pa + i) & 3)) * 8;
		u8 b = (word >> shift) & 0xFF;
		*hex++ = hexchars[(b >> 4) & 0xF];
		*hex++ = hexchars[b & 0xF];
	}
	*hex = 0;
	return len * 2;
}

static int gdb_write_mem(u32 addr, const char *hex, int len)
{
	int i;
	u32 pa = ppc_to_phys(addr);
	for (i = 0; i < len; i++)
	{
		int hi = hex_val(*hex++);
		int lo = hex_val(*hex++);
		if (hi < 0 || lo < 0) return -1;
		u8 b = (hi << 4) | lo;

		u32 aligned = (pa + i) & ~3;
		sync_before_read((void*)aligned, 4);
		u32 word = read32(aligned);
		int shift = (3 - ((pa + i) & 3)) * 8;
		word = (word & ~(0xFF << shift)) | (b << shift);
		write32(aligned, word);
		sync_after_write((void*)aligned, 4);
	}
	return 0;
}

static void do_continue(void)
{
	u32 pc = shm_read32(GDB_SHM_OFF_PC);
	u32 pa = ppc_to_phys(pc);
	u32 orig_insn;

	if (bp_at_addr(pc, &orig_insn))
	{
		/* Step past breakpoint: restore, step, re-insert */
		write32(pa, orig_insn);
		sync_after_write((void*)pa, 4);
		ic_inval_add(pc);

		shm_write32(GDB_SHM_OFF_STATE, GDB_STATE_STEP);

		{
			int step_wait = 0;
			while (shm_read32(GDB_SHM_OFF_STATE) != GDB_STATE_STOPPED)
			{
				mdelay(1);
				if (++step_wait > 3000)
					break;  /* 3s timeout — avoid infinite hang */
			}
		}

		write32(pa, PPC_TRAP_INSN);
		sync_after_write((void*)pa, 4);
		ic_inval_add(pc);
	}

	shm_write32(GDB_SHM_OFF_STATE, GDB_STATE_RESUME);
}

static void do_step(void)
{
	u32 pc = shm_read32(GDB_SHM_OFF_PC);
	u32 pa = ppc_to_phys(pc);
	u32 orig_insn;

	if (bp_at_addr(pc, &orig_insn))
	{
		write32(pa, orig_insn);
		sync_after_write((void*)pa, 4);
	}

	shm_write32(GDB_SHM_OFF_STATE, GDB_STATE_STEP);

	if (bp_at_addr(pc, NULL))
	{
	}
}

static void make_stop_reply(char *buf)
{
	u32 sig = shm_read32(GDB_SHM_OFF_SIGNAL);
	buf[0] = 'S';
	buf[1] = hexchars[(sig >> 4) & 0xF];
	buf[2] = hexchars[sig & 0xF];
	buf[3] = 0;
}

static int gdb_handle_command(const char *cmd, int len)
{
	static char reply[GDB_PKT_BUF_SIZE];

	if (len == 1 && cmd[0] == 0x03)
	{
		u32 state = shm_read32(GDB_SHM_OFF_STATE);
		if (state != GDB_STATE_STOPPED)
		{
			shm_write32(GDB_SHM_OFF_MAGIC, GDB_SHM_MAGIC);
			shm_write32(GDB_SHM_OFF_HALT_REQ, 1);
			return 2;
		}
		make_stop_reply(reply);
		gdb_send_str(reply);
		return 0;
	}

	switch (cmd[0])
	{
	case '?':
	{
		/* Flush ACK before halt wait — halt can take ~3s, GDB
		 * will timeout and retransmit if ACK is deferred */
		flush_pending_ack();

		u32 qstate = shm_read32(GDB_SHM_OFF_STATE);
		if (qstate != GDB_STATE_STOPPED)
		{
			/* Defer MAGIC/HALT_REQ to here so TCP handshake
			 * doesn't freeze the game */
			shm_write32(GDB_SHM_OFF_STATE, GDB_STATE_IDLE);
			shm_write32(GDB_SHM_OFF_MAGIC, GDB_SHM_MAGIC);
			shm_write32(GDB_SHM_OFF_HALT_REQ, 1);

			u32 hb_before = shm_read32(GDB_SHM_OFF_PPC_HEARTBEAT);

			int wait_ms = 0;
			while (wait_ms < 3000)
			{
				mdelay(10);
				wait_ms += 10;
				qstate = shm_read32(GDB_SHM_OFF_STATE);
				if (qstate == GDB_STATE_STOPPED)
					break;
			}

			u32 hb_after = shm_read32(GDB_SHM_OFF_PPC_HEARTBEAT);
			u32 seen_after = shm_read32(GDB_SHM_OFF_PPC_HALT_SEEN);
			u32 halt_after = shm_read32(GDB_SHM_OFF_HALT_REQ);
			gdb_dbg_ppc_hb = hb_after;
			gdb_dbg_ppc_seen = seen_after;
			gdb_dbg_shm_halt = halt_after;
			gdb_dbg_shm_state = qstate;
			/* Store hb_before in an unused debug field for comparison */
			gdb_dbg_last_poll = (s32)hb_before;

			if (qstate != GDB_STATE_STOPPED)
			{
				gdb_send_str("S02");
				break;
			}
		}
		make_stop_reply(reply);
		gdb_send_str(reply);
		break;
	}

	case 'g':
	{
		int n = build_all_regs(reply);
		gdb_send_packet(reply, n);
		break;
	}

	case 'G':
	{
		const char *hex = cmd + 1;
		int i;

		for (i = 0; i < 32; i++)
		{
			hex_to_reg32(hex, GDB_SHM_OFF_GPR + i * 4);
			hex += 8;
		}
		for (i = 0; i < 32; i++)
		{
			hex_to_reg64(hex, GDB_SHM_OFF_FPR + i * 8);
			hex += 16;
		}
		hex_to_reg32(hex, GDB_SHM_OFF_PC);  hex += 8;
		hex_to_reg32(hex, GDB_SHM_OFF_MSR); hex += 8;
		hex_to_reg32(hex, GDB_SHM_OFF_CR);  hex += 8;
		hex_to_reg32(hex, GDB_SHM_OFF_LR);  hex += 8;
		hex_to_reg32(hex, GDB_SHM_OFF_CTR); hex += 8;
		hex_to_reg32(hex, GDB_SHM_OFF_XER); hex += 8;
		{
			u32 val = hex2u32(hex, 8);
			shm_write64(GDB_SHM_OFF_FPSCR, (u64)val);
		}
		gdb_send_str("OK");
		break;
	}

	case 'p':
	{
		u32 regnum = hex2u32(cmd + 1, len - 1);
		int n = read_single_reg(regnum, reply);
		if (n > 0)
		{
			reply[n] = 0;
			gdb_send_packet(reply, n);
		}
		else
			gdb_send_str("E01");
		break;
	}

	case 'P':
	{
		const char *eq = cmd + 1;
		while (*eq && *eq != '=') eq++;
		if (!*eq) { gdb_send_str("E01"); break; }
		u32 regnum = hex2u32(cmd + 1, (int)(eq - (cmd + 1)));
		if (write_single_reg(regnum, eq + 1) == 0)
			gdb_send_str("OK");
		else
			gdb_send_str("E01");
		break;
	}

	case 'm':
	{
		const char *comma = cmd + 1;
		while (*comma && *comma != ',') comma++;
		if (!*comma) { gdb_send_str("E01"); break; }
		u32 addr = hex2u32(cmd + 1, (int)(comma - (cmd + 1)));
		u32 mlen = hex2u32(comma + 1, len - (int)(comma + 1 - cmd));
		if (mlen > (GDB_PKT_BUF_SIZE - 1) / 2)
			mlen = (GDB_PKT_BUF_SIZE - 1) / 2;
		int n = gdb_read_mem(addr, mlen, reply);
		gdb_send_packet(reply, n);
		break;
	}

	case 'M':
	{
		const char *comma = cmd + 1;
		while (*comma && *comma != ',') comma++;
		if (!*comma) { gdb_send_str("E01"); break; }
		const char *colon = comma + 1;
		while (*colon && *colon != ':') colon++;
		if (!*colon) { gdb_send_str("E01"); break; }
		u32 addr = hex2u32(cmd + 1, (int)(comma - (cmd + 1)));
		u32 mlen = hex2u32(comma + 1, (int)(colon - (comma + 1)));
		if (gdb_write_mem(addr, colon + 1, mlen) == 0)
			gdb_send_str("OK");
		else
			gdb_send_str("E01");
		break;
	}

	case 'c':
	{
		flush_pending_ack();
		if (len > 1)
		{
			u32 addr = hex2u32(cmd + 1, len - 1);
			shm_write32(GDB_SHM_OFF_PC, addr);
		}
		do_continue();
		break;
	}

	case 's':
	{
		flush_pending_ack();
		if (len > 1)
		{
			u32 addr = hex2u32(cmd + 1, len - 1);
			shm_write32(GDB_SHM_OFF_PC, addr);
		}
		do_step();
		break;
	}

	case 'Z':
	{
		if (cmd[1] != '0') { gdb_send_str(""); break; }
		const char *comma1 = cmd + 3;
		while (*comma1 && *comma1 != ',') comma1++;
		if (!*comma1) { gdb_send_str("E01"); break; }
		u32 addr = hex2u32(cmd + 3, (int)(comma1 - (cmd + 3)));
		if (bp_insert(addr) == 0)
			gdb_send_str("OK");
		else
			gdb_send_str("E01");
		break;
	}

	case 'z':
	{
		if (cmd[1] != '0') { gdb_send_str(""); break; }
		const char *comma1 = cmd + 3;
		while (*comma1 && *comma1 != ',') comma1++;
		if (!*comma1) { gdb_send_str("E01"); break; }
		u32 addr = hex2u32(cmd + 3, (int)(comma1 - (cmd + 3)));
		if (bp_remove(addr) == 0)
			gdb_send_str("OK");
		else
			gdb_send_str("E01");
		break;
	}

	case 'D':
		gdb_send_str("OK");
		bp_remove_all();
		shm_write32(GDB_SHM_OFF_STATE, GDB_STATE_DETACH);
		return 1;

	case 'k':
		bp_remove_all();
		shm_write32(GDB_SHM_OFF_EXIT_REQ, 1);
		shm_write32(GDB_SHM_OFF_STATE, GDB_STATE_DETACH);
		return 1;

	case 'H':
		gdb_send_str("OK");
		break;

	case 'q':
		if (len >= 10 && memcmp(cmd, "qSupported", 10) == 0)
		{
			gdb_send_str("PacketSize=1000;QStartNoAckMode+");
		}
		else if (len >= 9 && memcmp(cmd, "qAttached", 9) == 0)
		{
			gdb_send_str("1");
		}
		else if (len >= 2 && cmd[1] == 'C')
		{
			gdb_send_str("QC1");
		}
		else if (len >= 12 && memcmp(cmd, "qfThreadInfo", 12) == 0)
		{
			gdb_send_str("m1");
		}
		else if (len >= 12 && memcmp(cmd, "qsThreadInfo", 12) == 0)
		{
			gdb_send_str("l");
		}
		else
		{
			gdb_send_str("");
		}
		break;

	case 'Q':
		if (len >= 15 && memcmp(cmd, "QStartNoAckMode", 15) == 0)
		{
			/* Flush ACK separately — GDB reads + then $OK# */
			flush_pending_ack();
			gdb_send_str("OK");
			noack_mode = 1;
			return 0;
		}
		gdb_send_str("");
		break;

	case 'T':
		gdb_send_str("OK");
		break;

	default:
		gdb_send_str("");
		break;
	}

	return 0;
}

static u16 gdb_port = 0;
static volatile u32 gdb_running = 0;

volatile u32 gdb_dbg_state = 0;
volatile s32 gdb_dbg_err = 0;
volatile u32 gdb_dbg_polls = 0;
volatile s32 gdb_dbg_last_poll = 0;
volatile u32 gdb_dbg_shm_halt = 0xDEAD;
volatile u32 gdb_dbg_shm_state = 0xDEAD;
volatile u32 gdb_dbg_ppc_hb = 0;
volatile u32 gdb_dbg_ppc_seen = 0;
volatile s32 gdb_dbg_client_err = 0;
volatile u32 gdb_dbg_client_polls = 0;

static u32 GDBServerThread(void *arg)
{
	gdb_dbg_state = 5;

	while (gdb_running)
	{
		struct pollsd apsd;
		apsd.socket = gdb_listen_sock;
		apsd.events = POLLIN;
		apsd.revents = 0;
		s32 pr = net_poll(gdb_fd, &apsd, 1, 100);
		if (pr <= 0 || !(apsd.revents & POLLIN))
			continue;

		s32 client = net_accept(gdb_fd, gdb_listen_sock);
		gdb_dbg_polls++;

		if (client < 0)
		{
			gdb_dbg_err = client;
			mdelay(100);
			continue;
		}

		gdb_dbg_state = 6;
		gdb_dbg_last_poll = client;
		gdb_client_sock = client;
		tcp_rbuf_reset();
		noack_mode = 0;

		/* MAGIC deferred until '?' to avoid freezing game during TCP handshake */
		shm_write32(GDB_SHM_OFF_HALT_REQ, 0);
		shm_write32(GDB_SHM_OFF_STATE, GDB_STATE_IDLE);

		{
			u32 one = 1;
			net_setsockopt(gdb_fd, client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
		}

		int detached = 0;
		u32 cmd_history = 0;
		gdb_dbg_err = 0;
		gdb_dbg_client_polls = 0;
		pending_ack = 0;
		while (gdb_running && !detached)
		{
			int plen = gdb_recv_packet();
			if (plen < 0)
			{
				gdb_dbg_err = tcp_last_err;
				break; /* disconnect */
			}
			if (plen == 0)
			{
				mdelay(1);
				continue;
			}

			gdb_dbg_client_polls++;
			gdb_dbg_last_poll = (s32)pkt_buf[0];
			cmd_history = (cmd_history << 8) | (u8)pkt_buf[0];
			gdb_dbg_shm_halt = cmd_history;
			int r = gdb_handle_command(pkt_buf, plen);
			if (r == 1)
			{
				detached = 1;
				break;
			}

			u32 state = shm_read32(GDB_SHM_OFF_STATE);
			if (state == GDB_STATE_RESUME || state == GDB_STATE_STEP)
			{
				flush_pending_ack();
				while (gdb_running)
				{
					state = shm_read32(GDB_SHM_OFF_STATE);
					if (state == GDB_STATE_STOPPED)
					{
						char reply[4];
						make_stop_reply(reply);
						gdb_send_str(reply);
						break;
					}

					u8 cc;
					int crc = tcp_recv_byte(&cc);
					if (crc == 0 && cc == 0x03)
					{
						shm_write32(GDB_SHM_OFF_MAGIC, GDB_SHM_MAGIC);
						shm_write32(GDB_SHM_OFF_HALT_REQ, 1);
					}
					else if (crc == -1)
					{
						detached = 1;
						break;
					}

					mdelay(10);
				}
			}
		}

		net_close(gdb_fd, client);
		gdb_client_sock = -1;

		/* Always remove breakpoints on disconnect — even unclean.
		 * Without this, trap instructions (tw 31,0,0) remain in PPC
		 * memory and crash the game on resume. */
		bp_remove_all();

		shm_write32(GDB_SHM_OFF_STATE, GDB_STATE_DETACH);
		shm_write32(GDB_SHM_OFF_HALT_REQ, 0);
		shm_write32(GDB_SHM_OFF_MAGIC, 0);
		gdb_dbg_state = 5;
	}

	shm_write32(GDB_SHM_OFF_MAGIC, 0);
	net_close(gdb_fd, gdb_listen_sock);
	gdb_listen_sock = -1;
	IOS_Close(gdb_fd);
	gdb_fd = -1;
	return 0;
}

s32 gdb_start(u16 port)
{
	if (gdb_running)
		return 0;

	if (!NetworkStarted)
		return -1;

	gdb_port = port;
	if (gdb_port == 0)
		gdb_port = 2159;

	gdb_dbg_state = 0;
	gdb_dbg_err = 0;
	gdb_dbg_polls = 0;
	gdb_dbg_last_poll = 0;
	gdb_dbg_shm_halt = 0xDEAD;
	gdb_dbg_shm_state = 0xDEAD;
	gdb_dbg_ppc_hb = 0xDEAD;
	gdb_dbg_ppc_seen = 0xDEAD;
	gdb_dbg_client_err = 0;
	gdb_dbg_client_polls = 0;

	/* Own fd to avoid IOS RM contention with UDP listener thread */
	gdb_fd = IOS_Open(gdb_top_name, 0);
	if (gdb_fd < 0)
	{
		gdb_dbg_err = gdb_fd;
		return -6;
	}

	gdb_listen_sock = net_socket(gdb_fd, AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (gdb_listen_sock < 0)
	{
		gdb_dbg_err = gdb_listen_sock;
		IOS_Close(gdb_fd);
		gdb_fd = -1;
		return -3;
	}

	s32 res = net_bind(gdb_fd, gdb_listen_sock, INADDR_ANY, gdb_port);
	if (res < 0)
	{
		gdb_dbg_err = res;
		net_close(gdb_fd, gdb_listen_sock);
		gdb_listen_sock = -1;
		IOS_Close(gdb_fd);
		gdb_fd = -1;
		return -4;
	}

	res = net_listen(gdb_fd, gdb_listen_sock, 1);
	if (res < 0)
	{
		gdb_dbg_err = res;
		net_close(gdb_fd, gdb_listen_sock);
		gdb_listen_sock = -1;
		IOS_Close(gdb_fd);
		gdb_fd = -1;
		return -5;
	}

	/* MAGIC deferred until GDB client connects (avoids halting game) */
	shm_write32(GDB_SHM_OFF_HALT_REQ, 0);
	shm_write32(GDB_SHM_OFF_STATE, GDB_STATE_IDLE);
	shm_write32(GDB_SHM_OFF_MAGIC, 0);

	gdb_running = 1;

	u32 *stack = (u32*)heap_alloc_aligned(0, 0x4000, 32);
	if (!stack)
	{
		gdb_running = 0;
		return -2;
	}

	u32 tid = thread_create(GDBServerThread, NULL, stack, 0x4000 / sizeof(u32), 0x78, 1);
	thread_continue(tid);
	return 0;
}
