#ifndef __GDB_H__
#define __GDB_H__

#include "global.h"

#define GDB_SHM_ADDR_ARM  0x13003600
#define GDB_SHM_ADDR_PPC  0x93003600  /* same physical memory, PPC mapping */

#define GDB_SHM_SIZE      512

#define GDB_SHM_MAGIC     0x47444253  /* "GDBS" */

#define GDB_STATE_IDLE    0
#define GDB_STATE_STOPPED 1
#define GDB_STATE_RESUME  2
#define GDB_STATE_STEP    3
#define GDB_STATE_DETACH  4

#define GDB_SHM_OFF_MAGIC       0x000
#define GDB_SHM_OFF_STATE       0x004
#define GDB_SHM_OFF_STOP_REASON 0x008
#define GDB_SHM_OFF_SIGNAL      0x00C
#define GDB_SHM_OFF_GPR         0x010  /* 32 * 4 = 128 bytes */
#define GDB_SHM_OFF_PC          0x090
#define GDB_SHM_OFF_LR          0x094
#define GDB_SHM_OFF_CR          0x098
#define GDB_SHM_OFF_CTR         0x09C
#define GDB_SHM_OFF_XER         0x0A0
#define GDB_SHM_OFF_MSR         0x0A4
#define GDB_SHM_OFF_FPR         0x0A8  /* 32 * 8 = 256 bytes */
#define GDB_SHM_OFF_FPSCR       0x1A8  /* 8 bytes */
#define GDB_SHM_OFF_HALT_REQ    0x1B0  /* ARM sets 1 to request PPC halt */
#define GDB_SHM_OFF_PPC_HEARTBEAT 0x1B4 /* PPC writes frame counter here */
#define GDB_SHM_OFF_PPC_HALT_SEEN 0x1B8 /* PPC writes HALT_REQ value it reads */
#define GDB_SHM_OFF_EXIT_REQ     0x1BC /* ARM sets 1 to request PPC game exit */
#define GDB_SHM_OFF_IC_INVAL_CNT  0x1C0 /* Number of addrs to invalidate (0-8) */
#define GDB_SHM_OFF_IC_INVAL_ADDR 0x1C4 /* Array of up to 8 PPC virtual addrs */

s32 gdb_start(u16 port);

extern volatile u32 gdb_dbg_state;
extern volatile s32 gdb_dbg_err;
extern volatile u32 gdb_dbg_polls;
extern volatile s32 gdb_dbg_last_poll;
extern volatile u32 gdb_dbg_shm_halt;
extern volatile u32 gdb_dbg_shm_state;
extern volatile u32 gdb_dbg_ppc_hb;
extern volatile u32 gdb_dbg_ppc_seen;
extern volatile s32 gdb_dbg_client_err;
extern volatile u32 gdb_dbg_client_polls;

#endif /* __GDB_H__ */
