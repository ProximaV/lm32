/* LM32 IDP hardware defines - thanks to Proxima's proc gen

*/

#ifndef __LM32_HPP
#define __LM32_HPP
#pragma warning (disable : 4146)
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <name.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <problems.hpp>
#include <frame.hpp>
#include <jumptable.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <segregs.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include "ins.hpp"
#include "../idaidp.hpp"
#include "../iohandler.hpp"

#define lm32_type specval_shorts.low



#define OPVAL_H_GR_BASE   0
#define OPVAL_H_CSR_BASE  32
#define OPVAL_HW_H_GP     26
#define OPVAL_HW_H_FP     27
#define OPVAL_HW_H_SP     28
#define OPVAL_HW_H_RA     29
#define OPVAL_HW_H_EA     30
#define OPVAL_HW_H_BA     31

enum lm32_registers
{
    r_r0, r_r1, r_r2, r_r3, r_r4, r_r5, r_r6, r_r7,
    r_r8, r_r9, r_r10, r_r11, r_r12, r_r13, r_r14, r_r15,
    r_r16, r_r17, r_r18, r_r19, r_r20, r_r21, r_r22, r_r23,
    r_r24, r_r25, r_gp, r_fp, r_sp, r_ra, r_ea, r_ba,
    r_ie, r_im, r_ip, r_icc, r_dcc, r_cc, r_cfg, r_eba,
    r_dc, r_deba, r_cfg2,
    r_csr_b, r_csr_c, r_csr_d,
    r_jtx, r_jrx,
    r_bp0, r_bp1, r_bp2, r_bp3,
    r_csr_14, r_csr_15, r_csr_16, r_csr_17,
    r_wp0, r_wp1, r_wp2, r_wp3,
    r_csr_1c, r_psw, r_tlbvad, r_tlbpad,
    r_cs, r_ds
};

#define REGS_COUNT (r_ds + 1)

typedef enum lm32_operand_type {
    LM32_OPERAND_PC,
    LM32_OPERAND_R0,
    LM32_OPERAND_R1,
    LM32_OPERAND_R2,
    LM32_OPERAND_SHIFT,
    LM32_OPERAND_IMM,
    LM32_OPERAND_UIMM,
    LM32_OPERAND_BRANCH,
    LM32_OPERAND_CALL,
    LM32_OPERAND_CSR,
    LM32_OPERAND_USER,
    LM32_OPERAND_EXCEPTION,
    LM32_OPERAND_HI16,
    LM32_OPERAND_LO16,
    LM32_OPERAND_GP16,
    LM32_OPERAND_GOT16,
    LM32_OPERAND_GOTOFFHI16,
    LM32_OPERAND_GOTOFFLO16,
} LM32_OPERAND_TYPE;

/* Number of operands types.  */
#define MAX_OPERANDS 18

/* Maximum number of operands referenced by any insn.  */
#define MAX_OPERAND_INSTANCES 6

/* IDP exports */

DECLARE_PROC_LISTENER(idb_listener_t, struct LM32_t);

struct LM32_t : public procmod_t
{
    netnode helper;
    iohandler_t ioh = iohandler_t(helper);
    idb_listener_t idb_listener = idb_listener_t(*this);

    virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

    int LM32_ana(insn_t* _insn);
    int LM32_emu(const insn_t& insn);
    bool LM32_is_switch(switch_info_t* si, const insn_t& insn);
    void load_from_idb();
    bool LM32_find_ioport_bit(outctx_t& ctx, int port, int bit);
    int idaapi is_sp_based(const insn_t& insn, const op_t& op);
    bool idaapi create_func_frame(ea_t func_ea);
};

#define PROCMOD_NODE_NAME "$ LM32"
#define PROCMOD_NAME LM32

extern int data_id;

#endif
