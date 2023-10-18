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
#include "ins.hpp"
#include "../idaidp.hpp"
#include "../iohandler.hpp"

#define lm32_type specval_shorts.low



#define OPVAL_H_GR_BASE  0
#define OPVAL_H_CSR_BASE  32
#define REGS_COUNT 65
#define OPVAL_HW_H_SP 28

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
};

#define PROCMOD_NODE_NAME "$ LM32"
#define PROCMOD_NAME LM32

extern int data_id;

#endif
