/* LM32 IDP hardware defines

THIS FILE IS MACHINE GENERATED WITH CGEN.

Copyright 1996-2010 Free Software Foundation, Inc.

This file is part of the GNU Binutils and/or GDB, the GNU debugger.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.

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

/* needed for cgen.h */
#define CGEN_ARCH LM32
#define CGEN_SYM(s) LM32##_cgen_##s

/* for referring to operand type in cmd */
#define cgen_optype specval_shorts.low

/* Offsets for register names by cgen hw name */

#define REGS_HW_H_PC_BASE 0
#define REGS_HW_H_GR_BASE 1
#define REGS_HW_H_CSR_BASE 33
#define REGS_COUNT 65
#define REGS_HW_H_SP 29
/* Hardware attribute indices.  */

/* Enum declaration for cgen_hw attrs.  */
typedef enum cgen_hw_attr {
    CGEN_HW_VIRTUAL,
    CGEN_HW_CACHE_ADDR,
    CGEN_HW_PC,
    CGEN_HW_PROFILE,
    CGEN_HW_END_BOOLS,
    CGEN_HW_START_NBOOLS = 31,
    CGEN_HW_MACH,
    CGEN_HW_END_NBOOLS
} CGEN_HW_ATTR;

/* Number of non-boolean elements in cgen_hw_attr.  */
#define CGEN_HW_NBOOL_ATTRS (CGEN_HW_END_NBOOLS - CGEN_HW_START_NBOOLS - 1)

/* cgen_hw attribute accessor macros.  */
#define CGEN_ATTR_CGEN_HW_MACH_VALUE(attrs) ((attrs)->nonbool[CGEN_HW_MACH-CGEN_HW_START_NBOOLS-1].nonbitset)
#define CGEN_ATTR_CGEN_HW_VIRTUAL_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_HW_VIRTUAL)) != 0)
#define CGEN_ATTR_CGEN_HW_CACHE_ADDR_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_HW_CACHE_ADDR)) != 0)
#define CGEN_ATTR_CGEN_HW_PC_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_HW_PC)) != 0)
#define CGEN_ATTR_CGEN_HW_PROFILE_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_HW_PROFILE)) != 0)

/* Enum declaration for LM32 hardware types.  */
typedef enum cgen_hw_type {
    HW_H_MEMORY,
    HW_H_SINT,
    HW_H_UINT,
    HW_H_ADDR,
    HW_H_IADDR,
    HW_H_PC,
    HW_H_GR,
    HW_H_CSR,
    HW_MAX
} CGEN_HW_TYPE;

#define MAX_HW ((int) HW_MAX)

/* Operand attribute indices.  */

/* Enum declaration for cgen_operand attrs.  */
typedef enum cgen_operand_attr {
    CGEN_OPERAND_VIRTUAL,
    CGEN_OPERAND_PCREL_ADDR,
    CGEN_OPERAND_ABS_ADDR,
    CGEN_OPERAND_SIGN_OPT,
    CGEN_OPERAND_SIGNED,
    CGEN_OPERAND_NEGATIVE,
    CGEN_OPERAND_RELAX,
    CGEN_OPERAND_SEM_ONLY,
    CGEN_OPERAND_END_BOOLS,
    CGEN_OPERAND_START_NBOOLS = 31,
    CGEN_OPERAND_MACH,
    CGEN_OPERAND_END_NBOOLS
} CGEN_OPERAND_ATTR;

/* Number of non-boolean elements in cgen_operand_attr.  */
#define CGEN_OPERAND_NBOOL_ATTRS (CGEN_OPERAND_END_NBOOLS - CGEN_OPERAND_START_NBOOLS - 1)

/* cgen_operand attribute accessor macros.  */
#define CGEN_ATTR_CGEN_OPERAND_MACH_VALUE(attrs) ((attrs)->nonbool[CGEN_OPERAND_MACH-CGEN_OPERAND_START_NBOOLS-1].nonbitset)
#define CGEN_ATTR_CGEN_OPERAND_VIRTUAL_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_VIRTUAL)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_PCREL_ADDR_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_PCREL_ADDR)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_ABS_ADDR_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_ABS_ADDR)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_SIGN_OPT_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_SIGN_OPT)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_SIGNED_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_SIGNED)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_NEGATIVE_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_NEGATIVE)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_RELAX_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_RELAX)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_SEM_ONLY_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_SEM_ONLY)) != 0)

/* Enum declaration for LM32 operand types.  */
typedef enum cgen_operand_type {
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
    LM32_OPERAND_MAX, 
    LM32_OPERAND_DISPL
 } CGEN_OPERAND_TYPE;

/* Number of operands types.  */
#define MAX_OPERANDS 18

/* Maximum number of operands referenced by any insn.  */
#define MAX_OPERAND_INSTANCES 6

/* cgen.h must be included after all that decls */
#include "cgen.h"

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
