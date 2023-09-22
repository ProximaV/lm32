/* LM32 IDP output

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

#include "lm32.hpp"
class out_LM32_t : public outctx_t
{
    out_LM32_t(void) = delete; // not used
public:
    bool out_operand(const op_t& x);
    void out_insn(void);
private:
    void out_print_address(const op_t& x, ea_t pc, int n = 0);
    void out_print_spreg(const op_t&/*x*/, ea_t /*pc*/);
    void out_print_fpreg(const op_t&/*x*/, ea_t /*pc*/);
    bool cgen_outop(const op_t& x, uint16 opindex, ea_t pc);
};
CASSERT(sizeof(out_LM32_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_LM32_t);


void out_LM32_t::out_print_address(const op_t& x, ea_t pc, int n)
{
    const char* prefix;

    refinfo_t ri;
    if (get_refinfo(&ri, pc, n))
    {
        switch (ri.type())
        {
        case REF_LOW8: prefix = "low8"; break;
        case REF_LOW16: prefix = "low16"; break;
        case REF_HIGH8: prefix = "high8"; break;
        case REF_HIGH16: prefix = "high16"; break;
        default: prefix = NULL; break;
        }
    }
    else
    {
        prefix = NULL;
    }

    if (prefix)
    {
        out_line(prefix, COLOR_MACRO);
        out_line("(", COLOR_MACRO);
    }
    if (!out_name_expr(x, x.addr))
    {
        out_tagon(COLOR_ERROR);
        out_value(x, OOF_ADDR | OOFW_32 | OOF_NUMBER | OOFS_NOSIGN);
        out_tagoff(COLOR_ERROR);
        remember_problem(PR_NONAME, insn.ea);
    }
    if (prefix)
    {
        out_line(")", COLOR_MACRO);
    }
}

void out_LM32_t::out_print_spreg(const op_t&/*x*/, ea_t /*pc*/)
{
    out_register("$sp");
}

void out_LM32_t::out_print_fpreg(const op_t&/*x*/, ea_t /*pc*/)
{
    out_register("$fp");
}


bool out_LM32_t::cgen_outop(const op_t& x, uint16 opindex, ea_t pc)
{
    switch (opindex)
    {
    case LM32_OPERAND_BRANCH:
        if (!out_name_expr(x, x.addr)) out_value(x, OOF_ADDR | OOFS_NOSIGN | OOFW_IMM);
        break;
    case LM32_OPERAND_CALL:
        if (!out_name_expr(x, x.addr)) out_value(x, OOF_ADDR | OOFS_NOSIGN | OOFW_IMM);
        break;
    case LM32_OPERAND_CSR:
        out_register(ph.reg_names[x.reg]);
        break;
    case LM32_OPERAND_EXCEPTION:
        out_value(x, OOF_NUMBER | OOFW_IMM);
        break;
    case LM32_OPERAND_HI16:
        if (x.type == o_imm)
            out_value(x, OOF_SIGNED | OOF_NUMBER | OOFW_IMM);
        else if (x.type == o_mem)
            out_print_address(x, pc, x.n);
        break;
    case LM32_OPERAND_IMM:
        if (x.type == o_imm)
            out_value(x, OOF_SIGNED | OOF_NUMBER | OOFW_IMM);
        else if (x.type == o_mem)
            out_print_address(x, pc, x.n);
        break;
    case LM32_OPERAND_LO16:
        if (x.type == o_imm)
            out_value(x, OOF_SIGNED | OOF_NUMBER | OOFW_IMM);
        else if (x.type == o_mem)
            out_print_address(x, pc, x.n);
        break;
    case LM32_OPERAND_R0:
    case LM32_OPERAND_R1:
    case LM32_OPERAND_R2:
        out_register(ph.reg_names[x.reg]);
        break;
    case LM32_OPERAND_SHIFT:
        out_value(x, OOF_NUMBER | OOFW_IMM);
        break;
    case LM32_OPERAND_UIMM:
        if (x.type == o_imm)
            out_value(x, OOF_NUMBER | OOFW_IMM);
        else if (x.type == o_mem)
            out_print_address(x, pc, x.n);
        //out_value(x,OOF_ADDR|OOF_NUMBER|OOFW_IMM);
        break;
    case LM32_OPERAND_DISPL:
        out_register(ph.reg_names[x.reg]);
        out_value(x, OOF_ADDR | OOF_SIGNED | OOFS_NEEDSIGN);
        break;
    case LM32_OPERAND_USER:
        out_value(x, OOF_ADDR | OOF_NUMBER | OOFW_IMM);
        break;
    default:
        return 0;
    }

    return 1;
}

bool out_LM32_t::out_operand(const op_t& x)
{
    return cgen_outop(x, x.cgen_optype, insn.ea);
}

void out_LM32_t::out_insn(void)
{
    switch (insn.itype)
    {
        // These all use the standard 3 op type
    case LM32_INSN_ADD:
    case LM32_INSN_ADDI:
    case LM32_INSN_AND:
    case LM32_INSN_ANDI:
    case LM32_INSN_ANDHII:
    case LM32_INSN_BE:
    case LM32_INSN_BG:
    case LM32_INSN_BGE:
    case LM32_INSN_BGEU:
    case LM32_INSN_BGU:
    case LM32_INSN_BNE:
    case LM32_INSN_CMPE:
    case LM32_INSN_CMPEI:
    case LM32_INSN_CMPG:
    case LM32_INSN_CMPGI:
    case LM32_INSN_CMPGE:
    case LM32_INSN_CMPGEI:
    case LM32_INSN_CMPGEU:
    case LM32_INSN_CMPGEUI:
    case LM32_INSN_CMPGU:
    case LM32_INSN_CMPGUI:
    case LM32_INSN_CMPNE:
    case LM32_INSN_CMPNEI:
    case LM32_INSN_MUL:
    case LM32_INSN_MULI:
    case LM32_INSN_NOR:
    case LM32_INSN_NORI:
    case LM32_INSN_OR:
    case LM32_INSN_ORI:
    case LM32_INSN_ORHII:
    case LM32_INSN_SL:
    case LM32_INSN_SLI:
    case LM32_INSN_SR:
    case LM32_INSN_SRI:
    case LM32_INSN_SRU:
    case LM32_INSN_SRUI:
    case LM32_INSN_SUB:
    case LM32_INSN_XOR:
    case LM32_INSN_XORI:
    case LM32_INSN_XNOR:
    case LM32_INSN_XNORI:
        out_mnem();
        out_one_operand(0);
        out_symbol(',');
        out_char(' ');
        out_one_operand(1);
        out_symbol(',');
        out_char(' ');
        out_one_operand(2);
        break;
        // These are specific
    case LM32_INSN_B:
    case LM32_INSN_BI:
    case LM32_INSN_CALL:
    case LM32_INSN_CALLI:
        out_mnem();
        out_one_operand(0);
        break;
    case LM32_INSN_DIVU:
    case LM32_INSN_MODU:
        out_mnem();
        cgen_outop(insn.Op1, LM32_OPERAND_R2, insn.ea);
        out_symbol(',');
        out_char(' ');
        cgen_outop(insn.Op2, LM32_OPERAND_R0, insn.ea);
        out_symbol(',');
        out_char(' ');
        cgen_outop(insn.Op3, LM32_OPERAND_R1, insn.ea);
        break;
    case LM32_INSN_LB:
    case LM32_INSN_LBU:
    case LM32_INSN_LH:
    case LM32_INSN_LHU:
    case LM32_INSN_LW:
        out_mnem();
        out_one_operand(0);
        out_symbol(',');
        out_char(' ');
        out_symbol('(');
        out_one_operand(1);
        out_symbol(')');
        break;
    case LM32_INSN_RCSR:
    case LM32_INSN_SEXTB:
    case LM32_INSN_SEXTH:
    case LM32_INSN_MVI:
    case LM32_INSN_MV:
    case LM32_INSN_MVHI:
        out_mnem();
        out_one_operand(0);
        out_symbol(',');
        out_char(' ');
        out_one_operand(1);
        break;
    case LM32_INSN_SB:
    case LM32_INSN_SH:
    case LM32_INSN_SW:
        out_mnem();
        out_symbol('(');
        out_one_operand(0);
        out_symbol(')');
        out_symbol(',');
        out_char(' ');
        out_one_operand(1);
        break;
    case LM32_INSN_USER:
        out_mnem();
        out_one_operand(0);
        out_symbol(',');
        out_char(' ');
        out_one_operand(1);
        out_symbol(',');
        out_char(' ');
        out_one_operand(2);
        out_symbol(',');
        out_char(' ');
        out_one_operand(3);
        break;
    case LM32_INSN_WCSR:
        out_mnem();
        cgen_outop(insn.Op1, LM32_OPERAND_CSR, insn.ea);
        out_symbol(',');
        out_char(' ');
        out_one_operand(1);
        break;
    case LM32_INSN_NOP:
    case LM32_INSN_RET:
    case LM32_INSN_ERET:
    case LM32_INSN_BRET:
    case LM32_INSN_BREAK:
    case LM32_INSN_SCALL:
        out_mnem();
        break;
    default:
        break;
    }

    flush_outbuf();
}
