/* LM32 IDP analysis

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
#pragma warning (disable : 4146)
#include "lm32.hpp"

/* The size of an "int" needed to hold an instruction word.
   This is usually 32 bits, but some architectures needs 64 bits. */
typedef CGEN_INSN_INT CGEN_INSN_WORD;

/* Split the instruction into chunks. stolen from binutils */
static inline uint64_t get_bits(const void* p, int bits, int big_p)
{
    const unsigned char* addr = (const unsigned char*)p;
    uint64_t data;
    int i;
    int bytes;

    if (bits % 8 != 0)
        abort();

    data = 0;
    bytes = bits / 8;
    for (i = 0; i < bytes; i++) {
        int addr_index = big_p ? i : bytes - i - 1;
        data = (data << 8) | addr[addr_index];
    }

    return data;
}

static inline CGEN_INSN_WORD get_insn_value(unsigned char* buf, int length)
{
    int big_p = 1;
    int insn_chunk_bitsize = 0;
    CGEN_INSN_WORD value = 0;

    if (insn_chunk_bitsize != 0 && insn_chunk_bitsize < length)
    {
        /* We need to divide up the incoming value into insn_chunk_bitsize-length
           segments, and endian-convert them, one at a time. */
        int i;

        /* Enforce divisibility. */
        if ((length % insn_chunk_bitsize) != 0)
            abort();

        for (i = 0; i < length; i += insn_chunk_bitsize)
        { /* NB: i == bits */
            int bit_index;
            uint64_t this_value;

            bit_index = i; /* NB: not dependent on endianness; opposite of cgen_put_insn_value! */
            this_value = get_bits(&buf[bit_index / 8], insn_chunk_bitsize, big_p);
            value = (value << insn_chunk_bitsize) | this_value;
        }
    }
    else
    {
        value = get_bits(buf, length, big_p);
    }

    return value;
}

static inline ea_t calc_reference_target(ea_t from, const refinfo_t& ri, adiff_t opval)
{
    ea_t target;
    ea_t base;
    calc_reference_data(&target, &base, from, ri, opval);
    //msg("Target 0x%x, Base 0x%x\n", target, base);
    return target;
}

/* Analyze the current instruction. */
int LM32_t::LM32_ana(insn_t* _insn)
{
    insn_t& ida_insn = *_insn;
    /* temporary buffer */
    unsigned char buffer[4];

    /* Result of decoder. */
    LM32_INSN_TYPE itype;

    CGEN_INSN_WORD insn;
    CGEN_INSN_WORD entire_insn;
    ea_t pc;
    // on lm32, all inatructions are 32 bits, so insn and entire_insn are the same
    insn = entire_insn = get_dword(ida_insn.ea);
    //get_data_value((uval_t*)buffer, ida_insn.ea, 4);
    //insn = get_insn_value(buffer, 32);
    //entire_insn = get_insn_value(buffer, 32);
    pc = ida_insn.ea;
    {
        {
            unsigned int val = (((insn >> 26) & (63 << 0)));

            switch (val)
            {
            case 0: itype = LM32_INSN_SRUI; goto extract_sfmt_addi;
            case 1: itype = LM32_INSN_NORI; goto extract_sfmt_andi;
            case 2: itype = LM32_INSN_MULI; goto extract_sfmt_addi;
            case 3: itype = LM32_INSN_SH; goto extract_sfmt_sh;
            case 4: itype = LM32_INSN_LB; goto extract_sfmt_lb;
            case 5: itype = LM32_INSN_SRI; goto extract_sfmt_addi;
            case 6: itype = LM32_INSN_XORI; goto extract_sfmt_andi;
            case 7: itype = LM32_INSN_LH; goto extract_sfmt_lh;
            case 8: itype = LM32_INSN_ANDI; goto extract_sfmt_andi;
            case 9: itype = LM32_INSN_XNORI; goto extract_sfmt_andi;
            case 10: itype = LM32_INSN_LW; goto extract_sfmt_lw;
            case 11: itype = LM32_INSN_LHU; goto extract_sfmt_lh;
            case 12: itype = LM32_INSN_SB; goto extract_sfmt_sb;
            case 13: itype = LM32_INSN_ADDI; goto extract_sfmt_addi;
            case 14: itype = LM32_INSN_ORI; goto extract_sfmt_ori;
            case 15: itype = LM32_INSN_SLI; goto extract_sfmt_addi;
            case 16: itype = LM32_INSN_LBU; goto extract_sfmt_lb;
            case 17: itype = LM32_INSN_BE; goto extract_sfmt_be;
            case 18: itype = LM32_INSN_BG; goto extract_sfmt_be;
            case 19: itype = LM32_INSN_BGE; goto extract_sfmt_be;
            case 20: itype = LM32_INSN_BGEU; goto extract_sfmt_be;
            case 21: itype = LM32_INSN_BGU; goto extract_sfmt_be;
            case 22: itype = LM32_INSN_SW; goto extract_sfmt_sw;
            case 23: itype = LM32_INSN_BNE; goto extract_sfmt_be;
            case 24: itype = LM32_INSN_ANDHII; goto extract_sfmt_andhii;
            case 25: itype = LM32_INSN_CMPEI; goto extract_sfmt_addi;
            case 26: itype = LM32_INSN_CMPGI; goto extract_sfmt_addi;
            case 27: itype = LM32_INSN_CMPGEI; goto extract_sfmt_addi;
            case 28: itype = LM32_INSN_CMPGEUI; goto extract_sfmt_andi;
            case 29: itype = LM32_INSN_CMPGUI; goto extract_sfmt_andi;
            case 30: itype = LM32_INSN_ORHII; goto extract_sfmt_orhii;
            case 31: itype = LM32_INSN_CMPNEI; goto extract_sfmt_addi;
            case 32:
                if ((entire_insn & 0xfc0007ff) == 0x80000000) { itype = LM32_INSN_SRU; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 33:
                if ((entire_insn & 0xfc0007ff) == 0x84000000) { itype = LM32_INSN_NOR; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 34:
                if ((entire_insn & 0xfc0007ff) == 0x88000000) { itype = LM32_INSN_MUL; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 35:
                if ((entire_insn & 0xfc0007ff) == 0x8c000000) { itype = LM32_INSN_DIVU; goto extract_sfmt_divu; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 36:
                if ((entire_insn & 0xfc1f07ff) == 0x90000000) { itype = LM32_INSN_RCSR; goto extract_sfmt_rcsr; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 37:
                if ((entire_insn & 0xfc0007ff) == 0x94000000) { itype = LM32_INSN_SR; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 38:
                if ((entire_insn & 0xfc0007ff) == 0x98000000) { itype = LM32_INSN_XOR; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 40:
                if ((entire_insn & 0xfc0007ff) == 0xa0000000) { itype = LM32_INSN_AND; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 41:
                if ((entire_insn & 0xfc0007ff) == 0xa4000000) { itype = LM32_INSN_XNOR; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 43:
            {
                unsigned int val = (((insn >> 1) & (1 << 1)) | ((insn >> 0) & (1 << 0)));
                switch (val)
                {
                case 0:
                    if ((entire_insn & 0xffffffff) == 0xac000002) { itype = LM32_INSN_BREAK; goto extract_sfmt_break; }
                    itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
                case 3:
                    if ((entire_insn & 0xffffffff) == 0xac000007) { itype = LM32_INSN_SCALL; goto extract_sfmt_break; }
                    itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
                default:
                    itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
                }
            }
            case 44:
                if ((entire_insn & 0xfc1f07ff) == 0xb0000000) { itype = LM32_INSN_SEXTB; goto extract_sfmt_sextb; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 45:
                if ((entire_insn & 0xfc0007ff) == 0xb4000000) { itype = LM32_INSN_ADD; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 46:
                if ((entire_insn & 0xfc0007ff) == 0xb8000000) { itype = LM32_INSN_OR; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 47:
                if ((entire_insn & 0xfc0007ff) == 0xbc000000) { itype = LM32_INSN_SL; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 48:
                if (entire_insn == 0xc3a00000) { itype = LM32_INSN_RET; goto extract_sfmt_nopret; }
                if (entire_insn == 0xc3c00000) { itype = LM32_INSN_ERET; goto extract_sfmt_nopret; }
                if (entire_insn == 0xc3e00000) { itype = LM32_INSN_BRET; goto extract_sfmt_nopret; }
                if ((entire_insn & 0xfc1fffff) == 0xc0000000) { itype = LM32_INSN_B; goto extract_sfmt_b; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 49:
                if ((entire_insn & 0xfc0007ff) == 0xc4000000) { itype = LM32_INSN_MODU; goto extract_sfmt_divu; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 50:
                if ((entire_insn & 0xfc0007ff) == 0xc8000000) { itype = LM32_INSN_SUB; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 51: itype = LM32_INSN_USER; goto extract_sfmt_user;
            case 52:
                if ((entire_insn & 0xfc00ffff) == 0xd0000000) { itype = LM32_INSN_WCSR; goto extract_sfmt_wcsr; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 54:
                if ((entire_insn & 0xfc1fffff) == 0xd8000000) { itype = LM32_INSN_CALL; goto extract_sfmt_call; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 55:
                if ((entire_insn & 0xfc1f07ff) == 0xdc000000) { itype = LM32_INSN_SEXTH; goto extract_sfmt_sextb; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 56: itype = LM32_INSN_BI; goto extract_sfmt_bi;
            case 57:
                if ((entire_insn & 0xfc0007ff) == 0xe4000000) { itype = LM32_INSN_CMPE; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 58:
                if ((entire_insn & 0xfc0007ff) == 0xe8000000) { itype = LM32_INSN_CMPG; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 59:
                if ((entire_insn & 0xfc0007ff) == 0xec000000) { itype = LM32_INSN_CMPGE; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 60:
                if ((entire_insn & 0xfc0007ff) == 0xf0000000) { itype = LM32_INSN_CMPGEU; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 61:
                if ((entire_insn & 0xfc0007ff) == 0xf4000000) { itype = LM32_INSN_CMPGU; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            case 62: itype = LM32_INSN_CALLI; goto extract_sfmt_calli;
            case 63:
                if ((entire_insn & 0xfc0007ff) == 0xfc000000) { itype = LM32_INSN_CMPNE; goto extract_sfmt_add; }
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            default:
                itype = LM32_INSN_X_INVALID; goto extract_sfmt_empty;
            }
        }
    }

    /* The instruction has been decoded, now extract the fields. */

extract_sfmt_empty:
    {
        ida_insn.itype = itype;
        ida_insn.size = 0;

        return 0;
    }

extract_sfmt_add:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        UINT f_r2;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_r2 = EXTRACT_LSB0_UINT(insn, 32, 15, 5);

        /* Record the operands */
        // Handle Pseudo Instruction
        // mv
        if (itype == LM32_INSN_OR && f_r1 == 0)
        {
            itype = LM32_INSN_MV;
            ida_insn.Op2.type = o_reg;
            ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r0;
            ida_insn.Op2.cgen_optype = LM32_OPERAND_R0;
            ida_insn.Op1.type = o_reg;
            ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r2;
            ida_insn.Op1.cgen_optype = LM32_OPERAND_R2;
        }
        else
        {
            ida_insn.Op2.type = o_reg;
            ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r0;
            ida_insn.Op2.cgen_optype = LM32_OPERAND_R0;
            ida_insn.Op3.type = o_reg;
            ida_insn.Op3.reg = REGS_HW_H_GR_BASE + f_r1;
            ida_insn.Op3.cgen_optype = LM32_OPERAND_R1;
            ida_insn.Op1.type = o_reg;
            ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r2;
            ida_insn.Op1.cgen_optype = LM32_OPERAND_R2;
        }

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_nopret:
    {
        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_addi:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        INT f_imm;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_imm = EXTRACT_LSB0_SINT(insn, 32, 15, 16);

        /* Record the operands */
        // Handle Pseudo Instructions
        // nop
        if (itype == LM32_INSN_ADDI && f_r0 == 0 && f_r1 == 0 && f_imm == 0) {
            itype = LM32_INSN_NOP;
        }
        // mvi
        else if (itype == LM32_INSN_ADDI && f_r0 == 0)
        {
            itype = LM32_INSN_MVI;
            ida_insn.Op2.type = o_imm;
            ida_insn.Op2.dtype = get_dtype_by_size(4);
            ida_insn.Op2.value = f_imm;
            ida_insn.Op2.cgen_optype = LM32_OPERAND_IMM;
            ida_insn.Op1.type = o_reg;
            ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r1;
            ida_insn.Op1.cgen_optype = LM32_OPERAND_R1;
        }
        else
        {
            ida_insn.Op3.type = o_imm;
            ida_insn.Op3.dtype = get_dtype_by_size(4);
            ida_insn.Op3.value = f_imm;
            ida_insn.Op3.cgen_optype = LM32_OPERAND_IMM;
            ida_insn.Op2.type = o_reg;
            ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r0;
            ida_insn.Op2.cgen_optype = LM32_OPERAND_R0;
            ida_insn.Op1.type = o_reg;
            ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r1;
            ida_insn.Op1.cgen_optype = LM32_OPERAND_R1;
        }

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_andi:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        UINT f_uimm;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_uimm = EXTRACT_LSB0_UINT(insn, 32, 15, 16);

        /* Record the operands */
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_R0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.value = f_uimm;
        ida_insn.Op3.cgen_optype = LM32_OPERAND_UIMM;
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r1;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_R1;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_andhii:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        UINT f_uimm;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_uimm = EXTRACT_LSB0_UINT(insn, 32, 15, 16);

        /* Record the operands */
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.value = f_uimm;
        ida_insn.Op3.cgen_optype = LM32_OPERAND_HI16;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_R0;
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r1;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_R1;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_orhii:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        UINT f_uimm;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_uimm = EXTRACT_LSB0_UINT(insn, 32, 15, 16);

        /* Record the operands */
        //Handle Pseudo Instructions
        // mvhi
        if (f_r0 == 0)
        {
            itype = LM32_INSN_MVHI;
            ida_insn.Op2.type = o_imm;
            ida_insn.Op2.dtype = get_dtype_by_size(4);
            ida_insn.Op2.value = f_uimm;
            ida_insn.Op2.cgen_optype = LM32_OPERAND_HI16;
            ida_insn.Op1.type = o_reg;
            ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r1;
            ida_insn.Op1.cgen_optype = LM32_OPERAND_R1;

            refinfo_t ri;
            if (get_refinfo(&ri, ida_insn.ea, 2))
            {
                ida_insn.Op2.type = o_mem;
                ida_insn.Op2.addr = calc_reference_target(ida_insn.ea, ri, f_uimm);
            }
        }
        else
        {
            /* Record the operands */
            ida_insn.Op3.type = o_imm;
            ida_insn.Op3.dtype = get_dtype_by_size(4);
            ida_insn.Op3.value = f_uimm;
            ida_insn.Op3.cgen_optype = LM32_OPERAND_HI16;
            ida_insn.Op2.type = o_reg;
            ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r0;
            ida_insn.Op2.cgen_optype = LM32_OPERAND_R0;
            ida_insn.Op1.type = o_reg;
            ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r1;
            ida_insn.Op1.cgen_optype = LM32_OPERAND_R1;

            refinfo_t ri;
            if (get_refinfo(&ri, ida_insn.ea, 2))
            {
                ida_insn.Op3.type = o_mem;
                ida_insn.Op3.addr = calc_reference_target(ida_insn.ea, ri, f_uimm);
            }
        }

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_b:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);

        /* Record the operands */
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_R0;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_bi:
    {
        CGEN_INSN_WORD insn = entire_insn;
        SI f_call;

        f_call = ((pc)+(((SI)(((EXTRACT_LSB0_SINT(insn, 32, 25, 26)) << (6))) >> (4))));

        /* Record the operands */
        ida_insn.Op1.type = o_near;
        ida_insn.Op1.dtype = get_dtype_by_size(4);
        ida_insn.Op1.addr = f_call;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_CALL;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_be:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        SI f_branch;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_branch = ((pc)+(((SI)(((EXTRACT_LSB0_SINT(insn, 32, 15, 16)) << (16))) >> (14))));

        /* Record the operands */
        ida_insn.Op3.type = o_near;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.addr = f_branch;
        ida_insn.Op3.cgen_optype = LM32_OPERAND_BRANCH;
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_R0;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r1;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_R1;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_call:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);

        /* Record the operands */
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_R0;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_calli:
    {
        CGEN_INSN_WORD insn = entire_insn;
        SI f_call;

        f_call = ((pc)+(((SI)(((EXTRACT_LSB0_SINT(insn, 32, 25, 26)) << (6))) >> (4))));

        /* Record the operands */
        ida_insn.Op1.type = o_near;
        ida_insn.Op1.dtype = get_dtype_by_size(4);
        ida_insn.Op1.addr = f_call;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_CALL;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_divu:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        UINT f_r2;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_r2 = EXTRACT_LSB0_UINT(insn, 32, 15, 5);

        /* Record the operands */
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_R0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.reg = REGS_HW_H_GR_BASE + f_r1;
        ida_insn.Op3.cgen_optype = LM32_OPERAND_R1;
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r2;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_R2;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_lb:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        INT f_imm;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_imm = EXTRACT_LSB0_SINT(insn, 32, 15, 16);

        /* Record the operands */
        ida_insn.Op2.type = o_displ;
        ida_insn.Op2.dtype = get_dtype_by_size(1);
        ida_insn.Op2.addr = f_imm;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_DISPL;
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r1;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_R1;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_lh:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        INT f_imm;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_imm = EXTRACT_LSB0_SINT(insn, 32, 15, 16);

        /* Record the operands */
        ida_insn.Op2.type = o_displ;
        ida_insn.Op2.dtype = get_dtype_by_size(2);
        ida_insn.Op2.addr = f_imm;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_DISPL;
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r1;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_R1;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_lw:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        INT f_imm;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_imm = EXTRACT_LSB0_SINT(insn, 32, 15, 16);

        /* Record the operands */
        ida_insn.Op2.type = o_displ;
        ida_insn.Op2.dtype = get_dtype_by_size(4);
        ida_insn.Op2.addr = f_imm;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_DISPL;
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r1;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_R1;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_ori:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        UINT f_uimm;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_uimm = EXTRACT_LSB0_UINT(insn, 32, 15, 16);

        /* Record the operands */
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.value = f_uimm;
        ida_insn.Op3.cgen_optype = LM32_OPERAND_LO16;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_R0;
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r1;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_R1;

        refinfo_t ri;
        if (get_refinfo(&ri, ida_insn.ea, 2))
        {
            ida_insn.Op3.type = o_mem;
            ida_insn.Op3.addr = calc_reference_target(ida_insn.ea, ri, f_uimm);
        }

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_rcsr:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_csr;
        UINT f_r2;

        f_csr = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r2 = EXTRACT_LSB0_UINT(insn, 32, 15, 5);

        /* Record the operands */
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.reg = REGS_HW_H_CSR_BASE + f_csr;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_CSR;
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r2;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_R2;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_sb:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        INT f_imm;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_imm = EXTRACT_LSB0_SINT(insn, 32, 15, 16);

        /* Record the operands */
        ida_insn.Op1.type = o_displ;
        ida_insn.Op1.addr = f_imm;
        ida_insn.Op1.dtype = get_dtype_by_size(1);
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_DISPL;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r1;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_R1;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_sextb:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r2;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r2 = EXTRACT_LSB0_UINT(insn, 32, 15, 5);

        /* Record the operands */
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_R0;
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r2;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_R2;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_sh:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        INT f_imm;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_imm = EXTRACT_LSB0_SINT(insn, 32, 15, 16);

        /* Record the operands */
        ida_insn.Op1.type = o_displ;
        ida_insn.Op1.addr = f_imm;
        ida_insn.Op1.dtype = get_dtype_by_size(2);
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_DISPL;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r1;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_R1;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_sw:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        INT f_imm;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_imm = EXTRACT_LSB0_SINT(insn, 32, 15, 16);

        /* Record the operands */
        ida_insn.Op1.type = o_displ;
        ida_insn.Op1.addr = f_imm;
        ida_insn.Op1.dtype = get_dtype_by_size(4);
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_DISPL;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r1;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_R1;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_user:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_r0;
        UINT f_r1;
        UINT f_r2;
        UINT f_user;

        f_r0 = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);
        f_r2 = EXTRACT_LSB0_UINT(insn, 32, 15, 5);
        f_user = EXTRACT_LSB0_UINT(insn, 32, 10, 11);

        /* Record the operands */
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r0;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_R0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.reg = REGS_HW_H_GR_BASE + f_r1;
        ida_insn.Op3.cgen_optype = LM32_OPERAND_R1;
        ida_insn.Op4.type = o_imm;
        ida_insn.Op4.dtype = get_dtype_by_size(4);
        ida_insn.Op4.value = f_user;
        ida_insn.Op4.cgen_optype = LM32_OPERAND_USER;
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_GR_BASE + f_r2;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_R2;

        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_wcsr:
    {
        CGEN_INSN_WORD insn = entire_insn;
        UINT f_csr;
        UINT f_r1;

        f_csr = EXTRACT_LSB0_UINT(insn, 32, 25, 5);
        f_r1 = EXTRACT_LSB0_UINT(insn, 32, 20, 5);

        /* Record the operands */
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.reg = REGS_HW_H_GR_BASE + f_r1;
        ida_insn.Op2.cgen_optype = LM32_OPERAND_R1;
        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.reg = REGS_HW_H_CSR_BASE + f_csr;
        ida_insn.Op1.cgen_optype = LM32_OPERAND_CSR;
        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }

extract_sfmt_break:
    {
        ida_insn.itype = itype;
        ida_insn.size = 4;

        return 4;
    }
}
