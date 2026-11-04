/* LM32 IDP analysis - based on Proxima's proc gen
*/
#pragma warning (disable : 4146)
#include "lm32.hpp"

typedef unsigned int INSN;

int f_nil(INSN insn) { return (insn >> 1) & 0x0; }
int f_anyof(INSN insn) { return (insn >> 1) & 0x0; }
int f_opcode(INSN insn) { return (insn >> 26) & 0x3f; }
int f_r0(INSN insn) { return (insn >> 21) & 0x1f; }
int f_r1(INSN insn) { return (insn >> 16) & 0x1f; }
int f_r2(INSN insn) { return (insn >> 11) & 0x1f; }
int f_resv0(INSN insn) { return (insn >> 0) & 0x7ff; }
int f_shift(INSN insn) { return (insn >> 0) & 0x1f; }
int f_imm(INSN insn)
{
    int val = (insn >> 0);
    val &= 0xffff;
    if (val & 0x8000) return val - 0x10000;
    else return val;
}
int f_uimm(INSN insn) { return (insn >> 0) & 0xffff; }
int f_csr(INSN insn) { return (insn >> 21) & 0x1f; }
int f_user(INSN insn) { return (insn >> 0) & 0x7ff; }
int f_exception(INSN insn)
{
    int val = (insn >> 0);
    val &= 0x3ffffff;
    if (val & 0x2000000) return val - 0x4000000;
    else return val;
}
int f_branch(INSN insn)
{
    int val = (insn >> 0);
    val &= 0xffff;
    if (val & 0x8000) return val - 0x10000;
    else return val;
}
int f_call(INSN insn)
{
    int val = (insn >> 0);
    val &= 0x3ffffff;
    if (val & 0x2000000) return val - 0x4000000;
    else return val;
}

/* Analyze the current instruction. */
int LM32_t::LM32_ana(insn_t* _insn)
{
    insn_t& ida_insn = *_insn;
    LM32_INSN_TYPE itype;
    INSN insn;
    ea_t pc;

    insn = get_dword(ida_insn.ea);
    pc = ida_insn.ea;

    // Decode by 6-bit primary opcode
    int opcode = f_opcode(insn);
    switch (opcode)
    {
    case 0x00: itype = LM32_INSN_SRUI;   goto decode_insn_format_srui;
    case 0x01: itype = LM32_INSN_NORI;   goto decode_insn_format_nori;
    case 0x02: itype = LM32_INSN_MULI;   goto decode_insn_format_muli;
    case 0x03: itype = LM32_INSN_SH;     goto decode_insn_format_sh;
    case 0x04: itype = LM32_INSN_LB;     goto decode_insn_format_lb;
    case 0x05: itype = LM32_INSN_SRI;    goto decode_insn_format_sri;
    case 0x06: itype = LM32_INSN_XORI;   goto decode_insn_format_xori;
    case 0x07: itype = LM32_INSN_LH;     goto decode_insn_format_lh;
    case 0x08: itype = LM32_INSN_ANDI;   goto decode_insn_format_andi;
    case 0x09: itype = LM32_INSN_XNORI;  goto decode_insn_format_xnori;
    case 0x0A: itype = LM32_INSN_LW;     goto decode_insn_format_lw;
    case 0x0B: itype = LM32_INSN_LHU;    goto decode_insn_format_lhu;
    case 0x0C: itype = LM32_INSN_SB;     goto decode_insn_format_sb;
    case 0x0D:
        if (insn == 0x34000000) { itype = LM32_INSN_NOP; goto decode_insn_format_nop; }
        itype = LM32_INSN_ADDI;
        goto decode_insn_format_addi;
    case 0x0E: itype = LM32_INSN_ORI;    goto decode_insn_format_ori;
    case 0x0F: itype = LM32_INSN_SLI;    goto decode_insn_format_sli;
    case 0x10: itype = LM32_INSN_LBU;    goto decode_insn_format_lbu;
    case 0x11: itype = LM32_INSN_BE;     goto decode_insn_format_be;
    case 0x12: itype = LM32_INSN_BG;     goto decode_insn_format_bg;
    case 0x13: itype = LM32_INSN_BGE;    goto decode_insn_format_bge;
    case 0x14: itype = LM32_INSN_BGEU;   goto decode_insn_format_bgeu;
    case 0x15: itype = LM32_INSN_BGU;    goto decode_insn_format_bgu;
    case 0x16: itype = LM32_INSN_SW;     goto decode_insn_format_sw;
    case 0x17: itype = LM32_INSN_BNE;    goto decode_insn_format_bne;
    case 0x18: itype = LM32_INSN_ANDHII; goto decode_insn_format_andhii;
    case 0x19: itype = LM32_INSN_CMPEI;  goto decode_insn_format_cmpei;
    case 0x1A: itype = LM32_INSN_CMPGI;  goto decode_insn_format_cmpgi;
    case 0x1B: itype = LM32_INSN_CMPGEI; goto decode_insn_format_cmpgei;
    case 0x1C: itype = LM32_INSN_CMPGEUI; goto decode_insn_format_cmpgeui;
    case 0x1D: itype = LM32_INSN_CMPGUI; goto decode_insn_format_cmpgui;
    case 0x1E: itype = LM32_INSN_ORHII;  goto decode_insn_format_orhii;
    case 0x1F: itype = LM32_INSN_CMPNEI; goto decode_insn_format_cmpnei;
    case 0x20: itype = LM32_INSN_SRU;    goto decode_insn_format_sru;
    case 0x21: itype = LM32_INSN_NOR;    goto decode_insn_format_nor;
    case 0x22: itype = LM32_INSN_MUL;    goto decode_insn_format_mul;
    case 0x23: itype = LM32_INSN_DIVU;   goto decode_insn_format_divu;
    case 0x24: itype = LM32_INSN_RCSR;   goto decode_insn_format_rcsr;
    case 0x25: itype = LM32_INSN_SR;     goto decode_insn_format_sr;
    case 0x26: itype = LM32_INSN_XOR;    goto decode_insn_format_xor;
    case 0x27: itype = LM32_INSN_DIV;    goto decode_insn_format_div;
    case 0x28: itype = LM32_INSN_AND;    goto decode_insn_format_and;
    case 0x29: itype = LM32_INSN_XNOR;   goto decode_insn_format_xnor;
    case 0x2B:
    {
        int imm = insn & 0x1f;
        if (imm == 2) { itype = LM32_INSN_BREAK; goto decode_insn_format_break; }
        if (imm == 7) { itype = LM32_INSN_SCALL; goto decode_insn_format_scall; }
        itype = LM32_INSN_RAISE;
        goto decode_insn_format_raise;
    }
    case 0x2C: itype = LM32_INSN_SEXTB;  goto decode_insn_format_sextb;
    case 0x2D: itype = LM32_INSN_ADD;    goto decode_insn_format_add;
    case 0x2E: itype = LM32_INSN_OR;     goto decode_insn_format_or;
    case 0x2F: itype = LM32_INSN_SL;     goto decode_insn_format_sl;
    case 0x30:
    {
        int r0 = f_r0(insn);
        if (r0 == OPVAL_HW_H_RA) { itype = LM32_INSN_RET;  goto decode_insn_format_ret; }
        if (r0 == OPVAL_HW_H_EA) { itype = LM32_INSN_ERET; goto decode_insn_format_eret; }
        if (r0 == OPVAL_HW_H_BA) { itype = LM32_INSN_BRET; goto decode_insn_format_bret; }
        itype = LM32_INSN_B;
        goto decode_insn_format_b;
    }
    case 0x31: itype = LM32_INSN_MODU;   goto decode_insn_format_modu;
    case 0x32: itype = LM32_INSN_SUB;    goto decode_insn_format_sub;
    case 0x33: itype = LM32_INSN_USER;   goto decode_insn_format_user;
    case 0x34: itype = LM32_INSN_WCSR;   goto decode_insn_format_wcsr;
    case 0x35: itype = LM32_INSN_MOD;    goto decode_insn_format_mod;
    case 0x36: itype = LM32_INSN_CALL;   goto decode_insn_format_call;
    case 0x37: itype = LM32_INSN_SEXTH;  goto decode_insn_format_sexth;
    case 0x38: itype = LM32_INSN_BI;     goto decode_insn_format_bi;
    case 0x39: itype = LM32_INSN_CMPE;   goto decode_insn_format_cmpe;
    case 0x3A: itype = LM32_INSN_CMPG;   goto decode_insn_format_cmpg;
    case 0x3B: itype = LM32_INSN_CMPGE;  goto decode_insn_format_cmpge;
    case 0x3C: itype = LM32_INSN_CMPGEU; goto decode_insn_format_cmpgeu;
    case 0x3D: itype = LM32_INSN_CMPGU;  goto decode_insn_format_cmpgu;
    case 0x3E: itype = LM32_INSN_CALLI;  goto decode_insn_format_calli;
    case 0x3F: itype = LM32_INSN_CMPNE;  goto decode_insn_format_cmpne;
    default:
        itype = LM32_INSN_X_INVALID;
        goto decode_insn_format_empty;
    }

    /* The instruction has been decoded, now extract the fields. */
decode_insn_format_empty:
    {
        ida_insn.itype = itype;
        ida_insn.size = 0;
        return 0;
    }
decode_insn_format_add:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_addi:
    {
        if ((insn & 0xffe00000) == 0x34000000) { itype = LM32_INSN_MVI; goto decode_insn_format_mvi; } // mvi             $r1,$imm
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_imm = f_imm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_IMM;
        ida_insn.Op3.value = i_imm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_and:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_andi:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_uimm = f_uimm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_UIMM;
        ida_insn.Op3.value = i_uimm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_andhii:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_uimm = f_uimm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_HI16;
        ida_insn.Op3.value = i_uimm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_b:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_bi:
    {
        int i_opcode = f_opcode(insn);
        ea_t i_call = f_call(insn) << 2;

        ida_insn.Op1.type = o_near;
        ida_insn.Op1.lm32_type = LM32_OPERAND_CALL;
        ida_insn.Op1.addr = pc + i_call;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_be:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_branch = f_branch(insn) << 2;

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op3.type = o_near;
        ida_insn.Op3.lm32_type = LM32_OPERAND_BRANCH;
        ida_insn.Op3.addr = pc + i_branch;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_bg:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_branch = f_branch(insn) << 2;

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op3.type = o_near;
        ida_insn.Op3.lm32_type = LM32_OPERAND_BRANCH;
        ida_insn.Op3.addr = pc + i_branch;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_bge:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_branch = f_branch(insn) << 2;

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op3.type = o_near;
        ida_insn.Op3.lm32_type = LM32_OPERAND_BRANCH;
        ida_insn.Op3.addr = pc + i_branch;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_bgeu:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_branch = f_branch(insn) << 2;

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op3.type = o_near;
        ida_insn.Op3.lm32_type = LM32_OPERAND_BRANCH;
        ida_insn.Op3.addr = pc + i_branch;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_bgu:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_branch = f_branch(insn) << 2;

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op3.type = o_near;
        ida_insn.Op3.lm32_type = LM32_OPERAND_BRANCH;
        ida_insn.Op3.addr = pc + i_branch;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_bne:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_branch = f_branch(insn) << 2;

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op3.type = o_near;
        ida_insn.Op3.lm32_type = LM32_OPERAND_BRANCH;
        ida_insn.Op3.addr = pc + i_branch;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_call:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_calli:
    {
        int i_opcode = f_opcode(insn);
        ea_t i_call = f_call(insn) << 2;

        ida_insn.Op1.type = o_near;
        ida_insn.Op1.lm32_type = LM32_OPERAND_CALL;
        ida_insn.Op1.addr = pc + i_call;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_cmpe:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_cmpei:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_imm = f_imm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_IMM;
        ida_insn.Op3.value = i_imm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_cmpg:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_cmpgi:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_imm = f_imm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_IMM;
        ida_insn.Op3.value = i_imm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_cmpge:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_cmpgei:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_imm = f_imm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_IMM;
        ida_insn.Op3.value = i_imm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_cmpgeu:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_cmpgeui:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_uimm = f_uimm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_UIMM;
        ida_insn.Op3.value = i_uimm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_cmpgu:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_cmpgui:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_uimm = f_uimm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_UIMM;
        ida_insn.Op3.value = i_uimm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_cmpne:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_cmpnei:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_imm = f_imm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_IMM;
        ida_insn.Op3.value = i_imm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_div:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_divu:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_lb:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_imm = f_imm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;

        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        // TODO: Please clean up the .type reg setting above....
        ida_insn.Op2.type = o_displ;
        ida_insn.Op2.dtype = dt_byte;
        ida_insn.Op2.addr = i_imm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_lbu:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_imm = f_imm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;

        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        // TODO: Please clean up the .type reg setting above....
        ida_insn.Op2.type = o_displ;
        ida_insn.Op2.dtype = dt_byte;
        ida_insn.Op2.addr = i_imm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_lh:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_imm = f_imm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;

        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        // TODO: Please clean up the .type reg setting above....
        ida_insn.Op2.type = o_displ;
        ida_insn.Op2.dtype = dt_word;
        ida_insn.Op2.addr = i_imm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_lhu:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_imm = f_imm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;

        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        // TODO: Please clean up the .type reg setting above....
        ida_insn.Op2.type = o_displ;
        ida_insn.Op2.dtype = dt_word;
        ida_insn.Op2.addr = i_imm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_lw:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_imm = f_imm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;

        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        // TODO: Please clean up the .type reg setting above....
        ida_insn.Op2.type = o_displ;
        ida_insn.Op2.dtype = dt_dword;
        ida_insn.Op2.addr = i_imm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_mod:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_modu:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_mul:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_muli:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_imm = f_imm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_IMM;
        ida_insn.Op3.value = i_imm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_nor:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_nori:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_uimm = f_uimm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_UIMM;
        ida_insn.Op3.value = i_uimm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_or:
    {
        if (f_r1(insn) == 0) { itype = LM32_INSN_MV; goto decode_insn_format_mv; } // mv              $r2,$r0
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_ori:
    {
        if ((insn & 0xffe00000) == 0x38000000) { itype = LM32_INSN_MVUI; goto decode_insn_format_mvui; } // mvui            $r1,$lo16
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_uimm = f_uimm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_LO16;
        ida_insn.Op3.value = i_uimm;
        refinfo_t ri;
        if (get_refinfo(&ri, ida_insn.ea, 2))
        {
            ea_t target, base;
            ida_insn.Op3.type = o_mem;
            calc_reference_data(&target, &base, ida_insn.ea, ri, i_uimm);
            ida_insn.Op3.addr = target;
        }
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_orhii:
    {
        if ((insn & 0xffe00000) == 0x78000000) { itype = LM32_INSN_MVHI; goto decode_insn_format_mvhi; } // mvhi            $r1,$hi16
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_uimm = f_uimm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_HI16;
        ida_insn.Op3.value = i_uimm;
        refinfo_t ri;
        if (get_refinfo(&ri, ida_insn.ea, 2))
        {
            ea_t target, base;
            ida_insn.Op3.type = o_mem;
            calc_reference_data(&target, &base, ida_insn.ea, ri, i_uimm);
            ida_insn.Op3.addr = target;
        }
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_rcsr:
    {
        int i_opcode = f_opcode(insn);
        int i_csr = f_csr(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_CSR;
        ida_insn.Op2.reg = OPVAL_H_CSR_BASE + i_csr;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_sb:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_imm = f_imm(insn);


        ida_insn.Op1.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r0;
        // TODO: Please clean up the .type reg setting above....
        ida_insn.Op1.type = o_displ;
        ida_insn.Op1.dtype = dt_byte;
        ida_insn.Op1.addr = i_imm;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_sextb:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_sexth:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_sh:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_imm = f_imm(insn);


        ida_insn.Op1.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r0;
        // TODO: Please clean up the .type reg setting above....
        ida_insn.Op1.type = o_displ;
        ida_insn.Op1.dtype = dt_word;
        ida_insn.Op1.addr = i_imm;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_sl:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_sli:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_shift = f_shift(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = dt_byte;
        ida_insn.Op3.lm32_type = LM32_OPERAND_IMM;
        ida_insn.Op3.value = i_shift;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_sr:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_sri:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_shift = f_shift(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = dt_byte;
        ida_insn.Op3.lm32_type = LM32_OPERAND_IMM;
        ida_insn.Op3.value = i_shift;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_sru:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_srui:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_shift = f_shift(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = dt_byte;
        ida_insn.Op3.lm32_type = LM32_OPERAND_IMM;
        ida_insn.Op3.value = i_shift;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_sub:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_sw:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        ea_t i_imm = f_imm(insn);


        ida_insn.Op1.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r0;
        // TODO: Please clean up the .type reg setting above....
        ida_insn.Op1.type = o_displ;
        ida_insn.Op1.dtype = dt_dword;
        ida_insn.Op1.addr = i_imm;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_user:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_user = f_user(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op4.type = o_imm;
        ida_insn.Op4.dtype = get_dtype_by_size(4);
        ida_insn.Op4.lm32_type = LM32_OPERAND_IMM;
        ida_insn.Op4.value = i_user;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_wcsr:
    {
        int i_opcode = f_opcode(insn);
        int i_csr = f_csr(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_CSR;
        ida_insn.Op1.reg = OPVAL_H_CSR_BASE + i_csr;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_xor:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_xori:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_uimm = f_uimm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_UIMM;
        ida_insn.Op3.value = i_uimm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_xnor:
    {
        if (f_r1(insn) == 0) { itype = LM32_INSN_NOT; goto decode_insn_format_not; } // not             $r2,$r0
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_reg;
        ida_insn.Op3.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op3.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_xnori:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_uimm = f_uimm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.Op3.type = o_imm;
        ida_insn.Op3.dtype = get_dtype_by_size(4);
        ida_insn.Op3.lm32_type = LM32_OPERAND_UIMM;
        ida_insn.Op3.value = i_uimm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_raise:
    {
        int imm = insn & 0x1f;
        ida_insn.Op1.type = o_imm;
        ida_insn.Op1.dtype = dt_byte;
        ida_insn.Op1.lm32_type = LM32_OPERAND_IMM;
        ida_insn.Op1.value = imm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_break:
    {
        int i_opcode = f_opcode(insn);
        int i_exception = f_exception(insn);

        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_scall:
    {
        int i_opcode = f_opcode(insn);
        int i_exception = f_exception(insn);

        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_bret:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_eret:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_ret:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_mv:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_mvi:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_imm = f_imm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_imm;
        ida_insn.Op2.dtype = get_dtype_by_size(4);
        ida_insn.Op2.lm32_type = LM32_OPERAND_IMM;
        ida_insn.Op2.value = i_imm;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_mvui:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_uimm = f_uimm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_imm;
        ida_insn.Op2.dtype = get_dtype_by_size(4);
        ida_insn.Op2.lm32_type = LM32_OPERAND_LO16;
        ida_insn.Op2.value = i_uimm;
        refinfo_t ri;
        if (get_refinfo(&ri, ida_insn.ea, 2))
        {
            ea_t target, base;
            ida_insn.Op2.type = o_mem;
            calc_reference_data(&target, &base, ida_insn.ea, ri, i_uimm);
            ida_insn.Op2.addr = target;
        }
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_mvhi:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_uimm = f_uimm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;
        ida_insn.Op2.type = o_imm;
        ida_insn.Op2.dtype = get_dtype_by_size(4);
        ida_insn.Op2.lm32_type = LM32_OPERAND_HI16;
        ida_insn.Op2.value = i_uimm;
        refinfo_t ri;
        if (get_refinfo(&ri, ida_insn.ea, 2))
        {
            ea_t target, base;
            ida_insn.Op2.type = o_mem;
            calc_reference_data(&target, &base, ida_insn.ea, ri, i_uimm);
            ida_insn.Op2.addr = target;
        }
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_mva:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_imm = f_imm(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R1;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r1;

        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_not:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_r2 = f_r2(insn);
        int i_resv0 = f_resv0(insn);

        ida_insn.Op1.type = o_reg;
        ida_insn.Op1.lm32_type = LM32_OPERAND_R2;
        ida_insn.Op1.reg = OPVAL_H_GR_BASE + i_r2;
        ida_insn.Op2.type = o_reg;
        ida_insn.Op2.lm32_type = LM32_OPERAND_R0;
        ida_insn.Op2.reg = OPVAL_H_GR_BASE + i_r0;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_nop:
    {
        int i_opcode = f_opcode(insn);
        int i_r0 = f_r0(insn);
        int i_r1 = f_r1(insn);
        int i_imm = f_imm(insn);

        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
}