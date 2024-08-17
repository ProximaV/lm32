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
    // Pseudo Instruction
    if ((insn & 0xffffffff) == 0xc3e00000) { itype = LM32_INSN_BRET; goto decode_insn_format_bret; } // bret           
    if ((insn & 0xffffffff) == 0xc3c00000) { itype = LM32_INSN_ERET; goto decode_insn_format_eret; } // eret           
    if ((insn & 0xffffffff) == 0xc3a00000) { itype = LM32_INSN_RET; goto decode_insn_format_ret; } // ret            
    if ((insn & 0xffffffff) == 0x34000000) { itype = LM32_INSN_NOP; goto decode_insn_format_nop; } // nop            
    // Standard Instruction
    if ((insn & 0xfc0007ff) == 0xb4000000) { itype = LM32_INSN_ADD; goto decode_insn_format_add; } // add             $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x34000000) { itype = LM32_INSN_ADDI; goto decode_insn_format_addi; } // addi            $r1,$r0,$imm
    if ((insn & 0xfc0007ff) == 0xa0000000) { itype = LM32_INSN_AND; goto decode_insn_format_and; } // and             $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x20000000) { itype = LM32_INSN_ANDI; goto decode_insn_format_andi; } // andi            $r1,$r0,$uimm
    if ((insn & 0xfc000000) == 0x60000000) { itype = LM32_INSN_ANDHII; goto decode_insn_format_andhii; } // andhii          $r1,$r0,$hi16
    if ((insn & 0xfc1fffff) == 0xc0000000) { itype = LM32_INSN_B; goto decode_insn_format_b; } // b               $r0
    if ((insn & 0xfc000000) == 0xe0000000) { itype = LM32_INSN_BI; goto decode_insn_format_bi; } // bi              $call
    if ((insn & 0xfc000000) == 0x44000000) { itype = LM32_INSN_BE; goto decode_insn_format_be; } // be              $r0,$r1,$branch
    if ((insn & 0xfc000000) == 0x48000000) { itype = LM32_INSN_BG; goto decode_insn_format_bg; } // bg              $r0,$r1,$branch
    if ((insn & 0xfc000000) == 0x4c000000) { itype = LM32_INSN_BGE; goto decode_insn_format_bge; } // bge             $r0,$r1,$branch
    if ((insn & 0xfc000000) == 0x50000000) { itype = LM32_INSN_BGEU; goto decode_insn_format_bgeu; } // bgeu            $r0,$r1,$branch
    if ((insn & 0xfc000000) == 0x54000000) { itype = LM32_INSN_BGU; goto decode_insn_format_bgu; } // bgu             $r0,$r1,$branch
    if ((insn & 0xfc000000) == 0x5c000000) { itype = LM32_INSN_BNE; goto decode_insn_format_bne; } // bne             $r0,$r1,$branch
    if ((insn & 0xfc1fffff) == 0xd8000000) { itype = LM32_INSN_CALL; goto decode_insn_format_call; } // call            $r0
    if ((insn & 0xfc000000) == 0xf8000000) { itype = LM32_INSN_CALLI; goto decode_insn_format_calli; } // calli           $call
    if ((insn & 0xfc0007ff) == 0xe4000000) { itype = LM32_INSN_CMPE; goto decode_insn_format_cmpe; } // cmpe            $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x64000000) { itype = LM32_INSN_CMPEI; goto decode_insn_format_cmpei; } // cmpei           $r1,$r0,$imm
    if ((insn & 0xfc0007ff) == 0xe8000000) { itype = LM32_INSN_CMPG; goto decode_insn_format_cmpg; } // cmpg            $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x68000000) { itype = LM32_INSN_CMPGI; goto decode_insn_format_cmpgi; } // cmpgi           $r1,$r0,$imm
    if ((insn & 0xfc0007ff) == 0xec000000) { itype = LM32_INSN_CMPGE; goto decode_insn_format_cmpge; } // cmpge           $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x6c000000) { itype = LM32_INSN_CMPGEI; goto decode_insn_format_cmpgei; } // cmpgei          $r1,$r0,$imm
    if ((insn & 0xfc0007ff) == 0xf0000000) { itype = LM32_INSN_CMPGEU; goto decode_insn_format_cmpgeu; } // cmpgeu          $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x70000000) { itype = LM32_INSN_CMPGEUI; goto decode_insn_format_cmpgeui; } // cmpgeui         $r1,$r0,$uimm
    if ((insn & 0xfc0007ff) == 0xf4000000) { itype = LM32_INSN_CMPGU; goto decode_insn_format_cmpgu; } // cmpgu           $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x74000000) { itype = LM32_INSN_CMPGUI; goto decode_insn_format_cmpgui; } // cmpgui          $r1,$r0,$uimm
    if ((insn & 0xfc0007ff) == 0xfc000000) { itype = LM32_INSN_CMPNE; goto decode_insn_format_cmpne; } // cmpne           $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x7c000000) { itype = LM32_INSN_CMPNEI; goto decode_insn_format_cmpnei; } // cmpnei          $r1,$r0,$imm
    if ((insn & 0xfc0007ff) == 0x8c000000) { itype = LM32_INSN_DIVU; goto decode_insn_format_divu; } // divu            $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x10000000) { itype = LM32_INSN_LB; goto decode_insn_format_lb; } // lb              $r1,($r0+$imm)
    if ((insn & 0xfc000000) == 0x40000000) { itype = LM32_INSN_LBU; goto decode_insn_format_lbu; } // lbu             $r1,($r0+$imm)
    if ((insn & 0xfc000000) == 0x1c000000) { itype = LM32_INSN_LH; goto decode_insn_format_lh; } // lh              $r1,($r0+$imm)
    if ((insn & 0xfc000000) == 0x2c000000) { itype = LM32_INSN_LHU; goto decode_insn_format_lhu; } // lhu             $r1,($r0+$imm)
    if ((insn & 0xfc000000) == 0x28000000) { itype = LM32_INSN_LW; goto decode_insn_format_lw; } // lw              $r1,($r0+$imm)
    if ((insn & 0xfc0007ff) == 0xc4000000) { itype = LM32_INSN_MODU; goto decode_insn_format_modu; } // modu            $r2,$r0,$r1
    if ((insn & 0xfc0007ff) == 0x88000000) { itype = LM32_INSN_MUL; goto decode_insn_format_mul; } // mul             $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x08000000) { itype = LM32_INSN_MULI; goto decode_insn_format_muli; } // muli            $r1,$r0,$imm
    if ((insn & 0xfc0007ff) == 0x84000000) { itype = LM32_INSN_NOR; goto decode_insn_format_nor; } // nor             $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x04000000) { itype = LM32_INSN_NORI; goto decode_insn_format_nori; } // nori            $r1,$r0,$uimm
    if ((insn & 0xfc0007ff) == 0xb8000000) { itype = LM32_INSN_OR; goto decode_insn_format_or; } // or              $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x38000000) { itype = LM32_INSN_ORI; goto decode_insn_format_ori; } // ori             $r1,$r0,$lo16
    if ((insn & 0xfc000000) == 0x78000000) { itype = LM32_INSN_ORHII; goto decode_insn_format_orhii; } // orhii           $r1,$r0,$hi16
    if ((insn & 0xfc1f07ff) == 0x90000000) { itype = LM32_INSN_RCSR; goto decode_insn_format_rcsr; } // rcsr            $r2,$csr
    if ((insn & 0xfc000000) == 0x30000000) { itype = LM32_INSN_SB; goto decode_insn_format_sb; } // sb              ($r0+$imm),$r1
    if ((insn & 0xfc1f07ff) == 0xb0000000) { itype = LM32_INSN_SEXTB; goto decode_insn_format_sextb; } // sextb           $r2,$r0
    if ((insn & 0xfc1f07ff) == 0xdc000000) { itype = LM32_INSN_SEXTH; goto decode_insn_format_sexth; } // sexth           $r2,$r0
    if ((insn & 0xfc000000) == 0x0c000000) { itype = LM32_INSN_SH; goto decode_insn_format_sh; } // sh              ($r0+$imm),$r1
    if ((insn & 0xfc0007ff) == 0xbc000000) { itype = LM32_INSN_SL; goto decode_insn_format_sl; } // sl              $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x3c000000) { itype = LM32_INSN_SLI; goto decode_insn_format_sli; } // sli             $r1,$r0,$imm
    if ((insn & 0xfc0007ff) == 0x94000000) { itype = LM32_INSN_SR; goto decode_insn_format_sr; } // sr              $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x14000000) { itype = LM32_INSN_SRI; goto decode_insn_format_sri; } // sri             $r1,$r0,$imm
    if ((insn & 0xfc0007ff) == 0x80000000) { itype = LM32_INSN_SRU; goto decode_insn_format_sru; } // sru             $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x00000000) { itype = LM32_INSN_SRUI; goto decode_insn_format_srui; } // srui            $r1,$r0,$imm
    if ((insn & 0xfc0007ff) == 0xc8000000) { itype = LM32_INSN_SUB; goto decode_insn_format_sub; } // sub             $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x58000000) { itype = LM32_INSN_SW; goto decode_insn_format_sw; } // sw              ($r0+$imm),$r1
    if ((insn & 0xfc000000) == 0xcc000000) { itype = LM32_INSN_USER; goto decode_insn_format_user; } // user            $r2,$r0,$r1,$user
    if ((insn & 0xfc00ffff) == 0xd0000000) { itype = LM32_INSN_WCSR; goto decode_insn_format_wcsr; } // wcsr            $csr,$r1
    if ((insn & 0xfc0007ff) == 0x98000000) { itype = LM32_INSN_XOR; goto decode_insn_format_xor; } // xor             $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x18000000) { itype = LM32_INSN_XORI; goto decode_insn_format_xori; } // xori            $r1,$r0,$uimm
    if ((insn & 0xfc0007ff) == 0xa4000000) { itype = LM32_INSN_XNOR; goto decode_insn_format_xnor; } // xnor            $r2,$r0,$r1
    if ((insn & 0xfc000000) == 0x24000000) { itype = LM32_INSN_XNORI; goto decode_insn_format_xnori; } // xnori           $r1,$r0,$uimm
    if ((insn & 0xffffffff) == 0xac000002) { itype = LM32_INSN_BREAK; goto decode_insn_format_break; } // break          
    if ((insn & 0xffffffff) == 0xac000007) { itype = LM32_INSN_SCALL; goto decode_insn_format_scall; } // scall          
    else { itype = LM32_INSN_X_INVALID; goto decode_insn_format_empty; }

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
        ida_insn.Op2.dtype = get_dtype_by_size(4);
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
        ida_insn.Op2.dtype = get_dtype_by_size(4);
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
        ida_insn.Op2.dtype = get_dtype_by_size(4);
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
        ida_insn.Op2.dtype = get_dtype_by_size(4);
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
        ida_insn.Op2.dtype = get_dtype_by_size(4);
        ida_insn.Op2.addr = i_imm;
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
        if ((insn & 0xfc1f07ff) == 0xb8000000) { itype = LM32_INSN_MV; goto decode_insn_format_mv; } // mv              $r2,$r0
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
        ida_insn.Op1.dtype = get_dtype_by_size(4);
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
        ida_insn.Op1.dtype = get_dtype_by_size(4);
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
        ida_insn.Op1.dtype = get_dtype_by_size(4);
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
        if ((insn & 0xfc1f07ff) == 0xa4000000) { itype = LM32_INSN_NOT; goto decode_insn_format_not; } // not             $r2,$r0
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