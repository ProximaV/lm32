/* IDP emulator for LM32.

THIS FILE IS MACHINE GENERATED WITH CGEN.

Copyright (C) 2000-2010 Red Hat, Inc.

This file is part of the Red Hat simulators.


*/


#include "lm32.hpp"

std::map<uint16, uval_t> mvhi;

static void make_stack_var(const insn_t& insn, const op_t& x)
{
    adiff_t sp_off;
    if (may_create_stkvars())
    {
        if (x.type == o_displ)
            sp_off = x.addr;
        else
            sp_off = x.value;

        set_immd(insn.ea);
        if (insn_create_stkvar(insn, x, sp_off, 0))
            op_stkvar(insn.ea, x.n);
    }
}

static void add_sp(const insn_t& insn, sval_t delta)
{
    func_t* pfn = get_func(insn.ea);

    if (may_trace_sp() && pfn)
    {
        //if(delta <0)
        // This is to fix the arg_0 reference for sp+0
        add_auto_stkpnt(pfn, insn.ea + insn.size, delta - 4);
        //else add_auto_stkpnt(pfn, insn.ea + insn.size, delta);
    }
}
/*
*  Example Switch from lm32 module
*
    ROM:000337D0                 addi    r2, r1, -1
    ROM:000337D4                 mvi     r12, 0
    ROM:000337D8                 cmpgui  r1, r2, 0
    ROM:000337DC                 mv      r3, r12
    ROM:000337E0                 mvi     r13, 1
    ROM:000337E4                 mv      r4, r12
    ROM:000337E8                 mv      r11, r12
    ROM:000337EC                 bne     r1, r12, loc_33874
    ROM:000337F0                 sli     r1, r2, 2
    ROM:000337F4                 mvhi    r2, 3
    ROM:000337F8                 ori     r2, r2, low16(off_38A30)
    ROM:000337FC                 add     r1, r1, r2
    ROM:00033800                 lw      r1, (r1+0)
    ROM:00033804                 b       r1
*/


static size_t get_switch_entries(const insn_t& insn)
{
    size_t entries = 0;
    bool found = false;
    insn_t prev;
    ea_t prev_ea;
    uint16 sli_reg=0xFFFF;
    prev_ea= decode_prev_insn(&prev, insn.ea);
    for (int i = 0; i < 0x10; i++)
    {
        switch (prev.itype)
        {
        case LM32_INSN_SLI:
            if (prev.Op3.value == 2)
            {
                sli_reg = prev.Op2.reg;
            }
            //check for shift left 2 and get reg
            break;
        case LM32_INSN_CMPGUI:
            if (prev.Op2.reg == sli_reg && sli_reg != 0xFFFF)
            {
                entries = 1 + prev.Op3.value;
                found = true;
            }
            break;
        default:
            break;
        }
        if (found) break;
        else prev_ea = decode_prev_insn(&prev, prev_ea);
        
    }
    return entries;
}
static ea_t get_switch_table_addr(const insn_t& insn)
{
    ea_t table = BADADDR;
    bool found = false;
    insn_t prev;
    ea_t prev_ea;
    uint16 add_reg = 0xFFFF;
    prev_ea = decode_prev_insn(&prev, insn.ea);
    for (int i = 0; i < 0x10; i++)
    {
        switch (prev.itype)
        {
        case LM32_INSN_ADD:
            add_reg = prev.Op3.reg;
            break;
        case LM32_INSN_ORI:
            if (prev.Op2.reg == add_reg && prev.Op1.reg == add_reg && add_reg != 0xFFFF)
            {
                table= prev.Op3.value;
            }
            break;
        case LM32_INSN_MVHI:
            if (prev.Op1.reg == add_reg && add_reg != 0xFFFF)
            {
                table |= (prev.Op2.value << 0x10);
                found = true;
            }
            break;
        default:
            break;
        }
        if (found) break;
        else prev_ea = decode_prev_insn(&prev, prev_ea);
    }

    return table;
}
static ea_t get_switch_default_addr(const insn_t& insn)
{
    ea_t defjump = BADADDR, maybe = BADADDR;
    
    bool found = false;
    insn_t prev;
    ea_t prev_ea;
    uint16 bne_reg = 0xFFFF;
    prev_ea = decode_prev_insn(&prev, insn.ea);
    for (int i = 0; i < 0x10; i++)
    {
        switch (prev.itype)
        {
        case LM32_INSN_BNE:
            bne_reg = prev.Op1.reg;
            maybe = prev.Op3.addr;
            break;
        case LM32_INSN_CMPGUI:
            if (prev.Op1.reg == bne_reg  && bne_reg != 0xFFFF)
            {
                defjump = maybe;
                found = true;
            }
            break;
        default:
            break;
        }
        if (found) break;
        else prev_ea = decode_prev_insn(&prev, prev_ea);
    }

    return defjump;
}
bool LM32_t::LM32_is_switch(switch_info_t* si, const insn_t& insn) {
    if (insn.Op1.type == o_reg && insn.Op1.reg == 2)
    {
        // Find the values needed to create the switch.
        size_t num_entries;
        ea_t jump_table_addr;
        ea_t default_addr;

        // if we find everything we need then set the values and return true so IDA creates the switch
        num_entries = get_switch_entries(insn);
        jump_table_addr = get_switch_table_addr(insn);
        default_addr = get_switch_default_addr(insn);

        if (num_entries > 1 && jump_table_addr != BADADDR && default_addr != BADADDR)
        {
        
            si->set_jtable_element_size(4);  // 4 bytes for 32-bit pointers in the table on LM32
            si->set_jtable_size(num_entries);
            si->startea = insn.ea;
            si->jumps = jump_table_addr;
            si->set_shift(0);  // No shift operation on the index
            si->set_elbase(0);  // No base address for the jump table elements
            si->defjump = default_addr;
            si->regnum = 2;

            return true;
        }
    }

    return false;

}

static void fuse_far_ptrs(const insn_t& insn)
{
    /* MVHI and ORI pairs */
    ea_t target = BADADDR;

    if (insn.itype == LM32_INSN_MVHI)
        mvhi.insert(std::map<uint16, uval_t>::value_type(insn.Op1.reg, insn.Op2.value));
    if (insn.itype == LM32_INSN_OR && mvhi.count(insn.Op2.reg) > 0)
        mvhi.insert(std::map<uint16, uval_t>::value_type(insn.Op1.reg, mvhi.at(insn.Op2.reg)));
    if (insn.itype == LM32_INSN_ORI && mvhi.count(insn.Op1.reg) > 0)
    {
        target = mvhi.at(insn.Op1.reg) << 0x10 | insn.Op3.value;
        op_offset(insn.ea, 0x2, REF_LOW16, target);
        if (target <= 0x40000)
        {
            insn.add_dref(target, insn.ea, dr_O);
            /*

            Commenting out for now, we can decide later if we want to put comments instead
            or maybe if they are registers, have the name?

            } else if (target >= 0x40000) {
                char comment[MAXSTR];
                qsnprintf(comment, sizeof comment, "0x%08X", target);
                set_cmt(insn.ea, comment, false);

            */
        }
        mvhi.erase(insn.Op1.reg);
    }
}

// ********** x-invalid: --invalid--

static int LM32_emu_x_invalid(const insn_t& insn)
{
    return 0;
}

static int LM32_emu_standard_insn(const insn_t& insn)
{
    return 4;
}

// ********** addi: addi $r1,$r0,$imm

static int LM32_emu_addi(const insn_t& insn)
{
    if (insn.Op1.reg == REGS_HW_H_SP && insn.Op2.reg == REGS_HW_H_SP)
        add_sp(insn, (sval_t)insn.Op3.value);
    if (insn.Op1.reg != REGS_HW_H_SP && insn.Op2.reg == REGS_HW_H_SP)
        make_stack_var(insn, insn.Op3);

    return 4;
}

// ********** bi: bi $call

static int LM32_emu_bi(const insn_t& insn)
{
    unsigned int val;
    if (insn.Op1.type == o_near || insn.Op1.type == o_far) {
        val = insn.Op1.addr;
    }
    else {
        val = insn.Op1.value;
    }

    cref_t flag = has_insn_feature(insn.itype, CF_CALL) ? fl_CN : fl_JN;
    insn_add_cref(insn, val, 0, flag);

    return 4;
}



static int LM32_emu_branch(const insn_t& insn)
{
    unsigned int val;
    if (insn.Op3.type == o_near || insn.Op3.type == o_far) {
        val = insn.Op3.addr;
    }
    else {
        val = insn.Op3.value;
    }

    cref_t flag = has_insn_feature(insn.itype, CF_CALL) ? fl_CN : fl_JN;
    insn_add_cref(insn, val, 0, flag);

    return 4;
}


// ********** call: call $r0
/*
static int LM32_emu_call (const insn_t &insn)
{
    ea_t pc = insn.ea;
    int valid = 1;

    {
        ADDSI (pc, 4);
        { USI val = [&valid](){ valid = 0; return 0; }(); if (valid) insn_add_cref(insn, val,0, has_insn_feature(insn.itype, CF_CALL) ? fl_CN : fl_JN); }
    }

    return 4;
}
*/

// ********** calli: calli $call

static int LM32_emu_calli (const insn_t &insn)
{
    USI val;
    if (insn.Op1.type == o_near || insn.Op1.type == o_far) {
        val = static_cast<USI>(insn.Op1.addr);
    }
    else {
        val = static_cast<USI>(insn.Op1.value);
    }


    cref_t flag = has_insn_feature(insn.itype, CF_CALL) ? fl_CN : fl_JN;
    insn_add_cref(insn, val, 0, flag);
    
    return 4;
}


static int LM32_emu_load(const insn_t & insn)
{
    if (insn.Op2.reg == REGS_HW_H_SP)
        make_stack_var(insn, insn.Op2);
    return 4;
}


static int LM32_emu_store(const insn_t& insn)
{
    if (insn.Op1.reg == REGS_HW_H_SP)
        make_stack_var(insn, insn.Op1);
    return 4;
}

// Emulator entry
int LM32_t::LM32_emu(const insn_t& insn)
{
    int len;

    switch (insn.itype)
    {
    case LM32_INSN_X_INVALID: len = LM32_emu_x_invalid(insn); break;
    case LM32_INSN_B:
    case LM32_INSN_ADD:
    case LM32_INSN_AND:
    case LM32_INSN_ANDI:
    case LM32_INSN_ANDHII:
    case LM32_INSN_RET:
    case LM32_INSN_ERET:
    case LM32_INSN_BRET:
    case LM32_INSN_CMPE:
    case LM32_INSN_CMPEI:
    case LM32_INSN_CMPG:
    case LM32_INSN_CMPGI:
    case LM32_INSN_CMPGE:
    case LM32_INSN_CMPGEU:
    case LM32_INSN_CMPGEUI:
    case LM32_INSN_CMPGU:
    case LM32_INSN_CMPGUI:
    case LM32_INSN_CMPNE:
    case LM32_INSN_CMPNEI:
    case LM32_INSN_CMPGEI:
    case LM32_INSN_DIVU:
    case LM32_INSN_MODU:
    case LM32_INSN_MUL:
    case LM32_INSN_MULI:
    case LM32_INSN_MV:
    case LM32_INSN_MVI:
    case LM32_INSN_MVHI:
    case LM32_INSN_NOR:
    case LM32_INSN_NOP:
    case LM32_INSN_NORI:
    case LM32_INSN_OR:
    case LM32_INSN_ORI:
    case LM32_INSN_ORHII:
    case LM32_INSN_RCSR:
    case LM32_INSN_SEXTB:
    case LM32_INSN_SEXTH:
    case LM32_INSN_SL:
    case LM32_INSN_SLI:
    case LM32_INSN_SR:
    case LM32_INSN_SRI:
    case LM32_INSN_SRU:
    case LM32_INSN_SRUI:
    case LM32_INSN_SUB:
    case LM32_INSN_USER:
    case LM32_INSN_WCSR:
    case LM32_INSN_XOR:
    case LM32_INSN_XORI:
    case LM32_INSN_XNOR:
    case LM32_INSN_XNORI:
    case LM32_INSN_BREAK:
    case LM32_INSN_SCALL:
    case LM32_INSN_CALL:
        len = LM32_emu_standard_insn(insn); break;
    case LM32_INSN_CALLI:
        len = LM32_emu_calli(insn); break;
    case LM32_INSN_ADDI: len = LM32_emu_addi(insn); break;
    case LM32_INSN_BI: len = LM32_emu_bi(insn); break;
    case LM32_INSN_BE:
    case LM32_INSN_BG:
    case LM32_INSN_BGE:
    case LM32_INSN_BGEU:
    case LM32_INSN_BGU:
    case LM32_INSN_BNE: len = LM32_emu_branch(insn); break;

    case LM32_INSN_LB:
    case LM32_INSN_LBU:
    case LM32_INSN_LH:
    case LM32_INSN_LHU:
    case LM32_INSN_LW: len = LM32_emu_load(insn); break;
    case LM32_INSN_SB:
    case LM32_INSN_SH:
    case LM32_INSN_SW: len = LM32_emu_store(insn); break;
    default: len = 0; break;
    }

    fuse_far_ptrs(insn);

    if (len && !has_insn_feature(insn.itype, CF_STOP))
        insn_add_cref(insn, insn.ea + len, 0, fl_F);
    else if (may_trace_sp())
        recalc_spd(insn.ea);

    return 1;
}
