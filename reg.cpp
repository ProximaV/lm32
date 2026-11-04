#pragma warning ( disable : 4146)
#include "lm32.hpp"

int data_id;

//---------------------------------------------------------------------------------------------------------------------
static bool idaapi can_have_type(const op_t& x) // returns 1 - operand can have
{
    switch (x.type)
    {
    case o_void:
    case o_reg:
    case o_near:
        return 0;
        //case o_phrase: can have type because of ASI or 0 struct offsets
    }

    return 1;
}

//---------------------------------------------------------------------------------------------------------------------
ssize_t idaapi idb_listener_t::on_event(ssize_t code, va_list)
{
    /*
    switch (code)
    {
        // add stuff here...
        default: break;
    }
    */

    return 0;
}

//---------------------------------------------------------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void*, int msgid, va_list)
{
    if (msgid == processor_t::ev_get_procmod) return size_t(SET_MODULE_DATA(LM32_t));

    return 0;
}

void LM32_t::load_from_idb()
{
    ioh.restore_device();
}

//---------------------------------------------------------------------------------------------------------------------
bool LM32_t::LM32_find_ioport_bit(outctx_t& ctx, int port, int bit)
{
    const ioport_bit_t* b = find_ioport_bit(ioh.ports, port, bit);
    if (b != nullptr && !b->name.empty())
    {
        ctx.out_line(b->name.c_str(), COLOR_IMPNAME);
        return true;
    }

    return false;
}

//---------------------------------------------------------------------------------------------------------------------
ssize_t idaapi LM32_t::on_event(ssize_t msgid, va_list va)
{
    int code = 0;

    switch (msgid)
    {
    case processor_t::ev_newfile:
    {
        char cfgfile[QMAXFILE];
        //warning("In newfile");
        ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
        iohandler_t::parse_area_line0_t cb(ioh);
        if (choose_ioport_device2(&ioh.device, cfgfile, &cb))
            ioh.set_device_name(ioh.device.c_str(), IORESP_ALL);
        break;
    }
    case processor_t::ev_setup_til:
    {
        inf_set_cc_id(COMP_GNU);
        inf_set_cc_cm(CM_N32_F48 | CM_CC_CDECL);
        inf_set_cc_defalign(4);
        inf_set_cc_size_i(4);
        inf_set_cc_size_b(1);
        inf_set_cc_size_e(4);
        inf_set_cc_size_s(2);
        inf_set_cc_size_l(4);
        inf_set_cc_size_ll(8);
        inf_set_cc_size_ldbl(8);
        return 1;
    }
    case processor_t::ev_max_ptr_size:
        return 4;
    case processor_t::ev_calc_cdecl_purged_bytes:
        return 0;
    case processor_t::ev_get_cc_regs:
    {
        callregs_t* callregs = va_arg(va, callregs_t*);
        callcnv_t cc = va_arg(va, callcnv_t);
        static const int lm32_argregs[] = { 1, 2, 3, 4, 5, 6, 7, 8, -1 };
        callregs->set(ARGREGS_INDEPENDENT, lm32_argregs, nullptr);
        return 1;
    }
    case processor_t::ev_calc_retloc:
    {
        argloc_t* retloc = va_arg(va, argloc_t*);
        const tinfo_t* type = va_arg(va, const tinfo_t*);
        cm_t cc = va_arg(va, cm_t);
        if (type->is_void())
            return 1;
        size_t size = type->get_size();
        if (size == BADSIZE || size == 0)
            return -1;
        if (size <= 4)
            retloc->set_reg1(1); // r1
        else if (size <= 8)
            retloc->set_reg2(1, 2); // r1:r2
        else
            return -1;
        return 1;
    }
    case processor_t::ev_calc_arglocs:
    {
        func_type_data_t* fti = va_arg(va, func_type_data_t*);
        if (!fti->rettype.is_void())
        {
            size_t retsize = fti->rettype.get_size();
            if (retsize != BADSIZE && retsize > 0)
            {
                if (retsize <= 4)
                    fti->retloc.set_reg1(1);
                else if (retsize <= 8)
                    fti->retloc.set_reg2(1, 2);
            }
        }
        int r = 0; // argreg index: 0 = r1, ..., 7 = r8
        size_t retsize = fti->rettype.get_size();
        if (retsize != BADSIZE && retsize > 8)
            r++; // struct return pointer in r1

        sval_t spoff = 0;
        for (size_t i = 0; i < fti->size(); ++i)
        {
            funcarg_t& fa = (*fti)[i];
            size_t size = fa.type.get_size();
            if (size == BADSIZE || size == 0)
                return -1;
            int nregs = (int(size) + 3) / 4;
            if (r + nregs <= 8 && nregs <= 2)
            {
                if (nregs == 1)
                    fa.argloc.set_reg1(1 + r);
                else
                    fa.argloc.set_reg2(1 + r, 1 + r + 1);
                r += nregs;
            }
            else
            {
                spoff = align_up(spoff, 4);
                fa.argloc.set_stkoff(spoff);
                spoff += align_up(sval_t(size), 4);
            }
        }
        fti->stkargs = spoff;
        return 1;
    }
    case processor_t::ev_is_sp_based:
    {
        int* mode = va_arg(va, int*);
        const insn_t* insn = va_arg(va, const insn_t*);
        const op_t* op = va_arg(va, const op_t*);
        *mode = is_sp_based(*insn, *op);
        return 1;
    }
    case processor_t::ev_create_function_frame:
    {
        ea_t func_ea = va_arg(va, ea_t);
        return create_func_frame(func_ea) ? 1 : 0;
    }
    case processor_t::ev_is_call_insn:
    {
        const insn_t* insn = va_arg(va, const insn_t*);
        return (insn->itype == LM32_INSN_CALL || insn->itype == LM32_INSN_CALLI) ? 1 : -1;
    }
    case processor_t::ev_is_ret_insn:
    {
        const insn_t* insn = va_arg(va, const insn_t*);
        uchar iri_flags = va_arg(va, int);
        if (insn->itype == LM32_INSN_RET
            || insn->itype == LM32_INSN_ERET
            || insn->itype == LM32_INSN_BRET)
            return 1;
        if (insn->itype == LM32_INSN_B && insn->Op1.type == o_reg && insn->Op1.reg == OPVAL_HW_H_RA)
            return 1;
        return -1;
    }
    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:
    {
        load_from_idb();
        break;
    }
    case processor_t::ev_get_frame_retsize:
    {
        int* frsize = va_arg(va, int*);
        *frsize = 0;
        return 1;
    }
    case processor_t::ev_init:
    {
        hook_event_listener(HT_IDB, &idb_listener, &LPH);
        // Set a big endian mode of the IDA kernel
        inf_set_be(true);
        helper.create(PROCMOD_NODE_NAME);
        break;
    }
    case processor_t::ev_term:
    {
        unhook_event_listener(HT_IDB, &idb_listener);
        ioh.ports.clear();
        clr_module_data(data_id);
        break;
    }
    /*
    case processor_t::ev_creating_segm:
    {
        segment_t* s = va_arg(va, segment_t*);
        // Set default value of DS register for all segments
        set_default_dataseg(s->sel);
        break;
    }
    */
    case processor_t::ev_is_switch:
    {
        switch_info_t* si = va_arg(va, switch_info_t*);
        const insn_t* insn = va_arg(va, const insn_t*);
        return LM32_is_switch(si, *insn) ? 1 : -1;
    }
    case processor_t::ev_ana_insn:
    {
        insn_t* out = va_arg(va, insn_t*);
        return LM32_ana(out);
    }
    case processor_t::ev_emu_insn:
    {
        const insn_t* insn = va_arg(va, const insn_t*);
        return LM32_emu(*insn) ? 1 : -1;
    }
    case processor_t::ev_out_insn:
    {
        outctx_t* ctx = va_arg(va, outctx_t*);
        out_insn(*ctx);
        return 1;
    }
    case processor_t::ev_out_operand:
    {
        outctx_t* ctx = va_arg(va, outctx_t*);
        const op_t* op = va_arg(va, const op_t*);
        return out_opnd(*ctx, *op) ? 1 : -1;
    }
    case processor_t::ev_can_have_type:
    {
        const op_t* op = va_arg(va, const op_t*);
        return can_have_type(*op) ? 1 : -1;
    }
    case processor_t::ev_loader_elf_machine:
    {
        linput_t* li = va_arg(va, linput_t*);
        int machine_type = va_arg(va, int);
        const char** p_procname = va_arg(va, const char**);
        (void)li; // unused variable
        if (machine_type == 0x8A)
        {
            *p_procname = "LM32";
            code = machine_type;
        }
        break;
    }
    default:
        break;
    }
    va_end(va);

    return code;
}

//---------------------------------------------------------------------------------------------------------------------
static const asm_t lm32asm =
{
    ASH_HEXF3 | AS_COLON | ASB_BINF0 | ASO_OCTF1 | AS_NCMAS,
    0,
    "LM32 assembler",
    0,
    NULL,
    ".org",
    ".end",

    ";",           // comment string
    '"',           // string delimiter
    '\'',          // char delimiter (no char consts)
    "\\\"'",       // special symbols in char and string constants

    ".ascii",      // string literal directive
    ".byte",       // byte directive
    ".word",       // word directive
    ".dword",      // dword  (4 bytes)
    ".qword",      // qword  (8 bytes)
    NULL,          // oword  (16 bytes)
    ".float",      // float  (4 bytes)
    ".double",     // double (8 bytes)
    NULL,          // tbyte  (10/12 bytes)
    NULL,          // packed decimal real
    "#d dup(#v)",  // array keyword (#h,#d,#v,#s(...))

    ".block %s",   // uninitialized data directive
    ".equ",        // equ
    NULL,          // seg prefix
    NULL,          // comment close
    NULL,          // low 8 bits
    NULL,          // high 8 bits
    NULL,          // low 16 bits
    NULL,          // high 16 bits
    NULL,          // preline
    NULL,          // start of bold text
    NULL,          // start of normal text
    NULL,          // start of literal text
    NULL,          // end of comment
    NULL,          // get_type_name
    NULL,          // align
    NULL,          // left brace
    NULL,          // right brace
    NULL,          // modulo operator
    NULL,          // and operator
    NULL,          // or operator
    NULL,          // xor operator
    NULL,          // not operator
    NULL,          // shift left operator
    NULL,          // shift right operator
    NULL           // sizeof operator
};

//---------------------------------------------------------------------------------------------------------------------
static const asm_t* const asms[] = { &lm32asm, NULL };

//---------------------------------------------------------------------------------------------------------------------
static const uchar retcode_1[] = { 0xc3, 0xa0, 0x00, 0x00 };
static const uchar retcode_2[] = { 0xc3, 0xc0, 0x00, 0x00 };
static const uchar retcode_3[] = { 0xc3, 0xe0, 0x00, 0x00 };

//---------------------------------------------------------------------------------------------------------------------
static const bytes_t retcodes[] =
{
    { sizeof(retcode_1), retcode_1 },
    { sizeof(retcode_2), retcode_2 },
    { sizeof(retcode_3), retcode_3 },
    { 0, NULL }
};

//---------------------------------------------------------------------------------------------------------------------
#define FAMILY "LatticeMico Processors:"
static const char* const shnames[] = { "LM32", NULL };
static const char* const lnames[] = { FAMILY"LatticeMico32 big endian", NULL };

//---------------------------------------------------------------------------------------------------------------------

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------

#define PLFM_LM32 0xBABE
static const char* const RegNames[] =
{
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "r16",
    "r17",
    "r18",
    "r19",
    "r20",
    "r21",
    "r22",
    "r23",
    "r24",
    "r25",
    "gp",
    "fp",
    "sp",
    "ra",
    "ea",
    "ba",
    "IE", // 32
    "IM",
    "IP",
    "ICC",
    "DCC",
    "CC",
    "CFG",
    "EBA",
    "DC",
    "DEBA",
    "CFG2",
    "h-csr-b",
    "h-csr-c",
    "h-csr-d",
    "JTX",
    "JRX",
    "BP0",
    "BP1",
    "BP2",
    "BP3",
    "h-csr-14",
    "h-csr-15",
    "h-csr-16",
    "h-csr-17",
    "WP0",
    "WP1",
    "WP2",
    "WP3",
    "h-csr-1c",
    "PSW",
    "TLBVAD",
    "TLBPAD",
    "cs",
    "ds",
};

processor_t LPH =
{
    IDP_INTERFACE_VERSION,   // version
    PLFM_LM32,               // id
    // flag
    PR_USE32|PR_DEFSEG32|PRN_HEX|PR_RNAMESOK|PR_ALIGN,  

    0,                       // the module has processor-specific configuration options
    8,                       // 8 bits in a byte for code segments
    8,                       // 8 bits in a byte for other segments

    shnames,
    lnames,

    asms,

    notify,

    RegNames,
    qnumber(RegNames),       // number of registers

    r_cs,                    // first
    r_ds,                    // last
    0,                       // size of a segment register
    r_cs,                    // virtual CS
    r_ds,                    // virtual DS

    NULL,                    // no known code start sequences
    retcodes,                // 'Return' instruction codes

    0,                       // 
    LM32_INSN_NOP + 1,         // 
    Instructions,            // instruc
    0,                       // int tbyte_size;  -- doesn't exist
    { 0, 0, 0, 0 },          // char real_width[4];
    // number of symbols after decimal point
    // 2byte float (0-does not exist)
    // normal float
    // normal double
    // long double
    LM32_INSN_RET,           // icode of return instruction. It is ok to give any of possible return instructions
};
