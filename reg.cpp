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
    if (b != nullptr && !b->name.empty()) ctx.out_line(b->name.c_str(), COLOR_IMPNAME); return true;

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
            code = 0xBABE;
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

    ".ascii",      // ascii string directive
    ".byte",       // byte directive
    ".word",       // word directive
    ".dword",      // dword  (4 bytes)
    ".qword",      // qword  (8 bytes)
    NULL,          // oword  (16 bytes)
    ".float"       // float  (4 bytes)
    ".double",     // double (8 bytes)
    NULL,          // tbyte  (10/12 bytes)
    NULL,          // packed decimal real
    NULL,          // arrays (#h,#d,#v,#s(...)
    ".block %s",   // uninited arrays
    ".equ",        // equ
    NULL,          // seg prefix
    //  preline, NULL, operdim,
    NULL, NULL, NULL,
    NULL,
    NULL,
    NULL,          // func_header
    NULL,          // func_footer
    NULL,          // public
    NULL,          // weak
    NULL,          // extrn
    NULL,          // comm
    NULL,          // get_type_name
    NULL,          // align
    0, 0,          // lbrace, rbrace
    NULL,          // mod
    NULL,          // and
    NULL,          // or
    NULL,          // xor
    NULL,          // not
    NULL,          // shl
    NULL,          // shr
    NULL,          // sizeof
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

    qnumber(RegNames) - 2,     // first
    qnumber(RegNames) - 1,     // last
    0,                       // size of a segment register
    qnumber(RegNames) - 2,     // virtual CS
    qnumber(RegNames) - 1,     // virtual DS

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
