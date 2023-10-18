/* LM32 IDP output - thanks to Proxima's proc gen
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

bool out_LM32_t::out_operand(const op_t& x)
{
    uint16 opindex = x.lm32_type;
    ea_t pc = insn.ea;

    switch (opindex)
    {
    case LM32_OPERAND_R2:
    case LM32_OPERAND_R0:
    case LM32_OPERAND_R1:
    case LM32_OPERAND_CSR:
        if (x.type == o_displ)
        {
            out_register(ph.reg_names[x.reg]);
            out_value(x, OOF_ADDR | OOF_SIGNED | OOFS_NEEDSIGN);
        }
        else if (x.type == o_reg)
            out_register(ph.reg_names[x.reg]);
        else
            //something wrong - add messaging here
            out_symbol('?');
        break;
    case LM32_OPERAND_IMM:
        if (x.type == o_imm)
            out_value(x, OOF_SIGNED | OOF_NUMBER | OOFW_IMM);
        else if (x.type == o_mem)
            out_print_address(x, pc, x.n);
        else
            out_symbol('?');
        break;
    case LM32_OPERAND_CALL:
    case LM32_OPERAND_BRANCH:
        if (!out_name_expr(x, x.addr)) out_value(x, OOF_ADDR | OOFS_NOSIGN | OOFW_IMM);
        break;
    case LM32_OPERAND_LO16:
    case LM32_OPERAND_UIMM:
    case LM32_OPERAND_HI16:
        if (x.type == o_imm)
            out_value(x, OOF_NUMBER | OOFW_IMM);
        else if (x.type == o_mem)
            out_print_address(x, pc, x.n);
        else
            out_symbol('?');
        break;
    default:
        return 0;
    }

    return 1;
}
void out_LM32_t::out_insn(void)
{
    switch (insn.itype)
    {
        // M0,1,2
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
    case LM32_INSN_DIVU:
    case LM32_INSN_MODU:
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
        // M0
    case LM32_INSN_B:
    case LM32_INSN_BI:
    case LM32_INSN_CALL:
    case LM32_INSN_CALLI:
        out_mnem();
        out_one_operand(0);
        break;
        // M0,(1+2)
    case LM32_INSN_LB:
    case LM32_INSN_LBU:
    case LM32_INSN_LH:
    case LM32_INSN_LHU:
    case LM32_INSN_LW:
        // This has a displacement, so the '+ imm' is embedded in the operand
        out_mnem();
        out_one_operand(0);
        out_symbol(',');
        out_char(' ');
        out_symbol('(');
        out_one_operand(1);
        out_symbol(')');
        break;
        // M0,1
    case LM32_INSN_RCSR:
    case LM32_INSN_SEXTB:
    case LM32_INSN_SEXTH:
    case LM32_INSN_WCSR:
    case LM32_INSN_MV:
    case LM32_INSN_MVI:
    case LM32_INSN_MVUI:
    case LM32_INSN_MVHI:
    case LM32_INSN_MVA:
    case LM32_INSN_NOT:
        out_mnem();
        out_one_operand(0);
        out_symbol(',');
        out_char(' ');
        out_one_operand(1);
        break;
        // M(0+1),2
    case LM32_INSN_SB:
    case LM32_INSN_SH:
    case LM32_INSN_SW:
        // This has a displacement, so the '+ imm' is embedded in the operand
        out_mnem();
        out_symbol('(');
        out_one_operand(0);
        out_symbol(')');
        out_symbol(',');
        out_char(' ');
        out_one_operand(1);
        break;
        // M0,1,2,3
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
        // M
    case LM32_INSN_BREAK:
    case LM32_INSN_SCALL:
    case LM32_INSN_BRET:
    case LM32_INSN_ERET:
    case LM32_INSN_RET:
    case LM32_INSN_NOP:
        out_mnem();
        break;
    default:
        break;
    }
    flush_outbuf();
}
