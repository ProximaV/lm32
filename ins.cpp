/* LM32 IDP instructions - thanks to Proxima's proc gen
*/

#include "lm32.hpp"
instruc_t Instructions[] =
{
                          { "",            0                                       }, //unknown
                          { "--invalid--", 0                                       }, //--invalid--
    /* add */             { "add",           CF_CHG1 | CF_USE2 | CF_USE3           }, //add             $r2,$r0,$r1
    /* addi */            { "addi",          CF_CHG1 | CF_USE2 | CF_USE3           }, //addi            $r1,$r0,$imm
    /* and */             { "and",           CF_CHG1 | CF_USE2 | CF_USE3           }, //and             $r2,$r0,$r1
    /* andi */            { "andi",          CF_CHG1 | CF_USE2 | CF_USE3           }, //andi            $r1,$r0,$uimm
    /* andhii */          { "andhi",         CF_CHG1 | CF_USE2 | CF_USE3           }, //andhii          $r1,$r0,$hi16
    /* b */               { "b",             CF_USE1 | CF_STOP | CF_JUMP           }, //b               $r0
    /* bi */              { "bi",            CF_USE1 | CF_STOP                     }, //bi              $call
    /* be */              { "be",            CF_USE1 | CF_USE2 | CF_USE3           }, //be              $r0,$r1,$branch
    /* bg */              { "bg",            CF_CHG1 | CF_USE2 | CF_USE3           }, //bg              $r0,$r1,$branch
    /* bge */             { "bge",           CF_USE1 | CF_USE2 | CF_USE3           }, //bge             $r0,$r1,$branch
    /* bgeu */            { "bgeu",          CF_USE1 | CF_USE2 | CF_USE3           }, //bgeu            $r0,$r1,$branch
    /* bgu */             { "bgu",           CF_USE1 | CF_USE2 | CF_USE3           }, //bgu             $r0,$r1,$branch
    /* bne */             { "bne",           CF_CHG1 | CF_USE2 | CF_USE3           }, //bne             $r0,$r1,$branch
    /* call */            { "call",          CF_USE1 | CF_CALL                     }, //call            $r0
    /* calli */           { "calli",         CF_USE1 | CF_CALL                     }, //calli           $call
    /* cmpe */            { "cmpe",          CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpe            $r2,$r0,$r1
    /* cmpei */           { "cmpei",         CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpei           $r1,$r0,$imm
    /* cmpg */            { "cmpg",          CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpg            $r2,$r0,$r1
    /* cmpgi */           { "cmpgi",         CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpgi           $r1,$r0,$imm
    /* cmpge */           { "cmpge",         CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpge           $r2,$r0,$r1
    /* cmpgei */          { "cmpgei",        CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpgei          $r1,$r0,$imm
    /* cmpgeu */          { "cmpgeu",        CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpgeu          $r2,$r0,$r1
    /* cmpgeui */         { "cmpgeui",       CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpgeui         $r1,$r0,$uimm
    /* cmpgu */           { "cmpgu",         CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpgu           $r2,$r0,$r1
    /* cmpgui */          { "cmpgui",        CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpgui          $r1,$r0,$uimm
    /* cmpne */           { "cmpne",         CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpne           $r2,$r0,$r1
    /* cmpnei */          { "cmpnei",        CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpnei          $r1,$r0,$imm
    /* divu */            { "divu",          CF_CHG1 | CF_USE2 | CF_USE3           }, //divu            $r2,$r0,$r1
    /* lb */              { "lb",            CF_CHG1 | CF_USE2 | CF_USE3           }, //lb              $r1,($r0+$imm)
    /* lbu */             { "lbu",           CF_CHG1 | CF_USE2 | CF_USE3           }, //lbu             $r1,($r0+$imm)
    /* lh */              { "lh",            CF_CHG1 | CF_USE2 | CF_USE3           }, //lh              $r1,($r0+$imm)
    /* lhu */             { "lhu",           CF_CHG1 | CF_USE2 | CF_USE3           }, //lhu             $r1,($r0+$imm)
    /* lw */              { "lw",            CF_CHG1 | CF_USE2 | CF_USE3           }, //lw              $r1,($r0+$imm)
    /* modu */            { "modu",          CF_CHG1 | CF_USE2 | CF_USE3           }, //modu            $r2,$r0,$r1
    /* mul */             { "mul",           CF_CHG1 | CF_USE2 | CF_USE3           }, //mul             $r2,$r0,$r1
    /* muli */            { "muli",          CF_CHG1 | CF_USE2 | CF_USE3           }, //muli            $r1,$r0,$imm
    /* nor */             { "nor",           CF_CHG1 | CF_USE2 | CF_USE3           }, //nor             $r2,$r0,$r1
    /* nori */            { "nori",          CF_CHG1 | CF_USE2 | CF_USE3           }, //nori            $r1,$r0,$uimm
    /* or */              { "or",            CF_CHG1 | CF_USE2 | CF_USE3           }, //or              $r2,$r0,$r1
    /* ori */             { "ori",           CF_CHG1 | CF_USE2 | CF_USE3           }, //ori             $r1,$r0,$lo16
    /* orhii */           { "orhi",          CF_CHG1 | CF_USE2 | CF_USE3           }, //orhii           $r1,$r0,$hi16
    /* rcsr */            { "rcsr",          CF_CHG1 | CF_USE2                     }, //rcsr            $r2,$csr
    /* sb */              { "sb",            CF_CHG1 | CF_USE2 | CF_USE3           }, //sb              ($r0+$imm),$r1
    /* sextb */           { "sextb",         CF_CHG1 | CF_USE2                     }, //sextb           $r2,$r0
    /* sexth */           { "sexth",         CF_CHG1 | CF_USE2                     }, //sexth           $r2,$r0
    /* sh */              { "sh",            CF_CHG1 | CF_USE2 | CF_USE3           }, //sh              ($r0+$imm),$r1
    /* sl */              { "sl",            CF_CHG1 | CF_USE2 | CF_USE3           }, //sl              $r2,$r0,$r1
    /* sli */             { "sli",           CF_CHG1 | CF_USE2 | CF_USE3           }, //sli             $r1,$r0,$imm
    /* sr */              { "sr",            CF_CHG1 | CF_USE2 | CF_USE3           }, //sr              $r2,$r0,$r1
    /* sri */             { "sri",           CF_CHG1 | CF_USE2 | CF_USE3           }, //sri             $r1,$r0,$imm
    /* sru */             { "sru",           CF_CHG1 | CF_USE2 | CF_USE3           }, //sru             $r2,$r0,$r1
    /* srui */            { "srui",          CF_CHG1 | CF_USE2 | CF_USE3           }, //srui            $r1,$r0,$imm
    /* sub */             { "sub",           CF_CHG1 | CF_USE2 | CF_USE3           }, //sub             $r2,$r0,$r1
    /* sw */              { "sw",            CF_CHG1 | CF_USE2 | CF_USE3           }, //sw              ($r0+$imm),$r1
    /* user */            { "user",          CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, //user            $r2,$r0,$r1,$user
    /* wcsr */            { "wcsr",          CF_CHG1 | CF_USE2                     }, //wcsr            $csr,$r1
    /* xor */             { "xor",           CF_CHG1 | CF_USE2 | CF_USE3           }, //xor             $r2,$r0,$r1
    /* xori */            { "xori",          CF_CHG1 | CF_USE2 | CF_USE3           }, //xori            $r1,$r0,$uimm
    /* xnor */            { "xnor",          CF_CHG1 | CF_USE2 | CF_USE3           }, //xnor            $r2,$r0,$r1
    /* xnori */           { "xnori",         CF_CHG1 | CF_USE2 | CF_USE3           }, //xnori           $r1,$r0,$uimm
    /* break */           { "break",         CF_STOP                               }, //break          
    /* scall */           { "scall",         CF_STOP                               }, //scall          
    /* bret */            { "bret",          CF_STOP                               }, //bret           
    /* eret */            { "eret",          CF_STOP                               }, //eret           
    /* ret */             { "ret",           CF_STOP                               }, //ret            
    /* mv */              { "mv",            CF_CHG1 | CF_USE2                     }, //mv              $r2,$r0
    /* mvi */             { "mvi",           CF_CHG1 | CF_USE2                     }, //mvi             $r1,$imm
    /* mvui */            { "mvu",           CF_CHG1 | CF_USE2                     }, //mvui            $r1,$lo16
    /* mvhi */            { "mvhi",          CF_CHG1 | CF_USE2                     }, //mvhi            $r1,$hi16
    /* mva */             { "mva",           CF_CHG1 | CF_USE2                     }, //mva             $r1,$gp16
    /* not */             { "not",           CF_CHG1 | CF_USE2                     }, //not             $r2,$r0
    /* nop */             { "nop",           0                                     }, //nop            
};
