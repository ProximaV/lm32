/* LM32 IDP instructions

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

instruc_t Instructions[] =
{
    { "",            0                                     }, //unknown
    { "--invalid--", 0                                     }, //--invalid--
    { "add",         CF_CHG1 | CF_USE2 | CF_USE3           }, //add $r2,$r0,$r1
    { "addi",        CF_CHG1 | CF_USE2 | CF_USE3           }, //addi $r1,$r0,$imm
    { "and",         CF_CHG1 | CF_USE2 | CF_USE3           }, //and $r2,$r0,$r1
    { "andi",        CF_CHG1 | CF_USE2 | CF_USE3           }, //andi $r1,$r0,$uimm
    { "andhi",       CF_CHG1 | CF_USE2 | CF_USE3           }, //andhi $r1,$r0,$hi16
    { "b",           CF_USE1 | CF_STOP | CF_JUMP           }, //b $r0
    { "bi",          CF_USE1 | CF_STOP                     }, //bi $call
    { "be",          CF_USE1 | CF_USE2 | CF_USE3           }, //be $r0,$r1,$branch
    { "bg",          CF_USE1 | CF_USE2 | CF_USE3           }, //bg $r0,$r1,$branch
    { "bge",         CF_USE1 | CF_USE2 | CF_USE3           }, //bge $r0,$r1,$branch
    { "bgeu",        CF_USE1 | CF_USE2 | CF_USE3           }, //bgeu $r0,$r1,$branch
    { "bgu",         CF_USE1 | CF_USE2 | CF_USE3           }, //bgu $r0,$r1,$branch
    { "bne",         CF_USE1 | CF_USE2 | CF_USE3           }, //bne $r0,$r1,$branch
    { "call",        CF_USE1 | CF_CALL                     }, //call $r0
    { "calli",       CF_USE1 | CF_CALL                     }, //calli $call
    { "cmpe",        CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpe $r2,$r0,$r1
    { "cmpei",       CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpei $r1,$r0,$imm
    { "cmpg",        CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpg $r2,$r0,$r1
    { "cmpgi",       CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpgi $r1,$r0,$imm
    { "cmpge",       CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpge $r2,$r0,$r1
    { "cmpgei",      CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpgei $r1,$r0,$imm
    { "cmpgeu",      CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpgeu $r2,$r0,$r1
    { "cmpgeui",     CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpgeui $r1,$r0,$uimm
    { "cmpgu",       CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpgu $r2,$r0,$r1
    { "cmpgui",      CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpgui $r1,$r0,$uimm
    { "cmpne",       CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpne $r2,$r0,$r1
    { "cmpnei",      CF_CHG1 | CF_USE2 | CF_USE3           }, //cmpnei $r1,$r0,$imm
    { "divu",        CF_CHG1 | CF_USE2 | CF_USE3           }, //divu $r2,$r0,$r1
    { "lb",          CF_CHG1 | CF_USE2 | CF_USE3           }, //lb $r1,($r0+$imm)
    { "lbu",         CF_CHG1 | CF_USE2 | CF_USE3           }, //lbu $r1,($r0+$imm)
    { "lh",          CF_CHG1 | CF_USE2 | CF_USE3           }, //lh $r1,($r0+$imm)
    { "lhu",         CF_CHG1 | CF_USE2 | CF_USE3           }, //lhu $r1,($r0+$imm)
    { "lw",          CF_CHG1 | CF_USE2 | CF_USE3           }, //lw $r1,($r0+$imm)
    { "modu",        CF_CHG1 | CF_USE2 | CF_USE3           }, //modu $r2,$r0,$r1
    { "mul",         CF_CHG1 | CF_USE2 | CF_USE3           }, //mul $r2,$r0,$r1
    { "muli",        CF_CHG1 | CF_USE2 | CF_USE3           }, //muli $r1,$r0,$imm
    { "nor",         CF_CHG1 | CF_USE2 | CF_USE3           }, //nor $r2,$r0,$r1
    { "nori",        CF_CHG1 | CF_USE2 | CF_USE3           }, //nori $r1,$r0,$uimm
    { "or",          CF_CHG1 | CF_USE2 | CF_USE3           }, //or $r2,$r0,$r1
    { "ori",         CF_CHG1 | CF_USE2 | CF_USE3           }, //ori $r1,$r0,$lo16
    { "orhi",        CF_CHG1 | CF_USE2 | CF_USE3           }, //orhi $r1,$r0,$hi16
    { "rcsr",        CF_CHG1 | CF_USE2                     }, //rcsr $r2,$csr
    { "sb",          CF_CHG1 | CF_USE2 | CF_USE3           }, //sb ($r0+$imm),$r1
    { "sextb",       CF_CHG1 | CF_USE2                     }, //sextb $r2,$r0
    { "sexth",       CF_CHG1 | CF_USE2                     }, //sexth $r2,$r0
    { "sh",          CF_CHG1 | CF_USE2 | CF_USE3           }, //sh ($r0+$imm),$r1
    { "sl",          CF_CHG1 | CF_USE2 | CF_USE3           }, //sl $r2,$r0,$r1
    { "sli",         CF_CHG1 | CF_USE2 | CF_USE3           }, //sli $r1,$r0,$imm
    { "sr",          CF_CHG1 | CF_USE2 | CF_USE3           }, //sr $r2,$r0,$r1
    { "sri",         CF_CHG1 | CF_USE2 | CF_USE3           }, //sri $r1,$r0,$imm
    { "sru",         CF_CHG1 | CF_USE2 | CF_USE3           }, //sru $r2,$r0,$r1
    { "srui",        CF_CHG1 | CF_USE2 | CF_USE3           }, //srui $r1,$r0,$imm
    { "sub",         CF_CHG1 | CF_USE2 | CF_USE3           }, //sub $r2,$r0,$r1
    { "sw",          CF_CHG1 | CF_USE2 | CF_USE3           }, //sw ($r0+$imm),$r1
    { "user",        CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 }, //user $r2,$r0,$r1,$user
    { "wcsr",        CF_CHG1 | CF_USE2                     }, //wcsr $csr,$r1
    { "xor",         CF_CHG1 | CF_USE2 | CF_USE3           }, //xor $r2,$r0,$r1
    { "xori",        CF_CHG1 | CF_USE2 | CF_USE3           }, //xori $r1,$r0,$uimm
    { "xnor",        CF_CHG1 | CF_USE2 | CF_USE3           }, //xnor $r2,$r0,$r1
    { "xnori",       CF_CHG1 | CF_USE2 | CF_USE3           }, //xnori $r1,$r0,$uimm
    { "break",       CF_STOP                               }, //break
    { "scall",       CF_STOP                               }, //scall
    { "bret",        CF_STOP                               }, //bret
    { "eret",        CF_STOP                               }, //eret
    { "ret",         CF_STOP                               }, //ret
    { "mv",          CF_CHG1 | CF_USE2                     }, //mv $r2,$r0
    { "mvi",         CF_CHG1 | CF_USE2                     }, //mvi $r1,$imm
    { "mvu",         CF_CHG1 | CF_USE2                     }, //mvu $r1,$lo16
    { "mvhi",        CF_CHG1 | CF_USE2                     }, //mvhi $r1,$hi16
    { "mva",         CF_CHG1 | CF_USE2                     }, //mva $r1,$gp16
    { "not",         CF_CHG1 | CF_USE2                     }, //not $r2,$r0
    { "nop",         0                                     }, //nop
};
