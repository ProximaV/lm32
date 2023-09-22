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

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern instruc_t Instructions[];

typedef enum nameNum ENUM_SIZE(uint16)
{
  LM32_INSN_UNKNOWN = 0, 
  LM32_INSN_X_INVALID, 
  LM32_INSN_ADD, 
  LM32_INSN_ADDI, 
  LM32_INSN_AND, 
  LM32_INSN_ANDI, 
  LM32_INSN_ANDHII, 
  LM32_INSN_B, 
  LM32_INSN_BI, 
  LM32_INSN_BE, 
  LM32_INSN_BG, 
  LM32_INSN_BGE, 
  LM32_INSN_BGEU, 
  LM32_INSN_BGU, 
  LM32_INSN_BNE, 
  LM32_INSN_CALL, 
  LM32_INSN_CALLI, 
  LM32_INSN_CMPE, 
  LM32_INSN_CMPEI, 
  LM32_INSN_CMPG, 
  LM32_INSN_CMPGI, 
  LM32_INSN_CMPGE, 
  LM32_INSN_CMPGEI, 
  LM32_INSN_CMPGEU, 
  LM32_INSN_CMPGEUI, 
  LM32_INSN_CMPGU, 
  LM32_INSN_CMPGUI, 
  LM32_INSN_CMPNE, 
  LM32_INSN_CMPNEI, 
  LM32_INSN_DIVU, 
  LM32_INSN_LB, 
  LM32_INSN_LBU, 
  LM32_INSN_LH, 
  LM32_INSN_LHU, 
  LM32_INSN_LW, 
  LM32_INSN_MODU, 
  LM32_INSN_MUL, 
  LM32_INSN_MULI, 
  LM32_INSN_NOR, 
  LM32_INSN_NORI, 
  LM32_INSN_OR, 
  LM32_INSN_ORI, 
  LM32_INSN_ORHII, 
  LM32_INSN_RCSR, 
  LM32_INSN_SB, 
  LM32_INSN_SEXTB, 
  LM32_INSN_SEXTH, 
  LM32_INSN_SH, 
  LM32_INSN_SL, 
  LM32_INSN_SLI, 
  LM32_INSN_SR, 
  LM32_INSN_SRI, 
  LM32_INSN_SRU, 
  LM32_INSN_SRUI, 
  LM32_INSN_SUB, 
  LM32_INSN_SW, 
  LM32_INSN_USER, 
  LM32_INSN_WCSR, 
  LM32_INSN_XOR, 
  LM32_INSN_XORI, 
  LM32_INSN_XNOR, 
  LM32_INSN_XNORI, 
  LM32_INSN_BREAK, 
  LM32_INSN_SCALL, 
  LM32_INSN_BRET, 
  LM32_INSN_ERET, 
  LM32_INSN_RET, 
  LM32_INSN_MV, 
  LM32_INSN_MVI, 
  LM32_INSN_MVUI, 
  LM32_INSN_MVHI, 
  LM32_INSN_MVA, 
  LM32_INSN_NOT, 
  LM32_INSN_NOP, 
} LM32_INSN_TYPE;
#endif
