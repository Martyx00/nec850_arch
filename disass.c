#include "disass.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint64_t mask;
  uint16_t shr;
  uint16_t shl;
  uint16_t add;
  uint16_t size; // in bits
  uint16_t sign; // 0 unsigned
  uint16_t index;
  enum op_type type;
} disass_op_t;

typedef struct {
  const char* name; //instructio name
  enum insn_id insn_id;  // Instruction ID
  uint16_t size; // instruction size
  uint64_t mask; // instruction mask
  uint64_t static_mask;
  uint16_t n; // Number of arguments
  enum insn_type op_type; // Type of oepration
  enum op_condition cond; // Conditionals
  disass_op_t fields[5]; // Operands
} disass_insn_t;



const disass_insn_t instruction_list[] = {
    // 6-byte insturctions
    { "mov"   , N850_MOVI     ,    6, 0x63fffffffff  , 0x62000000000  , 2,   OP_TYPE_MOV, COND_NV, {{0xffff0000,  16,  0,  0, 16, UNSIGNED, 0, TYPE_IMM}, {0xffff,  0,  16,  0, 16, UNSIGNED, 0, TYPE_IMM},{0x001f00000000,  32,  0,  0, 5, UNSIGNED, 1, TYPE_REG},  {0}, {0}}},
    { "jarl"   , N850_JARL2     ,    6, 0x2fffffeffff  , 0x2e000000000  , 2,   OP_TYPE_CALL, COND_NV, {{0x001f00000000,  32,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xffff0000,  16,  0,  0, 16, UNSIGNED, 0, TYPE_MEM}, {0xffff,  0,  16,  0, 16, UNSIGNED, 0, TYPE_MEM}, {0}, {0}}},


    // 4 byte insturctions
//  { "name"   , enum          , size, mask        , static_mask , n,   op_type    , cond   , {{field ,shr,shl,  +, size, sign, index, TYPE_REG}, ...}
    // Floats
    { "absf.s"   , N850_ABSFS     ,    4, 0xFFE0FC48  , 0x07E00448  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "addf.s"   , N850_ADDFS     ,    4, 0xFFFFFC60  , 0x7E00460  , 3,   OP_TYPE_ADD, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}}},
    { "ceilf.sl"   , N850_CEILFSL     ,    4, 0xFFE2F444  , 0x07E20444  , 2,   OP_TYPE_MOV, COND_NV, {{0x000f000,  12,  0,  0, 4, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "ceilf.sul"   , N850_CEILFSUL     ,    4, 0xFFF2F444  , 0x07F20444  , 2,   OP_TYPE_MOV, COND_NV, {{0x000f000,  12,  0,  0, 4, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "ceilf.suw"   , N850_CEILFSUW     ,    4, 0xFFF2FC40  , 0x07F20440  , 2,   OP_TYPE_MOV, COND_NV, {{0x000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "ceilf.sw"   , N850_CEILFSW     ,    4, 0xFFE2FC40  , 0x07E20440  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "cmovf.s"   , N850_CMOVFS     ,    4, 0xFFFFFC0E  , 0x07E00400  , 4,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 3, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    // TODO ONLY FIRST ONE HERE IS CORRECT
    { "cmpf.s(F)"   , N850_CMPFSF     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(UN)"   , N850_CMPFSUN     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(EQ)"   , N850_CMPFSEQ     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(UEQ)"   , N850_CMPFSUEQ     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(OLT)"   , N850_CMPFSOLT     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(ULT)"   , N850_CMPFSULT     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(OLE)"   , N850_CMPFSOLE     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(ULE)"   , N850_CMPFSULE     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(SF)"   , N850_CMPFSSF     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(NGLE)"   , N850_CMPFSNGLE     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(SEQ)"   , N850_CMPFSSEQ     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(NGL)"   , N850_CMPFSNGL     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(SLT)"   , N850_CMPFSLT     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(NGE)"   , N850_CMPFSNGE     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(LE)"   , N850_CMPFSLE     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "cmpf.s(NGT)"   , N850_CMPFSNGT     ,    4, 0xFFFF042E , 0x07E00420  , 3,   OP_TYPE_MOV, COND_NV, {{0}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000000E,  1,  0,  0, 3, UNSIGNED, 0, TYPE_CR}, {0}}},
    // END OF TODO
    { "cvtf.hs"   , N850_CVTFHS     ,    4, 0xFFE2FC42  , 0x7E20442  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "cvtf.ls"   , N850_CVTFLS     ,    4, 0xF7E1FC42  , 0x7E10442  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf0000000,  28,  0,  0, 4, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "cvtf.sl"   , N850_CVTFSL     ,    4, 0xFFE4FC44  , 0x7E40444  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f000,  12,  0,  0, 4, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "cvtf.sh"   , N850_CVTFSH     ,    4, 0xFFE3FC42  , 0x7E30442  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "cvtf.sul"   , N850_CVTFSUL     ,    4, 0xFFF4FC44  , 0x07F40444  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "cvtf.suw"   , N850_CVTFSUW     ,    4, 0xFFF4FC40  , 0x07F40440 , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "cvtf.sw"   , N850_CVTFSW     ,    4, 0xFFF4FC40  , 0x07F40440 , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "cvtf.uls"   , N850_CVTFULS     ,    4, 0xF7F1FC42  , 0x07F10442 , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf0000000,  28,  0,  0, 4, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "cvtf.uws"   , N850_CVTFUWS     ,    4, 0xFFF0FC42  , 0x07F00442 , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "cvtf.ws"   , N850_CVTFWS     ,    4, 0xFFE0FC42  , 0x07E00442 , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},

    { "divf.s"   , N850_DIVFS     ,    4, 0xFFFFFC6E  , 0x7E0046E  , 3,   OP_TYPE_DIV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}}},
    
    { "floorf.sl"   , N850_FLOORFSL    ,    4, 0xFFE3F444  , 0x7E30444  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f000,  12,  0,  0, 4, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "floorf.sul"   , N850_FLOORFSUL    ,    4, 0xFFF3F444  , 0x7F30444  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f000,  12,  0,  0, 4, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},

    { "floorf.suw"   , N850_FLOORFSUW     ,    4, 0xFFF3FC40  , 0x7F30440  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "floorf.sw"   , N850_FLOORFSW     ,    4, 0xFFE3FC40  , 0x7E30440  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},

    { "fmaf.s"   , N850_FMAFS     ,    4, 0xFFFFFCE0  , 0x7E004E0  , 3,   OP_TYPE_DIV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}}},
    { "fmsf.s"   , N850_FMSFS     ,    4, 0xFFFFFCE2  , 0x7E004E2  , 3,   OP_TYPE_DIV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}}},
    { "fnmaf.s"   , N850_FNMAFS     ,    4, 0xFFFFFCE4  , 0x7E004E4  , 3,   OP_TYPE_DIV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}}},
    { "fnmsf.s"   , N850_FNMSFS     ,    4, 0xFFFFFCE6  , 0x7E004E6  , 3,   OP_TYPE_DIV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}}},
    { "maxf.s"   , N850_MAXFS     ,    4, 0xFFFFFC68  , 0x7E00468  , 3,   OP_TYPE_DIV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}}},
    { "minf.s"   , N850_MINFS     ,    4, 0xFFFFFC6A  , 0x7E0046A  , 3,   OP_TYPE_DIV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}}},

    { "mulf.s"   , N850_MULFS     ,    4, 0xFFFFFC64  , 0x7E00464  , 3,   OP_TYPE_DIV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}}},
    { "negf.s"   , N850_NEGFS     ,    4, 0xFFE1FC48  , 0x7E10448  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "recipf.s"   , N850_RECIPFS    ,    4, 0xFFE1FC48  , 0x7E1044E  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    
    { "roundf.sl"   , N850_EOUNDFSL    ,    4, 0xFFE0F444  , 0x7E00444  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f000,  12,  0,  0, 4, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "roundf.sul"   , N850_EOUNDFSUL    ,    4, 0xFFF0F444  , 0x7F00444  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f000,  12,  0,  0, 4, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},

    { "roundf.suw"   , N850_ROUNDFSUW     ,    4, 0xFFF0FC40  , 0x7F00440  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "roundf.sw"   , N850_ROUNDFSW     ,    4, 0xFFE0FC40  , 0x7E00440  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    
    { "rsqrtf.s"   , N850_RSQRTFS     ,    4, 0xFFE2FC40  , 0x7E2044E  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "sqrtf.s"   , N850_SQRTFS     ,    4, 0xFFE0FC40  , 0x7E0044E  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},

    { "subf.s"   , N850_SUBFS     ,    4, 0xFFFFFC62  , 0x7E00462  , 3,   OP_TYPE_SUB, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}}},

    { "trfsr.s"   , N850_TRFSR     ,    4, 0x7E0040E  , 0x7E00400  , 1,   OP_TYPE_SUB, COND_NV, {{0x0000000E,  1,  0,  0, 3, UNSIGNED, 2, TYPE_CR}, {0}, {0}, {0}, {0}}},

    { "trncf.sl"   , N850_TRNCFSL    ,    4, 0xFFE1F444  , 0x7E10444  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f000,  12,  0,  0, 4, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "trncf.sul"   , N850_TRNCFSUL    ,    4, 0xFFF1F444  , 0x7F10444  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f000,  12,  0,  0, 4, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},

    { "trncf.suw"   , N850_TRNCFSUW     ,    4, 0xFFF1FC40  , 0x7F10440  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "trncf.sw"   , N850_TRNCFSW     ,    4, 0xFFE0FC40  , 0x7E00440  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},

    { "addi"   , N850_ADDI     ,    4, 0xFE1FFFFF  , 0x06000000  , 3,   OP_TYPE_MOV, COND_NV, {{0x0000ffff,  0,  0,  0, 16, SIGNED, 0, TYPE_IMM}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "adf"   , N850_ADF     ,    4, 0xFFFFFBBE  , 0x7E003A0  , 4,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 3, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000001E,  1,  0,  0, 4, UNSIGNED, 0, TYPE_CR}, {0}}},
    { "andi"   , N850_ANDI     ,    4, 0xFEDFFFFF  , 0x06C00000  , 3,   OP_TYPE_MOV, COND_NV, {{0x0000ffff,  0,  0,  0, 16, SIGNED, 0, TYPE_IMM}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "bsh"   , N850_BSH     ,    4, 0xFFE0FB42  , 0x07e00342  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "caxi"   , N850_CAXI    ,    4, 0xFFFFF8EE , 0x07E000EE  , 3,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG_MEM}, {0}, {0}}},
    { "cll"   , N850_CLL     ,    4, 0xFFFFF160  , 0xFFFFF160  , 0,   OP_TYPE_NOP, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    
    // TODO tehse dont work (params are wrong? could be solved with lifting?)
    { "bins"   , N850_BINS     ,    4, 0xFFFFF89E  , 0x07e00090  , 4,   OP_TYPE_MOV, COND_NV, {{0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 3, TYPE_REG}, {0x0000F000,  12,  0,  0, 4, UNSIGNED, 2, TYPE_IMM}, {0x00000800,  8,  0,  0, 1, UNSIGNED, 1, TYPE_IMM}, {0x0000000E,  1,  0,  0x10, 3, UNSIGNED, 1, TYPE_IMM}}},
    { "bins"   , N850_BINS2    ,    4, 0xFFFFF8BE  , 0x07e000B0  , 4,   OP_TYPE_MOV, COND_NV, {{0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 3, TYPE_REG}, {0x0000F000,  12,  0,  0, 5, UNSIGNED, 2, TYPE_IMM}, {0x00000800,  8,  0,  0, 1, UNSIGNED, 1, TYPE_IMM}, {0x0000000E,  1,  0,  0x10, 3, UNSIGNED, 1, TYPE_IMM}}},
    { "bins"   , N850_BINS3    ,    4, 0xFFFFF8DE  , 0x07e000D0  , 4,   OP_TYPE_MOV, COND_NV, {{0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 3, TYPE_REG}, {0x0000F000,  12,  0,  0, 4, UNSIGNED, 2, TYPE_IMM}, {0x00000800,  8,  0,  0, 1, UNSIGNED, 1, TYPE_IMM}, {0x0000000E,  1,  0,  0x10, 3, UNSIGNED, 1, TYPE_IMM}}},
    
    { "bsw"   , N850_BSW     ,    4, 0xFFE0FB40  , 0x07e00340  , 2,   OP_TYPE_MOV, COND_NV, {{0x0000f800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "clr1"   , N850_CLR1     ,    4, 0xBFDFFFFF  , 0x87c00000  , 3,   OP_TYPE_MOV, COND_NV, {{0x38000000,  27,  0,  0, 3, UNSIGNED, 0, TYPE_IMM}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x0000FFFF,  0,  0,  0, 16, SIGNED, 1, TYPE_MEM}, {0}, {0}}},
    { "clr1"   , N850_CLR1R     ,    4, 0xFFFF00E4  , 0x07e000e4  , 2,   OP_TYPE_MOV, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "cmov"   , N850_CMOV     ,    4, 0xFFFFFB3E  , 0x07e00320  , 4,   OP_TYPE_MOV, COND_NV, {{0x0000001E,  1,  0,  0, 4, UNSIGNED, 0, TYPE_CR}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xF8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x0000f800,  11,  0,  0, 5, UNSIGNED, 3, TYPE_REG}, {0}}},
    { "cmov"   , N850_CMOVI     ,    4, 0xFFFFFB1E  , 0x07e00300  , 4,   OP_TYPE_MOV, COND_NV, {{0x0000001E,  1,  0,  0, 4, UNSIGNED, 0, TYPE_CR}, {0x001f0000,  16,  0,  0, 5, SIGNED, 1, TYPE_IMM}, {0xF8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x0000f800,  11,  0,  0, 5, UNSIGNED, 3, TYPE_REG}, {0}}},
    { "ctret"   , N850_CTRET     ,    4, 0x7e00144  , 0x7e00144  , 0,   OP_TYPE_RET, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    { "dbret"   , N850_DBRET     ,    4, 0x7e00146  , 0x7e00146  , 0,   OP_TYPE_RET, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    { "di"   , N850_DI     ,    4, 0x7e00160  , 0x7e00160  , 0,   OP_TYPE_RET, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    { "nop"   , N850_NOP     ,    4, 0xFFFFF960  , 0xE7E00160  , 0,   OP_TYPE_NOP, COND_NV, {{0}, {0}, {0}, {0}, {0}}},

    { "dispose"   , N850_DISPOSE     ,    4, 0x67fffe0  , 0x6400000  , 2,   OP_TYPE_MOV, COND_NV, {{0x003e0000,  17,  2,  0, 5, UNSIGNED, 0, TYPE_IMM}, {0x0001ffe0,  5,  0,  0, 12, UNSIGNED, 1, TYPE_LIST}, {0}, {0}, {0}}},
    { "dispose"   , N850_DISPOSER     ,    4, 0x67fffff  , 0x6400000  , 3,   OP_TYPE_MOV, COND_NV, {{0x003e0000,  17,  2,  0, 5, UNSIGNED, 0, TYPE_IMM}, {0x0001ffe0,  5,  0,  0, 12, UNSIGNED, 1, TYPE_LIST}, {0x0000001f,  0,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "div"   , N850_DIV     ,    4, 0xfffffac0  , 0x7e002c0  , 3,   OP_TYPE_DIV, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x0000F800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "divh"   , N850_DIVHR     ,    4, 0xfffffa80  , 0x7e00280  , 3,   OP_TYPE_DIV, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x0000F800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "divhu"   , N850_DIVHU     ,    4, 0xfffffa82  , 0x7e00282  , 3,   OP_TYPE_DIV, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x0000F800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "divq"   , N850_DIVQ     ,    4, 0xfffffafc  , 0x7e002fc  , 3,   OP_TYPE_DIV, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x0000F800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "divqu"   , N850_DIVQU     ,    4, 0xfffffafe  , 0x7e002fe  , 3,   OP_TYPE_DIV, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x0000F800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "divu"   , N850_DIVU     ,    4, 0xfffffac2  , 0x7e002c2  , 3,   OP_TYPE_DIV, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x0000F800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "ei"   , N850_EI     ,    4, 0x87e00160  , 0x87e00160  , 0,   OP_TYPE_RET, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    { "eiret"   , N850_EIRET     ,    4, 0x7E00148  , 0x7E00148  , 0,   OP_TYPE_RET, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    { "feret"   , N850_FERET     ,    4, 0x7E0014A  , 0x7E0014A  , 0,   OP_TYPE_RET, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    
    { "halt"   , N850_HALT     ,    4, 0x7e00120  , 0x7e00120  , 0,   OP_TYPE_RET, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    { "hsw"   , N850_HSW     ,    4, 0xfffe0fb44  , 0x7e00344  , 2,   OP_TYPE_MOV, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x0000F800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "hsh"   , N850_HSH    ,    4, 0xFFE0FB46  , 0x7E00346  , 2,   OP_TYPE_MOV, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x0000F800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    
    
    { "jr"   , N850_JR     ,    4, 0x07bffffe  , 0x07800000  , 1,   OP_TYPE_JMP, COND_NV, {{0x003fffff,  0,  0,  0, 22, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0},{0}}},

    { "jarl"   , N850_JARL     ,    4, 0xffbffffe  , 0x7800000  , 2,   OP_TYPE_CALL, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x003fffff,  0,  0,  0, 22, SIGNED, 0, TYPE_MEM}, {0}, {0}, {0}}},
    { "jarl"   , N850_JARL3     ,    4, 0xC7FFF960  , 0xC7E00160  , 2,   OP_TYPE_CALL, COND_NV, {{0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG_MEM}, {0x0000f800,  11,  0,  0, 5, SIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    
    { "ld.b"   , N850_LDB     ,    4, 0xff1fffff  , 0x7000000  , 3,   OP_TYPE_LOAD, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000FFFF,  0,  0,  0, 16, SIGNED, 0, TYPE_MEM}, {0}, {0}}},
    { "ld.bu"   , N850_LDBU     ,    4, 0xffbfffff  , 0x7800000  , 3,   OP_TYPE_LOAD, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000FFFE,  0,  0,  0, 15, SIGNED, 0, TYPE_MEM}, {0x00200000,  21,  0,  0, 1, UNSIGNED, 0, TYPE_MEM}, {0}}},
    { "ld.h"   , N850_LDH     ,    4, 0xff3ffffe  , 0x7200000  , 3,   OP_TYPE_LOAD, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000FFFE,  0,  0,  0, 15, SIGNED, 0, TYPE_MEM}, {0}, {0}}},
    { "ld.hu"   , N850_LDHU     ,    4, 0xffffffff  , 0x7E00001  , 3,   OP_TYPE_LOAD, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000FFFE,  0,  0,  0, 15, SIGNED, 0, TYPE_MEM}, {0}, {0}}},
    { "ld.w"   , N850_LDW     ,    4, 0xff3fffff  , 0x7200001  , 3,   OP_TYPE_LOAD, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000FFFE,  0,  0,  0, 15, SIGNED, 0, TYPE_MEM}, {0}, {0}}},
    { "ldsr"   , N850_LDSR     ,    4, 0xffff0020  , 0x7E00020  , 2,   OP_TYPE_LOAD, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_SYSREG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "movea"   , N850_MOVEA     ,    4, 0xfe3fffff  , 0x6200000  , 3,   OP_TYPE_MOV, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000FFFF,  0,  0,  0, 16, SIGNED, 0, TYPE_IMM}, {0}, {0}}},
    { "movhi"   , N850_MOVHI     ,    4, 0xfe5fffff  , 0x6400000  , 3,   OP_TYPE_MOV, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000FFFF,  0,  0,  0, 16, UNSIGNED, 0, TYPE_IMM}, {0}, {0}}},
    { "mul"   , N850_MUL     ,    4, 0xfffffa20  , 0x7e00220  , 3,   OP_TYPE_MUL, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x0000F800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "mul"   , N850_MULI     ,    4, 0xfffffa7c  , 0x7e00240  , 3,   OP_TYPE_MUL, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, SIGNED, 0, TYPE_IMM}, {0x0000F800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x0000003c,  0,  3,  0, 4, SIGNED, 0, TYPE_IMM}, {0}}},
    { "mulhi"   , N850_MULHI     ,    4, 0xfeffffff  , 0x6e00000  , 3,   OP_TYPE_MUL, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000FFFF,  0,  0,  0, 16, UNSIGNED, 0, TYPE_IMM}, {0}, {0}}},
    { "mulu"   , N850_MULU     ,    4, 0xfffffa22  , 0x7e00222  , 3,   OP_TYPE_MUL, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x0000F800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "mulu"   , N850_MULUI     ,    4, 0xfffffa7e  , 0x7e00242  , 3,   OP_TYPE_MUL, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_IMM}, {0x0000F800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x0000003c,  0,  3,  0, 4, UNSIGNED, 0, TYPE_IMM}, {0}}},
    { "not1"   , N850_NOT1     ,    4, 0x7fdfffff  , 0x23c00000  , 3,   OP_TYPE_NOT, COND_NV, {{0x38000000,  27,  0,  0, 3, UNSIGNED, 0, TYPE_IMM}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x0000FFFF,  0,  0,  0, 16, SIGNED, 1, TYPE_MEM}, {0}, {0}}},
    { "not1"   , N850_NOT1R     ,    4, 0xffff00e2  , 0x07e000e2  , 2,   OP_TYPE_NOT, COND_NV, {{0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "ori"   , N850_ORI     ,    4, 0xfe9fffff  , 0x6800000  , 3,   OP_TYPE_OR, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000FFFF,  0,  0,  0, 16, SIGNED, 0, TYPE_IMM}, {0}, {0}}},
    { "prepare"   , N850_PREPARE     ,    4, 0x7bfffe1  , 0x7800001  , 2,   OP_TYPE_OR, COND_NV, {{0x003e0000,  17,  0,  0, 5, UNSIGNED, 1, TYPE_IMM}, {0x001ffe0,  5,  0,  0, 12, UNSIGNED, 0, TYPE_LIST}, {0}, {0}, {0}}}, // TODO ????
    { "reti"   , N850_RETI     ,    4, 0x7e00140  , 0x7e00140  , 0,   OP_TYPE_RET, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    { "sar"   , N850_SAR     ,    4, 0xffff00a0  , 0x07e000a0  , 2,   OP_TYPE_SHR, COND_NV, {{0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "sasf"   , N850_SASF     ,    4, 0xffef0200  , 0x07e00200  , 2,   OP_TYPE_SHL, COND_NV, {{0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x000f0000,  16,  0,  0, 4, UNSIGNED, 0, TYPE_CR}, {0}, {0}, {0}}},
    { "satsubi"   , N850_SATSUBI     ,    4, 0xfe7fffff  , 0x6600000  , 3,   OP_TYPE_OR, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000FFFF,  0,  0,  0, 16, SIGNED, 0, TYPE_IMM}, {0}, {0}}},
    { "set1"   , N850_SET1     ,    4, 0x3fdfffff  , 0x7c00000  , 3,   OP_TYPE_AND, COND_NV, {{0x38000000,  27,  0,  0, 3, UNSIGNED, 0, TYPE_IMM}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x0000FFFF,  0,  0,  0, 16, SIGNED, 1, TYPE_MEM}, {0}, {0}}},
    { "set1"   , N850_SET1R     ,    4, 0xffff00e0  , 0x07e000e0  , 2,   OP_TYPE_AND, COND_NV, {{0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "setf"   , N850_SETF     ,    4, 0xffef0000  , 0x07e00000  , 2,   OP_TYPE_MOV, COND_NV, {{0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x000f0000,  16,  0,  0, 4, UNSIGNED, 0, TYPE_CR}, {0}, {0}, {0}}},
    { "shl"   , N850_SHL     ,    4, 0xffff00c0  , 0x07e000c0  , 2,   OP_TYPE_SHL, COND_NV, {{0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "shr"   , N850_SHR     ,    4, 0xffff0080  , 0x07e00080  , 2,   OP_TYPE_SHR, COND_NV, {{0xf8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "st.b"   , N850_STB     ,    4, 0xff5fffff  , 0x7400000  , 3,   OP_TYPE_OR, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x0000FFFF,  0,  0,  0, 16, SIGNED, 1, TYPE_MEM}, {0}, {0}}},
    { "st.h"   , N850_STH     ,    4, 0xff7ffffe  , 0x7600000  , 3,   OP_TYPE_OR, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x0000FFFE,  0,  0,  0, 15, SIGNED, 1, TYPE_MEM}, {0}, {0}}},
    { "st.w"   , N850_STW     ,    4, 0xff7fffff  , 0x7600001  , 3,   OP_TYPE_OR, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x0000FFFE,  0,  0,  0, 15, SIGNED, 1, TYPE_MEM}, {0}, {0}}},
    { "stsr"   , N850_STSR     ,    4, 0xffff0040  , 0x07e00040  , 2,   OP_TYPE_OR, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_SYSREG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}}},
    { "stsr"   , N850_STSRI     ,    4, 0xfffff840  , 0x07e00040  , 3,   OP_TYPE_OR, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_SYSREG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x0000f800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_IMM}, {0}, {0}}},
    { "syscall"   , N850_SYSCALL     ,    4, 0xd7ff3960  , 0xd7e00160  , 1,   OP_TYPE_CALL, COND_NV, {{0x00003800,  6,  0,  0, 3, UNSIGNED, 0, TYPE_IMM}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_IMM}, {0}, {0}, {0}}},
    { "trap"   , N850_TRAP     ,    4, 0x7ff0100  , 0x7e00100  , 1,   OP_TYPE_TRAP, COND_NV, {{0x001f0000,  16,  0,  0, 5, UNSIGNED, 0, TYPE_IMM}, {0},{0}, {0}, {0}}},
    { "tst1"   , N850_TST1     ,    4, 0xffdfffff  , 0xc7c00000  , 3,   OP_TYPE_NOT, COND_NV, {{0x38000000,  27,  0,  0, 3, UNSIGNED, 0, TYPE_IMM}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x0000FFFF,  0,  0,  0, 16, SIGNED, 1, TYPE_MEM}, {0}, {0}}},
    { "tst1"   , N850_TST1R     ,    4, 0xffff00e6  , 0x07e000e6  , 2,   OP_TYPE_NOT, COND_NV, {{0xf8000000,  27,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "xori"   , N850_XORI     ,    4, 0xfeBfffff  , 0x6A00000  , 3,   OP_TYPE_OR, COND_NV, {{0xF8000000,  27,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0x001f0000,  16,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x0000FFFF,  0,  0,  0, 16, SIGNED, 0, TYPE_IMM}, {0}, {0}}},

    // TODO check all these
    { "jmp"   , N850_JMPI     ,    6, 0x6ffffffeffff    , 0x6E000000000       , 2,   OP_TYPE_RJMP, COND_NV, {{0x001f00000000,  32,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0xffff0000,  16,  0,  0, 16, UNSIGNED, 0, TYPE_MEM}, {0xffff,  0,  16,  0, 16, UNSIGNED, 0, TYPE_MEM}, {0}, {0}}},
    { "jr"   , N850_JRL     ,    6, 0x2e0fffeffff    , 0x2e000000000      , 1,   OP_TYPE_JMP, COND_NV, {{0}, {0xffff0000,  16,  0,  0, 16, UNSIGNED, 0, TYPE_MEM}, {0xffff,  0,  16,  0, 16, UNSIGNED, 0, TYPE_MEM}, {0}, {0}}},
    { "ld.b"   , N850_LDBL     ,    6, 0x79FFFF5ffff    , 0x78000050000     , 3,   OP_TYPE_LOAD, COND_NV, {{0x001f00000000,  32,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x7fff0000,  20,  0,  0, 7, UNSIGNED, 0, TYPE_MEM}, {0xffff,  0,  16,  0, 16, UNSIGNED, 0, TYPE_MEM}, {0x0000f8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}}},
    { "ld.bu"   , N850_LDBUL     ,    6, 0x7BFFFF5ffff    , 0x7A000050000     , 3,   OP_TYPE_LOAD, COND_NV, {{0x001f00000000,  32,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x7fff0000,  20,  0,  0, 7, UNSIGNED, 0, TYPE_MEM}, {0xffff,  0,  16,  0, 16, UNSIGNED, 0, TYPE_MEM}, {0x0000f8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}}},
    { "ld.dw"   , N850_LDDW     ,    6, 0x7BFFFE9ffff    , 0x7A000090000     , 3,   OP_TYPE_LOAD, COND_NV, {{0x001f00000000,  32,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0x7ffe0000,  21,  0,  0, 6, UNSIGNED, 0, TYPE_MEM}, {0xffff,  0,  16,  0, 16, UNSIGNED, 0, TYPE_MEM}, {0x0000f8000000,  27,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}}},









   
    // 2-byte Instructions
//  { "name"  , enum         , size, mask      , static_mask  , n,   op_type    , cond   , {{field ,shr,shl,  +, size (in bits), sign, index, TYPE_REG}, ...}
    //{ "mov"   , N850_MOV   ,    2, 0x0000    , 2,   OP_TYPE_MOV, COND_NV, {{0xf800,  10,  0,  0, TYPE_REG}, {0x001f,  0,  0,  0, TYPE_REG}, {0}, {0}}},
    { "nop"   , N850_NOP ,    2, 0x0000    , 0x0000       , 0,   OP_TYPE_NOP, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    { "switch"   , N850_SWITCH     ,    2, 0x005f    , 0x0040       , 1,   OP_TYPE_SUB, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}, {0}}},
    { "sxb"   , N850_SXB     ,    2, 0x00bf    , 0x00A0       , 1,   OP_TYPE_MOV, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}, {0}}},
    { "sxh"   , N850_SXH     ,    2, 0x00ff    , 0x00E0       , 1,   OP_TYPE_MOV, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}, {0}}},
    { "synce"   , N850_SYNCE ,    2, 0x001D    , 0x001D       , 0,   OP_TYPE_MOV, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    { "synci"   , N850_SYNCI ,    2, 0x001C    , 0x001C       , 0,   OP_TYPE_MOV, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    { "syncm"   , N850_SYNCM ,    2, 0x001E    , 0x001E       , 0,   OP_TYPE_MOV, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    { "syncp"   , N850_SYNCP ,    2, 0x001F    , 0x001F       , 0,   OP_TYPE_MOV, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    { "zxb"   , N850_ZXB     ,    2, 0x009f    , 0x0080       , 1,   OP_TYPE_MOV, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}, {0}}},
    { "zxh"   , N850_ZXH     ,    2, 0x00df    , 0x00C0       , 1,   OP_TYPE_MOV, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}, {0}}},

    
    { "add"   , N850_ADD     ,    2, 0xF9DF    , 0x01c0       , 2,   OP_TYPE_ADD, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "add"   , N850_ADD_IMM ,    2, 0xFA5F    , 0x0240       , 2,   OP_TYPE_ADD, COND_NV, {{0x001f,  0,  0,  0, 5, SIGNED, 0, TYPE_IMM}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "and"   , N850_AND     ,    2, 0xF95F    , 0x0140       , 2,   OP_TYPE_AND, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "bge"   , N850_BGE     ,    2, 0xFDFE    , 0x058E       , 1,   OP_TYPE_CJMP, COND_GE, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bgt"   , N850_BGT     ,    2, 0xFDFF    , 0x058F       , 1,   OP_TYPE_CJMP, COND_GT, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "ble"   , N850_BLE     ,    2, 0xFDF7    , 0x0587       , 1,   OP_TYPE_CJMP, COND_LE, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "blt"   , N850_BLT     ,    2, 0xFDF6    , 0x0586       , 1,   OP_TYPE_CJMP, COND_LT, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bh"   , N850_BH     ,    2, 0xFDFB    , 0x058B       , 1,   OP_TYPE_CJMP, COND_H, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bl"   , N850_BL     ,    2, 0xFDF1    , 0x0581       , 1,   OP_TYPE_CJMP, COND_L, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bnh"   , N850_BNH     ,    2, 0xFDF3    , 0x0583       , 1,   OP_TYPE_CJMP, COND_NH, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bnl"   , N850_BNL     ,    2, 0xFDF9    , 0x0589       , 1,   OP_TYPE_CJMP, COND_NL, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "be"   , N850_BE     ,    2, 0xFDF2    , 0x0582       , 1,   OP_TYPE_CJMP, COND_EQ, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bne"   , N850_BNE     ,    2, 0xFDFA    , 0x058A       , 1,   OP_TYPE_CJMP, COND_NE, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bc"   , N850_BC     ,    2, 0xFDF1    , 0x0581       , 1,   OP_TYPE_CJMP, COND_CA, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bn"   , N850_BN     ,    2, 0xFDF4    , 0x0584       , 1,   OP_TYPE_CJMP, COND_NEG, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bnc"   , N850_BNC     ,    2, 0xFDF9    , 0x0589       , 1,   OP_TYPE_CJMP, COND_NCA, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bnv"   , N850_BNV     ,    2, 0xFDF8    , 0x0588       , 1,   OP_TYPE_CJMP, COND_NOF, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bnz"   , N850_BNZ     ,    2, 0xFDFA    , 0x058A       , 1,   OP_TYPE_CJMP, COND_NZ, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bp"   , N850_BP     ,    2, 0xFDFC    , 0x058C       , 1,   OP_TYPE_CJMP, COND_POS, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "br"   , N850_BR     ,    2, 0xFDF5    , 0x0585       , 1,   OP_TYPE_JMP, COND_NV, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bsa"   , N850_BSA     ,    2, 0xFDFD    , 0x058D       , 1,   OP_TYPE_CJMP, COND_SAT, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bv"   , N850_BV     ,    2, 0xFDF0    , 0x0580       , 1,   OP_TYPE_CJMP, COND_OF, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "bz"   , N850_BZ     ,    2, 0xFDF2    , 0x0582       , 1,   OP_TYPE_CJMP, COND_ZERO, {{0x0070,  3,  0,  0, 4, SIGNED, 0, TYPE_JMP}, {0xf800,  7,  0,  0, 5, SIGNED, 0, TYPE_JMP}, {0}, {0}, {0}}},
    { "callt"   , N850_CALLT     ,    2, 0x23f    , 0x0200       , 1,   OP_TYPE_CALL, COND_NV, {{0x003f,  0,  1,  0, 6, UNSIGNED, 0, TYPE_JMP}, {0}, {0}, {0}, {0}}},
    { "cmp"   , N850_CMP     ,    2, 0xF9FF    , 0x01E0       , 2,   OP_TYPE_CMP, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "cmp"   , N850_CMPI ,    2, 0xFA7F    , 0x0260       , 2,   OP_TYPE_CMP, COND_NV, {{0x001f,  0,  0,  0, 5, SIGNED, 0, TYPE_IMM}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "dbtrap"   , N850_DBTRAP ,    2, 0xF840    , 0xF840       , 0,   OP_TYPE_CMP, COND_NV, {{0}, {0}, {0}, {0}, {0}}},
    { "divh"   , N850_DIVH,    2, 0xF85F    , 0x0040       , 2,   OP_TYPE_DIV, COND_NV, {{0x001f,  0,  0,  0, 5, SIGNED, 0, TYPE_IMM}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "jmp"   , N850_JMP     ,    2, 0x007f    , 0x0060       , 1,   OP_TYPE_RJMP, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}, {0}}},

    { "fetrap"   , N850_FETRAP     ,    2, 0x7840    , 0x0040       , 1,   OP_TYPE_RJMP, COND_NV, {{0x7800,  11,  0,  0, 4, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}, {0}}},

    { "mov"   , N850_MOV ,    2, 0xf81f    , 0x0000       , 2,   OP_TYPE_MOV, COND_NV, {{0x001f,  0,  0,  0, 5, SIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "mov"   , N850_MOVI5 ,    2, 0xfa1f    , 0x0200       , 2,   OP_TYPE_MOV, COND_NV, {{0x001f,  0,  0,  0, 5, SIGNED, 0, TYPE_IMM}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "mulh"   , N850_MULH ,    2, 0xf8ff    , 0x00e0       , 2,   OP_TYPE_MUL, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "mulh"   , N850_MULHIMM ,    2, 0xfaff    , 0x02e0       , 2,   OP_TYPE_MUL, COND_NV, {{0x001f,  0,  0,  0, 5, SIGNED, 0, TYPE_IMM}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "not"   , N850_NOT     ,    2, 0xf83f    , 0x0020       , 2,   OP_TYPE_NOT, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "or"   , N850_OR     ,    2, 0xf91f    , 0x0100       , 2,   OP_TYPE_OR, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "sar"   , N850_SARI     ,    2, 0xfabf    , 0x02A0       , 2,   OP_TYPE_SHR, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_IMM}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "satadd"   , N850_SATADD     ,    2, 0xf8df    , 0x00c0       , 2,   OP_TYPE_ADD, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "satadd"   , N850_SATADDI     ,    2, 0xfa3f    , 0x0220       , 2,   OP_TYPE_ADD, COND_NV, {{0x001f,  0,  0,  0, 5, SIGNED, 0, TYPE_IMM}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "satsub"   , N850_SATSUB     ,    2, 0xf8bf    , 0x00A0       , 2,   OP_TYPE_SUB, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "satsubr"   , N850_SATSUBR     ,    2, 0xf89f    , 0x0080       , 2,   OP_TYPE_SUB, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "shl"   , N850_SHLI     ,    2, 0xfadf    , 0x02c0       , 2,   OP_TYPE_SHL, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_IMM}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "shr"   , N850_SHRI     ,    2, 0xfa9f    , 0x0280       , 2,   OP_TYPE_SHR, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_IMM}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "sld.b"   , N850_SLDB     ,    2, 0xfb7f    , 0x0300       , 3,   OP_TYPE_LOAD, COND_NV, {{0x007f,  0,  0,  0, 7, UNSIGNED, 0, TYPE_IMM}, {0x1000,  0,  0,  0, 0, UNSIGNED, 1, TYPE_EP}, {0xf800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "sld.bu"   , N850_SLDBU     ,    2, 0xf86f    , 0x0060       , 3,   OP_TYPE_LOAD, COND_NV, {{0x000f,  0,  0,  0, 4, UNSIGNED, 0, TYPE_IMM}, {0x1000,  0,  0,  0, 0, UNSIGNED, 1, TYPE_EP},{0xf800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "sld.h"   , N850_SLDH     ,    2, 0xfc7f    , 0x0400       , 3,   OP_TYPE_LOAD, COND_NV, {{0x007f,  0,  1,  0, 7, UNSIGNED, 0, TYPE_IMM}, {0x1000,  0,  0,  0, 0, UNSIGNED, 1, TYPE_EP},{0xf800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "sld.hu"   , N850_SLDHU     ,    2, 0xf87f    , 0x0070       , 3,   OP_TYPE_LOAD, COND_NV, {{0x000f,  0,  1,  0, 4, UNSIGNED, 0, TYPE_IMM}, {0x1000,  0,  0,  0, 0, UNSIGNED, 1, TYPE_EP},{0xf800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},
    { "sld.w"   , N850_SLDW     ,    2, 0xfd7e    , 0x0500       , 3,   OP_TYPE_LOAD, COND_NV, {{0x007e,  0,  1,  0, 6, UNSIGNED, 0, TYPE_IMM}, {0x1000,  0,  0,  0, 0, UNSIGNED, 1, TYPE_EP},{0xf800,  11,  0,  0, 5, UNSIGNED, 2, TYPE_REG}, {0}, {0}}},

    { "sst.b"   , N850_SSTB     ,    2, 0xfbff    , 0x0380       , 3,   OP_TYPE_STORE, COND_NV, {{0x007f,  0,  0,  0, 7, UNSIGNED, 1, TYPE_IMM}, {0xf800,  11,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x1000,  0,  0,  0, 0, UNSIGNED, 2, TYPE_EP}, {0}, {0}}},
    { "sst.h"   , N850_SSTH     ,    2, 0xfCff    , 0x0480       , 3,   OP_TYPE_STORE, COND_NV, {{0x007f,  0,  1,  0, 7, UNSIGNED, 1, TYPE_IMM}, {0xf800,  11,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x1000,  0,  0,  0, 0, UNSIGNED, 2, TYPE_EP}, {0}, {0}}},
    { "sst.w"   , N850_SSTW     ,    2, 0xfd7f    , 0x0501       , 3,   OP_TYPE_STORE, COND_NV, {{0x007e,  0,  1,  0, 6, UNSIGNED, 1, TYPE_IMM}, {0xf800,  11,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0x1000,  0,  0,  0, 0, UNSIGNED, 2, TYPE_EP}, {0}, {0}}},
    { "sub"   , N850_SUB     ,    2, 0xF9BF    , 0x01a0       , 2,   OP_TYPE_SUB, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "subr"   , N850_SUBR     ,    2, 0xF99F    , 0x0180       , 2,   OP_TYPE_SUB, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "sxb"   , N850_SXB     ,    2, 0x00Bf    , 0x00A0       , 1,   OP_TYPE_SUB, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0}, {0}, {0}, {0}}},
    { "tst"   , N850_TST     ,    2, 0xF97F    , 0x0160       , 2,   OP_TYPE_AND, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},
    { "xor"   , N850_XOR     ,    2, 0xf93f    , 0x0120       , 2,   OP_TYPE_OR, COND_NV, {{0x001f,  0,  0,  0, 5, UNSIGNED, 0, TYPE_REG}, {0xf800,  11,  0,  0, 5, UNSIGNED, 1, TYPE_REG}, {0}, {0}, {0}}},







};


insn_t *disassemble(const uint8_t *in_buffer) {
    insn_t* ret_val = malloc(sizeof(insn_t));
    memset(ret_val,0,sizeof(insn_t));
    uint64_t data;
    uint8_t had_partials = 0;
    const disass_insn_t* current_insn;
    const uint32_t insn_list_size = sizeof (instruction_list) / sizeof (disass_insn_t);
    for (int insn_list_index = 0; insn_list_index < insn_list_size; insn_list_index++) {
        data = 0;
        current_insn = &instruction_list[insn_list_index];
        // add EP as a operand
        for (int i = 0; i < current_insn->size; i+=2) {
            data |= (uint64_t)in_buffer[i+1] << ((current_insn->size - (i+1)) * 8);
            data |= (uint64_t)in_buffer[i] << ((current_insn->size - (i+2)) * 8);
            //printf("Switching[%d] (shift: %d - shifted: 0x%lx): %x and %x: 0x%lx\n",i,((current_insn->size - i) * 8),(uint64_t)in_buffer[i+1] << ((current_insn->size - i) * 8),in_buffer[i],in_buffer[i+1],data);
        }
        
        //printf("Converted to %x\n",(uint32_t)data);
        if (((current_insn->mask & data) == data) && (current_insn->static_mask & data) == current_insn->static_mask) {// && (current_insn->mask & data) == data) {
            ret_val->name = current_insn->name;
            ret_val->size = current_insn->size;
            ret_val->op_type = current_insn->op_type;
            ret_val->cond = current_insn->cond;
            ret_val->insn_id = current_insn->insn_id;
            ret_val->n = current_insn->n;
            for (int op_index = 0; op_index < 5; op_index++) {
                if (current_insn->fields[op_index].mask == 0) continue;
                uint16_t real_op_index = current_insn->fields[op_index].index;
                int64_t tmp_value = data & current_insn->fields[op_index].mask;
                if (current_insn->fields[op_index].type == TYPE_EP) {
                    ret_val->fields[real_op_index].value = 30;
                    ret_val->fields[real_op_index].type = TYPE_REG;
                    ret_val->fields[real_op_index].size += current_insn->fields[op_index].size;
                    ret_val->fields[real_op_index].sign = current_insn->fields[op_index].sign;
                    continue;
                }
                
                tmp_value >>= current_insn->fields[op_index].shr;
                tmp_value <<= current_insn->fields[op_index].shl;
                tmp_value += current_insn->fields[op_index].add;
                ret_val->fields[real_op_index].value |= tmp_value;
                ret_val->fields[real_op_index].type = current_insn->fields[op_index].type;
                ret_val->fields[real_op_index].size += current_insn->fields[op_index].size;
                ret_val->fields[real_op_index].sign = current_insn->fields[op_index].sign;
                // Convert to little endian
                
                //printf("GOT %ld\n",ret_val->fields[real_op_index].value);
            }
            for (int op_index = 0; op_index < 5; op_index++)
            {
                if ((ret_val->fields[op_index].type == TYPE_IMM || ret_val->fields[op_index].type == TYPE_JMP) && ret_val->fields[op_index].sign == SIGNED) {
                    int64_t m = 1UL << (ret_val->fields[op_index].size - 1);
                    ret_val->fields[op_index].value = (ret_val->fields[op_index].value ^ m) - m;
                }
            }
            return ret_val;
        }
    }
    return NULL;
}

/*

typedef struct {
  uint64_t value;
  enum op_type type;
} insn_op_t;

typedef struct {
  const char* name;
  insn_op_t fields[10];
  uint16_t n;
  uint16_t size;
  enum op_type op_type;
  enum op_condition cond;
} insn_t;
*/

void pretty_print(insn_t* insn){
    printf("%s  ",insn->name);
    for (int i = 0; i < insn->n; i++) {
        printf(" 0x%x,",(int64_t)insn->fields[i].value);
    }
    printf("\n");
}

int main() {
    uint8_t test[] = {0x41,0x8a,0xdc,0x09};
    pretty_print(disassemble(test));
    
    printf("=========================\n");
    uint8_t test2[] = {0xdc,0x09};
    pretty_print(disassemble(test2));
    printf("=========================\n");
    uint8_t test3[] = {0x06,0xf6,0x06,0x00};
    pretty_print(disassemble(test3));
    printf("=========================\n");
    uint8_t test4[] = {0x11,0x06,0x9c,0xff};
    pretty_print(disassemble(test4));
    printf("=========================\n");
    uint8_t test5[] = {0x53,0x09};
    pretty_print(disassemble(test5));
    printf("=========================\n");
    uint8_t test6[] = {0xc2,0x9e,0x63,0x00};
    pretty_print(disassemble(test6));
    printf("=========================\n");
    uint8_t test7[] = {0x9e,0x0d,0x63,0x00};
    pretty_print(disassemble(test7));
    printf("=========================\n");
    uint8_t test8[] = {0xCA ,0xFD};
    pretty_print(disassemble(test8));
    return 1;
}