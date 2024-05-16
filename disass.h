#include <stdint.h>

#ifdef __cplusplus
  extern "C" {
#endif
enum insn_id {
    N850_ADD,
    N850_ADD_IMM,
    N850_ADDI,
    N850_AND,
    N850_ANDI,
    N850_BGE,
    N850_BGT,
    N850_BLE,
    N850_BLT,
    N850_BH,
    N850_BL,
    N850_BNH,
    N850_BNL,
    N850_BE,
    N850_BNE,
    N850_BC,
    N850_BN,
    N850_BNC,
    N850_BNV,
    N850_BNZ,
    N850_BP,
    N850_BR,
    N850_BSA,
    N850_BV,
    N850_BZ,
    N850_BSH,
    N850_BSW,
    N850_CALLT,
    N850_CLR1,
    N850_CLR1R,
    N850_CMOV,
    N850_CMOVI,
    N850_CMP,
    N850_CMPI,
    N850_CTRET,
    N850_DBRET,
    N850_DBTRAP,
    N850_DI,
    N850_DISPOSE,
    N850_DISPOSER,
    N850_DIV,
    N850_DIVH,
    N850_DIVHR,
    N850_DIVHU,
    N850_DIVU,
    N850_EI,
    N850_HALT,
    N850_HSW,
    N850_JARL,
    N850_JMP,
    N850_JMPI,
    N850_JR,
    N850_LDB,
    N850_LDBU,
    N850_LDH,
    N850_LDHU,
    N850_LDW,
    N850_LDSR,
    N850_MOV,
    N850_MOVI5,
    N850_MOVI,
    N850_MOVEA,
    N850_MOVHI,
    N850_MUL,
    N850_MULI,
    N850_MULH,
    N850_MULHIMM,
    N850_MULHI,
    N850_MULU,
    N850_MULUI,
    N850_NOP,
    N850_NOT,
    N850_NOT1,
    N850_NOT1R,
    N850_OR,
    N850_ORI,
    N850_PREPARE,
    N850_RETI,
    N850_SAR,
    N850_SARI,
    N850_SASF,
    N850_SATADD,
    N850_SATADDI,
    N850_SATSUB,
    N850_SATSUBI,
    N850_SATSUBR,
    N850_SET1,
    N850_SET1R,
    N850_SETF,
    N850_SHL,
    N850_SHLI,
    N850_SHR,
    N850_SHRI,
    N850_SLDB,
    N850_SLDBU,
    N850_SLDH,
    N850_SLDHU,
    N850_SLDW,
    N850_SSTB,
    N850_SSTH,
    N850_SSTW,
    N850_STB,
    N850_STH,
    N850_STW,
    N850_STSR,
    N850_STSRI,
    N850_SUB,
    N850_SUBR,
    N850_SWITCH,
    N850_SXB,
    N850_SXH,
    N850_SYNCE,
    N850_SYNCI,
    N850_SYNCM,
    N850_SYNCP,
    N850_SYSCALL,
    N850_TRAP,
    N850_TST,
    N850_TST1,
    N850_TST1R,
    N850_XOR,
    N850_XORI,
    N850_ZXB,
    N850_ZXH,


};

enum op_type {
  TYPE_NONE = 0,
  TYPE_REG  = 1,
  TYPE_IMM  = 2,
  TYPE_MEM  = 3,
  TYPE_JMP  = 4,
  TYPE_CR   = 5,
  TYPE_LIST = 6,
  TYPE_SYSREG = 7
};

enum insn_type {
  OP_TYPE_ILL,

  OP_TYPE_ADD,
  OP_TYPE_SUB,
  OP_TYPE_MUL,
  OP_TYPE_DIV,
  OP_TYPE_SHR,
  OP_TYPE_SHL,
  OP_TYPE_ROR,

  OP_TYPE_AND,
  OP_TYPE_OR,
  OP_TYPE_XOR,
  OP_TYPE_NOR,
  OP_TYPE_NOT,

  OP_TYPE_IO,
  OP_TYPE_LOAD,
  OP_TYPE_STORE,
  OP_TYPE_MOV,

  OP_TYPE_CMP,
  OP_TYPE_JMP,
  OP_TYPE_CJMP,
  OP_TYPE_CALL,
  OP_TYPE_CCALL,
  OP_TYPE_RJMP,
  OP_TYPE_RCALL,
  OP_TYPE_RET,

  OP_TYPE_SYNC,
  OP_TYPE_SWI,
  OP_TYPE_TRAP,
  OP_TYPE_NOP
};

enum op_condition {
  COND_AL,
  COND_GE,
  COND_H,
  COND_NH,
  COND_LE,
  COND_L,
  COND_NL,
  COND_NE,
  COND_CA,
  COND_LT,
  COND_GT,
  COND_EQ,
  COND_NEG,
  COND_NZ,
  COND_NCA,
  COND_NOF,
  COND_POS,
  COND_SAT,
  COND_OF,
  COND_ZERO,
  COND_NV
};

enum sign {
  UNSIGNED,
  SIGNED
};

typedef struct {
  int64_t value;
  uint64_t size;
  enum sign sign;
  enum op_type type;
} insn_op_t;

typedef struct {
  const char* name;
  enum insn_id insn_id;
  insn_op_t fields[10];
  uint16_t n;
  uint16_t size;
  enum op_type op_type;
  enum op_condition cond;
} insn_t;

insn_t *disassemble(const uint8_t *in_buffer);

#ifdef __cplusplus
}
#endif