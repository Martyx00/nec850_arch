
#include "nec850.h"
#include "binaryninjaapi.h"
#include <vector>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "disass.h"

using namespace BinaryNinja;
using namespace std;

static const char *reg_name[] = {
	"r0",
	"r1",
	"r2",
	"sp",
	"gp",
	"tp",
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
	"r26",
	"r27",
	"r28",
	"r29",
	"ep",
	"lp",
	"pc"};

class NEC850 : public Architecture
{
private:
	BNEndianness endian;

	/* this can maybe be moved to the API later */
	BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset, size_t size, bool zeroExtend = false)
	{
		BNRegisterInfo result;
		result.fullWidthRegister = fullWidthReg;
		result.offset = offset;
		result.size = size;
		result.extend = zeroExtend ? ZeroExtendToFullWidth : NoExtend;
		return result;
	}

public:
	/* initialization list */
	NEC850(const char *name) : Architecture(name)
	{
	}

	/*************************************************************************/

	virtual BNEndianness GetEndianness() const override
	{
		// MYLOG("%s()\n", __func__);
		return LittleEndian;
	}

	virtual size_t GetAddressSize() const override
	{
		// MYLOG("%s()\n", __func__);
		return 4;
	}

	virtual size_t GetDefaultIntegerSize() const override
	{
		return 4;
	}

	virtual size_t GetInstructionAlignment() const override
	{
		return 2;
	}

	virtual size_t GetMaxInstructionLength() const override
	{
		return 8;
	}

	virtual vector<uint32_t> GetAllFlags() override
	{
		return vector<uint32_t>{
			FLAG_SAT,
			FLAG_CY,
			FLAG_OV,
			FLAG_S,
			FLAG_Z};
	}

	virtual string GetFlagName(uint32_t flag) override
	{
		switch (flag)
		{ // TODO more verbose? will it help?
		case FLAG_SAT:
			return "sat";
		case FLAG_CY:
			return "cy";
		case FLAG_OV:
			return "ov";
		case FLAG_S:
			return "s";
		case FLAG_Z:
			return "z";
		default:
			return "ERR_FLAG_NAME";
		}
	}

	virtual vector<uint32_t> GetAllFlagWriteTypes() override
	{
		return vector<uint32_t>{
			FLAG_WRITE_NONE,
			FLAG_WRITE_ALL,
			FLAG_WRITE_OVSZ};
	}

	virtual string GetFlagWriteTypeName(uint32_t writeType) override
	{
		switch (writeType)
		{
		case FLAG_WRITE_OVSZ:
			return "ovsz";
		case FLAG_WRITE_CYOVSZ:
			return "cyovsz";
		case FLAG_WRITE_ALL:
			return "*";
		default:
			return "none";
		}
	}

	virtual vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override
	{
		switch (writeType)
		{
		case FLAG_WRITE_OVSZ:
			return vector<uint32_t>{
				FLAG_Z, FLAG_S, FLAG_OV};
		case FLAG_WRITE_CYOVSZ:
			return vector<uint32_t>{
				FLAG_Z, FLAG_S, FLAG_OV ,FLAG_CY};
		case FLAG_WRITE_ALL:
			return vector<uint32_t>{
				FLAG_CY, FLAG_Z, FLAG_OV, FLAG_S};
		default:
			return vector<uint32_t>();
		}
	}

	virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass) override
	{
		bool signedClass = true;

		switch (flag)
		{
		case FLAG_SAT:
			return SpecialFlagRole;
		case FLAG_CY:
			return CarryFlagRole;
		case FLAG_Z:
			return ZeroFlagRole;
		case FLAG_OV:
			return OverflowFlagRole;
		case FLAG_S:
			return NegativeSignFlagRole;
		default:
			return SpecialFlagRole;
		}
	}

	virtual vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t) override
	{

		switch (cond)
		{
		case LLFC_E:  /* equal */
		case LLFC_NE: /* not equal */
			return vector<uint32_t>{FLAG_Z};

		case LLFC_ULT: /* (unsigned) less than == LT */
		case LLFC_UGE: /* (unsigned) greater-or-equal == !LT */
			return vector<uint32_t>{FLAG_CY};

		case LLFC_UGT: /* (unsigned) greater-than == GT */
		case LLFC_ULE: /* (unsigned) less-or-equal == !GT */
			return vector<uint32_t>{FLAG_CY, FLAG_Z};

		case LLFC_SLT: /* (signed) less than == LT */
		case LLFC_SGE: /* (signed) greater-or-equal == !LT */
			return vector<uint32_t>{FLAG_S, FLAG_OV};

		case LLFC_SGT: /* (signed) greater-than == GT */
		case LLFC_SLE: /* (signed) lesser-or-equal == !GT */
			return vector<uint32_t>{FLAG_S, FLAG_OV, FLAG_Z};

		case LLFC_NEG:
		case LLFC_POS:
			return vector<uint32_t>{FLAG_S};

		case LLFC_O:
		case LLFC_NO:
			return vector<uint32_t>{
				FLAG_OV};

		default:
			return vector<uint32_t>();
		}
	}

	virtual vector<uint32_t> GetFullWidthRegisters() override
	{

		return vector<uint32_t>{
			NEC_REG_R0, NEC_REG_R1, NEC_REG_R2, NEC_REG_SP, NEC_REG_R4, NEC_REG_R5, NEC_REG_R6, NEC_REG_R7,
			NEC_REG_R8, NEC_REG_R9, NEC_REG_R10, NEC_REG_R11, NEC_REG_R12, NEC_REG_R13, NEC_REG_R14, NEC_REG_R15,
			NEC_REG_R16, NEC_REG_R17, NEC_REG_R18, NEC_REG_R19, NEC_REG_R20, NEC_REG_R21, NEC_REG_R22, NEC_REG_R23,
			NEC_REG_R24, NEC_REG_R25, NEC_REG_R26, NEC_REG_R27, NEC_REG_R28, NEC_REG_EP, NEC_REG_LP, NEC_REG_PC};
	}

	virtual vector<uint32_t> GetAllRegisters() override
	{
		vector<uint32_t> result = {
			NEC_REG_R0, NEC_REG_R1, NEC_REG_R2, NEC_REG_SP, NEC_REG_R4, NEC_REG_R5, NEC_REG_R6, NEC_REG_R7,
			NEC_REG_R8, NEC_REG_R9, NEC_REG_R10, NEC_REG_R11, NEC_REG_R12, NEC_REG_R13, NEC_REG_R14, NEC_REG_R15,
			NEC_REG_R16, NEC_REG_R17, NEC_REG_R18, NEC_REG_R19, NEC_REG_R20, NEC_REG_R21, NEC_REG_R22, NEC_REG_R23,
			NEC_REG_R24, NEC_REG_R25, NEC_REG_R26, NEC_REG_R27, NEC_REG_R28, NEC_REG_EP, NEC_REG_LP, NEC_REG_PC
			// TODO system registers
		};

		return result;
	}

	virtual std::vector<uint32_t> GetGlobalRegisters() override
	{
		return vector<uint32_t>{NEC_REG_PC};
	}

	virtual string GetRegisterName(uint32_t regId) override
	{
		const char *result;

		if (regId >= NEC_REG_R0 && regId <= NEC_REG_PC)
			result = reg_name[regId];
		else
			result = "";

		// MYLOG("%s(%d) returns %s\n", __func__, regId, result);
		return result;
	}

	virtual BNRegisterInfo GetRegisterInfo(uint32_t regId) override
	{
		switch (regId)
		{
			// BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset,
			//   size_t size, bool zeroExtend = false)

		case NEC_REG_R0:
			return RegisterInfo(NEC_REG_R0, 0, 4);
		case NEC_REG_R1:
			return RegisterInfo(NEC_REG_R1, 0, 4);
		case NEC_REG_R2:
			return RegisterInfo(NEC_REG_R2, 0, 4);
		case NEC_REG_SP:
			return RegisterInfo(NEC_REG_SP, 0, 4);
		case NEC_REG_R4:
			return RegisterInfo(NEC_REG_R4, 0, 4);
		case NEC_REG_R5:
			return RegisterInfo(NEC_REG_R5, 0, 4);
		case NEC_REG_R6:
			return RegisterInfo(NEC_REG_R6, 0, 4);
		case NEC_REG_R7:
			return RegisterInfo(NEC_REG_R7, 0, 4);
		case NEC_REG_R8:
			return RegisterInfo(NEC_REG_R8, 0, 4);
		case NEC_REG_R9:
			return RegisterInfo(NEC_REG_R9, 0, 4);
		case NEC_REG_R10:
			return RegisterInfo(NEC_REG_R10, 0, 4);
		case NEC_REG_R11:
			return RegisterInfo(NEC_REG_R11, 0, 4);
		case NEC_REG_R12:
			return RegisterInfo(NEC_REG_R12, 0, 4);
		case NEC_REG_R13:
			return RegisterInfo(NEC_REG_R13, 0, 4);
		case NEC_REG_R14:
			return RegisterInfo(NEC_REG_R14, 0, 4);
		case NEC_REG_R15:
			return RegisterInfo(NEC_REG_R15, 0, 4);
		case NEC_REG_R16:
			return RegisterInfo(NEC_REG_R16, 0, 4);
		case NEC_REG_R17:
			return RegisterInfo(NEC_REG_R17, 0, 4);
		case NEC_REG_R18:
			return RegisterInfo(NEC_REG_R18, 0, 4);
		case NEC_REG_R19:
			return RegisterInfo(NEC_REG_R19, 0, 4);
		case NEC_REG_R20:
			return RegisterInfo(NEC_REG_R20, 0, 4);
		case NEC_REG_R21:
			return RegisterInfo(NEC_REG_R21, 0, 4);
		case NEC_REG_R22:
			return RegisterInfo(NEC_REG_R22, 0, 4);
		case NEC_REG_R23:
			return RegisterInfo(NEC_REG_R23, 0, 4);
		case NEC_REG_R24:
			return RegisterInfo(NEC_REG_R24, 0, 4);
		case NEC_REG_R25:
			return RegisterInfo(NEC_REG_R25, 0, 4);
		case NEC_REG_R26:
			return RegisterInfo(NEC_REG_R26, 0, 4);
		case NEC_REG_R27:
			return RegisterInfo(NEC_REG_R27, 0, 4);
		case NEC_REG_R28:
			return RegisterInfo(NEC_REG_R28, 0, 4);
		case NEC_REG_EP:
			return RegisterInfo(NEC_REG_EP, 0, 4);
		case NEC_REG_LP:
			return RegisterInfo(NEC_REG_LP, 0, 4);
		case NEC_REG_PC:
			return RegisterInfo(NEC_REG_PC, 0, 4);
		default:
			// LogError("%s(%d == \"%s\") invalid argument", __func__,
			//   regId, powerpc_reg_to_str(regId));
			return RegisterInfo(0, 0, 0);
		}
	}

	virtual uint32_t GetStackPointerRegister() override
	{
		return NEC_REG_SP;
	}

	virtual uint32_t GetLinkRegister() override
	{
		// MYLOG("%s()\n", __func__);
		return NEC_REG_LP;
	}
	virtual bool GetInstructionLowLevelIL(const uint8_t *data, uint64_t addr, size_t &len, LowLevelILFunction &il) override
	{
		insn_t *insn;
		if (insn = disassemble(data))
		{
			len = insn->size;
			switch (insn->insn_id)
			{
			case N850_ADD:
			{
				if (addr == 0x000d0d0c) {
					LogInfo("%s AT 0x%x: N: %d", insn->name, (uint32_t)addr,insn->n);
					LogInfo("%s OP[0] type: %d: value: %d", insn->name, insn->fields[0].type,insn->fields[0].value);
					LogInfo("%s OP[1] type: %d: value: %d", insn->name, insn->fields[1].type,insn->fields[1].value);
					LogInfo("%s OP[2] type: %d: value: %d", insn->name, insn->fields[2].type,insn->fields[2].value);
				}
				
				il.AddInstruction(
					il.SetRegister(
						4,
						insn->fields[1].value,
						il.Add(
							4,
							il.Register(
								4,
								insn->fields[1].value
							),
							il.Register(
								4,
								insn->fields[0].value
							),
							FLAG_WRITE_CYOVSZ
						)
					)
				);
			}
			break;
			case N850_ADD_IMM:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_ADDI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_AND:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_ANDI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BGE:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BGT:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BLE:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BLT:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BH:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BL:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BNH:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BNL:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BE:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BNE:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BC:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BN:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BNC:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BNV:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BNZ:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BP:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BR:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BSA:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BV:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BZ:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BSH:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_BSW:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_CALLT:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_CLR1:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_CLR1R:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_CMOV:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_CMOVI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_CMP:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_CMPI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_CTRET:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_DBRET:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_DBTRAP:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_DI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_DISPOSE:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_DISPOSER:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_DIV:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_DIVH:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_DIVHR:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_DIVHU:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_DIVU:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_EI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_HALT:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_HSW:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_JARL:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_JMP:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_JMPI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_JR:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_LDB:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_LDBU:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_LDH:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_LDHU:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_LDW:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_LDSR:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_MOV:
			{
				il.AddInstruction(
					il.SetRegister(
						4,
						insn->fields[1].value,
						il.Register(
							4,
							insn->fields[0].value
						)
					)
				);
			}
			break;
			case N850_MOVI5:
			{
				il.AddInstruction(
					il.SetRegister(
						4,
						insn->fields[1].value,
						il.SignExtend(
							4,
							il.Const(
								1,
								insn->fields[0].value
							)
						)
					)
				);
			}
			break;
			case N850_MOVI:
			{
				il.AddInstruction(
					il.SetRegister(
						4,
						insn->fields[1].value,
						il.Const(
							4,
							insn->fields[0].value
						)
					)
				);
			}
			break;
			case N850_MOVEA:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_MOVHI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_MUL:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_MULI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_MULH:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_MULHIMM:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_MULHI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_MULU:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_MULUI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_NOP:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_NOT:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_NOT1:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_NOT1R:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_OR:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_ORI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_PREPARE:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_RETI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SAR:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SARI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SASF:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SATADD:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SATADDI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SATSUB:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SATSUBI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SATSUBR:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SET1:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SET1R:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SETF:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SHL:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SHLI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SHR:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SHRI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SLDB:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SLDBU:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SLDH:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SLDHU:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SLDW:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SSTB:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SSTH:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SSTW:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_STB:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_STH:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_STW:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_STSR:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_STSRI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SUB:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SUBR:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SWITCH:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SXB:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SXH:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SYNCE:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SYNCI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SYNCM:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SYNCP:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_SYSCALL:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_TRAP:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_TST:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_TST1:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_TST1R:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_XOR:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_XORI:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_ZXB:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			case N850_ZXH:
			{
				il.AddInstruction(il.Unimplemented());
			}
			break;
			default:
				break;
			}

			free(insn);
			return true;
		}
		free(insn);
		return false;
	}

	virtual bool GetInstructionInfo(const uint8_t *data, uint64_t addr, size_t maxLen, InstructionInfo &result) override
	{
		insn_t *insn;
		if (insn = disassemble(data))
		{
			result.length = insn->size;
			uint32_t target;
			switch (insn->op_type)
			{
			case OP_TYPE_JMP:
				result.AddBranch(UnconditionalBranch, (insn->fields[0].value + (uint32_t)addr) & 0xffffffff);
				break;
			case OP_TYPE_CJMP:
				target = (insn->fields[0].value + (uint32_t)addr) & 0xffffffff;
				if (insn->fields[0].type == TYPE_JMP)
				{
					result.AddBranch(TrueBranch, target); // + (uint32_t) addr) & 0xffffffff);
					result.AddBranch(FalseBranch, (insn->size + addr) & 0xffffffff);
				}
				else
				{
					LogInfo("CJMP WENT WRONG AT 0x%x", addr);
					free(insn);
					return false;
				}
				break;
			case OP_TYPE_CALL:
				target = (insn->fields[0].value + (uint32_t)addr) & 0xffffffff;
				if (target != ((uint32_t)addr + insn->size))
					result.AddBranch(CallDestination, target); // + (uint32_t) addr) & 0xffffffff);
				break;
			case OP_TYPE_RCALL:
				result.AddBranch(IndirectBranch);
				break;
			case OP_TYPE_RJMP:
				result.AddBranch(IndirectBranch);
				break;
			case OP_TYPE_RET:
				result.AddBranch(FunctionReturn);
				break;
			case OP_TYPE_TRAP:
				result.AddBranch(FunctionReturn);
				break;
			default:
				break;
			}
			free(insn);
			return true;
		}
		free(insn);
		return false;
	}

	virtual bool GetInstructionText(const uint8_t *data, uint64_t addr, size_t &len, std::vector<InstructionTextToken> &result) override
	{
		insn_t *insn;
		char tmp[256] = {0};
		if (insn = disassemble(data))
		{

			int name_len = strlen(insn->name);
			for (int i = name_len; i < 8; i++)
			{
				tmp[i - name_len] = ' ';
			}
			len = insn->size;
			tmp[8 - name_len] = 0;
			result.emplace_back(InstructionToken, insn->name);
			result.emplace_back(TextToken, tmp);
			char hex_val[20] = {0};
			char reg_str[10] = {0};
			for (int op_index = 0; op_index < insn->n; op_index++)
			{
				switch (insn->fields[op_index].type)
				{
				case TYPE_REG:
					// sprintf(reg_str, "r%d", (uint32_t)insn->fields[op_index].value);
					result.emplace_back(RegisterToken, reg_name[insn->fields[op_index].value]);
					break;
				case TYPE_MEM: // TODO
				case TYPE_IMM:
					sprintf(hex_val, "%s0x%x", ((int32_t)insn->fields[op_index].value < 0) ? "-" : "", ((int32_t)insn->fields[op_index].value < 0) ? -(int32_t)insn->fields[op_index].value : (int32_t)insn->fields[op_index].value);
					result.emplace_back(IntegerToken, hex_val, insn->fields[op_index].value);
					break;
				case TYPE_JMP:
					sprintf(hex_val, "0x%x", (uint32_t)(insn->fields[op_index].value)); // + (uint32_t) addr));
					result.emplace_back(IntegerToken, hex_val, insn->fields[op_index].value);
					break;
				case TYPE_CR:
					sprintf(reg_str, "cr%d", (uint32_t)insn->fields[op_index].value);
					result.emplace_back(RegisterToken, reg_str);
					break;
				default:
					break;
				}
				result.emplace_back(OperandSeparatorToken, ", ");
			}
			result.pop_back();
			free(insn);
			return true;
		}
		free(insn);
		return false;
	}
};

class Nec850CallingConvention : public CallingConvention
{
public:
	Nec850CallingConvention(Architecture *arch) : CallingConvention(arch, "default")
	{
	}

	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{
			NEC_REG_R6, NEC_REG_R7, NEC_REG_R8, NEC_REG_R9};
	}

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return NEC_REG_R10;
	}

	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{
			NEC_REG_R10, NEC_REG_R11, NEC_REG_R12, NEC_REG_R13, NEC_REG_R14, NEC_REG_R15, NEC_REG_R16, NEC_REG_R17, NEC_REG_R18, NEC_REG_R19};
	}

	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t>{
			NEC_REG_R25, NEC_REG_R25, NEC_REG_R27, NEC_REG_R28, NEC_REG_EP, NEC_REG_LP};
	}
};
extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
		AddOptionalPluginDependency("view_elf");
		AddOptionalPluginDependency("view_macho");
		AddOptionalPluginDependency("view_pe");
	}

	BINARYNINJAPLUGIN bool CorePluginInit()
	{

		/* create, register arch in global list of available architectures */
		Architecture *nec850 = new NEC850("nec850");
		Architecture::Register(nec850);
		Ref<CallingConvention> conv;
		conv = new Nec850CallingConvention(nec850);
		nec850->RegisterCallingConvention(conv);
		nec850->SetDefaultCallingConvention(conv);

#define EM_NEC850 87
		BinaryViewType::RegisterArchitecture(
			"ELF",
			EM_NEC850,
			LittleEndian,
			nec850);
#define EM_NECV850 36
		BinaryViewType::RegisterArchitecture(
			"ELF",
			EM_NECV850,
			LittleEndian,
			nec850);

		return true;
	}
}
/*
extern "C"
{
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit()
	{
		PluginCommand::Register("Test Plugin\\Test", "It's a test action!", [](BinaryView* view) {
			for (auto& symbol: view->GetSymbols())
			{
				LogInfo("%s", symbol->GetFullName().c_str());
			}
		});
		return true;
	}

	BINARYNINJAPLUGIN void CorePluginDependencies()
	{
	}
}
*/
