
#include "nec850.h"
#include "binaryninjaapi.h"
#include <vector>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "disass.h"

using namespace BinaryNinja;
using namespace std;

static const char* reg_name[] = {
	"r0",
	"r1",
	"r2",
	"sp",
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
	"r26",
	"r27",
	"r28",
	"r29",
	"ep",
	"lp",
	"pc"
};

class NEC850: public Architecture
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
		NEC850(const char* name): Architecture(name)
		{
		}

		/*************************************************************************/

		virtual BNEndianness GetEndianness() const override
		{
			//MYLOG("%s()\n", __func__);
			return LittleEndian;
		}

		virtual size_t GetAddressSize() const override
		{
			//MYLOG("%s()\n", __func__);
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
			return vector<uint32_t> {
				FLAG_SAT,
				FLAG_CY,
				FLAG_OV,
				FLAG_S,
				FLAG_Z
			};
		}

		virtual string GetFlagName(uint32_t flag) override
		{
			switch(flag) { // TODO more verbose? will it help?
				case FLAG_SAT: return "sat";
				case FLAG_CY: return "cy";
				case FLAG_OV: return "ov";
				case FLAG_S: return "s";
				case FLAG_Z: return "z";
				default: return "ERR_FLAG_NAME";
			}
		}

		virtual vector<uint32_t> GetAllFlagWriteTypes() override
		{
			return vector<uint32_t> {
				FLAG_WRITE_NONE,
				FLAG_WRITE_ALL,
				FLAG_WRITE_OVSZ
			};
		}

		virtual string GetFlagWriteTypeName(uint32_t writeType) override
		{
			switch (writeType)
			{
				case FLAG_WRITE_OVSZ:
					return "ovsz";
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
					return vector<uint32_t> {
						FLAG_Z, FLAG_OV, FLAG_S
					};
				case FLAG_WRITE_ALL:
					return vector<uint32_t> {
						FLAG_CY,FLAG_Z, FLAG_OV, FLAG_S
					};
				default:
					return vector<uint32_t>();
			}
		}

		virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass) override
		{
			bool signedClass = true;

			switch (flag)
			{
				case FLAG_SAT: return SpecialFlagRole;
				case FLAG_CY: return CarryFlagRole;
				case FLAG_Z: return ZeroFlagRole;
				case FLAG_OV: return OverflowFlagRole;
				case FLAG_S: return NegativeSignFlagRole;
				default: return SpecialFlagRole;
			}
		}

		virtual vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t) override
		{

			switch (cond)
			{
				case LLFC_E: /* equal */
				case LLFC_NE: /* not equal */
					return vector<uint32_t>{ FLAG_Z };

				case LLFC_ULT: /* (unsigned) less than == LT */
				case LLFC_UGE: /* (unsigned) greater-or-equal == !LT */
					return vector<uint32_t>{ FLAG_CY };
				
				case LLFC_UGT: /* (unsigned) greater-than == GT */
				case LLFC_ULE: /* (unsigned) less-or-equal == !GT */
					return vector<uint32_t>{ FLAG_CY, FLAG_Z };
				
				case LLFC_SLT: /* (signed) less than == LT */
				case LLFC_SGE: /* (signed) greater-or-equal == !LT */
					return vector<uint32_t>{ FLAG_S, FLAG_OV };
				
				case LLFC_SGT: /* (signed) greater-than == GT */
				case LLFC_SLE: /* (signed) lesser-or-equal == !GT */
					return vector<uint32_t>{ FLAG_S, FLAG_OV, FLAG_Z };

				case LLFC_NEG:
				case LLFC_POS:
					return vector<uint32_t>{ FLAG_S };

				case LLFC_O:
				case LLFC_NO:
					return vector<uint32_t>{
						FLAG_OV
					};

				default:
					return vector<uint32_t>();
			}
		}


		virtual vector<uint32_t> GetFullWidthRegisters() override
		{

			return vector<uint32_t>{
				NEC_REG_R0,   NEC_REG_R1,   NEC_REG_R2,   NEC_REG_SP,   NEC_REG_R4,   NEC_REG_R5,   NEC_REG_R6,   NEC_REG_R7,
				NEC_REG_R8,   NEC_REG_R9,   NEC_REG_R10,  NEC_REG_R11,  NEC_REG_R12,  NEC_REG_R13,  NEC_REG_R14,  NEC_REG_R15,
				NEC_REG_R16,  NEC_REG_R17,  NEC_REG_R18,  NEC_REG_R19,  NEC_REG_R20,  NEC_REG_R21,  NEC_REG_R22,  NEC_REG_R23,
				NEC_REG_R24,  NEC_REG_R25,  NEC_REG_R26,  NEC_REG_R27,  NEC_REG_R28,  NEC_REG_EP,  NEC_REG_LP,  NEC_REG_PC
			};
		}

		virtual vector<uint32_t> GetAllRegisters() override
		{
			vector<uint32_t> result = {
					NEC_REG_R0,   NEC_REG_R1,   NEC_REG_R2,   NEC_REG_SP,   NEC_REG_R4,   NEC_REG_R5,   NEC_REG_R6,   NEC_REG_R7,
					NEC_REG_R8,   NEC_REG_R9,   NEC_REG_R10,  NEC_REG_R11,  NEC_REG_R12,  NEC_REG_R13,  NEC_REG_R14,  NEC_REG_R15,
					NEC_REG_R16,  NEC_REG_R17,  NEC_REG_R18,  NEC_REG_R19,  NEC_REG_R20,  NEC_REG_R21,  NEC_REG_R22,  NEC_REG_R23,
					NEC_REG_R24,  NEC_REG_R25,  NEC_REG_R26,  NEC_REG_R27,  NEC_REG_R28,  NEC_REG_EP,  NEC_REG_LP,  NEC_REG_PC
					// TODO system registers
				};

			return result;
		}

		virtual std::vector<uint32_t> GetGlobalRegisters() override
		{
			return vector<uint32_t>{ NEC_REG_PC };
		}

		virtual string GetRegisterName(uint32_t regId) override
		{
			const char *result = reg_name[regId];

			if(regId >= NEC_REG_R0 && regId <= NEC_REG_PC)
				result = "";

			//MYLOG("%s(%d) returns %s\n", __func__, regId, result);
			return result;
		}

		virtual BNRegisterInfo GetRegisterInfo(uint32_t regId) override
		{
			switch(regId) {
				// BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset,
				//   size_t size, bool zeroExtend = false)

				case NEC_REG_R0: return RegisterInfo(NEC_REG_R0, 0, 4);
				case NEC_REG_R1: return RegisterInfo(NEC_REG_R1, 0, 4);
				case NEC_REG_R2: return RegisterInfo(NEC_REG_R2, 0, 4);
				case NEC_REG_SP: return RegisterInfo(NEC_REG_SP, 0, 4);
				case NEC_REG_R4: return RegisterInfo(NEC_REG_R4, 0, 4);
				case NEC_REG_R5: return RegisterInfo(NEC_REG_R5, 0, 4);
				case NEC_REG_R6: return RegisterInfo(NEC_REG_R6, 0, 4);
				case NEC_REG_R7: return RegisterInfo(NEC_REG_R7, 0, 4);
				case NEC_REG_R8: return RegisterInfo(NEC_REG_R8, 0, 4);
				case NEC_REG_R9: return RegisterInfo(NEC_REG_R9, 0, 4);
				case NEC_REG_R10: return RegisterInfo(NEC_REG_R10, 0, 4);
				case NEC_REG_R11: return RegisterInfo(NEC_REG_R11, 0, 4);
				case NEC_REG_R12: return RegisterInfo(NEC_REG_R12, 0, 4);
				case NEC_REG_R13: return RegisterInfo(NEC_REG_R13, 0, 4);
				case NEC_REG_R14: return RegisterInfo(NEC_REG_R14, 0, 4);
				case NEC_REG_R15: return RegisterInfo(NEC_REG_R15, 0, 4);
				case NEC_REG_R16: return RegisterInfo(NEC_REG_R16, 0, 4);
				case NEC_REG_R17: return RegisterInfo(NEC_REG_R17, 0, 4);
				case NEC_REG_R18: return RegisterInfo(NEC_REG_R18, 0, 4);
				case NEC_REG_R19: return RegisterInfo(NEC_REG_R19, 0, 4);
				case NEC_REG_R20: return RegisterInfo(NEC_REG_R20, 0, 4);
				case NEC_REG_R21: return RegisterInfo(NEC_REG_R21, 0, 4);
				case NEC_REG_R22: return RegisterInfo(NEC_REG_R22, 0, 4);
				case NEC_REG_R23: return RegisterInfo(NEC_REG_R23, 0, 4);
				case NEC_REG_R24: return RegisterInfo(NEC_REG_R24, 0, 4);
				case NEC_REG_R25: return RegisterInfo(NEC_REG_R25, 0, 4);
				case NEC_REG_R26: return RegisterInfo(NEC_REG_R26, 0, 4);
				case NEC_REG_R27: return RegisterInfo(NEC_REG_R27, 0, 4);
				case NEC_REG_R28: return RegisterInfo(NEC_REG_R28, 0, 4);
				case NEC_REG_EP: return RegisterInfo(NEC_REG_EP, 0, 4);
				case NEC_REG_LP: return RegisterInfo(NEC_REG_LP, 0, 4);
				case NEC_REG_PC: return RegisterInfo(NEC_REG_PC, 0, 4);
				default:
					//LogError("%s(%d == \"%s\") invalid argument", __func__,
					//  regId, powerpc_reg_to_str(regId));
					return RegisterInfo(0,0,0);
			}
		}

		virtual uint32_t GetStackPointerRegister() override
		{
			return NEC_REG_SP;
		}

		virtual uint32_t GetLinkRegister() override
		{
			//MYLOG("%s()\n", __func__);
			return NEC_REG_LP;
		}
		virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
		{	
			insn_t* insn;
			if (insn = disassemble(data)) {
				len = insn->size;
				il.AddInstruction(il.Unimplemented());
				free(insn);
				return true;
			}
			free(insn);
			return false;
		}


		virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override
		{
			insn_t* insn;
			if (insn = disassemble(data)) {
				result.length = insn->size;
				uint32_t target;
				switch(insn->op_type) {
					case OP_TYPE_JMP:
                        result.AddBranch(UnconditionalBranch,(insn->fields[0].value + (uint32_t) addr) & 0xffffffff);
                        break;
					case OP_TYPE_CJMP:
						target = (insn->fields[0].value + (uint32_t) addr) & 0xffffffff;
                        if (insn->fields[0].type == TYPE_JMP) {
                            result.AddBranch(TrueBranch, target);// + (uint32_t) addr) & 0xffffffff);
                            result.AddBranch(FalseBranch,(insn->size + addr) & 0xffffffff);
                        } else {
							LogInfo("CJMP WENT WRONG AT 0x%x",addr);
                            return false;
                        }
                        break;
					case OP_TYPE_CALL:
                        target = (insn->fields[0].value + (uint32_t) addr) & 0xffffffff;
                        if (target != ((uint32_t) addr + insn->size)) 
                            result.AddBranch(CallDestination,target);// + (uint32_t) addr) & 0xffffffff);
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

		virtual bool GetInstructionText (const uint8_t *data, uint64_t addr, size_t &len, std::vector< InstructionTextToken > &result) override
		{
			insn_t* insn;
			char tmp[256] = {0};
			if (insn = disassemble(data)) {
				
				int name_len = strlen(insn->name);
                for (int i = name_len; i < 8; i++) {
                    tmp[i - name_len] = ' ';
                }
				len = insn->size;
                tmp[8 - name_len] = 0;
                result.emplace_back(InstructionToken, insn->name);
                result.emplace_back(TextToken, tmp);
				char hex_val[20] = {0};
                char reg_str[10] = {0};
				for (int op_index = 0; op_index < insn->n; op_index++) {
                    switch(insn->fields[op_index].type) {
                        case TYPE_REG:
                            //sprintf(reg_str, "r%d", (uint32_t)insn->fields[op_index].value);
                            result.emplace_back(RegisterToken, reg_name[insn->fields[op_index].value]);
                            break;
                        case TYPE_MEM: // TODO
						case TYPE_IMM:
                            sprintf(hex_val, "%s0x%x", ((int32_t)insn->fields[op_index].value<0) ? "-" : "",((int32_t)insn->fields[op_index].value<0) ?-(int32_t)insn->fields[op_index].value : (int32_t)insn->fields[op_index].value); 
                            result.emplace_back(IntegerToken, hex_val, insn->fields[op_index].value);
                            break;
                        case TYPE_JMP:
                            sprintf(hex_val, "0x%x", (uint32_t)(insn->fields[op_index].value));// + (uint32_t) addr)); 
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

class Nec850CallingConvention: public CallingConvention
{
	public:
		Nec850CallingConvention(Architecture* arch): CallingConvention(arch, "default")
		{
		}

		virtual vector<uint32_t> GetIntegerArgumentRegisters() override
		{
			return vector<uint32_t>{
				NEC_REG_R6, NEC_REG_R7, NEC_REG_R8, NEC_REG_R9
			};
		}

		virtual uint32_t GetIntegerReturnValueRegister() override
		{
			return NEC_REG_R10;
		}

		virtual vector<uint32_t> GetCallerSavedRegisters() override
		{
			return vector<uint32_t>{
				NEC_REG_R10, NEC_REG_R11, NEC_REG_R12, NEC_REG_R13, NEC_REG_R14, NEC_REG_R15, NEC_REG_R16, NEC_REG_R17, NEC_REG_R18, NEC_REG_R19
			};
		}

		virtual vector<uint32_t> GetCalleeSavedRegisters() override
		{
			return vector<uint32_t>{
				NEC_REG_R25, NEC_REG_R25, NEC_REG_R27, NEC_REG_R28, NEC_REG_EP, NEC_REG_LP
			};
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
			Architecture* nec850 = new NEC850("nec850");
			Architecture::Register(nec850);
			Ref<CallingConvention> conv;
			conv = new Nec850CallingConvention(nec850);
			nec850->RegisterCallingConvention(conv);
			nec850->SetDefaultCallingConvention(conv);

			#define EM_NEC850		87
			BinaryViewType::RegisterArchitecture(
				"ELF", 
				EM_NEC850, 
				LittleEndian,
				nec850 
			);
			#define EM_NECV850		36
			BinaryViewType::RegisterArchitecture(
				"ELF", 
				EM_NECV850, 
				LittleEndian,
				nec850 
			);

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
