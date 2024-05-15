
#include "nec850.h"
#include "binaryninjaapi.h"
#include <vector>
#include "disass.h"

using namespace BinaryNinja;

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
			return 6;
		}

		virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override
		{

			return false;
		}

		virtual bool GetInstructionText (const uint8_t *data, uint64_t addr, size_t &len, std::vector< InstructionTextToken > &result) override
		{
			return false;
		}

};

BINARYNINJAPLUGIN bool CorePluginInit()
	{

		/* create, register arch in global list of available architectures */
		Architecture* nec850 = new NEC850("nec850");
		Architecture::Register(nec850);
		/*
		Ref<CallingConvention> conv;
		conv = new PpcSvr4CallingConvention(ppc);
		ppc->RegisterCallingConvention(conv);
		ppc->SetDefaultCallingConvention(conv);
		ppc64->RegisterCallingConvention(conv);
		ppc64->SetDefaultCallingConvention(conv);
		conv = new PpcLinuxSyscallCallingConvention(ppc);
		ppc->RegisterCallingConvention(conv);
		ppc64->RegisterCallingConvention(conv);

		conv = new PpcSvr4CallingConvention(ppc_le);
		ppc_le->RegisterCallingConvention(conv);
		ppc_le->SetDefaultCallingConvention(conv);
		ppc64_le->RegisterCallingConvention(conv);
		ppc64_le->SetDefaultCallingConvention(conv);
		conv = new PpcLinuxSyscallCallingConvention(ppc_le);
		ppc_le->RegisterCallingConvention(conv);
		ppc64_le->RegisterCallingConvention(conv);

		
		ppc->RegisterFunctionRecognizer(new PpcImportedFunctionRecognizer());
		ppc_le->RegisterFunctionRecognizer(new PpcImportedFunctionRecognizer());

		ppc->RegisterRelocationHandler("ELF", new PpcElfRelocationHandler());
		ppc_le->RegisterRelocationHandler("ELF", new PpcElfRelocationHandler());
		ppc_le->RegisterRelocationHandler("Mach-O", new PpcMachoRelocationHandler());
		*/
		
		

		#define EM_V850		87 
		BinaryViewType::RegisterArchitecture(
			"ELF", 
			EM_V850, 
			LittleEndian,
			nec850 
		);

		return true;
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
