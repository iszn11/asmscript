#include "Common.h"
#include "Lexer.h"
#include "Parser.h"
#include "Compiler.h"

#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>

#include <errno.h>
#include <sys/mman.h>

static int RunFile(const char* filepath);
static void PrintLexResults(std::string_view filePrefix, const std::vector<std::unique_ptr<Token>>& tokens);
static void PrintParseResults(std::string_view filePrefix, const std::unordered_map<std::string, std::vector<std::unique_ptr<Statement>>>& procedures);
static void PrintCompileResults(const std::basic_string<unsigned char>& machineCode, size_t entry);
static void ExecuteCompileResults(const std::basic_string<unsigned char>& machineCode, size_t entry);
static void PrintStatements(std::string_view filePrefix, const std::vector<std::unique_ptr<Statement>>& statements, size_t level = 0);
static void PrintRegister(Register reg);
static void PrintOperation(Operation op);
static void PrintCondition(const Condition& condition);
static void PrintOperand(const Operand& operand);

int main(int argc, char* argv[])
{
	if (argc == 2)
	{
		return RunFile(argv[1]);
	}
	else
	{
		std::cerr << "Usage: " << argv[0] << " [FILE]\n"
			<< "Expected 1 arguments, got " << (argc - 1) << '\n';
		return 1;
	}
}

static int RunFile(const char* const filepath)
{
	std::string code;
	if (!ReadFile(filepath, code))
	{
		std::cerr << "Couldn't read file " << filepath << '\n';
		return 1;
	}

	std::vector<std::unique_ptr<Token>> tokens;
	Error error = Lex(code.c_str(), tokens);
	if (error)
	{
		std::cerr << filepath << ":" << error.pos.line << ":" << error.pos.col << ": Lexer error: " << error.message << '\n';
		return 1;
	}

	PrintLexResults(filepath, tokens);

	std::unordered_map<std::string, std::vector<std::unique_ptr<Statement>>> procedures;
	error = Parse(tokens, procedures);
	if (error)
	{
		std::cerr << filepath << ":" << error.pos.line << ":" << error.pos.col << ": Parser error: " << error.message << '\n';
		return 1;
	}

	PrintParseResults(filepath, procedures);

	std::basic_string<unsigned char> machineCode;
	size_t entry;
	error = Compile(procedures, machineCode, entry);
	if (error)
	{
		std::cerr << filepath << ":" << error.pos.line << ":" << error.pos.col << ": Compiler error: " << error.message << '\n';
		return 1;
	}

	PrintCompileResults(machineCode, entry);
	ExecuteCompileResults(machineCode, entry);

	return 0;
}

static void PrintLexResults(const std::string_view filePrefix, const std::vector<std::unique_ptr<Token>>& tokens)
{
	for (const auto& token : tokens)
	{
		std::cout << filePrefix << ':' << token->pos.line << ':' << token->pos.col << ": ";

		switch (token->tag)
		{
			case TokenTag::RegRax: std::cout << "RegRax"; break;
			case TokenTag::RegRbx: std::cout << "RegRbx"; break;
			case TokenTag::RegRcx: std::cout << "RegRcx"; break;
			case TokenTag::RegRdx: std::cout << "RegRdx"; break;
			case TokenTag::RegRsi: std::cout << "RegRsi"; break;
			case TokenTag::RegRdi: std::cout << "RegRdi"; break;
			case TokenTag::RegRbp: std::cout << "RegRbp"; break;
			case TokenTag::RegR8: std::cout << "RegR8"; break;
			case TokenTag::RegR9: std::cout << "RegR9"; break;
			case TokenTag::RegR10: std::cout << "RegR10"; break;
			case TokenTag::RegR11: std::cout << "RegR11"; break;
			case TokenTag::RegR12: std::cout << "RegR12"; break;
			case TokenTag::RegR13: std::cout << "RegR13"; break;
			case TokenTag::RegR14: std::cout << "RegR14"; break;
			case TokenTag::RegR15: std::cout << "RegR15"; break;
			case TokenTag::RegXmm0: std::cout << "RegXmm0"; break;
			case TokenTag::RegXmm1: std::cout << "RegXmm1"; break;
			case TokenTag::RegXmm2: std::cout << "RegXmm2"; break;
			case TokenTag::RegXmm3: std::cout << "RegXmm3"; break;
			case TokenTag::RegXmm4: std::cout << "RegXmm4"; break;
			case TokenTag::RegXmm5: std::cout << "RegXmm5"; break;
			case TokenTag::RegXmm6: std::cout << "RegXmm6"; break;
			case TokenTag::RegXmm7: std::cout << "RegXmm7"; break;
			case TokenTag::RegXmm8: std::cout << "RegXmm8"; break;
			case TokenTag::RegXmm9: std::cout << "RegXmm9"; break;
			case TokenTag::RegXmm10: std::cout << "RegXmm10"; break;
			case TokenTag::RegXmm11: std::cout << "RegXmm11"; break;
			case TokenTag::RegXmm12: std::cout << "RegXmm12"; break;
			case TokenTag::RegXmm13: std::cout << "RegXmm13"; break;
			case TokenTag::RegXmm14: std::cout << "RegXmm14"; break;
			case TokenTag::RegXmm15: std::cout << "RegXmm15"; break;
			case TokenTag::KeyBranch: std::cout << "KeyBranch"; break;
			case TokenTag::KeyBreak: std::cout << "KeyBreak"; break;
			case TokenTag::KeyContinue: std::cout << "KeyContinue"; break;
			case TokenTag::KeyElse: std::cout << "KeyElse"; break;
			case TokenTag::KeyIf: std::cout << "KeyIf"; break;
			case TokenTag::KeyLoop: std::cout << "KeyLoop"; break;
			case TokenTag::KeyMacro: std::cout << "KeyMacro"; break;
			case TokenTag::KeyPop: std::cout << "KeyPop"; break;
			case TokenTag::KeyProc: std::cout << "KeyProc"; break;
			case TokenTag::KeyPush: std::cout << "KeyPush"; break;
			case TokenTag::KeyReturn: std::cout << "KeyReturn"; break;
			case TokenTag::KeyVal: std::cout << "KeyVal"; break;
			case TokenTag::KeyVar: std::cout << "KeyVar"; break;
			case TokenTag::BracketOpen: std::cout << "BracketOpen"; break;
			case TokenTag::BracketClose: std::cout << "BracketClose"; break;
			case TokenTag::ParenOpen: std::cout << "ParenOpen"; break;
			case TokenTag::ParenClose: std::cout << "ParenClose"; break;
			case TokenTag::BraceOpen: std::cout << "BraceOpen"; break;
			case TokenTag::BraceClose: std::cout << "BraceClose"; break;
			case TokenTag::Plus: std::cout << "Plus"; break;
			case TokenTag::Minus: std::cout << "Minus"; break;
			case TokenTag::Star: std::cout << "Star"; break;
			case TokenTag::Slash: std::cout << "Slash"; break;
			case TokenTag::Percent: std::cout << "Percent"; break;
			case TokenTag::PlusEquals: std::cout << "PlusEquals"; break;
			case TokenTag::MinusEquals: std::cout << "MinusEquals"; break;
			case TokenTag::StarEquals: std::cout << "StarEquals"; break;
			case TokenTag::SlashEquals: std::cout << "SlashEquals"; break;
			case TokenTag::PercentEquals: std::cout << "PercentEquals"; break;
			case TokenTag::Equals: std::cout << "Equals"; break;
			case TokenTag::LessThan: std::cout << "LessThan"; break;
			case TokenTag::GreaterThan: std::cout << "GreaterThan"; break;
			case TokenTag::LessEquals: std::cout << "LessEquals"; break;
			case TokenTag::GreaterEquals: std::cout << "GreaterEquals"; break;
			case TokenTag::EqualsEquals: std::cout << "EqualsEquals"; break;
			case TokenTag::NotEquals: std::cout << "NotEquals"; break;
			case TokenTag::Hash: std::cout << "Hash"; break;
			case TokenTag::Shl: std::cout << "Shl"; break;
			case TokenTag::Shr: std::cout << "Shr"; break;
			case TokenTag::Comma: std::cout << "Comma"; break;
			case TokenTag::Semicolon: std::cout << "Semicolon"; break;
			case TokenTag::Number: std::cout << "Number " << static_cast<NumberToken*>(token.get())->value; break;
			case TokenTag::Identifier: std::cout << "Identifier " << static_cast<IdentifierToken*>(token.get())->name; break;
			case TokenTag::String: std::cout << "String " << static_cast<StringToken*>(token.get())->value; break;
			case TokenTag::Eof: std::cout << "EOF"; break;
		}

		std::cout << '\n';
	}
}

static void PrintParseResults(const std::string_view filePrefix, const std::unordered_map<std::string, std::vector<std::unique_ptr<Statement>>>& procedures)
{
	for (const auto& [name, statements] : procedures)
	{
		std::cout << "PROCEDURE " << name << "\n\n";

		PrintStatements(filePrefix, statements);

		std::cout << '\n';
	}
}

static void PrintCompileResults(const std::basic_string<unsigned char>& machineCode, const size_t entry)
{
	std::cout << "Entry at " << entry << '\n';

	std::cout << std::hex << std::setfill('0') << std::setw(2);
	for (const auto c : machineCode)
	{
		std::cout << static_cast<int>(c) << " ";
	}
	std::cout.copyfmt(std::ios(NULL));

	std::cout << '\n';
}

static void ExecuteCompileResults(const std::basic_string<unsigned char>& machineCode, size_t entry)
{
	const size_t len = machineCode.length();
	void* mem = mmap(NULL, len, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED)
	{
		std::cerr << "Mapping memory failed with errno " << errno << '\n';
		return;
	}
	memcpy(mem, machineCode.data(), len);
	mprotect(mem, len, PROT_EXEC);

	char* entryPtr = static_cast<char*>(mem) + entry;
	int64_t (*main)(int64_t a, int64_t b);
	memcpy(&main, &entryPtr, 8);
	const int64_t res = main(4, 7);

	std::cout << "Res: " << res << '\n';

	munmap(mem, len);
}

static void PrintStatements(const std::string_view filePrefix, const std::vector<std::unique_ptr<Statement>>& statements, const size_t level)
{
	for (const auto& statement : statements)
	{
		for (size_t i = 0; i < level; ++i) std::cout << '\t';

		switch (statement->tag)
		{
		case StatementTag::Assignment:
		{
			auto stmt = static_cast<AssignmentStatement*>(statement.get());
			std::cout << "Assignment ";
			PrintRegister(stmt->dest);
			std::cout << " = ";
			PrintOperand(*stmt->source);
			if (stmt->condition.has_value())
			{
				std::cout << " if ";
				PrintCondition(*stmt->condition);
			}
			break;
		}
		case StatementTag::Shorthand:
		{
			auto stmt = static_cast<ShorthandStatement*>(statement.get());
			std::cout << "Shorthand ";
			PrintRegister(stmt->dest);
			std::cout << ' ';
			PrintOperation(stmt->op);
			std::cout << "= ";
			PrintOperand(*stmt->source);
			if (stmt->condition.has_value())
			{
				std::cout << " if ";
				PrintCondition(*stmt->condition);
			}
			break;
		}
		case StatementTag::Longhand:
		{
			auto stmt = static_cast<LonghandStatement*>(statement.get());
			std::cout << "Longhand ";
			PrintRegister(stmt->dest);
			std::cout << " = ";
			PrintOperand(*stmt->sourceA);
			std::cout << ' ';
			PrintOperation(stmt->op);
			std::cout << ' ';
			PrintOperand(*stmt->sourceB);
			if (stmt->condition.has_value())
			{
				std::cout << " if ";
				PrintCondition(*stmt->condition);
			}
			break;
		}
		case StatementTag::Loop:
		{
			auto stmt = static_cast<LoopStatement*>(statement.get());
			std::cout << "Loop";
			if (stmt->condition.has_value())
			{
				std::cout << " (";
				PrintCondition(*stmt->condition);
				std::cout << ")";
			}
			std::cout << '\n';
			PrintStatements(filePrefix, stmt->statements, level + 1);
			continue;
		}
		case StatementTag::Branch:
		{
			auto stmt = static_cast<BranchStatement*>(statement.get());
			std::cout << "Branch (";
			PrintCondition(*stmt->condition);
			std::cout << ")\n";
			PrintStatements(filePrefix, stmt->statements, level + 1);
			std::cout << "Else\n";
			PrintStatements(filePrefix, stmt->elseBlock, level + 1);
			continue;
		}
		case StatementTag::Break:
		{
			std::cout << "Break";
			if (statement->condition.has_value())
			{
				std::cout << " if ";
				PrintCondition(*statement->condition);
			}
			break;
		}
		case StatementTag::Continue:
		{
			std::cout << "Continue";
			if (statement->condition.has_value())
			{
				std::cout << " if ";
				PrintCondition(*statement->condition);
			}
			break;
		}
		case StatementTag::Return:
		{
			std::cout << "Return";
			if (statement->condition.has_value())
			{
				std::cout << " if ";
				PrintCondition(*statement->condition);
			}
			break;
		}
		case StatementTag::Call:
		{
			auto stmt = static_cast<CallStatement*>(statement.get());
			std::cout << "Call " << stmt->name;
			if (stmt->condition.has_value())
			{
				std::cout << " if ";
				PrintCondition(*stmt->condition);
			}
			break;
		}
		case StatementTag::Stdout:
		{
			auto stmt = static_cast<StdoutStatement*>(statement.get());
			std::cout << "Stdout ";
			PrintOperand(*stmt->source);
			if (stmt->condition.has_value())
			{
				std::cout << " if ";
				PrintCondition(*stmt->condition);
			}
			break;
		}
		}
		std::cout << '\n';
	}
}

static void PrintRegister(const Register reg)
{
	switch (reg)
	{
		case Register::rax: std::cout << "rax"; break;
		case Register::rbx: std::cout << "rbx"; break;
		case Register::rcx: std::cout << "rcx"; break;
		case Register::rdx: std::cout << "rdx"; break;
		case Register::rsi: std::cout << "rsi"; break;
		case Register::rdi: std::cout << "rdi"; break;
		case Register::rbp: std::cout << "rbp"; break;
		case Register::r8: std::cout << "r8"; break;
		case Register::r9: std::cout << "r9"; break;
		case Register::r10: std::cout << "r10"; break;
		case Register::r11: std::cout << "r11"; break;
		case Register::r12: std::cout << "r12"; break;
		case Register::r13: std::cout << "r13"; break;
		case Register::r14: std::cout << "r14"; break;
		case Register::r15: std::cout << "r15"; break;
	}
}

static void PrintOperation(const Operation op)
{
	switch (op)
	{
		case Operation::Add: std::cout << '+'; break;
		case Operation::Sub: std::cout << '-'; break;
		case Operation::Mul: std::cout << '*'; break;
		case Operation::Div: std::cout << '/'; break;
		case Operation::Mod: std::cout << '%'; break;
	}
}

static void PrintCondition(const Condition& condition)
{
	PrintOperand(*condition.a);
	switch (condition.comp)
	{
		case Comparison::LessThan: std::cout << " < "; break;
		case Comparison::LessEquals: std::cout << " <= "; break;
		case Comparison::GreaterThan: std::cout << " > "; break;
		case Comparison::GreaterEquals: std::cout << " >= "; break;
		case Comparison::Equals: std::cout << " == "; break;
		case Comparison::NotEquals: std::cout << " != "; break;
	}
	PrintOperand(*condition.b);
}

static void PrintOperand(const Operand& operand)
{
	switch (operand.tag)
	{
		case OperandTag::Register: PrintRegister(static_cast<const RegisterOperand&>(operand).reg); break;
		case OperandTag::Immediate: std::cout << static_cast<const ImmediateOperand&>(operand).value; break;
	}
}
