#include "Common.h"
#include "Lexer.h"

#include <cstdio>
#include <iostream>

static int RunFile(const char* filepath);
static void PrintLexResults(std::string_view filePrefix, const std::vector<std::unique_ptr<Token>>& tokens);

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
			case TokenTag::KeyFn: std::cout << "KeyFn"; break;
			case TokenTag::KeyIf: std::cout << "KeyIf"; break;
			case TokenTag::KeyLoop: std::cout << "KeyLoop"; break;
			case TokenTag::KeyMacro: std::cout << "KeyMacro"; break;
			case TokenTag::KeyPop: std::cout << "KeyPop"; break;
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
