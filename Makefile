BINDIR := bin
OBJDIR := obj
SRCDIR := src

DEPDIR := $(OBJDIR)/.deps
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.d

CXXFLAGS += -std=c++17 -Wall -Wextra -pedantic
COMPILE.cc = $(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c

all : $(BINDIR)/asmscript
$(OBJDIR)/%.o : $(SRCDIR)/%.cpp $(DEPDIR)/%.d | $(DEPDIR)
	$(COMPILE.cc) $(OUTPUT_OPTION) $<

$(BINDIR): ; @mkdir -p $@
$(DEPDIR): ; @mkdir -p $@

SRC = $(wildcard $(SRCDIR)/*.cpp)
$(BINDIR)/asmscript : $(SRC:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o) | $(BINDIR)
	g++ $(CXXFLAGS) -o $@ $^

DEPFILES := $(SRC:$(SRCDIR)/%.cpp=$(DEPDIR)/%.d)
$(DEPFILES):
include $(wildcard $(DEPFILES))
