
CC=clang
CFLAGS=-c -Wall -fPIC

BuildDir=build
SrcDir=src

EXE=Prox

#utils

# Proxy
ProxyName=proxy
ProxyDir=$(SrcDir)/$(ProxyName)
ProxyBuildDir=$(ProxyDir)/$(BuildDir)
ProxySO=$(ProxyBuildDir)/proxy.so

# Utils
UtilsName=utils
UtilsDir=$(SrcDir)/$(UtilsName)
UtilsBuildDir=$(UtilsDir)/$(BuildDir)
UtilsSO=$(UtilsBuildDir)/utils.so

export

all: $(EXE)

$(EXE): $(ProxySO) $(UtilsSO)
	$(CC) $^ -o $(EXE)

$(ProxySO): $(ProxyBuildDir)
	@make -f $(ProxyDir)/makefile

$(UtilsSO): $(UtilsBuildDir)
	@make -f $(UtilsDir)/makefile

clean: clean$(ProxyName) clean$(UtilsName)
	rm $(EXE)

clean$(ProxyName):
	@make -f $(ProxyDir)/makefile clean

clean$(UtilsName):
	@make -f $(UtilsDir)/makefile clean

$(SrcDir)/%/$(BuildDir):
	mkdir $@




