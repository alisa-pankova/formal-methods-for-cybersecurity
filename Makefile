CC_FILES=generate-mcs.cc BasicDatabase.cc PrismDatabase.cc GeneratableDatabase.cc Database.cc Component.cc MinimumCut.cc WalletScenario.cc
O_FILES=generate-mcs.o BasicDatabase.o PrismDatabase.o GeneratableDatabase.o Database.o Component.o MinimumCut.o WalletScenario.o
H_FILES=globals.h BasicDatabase.h PrismDatabase.h GeneratableDatabase.h Database.h Component.h MinimumCut.h WalletScenario.h
OPTIONS=-O0 -Wall -Wno-sign-compare -Wno-parentheses

all: gen-mcs

clean:
	rm -f $(O_FILES)

gen-mcs-0: $(CC_FILES) $(H_FILES)
	g++ $(OPTIONS) $(CC_FILES) -o gen-mcs

gen-mcs: $(O_FILES)
	g++ $(OPTIONS) $(O_FILES) -o gen-mcs

generate-mcs.o: generate-mcs.cc $(H_FILES)
	g++ -c $(OPTIONS) generate-mcs.cc

BasicDatabase.o: BasicDatabase.cc globals.h BasicDatabase.h
	g++ -c $(OPTIONS) BasicDatabase.cc

PrismDatabase.o: PrismDatabase.cc globals.h PrismDatabase.h BasicDatabase.h
	g++ -c $(OPTIONS) PrismDatabase.cc

GeneratableDatabase.o: GeneratableDatabase.cc globals.h GeneratableDatabase.h PrismDatabase.h BasicDatabase.h
	g++ -c $(OPTIONS) GeneratableDatabase.cc

Database.o: Database.cc $(H_FILES)
	g++ -c $(OPTIONS) Database.cc

Component.o: Component.cc $(H_FILES)
	g++ -c $(OPTIONS) Component.cc

MinimumCut.o: MinimumCut.cc globals.h MinimumCut.h
	g++ -c $(OPTIONS) MinimumCut.cc

WalletScenario.o: WalletScenario.cc $(H_FILES)
	g++ -c $(OPTIONS) WalletScenario.cc

linear-mcs: gen-mcs
	./gen-mcs l generated-linear-mcs.prism

linear-mcsi: gen-mcs
	./gen-mcs li generated-linear-mcsi.prism

linear-mcsn: gen-mcs
	./gen-mcs ln generated-linear-mcsn.prism

linear-mcsni: gen-mcs
	./gen-mcs lni generated-linear-mcsni.prism

mcs: gen-mcs
	./gen-mcs "" generated-mcs.prism

mcsi: gen-mcs
	./gen-mcs i generated-mcsi.prism

mcsn: gen-mcs
	./gen-mcs n generated-mcsn.prism

mcsni: gen-mcs
	./gen-mcs ni generated-mcsni.prism

prism-symlink:
	test -h prism || (echo "./prism must be a symlink to the bin/prism script under the PRISM directory tree" && exit 1)

cut-mcs: gen-mcs prism-symlink
	./gen-mcs c

wallet-exponential: gen-mcs prism-symlink
	./gen-mcs x1

wallet-compositional: gen-mcs prism-symlink
	./gen-mcs c1

wallet2-exponential: gen-mcs prism-symlink
	./gen-mcs x2

wallet2-compositional: gen-mcs prism-symlink
	./gen-mcs c2

gen: generate.cc
	g++ generate.cc -o gen
