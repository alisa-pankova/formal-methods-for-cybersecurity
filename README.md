# Network Generator

The code allows defining cybersecurity scenarios, which can then be analyzed either directly or by splitting it into components, analyzing the components separately, and combining the results to get
the analysis of the whole scenario. The components can be either given manually or determined automatically. The attacker can probabilistic or nondeterministic.

## Usage

The main C++ file of the code is `generate-mcs.cc`. The files `generate.cc`, `generate-no-defender.cc`, and `generate-with-defender.cc` are not used in the main program, they are very old versions of it.
The code can be compiled by running
```
make
```
which produces the executable file `./gen-mcs`, which can be run without arguments to get usage instructions.

To execute the generated models automatically in PRISM, PRISM must be installed and ./prism must be a symlink to the bin/prism script under the PRISM directory tree. The symlink can be created with
```
ln -s PRISMDIR/bin/prism prism
```
where PRISMDIR is the root of the PRISM directory tree, which contains bin/prism.

There is a script `./run-tests`, which runs many examples and checks that they run without runtime errors. It does not check the correctness of the computed results.

## Examples

There are some examples of scenarios in `Component.cc` (`test_components()`, `test_components_2()`, and `test_components_3()`) and `WalletScenario.cc`.
In `test_components_3()`, the line
```
CompRef c = db.decompose();
```
is used to determine the components automatically after defining the whole scenario first.

To give the components manually, first define each component and then combine them using the sequential composition operator `>>` and the parallel composition operator `||`, e.g. `(G1 || G2) >> G3 || G4`.
The `>>` has higher precedence than `||` in C++.

In `test_components()`, the line
```
CompRef c2 = c1 >> c1 >> c1 || c1 >> c1;
```
illustrates that the same component (here `c1`) can be used multiple times in the scenario. It will still be analyzed only once.

`test_components_2()` is the example from the DSL section of the paper. It also defines the function `g` (as a lambda expression), which generates random components.

In `WalletScenario.cc`, `init1()` generates a simple wallet scenario, with or without revocations, depending on the parameter `revocations`. It can be run without revocations with
`./gen-mcs x1` and with revocations with `./gen-mcs x3`.

`init2()` generates a wallet scenario with multiple issuers (it is also described in the paper), with or without revocations, depending on the parameter `revocations`. It can be run without revocations with
`./gen-mcs x2` and with revocations with `./gen-mcs nx4`. With revocations, it is recommended to use `nx4` instead of `x4`, to make the attacker nondeterministic, as that scenario works best with a
nondeterministic attacker.

`run5()` generates and runs a wallet scenario with mutiple users (it is also described in the paper), if the parameter `find_user_probs` is true then it finds the probability of success for each user
type, otherwise it finds expected cost over all user types. The first case can be run with `./gen-mcs 6` and the second case with `./gen-mcs 5`. This scenario defines components separately and
combines them using sequential and parallel composition.

It is also possible to generate random examples that can be split into components and analyzed in the compositional model. The input parameters can be encoded in the example number, e.g.
```
./gen-mcs c450300602
```
generates a graph with 45 vertices, 3 vertices per cut, 6 components, and using mode 2 (mode 2 is with hyperedges, mode 1 is without). Here, the attacker is probabilistic. To make the attacker
nondeterministic, use
```
./gen-mcs nc450300602
```
instead.
