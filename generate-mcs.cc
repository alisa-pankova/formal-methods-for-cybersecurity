/*
 * Copyright 2026 Cybernetica AS
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
 #include "WalletScenario.h"
#include "Database.h"
#include "Component.h"
#include "globals.h"

#include <iostream>
#include <vector>
#include <string>
#include <cstdint>

extern void execute_prism(string prism_file, string props_file, vector<double> &res); // defined in PrismDatabase.cc

using namespace std;

bool linear_model; // whether to use a model with the number of states linear in the number of assets, instead of exponential
bool intervals_used; // is any likelihood or probability given as an interval instead of a single value
bool nondet; // is the attacker nondetermistic instead of probabilistic
bool use_cuts; // try to cut the IT infrastructure graph into smaller graphs, which PRISM may be able to analyze faster (in the exponential model)
bool limited_steps; // if false, the attacker does not quit after a number of steps, instead it keeps attacking until caught or it reaches the target

// When using probability intervals instead of exact probabilities,
// PRISM does not allow the lower bound to be zero if the upper bound is non-zero.
// To overcome this restriction, we replace the zero lower bound with ALMOST_ZERO in some cases.
// ALMOST_ZERO must be large enough that 1 - ALMOST_ZERO < 1 holds in floating-point numbers.
double ALMOST_ZERO = 1e-6;

// the cost of trying to detect an anomaly
double detect_anomaly_cost = 2;

// the cost of investigating an anomaly to detect if it is an incident
double investigate_anomaly_cost = 20;

int num_dm = 0; // the number of defensive measures

// the cost of applying each defensive measure
vector<double> dm_costs;

int main(int argc, char **argv) try {
  intervals_used = false;
  nondet = false;
  linear_model = false;
  use_cuts = false;
  bool execute = false;
  uint64_t example = 0;
  if (argc > 1) {
    string s = string(argv[1]);
    for (char c : s) {
      if (c == 'i')
        intervals_used = true;
      if (c == 'n')
        nondet = true;
      if (c == 'l')
        linear_model = true;
      if (c == 'c')
        use_cuts = true;
      if (c == 'x')
        execute = true;
      if (c >= '0' && c <= '9')
        example = example * 10 + (uint64_t)(c - '0');
    }
  } else {
    cout << "Usage: " << argv[0] << " [l][n][i][x][c][NUM] [FILE]" << endl;
    cout << "  l      generate a linear model" << endl;
    cout << "  n      generate a nondeterministic model" << endl;
    cout << "  i      generate a model with intervals" << endl;
    cout << "  x      execute the (noncompositional) model in PRISM" << endl;
    cout << "  c      generate a compositional model and execute it" << endl;
    cout << "  NUM    generate the example number NUM" << endl;
    cout << "  FILE   write the generated PRISM model to the file FILE" << endl;
    return 0;
  }
  if (use_cuts && linear_model)
    THROW("Decomposition not supported for linear models");
  if (use_cuts && intervals_used)
    THROW("Decomposition not supported for models with intervals");
  limited_steps = !use_cuts;
  if (example >= 1)
    limited_steps = false;

  Database db;
  if (example == 1) {
    WalletScenario::init1(db);
  } else if (example == 2) {
    WalletScenario::init2(db);
  } else if (example == 3) {
    WalletScenario::init1(db, true);
  } else if (example == 4) {
    WalletScenario::init2(db, true);
  } else if (example == 5) {
    WalletScenario::run5();
    return 0;
  } else if (example == 6) {
    WalletScenario::run5(true);
    return 0;
  } else if (example == 100) {
    test_components();
    return 0;
  } else if (example == 101) {
    test_components_2();
    return 0;
  } else if (example == 102) {
    test_components_3();
    return 0;
  } else if (example != 0 && example < 10000) {
    THROW_STREAM(<< "Example " << example << " not implemented.");
  } else if (use_cuts) {
    if (example == 0) {
      //db.init_gen(10, 1);
      //db.init_gen(62, 2, 2, 8);
      db.init_gen(70, 2, 2, 8);
      //db.init_gen(102, 2, 2, 13);
      //db.init();
    } else if (example % 100 <= 2)
      db.init_gen(example / 10000000, example % 100, example / 100000 % 100, example / 100 % 1000);
  } else {
    //db.init_gen(18);
    db.init();
  }
  if (argc > 2)
    db.generate_prism(argv[2]);
  if (use_cuts)
    db.find_cut();
  if (execute) {
    cerr << "Executing PRISM" << endl;
    vector<double> res;
    db.execute_prism(res);
    for (double x : res)
      cerr << "result: " << x << endl;
  }

  return 0;
} CATCH2(main)
