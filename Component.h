/*
 * Copyright 2026 Cybernetica AS
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
 #ifndef COMPONENT_H
#define COMPONENT_H

#include "Database.h"

#include <memory>
#include <iostream>

using namespace std;

struct Component;
struct SimpleComponent;

typedef shared_ptr<Component> CompRef;
typedef shared_ptr<SimpleComponent> SCompRef;

struct Component {
  PrismAnalysisResult res;

  virtual int num_inputs() = 0;
  virtual int num_outputs() = 0;
  virtual void analyze(bool need_probs) = 0; // fills res, using the res from the subcomponents, or using PRISM if it does not have subcomponents
  void compose(Database &db); // TODO: combine all subcomponents of this component into a single large database db
  bool is_analyzed(bool need_probs) { return need_probs ? !res.probs.empty() : !res.costs.empty(); }
  void clear_res();
  //~Component() { cerr << "~Component()" << this << endl; }
};

struct SimpleComponent : public Component {
  Database db;

  SimpleComponent() {}
  SimpleComponent(Database &db): db(db) {}
  static SCompRef make() { return make_shared<SimpleComponent>(); }
  static SCompRef make(Database &db) { return make_shared<SimpleComponent>(db); }
  static SCompRef gen(int num_assets, int num_inputs, int num_outputs, mt19937_64 &rng);
  int num_inputs() { return db.source_assets.size(); }
  int num_outputs() { return db.thracts.at(0).motivation.size(); }
  void analyze(bool need_probs);
  Asset *asset(int i) { return &db.assets.at(i); }
  //~SimpleComponent() { cerr << "~SimpleComponent()" << this << endl; }
};

struct SequentialComposition : public Component {
  CompRef comp1, comp2;

  SequentialComposition(CompRef c1, CompRef c2);
  int num_inputs() { return comp1->num_inputs(); }
  int num_outputs() { return comp2->num_outputs(); }
  void analyze(bool need_probs);
  static CompRef make(CompRef c1, CompRef c2) { return make_shared<SequentialComposition>(c1, c2); }
  //~SequentialComposition() { cerr << "~SequentialComposition()" << this << endl; }
};

struct ParallelComposition : public Component {
  CompRef comp1, comp2;

  ParallelComposition(CompRef c1, CompRef c2): comp1(c1), comp2(c2) {}
  int num_inputs() { return comp1->num_inputs() + comp2->num_inputs(); }
  int num_outputs() { return comp1->num_outputs() + comp2->num_outputs(); }
  void analyze(bool need_probs);
  static CompRef make(CompRef c1, CompRef c2) { return make_shared<ParallelComposition>(c1, c2); }
  //~ParallelComposition() { cerr << "~ParallelComposition()" << this << endl; }
};

inline CompRef operator>>(CompRef c1, CompRef c2) { return SequentialComposition::make(c1, c2); }
inline CompRef operator||(CompRef c1, CompRef c2) { return ParallelComposition::make(c1, c2); }
// need to give extra definitions for SCompRef, otherwise the C++ compiler tries to cast SCompRef into bool instead of into CompRef, as || is also defined for bools
inline CompRef operator||(SCompRef c1, CompRef c2) { return ParallelComposition::make(c1, c2); }
inline CompRef operator||(CompRef c1, SCompRef c2) { return ParallelComposition::make(c1, c2); }
inline CompRef operator||(SCompRef c1, SCompRef c2) { return ParallelComposition::make(c1, c2); }

extern void test_components();
extern void test_components_2();
extern void test_components_3();
#endif
