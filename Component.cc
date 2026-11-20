/*
 * Copyright 2026 Cybernetica AS
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
 #include "Component.h"
#include "globals.h"

#include <sstream>

void Component::clear_res() {
  res.costs.clear();
  res.probs.clear();
  res.cut_structure.clear();
}

void SimpleComponent::analyze(bool need_probs) {
  if (is_analyzed(need_probs))
    return;
  clear_res();
  db.analyze_with_prism(res, need_probs);
}

SCompRef SimpleComponent::gen(int num_assets, int num_inputs, int num_outputs, mt19937_64 &rng) {
  SCompRef c = make();
  c->db.generate_simple_component(num_assets, num_inputs, num_outputs, rng);
  return c;
}

void combine_sequential_composition_results(PrismAnalysisResult &whole_res, const PrismAnalysisResult &source_side_res, const PrismAnalysisResult &sink_side_res, bool need_probs) {
  int max_flow = sink_side_res.costs.size();
  for (int k = 0; k < source_side_res.costs.size(); k++) {
    cerr << endl << "if using source " << k << ":" << endl;
    cerr << "source side cost = " << source_side_res.costs[k] << endl;
    double cost = 0;
    for (int i = 0; i < max_flow; i++) {
      cerr << "probability of successfully reaching cut vertex " << i << ": " << source_side_res.probs[k][i] << endl;
      cerr << "sink side cost if using cut vertex " << i << ": " << sink_side_res.costs[i] << endl;
      double sink_side_cost = source_side_res.probs[k][i] * sink_side_res.costs[i];
      if (nondet) {
        if (source_side_res.probs[k][i] > 0) // avoid 0 * infinity
          cost = max(cost, sink_side_cost);
      } else
        cost += sink_side_cost;
    }
    cost += source_side_res.costs[k];
    cerr << "whole graph cost (computed from parts): " << cost << endl;
    whole_res.costs.push_back(cost);
    if (need_probs) {
      whole_res.probs.push_back({});
      for (int j = 0; j < sink_side_res.probs[0].size(); j++) {
        double prob = 0;
        for (int i = 0; i < max_flow; i++) {
          double p0 = source_side_res.probs[k][i] * sink_side_res.probs[i][j];
          if (nondet)
            prob = max(prob, p0);
          else
            prob += p0;
          cerr << "probability of reaching target " << j << " through cut vertex " << i << ": " << p0 << endl;
        }
        cerr << (nondet ? "maximum" : "total") << " probability of reaching target " << j << ": " << prob << endl;
        whole_res.probs[k].push_back(prob);
      }
    }
  }
  ostringstream oss;
  oss << "(" << source_side_res.cut_structure << max_flow << sink_side_res.cut_structure << ")";
  whole_res.cut_structure = oss.str();
}

SequentialComposition::SequentialComposition(CompRef c1, CompRef c2) try : comp1(c1), comp2(c2) {
  if (comp1->num_outputs() != comp2->num_inputs())
    THROW("SequentialComposition: the number of outputs of the first component must equal the number of inputs of the second component");
} CATCH2(SequentialComposition::SequentialComposition)

void SequentialComposition::analyze(bool need_probs) {
  if (is_analyzed(need_probs))
    return;
  clear_res();
  comp1->analyze(true);
  comp2->analyze(need_probs);
  combine_sequential_composition_results(res, comp1->res, comp2->res, need_probs);
}

void ParallelComposition::analyze(bool need_probs) try {
  if (is_analyzed(need_probs))
    return;
  clear_res();
  comp1->analyze(need_probs);
  comp2->analyze(need_probs);

  // combine the results
  res.costs = comp1->res.costs;
  for (double c : comp2->res.costs)
    res.costs.push_back(c);
  if (need_probs) {
    int n1 = comp1->res.probs.at(0).size();
    int n2 = comp2->res.probs.at(0).size();
    for (vector<double> ps : comp1->res.probs) {
      res.probs.push_back(ps);
      for (int i = 0; i < n2; i++)
        res.probs.back().push_back(0.0);
    }
    for (vector<double> ps : comp2->res.probs) {
      res.probs.emplace_back(n1, 0.0);
      for (double p : ps)
        res.probs.back().push_back(p);
    }
  }
  ostringstream oss;
  oss << "(" << comp1->res.cut_structure << "||" << comp2->res.cut_structure << ")";
  res.cut_structure = oss.str();
} CATCH2(ParallelComposition::analyze)

void test_components() try {
  cerr << "begin" << endl;
  SCompRef c1 = SimpleComponent::make();
  Database &db = c1->db;
  db.assets.push_back({sensitivity: 0});
  db.assets.push_back({sensitivity: 0});
  db.assets.push_back({sensitivity: 0});
  db.assets.push_back({sensitivity: 100});
  db.add_edge(c1->asset(0), c1->asset(1), 0.5);
  db.add_edge(c1->asset(0), c1->asset(2), 0.6);
  db.add_hyperedge({c1->asset(1), c1->asset(2)}, c1->asset(3), 0.4);
  db.set_inputs({c1->asset(0)});
  db.set_outputs({c1->asset(3)});
  db.init_common();
  // >> has higher priority than ||
  CompRef c2 = c1 >> c1 >> c1 || c1 >> c1;
  bool need_probs = true;
  c2->analyze(need_probs);
  cerr << endl << "Whole graph result:" << endl;
  c2->res.print(need_probs);
  cerr << "end " << c2->num_inputs() << " " << c2->num_outputs() << endl;
} CATCH2(test_components)

void test_components_2() try {
  mt19937_64 rng;
  auto g = [&](int num_assets, int num_inputs, int num_outputs) {
    return SimpleComponent::gen(num_assets, num_inputs, num_outputs, rng);
  };
  CompRef c = g(8,1,2) >> (g(7,1,3) || g(8,1,1)) >> g(7,4,2) || g(9,3,3);
  bool need_probs = true;
  c->analyze(need_probs);
  cerr << endl << "Whole graph result:" << endl;
  c->res.print(need_probs);
} CATCH2(test_components_2)

void test_components_3() try {
  Database db;
  db.assets.push_back({sensitivity: 0});
  db.assets.push_back({sensitivity: 0});
  db.assets.push_back({sensitivity: 0});
  db.assets.push_back({sensitivity: 100});
  db.assets.push_back({sensitivity: 0});
  db.assets.push_back({sensitivity: 100});
  auto a = [&](int i) { return &db.assets[i]; };
  db.add_edge(a(0), a(1), 0.5);
  db.add_edge(a(1), a(2), 0.5);
  db.add_hyperedge({a(1), a(2)}, a(3), 0.5);
  db.add_edge(a(4), a(5), 0.1);
  db.set_inputs({a(0), a(4)});
  db.set_outputs({a(3), a(5)});
  db.init_common();
  bool need_probs = true;
  CompRef c = db.decompose();
  c->analyze(need_probs);
  cerr << endl << "Whole graph result:" << endl;
  c->res.print(need_probs);
} CATCH2(test_components_3)
