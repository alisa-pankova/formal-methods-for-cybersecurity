/*
 * Copyright 2026 Cybernetica AS
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
 #ifndef DATABASE_H
#define DATABASE_H

#include "GeneratableDatabase.h"

#include <memory>
#include <vector>
#include <set>

using namespace std;

struct Component;
typedef shared_ptr<Component> CompRef;

struct PrismAnalysisResult {
  vector<double> costs; // the cost if the attacker starts from source i
  vector<vector<double> > probs; // the probability of reaching target j if the attacker starts from source i
  string cut_structure; // for debugging; * if no cuts, (SnT) if cut has size n and subgraphs have cut structures S and T

  void print(bool need_probs = false);
};

struct Database : public GeneratableDatabase {
  Database() {}
  Database(Database &db);
  CompRef decompose(); // decompose the database into components
  void analyze_with_prism(PrismAnalysisResult &r, bool need_probs);
  void analyze(PrismAnalysisResult &whole_res, bool need_probs);
  void find_cut();
  bool find_minimum_cut(set<Asset *> &source_side_assets, set<Asset *> &sink_side_assets); // returns true if could cut, false if could not cut
  bool find_parallel_decomposition(set<Asset *> &assets1, set<Asset *> &assets2); // returns true iff could find
  void restrict_to_assets(const set<Asset *> &asset_set, Database &new_db); // make new_db a copy of the database restricted to the given set of assets, parts of the database involving other assets are removed
};
#endif
