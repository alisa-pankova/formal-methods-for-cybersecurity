/*
 * Copyright 2026 Cybernetica AS
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
 #ifndef GENERATABLE_DATABASE_H
#define GENERATABLE_DATABASE_H

#include "PrismDatabase.h"

#include <set>
#include <random>

// Adds (mostly random) database generation functionality to PrismDatabase
struct GeneratableDatabase : public PrismDatabase {
  void init(); // fill the tables
  void init_gen(int n, int mode = 0, int cut_size = 1, int num_comps = 0); // fill the tables with generated data
  void add_edge(Asset *from_asset, Asset *to_asset, double severity, double likelihood = 1.0);
  void add_edge(Asset *from_asset, Asset *to_asset);
  void add_hyperedge(const vector<Asset *> &from_assets, Asset *to_asset, double severity);
  void add_hyperedge(const vector<Asset *> &from_assets, Asset *to_asset);
  void set_inputs(const vector<Asset *> &inputs) { source_assets = inputs; }
  void set_outputs(const vector<Asset *> &outputs);
  void init_common();
  void generate_simple_component(int num_assets, int num_inputs, int num_outputs, mt19937_64 &rng);

  void generate_component(
      const vector<Asset *> &comp,
      const vector<Asset *> &prev_cut,
      const set<Asset *> &midcomp,
      const set<Asset *> &next_cut,
      mt19937_64 &rng,
      bool add_vuln,
      bool hyperedges);
};
#endif

