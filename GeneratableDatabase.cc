/*
 * Copyright 2026 Cybernetica AS
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
 #include "GeneratableDatabase.h"
#include "globals.h"

#include <iostream>

using namespace std;

Asset *choose_random_asset_from_set(const set<Asset *> &s, mt19937_64 &rng) try {
  if (s.empty())
    THROW("choose_random_asset_from_set: empty set");
  uniform_int_distribution<int> dist(0, s.size() - 1);
  int index = dist(rng);
  auto it = s.begin();
  for (int i = 0; i < index; i++)
    it++;
  return *it;
} CATCH

vector<Asset *> choose_random_hyperedge_source_from_set(const set<Asset *> &s, mt19937_64 &rng) try {
  if (s.size() < 2)
    THROW("choose_random_hyperedge_source_from_set: at least two elements needed in the set");
  bernoulli_distribution dist(0.5);
  vector<Asset *> res;
  for (Asset *a : s)
    if (dist(rng))
      res.push_back(a);
  if (res.empty())
    res.push_back(choose_random_asset_from_set(s, rng));
  return res;
} CATCH

void GeneratableDatabase::generate_component(
    const vector<Asset *> &comp,
    const vector<Asset *> &prev_cut,
    const set<Asset *> &midcomp,
    const set<Asset *> &next_cut,
    mt19937_64 &rng,
    bool add_vuln,
    bool hyperedges)
try {
  uniform_real_distribution<double> dist_severity(0.001, 0.999);
  set<Asset *> not_reached_in_next_cut = next_cut;
  vector<Asset *> prev_cut_extended = prev_cut;
  if (prev_cut_extended.size() < next_cut.size()) {
    set<Asset *> prev_cut_set;
    for (Asset *a : prev_cut_extended)
      prev_cut_set.insert(a);
    while (prev_cut_extended.size() < next_cut.size())
      prev_cut_extended.push_back(choose_random_asset_from_set(prev_cut_set, rng));
  }
  int num_extra_to_reach_in_next_cut = prev_cut_extended.size() > next_cut.size() ? prev_cut_extended.size() - next_cut.size() : 0;
  for (Asset *s : prev_cut_extended) {
    // start from s, at each step add a hyperedge from a subset of already reached vertices to a random not yet reached vertex, until we reach one of the vertices in cuts[i]
    set<Asset *> reached, not_reached, reached_in_midcomp;
    if (s == NULL) {
      s = choose_random_asset_from_set(midcomp, rng);
      itinfra.entrance_points.push_back(s);
    }
    reached.insert(s);
    for (Asset *a : comp)
      if (a != s)
        not_reached.insert(a);
    for (;;) {
      Asset *dst = choose_random_asset_from_set(not_reached, rng);
      if (hyperedges && reached_in_midcomp.size() >= 2) { // hyperedges possible
        vector<Asset *> src = choose_random_hyperedge_source_from_set(reached_in_midcomp, rng);
        if (src.size() >= 2) {
          if (dst == NULL)
            THROW("hyperedge destination is null pointer");
          if (add_vuln)
            add_hyperedge(src, dst, dist_severity(rng));
          else
            add_hyperedge(src, dst);
          cerr << "Created a hyperedge with " << src.size() << " source vertices" << endl;
        } else {
          if (add_vuln)
            add_edge(src[0], dst, dist_severity(rng));
          else
            add_edge(src[0], dst);
          cerr << "Created an ordinary edge (tried to create a hyperedge)" << endl;
        }
      } else { // create an ordinary edge
        Asset *src = choose_random_asset_from_set(reached, rng);
        if (add_vuln)
          add_edge(src, dst, dist_severity(rng));
        else
          add_edge(src, dst);
        cerr << "Created an ordinary edge" << endl;
      }
      reached.insert(dst);
      not_reached.erase(dst);
      if (midcomp.count(dst))
        reached_in_midcomp.insert(dst);
      if (not_reached_in_next_cut.count(dst)) {
        if (num_extra_to_reach_in_next_cut > 0)
          num_extra_to_reach_in_next_cut--;
        else
          not_reached_in_next_cut.erase(dst);
        break;
      }
    }
  }
} CATCH2(GeneratableDatabase::generate_component)

// mode==0 generates a normal graph
// mode==1 generates a graph with the minimum vertex separator having size cut_size and the num_comps subgraphs between the cuts having roughly equal size
// mode==2 is like mode==1 but with hyperedges
void GeneratableDatabase::init_gen(int n, int mode, int cut_size, int num_comps) try {
  bool hyperedges = false;
  if (mode == 2) {
    hyperedges = true;
    mode = 1;
  }
  int num_users = mode==1 ? 1 : (n+2)/3;
  int num_assets = n;
  int num_vulns = mode==1 ? num_assets : num_assets + num_users;
  int num_attackers = mode==1 ? 1 : 2 + n/10;
  int num_restart_machines = mode==1 ? 0 : (n+4)/5;
  int cut_asset = n/2; // used if mode == 1
  num_dm = mode==1 ? 0 : (n+4)/5;

  mt19937_64 rng;
  uniform_int_distribution<int> dist_sensitivity(1, 1000);
  uniform_int_distribution<int> dist_restart_machine_cost(1, 500);
  uniform_int_distribution<int> dist_dm_cost(1, 100);
  uniform_int_distribution<int> dist_owner(-num_users, num_users-1);
  uniform_int_distribution<int> dist_dm(-(num_dm+1)/2, num_dm-1); // negative => no def.measure can avoid this threat
  uniform_int_distribution<int> dist_asset(mode==1 ? cut_asset+1 : 0, num_assets-1);
  uniform_real_distribution<double> dist_severity(0.001, 0.999);
  uniform_real_distribution<double> dist_lh(0.001, 9.999);
  bernoulli_distribution dist_threat_in_tactic(1.0);
  bernoulli_distribution dist_edge_in_graph(0.99);
  //bernoulli_distribution dist_edge_in_graph(0.2);
  double severity_uncertainty = 0.1;
  double lh_uncertainty = 0.2;

  for (int i = 0; i < num_dm; i++)
    dm_costs.push_back((double)dist_dm_cost(rng));

  for (int i = 0; i < num_users; i++)
    identities.push_back({userID: i});

  for (int i = 0; i < num_assets; i++) {
    double sensitivity = (double)dist_sensitivity(rng);
    int owner = dist_owner(rng);
    assets.push_back({sensitivity: sensitivity, owner: owner < 0 ? NULL : &identities[owner]});
    int rmc = i < num_restart_machines ? dist_restart_machine_cost(rng) : -1;
    restart_machine_costs.push_back(rmc > 0 ? (double)rmc : -1);
  }
  for (int i = 0; i < assets.size(); i++)
    assets[i].id = i;

  vector<IdOrAsset *> idOrAssets;
  for (Asset &a : assets)
    idOrAssets.push_back(&a);
  for (Identity &id : identities)
    idOrAssets.push_back(&id);

  for (int i = 0; i < num_vulns; i++) {
    double s = dist_severity(rng);
    if (intervals_used)
      vulns.push_back({severity_interval: {s - severity_uncertainty*s, s + severity_uncertainty*(1 - s)}, direct_targets: {idOrAssets[i]}});
    else
      vulns.push_back({severity: s, direct_targets: {idOrAssets[i]}});
  }
  for (int i = 0; i < num_vulns; i++) {
    int forbidden_dm = dist_dm(rng);
    if (forbidden_dm < 0 || mode == 1)
      threats.push_back({impact: &vulns[i]});
    else
      threats.push_back({impact: &vulns[i], vector_forbidden_def_measures: {forbidden_dm}});
  }

  for (int i = 0; i < num_attackers; i++) {
    // nondeterministic attacker must not be allowed to skip, otherwise it can cause an infinite loop and PRISM returns infinity as the maximum cost
    attechs.push_back({skip_lh: nondet ? 0 : dist_lh(rng)});
    auto &tactic = attechs[i].tactic;
    auto &interval_tactic = attechs[i].interval_tactic;
    for (Threat &t : threats)
      if (dist_threat_in_tactic(rng)) {
        double lh = dist_lh(rng);
        if (intervals_used)
          interval_tactic.push_back({{lh*(1 - lh_uncertainty), lh*(1 + lh_uncertainty)}, &t});
        else
          tactic.push_back({lh, &t});
      }
    //thracts.push_back({motivation: {{&assets[mode==1 ? assets.size()-1 : dist_asset(rng)]}}});
    if (mode == 1) {
      thracts.push_back({});
      for (int j = 1; j <= cut_size; j++)
        thracts[0].motivation.push_back({&assets[assets.size() - j]});
    } else {
      thracts.push_back({motivation: {{&assets[dist_asset(rng)]}, {&assets[dist_asset(rng)]}}});
    }
  }
  for (int i = 0; i < num_attackers; i++)
    ttps.push_back({actor: &thracts[i], technique: &attechs[i]});

  if (mode == 0) {
    for (IdOrAsset *ia : idOrAssets)
      if (dist_edge_in_graph(rng))
        itinfra.entrance_points.push_back(ia);
    for (Asset &a : assets)
      for (IdOrAsset *ia : idOrAssets)
        if (&a != ia && dist_edge_in_graph(rng))
          itinfra.edges.push_back({&a, ia});
  } else if (mode == 1) {
    if (cut_size == 1 && num_comps == 0 && !hyperedges) {
      for (Asset &a : assets)
        if (a.id < cut_asset && dist_edge_in_graph(rng))
          itinfra.entrance_points.push_back(&a);
      for (Asset &a : assets)
        for (Asset &b : assets)
          if (!(a.id < cut_asset && b.id > cut_asset) && &a != &b && dist_edge_in_graph(rng))
            itinfra.edges.push_back({&a, &b});
    } else {
      vector<vector<Asset *> > cuts(num_comps - 1);
      int total_size_of_cuts = cut_size * (num_comps - 1);
      int total_size_of_midcomps = num_assets - total_size_of_cuts;
      if (total_size_of_midcomps < cut_size * num_comps)
        THROW("The number of assets per component outsize cuts must be at least large as the size of a cut");
      vector<vector<Asset *> > midcomps(num_comps);
      for (Asset &a : assets) {
        int i = a.id;
        if (i < total_size_of_cuts)
          cuts[i / cut_size].push_back(&a);
        else
          midcomps[(i - total_size_of_cuts) * num_comps / total_size_of_midcomps].push_back(&a);
      }
      vector<vector<Asset *> > comps = midcomps;
      // make comps[i-1] and comps[i] have cuts[i-1] in common
      for (int i = 1; i < num_comps; i++)
        for (Asset *a : cuts[i-1]) {
          comps[i-1].push_back(a);
          comps[i].push_back(a);
        }

      for (int i = 0; i < num_comps; i++) {
        cerr << "Generating component " << i << endl;
        set<Asset *> not_reached_in_next_cut, midcomp;
        for (Asset *a : midcomps[i])
          midcomp.insert(a);
        if (i == num_comps - 1)
          for (int j = 0; j < cut_size; j++)
            not_reached_in_next_cut.insert(thracts[0].motivation[j][0]);
        else
          for (Asset *a : cuts[i])
            not_reached_in_next_cut.insert(a);
        vector<Asset *> prev_cut;
        if (i >= 1)
          prev_cut = cuts[i-1];
        else
          for (int j = 0; j < cut_size; j++)
            prev_cut.push_back(NULL);

        generate_component(comps[i], prev_cut, midcomp, not_reached_in_next_cut, rng, false, hyperedges);
      }
    }
  } else {
    THROW("Database::init_gen(): invalid mode");
  }

  compute_helper_fields();
} CATCH2(GeneratableDatabase::init_gen)

void GeneratableDatabase::init() {
  num_dm = 1;
  dm_costs = { 30 };
  restart_machine_costs = { 10, 100, -1, -1, -1 };

  identities.push_back({userID: 0});
  identities.push_back({userID: 1});

  assets.push_back({sensitivity: 1});
  assets.push_back({sensitivity: 1, owner: &identities[0]});
  assets.push_back({sensitivity: 1000});
  assets.push_back({sensitivity: 2, owner: &identities[0]});
  assets.push_back({sensitivity: 3, owner: &identities[1]});
  for (int i = 0; i < assets.size(); i++)
    assets[i].id = i;

  if (intervals_used) {
    if (linear_model)
      vulns.push_back({severity_interval: {0.35, 0.4}, direct_targets: {&assets[0]}});
    else
      vulns.push_back({severity_interval: {0.35, 0.4}, direct_targets: {&assets[0], &assets[1]}});
    vulns.push_back({severity_interval: {0.51, 0.6}, direct_targets: {&assets[1]}});
    vulns.push_back({severity_interval: {0.29, 0.3}, direct_targets: {&assets[2]}});
    vulns.push_back({severity_interval: {0.18, 0.2}, direct_targets: {&assets[2]}});
    if (linear_model)
      vulns.push_back({severity_interval: {0.09, 0.1}, direct_targets: {&assets[3]}});
    else
      vulns.push_back({severity_interval: {0.09, 0.1}, direct_targets: {&assets[3], &assets[4]}});
    if (linear_model)
      vulns.push_back({severity_interval: {0, 0.1}, direct_targets: {&identities[1]}});
    else
      vulns.push_back({severity_interval: {0, 0.1}, direct_targets: {&identities[0], &identities[1]}});
  } else {
    if (linear_model)
      vulns.push_back({severity: 0.4, direct_targets: {&assets[0]}});
    else
      vulns.push_back({severity: 0.4, direct_targets: {&assets[0], &assets[1]}});
    vulns.push_back({severity: 0.6, direct_targets: {&assets[1]}});
    vulns.push_back({severity: 0.3, direct_targets: {&assets[2]}});
    vulns.push_back({severity: 0.2, direct_targets: {&assets[2]}});
    if (linear_model)
      vulns.push_back({severity: 0.1, direct_targets: {&assets[3]}});
    else
      vulns.push_back({severity: 0.1, direct_targets: {&assets[3], &assets[4]}});
    if (linear_model)
      vulns.push_back({severity: 0.1, direct_targets: {&identities[1]}});
    else
      vulns.push_back({severity: 0.1, direct_targets: {&identities[0], &identities[1]}});
  }

  // Threat.likelihood is currently not used
  threats.push_back({likelihood: 1, impact: &vulns[0]});
  threats.push_back({likelihood: 2, impact: &vulns[1]});
  // threats[2] is available when defensive measure 0 is not being applied
  threats.push_back({likelihood: 4, impact: &vulns[2], vector_forbidden_def_measures: {0}});
  // threats[3] is available when defensive measure 0 is being applied
  threats.push_back({likelihood: 3, impact: &vulns[3], vector_required_def_measures: {0}});
  threats.push_back({impact: &vulns[4]});
  threats.push_back({impact: &vulns[5]});

  if (intervals_used) {
    attechs.push_back({interval_tactic: {{{0.09, 0.1}, &threats[0]}, {{0.17, 0.2}, &threats[1]}, {{0.36, 0.4}, &threats[2]}, {{0.24, 0.3}, &threats[3]}}, skip_lh_interval: {0, 0.01}});
    if (!use_cuts)
      attechs.push_back({interval_tactic: {{{0.05, 0.1}, &threats[0]}, {{0.19, 0.2}, &threats[1]}, {{0.23, 0.3}, &threats[2]}, {{0.18, 0.2}, &threats[3]}, {{0, 0.1}, &threats[5]}}, skip_lh_interval: {0.1, 0.2}});
  } else {
    attechs.push_back({tactic: {{0.1, &threats[0]}, {0.2, &threats[1]}, {0.4, &threats[2]}, {0.3, &threats[3]}}});
    if (!use_cuts)
      attechs.push_back({tactic: {{0.1, &threats[0]}, {0.2, &threats[1]}, {0.3, &threats[2]}, {0.2, &threats[3]}, {0.1, &threats[5]}}, skip_lh: 0.1});
  }

  thracts.push_back({motivation: {{&assets[2]}}});
  if (!use_cuts) {
    if (linear_model)
      thracts.push_back({motivation: {{&assets[1]}}});
    else
      thracts.push_back({motivation: {{&assets[1]}, {&assets[0], &assets[2]}}});
  }

  ttps.push_back({actor: &thracts[0], technique: &attechs[0]});
  if (!use_cuts)
    ttps.push_back({actor: &thracts[1], technique: &attechs[1]});

  itinfra.entrance_points = {&assets[0], &assets[1], &identities[1]};
  itinfra.edges = {
    {&assets[0], &assets[1]},
    {&assets[0], &assets[2]}, {&assets[1], &assets[2]},
    {&assets[0], &assets[3]}, {&assets[1], &assets[3]},
    {&assets[1], &assets[4]},
    {&assets[0], &identities[0]},
  };

  compute_helper_fields();
}

void GeneratableDatabase::init_common() {
  for (int i = 0; i < assets.size(); i++)
    assets[i].id = i;

  for (int i = 0; i < assets.size(); i++)
    restart_machine_costs.push_back(-1);

  for (Vulnerability &v : vulns)
    threats.push_back({impact: &v});

  attechs.push_back({});
  for (Threat &t : threats)
    attechs[0].tactic.push_back({t.impact->tmp_likelihood, &t}); // the attacker chooses its next step uniformly among all available threats

  ttps.push_back({actor: &thracts[0], technique: &attechs[0]});

  compute_helper_fields();
}

void GeneratableDatabase::add_edge(Asset *from_asset, Asset *to_asset, double severity, double likelihood) {
  add_edge(from_asset, to_asset);
  vulns.push_back({severity: severity, direct_targets: {to_asset}, prerequisites: {{from_asset}}, tmp_likelihood: likelihood});
}

void GeneratableDatabase::add_edge(Asset *from_asset, Asset *to_asset) {
  itinfra.edges.push_back({from_asset, to_asset});
}

void GeneratableDatabase::add_hyperedge(const vector<Asset *> &from_assets, Asset *to_asset, double severity) {
  add_hyperedge(from_assets, to_asset);
  vulns.push_back({severity: severity, direct_targets: {to_asset}, prerequisites: {from_assets}});
}

void GeneratableDatabase::add_hyperedge(const vector<Asset *> &from_assets, Asset *to_asset) {
  itinfra.hyperedges.push_back({from_assets, to_asset});
}

void GeneratableDatabase::set_outputs(const vector<Asset *> &outputs) {
  thracts.clear();
  thracts.push_back({});
  for (Asset *a : outputs)
    thracts[0].motivation.push_back({a});
}

void GeneratableDatabase::generate_simple_component(int num_assets, int num_inputs, int num_outputs, mt19937_64 &rng) {
  for (int i = 0; i < num_assets; i++)
    assets.push_back({sensitivity: 0});
  vector<Asset *> comp, prev_cut, next_cut_vec;
  set<Asset *> midcomp, next_cut;
  for (int i = 0; i < num_assets; i++)
    comp.push_back(&assets[i]);
  for (int i = 0; i < num_inputs; i++)
    prev_cut.push_back(&assets[i]);
  for (int i = num_inputs; i < num_assets - num_outputs; i++)
    midcomp.insert(&assets[i]);
  for (int i = num_assets - num_outputs; i < num_assets; i++) {
    next_cut.insert(&assets[i]);
    next_cut_vec.push_back(&assets[i]);
  }
  generate_component(comp, prev_cut, midcomp, next_cut, rng, true, true);
  set_inputs(prev_cut);
  set_outputs(next_cut_vec);
  init_common();
}
