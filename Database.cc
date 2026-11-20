/*
 * Copyright 2026 Cybernetica AS
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
 #include "Database.h"
#include "Component.h"
#include "MinimumCut.h"
#include "globals.h"

#include <map>
#include <queue>
#include <iostream>
#include <sstream>
#include <climits>

void PrismAnalysisResult::print(bool need_probs) {
  for (int i = 0; i < costs.size(); i++)
    cerr << "cost when starting from source " << i << ": " << costs[i] << endl;
  if (need_probs)
    for (int i = 0; i < probs.size(); i++)
      for (int j = 0; j < probs[i].size(); j++)
        cerr << "probability of reaching target " << j << " when starting from source " << i << ": " << probs[i][j] << endl;
  cerr << "cut structure: " << cut_structure << endl;
}

void Database::analyze_with_prism(PrismAnalysisResult &r, bool need_probs) try {
  vector<double> res;
  execute_prism(res, need_probs ? 1 : 0);
  int num_sources = source_assets.empty() ? 1 : source_assets.size();
  int num_targets = thracts[0].motivation.size();
  int num_results = num_sources;
  if (need_probs)
    num_results += num_sources * num_targets;
  if (res.size() != num_results)
    THROW("The number of results received from PRISM is incorrect.");

  int k = 0;
  for (int i = 0; i < num_sources; i++) {
    r.costs.push_back(res[k++]);
    if (need_probs) {
      r.probs.push_back({});
      for (int j = 0; j < num_targets; j++)
        r.probs[i].push_back(res[k++]);
    }
  }
  r.cut_structure = "*";
} CATCH2(Database::analyze_with_prism)

void Database::analyze(PrismAnalysisResult &whole_res, bool need_probs) try {
  CompRef c = decompose();
  c->analyze(need_probs);
  whole_res = c->res;
} CATCH2(Database::analyze)

void Database::find_cut() {
  PrismAnalysisResult r;
  analyze(r, false);

  if (assets.size() <= 10) {
    vector<double> res;
    execute_prism(res);
    for (double x : res)
      cerr << "whole graph cost (computed directly): " << x << endl;
  }

  cerr << "whole graph cost (computed from parts): " << r.costs[0] << endl;
  cerr << "cut structure: " << r.cut_structure << endl;
}

Database::Database(Database &db) {
  set<Asset *> asset_set;
  for (Asset &a : db.assets)
    asset_set.insert(&a);
  // here we do not actually restrict the assets but restrict_to_assets makes
  // the pointers inside the new database point to locations in the new database instead of the old database
  db.restrict_to_assets(asset_set, *this);
  cut_assets.clear();
}

bool Database::find_parallel_decomposition(set<Asset *> &assets1, set<Asset *> &assets2) try {
  if (source_assets.empty())
    return false;
  map<Asset *, vector<Asset *>> vv; // for each vertex v, the vertices connected to v by an edge or a hyperedge
  for (Asset &a : assets)
    vv.insert({&a, {}});
  for (auto p : itinfra.edges) {
    Asset *y = p.second->asset;
    if (y == NULL)
      THROW("find_parallel_decomposition(): identities not supported (1)");
    Asset *x = p.first;
    vv[x].push_back(y);
    vv[y].push_back(x);
  }
  for (auto &p : itinfra.hyperedges) {
    Asset *y = p.second->asset;
    if (y == NULL)
      THROW("find_parallel_decomposition(): identities not supported (2)");
    vector<Asset *> &xs = p.first;
    if (!xs.empty()) {
      vv[y].push_back(xs.front());
      for (int i = 1; i < xs.size(); i++)
        vv[xs[i-1]].push_back(xs[i]);
      vv[xs.back()].push_back(y);
    }
  }
  // all entrance points must be in the same component
  if (itinfra.entrance_points.size() >= 2) {
    vector<Asset *> xs;
    for (IdOrAsset *ia : itinfra.entrance_points) {
      Asset *y = ia->asset;
      if (y == NULL)
        THROW("find_parallel_decomposition(): identities not supported (3)");
      xs.push_back(y);
    }
    for (int i = 1; i < xs.size(); i++)
      vv[xs[i-1]].push_back(xs[i]);
    vv[xs.back()].push_back(xs.front());
  }

  Asset *v0 = source_assets.front();
  set<Asset *> reached;
  reached.insert(v0);
  queue<Asset *> q;
  q.push(v0);
  while (!q.empty()) {
    Asset *v = q.front();
    q.pop();
    for (Asset *a : vv[v])
      if (!reached.count(a)) {
        reached.insert(a);
        q.push(a);
      }
  }

  if (reached.size() >= assets.size()) {
    cerr << "No parallel decomposition found." << endl;
    return false;
  } else {
    assets1 = reached;
    assets2.clear();
    for (Asset &a : assets)
      if (!reached.count(&a))
        assets2.insert(&a);
    cerr << "Found parallel decomposition into graphs with " << assets1.size() << " and " << assets2.size() << " assets." << endl;
    return true;
  }
} CATCH2(Database::find_parallel_decomposition)

CompRef Database::decompose() try {
  set<Asset *> assets1, assets2;
  set<Asset *> source_side_assets, sink_side_assets; // the cut assets are included in both sets
  bool enough_assets = assets.size() >= 5;
  if (enough_assets && find_parallel_decomposition(assets1, assets2)) {
    Database db1, db2;
    restrict_to_assets(assets1, db1);
    restrict_to_assets(assets2, db2);
    if (db1.thracts[0].motivation.empty() || db2.thracts[0].motivation.empty())
      cerr << "Skipping parallel decomposition because one of the components has no targets." << endl;
    else
      return db1.decompose() || db2.decompose();
  }
  if (enough_assets && find_minimum_cut(source_side_assets, sink_side_assets)) { // also sets cut_assets
    Database source_side_db;
    restrict_to_assets(source_side_assets, source_side_db);
    source_side_db.thracts[0].motivation.clear();
    for (Asset *a : source_side_db.cut_assets)
      source_side_db.thracts[0].motivation.push_back({a});
    source_side_db.cut_assets.clear();

    Database sink_side_db;
    restrict_to_assets(sink_side_assets, sink_side_db);
    sink_side_db.source_assets = sink_side_db.cut_assets;
    sink_side_db.cut_assets.clear();
    sink_side_db.itinfra.entrance_points.clear();

    cut_assets.clear();

    return source_side_db.decompose() >> sink_side_db.decompose();
  } else {
    return SimpleComponent::make(*this);
  }
} CATCH2(Database::decompose)

inline int vertex_in(int i) { return 2 * i; }
inline int vertex_out(int i) { return 2 * i + 1; }
inline int vertex_orig(int i) { return i / 2; }

bool Database::find_minimum_cut(set<Asset *> &source_side_assets, set<Asset *> &sink_side_assets) try {
  cerr << "Database::find_minimum_cut()" << endl;
  if (thracts.size() > 1)
    THROW("multiple attackers not supported");
  set<Asset *> targets;
  for (vector<Asset *> &v : thracts[0].motivation) {
    if (v.size() > 1)
      THROW("targets with multiple assets not supported");
    targets.insert(v[0]);
  }
  set<Asset *> sources;
  for (Asset *a : source_assets)
    sources.insert(a);
  int source = 2 * assets.size();
  int sink = 2 * assets.size() + 1;
  MinimumCut mc(sink + 1, source, sink);
  cerr << "sink: " << sink << endl;
  for (Asset *a : targets) {
    int x = vertex_out(a->id);
    cerr << x << "->" << sink << endl;
    mc.add_edge(x, sink, INT_MAX);
  }
  for (IdOrAsset *v : itinfra.entrance_points) {
    if (v->asset != NULL) {
      int y = vertex_in(v->asset->id);
      cerr << source << "->" << y << endl;
      // INT_MAX for infinite capacity, as we do not want these edges in the cut
      mc.add_edge(source, y, INT_MAX);
    }
  }
  for (Asset *a : source_assets) {
      int y = vertex_in(a->id);
      cerr << source << "->" << y << endl;
      // INT_MAX for infinite capacity, as we do not want these edges in the cut
      mc.add_edge(source, y, INT_MAX);
  }
  for (pair<Asset *, IdOrAsset *> &e : itinfra.edges) {
    // we are ignoring edges where the endpoint is a user instead of an asset
    if (e.second->asset != NULL) {
      // since we want to find vertex cuts instead of edge cuts,
      // we split each vertex v into two vertices v_in and v_out,
      // such that an edge from x to y becomes an edge from x_out to y_in
      int x = vertex_out(e.first->id);
      int y = vertex_in(e.second->asset->id);
      cerr << x << "->" << y << endl;
      // INT_MAX for infinite capacity, as we do not want these edges in the cut
      mc.add_edge(x, y, INT_MAX);
    }
  }
  for (pair<vector<Asset *>, IdOrAsset *> &e : itinfra.hyperedges) {
    if (e.first.empty())
      THROW("Hyperedges with 0 source vertices are not supported. Use entrance points instead.");
    int n = e.first.size();
    // add an infinite-capacity cycle through all n sources of the hyperedge,
    // which is equivalent to collapsing them into a single vertex
    // and collapsing the hyperedge into an ordinary edge
    for (int i = 0; i < n; i++)
      mc.add_edge(vertex_out(e.first[i]->id), vertex_in(e.first[(i + 1) % n]->id), INT_MAX);
    mc.add_edge(vertex_out(e.first[0]->id), vertex_in(e.second->asset->id), INT_MAX);
  }
  for (Asset &a : assets) {
    int i = a.id;
    int x = vertex_in(i);
    int y = vertex_out(i);
    cerr << x << "->" << y << endl;
    // these are the only edges with finite nonzero capacity (if a is not a source or a target or a source of a hyperedge)
    mc.add_edge(x, y, sources.count(&a) || targets.count(&a) || a.is_hyperedge_source ? INT_MAX : 1);
  }
  mc.find_cut();
  if (mc.max_flow == 0) {
    THROW("The attacker's target is not reachable.");
  } else if (mc.max_flow == INT_MAX) {
    cerr << "The graph cannot be cut further." << endl;
    return false;
  }
  cerr << "max flow: " << mc.max_flow << endl;
  cut_assets.clear();
  for (Edge *e : mc.min_cut)
    cut_assets.push_back(&assets[vertex_orig(e->x)]);
  cerr << "The following vertices need to be cut in the IT infrastructure graph:" << endl;
  for (Asset *a : cut_assets)
    cerr << "asset " << a->id << endl;
  for (Asset &a : assets) {
    int i = a.id;
    if (mc.is_source_side[vertex_in(i)])
      source_side_assets.insert(&a);
    if (!mc.is_source_side[vertex_out(i)])
      sink_side_assets.insert(&a);
  }
  cerr << "Source side assets:" << endl;
  for (Asset *a : source_side_assets)
    cerr << "asset " << a->id << endl;
  cerr << "Sink side assets:" << endl;
  for (Asset *a : sink_side_assets)
    cerr << "asset " << a->id << endl;

  return true;
} CATCH2(Database::find_minimum_cut)

// returns true if at least one of the prerequisites is fulfillable in the restricted database
bool restrict_prerequisites(vector<vector<Asset *>> &new_prerequisites, const vector<vector<Asset *>> &prerequisites, const set<Asset *> &asset_set, map<Asset *, Asset *> asset_map) {
  bool prerequisites_fulfillable = true;
  if (!prerequisites.empty()) {
    for (const vector<Asset *> &prereq : prerequisites) {
      vector<Asset *> new_prereq;
      bool fulfillable = true;
      for (Asset *a : prereq) {
        if (asset_set.count(a))
          new_prereq.push_back(asset_map[a]);
        else {
          fulfillable = false;
          break;
        }
      }
      if (fulfillable)
        new_prerequisites.push_back(new_prereq);
    }
    if (new_prerequisites.empty())
      prerequisites_fulfillable = false;
  }
  return prerequisites_fulfillable;
}

void Database::restrict_to_assets(const set<Asset *> &asset_set, Database &new_db) try {
  if (!new_db.assets.empty())
    THROW("Database::restrict_to_assets(): new_db must be empty");

  int i = 0;
  map<Asset *, int> asset_map0;
  for (Asset &a : assets)
    if (asset_set.count(&a)) {
      new_db.assets.push_back({id: i, sensitivity: a.sensitivity});
      asset_map0.insert({&a, i++});
    }
  // could not map to Asset * earlier because pointers to vector elements can change if new elements are added to the vector
  map<Asset *, Asset *> asset_map;
  for (auto &p : asset_map0)
    asset_map.insert({p.first, &new_db.assets[p.second]});

  for (Asset *a : cut_assets)
    if (asset_set.count(a))
      new_db.cut_assets.push_back(asset_map[a]);
  for (Asset *a : source_assets)
    if (asset_set.count(a))
      new_db.source_assets.push_back(asset_map[a]);
  for (Asset *a : starting_assets)
    if (asset_set.count(a))
      new_db.starting_assets.push_back(asset_map[a]);
  
  new_db.restart_machine_costs.resize(new_db.assets.size(), -1);
  for (auto &p : asset_map)
    new_db.restart_machine_costs[p.second->id] = restart_machine_costs[p.first->id];

  for (DefenseTactic &dt : deftacs) {
    if (asset_set.count(dt.target)) {
      vector<vector<Asset *>> new_prerequisites;
      if (restrict_prerequisites(new_prerequisites, dt.prerequisites, asset_set, asset_map)) {
        new_db.deftacs.push_back({
          prob: dt.prob,
          cost: dt.cost,
          target: asset_map[dt.target],
          prerequisites: new_prerequisites
        });
      }
    }
  }

  i = 0;
  map<Vulnerability *, int> vuln_map0;
  for (Vulnerability &v : vulns) {
    vector<IdOrAsset *> new_direct_targets;
    for (IdOrAsset *ia : v.direct_targets) {
      Asset *a = ia->asset;
      if (a != NULL) {
        auto it = asset_map.find(a);
        if (it != asset_map.end())
          new_direct_targets.push_back(it->second);
      }
    }
    if (!new_direct_targets.empty()) {
      vector<vector<Asset *>> new_prerequisites;
      if (restrict_prerequisites(new_prerequisites, v.prerequisites, asset_set, asset_map)) {
        new_db.vulns.push_back({
          severity: v.severity,
          severity_interval: v.severity_interval,
          direct_targets: new_direct_targets,
          prerequisites: new_prerequisites
        });
        vuln_map0.insert({&v, i++});
      }
    }
  }
  map<Vulnerability *, Vulnerability *> vuln_map;
  for (auto &p : vuln_map0)
    vuln_map.insert({p.first, &new_db.vulns[p.second]});

  i = 0;
  map<Threat *, int> threat_map0;
  for (Threat &t : threats) {
    auto it = vuln_map.find(t.impact);
    if (it != vuln_map.end()) {
      new_db.threats.push_back({
        likelihood: t.likelihood,
        impact: it->second,
        vector_required_def_measures: t.vector_required_def_measures,
        vector_forbidden_def_measures: t.vector_forbidden_def_measures
      });
      threat_map0.insert({&t, i++});
    }
  }
  map<Threat *, Threat *> threat_map;
  for (auto &p : threat_map0)
    threat_map.insert({p.first, &new_db.threats[p.second]});

  if (attechs.size() != 1 || thracts.size() != 1 || ttps.size() != 1)
    THROW("Database::restrict_to_assets(): currently multiple attackers are not supported");

  AttackTechnique *at = &attechs[0];
  new_db.attechs.push_back({skip_lh: at->skip_lh, skip_lh_interval: at->skip_lh_interval});
  AttackTechnique *new_at = &new_db.attechs[0];
  for (auto &p : at->tactic) {
    auto it = threat_map.find(p.second);
    if (it != threat_map.end())
      new_at->tactic.push_back({p.first, it->second});
  }
  for (auto &p : at->interval_tactic) {
    auto it = threat_map.find(p.second);
    if (it != threat_map.end())
      new_at->interval_tactic.push_back({p.first, it->second});
  }

  new_db.thracts.push_back({});
  for (vector<Asset *> &v : thracts[0].motivation) {
    if (v.size() > 1)
      THROW("Database::restrict_to_assets(): targets with multiple assets not supported");
    auto it = asset_map.find(v[0]);
    if (it != asset_map.end())
      new_db.thracts[0].motivation.push_back({it->second});
  }
  new_db.ttps.push_back({actor: &new_db.thracts[0], technique: &new_db.attechs[0]});

  for (IdOrAsset *ia : itinfra.entrance_points) {
    Asset *a = ia->asset;
    if (a != NULL) {
      auto it = asset_map.find(a);
      if (it != asset_map.end()) {
        Asset *y = it->second;
        new_db.itinfra.entrance_points.push_back(y);
      }
    }
  }
  for (auto &p : itinfra.edges) {
    auto it = asset_map.find(p.first);
    if (it != asset_map.end()) {
      Asset *x = it->second;
      Asset *y = p.second->asset;
      if (y != NULL) {
        auto it = asset_map.find(y);
        if (it != asset_map.end()) {
          Asset *y = it->second;
          new_db.itinfra.edges.push_back({x, y});
        }
      }
    }
  }
  for (auto &p : itinfra.hyperedges) {
    bool is_inside = false, is_outside = false;
    // if one of the sources of the hyperedge is in this component then the whole hyperedge must be in this component
    for (Asset *a : p.first) {
      if (asset_map.count(a))
        is_inside = true;
      else
        is_outside = true;
    }
    if (is_inside && is_outside)
      THROW("ERROR: Sources of a hyperedge are not all in the same component");
    Asset *y = p.second->asset;
    if (y != NULL && is_inside && !asset_map.count(y)) {
      // Sources of a hyperedge are in the same component but the destination of the hyperedge is not in that component.
      // This can only happen if it is a backward hyperedge from a component after a cut to a component before the cut.
      // We can just remove that hyperedge as the compositional model does not allow the attacker to go back to a previous component.
      continue;
    }
    if (is_inside) {
      vector<Asset *> xs;
      for (Asset *x : p.first)
        xs.push_back(asset_map[x]);
      Asset *y = p.second->asset;
      if (y != NULL)
        new_db.itinfra.hyperedges.push_back({xs, asset_map[y]});
    }
  }

  new_db.compute_helper_fields();
} CATCH2(Database::restrict_to_assets)
