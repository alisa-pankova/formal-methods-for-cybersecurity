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
#include "Component.h"

#include <array>
#include <iomanip>

namespace WalletScenario {
  // hardness levels of attacks
  static const double S  = 1.0;
  //static const double VE = 0.5;
  //static const double E  = 0.25;
  static const double M  = 0.1;
  static const double H  = 0.05;
  static const double VH = 0.01;
  //static const double I  = 0.0;

  // A simple scenario
  void init1(GeneratableDatabase &db, bool revocations) try {
    for (int i = 0; i < 5; i++)
      db.assets.push_back({sensitivity: 0});
    db.assets.push_back({sensitivity: 100}); // D0, the goal of the attacker
    Asset *nr_a0 = NULL;
    if (revocations) {
      db.assets.push_back({sensitivity: 0});
      nr_a0 = &db.assets[6]; // the attacker has this asset iff A0 has not been revoked
    }
    Asset *a0 = &db.assets[0];
    Asset *b0 = &db.assets[1];
    Asset *b1 = &db.assets[2];
    Asset *b2 = &db.assets[3];
    Asset *c0 = &db.assets[4];
    Asset *d0 = &db.assets[5];

    db.itinfra.entrance_points = {b0, b1, c0, d0};
    db.itinfra.edges = {
      {b0, a0}, {c0, d0}
    };
    db.itinfra.hyperedges = {
      {{b0, b1}, b2}
    };

    db.vulns.push_back({severity: M,  direct_targets: {b0}}); // {} -> B0
    db.vulns.push_back({severity: H,  direct_targets: {b0}}); // {} -> B0
    db.vulns.push_back({severity: H,  direct_targets: {b1}}); // {} -> B1
    db.vulns.push_back({severity: S,  direct_targets: {b2}}); // {B0,B1} -> B2
    db.vulns.push_back({severity: S,  direct_targets: {a0}}); // B0 -> A0
    db.vulns.push_back({severity: VH, direct_targets: {c0}}); // {} -> C0
    db.vulns.push_back({severity: VH, direct_targets: {d0}}); // {} -> D0

    db.thracts.push_back({motivation: {{d0}}});

    if (revocations) {
      db.itinfra.hyperedges.push_back({{a0, nr_a0, b2}, d0});
      db.vulns.push_back({severity: S,  direct_targets: {d0}, prerequisites: {{a0, nr_a0, b2}, {c0}}}); // ({A0,NR_A0,B2} or C0) -> D0
      db.starting_assets = {nr_a0}; // at the start, A0 has not been revoked
    } else {
      db.itinfra.hyperedges.push_back({{a0, b2}, d0});
      db.vulns.push_back({severity: S,  direct_targets: {d0}, prerequisites: {{a0, b2}, {c0}}}); // ({A0,B2} or C0) -> D0
    }

    db.init_common();

    if (revocations) {
      // the defender only decides to revoke A0 if the cost is less than about 0.102
      //db.restart_machine_costs[nr_a0->id] = 0.102;
      //db.restart_machine_costs[nr_a0->id] = 0.103;
      db.restart_machine_costs[nr_a0->id] = 0.05;
      //db.restart_machine_costs[nr_a0->id] = 10; // the defender can revoke A0
      detect_anomaly_cost = 1;
      investigate_anomaly_cost = 2;

      db.deftacs.push_back({prob: 0.5, cost: 0.1, target: nr_a0, prerequisites: {{b0, nr_a0}}});
      //db.deftacs.push_back({prob: 0.5, cost: 10, target: nr_a0, prerequisites: {{b0, nr_a0}}});
    }
  } CATCH

  // Scenario with multiple issuers
  void init2(GeneratableDatabase &db, bool revocations) try {
    for (int i = 0; i < 9; i++)
      db.assets.push_back({sensitivity: 0});
    db.assets.push_back({sensitivity: 100}); // D0, the goal of the attacker
    Asset *nr_a0 = NULL;
    Asset *nr_a1 = NULL;
    Asset *nr_b2 = NULL;
    Asset *b0_stolen = NULL;
    Asset *a1_imp = NULL;
    if (revocations) {
      for (int i = 0; i < 5; i++)
        db.assets.push_back({sensitivity: 0});
      nr_a0 = &db.assets[10]; // the attacker has this asset iff A0 has not been revoked
      nr_a1 = &db.assets[11]; // the attacker has this asset iff A1 has not been revoked
      nr_b2 = &db.assets[12]; // the attacker has this asset iff B2 has not been revoked
      b0_stolen = &db.assets[13]; // the attacker has this asset iff it stole B2 (instead of convincing the user to share it)
      a1_imp = &db.assets[14]; // the attacker has this asset iff it obtained A1 through impersonation
    }
    Asset *a0 = &db.assets[0];
    Asset *a1 = &db.assets[1];
    Asset *a2 = &db.assets[2];
    Asset *b0 = &db.assets[3];
    Asset *b1 = &db.assets[4];
    Asset *b2 = &db.assets[5];
    Asset *c0 = &db.assets[6];
    Asset *c1 = &db.assets[7];
    Asset *c2 = &db.assets[8];
    Asset *d0 = &db.assets[9];

    db.itinfra.entrance_points = {b0, b1, c0, c1, c2, d0};
    db.itinfra.edges = {
      {b0, a0}, {b0, a1}, {b0, a2}, {c0, c1}, {c0, c2}
    };
    db.itinfra.hyperedges = {
      {{b0, b1}, b2},
      {{c1, c2}, d0}
    };

    db.vulns.push_back({severity: H,  direct_targets: {b0}}); // {} -> B0
    db.vulns.push_back({severity: H,  direct_targets: {b1}}); // {} -> B1
    db.vulns.push_back({severity: S,  direct_targets: {b2}}); // {B0,B1} -> B2
    db.vulns.push_back({severity: S,  direct_targets: {a0}}); // B0 -> A0
    db.vulns.push_back({severity: S,  direct_targets: {a1}}); // (B0 or {A0,B2} or A1_imp) -> A1
    db.vulns.push_back({severity: S,  direct_targets: {a2}}); // (B0 or {A0,B2}) -> A2
    db.vulns.push_back({severity: VH*VH, direct_targets: {c0}}); // {} -> C0
    db.vulns.push_back({severity: VH, direct_targets: {c1}}); // {} -> C1
    db.vulns.push_back({severity: VH, direct_targets: {c2}}); // {} -> C2
    db.vulns.push_back({severity: S,  direct_targets: {c1}, prerequisites: {{c0}}}); // C0 -> C1
    db.vulns.push_back({severity: S,  direct_targets: {c2}, prerequisites: {{c0}}}); // C0 -> C2
    db.vulns.push_back({severity: VH*VH, direct_targets: {d0}}); // {} -> D0

    db.thracts.push_back({motivation: {{d0}}});

    if (revocations) {
      db.itinfra.entrance_points.push_back(b0_stolen);
      db.itinfra.edges.push_back({b0_stolen, b0});
      db.itinfra.edges.push_back({a1_imp, a1});
      db.itinfra.hyperedges.push_back({{a0, nr_a0, b2, nr_b2}, a1_imp});
      db.itinfra.hyperedges.push_back({{a0, nr_a0, b2, nr_b2}, a2});
      db.itinfra.hyperedges.push_back({{a1, nr_a1, a2, b2, nr_b2}, d0});
      db.vulns.push_back({severity: M,  direct_targets: {b0_stolen}}); // {} -> B0_stolen
      db.vulns.push_back({severity: S,  direct_targets: {b0}, prerequisites: {{b0_stolen}}}); // B0_stolen -> B0
      db.vulns.push_back({severity: S,  direct_targets: {a1_imp}}); // {A0,NR_A0,B2,NR_B2} -> A1_imp
      db.vulns.push_back({severity: S,  direct_targets: {d0}, prerequisites: {{a1,nr_a1,a2,b2,nr_b2}, {c1,c2}}}); // ({A1,NR_A1,A2,B2,NR_B2} or {C1,C2}) -> D0
      db.starting_assets = {nr_a0, nr_a1, nr_b2}; // at the start, A0, A1, and B2 have not been revoked
    } else {
      db.itinfra.hyperedges.push_back({{a0, b2}, a1});
      db.itinfra.hyperedges.push_back({{a0, b2}, a2});
      db.itinfra.hyperedges.push_back({{a1, a2, b2}, d0});
      db.vulns.push_back({severity: M,  direct_targets: {b0}}); // {} -> B0
      db.vulns.push_back({severity: S,  direct_targets: {d0}, prerequisites: {{a1,a2,b2}, {c1,c2}}}); // ({A1,A2,B2} or {C1,C2}) -> D0
    }

    db.init_common();

    if (revocations) {
      db.deftacs.push_back({prob: 0.000001, cost: 10, target: nr_a0, prerequisites: {{b0_stolen, nr_a0}}});
      db.deftacs.push_back({prob: 0.1, cost: 2, target: nr_a1, prerequisites: {{b0_stolen, nr_a1}}});
      db.deftacs.push_back({prob: 0.1, cost: 2, target: nr_b2, prerequisites: {{b0_stolen, nr_b2}}});
      db.deftacs.push_back({prob: 0.5, cost: 10, target: nr_a0, prerequisites: {{a1_imp, a1, nr_a0}}});
      db.deftacs.push_back({prob: 1, cost: 0, target: a1_imp, prerequisites: {{a1_imp, a1, nr_a0}}}); // if impersonation is not noticed immediately, remove the possibility to revoke A0 for this reason
    }
  } CATCH

  // choose first branch with probability 1 - p and second with p
  CompRef make_c1_to_2(double p = 0.5) try {
    SCompRef c = SimpleComponent::make();
    Database &db = c->db;
    db.assets.push_back({sensitivity: 0});
    db.assets.push_back({sensitivity: 0});
    db.assets.push_back({sensitivity: 0});
    db.add_edge(c->asset(0), c->asset(1), 1.0, 1 - p);
    db.add_edge(c->asset(0), c->asset(2), 1.0, p);
    db.set_inputs({c->asset(0)});
    db.set_outputs({c->asset(1), c->asset(2)});
    db.init_common();
    return c;
  } CATCH

  template<size_t N> CompRef make_c1_to_(const array<double, N> &p) try {
    SCompRef c = SimpleComponent::make();
    Database &db = c->db;
    for (size_t i = 0; i < N + 1; i++)
      db.assets.push_back({sensitivity: 0});
    vector<Asset *> outputs;
    for (size_t i = 0; i < N; i++) {
      outputs.push_back(c->asset(i + 1));
      db.add_edge(c->asset(0), c->asset(i + 1), 1.0, p[i]);
    }
    db.set_inputs({c->asset(0)});
    db.set_outputs(outputs);
    db.init_common();
    return c;
  } CATCH

  // connect two targets into one
  CompRef make_c2_to_1(double target_sensitivity = 0) {
    SCompRef c = SimpleComponent::make();
    Database &db = c->db;
    db.assets.push_back({sensitivity: 0});
    db.assets.push_back({sensitivity: 0});
    db.assets.push_back({sensitivity: target_sensitivity});
    db.add_edge(c->asset(0), c->asset(2), 1.0);
    db.add_edge(c->asset(1), c->asset(2), 1.0);
    db.set_inputs({c->asset(0), c->asset(1)});
    db.set_outputs({c->asset(2)});
    db.init_common();
    return c;
  }

  CompRef make_user_type(size_t user_type) {
    bool use_cred_0 = (bool)((user_type >> 2) & 1);
    bool use_cred_1 = (bool)((user_type >> 1) & 1);
    bool use_cred_2 = (bool)(user_type & 1);
    double GOV_0 = 0.0, GOV_1 = 0.0, EXT = 0.01;
    double VER_0 = use_cred_0 ? 0.0001 : 0.00001; // different from examples.tex
    double VER_1 = 0.0, VER_2 = 0.0;
    double DEV_i = (user_type >> 4) & 1 ? 1.0 : 0.0;
    double PIN_i = (user_type >> 3) & 1 ? 1.0 : 0.0;
    SCompRef c = SimpleComponent::make();
    Database &db = c->db;
    size_t num_assets = 11 + (size_t)use_cred_1 + (size_t)use_cred_2;
    for (size_t i = 0; i < num_assets; i++)
      db.assets.push_back({sensitivity: 0});

    auto it = db.assets.begin();
    Asset *input = &*it++;
    //Asset *a0 = &*it++; // probably not needed
    Asset *a1 = use_cred_1 ? &*it++ : nullptr;
    Asset *a2 = use_cred_2 ? &*it++ : nullptr;
    Asset *b_DEV = &*it++;
    Asset *b_PIN = &*it++;
    Asset *b_KEY = &*it++;
    Asset *c0 = &*it++;
    Asset *c1 = &*it++;
    Asset *c2 = &*it++;
    Asset *d0 = &*it++;
    Asset *d1 = &*it++;
    Asset *d2 = &*it++;
    Asset *output = &*it++;

    db.add_edge(input, b_DEV, DEV_i);
    db.add_edge(input, b_PIN, PIN_i);
    db.add_hyperedge({b_DEV, b_PIN}, b_KEY, 1.0);
    if (use_cred_1)
      db.add_edge(b_DEV, a1, 1.0);
    if (use_cred_2)
      db.add_edge(b_DEV, a2, 1.0);
    db.add_edge(input, c0, GOV_0);
    db.add_edge(input, c1, GOV_1);
    db.add_edge(input, c2, EXT);
    db.add_edge(input, d0, VER_0);
    db.add_edge(c0, d0, 1.0);
    db.add_edge(input, d1, VER_1);
    if (use_cred_1)
      db.add_hyperedge({a1, b_KEY}, d1, 1.0);
    db.add_edge(c1, d1, 1.0);
    db.add_edge(input, d2, VER_2);
    if (use_cred_2)
      db.add_hyperedge({a2, b_KEY}, d2, 1.0);
    db.add_edge(c2, d2, 1.0);
    db.add_edge(d0, output, 1.0);
    db.add_edge(d1, output, 1.0);
    db.add_edge(d2, output, 1.0);

    db.set_inputs({input});
    db.set_outputs({output});
    db.init_common();
    return c;
  }

  // Multiuser scenario
  void run5(bool find_user_probs) try {
    //const double P_DEV = 0.5, P_PIN = 0.5;
    //const double P_DEV = 0.0, P_PIN = 1.0;
    double P_DEV = 0.75, P_PIN = 0.25;
    array<double, 8> P_CRED = {
    //0.125,0.125,0.125,0.125,0.125,0.125,0.125,0.125
    //0,    0,    0,    0,    0.9,  0,    0.1,  0
      0.01, 0.02, 0.03, 0.04, 0.09, 0.18, 0.27, 0.36
    //000   001   010   011   100   101   110   111
    };

    if (find_user_probs) {
      // in this case, need to make the probability of each user type equal
      P_DEV = 0.5;
      P_PIN = 0.5;
      P_CRED = { 0.125,0.125,0.125,0.125,0.125,0.125,0.125,0.125 };
    }

    // choosing which of the 32 user types to attack
    CompRef c1_to_2_DEV = make_c1_to_2(P_DEV);
    CompRef c1_to_2_PIN = make_c1_to_2(P_PIN);
    CompRef c2_to_4_PIN = c1_to_2_PIN || c1_to_2_PIN;
    CompRef c1_to_8_CRED = make_c1_to_<8>(P_CRED);
    CompRef c4_to_32_CRED = c1_to_8_CRED || c1_to_8_CRED || c1_to_8_CRED || c1_to_8_CRED;

    // the components for user types
    CompRef c1_to_1 = make_c1_to_<1>({1.0}); // dummy component to analyze user types with zero probability faster
    CompRef c_user;
    for (size_t i = 0; i < 32; i++) {
      bool zero_prob = P_CRED[i & 7] == 0 || i & 020 && P_DEV == 0 || !(i & 020) && P_DEV == 1 || i & 010 && P_PIN == 0 || !(i & 010) && P_PIN == 1;
      CompRef c = zero_prob ? c1_to_1 : make_user_type(i);
      if (c_user)
        c_user = c_user || c;
      else
        c_user = c;
    }

    // connecting the 32 targets into one target
    CompRef c2_to_1 = make_c2_to_1();
    CompRef c4_to_2 = c2_to_1 || c2_to_1;
    CompRef c8_to_4 = c4_to_2 || c4_to_2;
    CompRef c8_to_1 = c8_to_4 >> c4_to_2 >> c2_to_1;
    CompRef c32_to_4 = c8_to_1 || c8_to_1 || c8_to_1 || c8_to_1;

    // the whole circuit
    CompRef c = c1_to_2_DEV >> c2_to_4_PIN >> c4_to_32_CRED >> c_user;
    if (!find_user_probs)
      c = c >> c32_to_4 >> c4_to_2 >> make_c2_to_1(1000);

    bool need_probs = true;
    if (find_user_probs)
      need_probs = true;
    c->analyze(need_probs);
    cerr << endl << "Whole graph result:" << endl;
    if (find_user_probs) {
      c->res.print(false);
      size_t n = c->res.probs[0].size();
      for (size_t i = 0; i < n; i++) {
        cerr << "probability of reaching the target if choosing user type " << setw(2) << i << setw(0) << " (";
        for (int j = 4; j >= 0; j--) // size_t is unsigned and gets underflow, so use int
          cerr << ((i >> j) & 1);
        cerr << "): " << n * c->res.probs[0][i] << endl;
      }
    } else
      c->res.print(need_probs);
  } CATCH2(WalletScenario::run5)
}
