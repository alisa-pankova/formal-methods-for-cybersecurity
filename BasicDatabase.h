/*
 * Copyright 2026 Cybernetica AS
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
#ifndef BASIC_DATABASE_H
#define BASIC_DATABASE_H

#include <vector>
#include <string>

using namespace std;

struct Asset;

// a user or an asset that can be a target of an attacker
struct IdOrAsset {
  // helper fields, not in the database, computed from ITInfrastructure:
  vector<vector<Asset *>> vector_assets; // the attacker has to control all assets in at least one of these asset sets for this asset/user to be attackable; if this list is empty then the attacker does not have to control any assets
  bool reachable = false; // is the asset/user reachable from any other asset or from outside

  // helper fields, not in the database:
  vector<Asset *> owned_assets; // the asset itself or the assets owned by the user
  Asset *asset = NULL; // the asset itself or NULL if it is a user
};

struct Identity : IdOrAsset {
  int userID;
};

struct Asset : IdOrAsset {
  int id;
  double sensitivity; // the reward for the attacker (cost for the defender) if this asset is compromised
  Identity *owner; // the identity controlling the asset, NULL if no owner

  // helper field, not in the database:
  vector<int> targeting_vulns; // indices of vulnerabilities targeting this asset, only used if intervals_used == true
  bool is_hyperedge_source = false; // is the asset a source of a hyperedge
};

struct Vulnerability {
  double severity; // probability of getting control over an asset if this vulnerability is exploited
  pair<double, double> severity_interval; // min and max value of severity if not known exactly (severity must be left as 0)
  vector<IdOrAsset *> direct_targets; // all assets and users directly attacked by this vulnerability, not including assets only indirectly affected through users
  // if a user is successfully attacked, all assets owned by the user are compromised
  vector<vector<Asset *>> prerequisites; // the attacker has to control all assets in at least one of these asset sets for this vulnerability to be attackable; if this list is empty then the attacker does not have to control any assets (other than for the targets to be reachable)

  // helper field, not in the database:
  vector<Asset *> all_assets; // all assets affected by this vulnerability, both directly and through users
  vector<int> threats; // indices of threats exploiting this vulnerability
  bool is_target = false; // is this vulnerability a target of any attacker's tactic
  double tmp_likelihood = 1.0; // used to temporarily store the likelihood before it is added to the attacker's tactic in GeneratableDatabase::init_common()
};

struct Threat {
  double likelihood; // proportional to the probability of the attacker choosing this threat from all available threats
  Vulnerability *impact; // which vulnerability is exploited in this threat
  vector<int> vector_required_def_measures; // which defensive measures must be used for this (version of the) threat to be available
  vector<int> vector_forbidden_def_measures; // which defensive measures must not be used for this (version of the) threat to be available

  // helper field, not in the database:
  bool reachable; // are all the targets of the threat reachable from any asset or from outside
};

struct AttackTechnique {
  vector<pair<double, Threat *> > tactic; // the likelihood of each threat if the attacker uses this tactic, similar to Threat.likelihood, which is used if there is no concrete tactic
  vector<pair<pair<double, double>, Threat *> > interval_tactic; // a tactic where the likelihood is not known exactly but is given as an interval where it can be (min and max value)
  double skip_lh; // the likelihood that the attacker skips a step when using this attack technique
  pair<double, double> skip_lh_interval; // min and max value of skip_lh if not known exactly (skip_lh must then be left as 0)
};

struct ThreatActor {
  vector<vector<Asset *> > motivation; // the attacker wants to compromise all assets in at least one of the elements of `motivation`.
};

struct TTP {
  ThreatActor *actor; // an attacker
  AttackTechnique *technique; // the technique used by the given attacker

  double threat_likelihood(Threat *t); // the likelihood of the threat t for this attacker and technique
  double threat_likelihood_min(Threat *t); // the minimum likelihood of the threat t for this attacker and technique (when intervals are used)
  double threat_likelihood_max(Threat *t); // the maximum likelihood of the threat t for this attacker and technique (when intervals are used)
  double skip_likelihood(); // the likelihood of skipping a step for this attacker and technique
  double skip_likelihood_min(); // the minimum likelihood of skipping a step for this attacker and technique (when intervals are used)
  double skip_likelihood_max(); // the maximum likelihood of skipping a step for this attacker and technique (when intervals are used)
};

struct ITInfrastructure {
  vector<IdOrAsset *> entrance_points; // assets/users reachable from outside, i.e. the attacker does not have to control any other assets to attack these assets/users
  vector<pair<Asset *, IdOrAsset *> > edges; // edges (a_i, a_j) where the asset a_i can be used by the attacker to attack the asset/user a_j
  vector<pair<vector<Asset *>, IdOrAsset *> > hyperedges; // hyperedges (A_i, a_j) where the asset set A_i can be used by the attacker to attack the asset/user a_j
  // vertices of the graph come from the tables Asset and Identity
  // users cannot be starting vertices of edges, but can be ending vertices of edges or entrance points
};

struct DefenseTactic {
  double prob; // the probability that the defender uses this tactic if the prerequisites are fulfilled
  double cost; // the cost for the defender for using this tactic
  Asset *target; // the attacker loses this asset (if it has it) if the defense tactic is used
  vector<vector<Asset *>> prerequisites; // the attacker has to control all assets in at least one of these asset sets for this defense tactic to be available; if this list is empty then the attacker does not have to control any assets
};

// all the needed tables in the database
struct BasicDatabase {
  vector<Identity> identities;
  vector<Asset> assets;
  vector<Vulnerability> vulns;
  vector<Threat> threats;
  vector<AttackTechnique> attechs;
  vector<ThreatActor> thracts;
  vector<TTP> ttps;
  ITInfrastructure itinfra;

  vector<DefenseTactic> deftacs;

  // the cost of restarting each machine (asset); if negative (e.g. -1) then it cannot be restarted
  vector<double> restart_machine_costs;

  bool can_restart(int i) { return restart_machine_costs[i] >= 0; }
};
#endif
