/*
 * Copyright 2026 Cybernetica AS
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
 
#include "globals.h"
#include "PrismDatabase.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <set>
#include <limits>

using namespace std;

// PRISM boolean expression for determining whether the attacker controls this asset
string attacker_controls_asset(Asset *a) {
  ostringstream oss;
  if (linear_model)
    oss << "m = " << a->id;
  else
    oss << "m" << a->id;
  return oss.str();
}

// PRISM boolean expression for determining whether the attacker controls all assets in this set
string attacker_controls_all_assets(vector<Asset *> &v) {
  ostringstream oss;
  for (int j = 0; j < v.size(); j++) {
    if (j > 0)
      oss << " & ";
    oss << attacker_controls_asset(v[j]);
  }
  return oss.str();
}

// PRISM boolean expression for determining whether the attacker controls all assets in at least one of these sets
string attacker_controls_all_assets_in_any_of_the_sets(vector<vector<Asset *>> &v) {
  ostringstream oss;
  for (int j = 0; j < v.size(); j++) {
    if (j > 0)
      oss << " | ";
    oss << attacker_controls_all_assets(v[j]);
  }
  return oss.str();
}

// PRISM boolean expression for determining whether the target of this attacker has been reached
string ttp_target_str(TTP &t) {
  ostringstream oss;
  for (int i = 0; i < t.actor->motivation.size(); i++) {
    if (i > 0)
      oss << " | ";
    oss << attacker_controls_all_assets(t.actor->motivation[i]);
  }
  return oss.str();
}

// PRISM boolean expression for determining whether the threat is available
string threat_is_available(Threat &t) {
  if (!t.reachable)
    return "false";

  ostringstream oss;
  bool e = true;
  for (int i = 0; i < t.vector_required_def_measures.size(); i++) {
    if (e)
      e = false;
    else
      oss << " & ";
    oss << "d" << t.vector_required_def_measures[i];
  }
  for (int i = 0; i < t.vector_forbidden_def_measures.size(); i++) {
    if (e)
      e = false;
    else
      oss << " & ";
    oss << "!d" << t.vector_forbidden_def_measures[i];
  }
  // each of the directly targeted assets/users of this threat must be accessible from the currently controlled assets
  for (IdOrAsset *a : t.impact->direct_targets) {
    if (!a->vector_assets.empty()) {
      if (e)
        e = false;
      else
        oss << " & ";
      if (a->vector_assets.size() >= 2)
        oss << "(";
      oss << attacker_controls_all_assets_in_any_of_the_sets(a->vector_assets);
      if (a->vector_assets.size() >= 2)
        oss << ")";
    }
  }
  // at least one of the directly or indirectly targeted assets of this threat must not have been reached yet
  if (!t.impact->all_assets.empty()) {
    if (e)
      e = false;
    else
      oss << " & ";
    if (t.impact->all_assets.size() >= 2)
      oss << "(";
    for (int i = 0; i < t.impact->all_assets.size(); i++) {
      if (i > 0)
        oss << " | ";
      if (linear_model)
        oss << "m != " << t.impact->all_assets[i]->id;
      else
        oss << "!m" << t.impact->all_assets[i]->id;
    }
    if (t.impact->all_assets.size() >= 2)
      oss << ")";
  }
  // the attacker has to control all assets in at least one of the prerequisite assets (unless the list of prerequisites is empty)
  if (!t.impact->prerequisites.empty()) {
    if (e)
      e = false;
    else
      oss << " & ";
    if (t.impact->prerequisites.size() >= 2)
      oss << "(";
    oss << attacker_controls_all_assets_in_any_of_the_sets(t.impact->prerequisites);
    if (t.impact->prerequisites.size() >= 2)
      oss << ")";
  }
  if (e)
    oss << "true";
  return oss.str();
}

void PrismDatabase::generate_prism(const char *fname) try {
  ofstream fout(fname);

  if (nondet)
    fout << "mdp" << endl << endl;
  else
    fout << "dtmc" << endl << endl;

  if (!deftacs.empty()) {
    fout << "// avail_deftac_i is true iff the defense tactic i is available" << endl;
    for (int i = 0; i < deftacs.size(); i++)
      fout << "formula avail_deftac_" << i << " = " << (deftacs[i].prerequisites.empty() ? "true" : attacker_controls_all_assets_in_any_of_the_sets(deftacs[i].prerequisites)) << ";" << endl;
  }

  if (nondet) {
    fout << "// lhi is the likelihood of threat i, true if the current attacker has this threat in its tactic with positive likelihood" << endl;
    for (int i = 0; i < threats.size(); i++) {
      //fout << "const double lh" << i << " = " << threats[i].likelihood << ";" << endl;
      fout << "formula lh" << i << " = ";
      for (int j = 0; j < ttps.size(); j++) {
        if (j > 0)
          fout << " | ";
        //fout << "(ica = " << j << " ? " << (ttps[j].threat_likelihood(&threats[i]) > 0 ? "true" : "false") << " : false)";
        if (intervals_used && ttps[j].threat_likelihood_max(&threats[i]) > 0 || !intervals_used && ttps[j].threat_likelihood(&threats[i]) > 0)
          fout << "ica = " << j;
        else
          fout << "false";
      }
      fout << ";" << endl;
    }
    fout << "// the likelihood of skip" << endl;
    fout << "formula lh_skip = ";
    for (int j = 0; j < ttps.size(); j++) {
      if (j > 0)
        fout << " | ";
      bool positive_likelihood = intervals_used && ttps[j].skip_likelihood_max() > 0 || !intervals_used && ttps[j].skip_likelihood() > 0;
      if (positive_likelihood)
        fout << "ica = " << j;
      else
        fout << "false";
      //fout << "(ica = " << j << " ? " << (positive_likelihood ? "true" : "false") << " : false)";
    }
    fout << ";" << endl;
  } else if (intervals_used) {
    fout << "// lhi_min is the minimum likelihood of threat i" << endl;
    for (int i = 0; i < threats.size(); i++) {
      fout << "formula lh" << i << "_min = ";
      for (int j = 0; j < ttps.size(); j++) {
        if (j > 0)
          fout << " + ";
        fout << "(ica = " << j << " ? " << ttps[j].threat_likelihood_min(&threats[i]) << " : 0)";
      }
      fout << ";" << endl;
    }
    fout << "// lhi_max is the maximum likelihood of threat i" << endl;
    for (int i = 0; i < threats.size(); i++) {
      fout << "formula lh" << i << "_max = ";
      for (int j = 0; j < ttps.size(); j++) {
        if (j > 0)
          fout << " + ";
        fout << "(ica = " << j << " ? " << ttps[j].threat_likelihood_max(&threats[i]) << " : 0)";
      }
      fout << ";" << endl;
    }
    fout << "// the minimum likelihood of skip" << endl;
    fout << "formula lh_skip_min = ";
    for (int j = 0; j < ttps.size(); j++) {
      if (j > 0)
        fout << " + ";
      fout << "(ica = " << j << " ? " << ttps[j].skip_likelihood_min() << " : 0)";
    }
    fout << ";" << endl;
    fout << "// the maximum likelihood of skip" << endl;
    fout << "formula lh_skip_max = ";
    for (int j = 0; j < ttps.size(); j++) {
      if (j > 0)
        fout << " + ";
      fout << "(ica = " << j << " ? " << ttps[j].skip_likelihood_max() << " : 0)";
    }
    fout << ";" << endl;
  } else {
    fout << "// lhi is the likelihood of threat i" << endl;
    for (int i = 0; i < threats.size(); i++) {
      //fout << "const double lh" << i << " = " << threats[i].likelihood << ";" << endl;
      fout << "formula lh" << i << " = ";
      for (int j = 0; j < ttps.size(); j++) {
        if (j > 0)
          fout << " + ";
        fout << "(ica = " << j << " ? " << ttps[j].threat_likelihood(&threats[i]) << " : 0)";
      }
      fout << ";" << endl;
    }
    fout << "// the likelihood of skip" << endl;
    fout << "formula lh_skip = ";
    for (int j = 0; j < ttps.size(); j++) {
      if (j > 0)
        fout << " + ";
      fout << "(ica = " << j << " ? " << ttps[j].skip_likelihood() << " : 0)";
    }
    fout << ";" << endl;
  }

  fout << "// has the current attacker reached its target" << endl;
  fout << "formula ca_target_reached = ";
  for (int j = 0; j < ttps.size(); j++) {
    if (j > 0)
      fout << " | ";
    fout << "ica = " << j << " & target" << j;
  }
  fout << ";" << endl;
  if (!linear_model) {
    fout << "// is the current attacker caught" << endl;
    fout << "formula ca_caught = ";
    for (int j = 0; j < ttps.size(); j++) {
      if (j > 0)
        fout << " | ";
      fout << "ica = " << j << " & c" << j;
    }
    fout << ";" << endl;
    fout << "// the number of caught attackers" << endl;
    fout << "formula na_caught = ";
    for (int j = 0; j < ttps.size(); j++) {
      if (j > 0)
        fout << " + ";
      fout << "(c" << j << " ? 1 : 0)";
    }
    fout << ";" << endl;
  }
  fout << "// ai is true iff threat i is available to the attacker from the current state and not yet controlled by the attacker (the attacker can attack it in one step)" << endl;
  for (int i = 0; i < threats.size(); i++)
    fout << "formula a" << i << " = " << threat_is_available(threats[i]) << ";" << endl;

  fout << "// total likelihood of available threats and skip" << endl;
  if (nondet) {
    fout << "formula total_available_lh = lh_skip";
    for (int i = 0; i < threats.size(); i++) {
      fout << " | ";
      fout << "a" << i << " & " << "lh" << i << "";
    }
    fout << ";" << endl;
  } else if (intervals_used) {
    fout << "formula total_available_lh_min = lh_skip_min";
    for (int i = 0; i < threats.size(); i++) {
      fout << " + ";
      fout << "(a" << i << " ? " << "lh" << i << "_min : 0)";
    }
    fout << ";" << endl;
    fout << "formula total_available_lh_max = lh_skip_max";
    for (int i = 0; i < threats.size(); i++) {
      fout << " + ";
      fout << "(a" << i << " ? " << "lh" << i << "_max : 0)";
    }
    fout << ";" << endl;
  } else {
    fout << "formula total_available_lh = lh_skip";
    for (int i = 0; i < threats.size(); i++) {
      fout << " + ";
      fout << "(a" << i << " ? " << "lh" << i << " : 0)";
    }
    fout << ";" << endl;
  }

  fout << "// the attacker always skips a step if it has reached its target, has been caught, or has no available threats" << endl;
  if (linear_model) {
    if (nondet)
      fout << "formula threats_possible = !ca_target_reached;" << endl;
    else if (intervals_used)
      fout << "formula threats_possible = !ca_target_reached & total_available_lh_max > 0;" << endl;
    else
      fout << "formula threats_possible = !ca_target_reached & total_available_lh > 0;" << endl;
  } else {
    if (nondet)
      fout << "formula threats_possible = !ca_target_reached & !ca_caught;" << endl;
    else if (intervals_used)
      fout << "formula threats_possible = !ca_target_reached & !ca_caught & total_available_lh_max > 0;" << endl;
    else
      fout << "formula threats_possible = !ca_target_reached & !ca_caught & total_available_lh > 0;" << endl;
  }
  if (nondet)
    fout << "// p_threat_i is true if the attacker may choose threat i on the next step" << endl;
  else
    fout << "// p_threat_i is the probability that the attacker chooses threat i on the next step" << endl;
  if (nondet)
    for (int i = 0; i < threats.size(); i++)
      fout << "formula p_threat_" << i << " = a" << i << " & threats_possible & lh" << i << ";" << endl;
  else if (intervals_used)
    for (int i = 0; i < threats.size(); i++) {
      fout << "formula p_threat_" << i << "_min = a" << i << " & threats_possible ? lh" << i << "_min / (total_available_lh_max - lh" << i << "_max + lh" << i << "_min) : 0;" << endl;
      fout << "formula p_threat_" << i << "_max = a" << i << " & threats_possible ? lh" << i << "_max / (total_available_lh_min - lh" << i << "_min + lh" << i << "_max) : 0;" << endl;
    }
  else
    for (int i = 0; i < threats.size(); i++)
      fout << "formula p_threat_" << i << " = a" << i << " & threats_possible ? lh" << i << " / total_available_lh : 0;" << endl;

  if (nondet)
    fout << "// true if the attacker may skip the next step" << endl;
  else
    fout << "// the probability that the attacker skips the next step" << endl;
  if (nondet)
    fout << "formula p_skip = !threats_possible | lh_skip;" << endl;
  else if (intervals_used) {
    fout << "formula p_skip_min = threats_possible ? lh_skip_min / (total_available_lh_max - lh_skip_max + lh_skip_min) : 1;" << endl;
    fout << "formula p_skip_max = threats_possible ? lh_skip_max / (total_available_lh_min - lh_skip_min + lh_skip_max) : 1;" << endl;
  } else
    fout << "formula p_skip = threats_possible ? lh_skip / total_available_lh : 1;" << endl;

  if (nondet)
    fout << "// p_vuln_i is true if the attacker may attack vulnerability i on the next step" << endl;
  else
    fout << "// p_vuln_i is the probability that the attacker attacks vulnerability i on the next step" << endl;
  for (int i = 0; i < vulns.size(); i++) {
    if (nondet) {
      fout << "formula p_vuln_" << i << " = ";
      for (int j = 0; j < vulns[i].threats.size(); j++) {
        if (j > 0)
          fout << " | ";
        fout << "p_threat_" << vulns[i].threats[j];
      }
      if (vulns[i].threats.empty())
        fout << "false";
      fout << ";" << endl;
    } else if (intervals_used) {
      fout << "formula p_vuln_" << i << "_min = ";
      for (int j = 0; j < vulns[i].threats.size(); j++) {
        if (j > 0)
          fout << " + ";
        fout << "p_threat_" << vulns[i].threats[j] << "_min";
      }
      if (vulns[i].threats.empty())
        fout << "0";
      fout << ";" << endl;
      fout << "formula p_vuln_" << i << "_max = ";
      for (int j = 0; j < vulns[i].threats.size(); j++) {
        if (j > 0)
          fout << " + ";
        fout << "p_threat_" << vulns[i].threats[j] << "_max";
      }
      if (vulns[i].threats.empty())
        fout << "0";
      fout << ";" << endl;
    } else {
      fout << "formula p_vuln_" << i << " = ";
      for (int j = 0; j < vulns[i].threats.size(); j++) {
        if (j > 0)
          fout << " + ";
        fout << "p_threat_" << vulns[i].threats[j];
      }
      if (vulns[i].threats.empty())
        fout << "0";
      fout << ";" << endl;
    }
  }

  if (intervals_used || nondet) {
    fout << "// the probability that the attacker's attack against the chosen vulnerability (with index icv) is successful" << endl;
    if (intervals_used) {
      fout << "formula psa_min = ";
      for (int i = 0; i < vulns.size(); i++) {
        if (i > 0)
          fout << " + ";
        fout << "(icv = " << i << " ? " << vulns[i].severity_interval.first << " : 0)";
      }
      fout << ";" << endl;
      fout << "formula psa_max = ";
      for (int i = 0; i < vulns.size(); i++) {
        if (i > 0)
          fout << " + ";
        fout << "(icv = " << i << " ? " << vulns[i].severity_interval.second << " : 0)";
      }
      fout << ";" << endl;
    } else {
      fout << "formula psa = ";
      for (int i = 0; i < vulns.size(); i++) {
        if (i > 0)
          fout << " + ";
        fout << "(icv = " << i << " ? " << vulns[i].severity << " : 0)";
      }
      fout << ";" << endl;
    }
    fout << "// the probability that the attacker's attack against the chosen vulnerability (with index icv) fails" << endl;
    if (intervals_used) {
      fout << "formula paf_min = 1 - psa_max;" << endl;
      fout << "formula paf_max = 1 - psa_min;" << endl;
      if (linear_model) {
        fout << "formula paf_some_min = ica = na-1 ? 0 : paf_min;" << endl;
        fout << "formula paf_some_max = ica = na-1 ? 0 : paf_max;" << endl;
        fout << "formula paf_all_min = ica = na-1 ? paf_min : 0;" << endl;
        fout << "formula paf_all_max = ica = na-1 ? paf_max : 0;" << endl;
      } else {
        fout << "formula paf_some_min = na_caught = na-1 ? 0 : paf_min; // some but not all attackers have been caught" << endl;
        fout << "formula paf_some_max = na_caught = na-1 ? 0 : paf_max; // some but not all attackers have been caught" << endl;
        fout << "formula paf_all_min = na_caught = na-1 ? paf_min : 0; // all attackers have been caught" << endl;
        fout << "formula paf_all_max = na_caught = na-1 ? paf_max : 0; // all attackers have been caught" << endl;
      }
    } else {
      fout << "formula paf = 1 - psa;" << endl;
      if (linear_model) {
        fout << "formula paf_some = ica = na-1 ? 0 : paf;" << endl;
        fout << "formula paf_all = ica = na-1 ? paf : 0;" << endl;
      } else {
        fout << "formula paf_some = na_caught = na-1 ? 0 : paf; // some but not all attackers have been caught" << endl;
        fout << "formula paf_all = na_caught = na-1 ? paf : 0; // all attackers have been caught" << endl;
      }
    }
    fout << "// ctmi is true iff machine i is a (direct or indirect) target of the chosen vulnerability (with index icv)" << endl;
    for (int i = 0; i < assets.size(); i++) {
      fout << "formula ctm" << i << " = ";
      bool e = true;
      for (int j : assets[i].targeting_vulns) {
        if (e)
          e = false;
        else
          fout << " | ";
        fout << "icv = " << j;
      }
      if (e)
        fout << "false";
      fout << ";" << endl;
    }
    if (linear_model) {
      fout << "formula ctm = ";
      for (int i = 0; i < assets.size(); i++) {
        if (i > 0)
          fout << " + ";
        fout << "(ctm" << i << " ? " << i << " : 0)";
      }
      fout << ";" << endl;
    }
  } else {
    fout << "// psa_vuln_i is the probability that the attacker successfully attacks vulnerability i on the next step" << endl;
    for (int i = 0; i < vulns.size(); i++)
      fout << "formula psa_vuln_" << i << " = " << vulns[i].severity << " * p_vuln_" << i << ";" << endl;
    fout << "// probability that the attack fails on the next step" << endl;
    fout << "formula paf = 1";
    for (int i = 0; i < vulns.size(); i++)
      fout << " - psa_vuln_" << i;
    fout << " - p_skip;" << endl;
  }

  fout << "// the number of attackers" << endl;
  fout << "const int na = " << ttps.size() << ";" << endl;
  fout << "// the number of vulnerabilities" << endl;
  fout << "const int num_vuln = " << vulns.size() << ";" << endl;
  fout << "// total number of machines" << endl;
  fout << "const int nm = " << assets.size() << ";" << endl;
  fout << "// number of machines controlled by the attacker" << endl;
  fout << "formula nmc = ";
  if (linear_model)
    fout << "(m = -1 ? 0 : 1)";
  else
    for (int i = 0; i < assets.size(); i++) {
      if (i > 0)
        fout << " + ";
      fout << "(m" << i << " ? 1 : 0)";
    }
  fout << ";" << endl;

  bool any_restartable_machine = false;
  for (int i = 0; i < assets.size(); i++)
    if (can_restart(i))
      any_restartable_machine = true;

  if (any_restartable_machine)
    fout << "\n\
// probability of detecting an anomaly if the defender tries to detect it;\n\
// the more machines the attacker controls, the higher the probability of causing an anomaly\n\
// but an anomaly can also be caused by other things than the attacker\n\
// so there is a small probability of detecting an anomaly even if the attacker controls no machines\n\
formula pad = 0.1 + 0.7 * nmc / nm;\n\
\n\
// probability of detecting an incident if the defender tries to detect it;\n\
// higher cost but lower chance of false positive and false negative\n\
formula pid = (nmc >= 1 ? 0.5 : 0.01) + 0.48 * nmc / nm;\n\
// the condition for choosing to detect anomalies\n\
formula detect_anomaly_cond = s = DEFEND" << (deftacs.empty() ? "" : " & idt = -1") << " & d_an_in >= D_ANOMALY;\n\
// the condition for choosing to investigate an anomaly\n\
formula investigate_anomaly_cond = s = ANOMALY & d_an_in = D_INCIDENT;\n\
\n\
// values of d_an_in: \n\
const int D_NO_ANOMALY = 0; // the defender does not detect anomalies or incidents\n\
const int D_ANOMALY = 1; // the defender detects anomalies but not incidents, at some cost\n\
const int D_INCIDENT = 2; // the defender detects both anomalies and incidents, at more cost\n\
\n";
  fout << "\n\
// state names for the different values of s: \n\
const int CAUGHT = 0; // the attacker failed and got caught\n\
const int FINAL = -1; // the final state after the costs have been calculated\n\
const int CHOOSING = -2; // the defender is choosing which defensive measures to apply (when no attack is started yet)\n\
const int QUIT = -3; // the attacker quit the attack after reaching the maximum number of steps\n\
const int SUCCESS = -4; // the attacker successfully reached the goal\n\
// the attacker can attack in the following states (s >= ATTACK):\n\
const int ATTACK = 1; // the attacker is attacking" << (intervals_used || nondet ? ", choosing what to attack": "") << "\n";
  int state_no = 1;
  if (intervals_used || nondet)
    fout << "const int ATTACK2 = " << ++state_no << "; // the attacker is attacking, determining if the attack was successful\n";
  fout << "const int DEFEND = " << ++state_no << "; // the defender may be defending\n";
  if (any_restartable_machine) {
    fout << "const int ANOMALY = " << ++state_no << "; // the defender detected an anomaly\n";
    fout << "const int NO_ANOMALY = " << ++state_no << "; // the defender looked for anomalies or incidents but detected none\n";
    fout << "const int INCIDENT = " << ++state_no << "; // the defender detected an incident\n";
    fout << "const int RESTART_MACHINES = " << ++state_no << "; // the defender can restart some machines\n";
  }
  fout << "\n\
" << (limited_steps ? "const int max_steps = 5;\n\n" : "") << "\
module network\n\
\t// s is the state, the possible values of s are described above\n\
\ts : [-4.." << state_no << "];\n\
\n\
\t// the index of the current attacker, used only during attack and defense, otherwise ica = 0\n\
\tica : [0 .. (na > 1 ? na-1 : 1)];\n\
\n\
" << (intervals_used || nondet ? "\
\t// the index of the vulnerability that the attacker is currently attacking, used only when s = ATTACK2, otherwise icv = 0\n\
\ticv : [0 .. (num_vuln > 1 ? num_vuln-1 : 1)];\n\
\n\
" : "");

  if (!deftacs.empty()) {
    fout << "\t// the index of the current defense tactic, used only when s = DEFEND, otherwise idt = -1\n";
    fout << "\tidt : [-1 .. " << deftacs.size() - 1 << "];\n\n";
  }

  if (limited_steps) {
    fout << "\t// number of attacking steps done, if it reaches max_steps without the attacker reaching the target machine, the attacker quits the attack\n";
    fout << "\tsteps : [0..max_steps];\n\n";
  }

  if (linear_model) {
    fout << "\t// m = i iff the attacker controls machine i" << endl;
    fout << "\t// m = -1 iff the attacker does not control any machines" << endl;
    fout << "\tm : [-1 .. nm-1];" << endl;
  } else {
    fout << "\t// mi is true iff the attacker controls machine i" << endl;
    for (int i = 0; i < assets.size(); i++)
      fout << "\tm" << i << " : bool;" << endl;
  }

  if (!linear_model) {
    fout << endl << "\t// ci is true iff the attacker i has been caught" << endl;
    for (int i = 0; i < ttps.size(); i++)
      fout << "\tc" << i << " : bool;" << endl;
  }

  fout << endl << "\t// di is true iff the defender has applied the defensive measure i" << endl;
  for (int i = 0; i < num_dm; i++)
    fout << "\td" << i << " : bool;" << endl;

  if (any_restartable_machine) {
    fout << endl << "\t// whether the defender will restart a certain machine, after possible anomaly/incident detections (if any)" << endl;
    for (int i = 0; i < assets.size(); i++)
      if (can_restart(i))
        fout << "\td_restart_m" << i << " : bool;" << endl;
    fout << endl << "\t// whether the defender will detect anomalies and/or incidents, the possible values are described above" << endl;
    fout << "\td_an_in : [0..2];" << endl;
  }

  fout << "\n\
\t// compute the cost of defensive measures chosen by the defender\n\
\t[start_attack] s = CHOOSING -> (s' = ATTACK);\n\
\t\n\
\t// calculate the cost\n\
\t[succeeded] s = SUCCESS -> (s' = FINAL) & " << reset_m << ";\n\
\t[caught] s = CAUGHT -> (s' = FINAL) & " << reset_m << ";\n\
\t[quit] s = QUIT -> (s' = FINAL) & " << reset_m << ";\n\
\t[final] s = FINAL -> true;\n";
  if (any_restartable_machine) {
    fout << "\n\
\t// defending step\n\
\t// the defender may detect anomalies that can be caused by the attacker or by something else;\n\
\t// after detecting an anomaly, the defender may take some actions like restarting some machines;\n\
\t[detect_anomaly] detect_anomaly_cond -> pad : (s' = ANOMALY) + (1 - pad) : (s' = NO_ANOMALY);\n\
\t// if an anomaly was detected, the defender may further investigate it (at higher cost) to determine if it is an incident;\n\
\t// if an incident is detected, the defender may take some actions;\n\
\t[investigate_anomaly] investigate_anomaly_cond -> pid : (s' = INCIDENT) + (1 - pid) : (s' = NO_ANOMALY);\n\
\t[no_anomaly] s = NO_ANOMALY -> (s' = ATTACK);\n\
\n\
\t[finish_detection] s = DEFEND" << (deftacs.empty() ? "" : " & idt = -1") << " & d_an_in = D_NO_ANOMALY | s = ANOMALY & d_an_in = D_ANOMALY | s = INCIDENT -> (s' = RESTART_MACHINES);\n\
\t// the defender may restart some machines at some cost, which removes the attacker from that machine (if the attacker is there)\n\
";

    fout << "\t[restart_machines] s = RESTART_MACHINES -> (s' = ATTACK)";
    if (linear_model) {
      fout << " & (m' = ";
      bool e = true;
      for (int i = 0; i < assets.size(); i++) {
        if (can_restart(i)) {
          if (e)
            e = false;
          else
            fout << " | ";
          fout << "m = " << i << " & d_restart_m" << i;
        }
      }
      if (e)
        fout << "false";
      fout << " ? -1 : m)";
    } else
      for (int i = 0; i < assets.size(); i++)
        if (can_restart(i))
          fout << " & (m" << i << "' = m" << i << " & !d_restart_m" << i << ")";
    fout << ";" << endl;
  } else
    fout << "\n\t[finish_detection] s = DEFEND" << (deftacs.empty() ? "" : " & idt = -1") << " -> (s' = ATTACK);" << endl;
  fout << endl;

  if (!deftacs.empty()) {
    fout << "\t// defense tactics" << endl;
    for (int i = 0; i < deftacs.size(); i++) {
      int i_next = i + 1 == deftacs.size() ? -1 : i + 1;
      fout << "\t[defense_tactic] s = DEFEND & idt = " << i << " & !avail_deftac_" << i << " -> (idt' = " << i_next << ");" << endl; 
      fout << "\t[defense_tactic] s = DEFEND & idt = " << i << " &  avail_deftac_" << i << " -> " <<
        deftacs[i].prob << " : (idt' = " << i_next << ") & (m" << deftacs[i].target->id << "' = false) + " << 1 - deftacs[i].prob << " : (idt' = " << i_next << ");" << endl; 
    }
    fout << endl;
  }

  fout << "\t// attacking step" << endl;
  if (linear_model) {
    fout << "\t[attack] s = ATTACK & ca_target_reached & ica = na-1 ->" << endl;
    fout << "\t\t(s' = SUCCESS) & (ica' = 0)" << reset_dcs << "; // finish the successful attack" << endl;
    fout << "\t[attack] s = ATTACK & ca_target_reached & ica < na-1 ->" << endl;
    fout << "\t\t(ica' = ica + 1) & (steps' = 0) & (m' = -1);" << endl;
    fout << "\t[attack] s = ATTACK & !ca_target_reached & steps = max_steps & ica = na-1 ->" << endl;
    fout << "\t\t(s' = QUIT)" << reset_dcs << "; // quit the attack" << endl;
    fout << "\t[attack] s = ATTACK & !ca_target_reached & steps = max_steps & ica < na-1 ->" << endl;
    fout << "\t\t(ica' = ica + 1) & (steps' = 0) & (m' = -1);" << endl;
    if (!nondet)
      fout << "\t[attack] s = ATTACK & !ca_target_reached & steps < max_steps ->" << endl;
    for (int i = 0; i < vulns.size(); i++)
      if (vulns[i].is_target) {
        if (vulns[i].all_assets.size() > 1) {
          THROW_STREAM(<< "ERROR: Vulnerability " << i << " affects more than one asset (directly or through a user). This is not supported in the linear model.");
        }
        if (vulns[i].all_assets.size() == 0) {
          THROW_STREAM(<< "ERROR: Vulnerability " << i << " does not affect any assets (directly or through a user). This is not supported in the linear model.");
        }
        if (nondet)
          fout << "\t[attack] s = ATTACK & !ca_target_reached & steps < max_steps & p_vuln_" << i << " -> (s' = ATTACK2) & (icv' = " << i << ");" << endl; 
        else if (intervals_used)
          fout << "\t\t[p_vuln_" << i << "_min, p_vuln_" << i << "_max] : (s' = ATTACK2) & (icv' = " << i << ")"; 
        else {
          fout << "\t\tpsa_vuln_" << i << " : (s' = DEFEND) & (steps' = steps + 1)"; 
          for (Asset *a : vulns[i].all_assets)
            fout << " & (m' = " << a->id << ")";
        }
        if (!nondet)
          fout << " +" << endl;
      } else {
        fout << "\t\t// vulnerability " << i << " is not a target of any attacker's tactic" << endl;
      }
    if (intervals_used || nondet) {
      if (nondet)
        fout << "\t[attack] s = ATTACK & !ca_target_reached & steps < max_steps & p_skip -> (steps' = steps + 1);" << endl; 
      else
        fout << "\t\t[p_skip_min, p_skip_max] : (steps' = steps + 1);" << endl; 
      if (intervals_used) {
        fout << "\t[attack2] s = ATTACK2 ->" << endl;
        fout << "\t\t[psa_min, psa_max] : (icv' = 0) & (s' = DEFEND) & (steps' = steps + 1) & (m' = ctm) +" << endl;
        fout << "\t\t[paf_some_min, paf_some_max] : (icv' = 0) & (s' = ATTACK) & (ica' = ica + 1) & (steps' = 0) & (m' = -1) +" << endl;
        fout << "\t\t[paf_all_min, paf_all_max] : (icv' = 0) & (s' = CAUGHT) & (ica' = 0)" << reset_dcs << ";" << endl;
      } else {
        //fout << "\t\tpsa : (icv' = 0) & (s' = DEFEND) & (steps' = steps + 1) & (m' = ctm) +" << endl;
        //fout << "\t\t1 - paf_some - paf_all : (icv' = 0) & (s' = DEFEND) & (steps' = steps + 1) & (m' = ctm) +" << endl;
        //fout << "\t\tpaf_some : (icv' = 0) & (s' = ATTACK) & (ica' = ica + 1) & (steps' = 0) & (m' = -1) +" << endl;
        //fout << "\t\tpaf_all : (icv' = 0) & (s' = CAUGHT) & (ica' = 0)" << reset_dcs << ";" << endl;
        // For some reason, PRISM requires steps < max_steps here although this always holds when s = ATTACK2
        fout << "\t[attack2] s = ATTACK2 & ica != na-1 & steps < max_steps ->" << endl;
        fout << "\t\tpsa : (icv' = 0) & (s' = DEFEND) & (steps' = steps + 1) & (m' = ctm) +" << endl;
        fout << "\t\t1-psa : (icv' = 0) & (s' = ATTACK) & (ica' = ica + 1) & (steps' = 0) & (m' = -1);" << endl;
        // For some reason, PRISM requires steps < max_steps here although this always holds when s = ATTACK2
        fout << "\t[attack2] s = ATTACK2 & ica = na-1 & steps < max_steps ->" << endl;
        fout << "\t\tpsa : (icv' = 0) & (s' = DEFEND) & (steps' = steps + 1) & (m' = ctm) +" << endl;
        fout << "\t\t1-psa : (icv' = 0) & (s' = CAUGHT) & (ica' = 0)" << reset_dcs << ";" << endl;
      }
    } else {
      fout << "\t\tp_skip : (steps' = steps + 1) +" << endl; 
      fout << "\t\t(ica = na-1 ? 0 : paf) : (ica' = ica + 1) & (steps' = 0) & (m' = -1)";
      fout << " +" << endl;
      fout << "\t\t(ica = na-1 ? paf : 0) : (s' = CAUGHT) & (ica' = 0)" << reset_dcs << ";" << endl;
    }
  } else {
    fout << "\t[attack] s = ATTACK & targets_reached ->" << endl;
    fout << "\t\t(s' = SUCCESS) & (ica' = 0)" << reset_dcs << "; // finish the successful attack" << endl;
    if (limited_steps) {
      fout << "\t[attack] s = ATTACK & !targets_reached & steps = max_steps ->" << endl;
      fout << "\t\t(s' = QUIT)" << reset_dcs << "; // quit the attack" << endl;
    }
    string increase_steps = limited_steps ? " & (steps' = steps + (ica = na-1 ? 1 : 0))" : "";
    string steps_not_maxed = limited_steps ? " & steps < max_steps" : "";
    if (!nondet)
      fout << "\t[attack] s = ATTACK & !targets_reached" << steps_not_maxed << " ->" << endl;
    if (intervals_used || nondet) {
      for (int i = 0; i < vulns.size(); i++)
        if (vulns[i].is_target) {
          if (nondet)
            fout << "\t[attack] s = ATTACK & !targets_reached" << steps_not_maxed << " & p_vuln_" << i << " -> (s' = ATTACK2) & (icv' = " << i << ");" << endl; 
          else
            fout << "\t\t[p_vuln_" << i << "_min, p_vuln_" << i << "_max] : (s' = ATTACK2) & (icv' = " << i << ") +" << endl; 
        } else {
          fout << "\t\t// vulnerability " << i << " is not a target of any attacker's tactic" << endl;
        }
      if (nondet) {
        if (ttps.size() == 1 & !limited_steps) {
          // Nondeterministic attacker must not be allowed to skip, otherwise it can cause an infinite loop
          // (if there is no limit on the number of steps) and PRISM returns infinity as the maximum cost.
          // If it must skip because no more threats are possible then make it quit the attack instead.
          fout << "\t[attack] s = ATTACK & !targets_reached" << steps_not_maxed << " & !threats_possible -> (s' = QUIT)" << reset_dcs << "; // quit the attack" << endl;
        } else {
          // For multiple attackers we still allow skipping as other attackers may have threats available.
          fout << "\t[attack] s = ATTACK & !targets_reached" << steps_not_maxed << " & p_skip -> (ica' = mod(ica + 1, na))" << increase_steps << ";" << endl;
        }
      } else
        fout << "\t\t[p_skip_min, p_skip_max] : (ica' = mod(ica + 1, na))" << increase_steps << ";" << endl; 
      if (nondet && !intervals_used)
        // For some reason, PRISM requires steps < max_steps here although this always holds when s = ATTACK2
        fout << "\t[attack2] s = ATTACK2" << steps_not_maxed << " ->" << endl;
      else
        fout << "\t[attack2] s = ATTACK2 ->" << endl;
      if (intervals_used)
        fout << "\t\t[psa_min, psa_max]";
      else
        fout << "\t\tpsa";
      fout << " : (icv' = 0) & (ica' = mod(ica + 1, na)) & (s' = DEFEND)" << (deftacs.empty() ? "" : " & (idt' = 0)") << increase_steps;
      for (int i = 0; i < assets.size(); i++)
        fout << " & (m" << i << "' = m" << i << " | ctm" << i << ")";
      fout << " +" << endl;
      if (intervals_used)
        fout << "\t\t[paf_some_min, paf_some_max]";
      else
        fout << "\t\tpaf_some";
      fout << " : (icv' = 0) & (s' = ATTACK) & (ica' = mod(ica + 1, na))" << increase_steps;
      for (int i = 0; i < ttps.size(); i++)
        fout << " & (c" << i << "' = c" << i << " | ica = " << i << ")";
      fout << " +" << endl;
      if (intervals_used)
        fout << "\t\t[paf_all_min, paf_all_max]";
      else
        fout << "\t\tpaf_all";
      fout << " : (icv' = 0) & (s' = CAUGHT) & (ica' = 0)" << reset_dcs << ";" << endl;
    } else {
      for (int i = 0; i < vulns.size(); i++)
        if (vulns[i].is_target) {
          fout << "\t\tpsa_vuln_" << i << " : (ica' = mod(ica + 1, na)) & (s' = DEFEND)" << (deftacs.empty() ? "" : " & (idt' = 0)") << increase_steps;
          for (Asset *a : vulns[i].all_assets)
            fout << " & (m" << a->id << "' = true)";
          fout << " +" << endl;
        } else {
          fout << "\t\t// vulnerability " << i << " is not a target of any attacker's tactic" << endl;
        }
      fout << "\t\tp_skip : (ica' = mod(ica + 1, na))" << increase_steps << " +" << endl; 
      fout << "\t\t(na_caught = na-1 ? 0 : paf) : (ica' = mod(ica + 1, na))" << increase_steps;
      for (int i = 0; i < ttps.size(); i++)
        fout << " & (c" << i << "' = c" << i << " | ica = " << i << ")";
      fout << " +" << endl;
      fout << "\t\t(na_caught = na-1 ? paf : 0) : (s' = CAUGHT) & (ica' = 0)" << reset_dcs << ";" << endl;
    }
  }

  fout << "endmodule" << endl;

  fout << endl;
  fout << "// the target of attacker i" << endl;
  for (int i = 0; i < ttps.size(); i++)
    fout << "formula target" << i << " = " << ttp_target_str(ttps[i]) << ";" << endl;
  if (!linear_model) {
    fout << "// the attackers want to reach the targets of all attackers" << endl;
    fout << "formula targets_reached = " << targets_reached << ";" << endl;
  }

  fout << endl;
  fout << "// the cost to the defender of the assets compromised by the attacker(s)" << endl;
  fout << "formula compromised_assets_cost = ";
  for (int i = 0; i < assets.size(); i++) {
    if (i > 0)
      fout << " + ";
    fout << "(" << attacker_controls_asset(&assets[i]) << " ? " << assets[i].sensitivity << " : 0)";
  }
  fout << ";" << endl;

  ostringstream init;
  init << "s = CHOOSING & ica = 0";
  if (!deftacs.empty())
    init << " & idt = -1";
  if (limited_steps)
    init << " & steps = 0";
  if (intervals_used || nondet)
    init << " & icv = 0";
  if (linear_model)
    init << " & m = -1";
  else {
    set<Asset *> source_assets_set, starting_assets_set;
    for (Asset *a : source_assets)
      source_assets_set.insert(a);
    for (Asset *a : starting_assets)
      starting_assets_set.insert(a);
    for (int i = 0; i < assets.size(); i++)
      if (!source_assets_set.count(&assets[i]))
        init << " & " << (starting_assets_set.count(&assets[i]) ? "" : "!") << "m" << i;
  }
  if (!linear_model)
    for (int i = 0; i < ttps.size(); i++)
      init << " & !c" << i;

  fout << endl;
  if (source_assets.empty()) {
    fout << "// initially the attacker is in none of the machines (the attacker's own machine is not represented in this version of the model)" << endl;
    fout << "formula is_initial = " << init.str() << ";" << endl;
    fout << "init is_initial endinit" << endl;
    fout << "label \"initial\" = is_initial;" << endl;
  } else {
    if (linear_model || intervals_used)
      THROW("Cutting currently not implemented for models with intervals and linear models");
    fout << "formula is_initial_base = " << init.str() << ";" << endl;
    for (Asset *a : source_assets) {
      fout << "formula is_initial_" << a->id << " = is_initial_base";
      for (Asset *b : source_assets) {
        fout << " & ";
        if (b != a)
          fout << "!";
        fout << "m" << b->id;
      }
      fout << ";" << endl;
      fout << "label \"initial_" << a->id << "\" = is_initial_" << a->id << ";" << endl;
    }
    fout << "init";
    bool e = true;
    for (Asset *a : source_assets) {
      if (e)
        e = false;
      else
        fout << " |";
      fout << " is_initial_" << a->id;
    }
    fout << " endinit" << endl;
  }

  fout << endl;
  fout << "rewards \"cost\"" << endl;
  if (num_dm > 0) {
    fout << "\ts = CHOOSING : ";
    for (int i = 0; i < num_dm; i++) {
      if (i > 0)
        fout << " + ";
      fout << "(d" << i << " ? " << dm_costs[i] << " : 0)";
    }
    fout << ";" << endl;
  }
  if (any_restartable_machine) {
    fout << "\ts = RESTART_MACHINES : ";
    bool none_restarted = true;
    for (int i = 0; i < assets.size(); i++)
      if (can_restart(i)) {
        if (none_restarted)
          none_restarted = false;
        else
          fout << " + ";
        fout << "(d_restart_m" << i << " ? " << restart_machine_costs[i] << " : 0)";
      }
    fout << ";" << endl;
  }
  // PRISM supports only state rewards, not transition rewards for interval DTMC
  if (any_restartable_machine) {
    fout << "\tdetect_anomaly_cond : " << detect_anomaly_cost << ";" << endl;
    fout << "\tinvestigate_anomaly_cond : " << investigate_anomaly_cost << ";" << endl;
  }
  if (linear_model)
    fout << "\ts = ATTACK : compromised_assets_cost;" << endl;
  else {
    fout << "\ts = SUCCESS : compromised_assets_cost;" << endl;
    fout << "\ts = CAUGHT : compromised_assets_cost;" << endl;
    fout << "\ts = QUIT : compromised_assets_cost;" << endl;
  }
  if (!deftacs.empty()) {
    fout << "\t// we multiply the cost of using a defensive tactic by the probability that it is used because PRISM counts the cost regardless of whether the tactic is used (as long as it is available)" << endl;
    for (int i = 0; i < deftacs.size(); i++)
      fout << "\ts = DEFEND & idt = " << i << " & avail_deftac_" << i << " : " << deftacs[i].prob << " * " << deftacs[i].cost << ";" << endl;
  }
  fout << "endrewards" << endl;

  fout.close();
} CATCH2(PrismDatabase::generate_prism)

void PrismDatabase::compute_helper_fields() try {
  for (AttackTechnique &at : attechs) {
    //if (!at.interval_tactic.empty() || at.skip_lh_interval.second > 0)
    //  intervals_used = true;
    at.skip_lh_interval.first += at.skip_lh;
    at.skip_lh_interval.second += at.skip_lh;
    // overcome the PRISM restriction that forbids intervals [0, p] where p > 0
    // by replacing them with [min(ALMOST_ZERO, p), p]
    if (at.skip_lh_interval.first == 0 && at.skip_lh_interval.second > 0)
      at.skip_lh_interval.first = min(ALMOST_ZERO, at.skip_lh_interval.second);
    for (pair<pair<double, double>, Threat *> &p : at.interval_tactic)
      if (p.first.first == 0 && p.first.second > 0)
        p.first.first = min(ALMOST_ZERO, p.first.second);
  }

  for (Asset &a : assets) {
    if (a.owner != NULL)
      a.owner->owned_assets.push_back(&a);
    a.owned_assets.push_back(&a); // an asset owns itself, even if it is also owned by a user
    a.asset = &a;
  }
  for (Vulnerability &v : vulns) {
    v.severity_interval.first += v.severity;
    v.severity_interval.second += v.severity;
    if (v.severity_interval.first == 0 && v.severity_interval.second > 0)
      v.severity_interval.first = min(ALMOST_ZERO, v.severity_interval.second);
    if (v.severity_interval.first < 1 && v.severity_interval.second == 1)
      v.severity_interval.second = max(1 - ALMOST_ZERO, v.severity_interval.first);
    set<Asset *> s;
    for (IdOrAsset *ioa : v.direct_targets)
      for (Asset *a : ioa->owned_assets)
        s.insert(a);
    for (Asset *a : s)
      v.all_assets.push_back(a);
  }
  for (int i = 0; i < threats.size(); i++)
    threats[i].impact->threats.push_back(i);
  for (auto e : itinfra.edges) {
    e.second->reachable = true;
    e.second->vector_assets.push_back({e.first});
  }
  for (auto e : itinfra.hyperedges) {
    e.second->reachable = true;
    e.second->vector_assets.push_back(e.first);
    for (Asset *a : e.first)
      a->is_hyperedge_source = true;
  }
  for (IdOrAsset *a : itinfra.entrance_points) {
    a->reachable = true;
    a->vector_assets.clear();
  }
  for (Threat &t : threats) {
    t.reachable = true;
    // all assets/users directly affected by the threat must be reachable for the threat to be reachable
    for (IdOrAsset *a : t.impact->direct_targets)
      if (!a->reachable)
        t.reachable = false;
    if (!t.reachable)
      cerr << "WARNING: an unreachable threat was detected" << endl;
  }
  for (TTP &ttp : ttps) {
    for (pair<double, Threat *> p : ttp.technique->tactic)
      p.second->impact->is_target = true;
    for (pair<pair<double, double>, Threat *> &p : ttp.technique->interval_tactic)
      p.second->impact->is_target = true;
  }

  for (int i = 0; i < vulns.size(); i++)
    for (Asset *a : vulns[i].all_assets)
      a->targeting_vulns.push_back(i);

  bool any_restartable_machine = false;
  for (int i = 0; i < assets.size(); i++)
    if (can_restart(i))
      any_restartable_machine = true;
  ostringstream oss;
  if (any_restartable_machine)
    oss << " & (d_an_in' = 0)";
  if (limited_steps)
    oss << " & (steps' = 0)";
  for (int i = 0; i < num_dm; i++)
    oss << " & (d" << i << "' = false)";
  if (any_restartable_machine)
    for (int i = 0; i < assets.size(); i++)
      if (can_restart(i))
        oss << " & (d_restart_m" << i << "' = false)";
  if (!linear_model)
    for (int i = 0; i < ttps.size(); i++)
      oss << " & (c" << i << "' = false)";
  reset_dcs = oss.str();

  ostringstream oss2;
  if (linear_model)
    oss2 << "(m' = -1)";
  else
    for (int i = 0; i < assets.size(); i++) {
      if (i > 0)
        oss2 << " & ";
      oss2 << "(m" << i << "' = false)";
    }
  reset_m = oss2.str();

  ostringstream oss3;
  for (int i = 0; i < ttps.size(); i++) {
    if (i > 0)
      oss3 << " & ";
    oss3 << "target" << i;
  }
  targets_reached = oss3.str();
} CATCH2(PrismDatabase::compute_helper_fields)

// if mode==1 then also compute proabibilities, otherwise only compute costs
void PrismDatabase::generate_props(const char *fname, int mode) {
  ofstream fout(fname);
  string ndmax = nondet ? "max" : "";
  if (intervals_used) {
    fout << "filter(min, R" << ndmax << "max=? [ F s = FINAL ], \"initial\")" << endl << endl;
    fout << "filter(min, R" << ndmax << "min=? [ F s = FINAL ], \"initial\")" << endl << endl;
  } else {
    if (source_assets.empty()) {
      fout << "filter(min, R" << ndmax << "=? [ F s = FINAL ], \"initial\")" << endl << endl;
      if (mode == 1) {
        if (thracts[0].motivation.size() == 1)
          fout << "filter(min, P" << ndmax << "=? [ F s = SUCCESS ], \"initial\")" << endl << endl;
        else
          for (vector<Asset *> &v : thracts[0].motivation)
            fout << "filter(min, P" << ndmax << "=? [ F s = SUCCESS & m" << v[0]->id << " ], \"initial\")" << endl << endl;
      }
    } else {
      for (Asset *a : source_assets) {
        fout << "filter(min, R" << ndmax << "=? [ F s = FINAL ], \"initial_" << a->id << "\")" << endl << endl;
        if (mode == 1) {
          if (thracts[0].motivation.size() == 1)
            fout << "filter(min, P" << ndmax << "=? [ F s = SUCCESS ], \"initial_" << a->id << "\")" << endl << endl;
          else
            for (vector<Asset *> &v : thracts[0].motivation)
              fout << "filter(min, P" << ndmax << "=? [ F s = SUCCESS & m" << v[0]->id << " ], \"initial_" << a->id << "\")" << endl << endl;
        }
      }
    }
  }
  fout.close();
}

// ./prism should be a symlink to the prism script
// res will contain the result of each query in the props file
void execute_prism(string prism_file, string props_file, vector<double> &res) try {
  res.clear();
  string cmd = string("./prism ") + prism_file + " " + props_file + " -exportresults tmp_prism_results.txt";
  int errcode = system(cmd.c_str());
  if (errcode > 0) {
    THROW_STREAM(<< "PRISM exited with error code " << errcode);
  }
  ifstream fres("tmp_prism_results.txt");
  while (!fres.eof()) {
    string s;
    fres >> s;
    if (s == "Result") {
      fres >> s;
      double x;
      if (s == "Infinity")
        x = numeric_limits<double>::infinity();
      else {
        istringstream iss(s);
        iss >> x;
      }
      res.push_back(x);
    }
  }
  fres.close();
} CATCH

void PrismDatabase::execute_prism(vector<double> &res, int mode) {
  const char *prism_fname = "tmp_gen.prism";
  const char *props_fname = "tmp_gen.props";
  generate_prism(prism_fname);
  generate_props(props_fname, mode);
  ::execute_prism(string(prism_fname), string(props_fname), res);
}
