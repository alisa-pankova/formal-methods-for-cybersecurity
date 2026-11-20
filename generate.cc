/*
 * Copyright 2026 Cybernetica AS
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
 #include <iostream>
#include <iomanip>
#include <random>
#include <sstream>
using namespace std;

const int N = 20;
const int ND = 3; // number of defensive measures
const double dmcost = 30;
int dm[N][N]; // -1 if no defensive measure affects this edge
double prob[N][N]; // probability of successfully going from machine i to machine j in one step if defensive measure dm[i][j] is not used
double prob2[N][N]; // probability of successfully going from machine i to machine j in one step if defensive measure dm[i][j] is used
double maxprob[N][N]; // maximum probability of successfully going from machine i to machine j in any number of steps
double probbyndm[ND+1];

void compute_maxprob() {
  //for (int i = 0; i < N; i++)
  //  for (int j = 0; j < N; j++)
  //    maxprob[i][j] = i == j ? 1 : prob[i][j];
  //for (int k = 0; k < N; k++)
  //  for (int i = 0; i < N; i++)
  //    for (int j = 0; j < N; j++)
  //      if (maxprob[i][j] < maxprob[i][k] * maxprob[k][j])
  //        maxprob[i][j] = maxprob[i][k] * maxprob[k][j];

  double minmaxprob = 1;
  double minmaxcost = 1000;
  int minmaxndm = -1;
  for (int i = 0; i <= ND; i++)
    probbyndm[i] = 1;
  for (int dmu = 0; dmu < (1 << ND); dmu++) {
    for (int i = 0; i < N; i++)
      for (int j = 0; j < N; j++) {
        if (i == j)
          maxprob[i][j] = 1;
        else if (dm[i][j] < 0)
          maxprob[i][j] = prob[i][j];
        else if ((dmu >> dm[i][j]) & 1)
          maxprob[i][j] = prob2[i][j];
        else
          maxprob[i][j] = prob[i][j];
      }
    for (int k = 0; k < N; k++)
      for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++)
          if (maxprob[i][j] < maxprob[i][k] * maxprob[k][j])
            maxprob[i][j] = maxprob[i][k] * maxprob[k][j];
    //if (maxprob[0][1] < minmaxprob)
    //  minmaxprob = maxprob[0][1];
    int ndm = 0;
    double maxcost = maxprob[0][1] * 1000;
    for (int i = 0; i < ND; i++)
      if ((dmu >> i) & 1) {
        maxcost += dmcost;
        ndm++;
      }
    if (maxcost < minmaxcost) {
      minmaxcost = maxcost;
      minmaxprob = maxprob[0][1];
      minmaxndm = ndm;
    }
    if (maxprob[0][1] < probbyndm[ndm]) {
      probbyndm[ndm] = maxprob[0][1];
    }
  }

  //cerr << "maxprob = " << maxprob[0][N - 1] << endl;
  //cerr << "maxprob = " << maxprob[0][1] << endl;
  cerr << "minmaxndm = " << minmaxndm << endl;
  cerr << "minmaxprob = " << minmaxprob << endl;
  cerr << "minmaxcost = " << minmaxcost << endl;
  for (int i = 0; i <= ND; i++) {
    cerr << "ndm = " << i << ": minmaxprob = " << probbyndm[i] << ", " << (i == 0 ? 0 : (probbyndm[0] - probbyndm[i]) / i) << endl;
  }
}

int main() {
  mt19937_64 rng;
  uniform_real_distribution<double> dist01(0.0, 1.0);
  uniform_int_distribution<int> dist_dm_no(0, ND - 1);
  bernoulli_distribution dist_use_dm(0.9999);

  for (int i = 0; i < N; i++)
    for (int j = 0; j < N; j++) {
      prob[i][j] = i == j ? 1 : dist01(rng);
      if (dist_use_dm(rng)) {
        dm[i][j] = dist_dm_no(rng);
        //prob2[i][j] = i == j ? 1 : dist01(rng);
        //if (prob2[i][j] > prob[i][j])
        //  swap(prob2[i][j], prob[i][j]);
        prob2[i][j] = prob[i][j] * 0.999;
        prob2[i][j] *= (double)(dm[i][j] + 1) / ND;
      } else
        dm[i][j] = -1;
    }

  cout << "pomdp" << endl;
  cout << "observables s endobservables" << endl;
  for (int i = 0; i < ND; i++)
    cout << "const double p" << i << ";" << endl;

  cout << endl << "module network" << endl;

  cout << fixed << setprecision(10);
  cerr << fixed << setprecision(10);

  int tr = 1;

  cout << "\ts : [-" << ND + 1 << ".." << N << "] init -2;" << endl; // s = 0 iff caught, s = i + 1 iff in machine i, start from s = 1, goal s = 2
  for (int i = 0; i < ND; i++)
    cout << "\td" << i << " : bool init false;" << endl;

  for (int i = 0; i < ND; i++) {
    int i2 = i + 1 == ND ? 1 : -(i + 3);
    cout << "\t[] s = -" << i + 2 << " -> (1 - p" << i << ") : (s' = " << i2 << ") + p" << i << " : (s' = " << i2 << ") & (d" << i << "' = true);" << endl;
  }

  for (int i = 0; i < N; i++)
    for (int j = 0; j < N; j++)
      if (i != j) {
        double p = prob[i][j];
        int d = dm[i][j];
        if (d >= 0) {
          double p2 = prob2[i][j];
          cout << "\t[t" << tr++ << "] s = " << i + 1 << " -> (d" << d << " ? " << p2 << " : " << p << ") : (s' = " << j + 1 << ") + (d" << d << " ? " << 1 - p2 << " : " << 1 - p << ") : (s' = 0);" << endl;
        } else
          cout << "\t[t" << tr++ << "] s = " << i + 1 << " -> " << p << " : (s' = " << j + 1 << ") + " << 1 - p << " : (s' = 0);" << endl;
      }
  cout << "\t[] s = -1 -> true;" << endl;
  cout << "\t[succeeded] s = 2 -> (s' = -1);" << endl;
  cout << "\t[caught] s = 0 -> (s' = -1);" << endl;

  cout << "endmodule" << endl;

  ostringstream oss;
  for (int i = 0; i < ND; i++) {
    oss << " + (d" << i << " ? " << dmcost << " : 0)";
  }
  oss << ";";

  cout << endl;
  cout << "rewards \"cost\"" << endl;
  cout << "\t[succeeded] true : 1000" << oss.str() << endl;
  cout << "\t[caught] true : 0" << oss.str() << endl;
  cout << "endrewards" << endl;

  //cout << endl;
  //cout << "init s = 1 endinit" << endl;

  compute_maxprob();

  return 0;
}
