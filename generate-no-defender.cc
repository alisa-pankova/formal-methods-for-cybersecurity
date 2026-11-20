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
using namespace std;

const int N = 200;
double prob[N][N]; // probability of successfully going from machine i to machine j in one step
double maxprob[N][N]; // maximum probability of successfully going from machine i to machine j in any number of steps

void compute_maxprob() {
  for (int i = 0; i < N; i++)
    for (int j = 0; j < N; j++)
      maxprob[i][j] = i == j ? 1 : prob[i][j];
  for (int k = 0; k < N; k++)
    for (int i = 0; i < N; i++)
      for (int j = 0; j < N; j++)
        if (maxprob[i][j] < maxprob[i][k] * maxprob[k][j])
          maxprob[i][j] = maxprob[i][k] * maxprob[k][j];
}

int main() {
  mt19937_64 rng;
  uniform_real_distribution<double> dist01(0.0, 1.0);

  for (int i = 0; i < N; i++)
    for (int j = 0; j < N; j++)
      prob[i][j] = i == j ? 1 : dist01(rng);

  cout << "mdp" << endl;
  cout << "module network" << endl;

  cout << fixed << setprecision(10);
  cerr << fixed << setprecision(10);

  //cout << "\tcaught : bool init false;" << endl;
  //for (int i = 0; i < N; i++)
  //  //cout << "m" << i << " : bool;"
  //  cout << "\tm" << i << " : bool init " << (i == 0 ? "true" : "false") << ";" << endl;
  cout << "\ts : [0.." << N << "] init 1;" << endl; // s = 0 iff caught, s = i + 1 iff in machine i, start from s = 1, goal s = 2

  for (int i = 0; i < N; i++)
    for (int j = 0; j < N; j++)
      if (i != j) {
        double p = prob[i][j];
        //cout << "\t[] !caught & m" << i << " & !m" << j << " -> " << p << " : (m" << j << "' = true) + " << (1 - p) << " : (caught' = true);" << endl;
        cout << "\t[] s = " << i + 1 << " -> " << p << " : (s' = " << j + 1 << ") + " << 1 - p << " : (s' = 0);" << endl;
      }
  //cout << "\t[] caught | m" << (N - 1) << " -> true;" << endl;
  cout << "\t[] s = 0 | s = 2 -> true;" << endl;

  cout << "endmodule" << endl;

  compute_maxprob();
  //cerr << "maxprob = " << maxprob[0][N - 1] << endl;
  cerr << "maxprob = " << maxprob[0][1] << endl;

  return 0;
}
