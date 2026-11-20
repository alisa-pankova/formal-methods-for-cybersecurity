/*
 * Copyright 2026 Cybernetica AS
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
#ifndef MINIMUM_CUT_H
#define MINIMUM_CUT_H

#include <vector>

struct Edge {
  int x, y; // edge from vertex x to vertex y
  int original_capacity;
  int rcap; // residual capacity
  Edge *rev; // pointer to the reverse of this edge (y to x)
};

struct MinimumCut {
  std::vector<Edge *> min_cut; // filled by find_cut()
  std::vector<bool> is_source_side; // is vertex i on the source side of the cut?, filled by find_cut()
  int max_flow; // filled by find_cut()

  MinimumCut(int n, int source, int sink) : num_vertices(n), source(source), sink(sink) {}

  void add_edge(int x, int y, int cap) {
    edges.push_back({x: x, y: y, original_capacity: cap});
  }

  void find_cut();

private:
  int num_vertices, source, sink;
  std::vector<Edge> edges, rev_edges;
  std::vector<std::vector<Edge *> > ev; // ev[i] is the list of edges from vertex i

  int find_augmenting_path();
};
#endif
