/*
 * Copyright 2026 Cybernetica AS
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
#include "MinimumCut.h"
#include "globals.h"

#include <iostream>
#include <queue>
#include <climits>

using namespace std;

// returns the capacity of the augmenting path, 0 if no path found
int MinimumCut::find_augmenting_path() {
  vector<Edge *> reaching_edge(num_vertices, NULL); // the last edge on the path from source to vertex i, NULL if i has not been reached yet or is the source
  queue<int> q;
  q.push(source);
  while (!q.empty()) {
    int v = q.front();
    q.pop();
    for (Edge *e : ev[v])
      if (e->y != source && reaching_edge[e->y] == NULL && e->rcap > 0) {
        reaching_edge[e->y] = e;
        q.push(e->y);
      }
  }

  if (reaching_edge[sink] == NULL) {
    cerr << "Augmenting path does not exist." << endl;
    return 0;
  }

  cerr << "Found augmenting path." << endl;
  int path_cap = INT_MAX;
  for (int i = sink; i != source; i = reaching_edge[i]->x) {
    Edge *e = reaching_edge[i];
    cerr << e->x << "->" << e->y << ", cap: " << e->rcap << endl;
    if (e->rcap < path_cap)
      path_cap = e->rcap;
  }
  cerr << "Path capacity: " << path_cap << endl;
  if (path_cap > INT_MAX / 2) {
    cerr << "Path with infinite capacity. The graph does not have cuts with finite capacity." << endl;
    return INT_MAX;
  }

  for (int i = sink; i != source; i = reaching_edge[i]->x) {
    Edge *e = reaching_edge[i];
    e->rcap -= path_cap;
    e->rev->rcap += path_cap;
  }

  return path_cap;
}

void MinimumCut::find_cut() try {
  cerr << "MinimumCut::find_cut()" << endl;
  cerr << "source: " << source << ", sink: " << sink << endl;

  if (rev_edges.empty()) {
    for (Edge &e : edges) {
      e.rcap = e.original_capacity;
      rev_edges.push_back({x: e.y, y: e.x, original_capacity: 0, rcap: 0, rev: &e});
    }
    for (int i = 0; i < edges.size(); i++)
      edges[i].rev = &rev_edges[i];
    for (int i = 0; i < num_vertices; i++)
      ev.push_back({});
    for (Edge &e : edges)
      ev[e.x].push_back(&e);
    for (Edge &e : rev_edges)
      ev[e.x].push_back(&e);
  } else {
    THROW("MinimumCut::find_cut() called more than once");
  }

  max_flow = 0;
  for (;;) {
    int path_cap = find_augmenting_path();
    if (path_cap == 0)
      break;
    if (path_cap == INT_MAX) {
      cerr << "The graph cannot be cut." << endl;
      max_flow = INT_MAX;
      return;
    }
    max_flow += path_cap;
  }
  cerr << "max flow: " << max_flow << endl;

  vector<bool> reachable(num_vertices, false); // is the vertex i reachable from the source in the residual graph
  queue<int> q;
  reachable[source] = true;
  q.push(source);
  while (!q.empty()) {
    int v = q.front();
    q.pop();
    cerr << "reachable vertex: " << v << endl;
    for (Edge *e : ev[v])
      if (!reachable[e->y] && e->rcap > 0) {
        reachable[e->y] = true;
        q.push(e->y);
      }
  }
  is_source_side = reachable;

  // the minimum cut is the edges from reachable to non-reachable vertices that have positive capacity in the original graph
  for (Edge &e : edges)
    if (reachable[e.x] && !reachable[e.y] && e.original_capacity > 0) {
      cerr << "cut edge " << e.x << "->" << e.y << ", cap: " << e.original_capacity << endl;
      min_cut.push_back(&e);
    }
} CATCH
