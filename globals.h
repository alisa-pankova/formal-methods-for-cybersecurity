/*
 * Copyright 2026 Cybernetica AS
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
 // global parameters of the model that do not change when the model is split into parts

#ifndef GLOBALS_H
#define GLOBALS_H

#include <vector>
#include <iostream>
#include <exception>

#include <sstream>

extern bool linear_model;
extern bool intervals_used;
extern bool nondet;
extern bool use_cuts;
extern bool limited_steps;

extern double ALMOST_ZERO;

extern double detect_anomaly_cost;
extern double investigate_anomaly_cost;

extern int num_dm; // the number of defensive measures

extern std::vector<double> dm_costs;

[[noreturn]] inline void handle_exception(const char *filename, int line_no) {
  std::cerr << "exception rethrown at " << filename << ":" << line_no << std::endl;
  std::rethrow_exception(std::current_exception());
}

[[noreturn]] inline void handle_exception(const char *filename, int line_no, const char *func_name) {
  std::cerr << "exception rethrown at " << filename << ":" << line_no << ", in " << func_name << "()" << std::endl;
  std::rethrow_exception(std::current_exception());
}

[[noreturn]] inline void throw_exception(const char *filename, int line_no, const char *s) {
  std::cerr << "exception thrown at " << filename << ":" << line_no << std::endl;
  throw std::runtime_error(s);
}

[[noreturn]] inline void throw_exception(const char *filename, int line_no, const std::string &s) {
  throw_exception(filename, line_no, s.c_str());
}

#define CATCH catch (...) { handle_exception(__FILE__, __LINE__); }
#define CATCH2(func_name) catch (...) { handle_exception(__FILE__, __LINE__, #func_name); }
#define THROW(s) throw_exception(__FILE__, __LINE__, (s))

// if (...) THROW_STREAM(s); else ... cannot be used
// if (...) { THROW_STREAM(s) } else ... can be used
// used as THROW_STREAM(<< x1 << x2 << ... << xn)
#define THROW_STREAM(s) {std::ostringstream oss; oss s; THROW(oss.str());}
#endif
