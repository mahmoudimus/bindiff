// Copyright 2011-2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PYTHON_BINDIFF_SQLITE_THROWING_H_
#define PYTHON_BINDIFF_SQLITE_THROWING_H_

// Throwing adapters over BinDiff's sqlite wrapper.
//
// BinDiff reports sqlite failures as absl::Status; it used to expose
// StatementOrThrow()/ExecuteOrThrow() instead, which threw. The Cython
// extension declares these entry points `except +`, which maps a C++ exception
// onto a Python exception -- so this layer wants the throwing shape, and a
// status that is merely returned and ignored would surface as silently empty
// results instead of an error. These adapters convert a failed status into
// std::runtime_error at the point of failure.

#include <stdexcept>
#include <string>
#include <utility>

#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/zynamics/bindiff/sqlite.h"

namespace security::bindiff::python {

inline void ThrowIfError(const absl::Status& status, absl::string_view what) {
  if (!status.ok()) {
    throw std::runtime_error(absl::StrCat(what, ": ", status.ToString()));
  }
}

template <typename T>
T ValueOrThrow(absl::StatusOr<T> value, absl::string_view what) {
  ThrowIfError(value.status(), what);
  return std::move(*value);
}

// Mirrors the subset of the old throwing SqliteStatement API these wrappers
// use. Into() is forwarded as a template so the existing chained
// `.Into(&a).Into(&b)` call sites keep working unchanged.
class ThrowingStatement {
 public:
  explicit ThrowingStatement(SqliteStatement statement)
      : statement_(std::move(statement)) {}

  void ExecuteOrThrow() {
    ThrowIfError(statement_.Execute(), "executing statement");
  }

  bool GotData() const { return statement_.GotData(); }

  template <typename T>
  ThrowingStatement& Into(T* value, bool* is_null = nullptr) {
    statement_.Into(value, is_null);
    return *this;
  }

 private:
  SqliteStatement statement_;
};

// Mirrors the old throwing SqliteDatabase::StatementOrThrow().
class ThrowingDatabase {
 public:
  explicit ThrowingDatabase(SqliteDatabase database)
      : database_(std::move(database)) {}

  ThrowingStatement StatementOrThrow(absl::string_view statement) {
    return ThrowingStatement(ValueOrThrow(
        database_.Statement(statement),
        absl::StrCat("preparing statement '", statement.substr(0, 60), "'")));
  }

 private:
  SqliteDatabase database_;
};

// Opens a result database, throwing if it cannot be read.
inline ThrowingDatabase ConnectOrThrow(const std::string& filename) {
  return ThrowingDatabase(ValueOrThrow(SqliteDatabase::Connect(filename),
                                       absl::StrCat("opening '", filename, "'")));
}

}  // namespace security::bindiff::python

#endif  // PYTHON_BINDIFF_SQLITE_THROWING_H_
