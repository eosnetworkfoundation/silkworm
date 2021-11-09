/*
   Copyright 2020-2021 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

           http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <thread>

#include <silkworm/common/log.hpp>

#include "date.hpp"

namespace silkworm {

static teestream log_streams_{std::cerr, null_stream()};

LogLevel log_verbosity_{LogLevel::Info};
bool log_thread_enabled_{false};

static constexpr char const kLogTags_[7][6] = {
    "TRACE", "DEBUG", "INFO ", "WARN ", "ERROR", "CRIT ", "NONE ",
};

// Log to one or two output streams - typically the console and optional log file.
void log_set_streams_(std::ostream& o1, std::ostream& o2) { log_streams_.set_streams(o1.rdbuf(), o2.rdbuf()); }

std::mutex log_::log_mtx_;

std::ostream& log_::header_(LogLevel level) {
    auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    log_streams_ << kLogTags_[static_cast<int>(level)] << "[" << date::format("%D %T", now) << "]";
    if (log_thread_enabled_) {
        log_streams_ << " " << std::this_thread::get_id();
    }
    return log_streams_;
}

std::ostream& null_stream() {
    static struct null_buf : public std::streambuf {
        int overflow(int c) override { return c; }
    } null_buf;
    static struct null_strm : public std::ostream {
        null_strm() : std::ostream(&null_buf) {}
    } null_strm;
    return null_strm;
}

}  // namespace silkworm
