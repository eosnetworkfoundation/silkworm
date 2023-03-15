/*
   Copyright 2022 The Silkworm Authors

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

#pragma once

#include <memory>

#include <silkworm/node/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/node/rpc/server/server_context_pool.hpp>

#include "settings.hpp"

namespace silkworm::sentry {

class SentryImpl;

class Sentry final {
  public:
    explicit Sentry(Settings settings, silkworm::rpc::ServerContextPool& context_pool);
    ~Sentry();

    Sentry(const Sentry&) = delete;
    Sentry& operator=(const Sentry&) = delete;

    boost::asio::awaitable<void> run();

  private:
    std::unique_ptr<SentryImpl> p_impl_;
};

}  // namespace silkworm::sentry