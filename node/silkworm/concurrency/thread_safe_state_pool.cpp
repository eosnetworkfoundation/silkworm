/*
   Copyright 2021-2022 The Silkworm Authors

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

#include "thread_safe_state_pool.hpp"

#include <utility>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#include <evmone/advanced_analysis.hpp>
#pragma GCC diagnostic pop

namespace silkworm {

std::unique_ptr<EvmoneExecutionState> ThreadSafeExecutionStatePool::acquire() noexcept {
    const std::lock_guard lock{mutex_};
    return ExecutionStatePool::acquire();
}

void ThreadSafeExecutionStatePool::release(std::unique_ptr<EvmoneExecutionState> obj) noexcept {
    const std::lock_guard lock{mutex_};
    ExecutionStatePool::release(std::move(obj));
}

}  // namespace silkworm