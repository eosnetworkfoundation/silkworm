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

#include <silkworm/concurrency/containers.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/downloader/internals/types.hpp>
#include <silkworm/downloader/messages/internal_message.hpp>
#include <silkworm/stagedsync/stage.hpp>

namespace silkworm::stagedsync {

class DirectBodiesStage : public Stage {
  public:
    using BlockQueue = ConcurrentQueue<std::shared_ptr<silkworm::Block>>;

    DirectBodiesStage(SyncContext*, BlockQueue&, NodeSettings*);
    DirectBodiesStage(const DirectBodiesStage&) = delete;  // not copyable
    DirectBodiesStage(DirectBodiesStage&&) = delete;       // nor movable
    ~DirectBodiesStage();

    Stage::Result forward(db::RWTxn&) override;  // go forward, downloading headers
    Stage::Result unwind(db::RWTxn&) override;   // go backward, unwinding headers to new_height
    Stage::Result prune(db::RWTxn&) override;

  private:
    std::vector<std::string> get_log_progress() override;  // thread safe
    std::atomic<BlockNum> current_height_{0};

    BlockQueue& block_queue_;
};

}  // namespace silkworm::stagedsync
