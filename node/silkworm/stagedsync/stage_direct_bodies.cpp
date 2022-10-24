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

#include "stage_direct_bodies.hpp"

#include <chrono>
#include <thread>

#include "silkworm/common/log.hpp"
#include "silkworm/common/measure.hpp"
#include "silkworm/common/stopwatch.hpp"
#include "silkworm/db/stages.hpp"
#include "silkworm/downloader/internals/body_persistence.hpp"

namespace silkworm::stagedsync {

DirectBodiesStage::DirectBodiesStage(SyncContext* sc, BlockQueue& bq, NodeSettings* ns)
    : Stage(sc, db::stages::kBlockBodiesKey, ns), block_queue_{bq} {
}

DirectBodiesStage::~DirectBodiesStage() {
}

Stage::Result DirectBodiesStage::forward(db::RWTxn& txn) {
    using std::shared_ptr;
    using namespace std::chrono_literals;
    using namespace std::chrono;

    Stage::Result result = Stage::Result::kUnspecified;
    operation_ = OperationType::Forward;

    StopWatch timing;
    timing.start();
    log::Info(log_prefix_) << "Start";

    try {
        SILK_INFO << "Start Persist EVM Block ";

        std::shared_ptr<silkworm::Block> b;
        if( ! block_queue_.try_pop(b) ) {
            return Stage::Result::kSuccess;
        }

        SILK_INFO << "Persist EVM Block " << b->header.number;
        current_height_ = b->header.number;

        silkworm::HeaderPersistence hp{txn};
        silkworm::BodyPersistence bp{txn, *node_settings_->chain_config};

        hp.persist(b->header);
        bp.persist(*b);
        hp.finish();

        if(hp.unwind_needed()) {

        }

        txn.commit();

        result = Stage::Result::kSuccess;

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

    return result;
}

Stage::Result DirectBodiesStage::unwind(db::RWTxn& ) {
    Stage::Result result{Stage::Result::kSuccess};
    operation_ = OperationType::Unwind;

    StopWatch timing;
    timing.start();
    log::Info(log_prefix_) << "Unwind start";

    // TODO: anything needed here?

    return result;
}

auto DirectBodiesStage::prune(db::RWTxn&) -> Stage::Result {
    return Stage::Result::kSuccess;
}

std::vector<std::string> DirectBodiesStage::get_log_progress() {  // implementation MUST be thread safe
    static RepeatedMeasure<BlockNum> height_progress{0};

    height_progress.set(current_height_);

    return {"current number", std::to_string(height_progress.get()),
            "progress", std::to_string(height_progress.delta()),
            "bodies/secs", std::to_string(height_progress.throughput())};
}

}  // namespace silkworm::stagedsync
