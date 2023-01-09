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
    // User can specify to stop at some block
    const auto stop_at_block = stop_at_block_from_env();
    if (stop_at_block.has_value()) {
        target_block_ = stop_at_block;
        log::Info(log_prefix_) << "env var STOP_AT_BLOCK set, target block=" << target_block_.value();
    }
}

DirectBodiesStage::~DirectBodiesStage() = default;

Stage::Result DirectBodiesStage::forward(db::RWTxn& tx) {
    using std::shared_ptr;
    using namespace std::chrono_literals;
    using namespace std::chrono;

    Stage::Result result = Stage::Result::kUnspecified;
    std::thread message_receiving;
    operation_ = OperationType::Forward;

    StopWatch timing;
    timing.start();
    log::Info(log_prefix_) << "Start";

    try {
        HeaderPersistence header_persistence(tx);

        if (header_persistence.canonical_repaired()) {
            tx.commit();
            log::Info(log_prefix_) << "End (forward skipped due to the need of to complete the previous run, canonical chain updated), "
                                   << "duration=" << StopWatch::format(timing.lap_duration());
            return Stage::Result::kSuccess;
        }

        current_height_ = header_persistence.initial_height();
        get_log_progress();  // this is a trick to set log progress initial value, please improve

        if (target_block_ && current_height_ >= *target_block_) {
            tx.commit();
            log::Info(log_prefix_) << "End, forward skipped due to target block (" << *target_block_ << ") reached";
            return Stage::Result::kStoppedByEnv;
        }

        RepeatedMeasure<BlockNum> height_progress(header_persistence.initial_height());
        log::Debug(log_prefix_) << "Waiting for blocks... from=" << height_progress.get();

        silkworm::BodyPersistence body_persistence{tx, *node_settings_->chain_config};

        size_t block_count{0};
        while(true) {
            std::shared_ptr<silkworm::Block> b;
            if (!block_queue_.timed_wait_and_pop(b, 1000ms)) {
                result = Stage::Result::kSuccess;
                break;
            }

            //SILK_INFO << "Persist EVM Block: " << b->header.number;

            // Header & Body
            header_persistence.persist(b->header);
            current_height_ = header_persistence.highest_height();

            body_persistence.persist(*b);

            //bool unwind_needed = false;
            if (header_persistence.unwind_needed()) {
                result = Stage::Result::kWrongFork;
                sync_context_->unwind_point = header_persistence.unwind_point();
                //unwind_needed = true;
                // no need to set result.bad_block
                log::Info(log_prefix_) << "Unwind needed";
                break;
            }

            ++block_count;
            if(block_count == 5000 || b->irreversible == false || is_stopping() ) {
                result = Stage::Result::kSuccess;
                break;
            }
        }

        SILK_INFO << "Persisted #" << block_count << " blocks";

        header_persistence.finish();
        body_persistence.close();

        tx.commit();  // this will commit or not depending on the creator of txn

        // todo: do we need a sentry.set_status() here?

        log::Debug(log_prefix_) << "Done, duration= " << StopWatch::format(timing.lap_duration());

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

    return result;
}

Stage::Result DirectBodiesStage::unwind(db::RWTxn& tx) {
    Stage::Result result{Stage::Result::kSuccess};
    operation_ = OperationType::Unwind;

    StopWatch timing;
    timing.start();
    log::Info(log_prefix_) << "Unwind start";

    current_height_ = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);
    get_log_progress();  // this is a trick to set log progress initial value, please improve

    std::optional<Hash> bad_block = sync_context_->bad_block_hash;

    if (!sync_context_->unwind_point.has_value()) {
        operation_ = OperationType::None;
        return result;
    }
    auto new_height = sync_context_->unwind_point.value();

    try {
        std::set<Hash> bad_headers;
        std::tie(bad_headers, new_height) = HeaderPersistence::remove_headers(new_height, bad_block, tx);
        // todo: do we need to save bad_headers in the state and pass old bad headers here?

        silkworm::BodyPersistence body_persistence{tx, *node_settings_->chain_config};
        BodyPersistence::remove_bodies(new_height, sync_context_->bad_block_hash, tx);

        current_height_ = new_height;

        tx.commit();

        result = Stage::Result::kSuccess;

        // todo: do we need a sentry.set_status() here?

        log::Info(log_prefix_) << "Unwind completed, duration= " << StopWatch::format(timing.lap_duration());

    } catch (const std::exception& e) {
        log::Error(log_prefix_) << "Unwind aborted due to exception: " << e.what();

        // tx rollback executed automatically if needed
        result = Stage::Result::kUnexpectedError;
    }

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
