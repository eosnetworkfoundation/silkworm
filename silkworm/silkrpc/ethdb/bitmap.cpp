/*
   Copyright 2023 The Silkworm Authors

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

#include "bitmap.hpp"

#include <climits>
#include <memory>
#include <utility>
#include <vector>

#include <boost/endian/conversion.hpp>
#include <gsl/narrow>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/bitmap.hpp>

namespace silkworm::rpc::ethdb::bitmap {

using roaring_bitmap_t = roaring::api::roaring_bitmap_t;
using Roaring64Map = roaring::Roaring64Map;

static Roaring64Map fast_or(size_t n, const std::vector<std::unique_ptr<Roaring64Map>>& inputs) {
    Roaring64Map result;
    for (size_t k = 0; k < n; ++k) {
        result |= *inputs[k];
    }
    return result;
}

awaitable<Roaring64Map> get(core::rawdb::DatabaseReader& db_reader, const std::string& table, silkworm::Bytes& key,
                       uint32_t from_block, uint32_t to_block) {
    std::vector<std::unique_ptr<Roaring64Map>> chunks;

    silkworm::Bytes from_key{key.begin(), key.end()};
    from_key.resize(key.size() + sizeof(uint16_t));
    boost::endian::store_big_u16(&from_key[key.size()], 0);
    SILK_DEBUG << "table: " << table << " key: " << key << " from_key: " << from_key;

    core::rawdb::Walker walker = [&](const silkworm::Bytes& k, const silkworm::Bytes& v) {
        SILK_TRACE << "k: " << k << " v: " << v;
        auto chunck = std::make_unique<Roaring64Map>(silkworm::db::bitmap::parse(v));
        auto block = chunck->maximum();
        if (block >= from_block && chunck->minimum() <= to_block) {
            chunks.push_back(std::move(chunck));
        }
        return block < to_block;
    };
    co_await db_reader.walk(table, from_key, gsl::narrow<uint32_t>(key.size() * CHAR_BIT), walker);

    auto result{fast_or(chunks.size(), chunks)};
    SILK_DEBUG << "result: " << result.toString();
    co_return result;
}

awaitable<Roaring64Map> from_topics(core::rawdb::DatabaseReader& db_reader, const std::string& table, const FilterTopics& topics,
                               uint64_t start, uint64_t end) {
    SILK_DEBUG << "#topics: " << topics.size() << " start: " << start << " end: " << end;
    roaring::Roaring64Map result_bitmap;
    for (const auto& subtopics : topics) {
        SILK_DEBUG << "#subtopics: " << subtopics.size();
        roaring::Roaring64Map subtopic_bitmap;
        for (auto topic : subtopics) {
            silkworm::Bytes topic_key{std::begin(topic.bytes), std::end(topic.bytes)};
            SILK_TRACE << "topic: " << topic << " topic_key: " << silkworm::to_hex(topic);
            auto bitmap = co_await ethdb::bitmap::get(db_reader, table, topic_key, gsl::narrow<uint32_t>(start), gsl::narrow<uint32_t>(end));
            SILK_TRACE << "bitmap: " << bitmap.toString();
            subtopic_bitmap |= bitmap;
            SILK_TRACE << "subtopic_bitmap: " << subtopic_bitmap.toString();
        }
        if (!subtopic_bitmap.isEmpty()) {
            if (result_bitmap.isEmpty()) {
                result_bitmap = subtopic_bitmap;
            } else {
                result_bitmap &= subtopic_bitmap;
            }
        }
        SILK_DEBUG << "result_bitmap: " << result_bitmap.toString();
    }
    co_return result_bitmap;
}

awaitable<Roaring64Map> from_addresses(core::rawdb::DatabaseReader& db_reader, const std::string& table, const FilterAddresses& addresses,
                                  uint64_t start, uint64_t end) {
    SILK_TRACE << "#addresses: " << addresses.size() << " start: " << start << " end: " << end;
    roaring::Roaring64Map result_bitmap;
    for (auto address : addresses) {
        silkworm::Bytes address_key{std::begin(address.bytes), std::end(address.bytes)};
        auto bitmap = co_await ethdb::bitmap::get(db_reader, table, address_key, gsl::narrow<uint32_t>(start), gsl::narrow<uint32_t>(end));
        SILK_TRACE << "bitmap: " << bitmap.toString();
        result_bitmap |= bitmap;
    }
    SILK_TRACE << "result_bitmap: " << result_bitmap.toString();
    co_return result_bitmap;
}

}  // namespace silkworm::rpc::ethdb::bitmap
