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

#ifndef SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_CURSOR_HPP_
#define SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_CURSOR_HPP_

#include <silkworm/db/mdbx.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/trie/node.hpp>
#include <silkworm/trie/prefix_set.hpp>

namespace silkworm::trie {

//! \brief Traverses TrieAccount or TrieStorage in pre-order: \n
//! 1. Visit the current node \n
//! 2. Recursively traverse the current node's left subtree. \n
//! 3. Recursively traverse the current node's right subtree. \n
//! \see https://en.wikipedia.org/wiki/Tree_traversal#Pre-order,_NLR
//! \see Erigon's AccTrieCursor/StorageTrieCursor

class Cursor {
  public:
    // Ignores DB entries whose keys don't start with the prefix
    explicit Cursor(mdbx::cursor& db_cursor, PrefixSet& changed, etl::Collector* collector, ByteView prefix = {});

    // Not copyable nor movable
    Cursor(const Cursor&) = delete;
    Cursor& operator=(const Cursor&) = delete;

    void next();

    // nullopt key signifies end-of-tree
    [[nodiscard]] std::optional<Bytes> key() const;

    [[nodiscard]] const evmc::bytes32* hash() const;

    [[nodiscard]] bool children_are_in_trie() const;

    [[nodiscard]] bool can_skip_state() const { return can_skip_state_; }

    [[nodiscard]] std::optional<Bytes> first_uncovered_prefix() const;

  private:
    // TrieAccount(TrieStorage) node with a particular nibble selected
    struct SubNode {
        Bytes key;
        std::optional<Node> node;
        int nibble{-1};  // -1 points to the node itself instead of a nibble

        [[nodiscard]] Bytes full_key() const;
        [[nodiscard]] bool state_flag() const;
        [[nodiscard]] bool tree_flag() const;
        [[nodiscard]] bool hash_flag() const;
        [[nodiscard]] const evmc::bytes32* hash() const;
    };

    void consume_node(ByteView key, bool exact);

    void move_to_next_sibling(bool allow_root_to_child_nibble_within_subnode);

    void update_skip_state();

    mdbx::cursor db_cursor_;

    PrefixSet& changed_;

    etl::Collector* collector_;  // To queue deleted records and postpone deletion

    Bytes prefix_;

    std::vector<SubNode> subnodes_;

    bool can_skip_state_{false};
};

// class AccCursor {
//   public:
//     explicit AccCursor(mdbx::cursor& db_cursor, PrefixSet& changed, ByteView prefix = {},
//                        etl::Collector* collector = nullptr);
//
//     bool seek(ByteView prefix);  // Returns whether node is found
//     bool move_next();            // Returns whether node is found
//
//   private:
//     // TrieAccount(TrieStorage) node with a particular nibble selected
//     struct SubNode {
//         ByteView key{};
//         ByteView value{};
//         uint16_t state_mask{};
//         uint16_t tree_mask{};
//         uint16_t hash_mask{};
//         int8_t child_id{0};
//         int8_t hash_id{0};
//         bool deleted{false};
//
//         void reset();
//         void parse(ByteView k, ByteView v);
//     };
//
//     mdbx::cursor& db_cursor_;  // MDBX Cursor to TrieAccounts
//     PrefixSet& changed_;
//     etl::Collector* collector_{nullptr};  // To queue deleted records
//
//     std::vector<SubNode> sub_nodes_;
//     bool skip_state_{false};
//     size_t level_{0};
//
//     Bytes prefix_{};  // global prefix - cursor will never return keys without this prefix
//     Bytes prev_{};
//     Bytes curr_{};
//     Bytes next_{};
//     Bytes buff_{};
//
//     Bytes next_created_{};
//     Bytes first_uncovered_{};
//
//     bool has_state();
//     bool has_tree();
//     bool has_hash();
//
//     bool next();
//     void preorder_traversal_step();
//     void preorder_traversal_step_no_indepth();
//     void delete_current();
//
//     //! \brief Partially parses node
//     //! \remarks We don't need to copy all hashes for trie::Node
//     //! \see Erigon's _unmarshal
//     void parse_subnode(ByteView key, ByteView value);
//
//     void next_sibling_in_db();
//     bool next_sibling_in_mem();
//     bool next_sibling_of_parent_in_mem();
//
//     bool seek_in_db(ByteView within_prefix = {});
//
//     bool consume();
//
//     //! \brief Kinda normal lexicographic comparator with the difference empty keys are last
//     bool key_is_before(ByteView k1, ByteView k2);
// };

//! \brief Produces the next key in sequence from provided nibbled key
//! \details It's essentially +1 in the hexadecimal (base 16) numeral system.
//! \example
//! \verbatim
//! increment_key(120) = 121
//! increment_key(12e) = 12f
//! increment_key(12f) = 13
//! \endverbatim
//! \return The incremented (and eventually shortened) sequence of 0xF nibbles,
//! \remarks Being a prefix of nibbles trailing zeroes must be erased
std::optional<Bytes> increment_nibbled_key(ByteView nibbles);

////! \brief Computes the next uncovered (by trie cursor) prefix
// std::optional<Bytes> compute_next_uncovered_prefix(ByteView previous, ByteView prefix);

}  // namespace silkworm::trie

#endif  // SILKWORM_STAGEDSYNC_STAGE_INTERHASHES_CURSOR_HPP_