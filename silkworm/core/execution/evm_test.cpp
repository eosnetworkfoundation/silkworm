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

#include "evm.hpp"

#include <map>
#include <vector>

#include <catch2/catch.hpp>
#include <evmone/execution_state.hpp>

#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <eosevm/version.hpp>

#include "address.hpp"

namespace silkworm {

TEST_CASE("Value transfer") {
    Block block{};
    block.header.number = 10336006;

    evmc::address from{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb521_address};
    intx::uint256 value{10'200'000'000'000'000};

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};

    CHECK(state.get_balance(from) == 0);
    CHECK(state.get_balance(to) == 0);

    Transaction txn{};
    txn.from = from;
    txn.to = to;
    txn.value = value;

    CallResult res{evm.execute(txn, 0, {})};
    CHECK(res.status == EVMC_INSUFFICIENT_BALANCE);
    CHECK(res.data.empty());

    state.add_to_balance(from, kEther);

    res = evm.execute(txn, 0, {});
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    CHECK(state.get_balance(from) == kEther - value);
    CHECK(state.get_balance(to) == value);
    CHECK(state.touched().count(from) == 1);
    CHECK(state.touched().count(to) == 1);
}

TEST_CASE("Smart contract with storage") {
    Block block{};
    block.header.number = 1;
    evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

    // This contract initially sets its 0th storage to 0x2a
    // and its 1st storage to 0x01c9.
    // When called, it updates the 0th storage to the input provided.
    Bytes code{*from_hex("602a5f556101c960015560048060135f395ff35f355f55")};
    // https://github.com/CoinCulture/evm-tools/blob/master/analysis/guide.md#contracts
    // 0x00     PUSH1  => 2a
    // 0x02     PUSH0
    // 0x03     SSTORE         // storage[0] = 0x2a
    // 0x04     PUSH2  => 01c9
    // 0x07     PUSH1  => 01
    // 0x09     SSTORE         // storage[1] = 0x01c9
    // 0x0a     PUSH1  => 04   // deploy begin
    // 0x0c     DUP1
    // 0x0d     PUSH1  => 13
    // 0x0f     PUSH0
    // 0x10     CODECOPY
    // 0x11     PUSH0
    // 0x12     RETURN         // deploy end
    // 0x13     PUSH0          // contract code
    // 0x14     CALLDATALOAD
    // 0x15     PUSH0
    // 0x16     SSTORE         // storage[0] = input[0]

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, test::kShanghaiConfig};

    Transaction txn{};
    txn.from = caller;
    txn.data = code;

    uint64_t gas{0};
    CallResult res{evm.execute(txn, gas, {})};
    CHECK(res.status == EVMC_OUT_OF_GAS);
    CHECK(res.data.empty());

    gas = 50'000;
    res = evm.execute(txn, gas, {});
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(to_hex(res.data) == "5f355f55");

    evmc::address contract_address{create_address(caller, /*nonce=*/1)};
    evmc::bytes32 key0{};
    CHECK(to_hex(zeroless_view(state.get_current_storage(contract_address, key0))) == "2a");

    evmc::bytes32 new_val{to_bytes32(*from_hex("f5"))};
    txn.to = contract_address;
    txn.data = ByteView{new_val};

    res = evm.execute(txn, gas, {});
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());
    CHECK(state.get_current_storage(contract_address, key0) == new_val);
}

TEST_CASE("Maximum call depth") {
    Block block{};
    block.header.number = 1'431'916;
    evmc::address caller{0x8e4d1ea201b908ab5e1f5a1c3f9f1b4f6c1e9cf1_address};
    evmc::address contract{0x3589d05a1ec4af9f65b0e5554e645707775ee43c_address};

    // The contract just calls itself recursively a given number of times.
    Bytes code{*from_hex("60003580600857005b6001900360005260008060208180305a6103009003f1602357fe5b")};
    /* https://github.com/CoinCulture/evm-tools
    0      PUSH1  => 00
    2      CALLDATALOAD
    3      DUP1
    4      PUSH1  => 08
    6      JUMPI
    7      STOP
    8      JUMPDEST
    9      PUSH1  => 01
    11     SWAP1
    12     SUB
    13     PUSH1  => 00
    15     MSTORE
    16     PUSH1  => 00
    18     DUP1
    19     PUSH1  => 20
    21     DUP2
    22     DUP1
    23     ADDRESS
    24     GAS
    25     PUSH2  => 0300
    28     SWAP1
    29     SUB
    30     CALL
    31     PUSH1  => 23
    33     JUMPI
    34     INVALID
    35     JUMPDEST
    */

    InMemoryState db;
    IntraBlockState state{db};
    state.set_code(contract, code);

    EVM evm{block, state, kMainnetConfig};

    AnalysisCache analysis_cache{/*maxSize=*/16};
    evm.analysis_cache = &analysis_cache;

    Transaction txn{};
    txn.from = caller;
    txn.to = contract;

    uint64_t gas{1'000'000};
    CallResult res{evm.execute(txn, gas, {})};
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    evmc::bytes32 num_of_recursions{to_bytes32(*from_hex("0400"))};
    txn.data = ByteView{num_of_recursions};
    res = evm.execute(txn, gas, {});
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    num_of_recursions = to_bytes32(*from_hex("0401"));
    txn.data = ByteView{num_of_recursions};
    res = evm.execute(txn, gas, {});
    CHECK(res.status == EVMC_INVALID_INSTRUCTION);
    CHECK(res.data.empty());
}

TEST_CASE("DELEGATECALL") {
    Block block{};
    block.header.number = 1'639'560;
    evmc::address caller_address{0x8e4d1ea201b908ab5e1f5a1c3f9f1b4f6c1e9cf1_address};
    evmc::address callee_address{0x3589d05a1ec4af9f65b0e5554e645707775ee43c_address};

    // The callee writes the ADDRESS to storage.
    Bytes callee_code{*from_hex("30600055")};
    /* https://github.com/CoinCulture/evm-tools
    0      ADDRESS
    1      PUSH1  => 00
    3      SSTORE
    */

    // The caller delegate-calls the input contract.
    Bytes caller_code{*from_hex("6000808080803561eeeef4")};
    /* https://github.com/CoinCulture/evm-tools
    0      PUSH1  => 00
    2      DUP1
    3      DUP1
    4      DUP1
    5      DUP1
    6      CALLDATALOAD
    7      PUSH2  => eeee
    10     DELEGATECALL
    */

    InMemoryState db;
    IntraBlockState state{db};
    state.set_code(caller_address, caller_code);
    state.set_code(callee_address, callee_code);

    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.from = caller_address;
    txn.to = caller_address;
    txn.data = ByteView{to_bytes32(callee_address)};

    uint64_t gas{1'000'000};
    CallResult res{evm.execute(txn, gas, {})};
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    evmc::bytes32 key0{};
    CHECK(to_hex(zeroless_view(state.get_current_storage(caller_address, key0))) == to_hex(caller_address));
}

// https://eips.ethereum.org/EIPS/eip-211#specification
TEST_CASE("CREATE should only return on failure") {
    Block block{};
    block.header.number = 4'575'910;
    evmc::address caller{0xf466859ead1932d743d622cb74fc058882e8648a_address};

    Bytes code{
        *from_hex("0x602180601360003960006000f0503d600055006211223360005260206000602060006000600461900"
                  "0f1503d60005560206000f3")};
    /* https://github.com/CoinCulture/evm-tools
    0      PUSH1  => 21
    2      DUP1
    3      PUSH1  => 13
    5      PUSH1  => 00
    7      CODECOPY
    8      PUSH1  => 00
    10     PUSH1  => 00
    12     CREATE
    13     POP
    14     RETURNDATASIZE
    15     PUSH1  => 00
    17     SSTORE
    18     STOP
    19     PUSH3  => 112233
    23     PUSH1  => 00
    25     MSTORE
    26     PUSH1  => 20
    28     PUSH1  => 00
    30     PUSH1  => 20
    32     PUSH1  => 00
    34     PUSH1  => 00
    36     PUSH1  => 04
    38     PUSH2  => 9000
    41     CALL
    42     POP
    43     RETURNDATASIZE
    44     PUSH1  => 00
    46     SSTORE
    47     PUSH1  => 20
    49     PUSH1  => 00
    51     RETURN
    */

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.from = caller;
    txn.data = code;

    uint64_t gas{150'000};
    CallResult res{evm.execute(txn, gas, {})};
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    evmc::address contract_address{create_address(caller, /*nonce=*/0)};
    evmc::bytes32 key0{};
    CHECK(is_zero(state.get_current_storage(contract_address, key0)));
}

// https://github.com/ethereum/EIPs/issues/684
TEST_CASE("Contract overwrite") {
    Block block{};
    block.header.number = 7'753'545;

    Bytes old_code{*from_hex("6000")};
    Bytes new_code{*from_hex("6001")};

    evmc::address caller{0x92a1d964b8fc79c5694343cc943c27a94a3be131_address};

    evmc::address contract_address{create_address(caller, /*nonce=*/0)};

    InMemoryState db;
    IntraBlockState state{db};
    state.set_code(contract_address, old_code);

    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.from = caller;
    txn.data = new_code;

    uint64_t gas{100'000};
    CallResult res{evm.execute(txn, gas, {})};

    CHECK(res.status == EVMC_INVALID_INSTRUCTION);
    CHECK(res.gas_left == 0);
    CHECK(res.data.empty());
}

TEST_CASE("EIP-3541: Reject new contracts starting with the 0xEF byte") {
    const ChainConfig& config{kMainnetConfig};

    Block block;
    block.header.number = 13'500'000;
    REQUIRE(config.revision(block.header) == EVMC_LONDON);

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, config};

    Transaction txn;
    txn.from = 0x1000000000000000000000000000000000000000_address;
    const uint64_t gas{50'000};

    // https://eips.ethereum.org/EIPS/eip-3541#test-cases
    txn.data = *from_hex("0x60ef60005360016000f3");
    CHECK(evm.execute(txn, gas, {}).status == EVMC_CONTRACT_VALIDATION_FAILURE);

    txn.data = *from_hex("0x60ef60005360026000f3");
    CHECK(evm.execute(txn, gas, {}).status == EVMC_CONTRACT_VALIDATION_FAILURE);

    txn.data = *from_hex("0x60ef60005360036000f3");
    CHECK(evm.execute(txn, gas, {}).status == EVMC_CONTRACT_VALIDATION_FAILURE);

    txn.data = *from_hex("0x60ef60005360206000f3");
    CHECK(evm.execute(txn, gas, {}).status == EVMC_CONTRACT_VALIDATION_FAILURE);

    txn.data = *from_hex("0x60fe60005360016000f3");
    CHECK(evm.execute(txn, gas, {}).status == EVMC_SUCCESS);
}

class TestTracer : public EvmTracer {
  public:
    explicit TestTracer(std::optional<evmc::address> contract_address = std::nullopt,
                        std::optional<evmc::bytes32> key = std::nullopt)
        : contract_address_(contract_address), key_(key), rev_{} {}

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view bytecode) noexcept override {
        execution_start_called_ = true;
        rev_ = rev;
        msg_stack_.push_back(msg);
        bytecode_ = Bytes{bytecode};
    }
    void on_instruction_start(uint32_t pc, const intx::uint256* /*stack_top*/, int /*stack_height*/,
                              int64_t /*gas*/, const evmone::ExecutionState& state,
                              const IntraBlockState& intra_block_state) noexcept override {
        pc_stack_.push_back(pc);
        memory_size_stack_[pc] = state.memory.size();
        if (contract_address_) {
            storage_stack_[pc] =
                intra_block_state.get_current_storage(contract_address_.value(), key_.value_or(evmc::bytes32{}));
        }
    }
    void on_execution_end(const evmc_result& res, const IntraBlockState& intra_block_state) noexcept override {
        execution_end_called_ = true;
        const auto gas_left = static_cast<uint64_t>(res.gas_left);
        const auto gas_refund = static_cast<uint64_t>(res.gas_refund);
        const auto storage_gas_consumed = static_cast<uint64_t>(res.storage_gas_consumed);
        const auto storage_gas_refund = static_cast<uint64_t>(res.storage_gas_refund);
        const auto speculative_cpu_gas_consumed = static_cast<uint64_t>(res.speculative_cpu_gas_consumed);

        result_ = {res.status_code, gas_left, gas_refund, storage_gas_consumed, storage_gas_refund, speculative_cpu_gas_consumed, {res.output_data, res.output_size}};
        if (contract_address_ && !pc_stack_.empty()) {
            const auto pc = pc_stack_.back();
            storage_stack_[pc] =
                intra_block_state.get_current_storage(contract_address_.value(), key_.value_or(evmc::bytes32{}));
        }
    }

    void on_creation_completed(const evmc_result& /*result*/, const IntraBlockState& /*intra_block_state*/) noexcept override {
        creation_completed_called_ = true;
    }

    void on_precompiled_run(const evmc_result& /*result*/, int64_t /*gas*/,
                            const IntraBlockState& /*intra_block_state*/) noexcept override {}
    void on_reward_granted(const CallResult& /*result*/,
                           const IntraBlockState& /*intra_block_state*/) noexcept override {}

    [[nodiscard]] bool execution_start_called() const { return execution_start_called_; }
    [[nodiscard]] bool execution_end_called() const { return execution_end_called_; }
    [[nodiscard]] bool creation_completed_called() const { return creation_completed_called_; }
    [[nodiscard]] const Bytes& bytecode() const { return bytecode_; }
    [[nodiscard]] const evmc_revision& rev() const { return rev_; }
    [[nodiscard]] const std::vector<evmc_message>& msg_stack() const { return msg_stack_; }
    [[nodiscard]] const std::vector<uint32_t>& pc_stack() const { return pc_stack_; }
    [[nodiscard]] const std::map<uint32_t, std::size_t>& memory_size_stack() const { return memory_size_stack_; }
    [[nodiscard]] const std::map<uint32_t, evmc::bytes32>& storage_stack() const { return storage_stack_; }
    [[nodiscard]] const CallResult& result() const { return result_; }

  private:
    bool execution_start_called_{false};
    bool execution_end_called_{false};
    bool creation_completed_called_{false};
    std::optional<evmc::address> contract_address_;
    std::optional<evmc::bytes32> key_;
    evmc_revision rev_;
    std::vector<evmc_message> msg_stack_;
    Bytes bytecode_;
    std::vector<uint32_t> pc_stack_;
    std::map<uint32_t, std::size_t> memory_size_stack_;
    std::map<uint32_t, evmc::bytes32> storage_stack_;
    CallResult result_;
};

TEST_CASE("Tracing smart contract with storage") {
    Block block{};
    block.header.number = 10'336'006;
    evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

    // This contract initially sets its 0th storage to 0x2a
    // and its 1st storage to 0x01c9.
    // When called, it updates the 0th storage to the input provided.
    Bytes code{*from_hex("602a6000556101c960015560068060166000396000f3600035600055")};
    // https://github.com/CoinCulture/evm-tools
    // 0      PUSH1  => 2a
    // 2      PUSH1  => 00
    // 4      SSTORE         // storage[0] = 0x2a
    // 5      PUSH2  => 01c9
    // 8      PUSH1  => 01
    // 10     SSTORE         // storage[1] = 0x01c9
    // 11     PUSH1  => 06   // deploy begin
    // 13     DUP1
    // 14     PUSH1  => 16
    // 16     PUSH1  => 00
    // 18     CODECOPY
    // 19     PUSH1  => 00
    // 21     RETURN         // deploy end
    // 22     PUSH1  => 00   // contract code
    // 24     CALLDATALOAD
    // 25     PUSH1  => 00
    // 27     SSTORE         // storage[0] = input[0]

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.from = caller;
    txn.data = code;

    CHECK(evm.tracers().empty());

    // First execution: out of gas
    TestTracer tracer1;
    evm.add_tracer(tracer1);
    CHECK(evm.tracers().size() == 1);

    uint64_t gas{0};
    CallResult res{evm.execute(txn, gas, {})};
    CHECK(res.status == EVMC_OUT_OF_GAS);
    CHECK(res.data.empty());

    CHECK((tracer1.execution_start_called() && tracer1.execution_end_called() && tracer1.creation_completed_called()));
    CHECK(tracer1.rev() == evmc_revision::EVMC_ISTANBUL);
    CHECK(tracer1.msg_stack().at(0).kind == evmc_call_kind::EVMC_CALL);
    CHECK(tracer1.msg_stack().at(0).flags == 0);
    CHECK(tracer1.msg_stack().at(0).depth == 0);
    CHECK(tracer1.msg_stack().at(0).gas == 0);
    CHECK(tracer1.bytecode() == code);
    CHECK(tracer1.pc_stack() == std::vector<uint32_t>{0});
    CHECK(tracer1.memory_size_stack() == std::map<uint32_t, std::size_t>{{0, 0}});
    CHECK(tracer1.result().status == EVMC_OUT_OF_GAS);
    CHECK(tracer1.result().gas_left == 0);
    CHECK(tracer1.result().data.empty());

    // Second execution: success
    TestTracer tracer2;
    evm.add_tracer(tracer2);
    CHECK(evm.tracers().size() == 2);

    gas = 50'000;
    res = evm.execute(txn, gas, {});
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data == from_hex("600035600055"));

    CHECK((tracer2.execution_start_called() && tracer2.execution_end_called()));
    CHECK(tracer2.rev() == evmc_revision::EVMC_ISTANBUL);
    CHECK(tracer2.msg_stack().at(0).kind == evmc_call_kind::EVMC_CALL);
    CHECK(tracer2.msg_stack().at(0).flags == 0);
    CHECK(tracer2.msg_stack().at(0).depth == 0);
    CHECK(tracer2.msg_stack().at(0).gas == 50'000);
    CHECK(tracer2.bytecode() == code);
    CHECK(tracer2.pc_stack() == std::vector<uint32_t>{0, 2, 4, 5, 8, 10, 11, 13, 14, 16, 18, 19, 21});
    CHECK(tracer2.memory_size_stack() == std::map<uint32_t, std::size_t>{{0, 0},
                                                                         {2, 0},
                                                                         {4, 0},
                                                                         {5, 0},
                                                                         {8, 0},
                                                                         {10, 0},
                                                                         {11, 0},
                                                                         {13, 0},
                                                                         {14, 0},
                                                                         {16, 0},
                                                                         {18, 0},
                                                                         {19, 32},
                                                                         {21, 32}});
    CHECK(tracer2.result().status == EVMC_SUCCESS);
    CHECK(tracer2.result().gas_left == 9964);
    CHECK(tracer2.result().data == res.data);

    // Third execution: success
    evmc::address contract_address{create_address(caller, 1)};
    evmc::bytes32 key0{};

    TestTracer tracer3{contract_address, key0};
    evm.add_tracer(tracer3);
    CHECK(evm.tracers().size() == 3);

    CHECK(to_hex(zeroless_view(state.get_current_storage(contract_address, key0))) == "2a");
    evmc::bytes32 new_val{to_bytes32(*from_hex("f5"))};
    txn.to = contract_address;
    txn.data = ByteView{new_val};
    gas = 50'000;
    res = evm.execute(txn, gas, {});
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());
    CHECK(state.get_current_storage(contract_address, key0) == new_val);

    CHECK((tracer3.execution_start_called() && tracer3.execution_end_called()));
    CHECK(tracer3.rev() == evmc_revision::EVMC_ISTANBUL);
    CHECK(tracer3.msg_stack().at(0).kind == evmc_call_kind::EVMC_CALL);
    CHECK(tracer3.msg_stack().at(0).flags == 0);
    CHECK(tracer3.msg_stack().at(0).depth == 0);
    CHECK(tracer3.msg_stack().at(0).gas == 50'000);
    CHECK(tracer3.storage_stack() == std::map<uint32_t, evmc::bytes32>{
                                         {0, to_bytes32(*from_hex("2a"))},
                                         {2, to_bytes32(*from_hex("2a"))},
                                         {3, to_bytes32(*from_hex("2a"))},
                                         {5, to_bytes32(*from_hex("f5"))},
                                     });
    CHECK(tracer3.pc_stack() == std::vector<uint32_t>{0, 2, 3, 5});
    CHECK(tracer3.memory_size_stack() == std::map<uint32_t, std::size_t>{{0, 0}, {2, 0}, {3, 0}, {5, 0}});
    CHECK(tracer3.result().status == EVMC_SUCCESS);
    CHECK(tracer3.result().gas_left == 49191);
    CHECK(tracer3.result().data.empty());
}

TEST_CASE("Tracing creation smart contract with CREATE2") {
    Block block{};
    block.header.number = 10'336'006;
    evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

    Bytes code{*from_hex(
        "6080604052348015600f57600080fd5b506000801b604051601e906043565b81"
        "90604051809103906000f5905080158015603d573d6000803e3d6000fd5b5050"
        "604f565b605c8061009c83390190565b603f8061005d6000396000f3fe608060"
        "4052600080fdfea2646970667358221220ffaf2d6fdd061c3273248388b99d0e"
        "48f13466b078ba552718eb14d618127f5f64736f6c6343000813003360806040"
        "52348015600f57600080fd5b50603f80601d6000396000f3fe60806040526000"
        "80fdfea2646970667358221220ea2cccbd9b69291ff50e3244e6b74392bb58de"
        "7268abedc75e862628e939d32e64736f6c63430008130033")};
    // pragma solidity 0.8.19;
    //
    // contract Factory {
    //     constructor() {
    //         new TestContract{salt: 0}();
    //     }
    // }
    // contract TestContract {
    //     constructor() {}
    // }

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.from = caller;
    txn.data = code;

    TestTracer tracer;
    evm.add_tracer(tracer);
    CHECK(evm.tracers().size() == 1);

    uint64_t gas = {100'000};
    CallResult res{evm.execute(txn, gas, {})};

    CHECK(tracer.msg_stack().at(0).depth == 0);
    CHECK(tracer.msg_stack().at(1).depth == 1);

    CHECK(tracer.msg_stack().at(0).kind == evmc_call_kind::EVMC_CALL);
    CHECK(tracer.msg_stack().at(1).kind == evmc_call_kind::EVMC_CREATE2);
}

TEST_CASE("Tracing smart contract w/o code") {
    Block block{};
    block.header.number = 10'336'006;

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};
    CHECK(evm.tracers().empty());

    TestTracer tracer1;
    evm.add_tracer(tracer1);
    CHECK(evm.tracers().size() == 1);

    // Deploy contract without code
    evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    Bytes code{};

    Transaction txn{};
    txn.from = caller;
    txn.data = code;
    uint64_t gas{50'000};

    CallResult res{evm.execute(txn, gas, {})};
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    CHECK(tracer1.execution_start_called());
    CHECK(tracer1.execution_end_called());
    CHECK(tracer1.rev() == evmc_revision::EVMC_ISTANBUL);
    CHECK(tracer1.bytecode() == code);
    CHECK(tracer1.pc_stack().empty());
    CHECK(tracer1.memory_size_stack().empty());
    CHECK(tracer1.result().status == EVMC_SUCCESS);
    CHECK(tracer1.result().gas_left == gas);
    CHECK(tracer1.result().data.empty());

    // Send message to empty contract
    evmc::address contract_address{create_address(caller, 1)};
    evmc::bytes32 key0{};

    TestTracer tracer2{contract_address, key0};
    evm.add_tracer(tracer2);
    CHECK(evm.tracers().size() == 2);

    txn.to = contract_address;
    txn.data = ByteView{to_bytes32(*from_hex("f5"))};
    res = evm.execute(txn, gas, {});
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data.empty());

    CHECK(tracer2.execution_start_called());
    CHECK(tracer2.execution_end_called());
    CHECK(tracer2.rev() == evmc_revision::EVMC_ISTANBUL);
    CHECK(tracer2.bytecode() == code);
    CHECK(tracer2.pc_stack().empty());
    CHECK(tracer2.memory_size_stack().empty());
    CHECK(tracer2.result().status == EVMC_SUCCESS);
    CHECK(tracer2.result().gas_left == gas);
    CHECK(tracer2.result().data.empty());
}

TEST_CASE("Tracing precompiled contract failure") {
    Block block{};
    block.header.number = 10'336'006;

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};
    CHECK(evm.tracers().empty());

    TestTracer tracer1;
    evm.add_tracer(tracer1);
    CHECK(evm.tracers().size() == 1);

    // Execute transaction Deploy contract without code
    evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

    evmc::address blake2f_precompile{0x0000000000000000000000000000000000000009_address};

    Transaction txn{};
    txn.from = caller;
    txn.to = blake2f_precompile;
    uint64_t gas{50'000};

    CallResult res{evm.execute(txn, gas, {})};
    CHECK(res.status == EVMC_PRECOMPILE_FAILURE);
}

TEST_CASE("Smart contract creation w/ insufficient balance") {
    Block block{};
    block.header.number = 1;
    evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

    Bytes code{*from_hex("602a5f556101c960015560048060135f395ff35f355f55")};

    InMemoryState db;
    IntraBlockState state{db};
    EVM evm{block, state, test::kShanghaiConfig};

    Transaction txn{};
    txn.from = caller;
    txn.data = code;
    txn.value = intx::uint256{1};

    uint64_t gas = 50'000;
    CallResult res = evm.execute(txn, gas, {});
    CHECK(res.status == EVMC_INSUFFICIENT_BALANCE);
}

TEST_CASE("EOS EVM codedeposit test") {
    Block block{};
    block.header.number = 1;
    block.header.nonce = eosevm::version_to_nonce(1);

    evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    Bytes code{*from_hex("608060405234801561001057600080fd5b50610173806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c806313bdfacd14610030575b600080fd5b61003861004e565b604051610045919061011b565b60405180910390f35b60606040518060400160405280600c81526020017f48656c6c6f20576f726c64210000000000000000000000000000000000000000815250905090565b600081519050919050565b600082825260208201905092915050565b60005b838110156100c55780820151818401526020810190506100aa565b60008484015250505050565b6000601f19601f8301169050919050565b60006100ed8261008b565b6100f78185610096565b93506101078185602086016100a7565b610110816100d1565b840191505092915050565b6000602082019050818103600083015261013581846100e2565b90509291505056fea264697066735822122046344ce4c7e7c91dba98aef897cc7773af40fbff6b6da10885c36037b9d37a3764736f6c63430008110033")};

    evmone::gas_parameters gas_params;
    gas_params.G_codedeposit = 500;

    InMemoryState db;
    IntraBlockState state{db};
    state.set_balance(caller, intx::uint256{1e18});
    EVM evm{block, state, test::kIstanbulTrustConfig};

    Transaction txn{};
    txn.from = caller;
    txn.data = code;

    uint64_t gas = 1'500'000;
    CallResult res = evm.execute(txn, 1'500'000, gas_params);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(gas-res.gas_left == 123 + 500*371); //G_codedeposit=500, codelen=371
    CHECK(res.storage_gas_consumed == 0);
    CHECK(res.storage_gas_refund == 0);
    CHECK(res.speculative_cpu_gas_consumed == 0);
}

TEST_CASE("EOS EVM codedeposit v3 test") {
    Block block{};
    block.header.number = 1;
    block.header.nonce = eosevm::version_to_nonce(3);

    evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    Bytes code{*from_hex("608060405234801561001057600080fd5b50610173806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c806313bdfacd14610030575b600080fd5b61003861004e565b604051610045919061011b565b60405180910390f35b60606040518060400160405280600c81526020017f48656c6c6f20576f726c64210000000000000000000000000000000000000000815250905090565b600081519050919050565b600082825260208201905092915050565b60005b838110156100c55780820151818401526020810190506100aa565b60008484015250505050565b6000601f19601f8301169050919050565b60006100ed8261008b565b6100f78185610096565b93506101078185602086016100a7565b610110816100d1565b840191505092915050565b6000602082019050818103600083015261013581846100e2565b90509291505056fea264697066735822122046344ce4c7e7c91dba98aef897cc7773af40fbff6b6da10885c36037b9d37a3764736f6c63430008110033")};

    evmone::gas_parameters gas_params;
    gas_params.G_codedeposit = 500;

    InMemoryState db;
    IntraBlockState state{db};
    state.set_balance(caller, intx::uint256{1e18});
    state.set_nonce(caller, 10);
    EVM evm{block, state, test::kIstanbulTrustConfig};

    Transaction txn{};
    txn.from = caller;
    txn.data = code;

    uint64_t gas = 1'500'000;
    CallResult res = evm.execute(txn, gas, gas_params);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(gas-res.gas_left == 123 + 500*371); //G_codedeposit=500, codelen=371
    CHECK(res.storage_gas_consumed == 500*371);
    CHECK(res.storage_gas_refund == 0);
    CHECK(res.speculative_cpu_gas_consumed == 0);

    // verify that the code was indeed persisted
    auto contract_addr = create_address(caller, 10);
    auto c = state.get_code(contract_addr);
    CHECK(c.size() != 0);
}

TEST_CASE("EOS EVM codedeposit v3 test oog") {
    Block block{};
    block.header.number = 1;
    block.header.nonce = eosevm::version_to_nonce(3);

    evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    Bytes code{*from_hex("608060405234801561001057600080fd5b50610173806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c806313bdfacd14610030575b600080fd5b61003861004e565b604051610045919061011b565b60405180910390f35b60606040518060400160405280600c81526020017f48656c6c6f20576f726c64210000000000000000000000000000000000000000815250905090565b600081519050919050565b600082825260208201905092915050565b60005b838110156100c55780820151818401526020810190506100aa565b60008484015250505050565b6000601f19601f8301169050919050565b60006100ed8261008b565b6100f78185610096565b93506101078185602086016100a7565b610110816100d1565b840191505092915050565b6000602082019050818103600083015261013581846100e2565b90509291505056fea264697066735822122046344ce4c7e7c91dba98aef897cc7773af40fbff6b6da10885c36037b9d37a3764736f6c63430008110033")};

    evmone::gas_parameters gas_params;
    gas_params.G_codedeposit = 500;

    InMemoryState db;
    IntraBlockState state{db};
    state.set_balance(caller, intx::uint256{1e18});
    EVM evm{block, state, test::kIstanbulTrustConfig};

    Transaction txn{};
    txn.from = caller;
    txn.data = code;

    uint64_t gas = 123 + 500*370; // enough to run initialization (real), but not enough to store code (speculative)
    CallResult res = evm.execute(txn, gas, gas_params);
    CHECK(res.status == EVMC_OUT_OF_GAS);
    CHECK(res.gas_left == 500*370);
    CHECK(res.storage_gas_consumed == 0);
    CHECK(res.storage_gas_refund == 0);
    CHECK(res.speculative_cpu_gas_consumed == 0);

    InMemoryState db2;
    IntraBlockState state2{db2};
    state2.set_balance(caller, intx::uint256{1e18});
    EVM evm2{block, state2, test::kIstanbulTrustConfig};

    Transaction txn2{};
    txn2.from = caller;
    txn2.data = code;

    uint64_t gas2 = 122; // not-enough to run initialization (real)
    CallResult res2 = evm2.execute(txn, gas2, gas_params);
    CHECK(res2.status == EVMC_OUT_OF_GAS);
    CHECK(res2.gas_left == 0);
    CHECK(res2.storage_gas_consumed == 0);
    CHECK(res2.storage_gas_refund == 0);
    CHECK(res2.speculative_cpu_gas_consumed == 0);
}

TEST_CASE("EOS EVM G_txnewaccount") {
    Block block{};
    block.header.number = 1;
    block.header.nonce = eosevm::version_to_nonce(1);

    evmc::address sender{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    evmc::address receiver1{0x1a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    evmc::address receiver2{0x1000000000000000000000000000000000000001_address};

    evmone::gas_parameters gas_params;
    gas_params.G_txnewaccount = 0;

    InMemoryState db;
    IntraBlockState state{db};
    state.set_balance(sender, intx::uint256{1e18});
    EVM evm{block, state, test::kIstanbulTrustConfig};

    Transaction txn{};
    txn.from = sender;
    txn.to = receiver1;
    txn.value = intx::uint256{1};

    CallResult res = evm.execute(txn, 0, gas_params);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.gas_left == 0);
    CHECK(res.gas_refund == 0);
    CHECK(res.storage_gas_consumed == 0);
    CHECK(res.storage_gas_refund == 0);
    CHECK(res.speculative_cpu_gas_consumed == 0);

    txn.to = receiver2;
    gas_params.G_txnewaccount = 1;

    res = evm.execute(txn, 0, gas_params);
    CHECK(res.status == EVMC_OUT_OF_GAS);
    CHECK(res.gas_refund == 0);
    CHECK(res.gas_left == 0);
    CHECK(res.storage_gas_consumed == 0);
    CHECK(res.storage_gas_refund == 0);
    CHECK(res.speculative_cpu_gas_consumed == 0);
}

TEST_CASE("EOS EVM G_txnewaccount v3") {
    Block block{};
    block.header.number = 1;
    block.header.nonce = eosevm::version_to_nonce(3);

    evmc::address sender{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    evmc::address receiver1{0x1a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    evmc::address receiver2{0x1000000000000000000000000000000000000001_address};

    evmone::gas_parameters gas_params;
    gas_params.G_txnewaccount = 1000;

    InMemoryState db;
    IntraBlockState state{db};
    state.set_balance(sender, intx::uint256{1e18});
    EVM evm{block, state, test::kIstanbulTrustConfig};

    Transaction txn{};
    txn.from = sender;
    txn.to = receiver1;
    txn.value = intx::uint256{1};

    CallResult res = evm.execute(txn, 1000, gas_params);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.gas_left == 0);
    CHECK(res.gas_refund == 0);
    CHECK(res.storage_gas_consumed == 1000);
    CHECK(res.storage_gas_refund == 0);
    CHECK(res.speculative_cpu_gas_consumed == 0);

    InMemoryState db2;
    IntraBlockState state2{db2};
    state2.set_balance(sender, intx::uint256{1e18});
    EVM evm2{block, state2, test::kIstanbulTrustConfig};

    Transaction txn2{};
    txn2.from = sender;
    txn2.to = receiver1;
    txn2.value = intx::uint256{1};

    CallResult res2 = evm2.execute(txn2, 999, gas_params);
    CHECK(res2.status == EVMC_OUT_OF_GAS);
    CHECK(res2.gas_left == 999);
    CHECK(res2.gas_refund == 0);
    CHECK(res2.storage_gas_consumed == 0);
    CHECK(res2.storage_gas_refund == 0);
    CHECK(res2.speculative_cpu_gas_consumed == 0);
}


TEST_CASE("EOS EVM send value to reserved address (tx)") {

    auto send_tx_to_reserved_address = [&](uint64_t version, const evmone::gas_parameters& gas_params, uint64_t gas_limit) {

        Block block{};
        block.header.number = 1;
        block.header.nonce = eosevm::version_to_nonce(version);

        evmc::address sender{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
        evmc::address receiver1{make_reserved_address(0x3ab3400000000000)}; //beto

        InMemoryState db;
        IntraBlockState state{db};
        state.set_balance(sender, intx::uint256{1e18});
        EVM evm{block, state, test::kIstanbulTrustConfig};

        Transaction txn{};
        txn.from = sender;
        txn.to = receiver1;
        txn.value = intx::uint256{1};

        CallResult res = evm.execute(txn, gas_limit, gas_params);
        return res;
    };

    evmone::gas_parameters gas_params;

    //version = 1, G_txnewaccount = 0, gas_limit = 1000
    gas_params.G_txnewaccount = 0;
    auto res1 = send_tx_to_reserved_address(1, gas_params, 1000);
    CHECK(res1.status == EVMC_SUCCESS);
    CHECK(res1.gas_left == 1000);
    CHECK(res1.gas_refund == 0);
    CHECK(res1.storage_gas_consumed == 0);
    CHECK(res1.storage_gas_refund == 0);
    CHECK(res1.speculative_cpu_gas_consumed == 0);

    //version = 2, G_txnewaccount = 5000, gas_limit = 4999
    gas_params.G_txnewaccount = 5000;
    auto res2 = send_tx_to_reserved_address(1, gas_params, 4999);
    CHECK(res2.status == EVMC_SUCCESS);
    CHECK(res2.gas_left == 4999);
    CHECK(res2.gas_refund == 0);
    CHECK(res2.storage_gas_consumed == 0);
    CHECK(res2.storage_gas_refund == 0);
    CHECK(res2.speculative_cpu_gas_consumed == 0);

}

}  // namespace silkworm
