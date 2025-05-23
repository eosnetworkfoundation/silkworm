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

#include "estimate_gas_oracle.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <gmock/gmock.h>

#include <silkworm/db/chain/remote_chain_storage.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/db/kv/grpc/client/remote_transaction.hpp>
#include <silkworm/db/test_util/kv_test_base.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>
#include <silkworm/rpc/test_util/mock_back_end.hpp>
#include <silkworm/rpc/test_util/mock_estimate_gas_oracle.hpp>
#include <silkworm/rpc/types/block.hpp>
#include <eosevm/version.hpp>

namespace silkworm::rpc {

class RemoteDatabaseTest : public db::test_util::KVTestBase {
  public:
    db::kv::api::CoherentStateCache state_cache;
};

using testing::_;
using testing::Return;

TEST_CASE("EstimateGasException") {
    SECTION("EstimateGasException(int64_t, std::string const&)") {
        static constexpr char kErrorMessage[] = "insufficient funds for transfer";
        constexpr int64_t kErrorCode = -1;
        EstimateGasException ex{kErrorCode, kErrorMessage};
        CHECK(ex.error_code() == kErrorCode);
        CHECK(ex.message() == kErrorMessage);
        CHECK(std::strcmp(ex.what(), kErrorMessage) == 0);
    }
    SECTION("EstimateGasException(int64_t, std::string const&, silkworm::Bytes const&)") {
        static constexpr char kErrorMessage[] = "execution failed";
        constexpr int64_t kErrorCode = 3;
        const silkworm::Bytes data{*silkworm::from_hex("0x00")};
        EstimateGasException ex{kErrorCode, kErrorMessage, data};
        CHECK(ex.error_code() == kErrorCode);
        CHECK(ex.message() == kErrorMessage);
        CHECK(ex.data() == data);
        CHECK(std::strcmp(ex.what(), kErrorMessage) == 0);
    }
}

TEST_CASE("estimate gas") {
    WorkerPool pool{1};
    WorkerPool workers{1};

    intx::uint256 balance{1'000'000'000};

    silkworm::BlockHeader block_header;
    block_header.gas_limit = kTxGas * 2;

    silkworm::Account account{0, balance};

    BlockHeaderProvider block_header_provider = [&block_header](BlockNum /*block_num*/) -> Task<std::optional<BlockHeader>> {
        co_return block_header;
    };

    AccountReader account_reader = [&account](const evmc::address& /*address*/, std::optional<TxnId> /* txn_id */) -> Task<std::optional<silkworm::Account>> {
        co_return account;
    };

    Call call;
    const silkworm::Block block;
    const silkworm::ChainConfig& config{kMainnetConfig};
    RemoteDatabaseTest remote_db_test;
    test::BackEndMock backend;
    db::chain::Providers providers = ethdb::kv::make_backend_providers(&backend);
    auto tx = std::make_unique<db::kv::grpc::client::RemoteTransaction>(remote_db_test.stub(),
                                                                        remote_db_test.grpc_context(),
                                                                        &remote_db_test.state_cache,
                                                                        providers);
    const db::chain::RemoteChainStorage storage{*tx, std::move(providers)};
    AccountsOverrides accounts_overrides;
    MockEstimateGasOracle estimate_gas_oracle{block_header_provider, account_reader, config, workers, *tx, storage, accounts_overrides};

    SECTION("Conservative gas: check failure when gas=0 and inclusio_price>0") {
        block_header.number = 1;
        block_header.nonce = eosevm::version_to_nonce(eosevm::EVM_VERSION_3);
        try {
            call.gas = 0;
            call.max_priority_fee_per_gas = 1;
            call.max_fee_per_gas = 2;
            auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 1), boost::asio::use_future);
            result.get();
            CHECK(false);
        } catch (const silkworm::rpc::EstimateGasException& e) {
            CHECK(e.message() == "inclusion_price must be 0");
        } catch (const std::exception&) {
            CHECK(false);
        } catch (...) {
            CHECK(false);
        }
    }


    SECTION("Call empty, always fails but success in last step") {
        ExecutionResult expect_result_ok{.error_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.error_code = evmc_status_code::EVMC_OUT_OF_GAS};
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(16)
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas * 2);
    }

    SECTION("Call empty, always succeeds") {
        ExecutionResult expect_result_ok{.error_code = evmc_status_code::EVMC_SUCCESS};
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _)).Times(14).WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();
        CHECK(estimate_gas == kTxGas);
    }

    SECTION("Call empty, alternatively fails and succeeds") {
        ExecutionResult expect_result_ok{.error_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.error_code = evmc_status_code::EVMC_OUT_OF_GAS};
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(14)
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0x88b6);
    }

    SECTION("Call empty, alternatively succeeds and fails") {
        ExecutionResult expect_result_ok{.error_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.error_code = evmc_status_code::EVMC_OUT_OF_GAS};
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(14)
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillRepeatedly(Return(expect_result_fail));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0x6d5e);
    }

    SECTION("Call empty, alternatively succeeds and fails with intrinsic") {
        ExecutionResult expect_result_ok{.error_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail_pre_check{
            .pre_check_error = "intrinsic ",
            .pre_check_error_code = PreCheckErrorCode::kIntrinsicGasTooLow};
        ExecutionResult expect_result_fail{.error_code = evmc_status_code::EVMC_OUT_OF_GAS};
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(14)
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail_pre_check))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail_pre_check))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail_pre_check))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail_pre_check))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail_pre_check))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail_pre_check))
            .WillOnce(Return(expect_result_ok))
            .WillRepeatedly(Return(expect_result_fail));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0x6d5e);
    }

    SECTION("Call with gas, always fails but succes last step") {
        call.gas = kTxGas * 4;
        ExecutionResult expect_result_ok{.error_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.error_code = evmc_status_code::EVMC_OUT_OF_GAS};
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(17)
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas * 4);
    }

    SECTION("Call with gas, always succeeds") {
        call.gas = kTxGas * 4;
        ExecutionResult expect_result_ok{.error_code = evmc_status_code::EVMC_SUCCESS};
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(15)
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas);
    }

    SECTION("Call with gas_price, gas not capped") {
        ExecutionResult expect_result_ok{.error_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.error_code = evmc_status_code::EVMC_OUT_OF_GAS};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{10'000};

        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(16)
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas * 2);
    }

    SECTION("Call with gas_price, gas capped") {
        ExecutionResult expect_result_ok{.error_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.error_code = evmc_status_code::EVMC_OUT_OF_GAS};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{40'000};

        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(13)
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0x61a8);
    }

    SECTION("Call with gas_price and value, gas not capped") {
        ExecutionResult expect_result_ok{.error_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.error_code = evmc_status_code::EVMC_OUT_OF_GAS};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{10'000};
        call.value = intx::uint256{500'000'000};

        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(16)
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas * 2);
    }

    SECTION("Call with gas_price and value, gas capped") {
        ExecutionResult expect_result_ok{.error_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.error_code = evmc_status_code::EVMC_OUT_OF_GAS};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{20'000};
        call.value = intx::uint256{500'000'000};

        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(13)
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0x61a8);
    }

    SECTION("Call gas above allowance, always succeeds, gas capped") {
        ExecutionResult expect_result_ok{.error_code = evmc_status_code::EVMC_SUCCESS};
        call.gas = kGasCap * 2;
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _)).Times(25).WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas);
    }

    SECTION("Call gas below minimum, always succeeds") {
        ExecutionResult expect_result_ok{.error_code = evmc_status_code::EVMC_SUCCESS};
        call.gas = kTxGas / 2;

        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _)).Times(14).WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas);
    }

    SECTION("Call with too high value, exception") {
        ExecutionResult expect_result_fail{.error_code = evmc_status_code::EVMC_OUT_OF_GAS};
        call.value = intx::uint256{2'000'000'000};

        try {
            EXPECT_CALL(estimate_gas_oracle, try_execution(_, _)).Times(16).WillRepeatedly(Return(expect_result_fail));
            auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
            result.get();
            CHECK(false);
        } catch (const silkworm::rpc::EstimateGasException&) {
            CHECK(true);
        } catch (const std::exception&) {
            CHECK(false);
        } catch (...) {
            CHECK(false);
        }
    }

    SECTION("Call fail, try exception") {
        ExecutionResult expect_result_fail_pre_check{
            .pre_check_error = "insufficient funds",
            .pre_check_error_code = PreCheckErrorCode::kInsufficientFunds};
        ExecutionResult expect_result_fail{.error_code = evmc_status_code::EVMC_OUT_OF_GAS};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{20'000};
        call.value = intx::uint256{500'000'000};

        try {
            EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
                .Times(2)
                .WillOnce(Return(expect_result_fail))
                .WillRepeatedly(Return(expect_result_fail_pre_check));
            auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
            result.get();
            CHECK(false);
        } catch (const silkworm::rpc::EstimateGasException&) {
            CHECK(true);
        } catch (const std::exception&) {
            CHECK(false);
        } catch (...) {
            CHECK(false);
        }
    }

    SECTION("Call fail, try exception with data") {
        auto data = *silkworm::from_hex("2ac3c1d3e24b45c6c310534bc2dd84b5ed576335");
        ExecutionResult expect_result_fail_pre_check{
            .pre_check_error = "insufficient funds",
            .pre_check_error_code = PreCheckErrorCode::kInsufficientFunds};
        ExecutionResult expect_result_fail{.error_code = evmc_status_code::EVMC_OUT_OF_GAS, .data = data};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{20'000};
        call.value = intx::uint256{500'000'000};

        try {
            EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
                .Times(2)
                .WillOnce(Return(expect_result_fail))
                .WillRepeatedly(Return(expect_result_fail_pre_check));
            auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
            result.get();
            CHECK(false);
        } catch (const silkworm::rpc::EstimateGasException&) {
            CHECK(true);
        } catch (const std::exception&) {
            CHECK(false);
        } catch (...) {
            CHECK(false);
        }
    }

    SECTION("Call fail-EVMC_INVALID_INSTRUCTION, try exception") {
        ExecutionResult expect_result_fail_pre_check{
            .pre_check_error = "insufficient funds",
            .pre_check_error_code = PreCheckErrorCode::kInsufficientFunds};
        ExecutionResult expect_result_fail{.error_code = evmc_status_code::EVMC_INVALID_INSTRUCTION};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{20'000};
        call.value = intx::uint256{500'000'000};

        try {
            EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
                .Times(2)
                .WillOnce(Return(expect_result_fail))
                .WillRepeatedly(Return(expect_result_fail_pre_check));
            auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
            result.get();
            CHECK(false);
        } catch (const silkworm::rpc::EstimateGasException&) {
            CHECK(true);
        } catch (const std::exception&) {
            CHECK(false);
        } catch (...) {
            CHECK(false);
        }
    }
}

// TEST_CASE("estimate conservative gas") {
//     boost::asio::thread_pool pool{1};
//     boost::asio::thread_pool workers{1};

//     intx::uint256 kBalance{1'000'000'000};

//     silkworm::BlockHeader kBlockHeader;
//     kBlockHeader.number = 1;
//     kBlockHeader.gas_limit = kTxGas * 2;
//     kBlockHeader.nonce = eosevm::version_to_nonce(eosevm::EVM_VERSION_3);

//     silkworm::Account kAccount{0, kBalance};

//     BlockHeaderProvider block_header_provider = [&kBlockHeader](uint64_t /*block_number*/) -> boost::asio::awaitable<silkworm::BlockHeader> {
//         co_return kBlockHeader;
//     };

//     AccountReader account_reader = [&kAccount](const evmc::address& /*address*/, uint64_t /*block_number*/) -> boost::asio::awaitable<std::optional<silkworm::Account>> {
//         co_return kAccount;
//     };

//     Call call;
//     silkworm::Block block{.header=kBlockHeader};
//     block.set_gas_prices({.overhead_price=1, .storage_price=1});
//     const silkworm::ChainConfig config{.protocol_rule_set = protocol::RuleSetType::kTrust};
//     RemoteDatabaseTest remote_db_test;
//     auto tx = std::make_unique<ethdb::kv::RemoteTransaction>(*remote_db_test.stub_, remote_db_test.grpc_context_);
//     ethdb::TransactionDatabase tx_database{*tx};
//     MockEstimateGasOracle estimate_gas_oracle{block_header_provider, account_reader, config, workers, *tx, tx_database};

//     SECTION("Check failure when gas=0 and inclusio_price>0") {
//         try {
//             call.gas = 0;
//             call.max_priority_fee_per_gas = 1;
//             call.max_fee_per_gas = 2;
//             auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block), boost::asio::use_future);
//             result.get();
//             CHECK(false);
//         } catch (const silkworm::rpc::EstimateGasException& e) {
//             CHECK(e.message() == "inclusion_price must be 0");
//         } catch (const std::exception&) {
//             CHECK(false);
//         } catch (...) {
//             CHECK(false);
//         }
//     }
// }
}  // namespace silkworm::rpc
