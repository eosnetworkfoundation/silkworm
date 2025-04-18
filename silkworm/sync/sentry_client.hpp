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

#include <atomic>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/signals2.hpp>

#include <silkworm/infra/concurrency/task_group.hpp>
#include <silkworm/sentry/api/api_common/message_from_peer.hpp>
#include <silkworm/sentry/api/api_common/peer_event.hpp>
#include <silkworm/sentry/api/api_common/sentry_client.hpp>
#include <silkworm/sync/internals/types.hpp>
#include <silkworm/sync/messages/inbound_message.hpp>
#include <silkworm/sync/messages/outbound_message.hpp>

namespace silkworm {

/*
 * A SentryClient wrapper for the sync module.
 */
class SentryClient {
  public:
    explicit SentryClient(
        boost::asio::io_context& io_context,
        std::shared_ptr<silkworm::sentry::api::api_common::SentryClient> sentry_client);

    SentryClient(const SentryClient&) = delete;
    SentryClient(SentryClient&&) = delete;

    // sending messages
    using PeerIds = std::vector<PeerId>;

    boost::asio::awaitable<SentryClient::PeerIds> send_message_by_id_async(const OutboundMessage& outbound_message, const PeerId& peer_id);
    PeerIds send_message_by_id(const OutboundMessage& message, const PeerId& peer_id);

    boost::asio::awaitable<PeerIds> send_message_to_random_peers_async(const OutboundMessage& message, size_t max_peers);
    PeerIds send_message_to_random_peers(const OutboundMessage& message, size_t max_peers);

    boost::asio::awaitable<PeerIds> send_message_to_all_async(const OutboundMessage& message);
    PeerIds send_message_to_all(const OutboundMessage& message);

    boost::asio::awaitable<PeerIds> send_message_by_min_block_async(const OutboundMessage& message, BlockNum min_block, size_t max_peers);
    PeerIds send_message_by_min_block(const OutboundMessage& message, BlockNum min_block, size_t max_peers);

    boost::asio::awaitable<void> peer_min_block_async(const PeerId& peer_id, BlockNum min_block);
    void peer_min_block(const PeerId& peer_id, BlockNum min_block);

    // receiving messages
    using Subscriber = void(std::shared_ptr<InboundMessage>);
    boost::signals2::signal<Subscriber> announcements_subscription;  // subscription to headers & bodies announcements
    boost::signals2::signal<Subscriber> requests_subscription;       // subscription to headers & bodies requests
    boost::signals2::signal<Subscriber> rest_subscription;           // subscription to everything else

    // reports received message sizes
    boost::signals2::signal<void(size_t)> received_message_size_subscription;

    // reports if a malformed message was received
    boost::signals2::signal<void()> malformed_message_subscription;

    // ask the remote sentry for active peers
    boost::asio::awaitable<uint64_t> count_active_peers_async();
    uint64_t count_active_peers();

    // ask the remote sentry for peer info
    boost::asio::awaitable<std::string> request_peer_info_async(PeerId peer_id);
    std::string request_peer_info(PeerId peer_id);

    boost::asio::awaitable<void> penalize_peer_async(PeerId peer_id, Penalty penalty);
    void penalize_peer(PeerId peer_id, Penalty penalty);

    uint64_t active_peers();  // return cached peers count

    // receive messages and peer events
    boost::asio::awaitable<void> async_run();

    static constexpr seconds_t kRequestDeadline = std::chrono::seconds(30);          // time beyond which the remote sentry
                                                                                     // considers an answer lost
    static constexpr milliseconds_t kNoPeerDelay = std::chrono::milliseconds(3000);  // chosen delay when no peer
                                                                                     // accepted the last request
    static constexpr size_t kPerPeerMaxOutstandingRequests = 4;                      // max number of outstanding requests per peer

  protected:
    boost::asio::awaitable<void> receive_messages();
    boost::asio::awaitable<void> receive_peer_events();

    // notifying registered subscribers
    boost::asio::awaitable<void> publish(const silkworm::sentry::api::api_common::MessageFromPeer& message_from_peer);

    boost::asio::io_context& io_context_;
    std::shared_ptr<silkworm::sentry::api::api_common::SentryClient> sentry_client_;
    concurrency::TaskGroup tasks_;

    std::atomic<uint64_t> active_peers_{0};
};

}  // namespace silkworm
