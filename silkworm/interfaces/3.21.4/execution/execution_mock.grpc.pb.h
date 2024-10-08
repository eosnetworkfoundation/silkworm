// Generated by the gRPC C++ plugin.
// If you make any local change, they will be lost.
// source: execution/execution.proto

#include "execution/execution.pb.h"
#include "execution/execution.grpc.pb.h"

#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/sync_stream.h>
#include <gmock/gmock.h>
namespace execution {

class MockExecutionStub : public Execution::StubInterface {
 public:
  MOCK_METHOD3(InsertHeaders, ::grpc::Status(::grpc::ClientContext* context, const ::execution::InsertHeadersRequest& request, ::execution::EmptyMessage* response));
  MOCK_METHOD3(AsyncInsertHeadersRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::EmptyMessage>*(::grpc::ClientContext* context, const ::execution::InsertHeadersRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncInsertHeadersRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::EmptyMessage>*(::grpc::ClientContext* context, const ::execution::InsertHeadersRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(InsertBodies, ::grpc::Status(::grpc::ClientContext* context, const ::execution::InsertBodiesRequest& request, ::execution::EmptyMessage* response));
  MOCK_METHOD3(AsyncInsertBodiesRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::EmptyMessage>*(::grpc::ClientContext* context, const ::execution::InsertBodiesRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncInsertBodiesRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::EmptyMessage>*(::grpc::ClientContext* context, const ::execution::InsertBodiesRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(ValidateChain, ::grpc::Status(::grpc::ClientContext* context, const ::types::H256& request, ::execution::ValidationReceipt* response));
  MOCK_METHOD3(AsyncValidateChainRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::ValidationReceipt>*(::grpc::ClientContext* context, const ::types::H256& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncValidateChainRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::ValidationReceipt>*(::grpc::ClientContext* context, const ::types::H256& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(UpdateForkChoice, ::grpc::Status(::grpc::ClientContext* context, const ::types::H256& request, ::execution::ForkChoiceReceipt* response));
  MOCK_METHOD3(AsyncUpdateForkChoiceRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::ForkChoiceReceipt>*(::grpc::ClientContext* context, const ::types::H256& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncUpdateForkChoiceRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::ForkChoiceReceipt>*(::grpc::ClientContext* context, const ::types::H256& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(AssembleBlock, ::grpc::Status(::grpc::ClientContext* context, const ::execution::EmptyMessage& request, ::types::ExecutionPayload* response));
  MOCK_METHOD3(AsyncAssembleBlockRaw, ::grpc::ClientAsyncResponseReaderInterface< ::types::ExecutionPayload>*(::grpc::ClientContext* context, const ::execution::EmptyMessage& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncAssembleBlockRaw, ::grpc::ClientAsyncResponseReaderInterface< ::types::ExecutionPayload>*(::grpc::ClientContext* context, const ::execution::EmptyMessage& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(GetHeader, ::grpc::Status(::grpc::ClientContext* context, const ::execution::GetSegmentRequest& request, ::execution::GetHeaderResponse* response));
  MOCK_METHOD3(AsyncGetHeaderRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::GetHeaderResponse>*(::grpc::ClientContext* context, const ::execution::GetSegmentRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncGetHeaderRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::GetHeaderResponse>*(::grpc::ClientContext* context, const ::execution::GetSegmentRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(GetBody, ::grpc::Status(::grpc::ClientContext* context, const ::execution::GetSegmentRequest& request, ::execution::GetBodyResponse* response));
  MOCK_METHOD3(AsyncGetBodyRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::GetBodyResponse>*(::grpc::ClientContext* context, const ::execution::GetSegmentRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncGetBodyRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::GetBodyResponse>*(::grpc::ClientContext* context, const ::execution::GetSegmentRequest& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(IsCanonicalHash, ::grpc::Status(::grpc::ClientContext* context, const ::types::H256& request, ::execution::IsCanonicalResponse* response));
  MOCK_METHOD3(AsyncIsCanonicalHashRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::IsCanonicalResponse>*(::grpc::ClientContext* context, const ::types::H256& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncIsCanonicalHashRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::IsCanonicalResponse>*(::grpc::ClientContext* context, const ::types::H256& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(GetHeaderHashNumber, ::grpc::Status(::grpc::ClientContext* context, const ::types::H256& request, ::execution::GetHeaderHashNumberResponse* response));
  MOCK_METHOD3(AsyncGetHeaderHashNumberRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::GetHeaderHashNumberResponse>*(::grpc::ClientContext* context, const ::types::H256& request, ::grpc::CompletionQueue* cq));
  MOCK_METHOD3(PrepareAsyncGetHeaderHashNumberRaw, ::grpc::ClientAsyncResponseReaderInterface< ::execution::GetHeaderHashNumberResponse>*(::grpc::ClientContext* context, const ::types::H256& request, ::grpc::CompletionQueue* cq));
};

} // namespace execution

