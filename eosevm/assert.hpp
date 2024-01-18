#pragma once
#define EOSEVM_ABORT(msg) silkworm::abort_due_to_assertion_failure(msg, __FILE__, __LINE__)
