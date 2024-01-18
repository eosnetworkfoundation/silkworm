#pragma once
#ifdef ANTELOPE
#include <eosio/eosio.hpp>
#else
#include <silkworm/silkworm/core/common/assert.hpp>
#endif

namespace eosevm {

static void abort(const char* msg) {
    #ifdef ANTELOPE
    eosio::check(false, msg);
    #else
    silkworm::abort_due_to_assertion_failure(msg, __FILE__, __LINE__);
    #endif
}

}
