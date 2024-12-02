#pragma once
#include <cstdint>
#include <algorithm>

namespace silkworm {

struct gas_prices_t {
  uint64_t overhead_price{0};
  uint64_t storage_price{0};

  uint64_t get_base_price()const {
    return std::max(overhead_price, storage_price);
  }

  bool is_zero()const {
    return overhead_price == 0 && storage_price == 0;
  }
};

}  // namespace silkworm
