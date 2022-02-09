//
// Created by Andrea on 09/02/2022.
//

#ifndef SILKWORM_COMMON_LRU_CACHE2_HPP_
#define SILKWORM_COMMON_LRU_CACHE2_HPP_

#include <list>
#include <optional>
#include <unordered_map>
#include <utility>

namespace silkworm {

template <typename key_t, typename value_t>
class lru_cache2 {
  public:
    //! \brief Determines how items should be bumped up (as most recent)
    //! \remarks Items freshly inserted are always the most recent
    enum class BumpMode {
        kAlways,     // Always bump items
        kOnUpdate,   // Bump items on update only (i.e. is "used" when value inserted or updated)
        kOnConsume,  // Bump items on use only (i.e. is "used" when value accessed)
    };

    using list_type = std::list<key_t>;
    using map_type = std::unordered_map<key_t, std::pair<value_t, typename list_type::iterator>>;

    explicit lru_cache2(size_t max_size, BumpMode bump_mode = BumpMode::kAlways)
        : max_size_{max_size}, bump_mode_{bump_mode} {};
    ~lru_cache2() = default;

    [[nodiscard]] size_t size() { return map_.size(); }
    [[nodiscard]] size_t max_size() { return max_size_; }
    [[nodiscard]] bool empty() { return map_.empty(); }

    [[nodiscard]] bool contains(const key_t& key) { return map_.find(key) != map_.end(); }

    void put(const key_t& key, const value_t& value) {
        auto map_it{map_.find(key)};
        if (map_it == map_.end()) {
            // insert item into cache but first check if it's full
            if (size() >= max_size_) {
                evict_one();
            }
            list_.push_front(key);
            map_[key] = std::make_pair(value, list_.begin());
        } else {
            if (bump_mode_ != BumpMode::kOnConsume) {
                bump(map_it);
            }
            map_it->second.first = value;
        }
    }

    void erase(const key_t& key) { evict_one(key); }

    void clear() noexcept {
        list_.clear();
        map_.clear();
    }

    [[nodiscard]] std::optional<value_t> get(const key_t& key) {
        auto ptr{at(key)};
        if (!ptr) {
            return std::nullopt;
        }
        return *ptr;
    }

    [[nodiscard]] value_t* at(const key_t& key) {
        auto map_it{map_.find(key)};
        if (map_it == map_.end()) {
            return nullptr;  // Not in cache
        }
        if (bump_mode_ != BumpMode::kOnUpdate) {
            bump(map_it);
        }
        return &map_it->second.first;
    }

    [[nodiscard]] value_t* operator[](const key_t& key) { return at(key); }

  private:
    map_type map_;
    list_type list_;
    size_t max_size_;
    BumpMode bump_mode_;

    void evict_one(std::optional<key_t> key = std::nullopt) {
        if (list_.empty()) {
            return;
        }
        if (!key.has_value()) {
            const auto list_last{--list_.end()};
            map_.erase(*list_last);
            list_.erase(list_last);
        } else {
            const auto map_it{map_.find(key.value())};
            list_.erase(map_it->second.second);
            map_.erase(map_it);
        }
    }

    inline void bump(typename map_type::iterator map_it) {
        auto list_it{map_it->second.second};
        if (list_it != list_.begin()) {
            list_.splice(list_.begin(), list_, list_it);
            map_it->second.second = list_.begin();
        }
    }
};
}  // namespace silkworm

#endif  // SILKWORM_COMMON_LRU_CACHE2_HPP_
