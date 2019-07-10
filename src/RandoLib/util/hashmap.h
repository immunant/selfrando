 // Copyright (c) 2015-2019 RunSafe Security Inc.
#ifndef __HASH_MAP_H
#define __HASH_MAP_H
#pragma once

#include <OS.h>

namespace hashmap {

// Intrusive hash map that uses Robin Hood hashing
// Implementation inspired by: https://www.sebastiansylvan.com/post/robin-hood-hashing-should-be-your-default-hash-table-implementation/
// The template type T should be a class that provides
// the following types and methods:
// class Entry {
//   // The type of the keys
//   typedef ... Key;
//
//   // Get the key for this entry
//   Key key() const { ... }
//
//   // Returns whether a key is invalid (uninitialized)
//   // or has a proper value; this is used to check
//   // if this entry is in the hash map (entries with
//   // invalid keys are not present)
//   static bool key_is_invalid(const Key &key) { ... }
//
//   // Returns the hash value for the key in this entry
//   static uint32_t key_hash(const Key &key) { ... }
//
//   // Checks two keys for equality
//   static bool key_equals(const Key &ka, const Key &kb) { ... }
//
// };
template<typename T>
class HashMap {
public:
    ~HashMap() {
        clear();
    }

    void clear() {
        if (elems != nullptr) {
            for (size_t i = 0; i < capacity(); i++)
                elems[i].~T(); // Call the destructor for each element
            os::API::mem_free(elems);
            elems = nullptr;
        }
        num_elems = 0;
        cap_mask = 0;
    }

    size_t elements() const {
        return num_elems;
    }

    T *get(const typename T::Key &k) const {
        auto kh = T::key_hash(k);
        auto pos = kh & cap_mask;
        size_t dist = 0;
        for (;; dist++) {
            auto &e = elems[pos];
            auto &ek = e.key();
            if (T::key_is_invalid(ek))
                return nullptr; // Invalid key => empty element
            if (dist > elem_distance(pos))
                return nullptr; // Exceeded distance
            if (T::key_hash(ek) == kh && T::key_equals(k, ek))
                return &e;
            pos = (pos + 1) & cap_mask;
        }
    }

    struct InsertResult {
        T *at;
        bool inserted;
    };

    InsertResult insert(T &&x) {
        // Store a function-local copy of the inserted element,
        // but move `x` into it
        T lx = x;
        auto kh = T::key_hash(lx.key());
        auto pos = kh & cap_mask;
        size_t dist = 0;
        grow();
        for (;; dist++) {
            auto &e = elems[pos];
            auto &ek = e.key();
            if (T::key_is_invalid(ek)) {
                e = static_cast<T&&>(lx);
                num_elems++;
                return InsertResult{ &e, true };
            }
            if (T::key_hash(ek) == kh && T::key_equals(lx.key(), ek))
                return InsertResult{ &e, false };

            auto ed = elem_distance(pos);
            if (ed < dist) {
                os::API::swap(e, lx);
                kh = T::key_hash(lx.key());
                dist = ed;
            }
            pos = (pos + 1) & cap_mask;
        }
    }

    class Iterator {
    private:
        const HashMap &map;
        size_t idx;

    public:
        Iterator() = delete;
        Iterator(const HashMap &m, size_t i) : map(m), idx(i) {
            advance();
        }

        T &operator*() {
            return map.elems[idx];
        }

        const T &operator*() const {
            return map.elems[idx];
        }

        Iterator &operator++() {
            if (idx < map.capacity()) {
                idx++;
                advance();
            }
            return *this;
        }

        bool operator==(const Iterator &other) {
            return &map.elems[idx] == &other.map.elems[other.idx];
        }

        bool operator!=(const Iterator &other) {
            return !(*this == other);
        }

    private:
        void advance() {
            auto cap = map.capacity();
            while (idx < cap && T::key_is_invalid(map.elems[idx].key()))
                idx++;
        }
    };

    Iterator begin() const {
        return Iterator(*this, 0);
    }

    Iterator end() const {
        return Iterator(*this, capacity());
    }

private:
    T *elems = nullptr;
    size_t num_elems = 0;
    size_t cap_mask = 0;

private:
    size_t capacity() const {
        return cap_mask == 0 ? 0 : (cap_mask + 1);
    }

    size_t elem_distance(size_t idx) const {
        auto elem_pos = T::key_hash(elems[idx].key()) & cap_mask;
        return (idx + capacity() - elem_pos) & cap_mask;
    }

    static constexpr size_t DEFAULT_CAPACITY = 16;
    static constexpr size_t LOAD_FACTOR256 = 232;

    void grow() {
        size_t new_cap = capacity();
        if (num_elems < (new_cap * LOAD_FACTOR256) / 256)
            return;

        if (new_cap < DEFAULT_CAPACITY) {
            static_assert(DEFAULT_CAPACITY > 1,
                          "Default HashMap capacity too small");
            new_cap = DEFAULT_CAPACITY;
        } else {
            new_cap <<= 1;
        }

        auto old_cap = capacity();
        auto old_elems = elems;
        elems = reinterpret_cast<T*>(os::API::mem_alloc(new_cap * sizeof(T), false));
        for (size_t i = 0; i < new_cap; i++)
            new (&elems[i]) T(); // Call default initializer on each element

        num_elems = 0;
        cap_mask = new_cap - 1;
        if (old_elems != nullptr) {
            // Insert the old elements into the new table, then release them
            for (size_t i = 0; i < old_cap; i++) {
                auto &e = old_elems[i];
                if (!T::key_is_invalid(e.key()))
                    this->insert(static_cast<T&&>(e));
            }
            os::API::mem_free(old_elems);
        }
    }
};

// Hash functions from http://www.cris.com/~Ttwang/tech/inthash.htm
inline uint32_t int_hash(uint32_t key) {
    key += ~(key << 15);
    key ^=  (key >> 10);
    key +=  (key << 3);
    key ^=  (key >> 6);
    key += ~(key << 11);
    key ^=  (key >> 16);
    return key;
}

inline uint32_t int_hash(uint64_t key) {
    key += ~(key << 32);
    key ^=  (key >> 22);
    key += ~(key << 13);
    key ^=  (key >> 8);
    key +=  (key << 3);
    key ^=  (key >> 15);
    key += ~(key << 27);
    key ^=  (key >> 31);
    return static_cast<uint32_t>(key);
}

// Predefined entry implementation for entries that
// contain a single pointer value, which is used as the key
template<typename T>
class PointerEntry { };

template<typename T>
class PointerEntry<T*> {
public:
    typedef T *Key;

    PointerEntry() : k(nullptr) { }
    PointerEntry(T *ptr) : k(ptr) { }

    const Key &key() const {
        return k;
    }

    static bool key_is_invalid(const Key &k) {
        return k == nullptr;
    }

    static uint32_t key_hash(const Key &k) {
        return int_hash(reinterpret_cast<uintptr_t>(k));
    }

    static bool key_equals(const Key &ka, const Key &kb) {
        return ka == kb;
    }

private:
    Key k;
};

} // namespace hashmap

#endif // __HASH_MAP_H
