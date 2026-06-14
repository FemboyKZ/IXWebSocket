/*
 *  IXSelectInterruptEvent.h
 */

#pragma once

#include "IXSelectInterrupt.h"
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif

namespace ix
{
    class SelectInterruptEvent final : public SelectInterrupt
    {
    public:
        SelectInterruptEvent();
        virtual ~SelectInterruptEvent();

        bool init(std::string& /*errorMsg*/) final;

        bool notify(uint64_t value) final;
        bool clear() final;
        std::optional<uint64_t> read() final;
        void* getEvent() const final;
    private:
        // Contains every value only once, duplicates are ignored
        std::deque<uint64_t> _values;
        std::mutex _valuesMutex;
#ifdef _WIN32
        // Windows Event to wake up the socket poll
        HANDLE _event;
#endif
    };
} // namespace ix
