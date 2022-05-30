/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * May 26, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MESSAGECONTROLLER_HPP
#define _MESSAGECONTROLLER_HPP

#include <algorithm>
#include <chrono>
#include <string>
#include <map>
#include <mutex>
#include <shared_mutex>
#include "commonDefs.h"
#include "singleton.hpp"

class MessageController final : public Singleton<MessageController>
{
    private:
        struct ComponentContext
        {
            std::chrono::steady_clock::time_point lastMsgTime;
            std::chrono::seconds intervalTime;
        };
        std::shared_timed_mutex m_mutex;
        std::map<std::string, ComponentContext> m_componentContexts;
        std::map<std::string, RSYNC_HANDLE> m_componentHandle;
        std::map<std::string, bool> m_componentShutdownStatus;

    public:
        bool waitToStartSync(const std::string& messageHeaderId)
        {
            auto retVal { false };
            std::shared_lock<std::shared_timed_mutex> lock(m_mutex);
            const auto itCtx { m_componentContexts.find(messageHeaderId) };

            if (itCtx != m_componentContexts.end())
            {
                retVal = std::chrono::steady_clock::now() - itCtx->second.lastMsgTime <= itCtx->second.intervalTime;
            }
            return retVal;
        }

        void setComponentContext(const RSYNC_HANDLE handle,
                                 const std::string& messageHeaderId,
                                 const std::chrono::seconds& intervalTime)
        {
            std::lock_guard<std::shared_timed_mutex> lock(m_mutex);
            if (intervalTime.count() > 0)
            {
                m_componentContexts[messageHeaderId] =
                {
                    std::chrono::time_point<std::chrono::steady_clock>(),
                    intervalTime
                };
            }
            else
            {
                m_componentContexts.erase(messageHeaderId);
            }

            m_componentHandle[messageHeaderId] = handle;
            m_componentShutdownStatus[messageHeaderId] = false;
        }

        void setShutdownStatus(const RSYNC_HANDLE handle, const bool shutdownStatus)
        {
            std::lock_guard<std::shared_timed_mutex> lock(m_mutex);
            for (const auto& it : m_componentHandle)
            {
                if (it.second == handle)
                {
                    m_componentShutdownStatus[it.first] = shutdownStatus;
                }
            }
        }

        bool getShutdownStatus(const std::string& messageHeaderId)
        {
            bool retVal { false };
            std::shared_lock<std::shared_timed_mutex> lock(m_mutex);
            const auto it { m_componentShutdownStatus.find(messageHeaderId) };

            if (it != m_componentShutdownStatus.end())
            {
                retVal = it->second;
            }
            return retVal;
        }

        void refreshLastMsgTime(const std::string& messageHeaderId)
        {
            std::lock_guard<std::shared_timed_mutex> lock(m_mutex);
            const auto itCtx { m_componentContexts.find(messageHeaderId) };

            if (itCtx != m_componentContexts.end())
            {
                itCtx->second.lastMsgTime = std::chrono::steady_clock::now();
            }
        }

};

#endif // _MESSAGECONTROLLER_HPP
