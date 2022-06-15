/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "assetBuilderDecoder.hpp"

#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include <fmt/format.h>

#include "registry.hpp"
#include <logging/logging.hpp>

namespace builder::internals::builders
{

types::ConnectableT assetBuilderDecoder(const base::Document& def)
{
    // Assert document is as expected
    if (!def.m_doc.IsObject())
    {
        auto msg =
            fmt::format("Decoder builder expects value to be an object, but got [{}]",
                        def.m_doc.GetType());
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(msg);
    }
    auto objDef = def.m_doc.GetObject();
    std::unordered_set<std::string> proccessed;

    std::vector<base::Lifter> stages;

    // Implicit XOR condition in front
    stages.push_back([](base::Observable o)
                     { return o.filter([](base::Event e) { return !e->isDecoded(); }); });

    // First get non-stage attributes and mandatory stages (check), then iterate over
    // JsonObject
    // TODO: once json abstraction is implemented we can use stl structures instead of
    // JsonObject This is because JsonValue has not copy assignment operator, and maps
    // brokens order of stages

    // Name
    std::string name;
    if (objDef.HasMember("name"))
    {
        try
        {
            name = objDef["name"].GetString();
            proccessed.insert("name");
        }
        catch (std::exception& e)
        {
            const char* msg =
                "Decoder builder encountered exception building attribute name.";
            WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
            std::throw_with_nested(std::runtime_error(msg));
        }
    }
    else
    {
        const char* msg = "Decoder builder expects definition to have a name attribute.";
        WAZUH_LOG_ERROR("{}", msg);
        throw std::runtime_error(msg);
    }

    // Parents
    std::vector<std::string> parents;
    if (objDef.HasMember("parents"))
    {
        try
        {
            auto arr = objDef["parents"].GetArray();
            for (auto& v : arr)
            {
                parents.push_back(v.GetString());
            }
            proccessed.insert("parents");
        }
        catch (std::exception& e)
        {
            const char* msg =
                "Decoder builder encountered exception building attribute parents.";
            WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
            std::throw_with_nested(std::invalid_argument(msg));
        }
    }

    // Metadata
    std::map<std::string, base::Document> metadata;
    if (objDef.HasMember("metadata"))
    {
        try
        {
            auto obj = objDef["metadata"].GetObject();
            for (auto& m : obj)
            {
                metadata[m.name.GetString()] = base::Document(m.value);
            }
            proccessed.insert("metadata");
        }
        catch (std::exception& e)
        {
            const char* msg =
                "Decoder builder encountered exception building attribute metadata.";
            WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
            std::throw_with_nested(std::runtime_error(msg));
        }
    }

    // Build tracer
    types::ConnectableT::Tracer tr {name};

    // Stage check
    if (objDef.HasMember("check"))
    {
        try
        {
            stages.push_back(std::get<types::OpBuilder>(Registry::getBuilder("check"))(
                objDef["check"], tr.tracerLogger()));
            proccessed.insert("check");
        }
        catch (std::exception& e)
        {
            const char* msg =
                "Decoder builder encountered exception building stage check.";
            WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
            std::throw_with_nested(std::runtime_error(msg));
        }
    }
    else
    {
        const char* msg = "Decoder builder expects value to have a check stage.";
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(msg);
    }

    // Rest of stages
    for (auto& m : objDef)
    {
        // Check that we haven't already proccessed this attribute
        if (proccessed.find(m.name.GetString()) == proccessed.end())
        {
            auto stageName = m.name.GetString();
            const auto& stageDef = m.value;
            try
            {
                stages.push_back(std::get<types::OpBuilder>(
                    Registry::getBuilder(stageName))(stageDef, tr.tracerLogger()));
                proccessed.insert(stageName);
            }
            catch (std::exception& e)
            {
                auto msg = fmt::format(
                    "Decoder builder encountered exception building stage {}", stageName);
                WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
                std::throw_with_nested(std::runtime_error(msg));
            }
        }
    }

    try
    {
        base::Lifter decoder = std::get<types::CombinatorBuilder>(
            Registry::getBuilder("combinator.chain"))(stages);
        // Finally return connectable
        return types::ConnectableT {name, parents, decoder, tr};
    }
    catch (std::exception& e)
    {
        const char* msg = "Decoder builder encountered exception building "
                          "chaining all stages.";
        WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
        std::throw_with_nested(std::runtime_error(msg));
    }
}

} // namespace builder::internals::builders
