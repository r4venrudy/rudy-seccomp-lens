#pragma once

#include "json.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace rudy::seccomp {

struct Argument {
    std::uint32_t index = 0;
    std::uint64_t value = 0;
    std::uint64_t value_two = 0;
    std::string op;
};

struct Rule {
    std::vector<std::string> names;
    std::string action;
    std::optional<std::uint32_t> errno_ret;
    std::vector<Argument> args;
};

struct Profile {
    std::string default_action;
    std::optional<std::uint32_t> default_errno_ret;
    std::vector<std::string> architectures;
    std::vector<std::string> flags;
    std::vector<Rule> syscalls;
    bool has_listener_path = false;
    bool has_listener_metadata = false;
};

struct Finding {
    std::string rule_id;
    std::string level;
    std::string path;
    std::string message;
};

struct ProbeResult {
    std::string action;
    std::optional<std::uint32_t> errno_ret;
    std::string source;
    std::string note;
};

Profile parse_profile(const json::Value& root);
std::vector<Finding> lint(const Profile& profile);
ProbeResult probe(const Profile& profile, const std::string& syscall,
                  const std::array<std::uint64_t, 6>& args);
bool action_is_known(const std::string& action);
bool is_allowed_arch(const std::string& architecture);
bool is_allowed_operator(const std::string& op);
std::string format_text(const Profile& profile, const std::vector<Finding>& findings);
std::string format_json(const Profile& profile, const std::vector<Finding>& findings);
std::string format_sarif(const std::vector<Finding>& findings);
std::string format_probe_json(const std::string& syscall, const ProbeResult& result);
std::string format_diff_text(const Profile& before, const Profile& after);
std::string format_diff_json(const Profile& before, const Profile& after);

} // namespace rudy::seccomp
