#include "seccomp.hpp"

#include <algorithm>
#include <charconv>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace rudy::seccomp {
namespace {

using Object = json::Value::Object;
using Array = json::Value::Array;

const json::Value& required(const Object& object, const std::string& key, const std::string& at) {
    const auto it = object.find(key);
    if (it == object.end()) throw std::runtime_error(at + "." + key + " is required");
    return it->second;
}

const json::Value* optional(const Object& object, const std::string& key) {
    const auto it = object.find(key);
    return it == object.end() ? nullptr : &it->second;
}

const Object& as_object(const json::Value& value, const std::string& at) {
    const Object* result = value.object();
    if (!result) throw std::runtime_error(at + " must be an object");
    return *result;
}

const Array& as_array(const json::Value& value, const std::string& at) {
    const Array* result = value.array();
    if (!result) throw std::runtime_error(at + " must be an array");
    return *result;
}

std::string as_string(const json::Value& value, const std::string& at) {
    const std::string* result = value.string();
    if (!result) throw std::runtime_error(at + " must be a string");
    return *result;
}

std::uint64_t as_uint(const json::Value& value, const std::string& at) {
    const json::Number* number = value.number();
    if (!number || number->text.empty() || number->text.front() == '-' ||
        number->text.find_first_of(".eE") != std::string::npos) {
        throw std::runtime_error(at + " must be a non-negative integer");
    }
    std::uint64_t parsed = 0;
    const auto result = std::from_chars(number->text.data(), number->text.data() + number->text.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != number->text.data() + number->text.size())
        throw std::runtime_error(at + " is outside the uint64 range");
    return parsed;
}

std::vector<std::string> string_array(const Object& object, const std::string& key,
                                      const std::string& at, bool required_field = false) {
    const json::Value* value = optional(object, key);
    if (!value) {
        if (required_field) throw std::runtime_error(at + "." + key + " is required");
        return {};
    }
    const auto& array = as_array(*value, at + "." + key);
    std::vector<std::string> result;
    result.reserve(array.size());
    for (std::size_t i = 0; i < array.size(); ++i)
        result.push_back(as_string(array[i], at + "." + key + "[" + std::to_string(i) + "]"));
    return result;
}

std::uint32_t uint32_field(const Object& object, const std::string& key, const std::string& at) {
    const std::uint64_t value = as_uint(required(object, key, at), at + "." + key);
    if (value > UINT32_MAX) throw std::runtime_error(at + "." + key + " exceeds uint32");
    return static_cast<std::uint32_t>(value);
}

std::string field(const Object& object, const std::string& key, const std::string& at) {
    return as_string(required(object, key, at), at + "." + key);
}

std::string severity_rank(const std::string& level) {
    if (level == "error") return "0";
    if (level == "warning") return "1";
    return "2";
}

std::string findings_json(const std::vector<Finding>& findings, const std::string& indent) {
    std::ostringstream out;
    out << "[";
    for (std::size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        if (i) out << ",";
        out << "\n" << indent << "  {\"id\":" << json::quote(f.rule_id)
            << ",\"level\":" << json::quote(f.level)
            << ",\"path\":" << json::quote(f.path)
            << ",\"message\":" << json::quote(f.message) << "}";
    }
    if (!findings.empty()) out << "\n" << indent;
    out << "]";
    return out.str();
}

bool arg_matches(const Argument& rule, const std::array<std::uint64_t, 6>& args) {
    const std::uint64_t actual = args[rule.index];
    if (rule.op == "SCMP_CMP_NE") return actual != rule.value;
    if (rule.op == "SCMP_CMP_LT") return actual < rule.value;
    if (rule.op == "SCMP_CMP_LE") return actual <= rule.value;
    if (rule.op == "SCMP_CMP_EQ") return actual == rule.value;
    if (rule.op == "SCMP_CMP_GE") return actual >= rule.value;
    if (rule.op == "SCMP_CMP_GT") return actual > rule.value;
    if (rule.op == "SCMP_CMP_MASKED_EQ") return (actual & rule.value) == rule.value_two;
    throw std::runtime_error("unsupported argument comparator: " + rule.op);
}

std::optional<std::uint32_t> effective_errno(const std::string& action,
                                              const std::optional<std::uint32_t>& configured) {
    if (action != "SCMP_ACT_ERRNO" && action != "SCMP_ACT_TRACE") return std::nullopt;
    return configured.value_or(1U); // EPERM is the OCI Runtime Specification default.
}

std::string severity_for_sarif(const std::string& level) {
    if (level == "error") return "error";
    if (level == "warning") return "warning";
    return "note";
}

} // namespace

bool action_is_known(const std::string& action) {
    static const std::set<std::string, std::less<>> allowed{
        "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_KILL_THREAD", "SCMP_ACT_TRAP",
        "SCMP_ACT_ERRNO", "SCMP_ACT_TRACE", "SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_NOTIFY"};
    return allowed.contains(action);
}

bool is_allowed_arch(const std::string& architecture) {
    static const std::set<std::string, std::less<>> allowed{
        "SCMP_ARCH_X86", "SCMP_ARCH_X86_64", "SCMP_ARCH_X32", "SCMP_ARCH_ARM", "SCMP_ARCH_AARCH64",
        "SCMP_ARCH_MIPS", "SCMP_ARCH_MIPS64", "SCMP_ARCH_MIPS64N32", "SCMP_ARCH_MIPSEL",
        "SCMP_ARCH_MIPSEL64", "SCMP_ARCH_MIPSEL64N32", "SCMP_ARCH_PPC", "SCMP_ARCH_PPC64",
        "SCMP_ARCH_PPC64LE", "SCMP_ARCH_S390", "SCMP_ARCH_S390X", "SCMP_ARCH_PARISC",
        "SCMP_ARCH_PARISC64", "SCMP_ARCH_RISCV64", "SCMP_ARCH_LOONGARCH64", "SCMP_ARCH_M68K",
        "SCMP_ARCH_SH", "SCMP_ARCH_SHEB"};
    return allowed.contains(architecture);
}

bool is_allowed_operator(const std::string& op) {
    static const std::set<std::string, std::less<>> allowed{
        "SCMP_CMP_NE", "SCMP_CMP_LT", "SCMP_CMP_LE", "SCMP_CMP_EQ", "SCMP_CMP_GE",
        "SCMP_CMP_GT", "SCMP_CMP_MASKED_EQ"};
    return allowed.contains(op);
}

Profile parse_profile(const json::Value& root) {
    const Object& root_object = as_object(root, "$" );
    const json::Value* seccomp_value = nullptr;
    if (const auto* linux_value = optional(root_object, "linux")) {
        const Object& linux_object = as_object(*linux_value, "$.linux");
        seccomp_value = optional(linux_object, "seccomp");
    }
    if (!seccomp_value && optional(root_object, "defaultAction")) seccomp_value = &root;
    if (!seccomp_value) throw std::runtime_error("expected an OCI config with $.linux.seccomp or a LinuxSeccomp object");

    const Object& object = as_object(*seccomp_value, "$.linux.seccomp");
    Profile result;
    result.default_action = field(object, "defaultAction", "$.linux.seccomp");
    if (!action_is_known(result.default_action)) throw std::runtime_error("unsupported defaultAction: " + result.default_action);
    if (const auto* value = optional(object, "defaultErrnoRet")) {
        const std::uint64_t parsed = as_uint(*value, "$.linux.seccomp.defaultErrnoRet");
        if (parsed > UINT32_MAX) throw std::runtime_error("$.linux.seccomp.defaultErrnoRet exceeds uint32");
        result.default_errno_ret = static_cast<std::uint32_t>(parsed);
    }
    result.architectures = string_array(object, "architectures", "$.linux.seccomp");
    result.flags = string_array(object, "flags", "$.linux.seccomp");
    if (const auto* listener = optional(object, "listenerPath")) {
        const std::string path = as_string(*listener, "$.linux.seccomp.listenerPath");
        if (path.empty()) throw std::runtime_error("$.linux.seccomp.listenerPath cannot be empty");
        result.has_listener_path = true;
    }
    if (const auto* metadata = optional(object, "listenerMetadata")) {
        (void)as_string(*metadata, "$.linux.seccomp.listenerMetadata");
        result.has_listener_metadata = true;
    }

    if (const auto* syscalls_value = optional(object, "syscalls")) {
        const auto& syscalls = as_array(*syscalls_value, "$.linux.seccomp.syscalls");
        if (syscalls.size() > 100000U) throw std::runtime_error("syscall rule limit exceeded");
        result.syscalls.reserve(syscalls.size());
        for (std::size_t i = 0; i < syscalls.size(); ++i) {
            const std::string at = "$.linux.seccomp.syscalls[" + std::to_string(i) + "]";
            const Object& entry = as_object(syscalls[i], at);
            Rule rule;
            rule.names = string_array(entry, "names", at, true);
            rule.action = field(entry, "action", at);
            if (!action_is_known(rule.action)) throw std::runtime_error(at + ".action is unsupported: " + rule.action);
            if (const auto* errno_value = optional(entry, "errnoRet")) {
                const std::uint64_t parsed = as_uint(*errno_value, at + ".errnoRet");
                if (parsed > UINT32_MAX) throw std::runtime_error(at + ".errnoRet exceeds uint32");
                rule.errno_ret = static_cast<std::uint32_t>(parsed);
            }
            if (const auto* args_value = optional(entry, "args")) {
                const auto& args = as_array(*args_value, at + ".args");
                rule.args.reserve(args.size());
                for (std::size_t j = 0; j < args.size(); ++j) {
                    const std::string arg_at = at + ".args[" + std::to_string(j) + "]";
                    const Object& arg_object = as_object(args[j], arg_at);
                    Argument arg;
                    const std::uint64_t index = as_uint(required(arg_object, "index", arg_at), arg_at + ".index");
                    if (index > UINT32_MAX) throw std::runtime_error(arg_at + ".index exceeds uint32");
                    arg.index = static_cast<std::uint32_t>(index);
                    arg.value = as_uint(required(arg_object, "value", arg_at), arg_at + ".value");
                    arg.value_two = optional(arg_object, "valueTwo")
                        ? as_uint(*optional(arg_object, "valueTwo"), arg_at + ".valueTwo") : 0U;
                    arg.op = field(arg_object, "op", arg_at);
                    if (!is_allowed_operator(arg.op)) throw std::runtime_error(arg_at + ".op is unsupported: " + arg.op);
                    rule.args.push_back(std::move(arg));
                }
            }
            result.syscalls.push_back(std::move(rule));
        }
    }
    return result;
}

std::vector<Finding> lint(const Profile& profile) {
    std::vector<Finding> findings;
    const auto add = [&findings](std::string id, std::string level, std::string path, std::string message) {
        findings.push_back(Finding{std::move(id), std::move(level), std::move(path), std::move(message)});
    };
    if (profile.default_action == "SCMP_ACT_ALLOW")
        add("RSL001", "warning", "$.linux.seccomp.defaultAction",
            "Unlisted syscalls are allowed. Confirm that a deny-by-default policy is not required for this workload.");
    if (profile.default_errno_ret && profile.default_action != "SCMP_ACT_ERRNO" && profile.default_action != "SCMP_ACT_TRACE")
        add("RSL015", "error", "$.linux.seccomp.defaultErrnoRet",
            "defaultErrnoRet is supported only with SCMP_ACT_ERRNO or SCMP_ACT_TRACE.");
    if (profile.has_listener_metadata && !profile.has_listener_path)
        add("RSL016", "error", "$.linux.seccomp.listenerMetadata",
            "listenerMetadata must not be set unless listenerPath is set.");
    if ((profile.default_action == "SCMP_ACT_KILL" || profile.default_action == "SCMP_ACT_KILL_PROCESS" ||
         profile.default_action == "SCMP_ACT_KILL_THREAD") && profile.syscalls.empty())
        add("RSL002", "error", "$.linux.seccomp.syscalls",
            "The default action kills and no named syscalls are configured; the process is likely to fail immediately.");
    if (profile.architectures.empty())
        add("RSL003", "note", "$.linux.seccomp.architectures",
            "No additional syscall architectures are listed. The runtime's native architecture is environment-dependent.");

    std::set<std::string> arch_seen;
    for (std::size_t i = 0; i < profile.architectures.size(); ++i) {
        const auto& arch = profile.architectures[i];
        const std::string path = "$.linux.seccomp.architectures[" + std::to_string(i) + "]";
        if (!is_allowed_arch(arch)) add("RSL004", "warning", path, "Architecture name is not in the OCI Runtime Specification v1.3 list: " + arch);
        if (!arch_seen.insert(arch).second) add("RSL005", "warning", path, "Architecture is listed more than once: " + arch);
    }

    static const std::set<std::string, std::less<>> known_flags{
        "SECCOMP_FILTER_FLAG_TSYNC", "SECCOMP_FILTER_FLAG_LOG", "SECCOMP_FILTER_FLAG_SPEC_ALLOW",
        "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV"};
    std::set<std::string> flag_seen;
    for (std::size_t i = 0; i < profile.flags.size(); ++i) {
        const auto& flag = profile.flags[i];
        const std::string path = "$.linux.seccomp.flags[" + std::to_string(i) + "]";
        if (!known_flags.contains(flag)) add("RSL017", "warning", path, "Flag name is not in the reviewed OCI Runtime Specification v1.3 list: " + flag);
        if (!flag_seen.insert(flag).second) add("RSL018", "warning", path, "Filter flag is listed more than once: " + flag);
    }

    std::map<std::string, std::vector<std::pair<std::size_t, const Rule*>>, std::less<>> name_rules;
    for (std::size_t i = 0; i < profile.syscalls.size(); ++i) {
        const Rule& rule = profile.syscalls[i];
        const std::string path = "$.linux.seccomp.syscalls[" + std::to_string(i) + "]";
        if (rule.names.empty()) add("RSL006", "error", path + ".names", "Each syscall rule must name at least one syscall.");
        if (rule.errno_ret && rule.action != "SCMP_ACT_ERRNO" && rule.action != "SCMP_ACT_TRACE")
            add("RSL007", "error", path + ".errnoRet", "errnoRet is supported only with SCMP_ACT_ERRNO or SCMP_ACT_TRACE.");
        if (rule.action == "SCMP_ACT_NOTIFY" && !profile.has_listener_path)
            add("RSL008", "note", path + ".action", "SCMP_ACT_NOTIFY is configured; confirm the runtime has a notification listener.");
        if (rule.action == profile.default_action && rule.args.empty())
            add("RSL009", "note", path, "This unconditional rule repeats the profile default action.");
        std::set<std::string> names_in_rule;
        for (std::size_t j = 0; j < rule.names.size(); ++j) {
            const std::string& name = rule.names[j];
            const std::string name_path = path + ".names[" + std::to_string(j) + "]";
            if (name.empty()) add("RSL006", "error", name_path, "Syscall name cannot be empty.");
            if (name.find('*') != std::string::npos)
                add("RSL010", "error", name_path, "Wildcard syscall names are not part of OCI seccomp syscall rules.");
            if (!names_in_rule.insert(name).second)
                add("RSL019", "warning", name_path, "Syscall name is repeated inside the same rule: " + name);
            name_rules[name].push_back({i, &rule});
        }
        std::set<std::uint32_t> arg_indices;
        for (std::size_t j = 0; j < rule.args.size(); ++j) {
            const Argument& arg = rule.args[j];
            const std::string arg_path = path + ".args[" + std::to_string(j) + "]";
            if (arg.index >= 6U) add("RSL011", "error", arg_path + ".index", "Seccomp syscall argument index must be from 0 through 5.");
            if (!arg_indices.insert(arg.index).second)
                add("RSL012", "warning", arg_path + ".index", "The same syscall argument index is constrained more than once in this rule.");
            if (arg.op == "SCMP_CMP_MASKED_EQ" && (arg.value_two & ~arg.value) != 0U)
                add("RSL013", "warning", arg_path + ".valueTwo", "Masked comparison target contains bits outside its mask and can never match.");
        }
    }
    for (const auto& [name, entries] : name_rules) {
        if (entries.size() > 1U) {
            for (const auto& [idx, ignored] : entries) {
                (void)ignored;
                add("RSL014", "note", "$.linux.seccomp.syscalls[" + std::to_string(idx) + "].names",
                    "The syscall '" + name + "' appears in multiple rules; argument conditions and runtime compilation determine the effective policy.");
            }
        }
    }
    std::stable_sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b) {
        if (a.path != b.path) return a.path < b.path;
        if (a.rule_id != b.rule_id) return a.rule_id < b.rule_id;
        return severity_rank(a.level) < severity_rank(b.level);
    });
    return findings;
}

ProbeResult probe(const Profile& profile, const std::string& syscall,
                  const std::array<std::uint64_t, 6>& args) {
    std::vector<const Rule*> matched;
    for (const Rule& rule : profile.syscalls) {
        if (std::find(rule.names.begin(), rule.names.end(), syscall) == rule.names.end()) continue;
        const bool all = std::all_of(rule.args.begin(), rule.args.end(), [&args](const Argument& arg) {
            if (arg.index >= args.size()) return false;
            return arg_matches(arg, args);
        });
        if (all) matched.push_back(&rule);
    }
    if (matched.empty()) return {profile.default_action, effective_errno(profile.default_action, profile.default_errno_ret), "defaultAction",
        "Symbolic offline probe only; syscall-number mapping and kernel/runtime behavior are not evaluated."};
    const Rule* chosen = matched.front();
    for (const Rule* rule : matched) {
        if (rule->action != chosen->action || rule->errno_ret != chosen->errno_ret)
            throw std::runtime_error("probe is ambiguous: multiple matching OCI rules have different actions or errno values");
    }
    return {chosen->action, effective_errno(chosen->action, chosen->errno_ret), "syscalls",
        "Symbolic offline probe only; syscall-number mapping and kernel/runtime behavior are not evaluated."};
}

std::string format_text(const Profile& profile, const std::vector<Finding>& findings) {
    std::ostringstream out;
    out << "Rudy Seccomp Lens - offline OCI profile review\n"
        << "default action: " << profile.default_action << "\n"
        << "architectures: " << (profile.architectures.empty() ? "native runtime architecture (not resolved here)" : "") ;
    for (std::size_t i = 0; i < profile.architectures.size(); ++i) {
        if (i) out << ", ";
        out << profile.architectures[i];
    }
    out << "\nrules: " << profile.syscalls.size() << "\n";
    if (findings.empty()) out << "findings: none\n";
    for (const Finding& f : findings)
        out << "[" << f.level << "] " << f.rule_id << " " << f.path << " - " << f.message << "\n";
    out << "\nScope: offline structural review; this does not install or execute a seccomp filter.\n";
    return out.str();
}

std::string format_json(const Profile& profile, const std::vector<Finding>& findings) {
    std::ostringstream out;
    out << "{\n  \"tool\":\"rudy-seccomp-lens\",\n  \"schemaVersion\":1,\n  \"defaultAction\":" << json::quote(profile.default_action)
        << ",\n  \"architectures\":[";
    for (std::size_t i = 0; i < profile.architectures.size(); ++i) {
        if (i) out << ",";
        out << json::quote(profile.architectures[i]);
    }
    out << "],\n  \"defaultErrnoRet\":";
    if (profile.default_errno_ret) out << *profile.default_errno_ret;
    else out << "null";
    out << ",\n  \"ruleCount\":" << profile.syscalls.size()
        << ",\n  \"findings\":" << findings_json(findings, "  ")
        << ",\n  \"scope\":\"Offline structural and symbolic review only; no filter is installed or executed.\"\n}\n";
    return out.str();
}

std::string format_sarif(const std::vector<Finding>& findings) {
    std::set<std::string> ids;
    for (const auto& f : findings) ids.insert(f.rule_id);
    std::ostringstream out;
    out << "{\"version\":\"2.1.0\",\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"Rudy Seccomp Lens\",\"informationUri\":\"https://github.com/r4venrudy/rudy-seccomp-lens\",\"rules\":[";
    bool first = true;
    for (const auto& id : ids) {
        if (!first) out << ",";
        first = false;
        out << "{\"id\":" << json::quote(id) << "}";
    }
    out << "]}},\"results\":[";
    for (std::size_t i = 0; i < findings.size(); ++i) {
        if (i) out << ",";
        const auto& f = findings[i];
        out << "{\"ruleId\":" << json::quote(f.rule_id)
            << ",\"level\":" << json::quote(severity_for_sarif(f.level))
            << ",\"message\":{\"text\":" << json::quote(f.message) << "}"
            << ",\"locations\":[{\"logicalLocations\":[{\"name\":" << json::quote(f.path)
            << ",\"kind\":\"member\"}]}]}";
    }
    out << "]}]}\n";
    return out.str();
}

std::string format_probe_json(const std::string& syscall, const ProbeResult& result) {
    std::ostringstream out;
    out << "{\"tool\":\"rudy-seccomp-lens\",\"syscall\":" << json::quote(syscall)
        << ",\"action\":" << json::quote(result.action)
        << ",\"source\":" << json::quote(result.source) << ",\"errnoRet\":";
    if (result.errno_ret) out << *result.errno_ret;
    else out << "null";
    out << ",\"note\":" << json::quote(result.note) << "}\n";
    return out.str();
}

namespace {
std::map<std::string, std::vector<std::string>, std::less<>> rule_map(const Profile& profile) {
    std::map<std::string, std::vector<std::string>, std::less<>> result;
    for (const Rule& rule : profile.syscalls) {
        std::ostringstream signature;
        signature << rule.action << ";errno=";
        if (rule.errno_ret) signature << *rule.errno_ret;
        else signature << "default";
        for (const Argument& arg : rule.args)
            signature << ";arg" << arg.index << ":" << arg.op << ":" << arg.value << ":" << arg.value_two;
        for (const std::string& name : rule.names) result[name].push_back(signature.str());
    }
    for (auto& [name, signatures] : result) { (void)name; std::sort(signatures.begin(), signatures.end()); }
    return result;
}

std::string joined(const std::vector<std::string>& values) {
    if (values.empty()) return "(none)";
    std::ostringstream out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i) out << " || ";
        out << values[i];
    }
    return out.str();
}

std::string string_array_json(const std::vector<std::string>& values) {
    std::ostringstream out;
    out << "[";
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i) out << ",";
        out << json::quote(values[i]);
    }
    out << "]";
    return out.str();
}
}

std::string format_diff_text(const Profile& before, const Profile& after) {
    const auto left = rule_map(before);
    const auto right = rule_map(after);
    std::set<std::string> names;
    for (const auto& [name, signature] : left) { (void)signature; names.insert(name); }
    for (const auto& [name, signature] : right) { (void)signature; names.insert(name); }
    std::ostringstream out;
    out << "Structural seccomp profile diff (not a proof of kernel-policy equivalence)\n"
        << "defaultAction: " << before.default_action << " -> " << after.default_action << "\n"
        << "defaultErrnoRet: " << (before.default_errno_ret ? std::to_string(*before.default_errno_ret) : "unset")
        << " -> " << (after.default_errno_ret ? std::to_string(*after.default_errno_ret) : "unset") << "\n"
        << "architectures: " << joined(before.architectures) << " -> " << joined(after.architectures) << "\n"
        << "flags: " << joined(before.flags) << " -> " << joined(after.flags) << "\n";
    bool changed = before.default_action != after.default_action || before.default_errno_ret != after.default_errno_ret ||
        before.architectures != after.architectures || before.flags != after.flags;
    for (const auto& name : names) {
        const auto a = left.find(name), b = right.find(name);
        if (a == left.end()) { out << "+ " << name << " : " << joined(b->second) << "\n"; changed = true; }
        else if (b == right.end()) { out << "- " << name << " : " << joined(a->second) << "\n"; changed = true; }
        else if (a->second != b->second) { out << "~ " << name << " : " << joined(a->second) << " -> " << joined(b->second) << "\n"; changed = true; }
    }
    if (!changed) out << "No structural changes detected.\n";
    return out.str();
}

std::string format_diff_json(const Profile& before, const Profile& after) {
    const auto left = rule_map(before);
    const auto right = rule_map(after);
    std::set<std::string> names;
    for (const auto& [name, signature] : left) { (void)signature; names.insert(name); }
    for (const auto& [name, signature] : right) { (void)signature; names.insert(name); }
    std::ostringstream out;
    out << "{\"tool\":\"rudy-seccomp-lens\",\"mode\":\"structural-diff\",\"defaultActionChanged\":"
        << (before.default_action == after.default_action ? "false" : "true")
        << ",\"beforeDefaultAction\":" << json::quote(before.default_action)
        << ",\"afterDefaultAction\":" << json::quote(after.default_action)
        << ",\"defaultErrnoRetChanged\":" << (before.default_errno_ret == after.default_errno_ret ? "false" : "true")
        << ",\"beforeDefaultErrnoRet\":";
    if (before.default_errno_ret) out << *before.default_errno_ret;
    else out << "null";
    out << ",\"afterDefaultErrnoRet\":";
    if (after.default_errno_ret) out << *after.default_errno_ret;
    else out << "null";
    out
        << ",\"architecturesChanged\":" << (before.architectures == after.architectures ? "false" : "true")
        << ",\"flagsChanged\":" << (before.flags == after.flags ? "false" : "true")
        << ",\"beforeArchitectures\":" << string_array_json(before.architectures)
        << ",\"afterArchitectures\":" << string_array_json(after.architectures)
        << ",\"beforeFlags\":" << string_array_json(before.flags)
        << ",\"afterFlags\":" << string_array_json(after.flags) << ",\"changes\":[";
    bool first = true;
    for (const auto& name : names) {
        const auto a = left.find(name), b = right.find(name);
        std::string change;
        if (a == left.end()) change = "added";
        else if (b == right.end()) change = "removed";
        else if (a->second != b->second) change = "changed";
        else continue;
        if (!first) out << ",";
        first = false;
        out << "{\"syscall\":" << json::quote(name) << ",\"change\":" << json::quote(change)
            << ",\"before\":" << (a == left.end() ? "null" : string_array_json(a->second))
            << ",\"after\":" << (b == right.end() ? "null" : string_array_json(b->second)) << "}";
    }
    out << "],\"scope\":\"Structural diff; rule precedence and kernel/runtime compilation are not evaluated.\"}\n";
    return out.str();
}

} // namespace rudy::seccomp
