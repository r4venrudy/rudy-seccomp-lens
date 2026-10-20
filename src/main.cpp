#include "seccomp.hpp"

#include <array>
#include <charconv>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::size_t kMaximumInput = 8U * 1024U * 1024U;

void usage(std::ostream& out) {
    out << R"(Rudy Seccomp Lens - offline OCI Linux seccomp profile review

Usage:
  seccomp-lens lint [--format text|json|sarif] [--fail-on error|warning|none] PROFILE.json
  seccomp-lens probe PROFILE.json --syscall NAME --args A0,A1,A2,A3,A4,A5
  seccomp-lens diff [--format text|json] BEFORE.json AFTER.json

All commands are offline. Probe arguments are unsigned 64-bit integers in decimal or 0x hex.
Exit codes: 0 clean/below threshold; 1 lint threshold reached; 2 input/usage error; 3 ambiguous probe.
 )";
}

std::string read_file(const std::string& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) throw std::runtime_error("cannot open input: " + path);
    const std::streamoff size = input.tellg();
    if (size < 0 || static_cast<std::uint64_t>(size) > kMaximumInput)
        throw std::runtime_error("input exceeds the 8 MiB byte limit: " + path);
    std::string data(static_cast<std::size_t>(size), '\0');
    input.seekg(0, std::ios::beg);
    if (!data.empty() && !input.read(data.data(), static_cast<std::streamsize>(data.size())))
        throw std::runtime_error("failed while reading input: " + path);
    return data;
}

rudy::seccomp::Profile load_profile(const std::string& path) {
    return rudy::seccomp::parse_profile(rudy::json::parse(read_file(path)));
}

std::uint64_t parse_uint(std::string_view value, const std::string& label) {
    if (value.empty() || value.front() == '-') throw std::runtime_error(label + " must be an unsigned integer");
    int base = 10;
    if (value.size() > 2U && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) {
        base = 16;
        value.remove_prefix(2);
        if (value.empty()) throw std::runtime_error(label + " has an empty hex value");
    }
    std::uint64_t number = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), number, base);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size())
        throw std::runtime_error(label + " is invalid or outside the uint64 range");
    return number;
}

std::array<std::uint64_t, 6> parse_args(const std::string& text) {
    std::array<std::uint64_t, 6> result{};
    std::size_t start = 0;
    for (std::size_t i = 0; i < result.size(); ++i) {
        const std::size_t end = text.find(',', start);
        if (i < 5U && end == std::string::npos) throw std::runtime_error("--args requires exactly six comma-separated values");
        if (i == 5U && end != std::string::npos) throw std::runtime_error("--args requires exactly six comma-separated values");
        const std::size_t stop = end == std::string::npos ? text.size() : end;
        result[i] = parse_uint(std::string_view(text).substr(start, stop - start), "argument " + std::to_string(i));
        start = stop + 1U;
    }
    return result;
}

int lint_command(const std::vector<std::string>& args) {
    std::string format = "text";
    std::string fail_on = "error";
    std::string path;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--format" || args[i] == "--fail-on") {
            if (i + 1U >= args.size()) throw std::runtime_error(args[i] + " requires a value");
            const std::string option = args[i++];
            const std::string value = args[i];
            if (option == "--format") format = value;
            else fail_on = value;
        } else if (args[i].starts_with('-')) throw std::runtime_error("unknown lint option: " + args[i]);
        else if (path.empty()) path = args[i];
        else throw std::runtime_error("lint accepts exactly one profile path");
    }
    if (path.empty()) throw std::runtime_error("lint requires a profile path");
    if (format != "text" && format != "json" && format != "sarif") throw std::runtime_error("format must be text, json or sarif");
    if (fail_on != "error" && fail_on != "warning" && fail_on != "none") throw std::runtime_error("fail-on must be error, warning or none");
    const auto profile = load_profile(path);
    const auto findings = rudy::seccomp::lint(profile);
    if (format == "json") std::cout << rudy::seccomp::format_json(profile, findings);
    else if (format == "sarif") std::cout << rudy::seccomp::format_sarif(findings);
    else std::cout << rudy::seccomp::format_text(profile, findings);
    if (fail_on == "none") return 0;
    for (const auto& finding : findings) {
        if (finding.level == "error" || (fail_on == "warning" && finding.level == "warning")) return 1;
    }
    return 0;
}

int probe_command(const std::vector<std::string>& args) {
    if (args.empty()) throw std::runtime_error("probe requires a profile path");
    const std::string path = args.front();
    std::string syscall;
    std::string raw_args;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] != "--syscall" && args[i] != "--args") throw std::runtime_error("unknown probe option: " + args[i]);
        if (i + 1U >= args.size()) throw std::runtime_error(args[i] + " requires a value");
        const std::string option = args[i++];
        if (option == "--syscall") syscall = args[i];
        else raw_args = args[i];
    }
    if (syscall.empty()) throw std::runtime_error("probe requires --syscall NAME");
    if (raw_args.empty()) throw std::runtime_error("probe requires --args A0,A1,A2,A3,A4,A5");
    const auto profile = load_profile(path);
    try {
        const auto result = rudy::seccomp::probe(profile, syscall, parse_args(raw_args));
        std::cout << rudy::seccomp::format_probe_json(syscall, result);
    } catch (const std::runtime_error& error) {
        if (std::string_view(error.what()).starts_with("probe is ambiguous:")) {
            std::cerr << error.what() << '\n';
            return 3;
        }
        throw;
    }
    return 0;
}

int diff_command(const std::vector<std::string>& args) {
    std::string format = "text";
    std::vector<std::string> paths;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--format") {
            if (i + 1U >= args.size()) throw std::runtime_error("--format requires a value");
            format = args[++i];
        } else if (args[i].starts_with('-')) throw std::runtime_error("unknown diff option: " + args[i]);
        else paths.push_back(args[i]);
    }
    if (format != "text" && format != "json") throw std::runtime_error("diff format must be text or json");
    if (paths.size() != 2U) throw std::runtime_error("diff requires BEFORE.json and AFTER.json");
    const auto before = load_profile(paths[0]);
    const auto after = load_profile(paths[1]);
    if (format == "json") std::cout << rudy::seccomp::format_diff_json(before, after);
    else std::cout << rudy::seccomp::format_diff_text(before, after);
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { usage(std::cerr); return 2; }
    const std::string command = argv[1];
    if (command == "--help" || command == "-h") { usage(std::cout); return 0; }
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) args.emplace_back(argv[i]);
    try {
        if (command == "lint") return lint_command(args);
        if (command == "probe") return probe_command(args);
        if (command == "diff") return diff_command(args);
        throw std::runtime_error("unknown command: " + command);
    } catch (const std::exception& error) {
        std::cerr << "seccomp-lens: " << error.what() << '\n';
        return 2;
    }
}
