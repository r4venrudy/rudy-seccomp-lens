#include "json.hpp"
#include "seccomp.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

int checks = 0;

void expect(bool condition, const std::string& message) {
    ++checks;
    if (!condition) throw std::runtime_error("check failed: " + message);
}

template <typename Function>
void expect_throw(Function&& function, const std::string& message) {
    ++checks;
    try { function(); }
    catch (const std::exception&) { return; }
    throw std::runtime_error("expected exception: " + message);
}

rudy::seccomp::Profile parse(const std::string& text) {
    return rudy::seccomp::parse_profile(rudy::json::parse(text));
}

void test_json() {
    const auto value = rudy::json::parse(R"({"unicode":"\ud83d\ude80","list":[1,true,null]})");
    expect(value.object() != nullptr, "JSON object parses");
    expect(rudy::json::quote("line\n\"x") == "\"line\\n\\\"x\"", "JSON strings escape controls and quotes");
    expect_throw([] { (void)rudy::json::parse("{\"x\":1,\"x\":2}"); }, "duplicate object members are rejected");
    expect_throw([] { (void)rudy::json::parse("[1] trailing"); }, "trailing content is rejected");
    expect_throw([] { (void)rudy::json::parse("\"\\ud800\""); }, "unpaired UTF-16 surrogate is rejected");
    expect_throw([] { (void)rudy::json::parse("[[[0]]]", 100, 2); }, "excessive nesting is rejected");
}

void test_profile_and_lint() {
    const auto profile = parse(R"({"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":13,"architectures":["SCMP_ARCH_X86_64"],"syscalls":[{"names":["openat"],"action":"SCMP_ACT_ALLOW","args":[{"index":2,"value":0,"op":"SCMP_CMP_EQ"}]}]}}})");
    expect(profile.default_action == "SCMP_ACT_ERRNO", "OCI wrapper locates linux.seccomp");
    expect(profile.default_errno_ret == 13U, "default errno value is retained");
    expect(profile.syscalls.size() == 1U && profile.syscalls[0].args[0].index == 2U, "syscall argument rule parses");
    expect(rudy::seccomp::lint(profile).empty(), "tight profile produces no linter findings");

    const auto allow = parse(R"({"defaultAction":"SCMP_ACT_ALLOW"})");
    const auto findings = rudy::seccomp::lint(allow);
    expect(findings.size() == 2U, "allow-all profile has a warning and native-architecture note");
    expect(findings[0].rule_id == "RSL001" || findings[1].rule_id == "RSL001", "allow-all finding has stable rule id");

    const auto empty_kill = parse(R"({"defaultAction":"SCMP_ACT_KILL_PROCESS"})");
    const auto kill_findings = rudy::seccomp::lint(empty_kill);
    expect(std::any_of(kill_findings.begin(), kill_findings.end(), [](const auto& f) { return f.rule_id == "RSL002" && f.level == "error"; }),
           "empty kill-by-default profile is identified");

    const auto bad_index = parse(R"({"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW","args":[{"index":6,"value":0,"op":"SCMP_CMP_EQ"}]}]})");
    const auto bad_index_findings = rudy::seccomp::lint(bad_index);
    expect(std::any_of(bad_index_findings.begin(), bad_index_findings.end(),
        [](const auto& f) { return f.rule_id == "RSL011"; }), "invalid syscall argument index is reported");
    const auto bad_errno = parse(R"({"defaultAction":"SCMP_ACT_ALLOW","defaultErrnoRet":13,"listenerMetadata":"opaque"})");
    const auto bad_errno_findings = rudy::seccomp::lint(bad_errno);
    expect(std::any_of(bad_errno_findings.begin(), bad_errno_findings.end(),
        [](const auto& f) { return f.rule_id == "RSL015"; }), "incompatible default errno action is reported");
    expect(std::any_of(bad_errno_findings.begin(), bad_errno_findings.end(),
        [](const auto& f) { return f.rule_id == "RSL016"; }), "listener metadata without a listener path is reported");
    expect_throw([] { (void)parse(R"({"defaultAction":"SCMP_ACT_BOGUS"})"); }, "unknown action is rejected");
}

void test_probe() {
    const auto profile = parse(R"({"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"syscalls":[{"names":["openat"],"action":"SCMP_ACT_ALLOW","args":[{"index":2,"value":3,"op":"SCMP_CMP_EQ"}]},{"names":["ioctl"],"action":"SCMP_ACT_ALLOW","args":[{"index":1,"value":240,"valueTwo":32,"op":"SCMP_CMP_MASKED_EQ"}]}]})");
    std::array<std::uint64_t, 6> args{};
    args[2] = 3;
    const auto allowed = rudy::seccomp::probe(profile, "openat", args);
    expect(allowed.action == "SCMP_ACT_ALLOW" && allowed.source == "syscalls", "matching argument rule returns its action");
    args[2] = 4;
    const auto denied = rudy::seccomp::probe(profile, "openat", args);
    expect(denied.action == "SCMP_ACT_ERRNO" && denied.errno_ret == 1U, "non-matching rule falls back to default action");
    args[1] = 0x120U;
    expect(rudy::seccomp::probe(profile, "ioctl", args).action == "SCMP_ACT_ALLOW", "masked-equal comparator uses mask and target");
    args[1] = 0x130U;
    expect(rudy::seccomp::probe(profile, "ioctl", args).action == "SCMP_ACT_ERRNO", "masked-equal comparator rejects a different value");

    const auto ambiguous = parse(R"({"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"},{"names":["read"],"action":"SCMP_ACT_TRAP"}]})");
    expect_throw([&] { (void)rudy::seccomp::probe(ambiguous, "read", args); }, "conflicting overlapping rules do not guess");
    const auto default_eperm = parse(R"({"defaultAction":"SCMP_ACT_ERRNO"})");
    expect(rudy::seccomp::probe(default_eperm, "write", args).errno_ret == 1U,
           "probe applies OCI's default EPERM errno when it is omitted");
}

void test_reports_and_diff() {
    const auto before = parse(R"({"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]})");
    const auto after = parse(R"({"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["read"],"action":"SCMP_ACT_ERRNO"},{"names":["write"],"action":"SCMP_ACT_ALLOW"}]})");
    const auto json = rudy::seccomp::format_json(after, rudy::seccomp::lint(after));
    expect(rudy::json::parse(json).object() != nullptr, "JSON report is parseable");
    const auto sarif = rudy::seccomp::format_sarif(rudy::seccomp::lint(after));
    expect(rudy::json::parse(sarif).object() != nullptr, "SARIF report is valid JSON");
    const auto diff = rudy::seccomp::format_diff_json(before, after);
    expect(rudy::json::parse(diff).object() != nullptr, "diff report is parseable JSON");
    expect(diff.find("added") != std::string::npos && diff.find("changed") != std::string::npos,
           "diff reports added and changed named rules");
    expect(diff.find("architecturesChanged") != std::string::npos && diff.find("flagsChanged") != std::string::npos,
           "diff reports architecture and flag drift");
    expect(rudy::seccomp::format_diff_text(before, after).find("not a proof") != std::string::npos,
           "text diff keeps its semantic boundary visible");
}

} // namespace

int main() {
    try {
        test_json();
        test_profile_and_lint();
        test_probe();
        test_reports_and_diff();
        std::cout << "Rudy Seccomp Lens: " << checks << " checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
