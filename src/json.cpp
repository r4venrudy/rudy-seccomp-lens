#include "json.hpp"

#include <charconv>
#include <cstdint>
#include <sstream>

namespace rudy::json {

const Value::Object* Value::object() const noexcept { return std::get_if<Object>(&data); }
const Value::Array* Value::array() const noexcept { return std::get_if<Array>(&data); }
const std::string* Value::string() const noexcept { return std::get_if<std::string>(&data); }
const Number* Value::number() const noexcept { return std::get_if<Number>(&data); }
const bool* Value::boolean() const noexcept { return std::get_if<bool>(&data); }

ParseError::ParseError(std::size_t offset, const std::string& message)
    : std::runtime_error(message + " at byte " + std::to_string(offset)), offset_(offset) {}

namespace {

void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp <= 0x7fU) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7ffU) {
        out.push_back(static_cast<char>(0xc0U | (cp >> 6U)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    } else if (cp <= 0xffffU) {
        out.push_back(static_cast<char>(0xe0U | (cp >> 12U)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    } else {
        out.push_back(static_cast<char>(0xf0U | (cp >> 18U)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 12U) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    }
}

bool valid_utf8(const std::string& value) {
    std::size_t i = 0;
    while (i < value.size()) {
        const auto c = static_cast<unsigned char>(value[i]);
        if (c <= 0x7fU) { ++i; continue; }
        std::size_t n = 0;
        std::uint32_t cp = 0;
        if ((c & 0xe0U) == 0xc0U) { n = 2; cp = c & 0x1fU; }
        else if ((c & 0xf0U) == 0xe0U) { n = 3; cp = c & 0x0fU; }
        else if ((c & 0xf8U) == 0xf0U) { n = 4; cp = c & 0x07U; }
        else return false;
        if (i + n > value.size()) return false;
        for (std::size_t j = 1; j < n; ++j) {
            const auto d = static_cast<unsigned char>(value[i + j]);
            if ((d & 0xc0U) != 0x80U) return false;
            cp = (cp << 6U) | (d & 0x3fU);
        }
        if ((n == 2 && cp < 0x80U) || (n == 3 && cp < 0x800U) ||
            (n == 4 && cp < 0x10000U) || cp > 0x10ffffU ||
            (cp >= 0xd800U && cp <= 0xdfffU)) return false;
        i += n;
    }
    return true;
}

class Parser {
public:
    Parser(const std::string& input, std::size_t max_depth) : input_(input), max_depth_(max_depth) {}

    Value run() {
        skip_ws();
        Value value = parse_value(0);
        skip_ws();
        if (pos_ != input_.size()) fail("unexpected trailing data");
        return value;
    }

private:
    const std::string& input_;
    std::size_t max_depth_;
    std::size_t pos_ = 0;

    [[noreturn]] void fail(const std::string& message) const { throw ParseError(pos_, message); }
    char peek() const { return pos_ < input_.size() ? input_[pos_] : '\0'; }
    char take() {
        if (pos_ >= input_.size()) fail("unexpected end of input");
        return input_[pos_++];
    }
    void skip_ws() {
        while (pos_ < input_.size()) {
            const char c = input_[pos_];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
            ++pos_;
        }
    }
    bool consume(char c) {
        if (peek() != c) return false;
        ++pos_;
        return true;
    }
    void literal(const char* expected) {
        while (*expected != '\0') if (take() != *expected++) fail("invalid literal");
    }
    Value parse_value(std::size_t depth) {
        if (depth > max_depth_) fail("maximum nesting depth exceeded");
        switch (peek()) {
        case 'n': literal("null"); return Value{nullptr};
        case 't': literal("true"); return Value{true};
        case 'f': literal("false"); return Value{false};
        case '"': return Value{parse_string()};
        case '[': return Value{parse_array(depth + 1U)};
        case '{': return Value{parse_object(depth + 1U)};
        default:
            if (peek() == '-' || (peek() >= '0' && peek() <= '9')) return Value{parse_number()};
            fail("expected JSON value");
        }
    }
    std::uint16_t hex4() {
        std::uint16_t value = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = take();
            value = static_cast<std::uint16_t>(value << 4U);
            if (c >= '0' && c <= '9') value = static_cast<std::uint16_t>(value | static_cast<std::uint16_t>(c - '0'));
            else if (c >= 'a' && c <= 'f') value = static_cast<std::uint16_t>(value | static_cast<std::uint16_t>(c - 'a' + 10));
            else if (c >= 'A' && c <= 'F') value = static_cast<std::uint16_t>(value | static_cast<std::uint16_t>(c - 'A' + 10));
            else fail("invalid Unicode escape");
        }
        return value;
    }
    std::string parse_string() {
        if (take() != '"') fail("expected string");
        std::string out;
        while (true) {
            if (pos_ >= input_.size()) fail("unterminated string");
            const unsigned char c = static_cast<unsigned char>(take());
            if (c == '"') break;
            if (c < 0x20U) fail("unescaped control character in string");
            if (c != '\\') { out.push_back(static_cast<char>(c)); continue; }
            switch (take()) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': {
                std::uint32_t cp = hex4();
                if (cp >= 0xd800U && cp <= 0xdbffU) {
                    if (take() != '\\' || take() != 'u') fail("high surrogate missing low surrogate");
                    const std::uint32_t low = hex4();
                    if (low < 0xdc00U || low > 0xdfffU) fail("invalid low surrogate");
                    cp = 0x10000U + ((cp - 0xd800U) << 10U) + (low - 0xdc00U);
                } else if (cp >= 0xdc00U && cp <= 0xdfffU) {
                    fail("unpaired low surrogate");
                }
                append_utf8(out, cp);
                break;
            }
            default: fail("invalid string escape");
            }
        }
        if (!valid_utf8(out)) fail("invalid UTF-8 in string");
        return out;
    }
    Number parse_number() {
        const std::size_t start = pos_;
        consume('-');
        if (consume('0')) {
            if (peek() >= '0' && peek() <= '9') fail("leading zero in number");
        } else {
            if (peek() < '1' || peek() > '9') fail("invalid number");
            while (peek() >= '0' && peek() <= '9') ++pos_;
        }
        if (consume('.')) {
            if (peek() < '0' || peek() > '9') fail("fraction requires a digit");
            while (peek() >= '0' && peek() <= '9') ++pos_;
        }
        if (consume('e') || consume('E')) {
            if (peek() == '+' || peek() == '-') ++pos_;
            if (peek() < '0' || peek() > '9') fail("exponent requires a digit");
            while (peek() >= '0' && peek() <= '9') ++pos_;
        }
        return Number{input_.substr(start, pos_ - start)};
    }
    Value::Array parse_array(std::size_t depth) {
        take();
        skip_ws();
        Value::Array values;
        if (consume(']')) return values;
        while (true) {
            if (values.size() >= 200000U) fail("array item limit exceeded");
            skip_ws();
            values.push_back(parse_value(depth));
            skip_ws();
            if (consume(']')) return values;
            if (!consume(',')) fail("expected comma or closing bracket");
        }
    }
    Value::Object parse_object(std::size_t depth) {
        take();
        skip_ws();
        Value::Object values;
        if (consume('}')) return values;
        while (true) {
            skip_ws();
            if (peek() != '"') fail("object key must be a string");
            std::string key = parse_string();
            skip_ws();
            if (!consume(':')) fail("expected colon after object key");
            skip_ws();
            Value value = parse_value(depth);
            if (!values.emplace(std::move(key), std::move(value)).second) fail("duplicate object key");
            if (values.size() >= 200000U) fail("object member limit exceeded");
            skip_ws();
            if (consume('}')) return values;
            if (!consume(',')) fail("expected comma or closing brace");
        }
    }
};

} // namespace

Value parse(const std::string& input, std::size_t max_bytes, std::size_t max_depth) {
    if (input.size() > max_bytes) throw ParseError(0, "input byte limit exceeded");
    return Parser(input, max_depth).run();
}

std::string quote(const std::string& value) {
    std::string out = "\"";
    static constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char c : value) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20U) {
                out += "\\u00";
                out.push_back(hex[c >> 4U]);
                out.push_back(hex[c & 0x0fU]);
            } else out.push_back(static_cast<char>(c));
        }
    }
    out.push_back('"');
    return out;
}

} // namespace rudy::json
