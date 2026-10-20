#pragma once

#include <cstddef>
#include <map>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace rudy::json {

struct Number {
    std::string text;
};

struct Value {
    using Array = std::vector<Value>;
    using Object = std::map<std::string, Value, std::less<>>;
    using Storage = std::variant<std::nullptr_t, bool, Number, std::string, Array, Object>;

    Storage data;
    const Object* object() const noexcept;
    const Array* array() const noexcept;
    const std::string* string() const noexcept;
    const Number* number() const noexcept;
    const bool* boolean() const noexcept;
};

class ParseError final : public std::runtime_error {
public:
    ParseError(std::size_t offset, const std::string& message);
    std::size_t offset() const noexcept { return offset_; }
private:
    std::size_t offset_;
};

Value parse(const std::string& input, std::size_t max_bytes = 8U * 1024U * 1024U,
            std::size_t max_depth = 64U);
std::string quote(const std::string& value);

} // namespace rudy::json
