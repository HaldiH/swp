//
// Created by hugo on 07.06.19.
//

#pragma once

#include <algorithm>
#include <cstring>
#include <string_view>
#include <vector>
#include <ctll.hpp>
#include <ctre.hpp>
#include "cexpr_algs.hpp"
#include "flatmap.hpp"

constexpr auto target_pattern = ctll::fixed_string{R"(^($|/[^#?\s]+)?(.*?)?(#[A-Za-z_\-]+)?$)"};

static constexpr auto target_match(std::string_view sv) noexcept { return ctre::match<target_pattern>(sv); }

constexpr auto target_queries = ctll::fixed_string{R"([&;]?([^=&;]+)=?([^=&;]*))"};
constexpr auto target_path_parts = ctll::fixed_string{R"(/([^/]+))"};

#ifndef HE_WA_CTRE_URL_SPLIT
constexpr auto url_pattern = ctll::fixed_string{R"(^(?:(http[s]?|ftp)://)?([^/]+?)(?::(\d+))?(?:$|/)([^#?\s]+)?(.*?)?(#[A-Za-z_\-]+)?$)"};

static constexpr auto url_match(std::string_view sv) noexcept { return ctre::match<url_pattern>(sv); }

#else
// https://godbolt.org/#z:OYLghAFBqd5QCxAYwPYBMCmBRdBLAF1QCcAaPECAKxAEZSAbAQwDtRkBSAJgCFufSAZ1QBXYskwgA5NwDMeFsgYisAag6yAwkwbAShBAFsN2DgAYAgnIVKVmdVuQEGDAHQIADh5PmrXeYrKahqaTsSY7l4%2BltaBdg6aggTECsAA%2BgBueJgA7tF%2BAbbBWhmYTiT5sUX2IXioSeFMxrKmMf42QTVaBCIeDJiVliKCqaosTZiCHkwSqknoICAMhJjEOoIafDGWAPQ7qmgsSZgAHh7EqkwiRKrTBASrLA4AIgfODIsAZngnmOhpDVSHAA7DwAErcLgQDgAVmw0NkADFKAh7t4YTwNjDnhpESDNJ8CB4AJQgPbE3HQjGw7A7WE43i44kI5GUWGadAgnj0GEg57EilIlkgAAk%2BJ2zNhfDhclx7KxDJ4gsREFcAComZTZRiLABaABaTF1AC80uzdfT%2BMqRRSuFw%2BZtfIdjmcLlcbncHsQWLQXm8XF8fn8AckgaCIXaqfDcSi0VKFXLgQSiaTyVrqXCdiBLbxma4rTbIQ7ZFsLM6Hq7LtdULcmPdHlw/U4AyBvr9/oC2FyI1CacK2TCOVblcKxUmJVTpaZ/HLBwnc5T1ZqhdqeHrDSazYOLdirbjC3bi6WFARVIYmAoIBTQb5VHfVHsDqgjhXzlWbuFBE3kpIQOeCMgCAhJ6jwmNCdqokSZI7AwqDIDoCD1AQIAABxmChtAwXgABGWTEAQOzoKg54KBsdqCBkgqlvecwEAsICdsAtHEFykKQR4gjQYhSTjIYkgoShAAsgk7HcCA7EQMFwbiACOIirAAnhozysGRABsGRMCxsjPJpDByJ8azAEWwI4iWt73u6Nafr6ylvOEiz/oBwF1l6PpgfMiyMZk2R5KCDR8lRFl3lZ6gYoIaQ6Aw9BzACgGYHxpCxdxBBJRFLCnAQ9J%2BjZjrbBYNGhZ%2BjZ2WEv5OUBWggd69otBA6WZa4RA%2BbkV5BZYNGPqF8aRS4aVxQgCWYP1KX9R4JCpbFYn9XJin9YZTDAHxLBZdiOWTHlBWWdWYWYr1DD9TFEVcP1sj9YJ2V2cVm00Z5KCiKeIQhKoEDYagqAMMS10dfeT1aKoYAyIOLCAwkz0RYI8V8U1qAtTkV7BWD/2A%2ByINSEjmjJUhMNwwjP13n9mMo8DoOE7FtA41krUUvjGMA0Dmho3Tx2U75eNbQTWjPcTjOk1z/0RbIrPU4jZM80zZMRYJwvw8SzN0YsmAsOg%2BnmflfJSMSjDSDCUikCw0hmHrqDSJo/D8HMojiDU/i0HryFSEbAqkAA1iAMJmK4tCCTCgkAJy0LQXC0MCMJcMCana1Igl6wbjvG9IeucWYpAO07pBwLAMCIPdhgeHg/RkBQEBoHnBerCAwAoWd3wMF6nGvYbevYQoWkKdIdukKXy0EAA8iwDDt/HpBYOebD9E3I94OETh4KUnHD6cZTXJIw8npgHzD8s2FrMQCmaBgq%2Bd6GhhN1rzBsCg5u8IwOGcbAvGSGVpClMQIDJCILAu87qAeAQdRHGkLqeYylOCMl4CHVQupe6yCTlbCQdBz461jpPE2UgTgoTUrqNSglVDAGQMgVQKFXCyBergQgJB1C2ySgfMuhcqGyFoHLM24CeD2zPlrN2shPZ%2BzMAHYEftBKML9ihO0fsYRRxjqQU%2BHt9aoMTkIEAKc06awztnCASBS750LuQSgWjy5vyUKwKuZgU613rpQbCk8W7jD3h3PW3clZ9wHkPI2I8ErGInsPfAM9/7z0nkvZAK9J7r03m47eu996H3sanFIp8pB23PsYq%2BrDb7YXvlAR%2BKAfwvwrh/L%2BP8/4AIXsAuioDr7cmBFAmBcCxAIKYVHXWcjh5oIwVgnBBwL5MWIZ7MwZD8BEAuHIGKtDtGrAYVwZhFT2Hx2doNJgWA35XkkXrGRKc45uLQUnJRqcOGuxAFwNSrgBLAjMFwQSKFxE4P4WdTesDmmbIUSorWmcoDqKQA9Dw1xdEl2ImMt%2B9A/gUIBaQHIawPD2KQVIJpGyE4yFtqoHIBhVBtOwbg/BhDiH3OeZwg5XBXB%2BzUsCC5sgRFcBhCIswocVnSPdus%2BRUhtnKLPmo%2BAGiQCfO%2BcXfRhcDmkCBYMugoLwWQsaSglp0g5CNiRQQBAKLMFos6cYohrhekzKdlreZizKBQqkWsh5cKmW7Nmbiu0BKiUkrJRStC1K7niseYy41Gqo5cHtYap1mstavxGM%2BEAgkgA
[[deprecated]] constexpr auto url_pat_split1 = ctll::fixed_string{R"(^(?:(http[s]?|ftp)://)?([^/:]+)(.+)$)"};
[[deprecated]] constexpr auto url_pat_split2 = ctll::fixed_string{R"(^(?::(\d+))?(?:$|/)([^#?\s]+)?(.*?)?(#[A-Za-z_\-]+)?$)"};

[[deprecated]] static constexpr auto url_match_split1(std::string_view sv) noexcept { return ctre::match<url_pat_split1>(sv); }
[[deprecated]] static constexpr auto url_match_split2(std::string_view sv) noexcept { return ctre::match<url_pat_split2>(sv); }
#endif

class TargetParser {
  protected:
    std::string_view url{};
    std::string_view path{};

    std::vector<std::string_view> path_parts = {};
    flatmap<std::string_view, std::string_view> queries = {};

    constexpr std::string_view match() noexcept {
        auto res = target_match(url);
        auto [s_all, s_path, s_query, s_fragment] = res;
        path = s_path;
        return s_query;
    }

    void parse_queries(std::string_view sv_query) noexcept {
        queries.clear();
        for (auto [s_match, s_val] : ctre::range<target_path_parts>(path))
            path_parts.emplace_back(s_val);
        if (sv_query.length() > 0)
            sv_query.remove_prefix(1); // strip leading '?'
        for (auto [s_match, s_name, s_value] : ctre::range<target_queries>(sv_query))
            queries.emplace(s_name, s_value);
    }

    void parse() noexcept { parse_queries(match()); }

  public:
    constexpr TargetParser() = default;

    explicit TargetParser(std::string_view url) : url(url) { parse(); }

    void setURL(const char* v) {
        url = v;
        parse();
    }

    void setURL(std::string_view sv) {
        url = sv;
        parse();
    }

    [[nodiscard]] constexpr std::string_view getPath() const noexcept { return path; }

    [[nodiscard]] constexpr std::string_view getURL() const noexcept { return url; }

    [[nodiscard]] constexpr const flatmap<std::string_view, std::string_view>& getQueries() const noexcept { return queries; }
    [[nodiscard]] constexpr const std::vector<std::string_view>& getPathParts() const noexcept { return path_parts; }

    [[nodiscard]] constexpr std::string_view operator[](std::string_view key) const noexcept {
        if (auto it = queries.find(key); it != queries.end())
            return it->second;
        return {};
    }

    [[nodiscard]] constexpr std::optional<bool> getBool(std::string_view key) const noexcept {
        const auto val = (*this)[key];
        if (val.data() == nullptr)
            return std::nullopt;
        if (val.empty())
            return true;
        if (val == "1" || val == "yes" || val == "true")
            return true;
        if (val == "0" || val == "no" || val == "false")
            return false;
        return std::nullopt;
    }
};

class URLParser : public TargetParser {
  private:
    std::string_view scheme;
    std::string_view host;
    unsigned short port{0};

    void parse_all() noexcept {
        queries.clear();
#ifndef HE_WA_CTRE_URL_SPLIT
        auto [s_all, s_scheme, s_host, s_port, s_path, s_query, s_fragment] = url_match(url);
#else
        auto [s_all1, s_scheme, s_host, s_next] = url_match_split1(url);
        auto [s_all2, s_port, s_path, s_query, s_fragment] = url_match_split2(s_next.to_view());
#endif
        scheme = s_scheme;
        host = s_host;
        if (s_port)
            port = std::strtoul(s_port.to_view().data(), nullptr, 10);
        path = s_path;
        parse_queries(s_query);
    }

  public:
    explicit URLParser(const char* uri) noexcept { setURL(uri); }

    explicit URLParser(std::string_view uri) noexcept { setURL(uri); }

    constexpr URLParser() = default;

    URLParser(const URLParser&) = default;

    URLParser(URLParser&&) noexcept = default;

    ~URLParser() noexcept = default;

    URLParser& operator=(const URLParser&) = default;

    URLParser& operator=(URLParser&&) = default;

    void setURL(const char* v) {
        url = v;
        parse_all();
    }

    void setURL(std::string_view sv) {
        url = sv;
        parse_all();
    }

    [[nodiscard]] constexpr std::string_view getScheme() const noexcept { return scheme; }

    [[nodiscard]] constexpr std::string_view getHost() const noexcept { return host; }

    /**
     * Returns the port used in the URL; 0 if no explicit one
     * */
    [[nodiscard]] constexpr unsigned short getPort() const noexcept { return port; }
};

struct CSVIterator {
    std::string_view sv;

    constexpr CSVIterator& operator++() noexcept {
        const auto it = cexpr::find(sv.begin(), sv.end(), ',');
        sv.remove_prefix(it != sv.end() ? std::distance(sv.begin(), it) + 1 : sv.size());
        return *this;
    }
    [[nodiscard]] constexpr std::string_view operator*() const noexcept {
        auto csv = sv;
        while (!csv.empty() && csv[0] == ',')
            csv.remove_prefix(1);
        const auto it = cexpr::find(csv.begin(), csv.end(), ',');
        return sv.substr(0, std::distance(sv.begin(), it));
    }
    [[nodiscard]] constexpr bool operator==(const CSVIterator& oth) const noexcept { return sv == oth.sv; }
    [[nodiscard]] constexpr bool operator!=(const CSVIterator& oth) const noexcept { return sv != oth.sv; }
    [[nodiscard]] constexpr CSVIterator end() const noexcept { return {sv.substr(sv.size(), 0)}; }
};