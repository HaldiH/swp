//
// Created by hugo on 4/12/20.
//

#pragma once

std::string_view bsv2sv(boost::string_view bsv) { return std::string_view(bsv.data(), bsv.size()); }

boost::string_view sv2bsv(std::string_view sv) { return boost::string_view(sv.data(), sv.size()); }

class path_segment {
  private:
    const boost::string_view segment_;
    const uint next_segment_starts_;

  public:
    path_segment(const boost::string_view segment, const uint next_segment_starts) : segment_(segment), next_segment_starts_(next_segment_starts){};

    [[nodiscard]] boost::string_view segment() const { return segment_; }
    [[nodiscard]] uint next_segment_starts() const { return next_segment_starts_; }
};

path_segment get_first_segment(boost::string_view path) {
    uint i = 0;
    while (path[0] == '/') {
        path = path.substr(1);
        i++;
    }

    uint j = 0;
    while (j < path.length() && path[j] != '/')
        j++;

    return path_segment(path.substr(0, j), i + j);
}

bool handle_endpoint(boost::string_view key, boost::string_view* sub_path) {
    auto segment = get_first_segment(*sub_path);
    if (key == segment.segment()) {
        uint i = segment.next_segment_starts();
        *sub_path = (*sub_path)[i] == '/' ? sub_path->substr(i + 1) : sub_path->substr(i);
        return true;
    }
    return false;
}