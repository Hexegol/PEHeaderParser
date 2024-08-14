#pragma once
#include <fstream>
#include <string>
#include <windows.h>
#include <vector>

class Parser
{
public:
    std::string parse_header(const std::string& file_path);
private:
    std::ifstream file;
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    std::vector<IMAGE_SECTION_HEADER> sectionHeaders;

    bool open_file(const std::string& file_path);
    void close_file();

    bool read_dos_header();
    bool read_pe_header();
    bool read_optional_header();
    bool read_section_headers();

    void display_info();
};
