#include "Parser.h"
#include <iostream>

using namespace std;

std::string Parser::parse_header(const std::string& file_path) {
    if (!open_file(file_path))
        return "failed to open file";

    if (!read_dos_header())
        return "invalid DOS header";

    if (!read_pe_header())
        return "Invalid PE header";

    if (!read_optional_header())
        return "failed to read optional header";

    if (!read_section_headers())
        return "failed to read section headers";

    display_info();

    close_file();
    return "PE parsed";
}

bool Parser::open_file(const std::string& file_path) {
    file.open(file_path, std::ios::binary);
    return file.is_open();
}

void Parser::close_file() {
    if (file.is_open())
        file.close();
}

bool Parser::read_dos_header() {
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    return dosHeader.e_magic == IMAGE_DOS_SIGNATURE;
}

bool Parser::read_pe_header() {
    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    DWORD peSignature;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));
    return peSignature == IMAGE_NT_SIGNATURE;
}

bool Parser::read_optional_header() {
    file.read(reinterpret_cast<char*>(&ntHeaders.FileHeader), sizeof(ntHeaders.FileHeader));
    file.read(reinterpret_cast<char*>(&ntHeaders.OptionalHeader), sizeof(ntHeaders.OptionalHeader));
    return true;
}

bool Parser::read_section_headers() {
    sectionHeaders.resize(ntHeaders.FileHeader.NumberOfSections);
    for (auto& sectionHeader : sectionHeaders) {
        file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(sectionHeader));
    }
    return true;
}

void Parser::display_info() {
    cout << "Entry Point : " << hex << ntHeaders.OptionalHeader.AddressOfEntryPoint << endl;
    cout << "Number of Sections : " << dec << ntHeaders.FileHeader.NumberOfSections << endl;
    cout << "DOS Header:" << endl;
    cout << "  Magic Number: " << hex << dosHeader.e_magic << endl;
    cout << "  PE Header Offset: " << hex << dosHeader.e_lfanew << endl;
    cout << "File Header:" << endl;
    cout << "  Machine: " << hex << ntHeaders.FileHeader.Machine << endl;
    cout << "  Number of Symbols: " << ntHeaders.FileHeader.NumberOfSymbols << endl;
    cout << "  Time Date Stamp: " << hex << ntHeaders.FileHeader.TimeDateStamp << " (Unix timestamp)" << endl;
    cout << "  Size of Headers: " << hex << ntHeaders.OptionalHeader.SizeOfHeaders << endl;
    cout << "Optional Header:" << endl;
    cout << "  size of Image: " << hex << ntHeaders.OptionalHeader.SizeOfImage << endl;
    cout << "  checksum: " << hex << ntHeaders.OptionalHeader.CheckSum << endl;
    cout << "  address of Entry Point: " << hex << ntHeaders.OptionalHeader.AddressOfEntryPoint << endl;


    cout << "SECTIONS :" << endl;
    for (size_t i = 0; i < sectionHeaders.size(); ++i) {
        const auto& sectionHeader = sectionHeaders[i];
        string sectionName(reinterpret_cast<const char*>(sectionHeader.Name), 8);
        sectionName = sectionName.substr(0, sectionName.find('\0'));

        cout << "Section " << i + 1 << " :" << endl;
        cout << "  Name: " << sectionName << endl;
        cout << "  Virtual Size: " << hex << sectionHeader.Misc.VirtualSize << endl;
        cout << "  Virtual Address: " << hex << sectionHeader.VirtualAddress << endl;
        cout << "  Size of Raw Data: " << hex << sectionHeader.SizeOfRawData << endl;
        cout << "  Pointer to Raw Data: " << hex << sectionHeader.PointerToRawData << endl;
        cout << "  Characteristics: " << hex << sectionHeader.Characteristics << endl;
    }
}

