#include <iostream>
#include <fstream>
#include <string>
#include "Parser.h"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>

using namespace std;

string AskFile()
{
    string path = "test.exe";
    cout << "enter the relative path to the file you want to parse : ";
    cin >> path;
    return path;
}

int main()
{
    Parser* parser = new Parser();
    string path = AskFile();
    std::cout << parser->parse_header(path) << std::endl;
    return 0;
}

