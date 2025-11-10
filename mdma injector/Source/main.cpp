#include "Core/injector.h"
#include "Utils/pid.h"
#include "Utils/log.h"
#include "backend/main/imgui.h"
#include "backend/main/imgui_impl_win32.h"
#include "backend/main/imgui_impl_dx11.h"
#include <d3d11.h>
#include <Windows.h>
#include <string>
#include <vector>
#include <commdlg.h>
#include <fstream>
#include <algorithm>
#include <tlhelp32.h>

#pragma comment(lib, "d3d11.lib")

static ID3D11Device* g_pd3d_device = nullptr;
static ID3D11DeviceContext* g_pd3d_device_context = nullptr;
static IDXGISwapChain* g_pswap_chain = nullptr;
static ID3D11RenderTargetView* g_main_render_target_view = nullptr;

void create_render_target() { ID3D11Texture2D* back_buffer; g_pswap_chain->GetBuffer(0, IID_PPV_ARGS(&back_buffer)); g_pd3d_device->CreateRenderTargetView(back_buffer, nullptr, &g_main_render_target_view); back_buffer->Release(); }
void cleanup_render_target() { if (g_main_render_target_view) { g_main_render_target_view->Release(); g_main_render_target_view = nullptr; } }

void cleanup_device_d3d() {
	cleanup_render_target();
	if (g_pswap_chain) { g_pswap_chain->Release(); g_pswap_chain = nullptr; }
	if (g_pd3d_device_context) { g_pd3d_device_context->Release(); g_pd3d_device_context = nullptr; }
	if (g_pd3d_device) { g_pd3d_device->Release(); g_pd3d_device = nullptr; }
}

bool create_device_d3d(HWND hwnd) {
	DXGI_SWAP_CHAIN_DESC sd;
	ZeroMemory(&sd, sizeof(sd));
	sd.BufferCount = 2;
	sd.BufferDesc.Width = 0;
	sd.BufferDesc.Height = 0;
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	sd.BufferDesc.RefreshRate.Numerator = 60;
	sd.BufferDesc.RefreshRate.Denominator = 1;
	sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.OutputWindow = hwnd;
	sd.SampleDesc.Count = 1;
	sd.SampleDesc.Quality = 0;
	sd.Windowed = TRUE;
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

	UINT create_device_flags = 0;
	D3D_FEATURE_LEVEL feature_level;
	const D3D_FEATURE_LEVEL feature_level_array[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
	HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, create_device_flags, feature_level_array, 2, D3D11_SDK_VERSION, &sd, &g_pswap_chain, &g_pd3d_device, &feature_level, &g_pd3d_device_context);
	if (res != S_OK) return false;
	create_render_target();
	return true;
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
	if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wparam, lparam)) return true;
	switch (msg) {
	case WM_SIZE: if (g_pd3d_device != nullptr && wparam != SIZE_MINIMIZED) { cleanup_render_target(); g_pswap_chain->ResizeBuffers(0, (UINT)LOWORD(lparam), (UINT)HIWORD(lparam), DXGI_FORMAT_UNKNOWN, 0); create_render_target(); } return 0;
	case WM_SYSCOMMAND: if ((wparam & 0xfff0) == SC_KEYMENU) return 0; break;
	case WM_DESTROY: PostQuitMessage(0); return 0;
	}
	return DefWindowProcW(hwnd, msg, wparam, lparam);
}

struct process_info { DWORD pid; std::wstring name; };
struct dll_entry { std::wstring path; std::string display_name; bool enabled; };

std::vector<process_info> get_process_list() {
	std::vector<process_info> processes;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32W entry;
		entry.dwSize = sizeof(entry);
		if (Process32FirstW(snapshot, &entry)) { do { processes.push_back({ entry.th32ProcessID, entry.szExeFile }); } while (Process32NextW(snapshot, &entry)); }
		CloseHandle(snapshot);
	}
	return processes;
}

std::wstring open_file_dialog() {
	OPENFILENAMEW ofn = { 0 };
	wchar_t file[MAX_PATH] = { 0 };
	ofn.lStructSize = sizeof(ofn);
	ofn.lpstrFile = file;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = L"DLL Files\0*.dll\0All Files\0*.*\0";
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (GetOpenFileNameW(&ofn)) return std::wstring(file);
	return L"";
}

int WINAPI WinMain(HINSTANCE hinstance, HINSTANCE hprev_instance, LPSTR lpcmd_line, int ncmd_show) {
	WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, wnd_proc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"MDMA Injector", nullptr };
	RegisterClassExW(&wc);
	HWND hwnd = CreateWindowW(wc.lpszClassName, L"MDMA Injector", WS_OVERLAPPEDWINDOW, 100, 100, 520, 440, nullptr, nullptr, wc.hInstance, nullptr);

	if (!create_device_d3d(hwnd)) { cleanup_device_d3d(); UnregisterClassW(wc.lpszClassName, wc.hInstance); return 1; }

	ShowWindow(hwnd, SW_SHOWDEFAULT);
	UpdateWindow(hwnd);

	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO(); (void)io;
	ImGui::StyleColorsDark();
	
	ImGuiStyle& style = ImGui::GetStyle();
	style.WindowRounding = 0.0f;
	style.ChildRounding = 0.0f;
	style.FrameRounding = 0.0f;
	style.ScrollbarRounding = 0.0f;
	style.GrabRounding = 0.0f;
	style.PopupRounding = 0.0f;
	style.TabRounding = 0.0f;
	style.AntiAliasedLines = false;
	style.AntiAliasedFill = false;

	ImGui_ImplWin32_Init(hwnd);
	ImGui_ImplDX11_Init(g_pd3d_device, g_pd3d_device_context);

	static DWORD selected_pid = 0;
	static char process_display[256] = "";
	static char process_search[256] = "";
	static std::vector<process_info> processes;
	static std::vector<const char*> process_names;
	static std::vector<std::string> process_strings;
	static int selected_process_idx = 0;
	static std::vector<dll_entry> dll_list;
	static int selected_dll_idx = -1;
	static float last_refresh = 0.0f;
	static bool show_settings = false;
	static bool auto_inject = false;
	static bool close_on_inject = false;
	static bool manual_map_mode = true;
	static bool show_console = false;
	static std::vector<std::string> log_messages;
	static char dll_path_display[512] = "No DLL selected";

	processes = get_process_list();
	for (auto& p : processes) { char buf[256]; WideCharToMultiByte(CP_UTF8, 0, p.name.c_str(), -1, buf, sizeof(buf), nullptr, nullptr); process_strings.push_back(std::string(buf)); }
	for (auto& s : process_strings) process_names.push_back(s.c_str());

	bool running = true;
	while (running) {
		MSG msg;
		while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessage(&msg); if (msg.message == WM_QUIT) running = false; }
		if (!running) break;

		if (ImGui::GetTime() - last_refresh > 2.0f) {
			processes = get_process_list();
			process_strings.clear();
			process_names.clear();
			for (auto& p : processes) { char buf[256]; WideCharToMultiByte(CP_UTF8, 0, p.name.c_str(), -1, buf, sizeof(buf), nullptr, nullptr); process_strings.push_back(std::string(buf)); }
			for (auto& s : process_strings) process_names.push_back(s.c_str());
			last_refresh = ImGui::GetTime();
		}

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		ImGui::SetNextWindowPos(ImVec2(0, 0));
		ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
		ImGui::Begin("MDMA Injector", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

		ImGui::Text("Process Name:");
		ImGui::SameLine();
		ImGui::PushItemWidth(230);
		if (!process_names.empty()) { if (ImGui::Combo("##process", &selected_process_idx, process_names.data(), (int)process_names.size())) { selected_pid = processes[selected_process_idx].pid; WideCharToMultiByte(CP_UTF8, 0, processes[selected_process_idx].name.c_str(), -1, process_display, sizeof(process_display), nullptr, nullptr); } }
		ImGui::PopItemWidth();
		ImGui::SameLine();
		if (ImGui::Button("Select", ImVec2(65, 0))) { selected_pid = processes[selected_process_idx].pid; }
		ImGui::SameLine();
	/*	if (ImGui::Button("Refresh", ImVec2(65, 0))) {
			processes = get_process_list();
			process_strings.clear();
			process_names.clear();
			for (auto& p : processes) { char buf[256]; WideCharToMultiByte(CP_UTF8, 0, p.name.c_str(), -1, buf, sizeof(buf), nullptr, nullptr); process_strings.push_back(std::string(buf)); }
			for (auto& s : process_strings) process_names.push_back(s.c_str());
		}*/

		ImGui::Spacing();
		ImGui::BeginChild("InjectList", ImVec2(0, -32), true);
		ImGui::Text("Inject List");
		ImGui::Separator();
		ImGui::Spacing();

		ImGui::BeginChild("LeftButtons", ImVec2(120, 0), false);
		if (ImGui::Button("Add DLL", ImVec2(-1, 24))) {
			std::wstring dll = open_file_dialog();
			if (!dll.empty()) {
				size_t pos = dll.find_last_of(L"\\/");
				std::wstring filename = (pos != std::wstring::npos) ? dll.substr(pos + 1) : dll;
				char display[256];
				WideCharToMultiByte(CP_UTF8, 0, filename.c_str(), -1, display, sizeof(display), nullptr, nullptr);
				dll_list.push_back({ dll, std::string(display), true });
				WideCharToMultiByte(CP_UTF8, 0, dll.c_str(), -1, dll_path_display, sizeof(dll_path_display), nullptr, nullptr);
			}
		}
		if (ImGui::Button("Enable/Disable", ImVec2(-1, 24))) { if (selected_dll_idx >= 0 && selected_dll_idx < dll_list.size()) dll_list[selected_dll_idx].enabled = !dll_list[selected_dll_idx].enabled; }
		if (ImGui::Button("Remove", ImVec2(-1, 24))) { if (selected_dll_idx >= 0 && selected_dll_idx < dll_list.size()) { dll_list.erase(dll_list.begin() + selected_dll_idx); selected_dll_idx = -1; } }
		if (ImGui::Button("Clear", ImVec2(-1, 24))) { dll_list.clear(); selected_dll_idx = -1; strcpy_s(dll_path_display, "no dll selected"); }
		ImGui::EndChild();

		ImGui::SameLine();

		ImGui::BeginChild("DLLListBox", ImVec2(0, 0), true);
		ImGui::Text("DLL Name");
		ImGui::Separator();
		for (int i = 0; i < dll_list.size(); i++) {
			char label[300];
			snprintf(label, sizeof(label), "%s%s", dll_list[i].enabled ? "" : "[DISABLED] ", dll_list[i].display_name.c_str());
			if (ImGui::Selectable(label, selected_dll_idx == i)) { selected_dll_idx = i; WideCharToMultiByte(CP_UTF8, 0, dll_list[i].path.c_str(), -1, dll_path_display, sizeof(dll_path_display), nullptr, nullptr); }
		}
		ImGui::EndChild();

		ImGui::EndChild();

		if (ImGui::Button("Settings", ImVec2(100, 26))) show_settings = true;
		ImGui::SameLine();
		ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 108);
		if (ImGui::Button("Inject", ImVec2(100, 26))) {
			if (selected_pid == 0) { MessageBoxA(hwnd, "No process selected!", "Error", MB_OK | MB_ICONERROR); }
			else if (dll_list.empty()) { MessageBoxA(hwnd, "No DLLs added!", "Error", MB_OK | MB_ICONERROR); }
			else {
				pid::enable_debug_priv();
				HANDLE h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, selected_pid);
				if (!h_proc) { MessageBoxA(hwnd, "Failed to open process!", "Error", MB_OK | MB_ICONERROR); }
				else {
					int success = 0, failed = 0;
					for (auto& dll : dll_list) {
						if (!dll.enabled) continue;
						std::ifstream file(dll.path, std::ios::binary | std::ios::ate);
						if (file.fail()) { failed++; continue; }
						auto file_size = file.tellg();
						BYTE* p_src_data = new BYTE[(UINT_PTR)file_size];
						file.seekg(0, std::ios::beg);
						file.read((char*)p_src_data, file_size);
						file.close();
						if (manual_map_dll(h_proc, p_src_data, file_size)) success++; else failed++;
						delete[] p_src_data;
					}
					CloseHandle(h_proc);
					char msg[256];
					snprintf(msg, sizeof(msg), "Injection complete!\n\nSuccess: %d\nFailed: %d", success, failed);
					MessageBoxA(hwnd, msg, "Result", MB_OK | MB_ICONINFORMATION);
					if (close_on_inject) running = false;
				}
			}
		}

		if (show_settings) {
			ImGui::OpenPopup("Settings");
			if (ImGui::BeginPopupModal("Settings", &show_settings, ImGuiWindowFlags_AlwaysAutoResize)) {
				ImGui::Checkbox("Manual Mapping Mode", &manual_map_mode);
				ImGui::Checkbox("Auto-inject on add", &auto_inject);
				ImGui::Checkbox("Close after injection", &close_on_inject);
				if (ImGui::Checkbox("Show Console", &show_console)) { HWND console = GetConsoleWindow(); if (show_console) { if (!console) { AllocConsole(); freopen_s((FILE**)stdout, "CONOUT$", "w", stdout); } else ShowWindow(console, SW_SHOW); } else { if (console) ShowWindow(console, SW_HIDE); } }
				ImGui::Separator();
				if (ImGui::Button("Close", ImVec2(200, 0))) { show_settings = false; ImGui::CloseCurrentPopup(); }
				ImGui::EndPopup();
			}
		}

		ImGui::End();

		ImGui::Render();
		const float clear_color[4] = { 0.05f, 0.05f, 0.05f, 1.0f };
		g_pd3d_device_context->OMSetRenderTargets(1, &g_main_render_target_view, nullptr);
		g_pd3d_device_context->ClearRenderTargetView(g_main_render_target_view, clear_color);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

		g_pswap_chain->Present(1, 0);
	}

	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();

	cleanup_device_d3d();
	DestroyWindow(hwnd);
	UnregisterClassW(wc.lpszClassName, wc.hInstance);

	return 0;
}

