#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scanner_win.h"

/* Control IDs */
enum {
    ID_HOST_EDIT = 100,
    ID_PORTS_EDIT,
    ID_THREADS_EDIT,
    ID_TIMEOUT_EDIT,
    ID_BANNER_CHECK,
    ID_ALL_CHECK,
    ID_SCAN_BUTTON,
    ID_STOP_BUTTON,
    ID_PROGRESS,
    ID_STATUS_LABEL,
    ID_LISTVIEW
};

/* Messages posted from the worker thread back to the GUI thread. */
#define WM_APP_RESULT (WM_APP + 1)
#define WM_APP_DONE   (WM_APP + 2)

typedef struct {
    HWND host_edit, ports_edit, threads_edit, timeout_edit;
    HWND banner_check, all_check;
    HWND scan_button, stop_button;
    HWND progress, status_label, listview;

    size_t total_ports;
    size_t completed_ports;
    int open_count, closed_count, filtered_count;

    struct ScanJob *job;
} AppState;

typedef struct ScanJob {
    AppState *app;
    HWND window;
    scan_config_t cfg;
    volatile LONG cancel;
    int show_all;
    int resolve_failed;
    double elapsed;
    HANDLE thread;
} ScanJob;

typedef struct {
    ScanJob *job;
    port_result_t result;
} ResultMsg;

static COLORREF color_for_status(port_status_t status) {
    switch (status) {
        case PORT_OPEN: return RGB(0x2e, 0x7d, 0x32);
        case PORT_CLOSED: return RGB(0x75, 0x75, 0x75);
        default: return RGB(0xef, 0x6c, 0x00);
    }
}

static void update_status_text(AppState *app) {
    wchar_t buf[192];
    _snwprintf(buf, 192, L"Escaneando... %zu/%zu portas (%d aberta(s))",
               app->completed_ports, app->total_ports, app->open_count);
    SetWindowTextW(app->status_label, buf);
}

static void append_row(AppState *app, const port_result_t *r) {
    wchar_t port_str[16], banner_w[256], service_w[64];
    _snwprintf(port_str, 16, L"%d", r->port);
    MultiByteToWideChar(CP_UTF8, 0, r->service[0] ? r->service : "-", -1, service_w, 64);
    MultiByteToWideChar(CP_UTF8, 0, r->banner, -1, banner_w, 256);

    LVITEMW item;
    memset(&item, 0, sizeof(item));
    item.mask = LVIF_TEXT;
    item.iItem = ListView_GetItemCount(app->listview);
    item.iSubItem = 0;
    item.pszText = port_str;
    int idx = (int)SendMessageW(app->listview, LVM_INSERTITEMW, 0, (LPARAM)&item);

    wchar_t status_w[16];
    MultiByteToWideChar(CP_UTF8, 0, status_to_str(r->status), -1, status_w, 16);
    ListView_SetItemText(app->listview, idx, 1, status_w);
    ListView_SetItemText(app->listview, idx, 2, service_w);
    ListView_SetItemText(app->listview, idx, 3, banner_w);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
static DWORD WINAPI scan_thread_proc(LPVOID data);

static void start_scan(AppState *app, HWND hwnd) {
    if (app->job) return;

    wchar_t host_w[256], ports_w[256];
    GetWindowTextW(app->host_edit, host_w, 256);
    GetWindowTextW(app->ports_edit, ports_w, 256);

    char host[256], ports_spec[256];
    WideCharToMultiByte(CP_UTF8, 0, host_w, -1, host, sizeof(host), NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, ports_w, -1, ports_spec, sizeof(ports_spec), NULL, NULL);

    if (host[0] == '\0') {
        MessageBoxW(hwnd, L"Informe um host.", L"Port Scanner", MB_ICONERROR | MB_OK);
        return;
    }

    int *ports = NULL;
    size_t port_count = 0;
    if (parse_port_spec(ports_spec, &ports, &port_count) != 0) {
        MessageBoxW(hwnd, L"Especificacao de portas invalida (ex: 22,80,1000-2000).",
                    L"Port Scanner", MB_ICONERROR | MB_OK);
        return;
    }

    wchar_t threads_w[16], timeout_w[16];
    GetWindowTextW(app->threads_edit, threads_w, 16);
    GetWindowTextW(app->timeout_edit, timeout_w, 16);
    int threads = _wtoi(threads_w);
    int timeout_ms = _wtoi(timeout_w);
    if (threads < 1) threads = 100;
    if (timeout_ms < 1) timeout_ms = 500;

    ListView_DeleteAllItems(app->listview);
    app->total_ports = port_count;
    app->completed_ports = 0;
    app->open_count = app->closed_count = app->filtered_count = 0;
    SendMessageW(app->progress, PBM_SETPOS, 0, 0);
    SetWindowTextW(app->status_label, L"Resolvendo host...");

    ScanJob *job = calloc(1, sizeof(ScanJob));
    job->app = app;
    job->window = hwnd;
    job->cfg.host = _strdup(host);
    job->cfg.ports = ports;
    job->cfg.port_count = port_count;
    job->cfg.timeout_ms = timeout_ms;
    job->cfg.thread_count = threads;
    job->cfg.grab_banner = (IsDlgButtonChecked(hwnd, ID_BANNER_CHECK) == BST_CHECKED);
    job->show_all = (IsDlgButtonChecked(hwnd, ID_ALL_CHECK) == BST_CHECKED);

    app->job = job;
    EnableWindow(app->scan_button, FALSE);
    EnableWindow(app->stop_button, TRUE);

    DWORD tid;
    job->thread = CreateThread(NULL, 0, scan_thread_proc, job, 0, &tid);
}

static void on_port_result(const port_result_t *result, void *ctx) {
    ScanJob *job = ctx;
    ResultMsg *msg = malloc(sizeof(ResultMsg));
    msg->job = job;
    msg->result = *result;
    PostMessageW(job->window, WM_APP_RESULT, 0, (LPARAM)msg);
}

static DWORD WINAPI scan_thread_proc(LPVOID data) {
    ScanJob *job = data;
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    if (scanner_resolve_host(&job->cfg) != 0) {
        job->resolve_failed = 1;
    } else {
        job->cfg.results = calloc(job->cfg.port_count, sizeof(port_result_t));
        job->cfg.cancel_flag = &job->cancel;
        job->cfg.on_result = on_port_result;
        job->cfg.on_result_ctx = job;
        run_scan(&job->cfg);
    }

    QueryPerformanceCounter(&end);
    job->elapsed = (double)(end.QuadPart - start.QuadPart) / (double)freq.QuadPart;

    PostMessageW(job->window, WM_APP_DONE, 0, (LPARAM)job);
    return 0;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    AppState *app = (AppState *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    switch (msg) {
        case WM_CREATE: {
            app = calloc(1, sizeof(AppState));
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)app);

            HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            int y = 12;

            CreateWindowW(L"STATIC", L"Host:", WS_CHILD | WS_VISIBLE, 12, y + 3, 60, 20, hwnd, NULL, NULL, NULL);
            app->host_edit = CreateWindowW(L"EDIT", L"127.0.0.1", WS_CHILD | WS_VISIBLE | WS_BORDER,
                                            80, y, 660, 22, hwnd, (HMENU)ID_HOST_EDIT, NULL, NULL);
            y += 30;

            CreateWindowW(L"STATIC", L"Portas:", WS_CHILD | WS_VISIBLE, 12, y + 3, 60, 20, hwnd, NULL, NULL, NULL);
            app->ports_edit = CreateWindowW(L"EDIT", L"1-1024", WS_CHILD | WS_VISIBLE | WS_BORDER,
                                             80, y, 660, 22, hwnd, (HMENU)ID_PORTS_EDIT, NULL, NULL);
            y += 30;

            CreateWindowW(L"STATIC", L"Threads:", WS_CHILD | WS_VISIBLE, 12, y + 3, 60, 20, hwnd, NULL, NULL, NULL);
            app->threads_edit = CreateWindowW(L"EDIT", L"100", WS_CHILD | WS_VISIBLE | WS_BORDER,
                                               80, y, 80, 22, hwnd, (HMENU)ID_THREADS_EDIT, NULL, NULL);
            CreateWindowW(L"STATIC", L"Timeout (ms):", WS_CHILD | WS_VISIBLE, 180, y + 3, 90, 20, hwnd, NULL, NULL, NULL);
            app->timeout_edit = CreateWindowW(L"EDIT", L"500", WS_CHILD | WS_VISIBLE | WS_BORDER,
                                               275, y, 80, 22, hwnd, (HMENU)ID_TIMEOUT_EDIT, NULL, NULL);
            y += 32;

            app->banner_check = CreateWindowW(L"BUTTON", L"Capturar banner",
                                               WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                               12, y, 160, 20, hwnd, (HMENU)ID_BANNER_CHECK, NULL, NULL);
            app->all_check = CreateWindowW(L"BUTTON", L"Mostrar todas as portas",
                                            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                            200, y, 200, 20, hwnd, (HMENU)ID_ALL_CHECK, NULL, NULL);
            y += 30;

            app->scan_button = CreateWindowW(L"BUTTON", L"Escanear", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                              12, y, 100, 28, hwnd, (HMENU)ID_SCAN_BUTTON, NULL, NULL);
            app->stop_button = CreateWindowW(L"BUTTON", L"Parar", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                              120, y, 100, 28, hwnd, (HMENU)ID_STOP_BUTTON, NULL, NULL);
            EnableWindow(app->stop_button, FALSE);
            y += 38;

            app->progress = CreateWindowW(PROGRESS_CLASSW, NULL, WS_CHILD | WS_VISIBLE,
                                           12, y, 728, 18, hwnd, (HMENU)ID_PROGRESS, NULL, NULL);
            y += 26;

            app->status_label = CreateWindowW(L"STATIC", L"Pronto.", WS_CHILD | WS_VISIBLE,
                                               12, y, 728, 20, hwnd, (HMENU)ID_STATUS_LABEL, NULL, NULL);
            y += 26;

            app->listview = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, NULL,
                                             WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
                                             12, y, 728, 380, hwnd, (HMENU)ID_LISTVIEW, NULL, NULL);
            ListView_SetExtendedListViewStyle(app->listview, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

            LVCOLUMNW col;
            memset(&col, 0, sizeof(col));
            col.mask = LVCF_TEXT | LVCF_WIDTH;

            col.pszText = L"Porta"; col.cx = 70;
            ListView_InsertColumn(app->listview, 0, &col);
            col.pszText = L"Status"; col.cx = 90;
            ListView_InsertColumn(app->listview, 1, &col);
            col.pszText = L"Servico"; col.cx = 140;
            ListView_InsertColumn(app->listview, 2, &col);
            col.pszText = L"Banner"; col.cx = 400;
            ListView_InsertColumn(app->listview, 3, &col);

            HWND children[] = {
                app->host_edit, app->ports_edit, app->threads_edit, app->timeout_edit,
                app->banner_check, app->all_check, app->scan_button, app->stop_button,
                app->status_label
            };
            for (size_t i = 0; i < sizeof(children) / sizeof(children[0]); i++) {
                SendMessageW(children[i], WM_SETFONT, (WPARAM)font, TRUE);
            }
            return 0;
        }

        case WM_COMMAND: {
            int id = LOWORD(wParam);
            if (id == ID_SCAN_BUTTON && HIWORD(wParam) == BN_CLICKED) {
                start_scan(app, hwnd);
            } else if (id == ID_STOP_BUTTON && HIWORD(wParam) == BN_CLICKED) {
                if (app->job) {
                    InterlockedExchange(&app->job->cancel, 1);
                    EnableWindow(app->stop_button, FALSE);
                }
            }
            return 0;
        }

        case WM_NOTIFY: {
            NMHDR *nmhdr = (NMHDR *)lParam;
            if (nmhdr->idFrom == ID_LISTVIEW && nmhdr->code == NM_CUSTOMDRAW) {
                NMLVCUSTOMDRAW *cd = (NMLVCUSTOMDRAW *)lParam;
                switch (cd->nmcd.dwDrawStage) {
                    case CDDS_PREPAINT:
                        SetWindowLongPtrW(hwnd, DWLP_MSGRESULT, CDRF_NOTIFYITEMDRAW);
                        return CDRF_NOTIFYITEMDRAW;
                    case CDDS_ITEMPREPAINT:
                        /* Ask for a per-subitem callback too, so the color
                         * applies to every column, not just the first. */
                        SetWindowLongPtrW(hwnd, DWLP_MSGRESULT, CDRF_NOTIFYSUBITEMDRAW);
                        return CDRF_NOTIFYSUBITEMDRAW;
                    case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
                        wchar_t status_text[16];
                        ListView_GetItemText(app->listview, (int)cd->nmcd.dwItemSpec, 1, status_text, 16);
                        port_status_t st = PORT_CLOSED;
                        if (wcscmp(status_text, L"open") == 0) st = PORT_OPEN;
                        else if (wcscmp(status_text, L"filtered") == 0) st = PORT_FILTERED;
                        cd->clrText = color_for_status(st);
                        SetWindowLongPtrW(hwnd, DWLP_MSGRESULT, CDRF_DODEFAULT);
                        return CDRF_DODEFAULT;
                    }
                }
            }
            return 0;
        }

        case WM_APP_RESULT: {
            ResultMsg *rm = (ResultMsg *)lParam;
            ScanJob *job = rm->job;

            app->completed_ports++;
            switch (rm->result.status) {
                case PORT_OPEN: app->open_count++; break;
                case PORT_CLOSED: app->closed_count++; break;
                default: app->filtered_count++; break;
            }

            if (job->show_all || rm->result.status == PORT_OPEN) {
                append_row(app, &rm->result);
            }

            int frac = app->total_ports
                ? (int)((double)app->completed_ports * 100.0 / (double)app->total_ports)
                : 100;
            SendMessageW(app->progress, PBM_SETPOS, (WPARAM)frac, 0);
            update_status_text(app);

            free(rm);
            return 0;
        }

        case WM_APP_DONE: {
            ScanJob *job = (ScanJob *)lParam;
            WaitForSingleObject(job->thread, INFINITE);
            CloseHandle(job->thread);

            if (job->resolve_failed) {
                wchar_t buf[300];
                _snwprintf(buf, 300, L"Nao foi possivel resolver o host '%hs'.", job->cfg.host);
                MessageBoxW(hwnd, buf, L"Port Scanner", MB_ICONERROR | MB_OK);
                SetWindowTextW(app->status_label, L"Falha ao resolver host.");
            } else {
                wchar_t buf[220];
                _snwprintf(buf, 220, L"%hs: %d aberta(s), %d fechada(s), %d filtrada(s) em %.2fs",
                           job->cancel ? "Interrompido" : "Concluido",
                           app->open_count, app->closed_count, app->filtered_count, job->elapsed);
                SetWindowTextW(app->status_label, buf);
                SendMessageW(app->progress, PBM_SETPOS, 100, 0);
            }

            EnableWindow(app->scan_button, TRUE);
            EnableWindow(app->stop_button, FALSE);

            free(job->cfg.ports);
            free(job->cfg.results);
            free((void *)job->cfg.host);
            app->job = NULL;
            free(job);
            return 0;
        }

        case WM_DESTROY:
            free(app);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPWSTR cmdline, int nCmdShow) {
    (void)hPrev; (void)cmdline;

    if (scanner_winsock_init() != 0) {
        MessageBoxW(NULL, L"Falha ao inicializar Winsock.", L"Port Scanner", MB_ICONERROR | MB_OK);
        return 1;
    }

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSW wc;
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"PortScannerGuiWindow";
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowW(L"PortScannerGuiWindow", L"Port Scanner",
                               WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                               CW_USEDEFAULT, CW_USEDEFAULT, 770, 560,
                               NULL, NULL, hInstance, NULL);
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    scanner_winsock_cleanup();
    return 0;
}
