#include <gtk/gtk.h>
#include <glib.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scanner.h"

enum {
    COL_PORT = 0,
    COL_STATUS,
    COL_SERVICE,
    COL_BANNER,
    COL_COLOR,
    N_COLS
};

typedef struct {
    GtkWidget *window;
    GtkWidget *host_entry;
    GtkWidget *ports_entry;
    GtkWidget *threads_spin;
    GtkWidget *timeout_spin;
    GtkWidget *banner_check;
    GtkWidget *all_check;
    GtkWidget *scan_button;
    GtkWidget *stop_button;
    GtkWidget *status_label;
    GtkWidget *progress_bar;
    GtkListStore *store;

    size_t total_ports;
    size_t completed_ports;
    int open_count;
    int closed_count;
    int filtered_count;

    struct ScanJob *job;
} AppWidgets;

typedef struct ScanJob {
    AppWidgets *app;
    scan_config_t cfg;
    volatile sig_atomic_t cancel;
    gboolean show_all;
    gboolean resolve_failed;
    double elapsed;
    GThread *thread;
} ScanJob;

typedef struct {
    ScanJob *job;
    port_result_t result;
} ResultMsg;

static void show_error(AppWidgets *app, const char *msg) {
    GtkWidget *dialog = gtk_message_dialog_new(
        GTK_WINDOW(app->window), GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR,
        GTK_BUTTONS_OK, "%s", msg);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

static gboolean apply_result_idle(gpointer data) {
    ResultMsg *msg = data;
    ScanJob *job = msg->job;
    AppWidgets *app = job->app;

    app->completed_ports++;
    switch (msg->result.status) {
        case PORT_OPEN: app->open_count++; break;
        case PORT_CLOSED: app->closed_count++; break;
        default: app->filtered_count++; break;
    }

    if (job->show_all || msg->result.status == PORT_OPEN) {
        const char *color;
        switch (msg->result.status) {
            case PORT_OPEN: color = "#2e7d32"; break;
            case PORT_CLOSED: color = "#9e9e9e"; break;
            default: color = "#ef6c00"; break;
        }
        GtkTreeIter iter;
        gtk_list_store_append(app->store, &iter);
        gtk_list_store_set(app->store, &iter,
            COL_PORT, msg->result.port,
            COL_STATUS, status_to_str(msg->result.status),
            COL_SERVICE, msg->result.service[0] ? msg->result.service : "-",
            COL_BANNER, msg->result.banner,
            COL_COLOR, color,
            -1);
    }

    double frac = app->total_ports
        ? (double)app->completed_ports / (double)app->total_ports
        : 1.0;
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress_bar), frac);

    char status_text[160];
    snprintf(status_text, sizeof(status_text),
             "Escaneando... %zu/%zu portas (%d aberta(s))",
             app->completed_ports, app->total_ports, app->open_count);
    gtk_label_set_text(GTK_LABEL(app->status_label), status_text);

    g_free(msg);
    return G_SOURCE_REMOVE;
}

static void on_port_result(const port_result_t *result, void *ctx) {
    ScanJob *job = ctx;
    ResultMsg *msg = g_new(ResultMsg, 1);
    msg->job = job;
    msg->result = *result;
    g_idle_add(apply_result_idle, msg);
}

static gboolean scan_finished_idle(gpointer data) {
    ScanJob *job = data;
    AppWidgets *app = job->app;

    g_thread_join(job->thread);

    if (job->resolve_failed) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Nao foi possivel resolver o host '%s'.",
                 job->cfg.host);
        show_error(app, msg);
        gtk_label_set_text(GTK_LABEL(app->status_label), "Falha ao resolver host.");
    } else {
        char status_text[192];
        snprintf(status_text, sizeof(status_text),
                 "%s: %d aberta(s), %d fechada(s), %d filtrada(s) em %.2fs",
                 job->cancel ? "Interrompido" : "Concluido",
                 app->open_count, app->closed_count, app->filtered_count,
                 job->elapsed);
        gtk_label_set_text(GTK_LABEL(app->status_label), status_text);
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress_bar), 1.0);
    }

    gtk_widget_set_sensitive(app->scan_button, TRUE);
    gtk_widget_set_sensitive(app->stop_button, FALSE);

    free(job->cfg.ports);
    g_free(job->cfg.results);
    g_free((gpointer)job->cfg.host);
    app->job = NULL;
    g_free(job);
    return G_SOURCE_REMOVE;
}

static gpointer scan_thread_func(gpointer data) {
    ScanJob *job = data;
    GTimer *timer = g_timer_new();

    if (scanner_resolve_host(&job->cfg) != 0) {
        job->resolve_failed = TRUE;
    } else {
        job->cfg.results = g_new0(port_result_t, job->cfg.port_count);
        job->cfg.cancel_flag = &job->cancel;
        job->cfg.on_result = on_port_result;
        job->cfg.on_result_ctx = job;
        run_scan(&job->cfg);
    }

    job->elapsed = g_timer_elapsed(timer, NULL);
    g_timer_destroy(timer);

    g_idle_add(scan_finished_idle, job);
    return NULL;
}

static void on_scan_clicked(GtkButton *button, gpointer data) {
    (void)button;
    AppWidgets *app = data;
    if (app->job) return;

    const char *host = gtk_entry_get_text(GTK_ENTRY(app->host_entry));
    const char *ports_spec = gtk_entry_get_text(GTK_ENTRY(app->ports_entry));

    if (host[0] == '\0') {
        show_error(app, "Informe um host.");
        return;
    }

    int *ports = NULL;
    size_t port_count = 0;
    if (parse_port_spec(ports_spec, &ports, &port_count) != 0) {
        show_error(app, "Especificacao de portas invalida (ex: 22,80,1000-2000).");
        return;
    }

    gtk_list_store_clear(app->store);
    app->total_ports = port_count;
    app->completed_ports = 0;
    app->open_count = app->closed_count = app->filtered_count = 0;
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress_bar), 0.0);
    gtk_label_set_text(GTK_LABEL(app->status_label), "Resolvendo host...");

    ScanJob *job = g_new0(ScanJob, 1);
    job->app = app;
    job->cfg.host = g_strdup(host);
    job->cfg.ports = ports;
    job->cfg.port_count = port_count;
    job->cfg.timeout_ms = (int)gtk_spin_button_get_value(GTK_SPIN_BUTTON(app->timeout_spin));
    job->cfg.thread_count = (int)gtk_spin_button_get_value(GTK_SPIN_BUTTON(app->threads_spin));
    job->cfg.grab_banner = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->banner_check));
    job->show_all = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(app->all_check));

    app->job = job;
    gtk_widget_set_sensitive(app->scan_button, FALSE);
    gtk_widget_set_sensitive(app->stop_button, TRUE);

    job->thread = g_thread_new("scan-worker", scan_thread_func, job);
}

static void on_stop_clicked(GtkButton *button, gpointer data) {
    (void)button;
    AppWidgets *app = data;
    if (app->job) {
        app->job->cancel = 1;
        gtk_widget_set_sensitive(app->stop_button, FALSE);
    }
}

static void add_column(GtkWidget *tree_view, const char *title, int col_id) {
    GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *column = gtk_tree_view_column_new_with_attributes(
        title, renderer, "text", col_id, "foreground", COL_COLOR, NULL);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_column_set_sort_column_id(column, col_id);
    gtk_tree_view_append_column(GTK_TREE_VIEW(tree_view), column);
}

static void activate(GtkApplication *gtk_app, gpointer user_data) {
    AppWidgets *app = user_data;

    app->window = gtk_application_window_new(gtk_app);
    gtk_window_set_title(GTK_WINDOW(app->window), "Port Scanner");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 760, 540);
    gtk_container_set_border_width(GTK_CONTAINER(app->window), 12);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(app->window), vbox);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);
    gtk_box_pack_start(GTK_BOX(vbox), grid, FALSE, FALSE, 0);

    GtkWidget *host_label = gtk_label_new("Host:");
    gtk_widget_set_halign(host_label, GTK_ALIGN_START);
    app->host_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(app->host_entry), "127.0.0.1");
    gtk_widget_set_hexpand(app->host_entry, TRUE);
    gtk_grid_attach(GTK_GRID(grid), host_label, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), app->host_entry, 1, 0, 3, 1);

    GtkWidget *ports_label = gtk_label_new("Portas:");
    gtk_widget_set_halign(ports_label, GTK_ALIGN_START);
    app->ports_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(app->ports_entry), "1-1024");
    gtk_grid_attach(GTK_GRID(grid), ports_label, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), app->ports_entry, 1, 1, 3, 1);

    GtkWidget *threads_label = gtk_label_new("Threads:");
    gtk_widget_set_halign(threads_label, GTK_ALIGN_START);
    app->threads_spin = gtk_spin_button_new_with_range(1, 1000, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(app->threads_spin), 100);
    gtk_grid_attach(GTK_GRID(grid), threads_label, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), app->threads_spin, 1, 2, 1, 1);

    GtkWidget *timeout_label = gtk_label_new("Timeout (ms):");
    gtk_widget_set_halign(timeout_label, GTK_ALIGN_START);
    app->timeout_spin = gtk_spin_button_new_with_range(50, 10000, 50);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(app->timeout_spin), 500);
    gtk_grid_attach(GTK_GRID(grid), timeout_label, 2, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), app->timeout_spin, 3, 2, 1, 1);

    app->banner_check = gtk_check_button_new_with_label("Capturar banner");
    gtk_grid_attach(GTK_GRID(grid), app->banner_check, 0, 3, 2, 1);

    app->all_check = gtk_check_button_new_with_label("Mostrar todas as portas");
    gtk_grid_attach(GTK_GRID(grid), app->all_check, 2, 3, 2, 1);

    GtkWidget *button_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    app->scan_button = gtk_button_new_with_label("Escanear");
    app->stop_button = gtk_button_new_with_label("Parar");
    gtk_widget_set_sensitive(app->stop_button, FALSE);
    gtk_box_pack_start(GTK_BOX(button_box), app->scan_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(button_box), app->stop_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), button_box, FALSE, FALSE, 0);

    app->progress_bar = gtk_progress_bar_new();
    gtk_box_pack_start(GTK_BOX(vbox), app->progress_bar, FALSE, FALSE, 0);

    app->status_label = gtk_label_new("Pronto.");
    gtk_widget_set_halign(app->status_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), app->status_label, FALSE, FALSE, 0);

    app->store = gtk_list_store_new(N_COLS, G_TYPE_INT, G_TYPE_STRING,
                                     G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    GtkWidget *tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(app->store));
    g_object_unref(app->store);

    add_column(tree_view, "Porta", COL_PORT);
    add_column(tree_view, "Status", COL_STATUS);
    add_column(tree_view, "Servico", COL_SERVICE);
    add_column(tree_view, "Banner", COL_BANNER);
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(app->store),
                                          COL_PORT, GTK_SORT_ASCENDING);

    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(scroll), tree_view);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    g_signal_connect(app->scan_button, "clicked", G_CALLBACK(on_scan_clicked), app);
    g_signal_connect(app->stop_button, "clicked", G_CALLBACK(on_stop_clicked), app);

    gtk_widget_show_all(app->window);
}

int main(int argc, char **argv) {
    AppWidgets app;
    memset(&app, 0, sizeof(app));

#if GLIB_CHECK_VERSION(2, 74, 0)
    GtkApplication *gtk_app = gtk_application_new("dev.portscanner.gui",
                                                    G_APPLICATION_DEFAULT_FLAGS);
#else
    GtkApplication *gtk_app = gtk_application_new("dev.portscanner.gui",
                                                    G_APPLICATION_FLAGS_NONE);
#endif
    g_signal_connect(gtk_app, "activate", G_CALLBACK(activate), &app);
    int status = g_application_run(G_APPLICATION(gtk_app), argc, argv);
    g_object_unref(gtk_app);
    return status;
}
