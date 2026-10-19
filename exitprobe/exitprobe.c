// exitprobe - minimal repro for the Petrel "Exit" crash.
//
// Same shape as Petrel's exit path: a custom View on a fullscreen ViewDispatcher whose
// input callback stops the dispatcher, then the app returns. Deliberately does NOT touch
// the expansion, OTG, the UART or any module view, so if THIS crashes on OK we have an
// isolated repro; if it doesn't, petrel's extra setup/teardown is the trigger.
#include <furi.h>
#include <gui/gui.h>
#include <gui/view.h>
#include <gui/view_dispatcher.h>

typedef struct {
    Gui* gui;
    ViewDispatcher* vd;
    View* view;
} ExitProbe;

static void exitprobe_draw(Canvas* canvas, void* model) {
    UNUSED(model);
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 16, AlignCenter, AlignTop, "ExitProbe");
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignTop, "OK = stop & exit");
}

static bool exitprobe_input(InputEvent* event, void* context) {
    ExitProbe* p = context;
    if(event->type == InputTypeShort && event->key == InputKeyOk) {
        view_dispatcher_stop(p->vd); // same call Petrel makes on Exit
        return true;
    }
    return false;
}

int32_t exitprobe_app(void* p) {
    UNUSED(p);
    ExitProbe app = {0};
    app.gui = furi_record_open(RECORD_GUI);
    app.vd = view_dispatcher_alloc();
    app.view = view_alloc();
    view_set_context(app.view, &app);
    view_set_draw_callback(app.view, exitprobe_draw);
    view_set_input_callback(app.view, exitprobe_input);
    view_dispatcher_add_view(app.vd, 0, app.view);
    view_dispatcher_attach_to_gui(app.vd, app.gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_switch_to_view(app.vd, 0);
    view_dispatcher_run(app.vd);
    view_dispatcher_remove_view(app.vd, 0);
    view_dispatcher_free(app.vd);
    view_free(app.view);
    furi_record_close(RECORD_GUI);
    return 0;
}
