import math
import tkinter as tk
from config import T, FONT_BOLD, FONT_MONO, FONT_SMALL, FONT_TINY, _glow_color
from engine import PORT_SERVICES


class GraphCanvas(tk.Canvas):
    def __init__(self, master, **kw):
        super().__init__(master, bg=T["surface"], highlightthickness=0, **kw)
        self._report = None
        self._after_id = None
        self._zoom = 1.0
        self._pan_x = 0
        self._pan_y = 0
        self._drag_start_x = 0
        self._drag_start_y = 0
        self._drag_pan_x = 0
        self._drag_pan_y = 0
        self._dragging = False
        self._last_drawn_zoom = None
        self._last_drawn_pan = (None, None)
        self.bind("<Configure>", self._on_resize)
        self.bind("<MouseWheel>", self._on_wheel)
        self.bind("<Button-4>", self._on_wheel_down)
        self.bind("<Button-5>", self._on_wheel_down)
        self.bind("<ButtonPress-1>", self._on_drag_start)
        self.bind("<B1-Motion>", self._on_drag_move)
        self.bind("<ButtonRelease-1>", self._on_drag_end)
        self.bind("<ButtonPress-3>", self._on_reset_view)
        self.bind("<Double-Button-1>", self._on_reset_view)

    def draw_graph(self, report):
        self._report = report
        self._zoom = 1.0
        self._pan_x = 0
        self._pan_y = 0
        self._last_drawn_zoom = None
        self._last_drawn_pan = (None, None)
        if self._after_id is not None:
            self.after_cancel(self._after_id)
        self._after_id = self.after(30, self._do_redraw)

    def _on_resize(self, event):
        if self._report:
            self._schedule_redraw(resize=True)

    def _on_wheel(self, event):
        if event.delta > 0 or event.num == 4:
            self._zoom = min(5.0, self._zoom * 1.12)
        elif event.delta < 0 or event.num == 5:
            self._zoom = max(0.2, self._zoom / 1.12)
        self._schedule_redraw(wheel=True)

    def _on_wheel_down(self, event):
        if event.num == 4:
            self._zoom = min(5.0, self._zoom * 1.12)
        elif event.num == 5:
            self._zoom = max(0.2, self._zoom / 1.12)
        self._schedule_redraw(wheel=True)

    def _on_drag_start(self, event):
        self._drag_start_x = event.x
        self._drag_start_y = event.y
        self._drag_pan_x = self._pan_x
        self._drag_pan_y = self._pan_y
        self._dragging = True
        self.configure(cursor="fleur")

    def _on_drag_move(self, event):
        dx = event.x - self._drag_start_x
        dy = event.y - self._drag_start_y
        self._pan_x = self._drag_pan_x + dx
        self._pan_y = self._drag_pan_y + dy
        if self._last_drawn_pan != (None, None) and self._last_drawn_zoom == self._zoom:
            old_px, old_py = self._last_drawn_pan
            delta_x = self._pan_x - old_px
            delta_y = self._pan_y - old_py
            if abs(delta_x) >= 1 or abs(delta_y) >= 1:
                self.move("graph", delta_x, delta_y)
                self._last_drawn_pan = (self._pan_x, self._pan_y)
                return
        self._schedule_redraw(drag=True)

    def _on_drag_end(self, event):
        self._dragging = False
        self.configure(cursor="")
        if self._report:
            self._schedule_redraw()

    def _on_reset_view(self, event):
        self._zoom = 1.0
        self._pan_x = 0
        self._pan_y = 0
        self._dragging = False
        self.configure(cursor="")
        self._schedule_redraw()

    def _schedule_redraw(self, drag=False, wheel=False, resize=False):
        if self._after_id is not None:
            self.after_cancel(self._after_id)
        if resize:
            delay = 100
        elif drag:
            delay = 40
        elif wheel:
            delay = 30
        else:
            delay = 50
        self._after_id = self.after(delay, self._do_redraw)

    def _tx(self, x):
        return x * self._zoom + self._pan_x

    def _ty(self, y):
        return y * self._zoom + self._pan_y

    def _tr(self, r):
        return r * self._zoom

    def _do_redraw(self):
        self._after_id = None
        report = self._report
        if not report:
            self.delete("all")
            return
        w = self.winfo_width()
        h = self.winfo_height()
        if w < 50 or h < 50:
            return

        cx, cy = w // 2, h // 2
        z = self._zoom

        self.delete("graph")
        self._last_drawn_zoom = z
        self._last_drawn_pan = (self._pan_x, self._pan_y)

        margin = 60
        view_left = -margin
        view_right = w + margin
        view_top = -margin
        view_bottom = h + margin

        def _visible(x, y):
            return view_left <= x <= view_right and view_top <= y <= view_bottom

        zoom_pct = int(z * 100)
        self.create_text(w - 10, 14, text=f"{zoom_pct}%", fill=T["fg4"],
            font=FONT_TINY, anchor="e", tags="graph")

        if z == 1.0 and self._pan_x == 0 and self._pan_y == 0:
            self.create_text(w - 10, h - 14, text="Scroll: zoom  |  Drag: pan  |  Double-click: reset",
                fill=T["fg4"], font=FONT_TINY, anchor="e", tags="graph")

        self.create_text(self._tx(cx), self._ty(16), text=f"Topology - {report.host}",
            fill=T["blue"], font=FONT_BOLD, tags="graph")
        self.create_text(self._tx(cx), self._ty(32), text=f"IP: {report.ip or 'n/a'}",
            fill=T["fg4"], font=FONT_SMALL, tags="graph")

        main_r = self._tr(28)
        tcx, tcy = self._tx(cx), self._ty(cy)
        self._draw_hub(tcx, tcy, main_r, report.host, T["blue"])

        subs = report.subdomains[:15]
        if subs:
            sub_r = min(w, h) * 0.30
            n = len(subs)
            for i, sub in enumerate(subs):
                angle = i * (2 * math.pi / n) - math.pi / 2
                sx = self._tx(cx + sub_r * math.cos(angle))
                sy = self._ty(cy + sub_r * math.sin(angle))
                if not _visible(sx, sy):
                    continue
                short = sub.replace("." + report.host, "") if report.host in sub else sub
                if len(short) > 15:
                    short = short[:14] + ".."
                leaf_r = self._tr(14)
                self._draw_leaf(sx, sy, leaf_r, short, T["cyan"])
                self._draw_conn(tcx, tcy, main_r, sx, sy, leaf_r, T["cyan"])

        ports = report.open_ports[:12]
        if ports:
            port_ring = min(w, h) * 0.44
            port_start = math.pi * 0.6
            port_spread = math.pi * 0.8
            n = max(len(ports) - 1, 1)
            for i, p in enumerate(ports):
                angle = port_start + (i / n) * port_spread
                px = self._tx(cx + port_ring * math.cos(angle))
                py = self._ty(cy + port_ring * math.sin(angle) + 20)
                if not _visible(px, py):
                    continue
                svc = PORT_SERVICES.get(p, "?")
                leaf_r = self._tr(12)
                self._draw_leaf(px, py, leaf_r, str(p), T["orange"])
                self._draw_conn(tcx, tcy, main_r, px, py, leaf_r, T["orange"])
                self.create_text(px, py + self._tr(18), text=svc, fill=T["fg4"],
                    font=FONT_TINY, tags="graph")

        if report.critical_paths:
            crit_ring = min(w, h) * 0.46
            crit_start = -math.pi * 0.3
            crits = report.critical_paths[:5]
            n = max(len(crits) - 1, 1)
            for i, cp in enumerate(crits):
                angle = crit_start + (i / n) * 0.4
                raw_x = cx + crit_ring * math.cos(angle)
                raw_y = cy - crit_ring * 0.6 + crit_ring * math.sin(angle) * 0.3
                crx = self._tx(raw_x)
                cry = self._ty(raw_y)
                if not _visible(crx, cry):
                    continue
                name = cp.split("/")[-1][:10] or cp[:10]
                leaf_r = self._tr(11)
                self._draw_leaf(crx, cry, leaf_r, name, T["red"])
                self._draw_conn(tcx, tcy, main_r, crx, cry, leaf_r, T["red"])

        # ── Plugin-contributed nodes ──
        plugin_nodes = getattr(report, 'plugin_graph_nodes', [])
        if plugin_nodes:
            plugin_ring = min(w, h) * 0.52
            n = max(len(plugin_nodes) - 1, 1)
            for i, node in enumerate(plugin_nodes):
                angle = -math.pi * 0.8 + (i / n) * 0.5
                raw_x = cx + plugin_ring * math.cos(angle)
                raw_y = cy + plugin_ring * 0.5 + plugin_ring * math.sin(angle) * 0.3
                px = self._tx(raw_x)
                py = self._ty(raw_y)
                if not _visible(px, py):
                    continue
                color = node.get("color", T.get("purple", "#a855f7"))
                name = node.get("label", "?")[:12]
                leaf_r = self._tr(10)
                self._draw_leaf(px, py, leaf_r, name, color)
                self._draw_conn(tcx, tcy, main_r, px, py, leaf_r, color)

        if not subs and not ports and not report.critical_paths and not plugin_nodes:
            self.create_text(tcx, tcy, text="No data found",
                fill=T["fg4"], font=FONT_SMALL, tags="graph")

        ly = h - 18
        lx = 20
        for color, label in [(T["blue"], "Host"), (T["cyan"], "Subdomains"),
                              (T["orange"], "Ports"), (T["red"], "Critical"),
                              (T.get("purple", "#a855f7"), "Plugins")]:
            self.create_oval(lx, ly - 4, lx + 8, ly + 4, fill=color, outline="", tags="graph")
            self.create_text(lx + 12, ly, text=label, fill=T["fg4"], font=FONT_TINY, anchor="w", tags="graph")
            lx += len(label) * 6 + 28

    def _draw_hub(self, x, y, r, text, color):
        for i in range(2):
            self.create_oval(x - r - i * self._tr(4), y - r - i * self._tr(4),
                x + r + i * self._tr(4), y + r + i * self._tr(4),
                outline=_glow_color(T["purple"], 3 - i), width=1, tags="graph")
        self.create_oval(x - r, y - r, x + r, y + r, fill=T["bg"], outline=color, width=3, tags="graph")
        self.create_text(x, y, text=text, fill=T["fg"], font=FONT_MONO, tags="graph")

    def _draw_leaf(self, x, y, r, text, color):
        self.create_oval(x - r, y - r, x + r, y + r, fill=T["bg"], outline=color, width=2, tags="graph")
        self.create_text(x, y, text=text, fill=T["fg"], font=FONT_TINY, tags="graph")

    def _draw_conn(self, x1, y1, r1, x2, y2, r2, color):
        dx = x2 - x1
        dy = y2 - y1
        dist = max(1, math.sqrt(dx * dx + dy * dy))
        nx, ny = dx / dist, dy / dist
        self.create_line(x1 + nx * r1, y1 + ny * r1, x2 - nx * r2, y2 - ny * r2,
            fill=color, width=1, dash=(3, 3), tags="graph")
