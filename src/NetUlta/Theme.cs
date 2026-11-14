using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace NetUlta;

static class Theme
{
    public static Color Background => SystemInformation.HighContrast ? SystemColors.Window : Color.FromArgb(16, 17, 20);
    public static Color Surface => SystemInformation.HighContrast ? SystemColors.Control : Color.FromArgb(26, 28, 33);
    public static Color Sidebar => SystemInformation.HighContrast ? SystemColors.Control : Color.FromArgb(10, 11, 13);
    public static Color Text => SystemInformation.HighContrast ? SystemColors.WindowText : Color.FromArgb(243, 243, 245);
    public static Color Muted => SystemInformation.HighContrast ? SystemColors.WindowText : Color.FromArgb(160, 165, 177);
    public static Color Accent => SystemInformation.HighContrast ? SystemColors.Highlight : Color.FromArgb(255, 166, 77);
    public static Color Line => SystemInformation.HighContrast ? SystemColors.WindowText : Color.FromArgb(51, 54, 63);
    public static Color Success => SystemInformation.HighContrast ? SystemColors.Highlight : Color.FromArgb(124, 220, 174);

    public static void Apply(Control control)
    {
        control.ForeColor = control is Label && control.ForeColor == Muted ? Muted : Text;
        control.BackColor = control is TextBoxBase or ComboBox or NumericUpDown ? Surface : Background;
        if (control is Button button)
        {
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderColor = Line;
            button.FlatAppearance.MouseOverBackColor = Surface;
            button.BackColor = Surface;
            button.Padding = new Padding(9, 4, 9, 4);
            button.Cursor = Cursors.Hand;
        }
        if (control is TextBox text) text.BorderStyle = BorderStyle.FixedSingle;
        if (control is ComboBox combo) combo.FlatStyle = FlatStyle.Flat;
        if (control is LinkLabel link) { link.LinkColor = Accent; link.ActiveLinkColor = Text; link.VisitedLinkColor = Accent; }
        foreach (Control child in control.Controls) Apply(child);
        if (control is Form form)
        {
            form.HandleCreated += (_, _) => DarkTitle(form);
            if (form.IsHandleCreated) DarkTitle(form);
        }
    }
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
    static void DarkTitle(Form form)
    {
        if (SystemInformation.HighContrast) return;
        int enabled = 1;
        try { DwmSetWindowAttribute(form.Handle, 20, ref enabled, sizeof(int)); }
        catch (DllNotFoundException) { }
    }
    public static ToolTip Tips()
    {
        var tip = new ToolTip { InitialDelay = 400, ReshowDelay = 150, AutoPopDelay = 16000, ShowAlways = true, OwnerDraw = true };
        tip.Popup += (_, e) =>
        {
            var size = TextRenderer.MeasureText(tip.GetToolTip(e.AssociatedControl), SystemFonts.MessageBoxFont,
                new Size(420, 0), TextFormatFlags.WordBreak | TextFormatFlags.NoPrefix);
            e.ToolTipSize = new Size(size.Width + 24, size.Height + 20);
        };
        tip.Draw += (_, e) =>
        {
            using var brush = new SolidBrush(Surface); e.Graphics.FillRectangle(brush, e.Bounds);
            using var border = new Pen(Line); e.Graphics.DrawRectangle(border, 0, 0, e.Bounds.Width - 1, e.Bounds.Height - 1);
            TextRenderer.DrawText(e.Graphics, e.ToolTipText, SystemFonts.MessageBoxFont,
                new Rectangle(12, 10, e.Bounds.Width - 24, e.Bounds.Height - 20), Text,
                TextFormatFlags.WordBreak | TextFormatFlags.NoPrefix);
        };
        return tip;
    }
    public static void Tabs(TabControl tabs)
    {
        tabs.ShowToolTips = true;
        tabs.DrawMode = TabDrawMode.OwnerDrawFixed;
        tabs.Padding = new Point(14, 9);
        tabs.DrawItem += (_, e) =>
        {
            var page = tabs.TabPages[e.Index];
            using var brush = new SolidBrush(e.Index == tabs.SelectedIndex ? Surface : Background);
            e.Graphics.FillRectangle(brush, e.Bounds);
            TextRenderer.DrawText(e.Graphics, page.Text, tabs.Font, e.Bounds,
                e.Index == tabs.SelectedIndex ? Accent : Muted, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        };
    }
}

sealed class DarkTabControl : TabControl
{
    protected override void WndProc(ref Message m)
    {
        base.WndProc(ref m);
        if (m.Msg != 0x000F || SystemInformation.HighContrast || TabCount == 0) return;
        using var g = Graphics.FromHwnd(Handle);
        using var background = new SolidBrush(Theme.Background);
        var last = GetTabRect(TabCount - 1);
        if (last.Right < ClientSize.Width)
            g.FillRectangle(background, last.Right + 1, 0, ClientSize.Width - last.Right, last.Bottom + 1);
        var content = DisplayRectangle;
        g.FillRectangle(background, 0, content.Top, content.Left, Height - content.Top);
        g.FillRectangle(background, content.Right, content.Top, Width - content.Right, Height - content.Top);
        g.FillRectangle(background, 0, content.Bottom, Width, Height - content.Bottom);
        using var edge = new Pen(Theme.Line);
        g.DrawLine(edge, 0, content.Top - 1, Width, content.Top - 1);
    }
}

sealed class ConnectButton : Button
{
    public bool Active { get; set; }
    public bool Waiting { get; set; }
    public ConnectButton()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
        Size = new Size(244, 244);
        FlatStyle = FlatStyle.Flat;
        FlatAppearance.BorderSize = 0;
        Cursor = Cursors.Hand;
        AccessibleName = "Подключить сервер";
        Font = new Font("Segoe UI Semibold", 13);
    }
    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.Clear(Theme.Background);
        var bounds = new Rectangle(22, 22, Width - 44, Height - 44);
        var color = Enabled ? (Active ? Theme.Success : Theme.Accent) : Theme.Muted;
        if (!SystemInformation.HighContrast)
            for (int i = 16; i >= 2; i -= 2)
            {
                using var glow = new Pen(Color.FromArgb(8 + (16 - i), color), i);
                g.DrawEllipse(glow, bounds);
            }
        using (var pen = new Pen(color, 3)) g.DrawEllipse(pen, bounds);
        using (var power = new Pen(color, 3) { StartCap = LineCap.Round, EndCap = LineCap.Round })
        {
            var icon = new Rectangle(Width / 2 - 16, Height / 2 - 45, 32, 32);
            g.DrawArc(power, icon, -48, 276);
            g.DrawLine(power, Width / 2, icon.Y - 5, Width / 2, icon.Y + 15);
        }
        TextRenderer.DrawText(g, Text, Font, new Rectangle(18, Height / 2 + 5, Width - 36, 43),
            Enabled ? Theme.Text : Theme.Muted, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        using var captionFont = new Font("Segoe UI", 9);
        TextRenderer.DrawText(g, Waiting ? "идёт подключение" : Active ? "мост работает" : "к своему серверу", captionFont,
            new Rectangle(18, Height / 2 + 49, Width - 36, 22), Theme.Muted, TextFormatFlags.HorizontalCenter);
        if (Focused && ShowFocusCues) ControlPaint.DrawFocusRectangle(g, new Rectangle(12, 12, Width - 24, Height - 24), Theme.Accent, Theme.Background);
    }
}
