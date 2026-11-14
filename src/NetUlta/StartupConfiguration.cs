namespace NetUlta;

static class StartupConfiguration
{
    public static void UseManualStart(ProfileStore store, Action<bool> register)
    {
        var next = store.Load().Select(p => p with
        {
            AutoConnect = false, StartWithWindows = false, AmneziaServerIndex = null
        }).ToArray();
        store.Save(next, () => register(false));
    }

    public static void Configure(ProfileStore store, Guid id, int amneziaIndex, Action<bool> register)
    {
        if (amneziaIndex is < 0 or > 999) throw new UserFault("Неверный номер сервера AmneziaVPN.");
        var previous = store.Load();
        var selected = previous.SingleOrDefault(p => p.Id == id)
            ?? throw new UserFault("Профиль для автозапуска не найден.");
        Model.Validate(selected);
        var next = previous.Select(p => p.Id == id
            ? p with { AutoConnect = true, StartWithWindows = true, AmneziaServerIndex = amneziaIndex }
            : p with { AutoConnect = false, StartWithWindows = false }).ToArray();
        store.Save(next, () => register(true));
    }
}
