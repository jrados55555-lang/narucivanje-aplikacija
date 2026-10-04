using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();

// Render je "proxy" ispred aplikacije, pa ovako dobivamo pravu IP adresu posjetitelja
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownNetworks.Clear();
    o.KnownProxies.Clear();
});

// Zaštita od spama: najviše 10 pokušaja rezervacije u 10 minuta po IP adresi
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("rezervacije", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "nepoznato",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 10,
            Window = TimeSpan.FromMinutes(10)
        }));

    // Zaštita od pogađanja lozinke: najviše 8 pokušaja prijave u 10 minuta po IP adresi
    o.AddPolicy("prijava", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "nepoznato",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 8,
            Window = TimeSpan.FromMinutes(10)
        }));
});

var app = builder.Build();
app.UseForwardedHeaders();

// ===== POSTAVKE (sve se mijenja preko Environment varijabli na hostingu, bez diranja koda) =====
var dbPath = Env("DB_PATH", "raspored.db");
var connStr = $"Data Source={dbPath}";
var adminLozinka = Environment.GetEnvironmentVariable("ADMIN_PASSWORD");

var salonNaziv = Env("SALON_NAZIV", "Rezervacija termina");
var salonTelefon = Env("SALON_TELEFON", "");
var boja = Boja(Env("BOJA", "#d32f2f"), "#d32f2f");
var pozadina = Boja(Env("POZADINA", "#363435"), "#363435");
var logo = Env("LOGO_URL", "/logo.png");
// Telegram obavijesti (neobavezno): ako nisu postavljene, jednostavno se ne šalju
var telegramToken = Env("TELEGRAM_TOKEN", "");
var telegramChatId = Env("TELEGRAM_CHAT_ID", "");
var korakMin = int.TryParse(Env("KORAK_MIN", "30"), out var k) ? k : 30;
var radnoVrijeme = GenerirajTermine(Env("RADNO_OD", "11:00"), Env("RADNO_DO", "20:00"), korakMin);
var trajanjeMin = (korakMin < 5 || korakMin > 240) ? 30 : korakMin;
// Cjenik: stavke odvojene točkom-zarezom, oblik "Naziv=Cijena" (npr. Šišanje=20 €;Brijanje brade=10 €)
var cjenik = ParsirajCjenik(Env("CJENIK", "Šišanje=20 €"));

// Zaštita admina: admin stranica, popis svih rezervacija i brisanje traže lozinku
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value?.ToLowerInvariant() ?? "";
    var method = ctx.Request.Method;

    bool zasticeno =
        path.StartsWith("/admin") ||
        path.StartsWith("/api/admin") ||
        (path == "/api/rezervacije" && method == "GET") ||
        (path.StartsWith("/api/rezervacije/") && method == "DELETE");

    if (zasticeno && !ProvjeriAdmina(ctx, adminLozinka))
    {
        if (path.StartsWith("/admin"))
            ctx.Response.Redirect("/prijava.html");   // admin stranica: na prijavu
        else
            ctx.Response.StatusCode = 401;            // API pozivi: greška 401
        return;
    }
    await next();
});

app.UseRateLimiter();
app.UseDefaultFiles();
app.UseStaticFiles();

// Inicijalizacija SQLite baze
Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(dbPath))!);
using (var connection = new SqliteConnection(connStr))
{
    connection.Open();

    var command = connection.CreateCommand();
    command.CommandText = @"
        CREATE TABLE IF NOT EXISTS Rezervacije (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Ime TEXT NOT NULL,
            Datum TEXT NOT NULL,
            Vrijeme TEXT NOT NULL,
            Telefon TEXT NOT NULL DEFAULT ''
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_termin ON Rezervacije(Datum, Vrijeme);

        -- Blokade: Vrijeme = '' znači da je blokiran cijeli dan
        CREATE TABLE IF NOT EXISTS Blokade (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Datum TEXT NOT NULL,
            Vrijeme TEXT NOT NULL DEFAULT ''
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_blokada ON Blokade(Datum, Vrijeme);";
    command.ExecuteNonQuery();

    // Ako je baza nastala u starijoj verziji (bez telefona), dodaj stupac Telefon
    bool imaTelefon = false;
    var info = connection.CreateCommand();
    info.CommandText = "PRAGMA table_info(Rezervacije)";
    using (var r = info.ExecuteReader())
    {
        while (r.Read())
        {
            if (r.GetString(1) == "Telefon") imaTelefon = true;
        }
    }
    if (!imaTelefon)
    {
        var alter = connection.CreateCommand();
        alter.CommandText = "ALTER TABLE Rezervacije ADD COLUMN Telefon TEXT NOT NULL DEFAULT ''";
        alter.ExecuteNonQuery();
    }
}

// JAVNO: prijava admina (lozinka se šalje jednom, a server postavi kolačić koji vrijedi 60 dana)
app.MapPost("/api/prijava", (PrijavaDto dto, HttpContext ctx) =>
{
    if (string.IsNullOrEmpty(adminLozinka))
        return Results.Problem("Lozinka admina nije postavljena na serveru.", statusCode: 503);

    var uneseno = Encoding.UTF8.GetBytes(dto.Lozinka ?? "");
    var ocekivano = Encoding.UTF8.GetBytes(adminLozinka);
    if (!CryptographicOperations.FixedTimeEquals(uneseno, ocekivano))
        return Results.Unauthorized();

    var istek = DateTimeOffset.UtcNow.AddDays(60);
    ctx.Response.Cookies.Append("admin_sesija", NapraviToken(adminLozinka, istek), new CookieOptions
    {
        HttpOnly = true,
        Secure = ctx.Request.IsHttps,
        SameSite = SameSiteMode.Lax,
        Expires = istek,
        Path = "/"
    });
    return Results.Ok();
}).RequireRateLimiting("prijava");

// Odjava admina
app.MapPost("/api/odjava", (HttpContext ctx) =>
{
    ctx.Response.Cookies.Delete("admin_sesija");
    return Results.Ok();
});

// PWA: opis aplikacije za instalaciju admina na početni zaslon mobitela
app.MapGet("/manifest.webmanifest", () => Results.Json(new
{
    id = "/admin.html",
    name = salonNaziv + " - Admin",
    short_name = "Admin",
    start_url = "/admin.html",
    scope = "/",
    display = "standalone",
    background_color = pozadina,
    theme_color = pozadina,
    icons = new[]
    {
        new { src = "/icon-192.png", sizes = "192x192", type = "image/png", purpose = "any" },
        new { src = "/icon-512.png", sizes = "512x512", type = "image/png", purpose = "any" }
    }
}, contentType: "application/manifest+json"));

// PWA: minimalni service worker (potreban da se aplikacija može instalirati; ništa ne sprema)
app.MapGet("/sw.js", () => Results.Content("self.addEventListener('fetch', () => {});", "application/javascript"));

// JAVNO: kalendarski događaj (.ics) s podsjetnicima, da klijent termin doda u svoj kalendar na mobitelu
app.MapGet("/api/kalendar", (string datum, string vrijeme) =>
{
    if (!DateOnly.TryParseExact(datum, "yyyy-MM-dd", out var d) || !radnoVrijeme.Contains(vrijeme))
        return Results.BadRequest();

    var pocetak = d.ToDateTime(TimeOnly.ParseExact(vrijeme, "HH:mm"));
    var kraj = pocetak.AddMinutes(trajanjeMin);
    string F(DateTime t) => t.ToString("yyyyMMdd'T'HHmmss", CultureInfo.InvariantCulture);
    var pecat = DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);

    var ics = string.Join("\r\n", new[]
    {
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Rezervacije//HR",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        "BEGIN:VEVENT",
        $"UID:{Guid.NewGuid():N}@rezervacije",
        $"DTSTAMP:{pecat}",
        $"DTSTART:{F(pocetak)}",
        $"DTEND:{F(kraj)}",
        $"SUMMARY:{IcsTekst(salonNaziv)} - termin",
        "BEGIN:VALARM",
        "TRIGGER:-P1D",
        "ACTION:DISPLAY",
        "DESCRIPTION:Sutra imate termin",
        "END:VALARM",
        "BEGIN:VALARM",
        "TRIGGER:-PT1H",
        "ACTION:DISPLAY",
        "DESCRIPTION:Termin je za sat vremena",
        "END:VALARM",
        "END:VEVENT",
        "END:VCALENDAR",
        ""
    });
    return Results.Content(ics, "text/calendar; charset=utf-8");
});

// JAVNO: postavke salona (naziv, boje, logo, popis termina)
app.MapGet("/api/postavke", () => Results.Ok(new
{
    naziv = salonNaziv,
    telefon = salonTelefon,
    boja,
    pozadina,
    logo,
    termini = radnoVrijeme,
    cjenik
}));

// JAVNO: stanje jednog dana (bez imena i telefona): je li dan zatvoren, koja su vremena zauzeta, a koja blokirana
app.MapGet("/api/zauzeto", (string datum) =>
{
    if (!DateOnly.TryParseExact(datum, "yyyy-MM-dd", out _))
        return Results.BadRequest();

    using var connection = new SqliteConnection(connStr);
    connection.Open();
    var zatvoren = Broji(connection, null, "SELECT COUNT(*) FROM Blokade WHERE Datum = $d AND Vrijeme = ''", ("$d", datum)) > 0;
    var zauzeto = Stupac(connection, "SELECT Vrijeme FROM Rezervacije WHERE Datum = $d", ("$d", datum));
    var blokirano = Stupac(connection, "SELECT Vrijeme FROM Blokade WHERE Datum = $d AND Vrijeme <> ''", ("$d", datum));
    return Results.Ok(new { zatvoren, zauzeto, blokirano });
});

// ADMIN: popis svih rezervacija
app.MapGet("/api/rezervacije", () =>
{
    var lista = new List<object>();
    using var connection = new SqliteConnection(connStr);
    connection.Open();
    var command = connection.CreateCommand();
    command.CommandText = "SELECT Id, Ime, Datum, Vrijeme, Telefon FROM Rezervacije ORDER BY Datum ASC, Vrijeme ASC";
    using var reader = command.ExecuteReader();
    while (reader.Read())
    {
        lista.Add(new
        {
            id = reader.GetInt32(0),
            ime = reader.GetString(1),
            datum = reader.GetString(2),
            vrijeme = reader.GetString(3),
            telefon = reader.GetString(4)
        });
    }
    return Results.Ok(lista);
});

// JAVNO: nova rezervacija
app.MapPost("/api/rezervacije", async (HttpRequest request, IHttpClientFactory httpFactory) =>
{
    var form = await request.ReadFromJsonAsync<RezervacijaDto>();
    if (form == null) return Results.BadRequest();

    var ime = form.Ime?.Trim() ?? "";
    if (ime.Length == 0 || ime.Length > 100)
        return Results.BadRequest("Neispravno ime.");

    var telefon = form.Telefon?.Trim() ?? "";
    if (!Regex.IsMatch(telefon, @"^[0-9+\-\s()/]{6,20}$"))
        return Results.BadRequest("Neispravan broj telefona.");

    if (!DateOnly.TryParseExact(form.Datum, "yyyy-MM-dd", out var datum))
        return Results.BadRequest("Neispravan datum.");

    var danas = DateOnly.FromDateTime(DateTime.UtcNow.AddHours(2)); // otprilike hrvatsko vrijeme
    if (datum < danas)
        return Results.BadRequest("Datum je u prošlosti.");

    if (!radnoVrijeme.Contains(form.Vrijeme))
        return Results.BadRequest("Neispravno vrijeme.");

    try
    {
        using var connection = new SqliteConnection(connStr);
        connection.Open();

        // Provjera blokade (cijeli dan ili samo taj termin)
        if (Broji(connection, null, "SELECT COUNT(*) FROM Blokade WHERE Datum = $d AND (Vrijeme = '' OR Vrijeme = $v)",
                ("$d", form.Datum), ("$v", form.Vrijeme)) > 0)
            return Results.Conflict("Termin nije dostupan.");

        var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO Rezervacije (Ime, Datum, Vrijeme, Telefon) VALUES ($ime, $datum, $vrijeme, $telefon)";
        command.Parameters.AddWithValue("$ime", ime);
        command.Parameters.AddWithValue("$datum", form.Datum);
        command.Parameters.AddWithValue("$vrijeme", form.Vrijeme);
        command.Parameters.AddWithValue("$telefon", telefon);
        command.ExecuteNonQuery();
    }
    catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
    {
        return Results.Conflict("Termin je već zauzet.");
    }

    // Obavijest na Telegram (ne čekamo odgovor, a greška nikad ne ruši rezervaciju)
    if (telegramToken != "" && telegramChatId != "")
    {
        var tekst = $"Nova rezervacija\n{ime}\nTel: {telefon}\n{datum:dd.MM.yyyy.} u {form.Vrijeme}";
        _ = PosaljiTelegram(httpFactory, telegramToken, telegramChatId, tekst);
    }
    return Results.Ok();
}).RequireRateLimiting("rezervacije");

// ADMIN: brisanje rezervacije
app.MapDelete("/api/rezervacije/{id:int}", (int id) =>
{
    using var connection = new SqliteConnection(connStr);
    connection.Open();
    var command = connection.CreateCommand();
    command.CommandText = "DELETE FROM Rezervacije WHERE Id = $id";
    command.Parameters.AddWithValue("$id", id);
    command.ExecuteNonQuery();
    return Results.Ok();
});

// ===== BLOKIRANJE TERMINA I RUČNI UPIS (samo admin) =====

// ADMIN: popis svih blokada (vrijeme "" znači cijeli dan)
app.MapGet("/api/admin/blokade", () =>
{
    var lista = new List<object>();
    using var connection = new SqliteConnection(connStr);
    connection.Open();
    using var cmd = connection.CreateCommand();
    cmd.CommandText = "SELECT Id, Datum, Vrijeme FROM Blokade ORDER BY Datum, Vrijeme";
    using var reader = cmd.ExecuteReader();
    while (reader.Read())
        lista.Add(new { id = reader.GetInt32(0), datum = reader.GetString(1), vrijeme = reader.GetString(2) });
    return Results.Ok(lista);
});

// ADMIN: blokiraj cijeli dan ili odabrane termine jednog dana
app.MapPost("/api/admin/blokade", (BlokadaDto dto) =>
{
    if (!DateOnly.TryParseExact(dto.Datum, "yyyy-MM-dd", out _))
        return Results.BadRequest("Neispravan datum.");

    var vremena = dto.CijeliDan
        ? new List<string> { "" }
        : (dto.Vremena ?? new List<string>()).Where(v => radnoVrijeme.Contains(v)).Distinct().ToList();
    if (vremena.Count == 0)
        return Results.BadRequest("Nije odabran nijedan termin.");

    using var connection = new SqliteConnection(connStr);
    connection.Open();
    foreach (var v in vremena)
        Izvrsi(connection, null, "INSERT OR IGNORE INTO Blokade (Datum, Vrijeme) VALUES ($d, $v)", ("$d", dto.Datum), ("$v", v));
    return Results.Ok();
});

// ADMIN: ukloni jednu blokadu (bez vremena = ponovno otvori cijeli dan)
app.MapDelete("/api/admin/blokade", (string datum, string? vrijeme) =>
{
    using var connection = new SqliteConnection(connStr);
    connection.Open();
    Izvrsi(connection, null, "DELETE FROM Blokade WHERE Datum = $d AND Vrijeme = $v", ("$d", datum), ("$v", vrijeme ?? ""));
    return Results.Ok();
});

// ADMIN: blokiraj ili ukloni blokade u razdoblju (godišnji odmor, svake nedjelje, pauza za ručak...)
app.MapPost("/api/admin/blokade/raspon", (RasponDto dto) =>
{
    if (!DateOnly.TryParseExact(dto.OdDatuma, "yyyy-MM-dd", out var od) ||
        !DateOnly.TryParseExact(dto.DoDatuma, "yyyy-MM-dd", out var doDatuma))
        return Results.BadRequest("Neispravan datum.");
    if (doDatuma < od)
        return Results.BadRequest("Završni datum mora biti nakon početnog.");
    if (doDatuma.DayNumber - od.DayNumber > 365)
        return Results.BadRequest("Odjednom je moguće najviše 366 dana.");

    var dani = dto.Dani is { Length: > 0 } ? dto.Dani.ToHashSet() : new HashSet<int> { 1, 2, 3, 4, 5, 6, 7 };

    // Cijeli dan ("") ili samo termini od vrijemeOd (uključivo) do vrijemeDo (isključivo)
    var vOd = dto.VrijemeOd ?? "";
    var vDo = dto.VrijemeDo ?? "";
    List<string> vremena;
    if (dto.CijeliDan)
    {
        vremena = new List<string> { "" };
    }
    else
    {
        vremena = radnoVrijeme
            .Where(t => string.CompareOrdinal(t, vOd) >= 0 && string.CompareOrdinal(t, vDo) < 0)
            .ToList();
        if (vremena.Count == 0)
            return Results.BadRequest("Neispravan raspon vremena.");
    }

    int promijenjeno = 0, rezervacije = 0;
    using var connection = new SqliteConnection(connStr);
    connection.Open();
    using var tx = connection.BeginTransaction();

    for (var dan = od; dan <= doDatuma; dan = dan.AddDays(1))
    {
        var iso = dan.DayOfWeek == DayOfWeek.Sunday ? 7 : (int)dan.DayOfWeek; // 1 = ponedjeljak ... 7 = nedjelja
        if (!dani.Contains(iso)) continue;
        var d = dan.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

        if (dto.Ukloni)
        {
            if (dto.CijeliDan)
            {
                // "Cijeli dan" pri uklanjanju briše sve blokade tog dana
                promijenjeno += Izvrsi(connection, tx, "DELETE FROM Blokade WHERE Datum = $d", ("$d", d));
            }
            else
            {
                foreach (var v in vremena)
                    promijenjeno += Izvrsi(connection, tx, "DELETE FROM Blokade WHERE Datum = $d AND Vrijeme = $v", ("$d", d), ("$v", v));
            }
        }
        else
        {
            foreach (var v in vremena)
                promijenjeno += Izvrsi(connection, tx, "INSERT OR IGNORE INTO Blokade (Datum, Vrijeme) VALUES ($d, $v)", ("$d", d), ("$v", v));

            // Koliko već postojećih rezervacija pada u blokirano razdoblje (samo za informaciju adminu)
            if (dto.CijeliDan)
                rezervacije += (int)Broji(connection, tx, "SELECT COUNT(*) FROM Rezervacije WHERE Datum = $d", ("$d", d));
            else
                rezervacije += (int)Broji(connection, tx,
                    "SELECT COUNT(*) FROM Rezervacije WHERE Datum = $d AND Vrijeme >= $od AND Vrijeme < $do",
                    ("$d", d), ("$od", vOd), ("$do", vDo));
        }
    }

    tx.Commit();
    return Results.Ok(new { promijenjeno, rezervacijaNaTimDanima = rezervacije });
});

// ADMIN: ručni upis klijenta (telefonom ili uživo), telefon nije obavezan
app.MapPost("/api/admin/rezervacije", (RucnaRezervacijaDto dto) =>
{
    var ime = dto.Ime?.Trim() ?? "";
    if (ime.Length == 0 || ime.Length > 100)
        return Results.BadRequest("Neispravno ime.");

    var telefon = dto.Telefon?.Trim() ?? "";
    if (telefon.Length > 0 && !Regex.IsMatch(telefon, @"^[0-9+\-\s()/]{6,20}$"))
        return Results.BadRequest("Neispravan broj telefona.");

    if (!DateOnly.TryParseExact(dto.Datum, "yyyy-MM-dd", out var datum))
        return Results.BadRequest("Neispravan datum.");
    if (datum < DateOnly.FromDateTime(DateTime.UtcNow.AddHours(2)))
        return Results.BadRequest("Datum je u prošlosti.");
    if (!radnoVrijeme.Contains(dto.Vrijeme))
        return Results.BadRequest("Neispravno vrijeme.");

    try
    {
        using var connection = new SqliteConnection(connStr);
        connection.Open();
        if (Broji(connection, null, "SELECT COUNT(*) FROM Blokade WHERE Datum = $d AND (Vrijeme = '' OR Vrijeme = $v)",
                ("$d", dto.Datum), ("$v", dto.Vrijeme)) > 0)
            return Results.Conflict("Termin je blokiran.");

        Izvrsi(connection, null, "INSERT INTO Rezervacije (Ime, Datum, Vrijeme, Telefon) VALUES ($ime, $d, $v, $t)",
            ("$ime", ime), ("$d", dto.Datum), ("$v", dto.Vrijeme), ("$t", telefon));
    }
    catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
    {
        return Results.Conflict("Termin je već zauzet.");
    }
    return Results.Ok();
});

app.Run();

// ===== Pomoćne funkcije =====

static string Env(string kljuc, string zadano)
{
    var v = Environment.GetEnvironmentVariable(kljuc);
    return string.IsNullOrWhiteSpace(v) ? zadano : v.Trim();
}

// Izvrši SQL naredbu (INSERT/DELETE) s imenovanim parametrima; vraća broj promijenjenih redaka
static int Izvrsi(SqliteConnection c, SqliteTransaction? tx, string sql, params (string Ime, object? Vrijednost)[] p)
{
    using var cmd = c.CreateCommand();
    cmd.Transaction = tx;
    cmd.CommandText = sql;
    foreach (var (ime, v) in p) cmd.Parameters.AddWithValue(ime, v ?? DBNull.Value);
    return cmd.ExecuteNonQuery();
}

// Izvrši SELECT COUNT(*) i vrati broj
static long Broji(SqliteConnection c, SqliteTransaction? tx, string sql, params (string Ime, object? Vrijednost)[] p)
{
    using var cmd = c.CreateCommand();
    cmd.Transaction = tx;
    cmd.CommandText = sql;
    foreach (var (ime, v) in p) cmd.Parameters.AddWithValue(ime, v ?? DBNull.Value);
    return Convert.ToInt64(cmd.ExecuteScalar());
}

// Izvrši SELECT s jednim stupcem teksta i vrati popis
static List<string> Stupac(SqliteConnection c, string sql, params (string Ime, object? Vrijednost)[] p)
{
    using var cmd = c.CreateCommand();
    cmd.CommandText = sql;
    foreach (var (ime, v) in p) cmd.Parameters.AddWithValue(ime, v ?? DBNull.Value);
    var lista = new List<string>();
    using var r = cmd.ExecuteReader();
    while (r.Read()) lista.Add(r.GetString(0));
    return lista;
}

// Šalje poruku preko Telegram bota
static async Task PosaljiTelegram(IHttpClientFactory factory, string token, string chatId, string tekst)
{
    try
    {
        var client = factory.CreateClient();
        client.Timeout = TimeSpan.FromSeconds(10);
        await client.PostAsJsonAsync($"https://api.telegram.org/bot{token}/sendMessage",
            new { chat_id = chatId, text = tekst });
    }
    catch
    {
        // namjerno ignoriramo greške: nedostupan Telegram ne smije pokvariti rezervaciju
    }
}

// Priprema tekst za .ics datoteku (posebni znakovi moraju imati kosu crtu ispred)
static string IcsTekst(string t) =>
    t.Replace("\\", "\\\\").Replace(";", "\\;").Replace(",", "\\,").Replace("\r", "").Replace("\n", "\\n");

// Pretvara tekst "Šišanje=20 €;Brijanje=10 €" u popis stavki cjenika (najviše 30)
static List<object> ParsirajCjenik(string tekst)
{
    var lista = new List<object>();
    foreach (var dio in tekst.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    {
        var i = dio.IndexOf('=');
        if (i <= 0 || i == dio.Length - 1) continue;
        lista.Add(new { naziv = dio[..i].Trim(), cijena = dio[(i + 1)..].Trim() });
        if (lista.Count >= 30) break;
    }
    return lista;
}

// Prihvaća samo oblik #rrggbb, inače vraća zadanu boju
static string Boja(string vrijednost, string zadano) =>
    Regex.IsMatch(vrijednost, "^#[0-9a-fA-F]{6}$") ? vrijednost : zadano;

// Napravi popis termina od "od" do "do" na svakih "korak" minuta
static List<string> GenerirajTermine(string od, string doo, int korak)
{
    if (!TimeOnly.TryParseExact(od, "HH:mm", out var o)) o = new TimeOnly(11, 0);
    if (!TimeOnly.TryParseExact(doo, "HH:mm", out var d)) d = new TimeOnly(20, 0);
    if (korak < 5 || korak > 240) korak = 30;

    var lista = new List<string>();
    for (int m = o.Hour * 60 + o.Minute; m <= d.Hour * 60 + d.Minute; m += korak)
        lista.Add($"{m / 60:00}:{m % 60:00}");
    return lista;
}

// ===== Prijava admina: potpisani kolačić (vrijedi 60 dana, a promjena lozinke odjavljuje sve) =====

static string Potpis(string podatak, string lozinka)
{
    using var h = new HMACSHA256(Encoding.UTF8.GetBytes(lozinka));
    return Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(podatak)));
}

static string NapraviToken(string lozinka, DateTimeOffset istek)
{
    var exp = istek.ToUnixTimeSeconds().ToString();
    return exp + "." + Potpis(exp, lozinka);
}

static bool ProvjeriAdmina(HttpContext ctx, string? lozinka)
{
    if (string.IsNullOrEmpty(lozinka)) return false; // ako lozinka nije postavljena, admin je zaključan

    var token = ctx.Request.Cookies["admin_sesija"];
    if (string.IsNullOrEmpty(token)) return false;

    var dijelovi = token.Split('.');
    if (dijelovi.Length != 2 || !long.TryParse(dijelovi[0], out var istek)) return false;
    if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > istek) return false;

    var ocekivano = Encoding.UTF8.GetBytes(Potpis(dijelovi[0], lozinka));
    var dobiveno = Encoding.UTF8.GetBytes(dijelovi[1]);
    return CryptographicOperations.FixedTimeEquals(ocekivano, dobiveno);
}

record RezervacijaDto(string Ime, string Telefon, string Datum, string Vrijeme);
record PrijavaDto(string Lozinka);
record BlokadaDto(string Datum, bool CijeliDan, List<string>? Vremena);
record RasponDto(string OdDatuma, string DoDatuma, int[]? Dani, bool CijeliDan, string? VrijemeOd, string? VrijemeDo, bool Ukloni);
record RucnaRezervacijaDto(string Ime, string? Telefon, string Datum, string Vrijeme);
