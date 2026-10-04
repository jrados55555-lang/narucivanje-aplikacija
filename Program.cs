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

// Zaštita admina: admin stranica, popis svih rezervacija i brisanje traže lozinku
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value?.ToLowerInvariant() ?? "";
    var method = ctx.Request.Method;

    bool zasticeno =
        path.StartsWith("/admin") ||
        (path == "/api/rezervacije" && method == "GET") ||
        (path.StartsWith("/api/rezervacije/") && method == "DELETE");

    if (zasticeno && !ProvjeriAdmina(ctx, adminLozinka))
    {
        ctx.Response.Headers.WWWAuthenticate = "Basic realm=\"Admin\"";
        ctx.Response.StatusCode = 401;
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
        CREATE UNIQUE INDEX IF NOT EXISTS ux_termin ON Rezervacije(Datum, Vrijeme);";
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

// JAVNO: postavke salona (naziv, boje, logo, popis termina)
app.MapGet("/api/postavke", () => Results.Ok(new
{
    naziv = salonNaziv,
    telefon = salonTelefon,
    boja,
    pozadina,
    logo,
    termini = radnoVrijeme
}));

// JAVNO: samo zauzeta vremena za jedan datum (bez imena i telefona)
app.MapGet("/api/zauzeto", (string datum) =>
{
    var lista = new List<string>();
    using var connection = new SqliteConnection(connStr);
    connection.Open();
    var cmd = connection.CreateCommand();
    cmd.CommandText = "SELECT Vrijeme FROM Rezervacije WHERE Datum = $datum";
    cmd.Parameters.AddWithValue("$datum", datum);
    using var reader = cmd.ExecuteReader();
    while (reader.Read()) lista.Add(reader.GetString(0));
    return Results.Ok(lista);
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

app.Run();

// ===== Pomoćne funkcije =====

static string Env(string kljuc, string zadano)
{
    var v = Environment.GetEnvironmentVariable(kljuc);
    return string.IsNullOrWhiteSpace(v) ? zadano : v.Trim();
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

static bool ProvjeriAdmina(HttpContext ctx, string? lozinka)
{
    if (string.IsNullOrEmpty(lozinka)) return false; // ako lozinka nije postavljena, admin je zaključan

    var header = ctx.Request.Headers.Authorization.ToString();
    if (!header.StartsWith("Basic ")) return false;

    try
    {
        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header[6..]));
        var idx = decoded.IndexOf(':');
        if (idx < 0) return false;

        var uneseno = Encoding.UTF8.GetBytes(decoded[(idx + 1)..]);
        var ocekivano = Encoding.UTF8.GetBytes(lozinka);
        return CryptographicOperations.FixedTimeEquals(uneseno, ocekivano);
    }
    catch
    {
        return false;
    }
}

record RezervacijaDto(string Ime, string Telefon, string Datum, string Vrijeme);
