using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using Google.Cloud.Firestore;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;

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
// Neradni dani u tjednu: brojevi 1 (ponedjeljak) do 7 (nedjelja) odvojeni zarezom, zadano je nedjelja. "nema" = radi se svaki dan
var neradniDani = Env("NERADNI_DANI", "7")
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
    .Select(x => int.TryParse(x, out var n) ? n : 0)
    .Where(n => n >= 1 && n <= 7)
    .ToHashSet();

// ===== SPOJ NA FIREBASE (Firestore) =====
// Ključ (JSON) se čita iz varijable FIREBASE_CREDENTIALS ili iz tajne datoteke firebase.json na Renderu
var firebaseJson = Environment.GetEnvironmentVariable("FIREBASE_CREDENTIALS");
if (string.IsNullOrWhiteSpace(firebaseJson))
{
    foreach (var putanja in new[] { "/etc/secrets/firebase.json", "firebase.json" })
    {
        if (File.Exists(putanja))
        {
            firebaseJson = File.ReadAllText(putanja);
            break;
        }
    }
}
if (string.IsNullOrWhiteSpace(firebaseJson))
    throw new InvalidOperationException(
        "Nedostaje Firebase ključ. Na Renderu dodaj tajnu datoteku firebase.json (ili varijablu FIREBASE_CREDENTIALS) sa sadržajem JSON ključa.");

var firebaseProjekt = JsonDocument.Parse(firebaseJson).RootElement.GetProperty("project_id").GetString();
var firestore = new FirestoreDbBuilder { ProjectId = firebaseProjekt, JsonCredentials = firebaseJson }.Build();
var baza = new Baza(firestore);

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
    cjenik,
    neradniDani = neradniDani.OrderBy(x => x).ToArray()
}));

// JAVNO: stanje jednog dana (bez imena i telefona): je li dan zatvoren, koja su vremena zauzeta, a koja blokirana
app.MapGet("/api/zauzeto", async (string datum) =>
{
    if (!DateOnly.TryParseExact(datum, "yyyy-MM-dd", out var dan))
        return Results.BadRequest();

    var (blokiranCijeliDan, zauzeto, blokirano) = await baza.Stanje(datum);
    var zatvoren = neradniDani.Contains(IsoDan(dan)) || blokiranCijeliDan;
    return Results.Ok(new { zatvoren, zauzeto, blokirano });
});

// ADMIN: popis svih rezervacija
app.MapGet("/api/rezervacije", async () => Results.Ok(await baza.SveRezervacije()));

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

    if (neradniDani.Contains(IsoDan(datum)))
        return Results.Conflict("Taj dan ne radimo.");

    if (!radnoVrijeme.Contains(form.Vrijeme))
        return Results.BadRequest("Neispravno vrijeme.");

    var ishod = await baza.DodajRezervaciju(ime, telefon, form.Datum, form.Vrijeme);
    if (ishod == Ishod.Blokirano) return Results.Conflict("Termin nije dostupan.");
    if (ishod == Ishod.Zauzeto) return Results.Conflict("Termin je već zauzet.");

    // Obavijest na Telegram (ne čekamo odgovor, a greška nikad ne ruši rezervaciju)
    if (telegramToken != "" && telegramChatId != "")
    {
        var tekst = $"Nova rezervacija\n{ime}\nTel: {telefon}\n{datum:dd.MM.yyyy.} u {form.Vrijeme}";
        _ = PosaljiTelegram(httpFactory, telegramToken, telegramChatId, tekst);
    }
    return Results.Ok();
}).RequireRateLimiting("rezervacije");

// ADMIN: brisanje rezervacije
app.MapDelete("/api/rezervacije/{id}", async (string id) =>
{
    await baza.ObrisiRezervaciju(id);
    return Results.Ok();
});

// ===== BLOKIRANJE TERMINA I RUČNI UPIS (samo admin) =====

// ADMIN: popis svih blokada (vrijeme "" znači cijeli dan)
app.MapGet("/api/admin/blokade", async () => Results.Ok(await baza.SveBlokade()));

// ADMIN: blokiraj cijeli dan ili odabrane termine jednog dana
app.MapPost("/api/admin/blokade", async (BlokadaDto dto) =>
{
    if (!DateOnly.TryParseExact(dto.Datum, "yyyy-MM-dd", out _))
        return Results.BadRequest("Neispravan datum.");

    var vremena = dto.CijeliDan
        ? new List<string> { "" }
        : (dto.Vremena ?? new List<string>()).Where(v => radnoVrijeme.Contains(v)).Distinct().ToList();
    if (vremena.Count == 0)
        return Results.BadRequest("Nije odabran nijedan termin.");

    await baza.BlokirajTermine(dto.Datum, vremena);
    return Results.Ok();
});

// ADMIN: ukloni jednu blokadu (bez vremena = ponovno otvori cijeli dan)
app.MapDelete("/api/admin/blokade", async (string datum, string? vrijeme) =>
{
    if (!DateOnly.TryParseExact(datum, "yyyy-MM-dd", out _))
        return Results.BadRequest("Neispravan datum.");

    await baza.OdblokirajTermin(datum, vrijeme ?? "");
    return Results.Ok();
});

// ADMIN: blokiraj ili ukloni blokade u razdoblju (godišnji odmor, svake nedjelje, pauza za ručak...)
app.MapPost("/api/admin/blokade/raspon", async (RasponDto dto) =>
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

    var (promijenjeno, rezervacije) = await baza.Raspon(od, doDatuma, dani, dto.CijeliDan, vremena, vOd, vDo, dto.Ukloni);
    return Results.Ok(new { promijenjeno, rezervacijaNaTimDanima = rezervacije });
});

// ADMIN: ručni upis klijenta (telefonom ili uživo), telefon nije obavezan
app.MapPost("/api/admin/rezervacije", async (RucnaRezervacijaDto dto) =>
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
    if (neradniDani.Contains(IsoDan(datum)))
        return Results.Conflict("Neradni dan.");
    if (!radnoVrijeme.Contains(dto.Vrijeme))
        return Results.BadRequest("Neispravno vrijeme.");

    var ishod = await baza.DodajRezervaciju(ime, telefon, dto.Datum, dto.Vrijeme);
    if (ishod == Ishod.Blokirano) return Results.Conflict("Termin je blokiran.");
    if (ishod == Ishod.Zauzeto) return Results.Conflict("Termin je već zauzet.");
    return Results.Ok();
});

// Probno spajanje pri pokretanju: ako ključ ili dozvole ne valjaju, greška se vidi u Logs na Renderu
try
{
    await baza.SveBlokade();
    Console.WriteLine("Firestore: spojeno na projekt " + firebaseProjekt);
}
catch (Exception ex)
{
    Console.WriteLine("UPOZORENJE: ne mogu se spojiti na Firestore: " + ex.Message);
}

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

// Dan u tjednu kao broj: 1 = ponedjeljak ... 7 = nedjelja
static int IsoDan(DateOnly d) => d.DayOfWeek == DayOfWeek.Sunday ? 7 : (int)d.DayOfWeek;

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

// ===== Podaci =====

record RezervacijaDto(string Ime, string Telefon, string Datum, string Vrijeme);
record PrijavaDto(string Lozinka);
record BlokadaDto(string Datum, bool CijeliDan, List<string>? Vremena);
record RasponDto(string OdDatuma, string DoDatuma, int[]? Dani, bool CijeliDan, string? VrijemeOd, string? VrijemeDo, bool Ukloni);
record RucnaRezervacijaDto(string Ime, string? Telefon, string Datum, string Vrijeme);

// Rezervacija i blokada u memoriji (Vrijeme "" kod blokade znači cijeli dan)
record Rez(string Id, string Ime, string Telefon, string Datum, string Vrijeme);
record Blok(string Id, string Datum, string Vrijeme);

enum Ishod { Ok, Zauzeto, Blokirano }

/// <summary>
/// Trajna pohrana u Firebase Firestoreu, uz brzi pregled u memoriji.
/// Firestore čuva podatke (kolekcije "rezervacije" i "blokade"), a server pri pokretanju učita posljednjih 60 dana
/// i sve buduće termine, pa se čitanja ne troše pri svakom osvježavanju admina (besplatni plan ima dnevni limit).
/// </summary>
class Baza
{
    readonly FirestoreDb _db;
    readonly CollectionReference _rez;
    readonly CollectionReference _blok;
    readonly SemaphoreSlim _brava = new(1, 1);
    readonly Dictionary<string, Rez> _rezervacije = new();
    readonly Dictionary<string, Blok> _blokade = new();
    bool _ucitano;

    public Baza(FirestoreDb db)
    {
        _db = db;
        _rez = db.Collection("rezervacije");
        _blok = db.Collection("blokade");
    }

    // ID dokumenta je datum + vrijeme, pa Firestore sam sprječava dvije rezervacije na isti termin
    static string RezId(string datum, string vrijeme) => $"{datum}_{vrijeme.Replace(":", "")}";
    static string BlokId(string datum, string vrijeme) =>
        vrijeme == "" ? $"{datum}_dan" : $"{datum}_{vrijeme.Replace(":", "")}";

    static string Tekst(DocumentSnapshot d, string polje) =>
        d.TryGetValue(polje, out string v) ? (v ?? "") : "";

    // Jednom po pokretanju učita podatke iz Firestorea u memoriju
    async Task Ucitaj()
    {
        if (_ucitano) return;

        var od = DateTime.UtcNow.AddHours(2).AddDays(-60).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

        _rezervacije.Clear();
        var rez = await _rez.WhereGreaterThanOrEqualTo("datum", od).GetSnapshotAsync();
        foreach (var d in rez.Documents)
            _rezervacije[d.Id] = new Rez(d.Id, Tekst(d, "ime"), Tekst(d, "telefon"), Tekst(d, "datum"), Tekst(d, "vrijeme"));

        _blokade.Clear();
        var blok = await _blok.WhereGreaterThanOrEqualTo("datum", od).GetSnapshotAsync();
        foreach (var d in blok.Documents)
            _blokade[d.Id] = new Blok(d.Id, Tekst(d, "datum"), Tekst(d, "vrijeme"));

        _ucitano = true;
    }

    // Sve operacije idu jedna po jedna, da se dva klijenta ne mogu istovremeno upisati na isti termin
    async Task<T> Pod<T>(Func<Task<T>> posao)
    {
        await _brava.WaitAsync();
        try
        {
            await Ucitaj();
            return await posao();
        }
        finally
        {
            _brava.Release();
        }
    }

    public Task<(bool, List<string>, List<string>)> Stanje(string datum) => Pod(() =>
    {
        var zauzeto = _rezervacije.Values.Where(r => r.Datum == datum).Select(r => r.Vrijeme).ToList();
        var blokade = _blokade.Values.Where(b => b.Datum == datum).ToList();
        var cijeliDan = blokade.Any(b => b.Vrijeme == "");
        var blokirano = blokade.Where(b => b.Vrijeme != "").Select(b => b.Vrijeme).ToList();
        return Task.FromResult((cijeliDan, zauzeto, blokirano));
    });

    public Task<List<Rez>> SveRezervacije() => Pod(() => Task.FromResult(
        _rezervacije.Values
            .OrderBy(r => r.Datum, StringComparer.Ordinal)
            .ThenBy(r => r.Vrijeme, StringComparer.Ordinal)
            .ToList()));

    public Task<List<Blok>> SveBlokade() => Pod(() => Task.FromResult(
        _blokade.Values
            .OrderBy(b => b.Datum, StringComparer.Ordinal)
            .ThenBy(b => b.Vrijeme, StringComparer.Ordinal)
            .ToList()));

    public Task<Ishod> DodajRezervaciju(string ime, string telefon, string datum, string vrijeme) => Pod(async () =>
    {
        if (_blokade.Values.Any(b => b.Datum == datum && (b.Vrijeme == "" || b.Vrijeme == vrijeme)))
            return Ishod.Blokirano;

        var id = RezId(datum, vrijeme);
        if (_rezervacije.ContainsKey(id))
            return Ishod.Zauzeto;

        try
        {
            await _rez.Document(id).CreateAsync(new Dictionary<string, object>
            {
                ["ime"] = ime,
                ["telefon"] = telefon,
                ["datum"] = datum,
                ["vrijeme"] = vrijeme,
                ["kreirano"] = Timestamp.GetCurrentTimestamp()
            });
        }
        catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.AlreadyExists)
        {
            return Ishod.Zauzeto;
        }

        _rezervacije[id] = new Rez(id, ime, telefon, datum, vrijeme);
        return Ishod.Ok;
    });

    public Task<bool> ObrisiRezervaciju(string id) => Pod(async () =>
    {
        await _rez.Document(id).DeleteAsync();
        _rezervacije.Remove(id);
        return true;
    });

    public Task<bool> BlokirajTermine(string datum, List<string> vremena) => Pod(async () =>
    {
        var novi = vremena.Distinct()
            .Select(v => new Blok(BlokId(datum, v), datum, v))
            .Where(b => !_blokade.ContainsKey(b.Id))
            .ToList();
        await ZapisiBlokade(novi);
        return true;
    });

    public Task<bool> OdblokirajTermin(string datum, string vrijeme) => Pod(async () =>
    {
        if (_blokade.TryGetValue(BlokId(datum, vrijeme), out var b))
            await ObrisiBlokade(new List<Blok> { b });
        return true;
    });

    public Task<(int, int)> Raspon(DateOnly od, DateOnly doDatuma, HashSet<int> dani, bool cijeliDan,
        List<string> vremena, string vOd, string vDo, bool ukloni) => Pod(async () =>
    {
        var dodaj = new List<Blok>();
        var makni = new List<Blok>();
        int rezervacije = 0;

        for (var dan = od; dan <= doDatuma; dan = dan.AddDays(1))
        {
            var iso = dan.DayOfWeek == DayOfWeek.Sunday ? 7 : (int)dan.DayOfWeek; // 1 = ponedjeljak ... 7 = nedjelja
            if (!dani.Contains(iso)) continue;
            var d = dan.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

            if (ukloni)
            {
                if (cijeliDan)
                {
                    // "Cijeli dan" pri uklanjanju briše sve blokade tog dana
                    makni.AddRange(_blokade.Values.Where(b => b.Datum == d));
                }
                else
                {
                    foreach (var v in vremena)
                        if (_blokade.TryGetValue(BlokId(d, v), out var b)) makni.Add(b);
                }
            }
            else
            {
                foreach (var v in vremena)
                {
                    var id = BlokId(d, v);
                    if (!_blokade.ContainsKey(id)) dodaj.Add(new Blok(id, d, v));
                }

                // Koliko već postojećih rezervacija pada u blokirano razdoblje (samo za informaciju adminu)
                rezervacije += cijeliDan
                    ? _rezervacije.Values.Count(r => r.Datum == d)
                    : _rezervacije.Values.Count(r => r.Datum == d
                        && string.CompareOrdinal(r.Vrijeme, vOd) >= 0
                        && string.CompareOrdinal(r.Vrijeme, vDo) < 0);
            }
        }

        await ObrisiBlokade(makni);
        await ZapisiBlokade(dodaj);
        return (makni.Count + dodaj.Count, rezervacije);
    });

    // Firestore dopušta najviše 500 upisa odjednom, pa idemo po 400
    async Task ZapisiBlokade(List<Blok> novi)
    {
        foreach (var dio in novi.Chunk(400))
        {
            var batch = _db.StartBatch();
            foreach (var b in dio)
                batch.Set(_blok.Document(b.Id), new Dictionary<string, object> { ["datum"] = b.Datum, ["vrijeme"] = b.Vrijeme });
            await batch.CommitAsync();
            foreach (var b in dio) _blokade[b.Id] = b;
        }
    }

    async Task ObrisiBlokade(List<Blok> stari)
    {
        foreach (var dio in stari.Chunk(400))
        {
            var batch = _db.StartBatch();
            foreach (var b in dio)
                batch.Delete(_blok.Document(b.Id));
            await batch.CommitAsync();
            foreach (var b in dio) _blokade.Remove(b.Id);
        }
    }
}
