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

// Zaštita od spama i pogađanja lozinki (ograničenje po IP adresi)
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // Naručivanje: najviše 10 pokušaja u 10 minuta
    o.AddPolicy("rezervacije", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "nepoznato",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(10) }));

    // Prijava admina: najviše 8 pokušaja u 10 minuta
    o.AddPolicy("prijava", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "nepoznato",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 8, Window = TimeSpan.FromMinutes(10) }));

    // Registracija i prijava klijenata: najviše 20 pokušaja u 10 minuta
    o.AddPolicy("klijent", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "nepoznato",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 20, Window = TimeSpan.FromMinutes(10) }));
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
var korakMin = int.TryParse(Env("KORAK_MIN", "30"), out var korakPokusaj) ? korakPokusaj : 30;
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
// Pravila za klijente
var otkazSati = double.TryParse(Env("OTKAZ_SATI", "2"), NumberStyles.Float, CultureInfo.InvariantCulture, out var otkazPokusaj) ? otkazPokusaj : 2;       // koliko sati prije termina se još može otkazati
var minObavijestMin = int.TryParse(Env("MIN_OBAVIJEST_MIN", "30"), out var obavijestPokusaj) ? obavijestPokusaj : 30;                                      // termini koji počinju za manje od toliko minuta se ne nude
var maxAktivnih = int.TryParse(Env("MAX_AKTIVNIH", "3"), out var aktivnihPokusaj) ? aktivnihPokusaj : 3;                                                  // najviše toliko budućih termina po računu

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

// Tajni ključ za potpisivanje prijava klijenata (sprema se u Firestore, pa prijave prežive ponovno pokretanje)
string tajna;
try
{
    tajna = await baza.Tajna();
    Console.WriteLine("Firestore: spojeno na projekt " + firebaseProjekt);
}
catch (Exception ex)
{
    Console.WriteLine("UPOZORENJE: ne mogu se spojiti na Firestore: " + ex.Message);
    tajna = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
}

// Vraća prijavljenog klijenta (iz kolačića) ili null
async Task<Korisnik?> Klijent(HttpContext ctx)
{
    var id = KlijentIdIzTokena(ctx.Request.Cookies["klijent_sesija"], tajna);
    return id == null ? null : await baza.NadiKorisnika(id);
}

// Zaštita admina: admin stranice, popis svih rezervacija i brisanje traže lozinku
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

// ===== ADMIN: prijava =====

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

// ===== PWA =====

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

// ===== JAVNO =====

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

// JAVNO: postavke salona (naziv, boje, logo, cjenik, pravila)
app.MapGet("/api/postavke", () => Results.Ok(new
{
    naziv = salonNaziv,
    telefon = salonTelefon,
    boja,
    pozadina,
    logo,
    termini = radnoVrijeme,
    cjenik,
    neradniDani = neradniDani.OrderBy(x => x).ToArray(),
    otkazSati,
    maxAktivnih
}));

// ===== KLIJENT: račun =====

// Registracija novog računa (ime, telefon i lozinka); nakon registracije klijent je odmah prijavljen
app.MapPost("/api/klijent/registracija", async (RegistracijaDto dto, HttpContext ctx) =>
{
    var ime = dto.Ime?.Trim() ?? "";
    if (ime.Length < 2 || ime.Length > 100)
        return Results.BadRequest("Upišite ime i prezime.");

    var id = NormalizirajTelefon(dto.Telefon);
    if (id == null)
        return Results.BadRequest("Neispravan broj telefona.");

    var lozinka = dto.Lozinka ?? "";
    if (lozinka.Length < 6 || lozinka.Length > 100)
        return Results.BadRequest("Lozinka mora imati najmanje 6 znakova.");

    var (sol, hash) = Lozinke.Napravi(lozinka);
    var novi = await baza.Registriraj(id, ime, dto.Telefon!.Trim(), sol, hash);
    if (novi == null)
        return Results.Conflict("Račun s tim brojem telefona već postoji. Prijavite se.");

    PostaviKlijentKolacic(ctx, novi.Id, tajna);
    return Results.Ok(new { ime = novi.Ime, telefon = novi.Telefon });
}).RequireRateLimiting("klijent");

// Prijava klijenta (telefon i lozinka)
app.MapPost("/api/klijent/prijava", async (KlijentPrijavaDto dto, HttpContext ctx) =>
{
    var id = NormalizirajTelefon(dto.Telefon);
    var korisnik = id == null ? null : await baza.NadiKorisnika(id);

    // Provjera se radi i kad račun ne postoji, da se ne može doznati koji su brojevi registrirani
    var ispravno = Lozinke.Provjeri(korisnik, dto.Lozinka ?? "");
    if (!ispravno || korisnik == null)
        return Results.Unauthorized();

    PostaviKlijentKolacic(ctx, korisnik.Id, tajna);
    return Results.Ok(new { ime = korisnik.Ime, telefon = korisnik.Telefon });
}).RequireRateLimiting("klijent");

// Odjava klijenta
app.MapPost("/api/klijent/odjava", (HttpContext ctx) =>
{
    ctx.Response.Cookies.Delete("klijent_sesija");
    return Results.Ok();
});

// Tko je prijavljen (koristi stranica pri otvaranju)
app.MapGet("/api/klijent/ja", async (HttpContext ctx) =>
{
    var korisnik = await Klijent(ctx);
    if (korisnik == null) return Results.Unauthorized();
    return Results.Ok(new { ime = korisnik.Ime, telefon = korisnik.Telefon });
});

// Promjena lozinke
app.MapPost("/api/klijent/promjena-lozinke", async (PromjenaLozinkeDto dto, HttpContext ctx) =>
{
    var korisnik = await Klijent(ctx);
    if (korisnik == null) return Results.Unauthorized();

    if (!Lozinke.Provjeri(korisnik, dto.Stara ?? ""))
        return Results.BadRequest("Trenutna lozinka nije točna.");

    var nova = dto.Nova ?? "";
    if (nova.Length < 6 || nova.Length > 100)
        return Results.BadRequest("Nova lozinka mora imati najmanje 6 znakova.");

    var (sol, hash) = Lozinke.Napravi(nova);
    await baza.PostaviLozinku(korisnik.Id, sol, hash);
    return Results.Ok();
}).RequireRateLimiting("klijent");

// Brisanje vlastitog računa (briše se račun i sve rezervacije tog računa)
app.MapPost("/api/klijent/brisanje-racuna", async (LozinkaDto dto, HttpContext ctx) =>
{
    var korisnik = await Klijent(ctx);
    if (korisnik == null) return Results.Unauthorized();

    if (!Lozinke.Provjeri(korisnik, dto.Lozinka ?? ""))
        return Results.BadRequest("Lozinka nije točna.");

    await baza.ObrisiKorisnika(korisnik.Id, true);
    ctx.Response.Cookies.Delete("klijent_sesija");
    return Results.Ok();
}).RequireRateLimiting("klijent");

// ===== KLIJENT: naručivanje =====

// Pregled mjeseca: za svaki dan broj slobodnih termina (0 = zatvoreno, prošlo ili popunjeno)
app.MapGet("/api/dani", async (string mjesec, HttpContext ctx) =>
{
    if (await Klijent(ctx) == null) return Results.Unauthorized();

    if (!DateOnly.TryParseExact(mjesec + "-01", "yyyy-MM-dd", out var prvi))
        return Results.BadRequest();

    var brojDana = DateTime.DaysInMonth(prvi.Year, prvi.Month);
    var datumi = Enumerable.Range(0, brojDana)
        .Select(i => prvi.AddDays(i))
        .ToList();
    var stanje = await baza.StanjeDana(datumi.Select(x => x.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)));
    var sad = Sat.Sad();

    var rezultat = new List<object>();
    foreach (var dan in datumi)
    {
        var iso = dan.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var slobodno = neradniDani.Contains(IsoDan(dan))
            ? 0
            : SlobodniTermini(radnoVrijeme, iso, stanje[iso], sad, minObavijestMin).Count;
        rezultat.Add(new { datum = iso, slobodno });
    }
    return Results.Ok(rezultat);
});

// Slobodni termini jednog dana (zauzeti i blokirani se uopće ne prikazuju)
app.MapGet("/api/termini", async (string datum, HttpContext ctx) =>
{
    if (await Klijent(ctx) == null) return Results.Unauthorized();

    if (!DateOnly.TryParseExact(datum, "yyyy-MM-dd", out var dan))
        return Results.BadRequest();
    if (neradniDani.Contains(IsoDan(dan)))
        return Results.Ok(new List<string>());

    var stanje = await baza.StanjeDana(new[] { datum });
    return Results.Ok(SlobodniTermini(radnoVrijeme, datum, stanje[datum], Sat.Sad(), minObavijestMin));
});

// Naruči termin (samo prijavljeni klijent; ime i telefon se uzimaju iz računa)
app.MapPost("/api/naruci", async (NaruciDto dto, HttpContext ctx, IHttpClientFactory httpFactory) =>
{
    var korisnik = await Klijent(ctx);
    if (korisnik == null) return Results.Unauthorized();

    if (!DateOnly.TryParseExact(dto.Datum, "yyyy-MM-dd", out var datum))
        return Results.BadRequest("Neispravan datum.");
    if (!radnoVrijeme.Contains(dto.Vrijeme))
        return Results.BadRequest("Neispravno vrijeme.");
    if (neradniDani.Contains(IsoDan(datum)))
        return Results.Conflict("Taj dan ne radimo.");

    var ishod = await baza.DodajRezervaciju(korisnik.Ime, korisnik.Telefon, dto.Datum, dto.Vrijeme,
        korisnik.Id, Sat.Sad(), minObavijestMin, maxAktivnih);

    if (ishod == Ishod.Proslo)
        return Results.Conflict("Taj termin više nije moguće rezervirati. Odaberite drugi.");
    if (ishod == Ishod.Limit)
        return Results.Conflict($"Možete imati najviše {maxAktivnih} aktivna termina. Otkažite jedan ili nazovite salon.");
    if (ishod != Ishod.Ok)
        return Results.Conflict("Termin više nije dostupan. Odaberite drugi.");

    // Obavijest na Telegram (ne čekamo odgovor, a greška nikad ne ruši rezervaciju)
    if (telegramToken != "" && telegramChatId != "")
    {
        var tekst = $"Nova rezervacija\n{korisnik.Ime}\nTel: {korisnik.Telefon}\n{HrDatum(dto.Datum)} u {dto.Vrijeme}";
        _ = PosaljiTelegram(httpFactory, telegramToken, telegramChatId, tekst);
    }
    return Results.Ok();
}).RequireRateLimiting("rezervacije");

// Moje rezervacije (buduće i prošle)
app.MapGet("/api/moje/rezervacije", async (HttpContext ctx) =>
{
    var korisnik = await Klijent(ctx);
    if (korisnik == null) return Results.Unauthorized();

    var sad = Sat.Sad();
    var lista = new List<object>();
    foreach (var r in await baza.MojeRezervacije(korisnik.Id))
    {
        var imaPocetak = Sat.Pocetak(r.Datum, r.Vrijeme, out var pocetak);
        var proslo = !imaPocetak || pocetak <= sad;
        var mozeOtkazati = !proslo && (pocetak - sad).TotalHours >= otkazSati;
        lista.Add(new { id = r.Id, datum = r.Datum, vrijeme = r.Vrijeme, proslo, mozeOtkazati });
    }
    return Results.Ok(lista);
});

// Otkazivanje vlastite rezervacije
app.MapDelete("/api/moje/rezervacije/{id}", async (string id, HttpContext ctx, IHttpClientFactory httpFactory) =>
{
    var korisnik = await Klijent(ctx);
    if (korisnik == null) return Results.Unauthorized();

    var (ishod, otkazana) = await baza.Otkazi(id, korisnik.Id, Sat.Sad(), otkazSati);
    if (ishod == OtkazIshod.NemaTermina)
        return Results.NotFound("Termin nije pronađen.");
    if (ishod == OtkazIshod.Prekasno)
        return Results.Conflict($"Termin se može otkazati najkasnije {otkazSati} h prije početka. Nazovite salon.");

    if (otkazana != null && telegramToken != "" && telegramChatId != "")
    {
        var tekst = $"OTKAZAN termin\n{otkazana.Ime}\nTel: {otkazana.Telefon}\n{HrDatum(otkazana.Datum)} u {otkazana.Vrijeme}";
        _ = PosaljiTelegram(httpFactory, telegramToken, telegramChatId, tekst);
    }
    return Results.Ok();
});

// ===== ADMIN: rezervacije =====

// ADMIN: popis svih rezervacija
app.MapGet("/api/rezervacije", async () => Results.Ok(await baza.SveRezervacije()));

// ADMIN: brisanje rezervacije
app.MapDelete("/api/rezervacije/{id}", async (string id) =>
{
    await baza.ObrisiRezervaciju(id);
    return Results.Ok();
});

// ===== ADMIN: blokiranje termina i ručni upis =====

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
    if (datum < DateOnly.FromDateTime(Sat.Sad()))
        return Results.BadRequest("Datum je u prošlosti.");
    if (neradniDani.Contains(IsoDan(datum)))
        return Results.Conflict("Neradni dan.");
    if (!radnoVrijeme.Contains(dto.Vrijeme))
        return Results.BadRequest("Neispravno vrijeme.");

    var ishod = await baza.DodajRezervaciju(ime, telefon, dto.Datum, dto.Vrijeme, "", null, 0, 0);
    if (ishod == Ishod.Blokirano) return Results.Conflict("Termin je blokiran.");
    if (ishod == Ishod.Zauzeto) return Results.Conflict("Termin je već zauzet.");
    return Results.Ok();
});

// ===== ADMIN: računi klijenata =====

// ADMIN: popis računa klijenata
app.MapGet("/api/admin/klijenti", async () =>
{
    var lista = await baza.SviKorisnici();
    return Results.Ok(lista.Select(x => new { id = x.Id, ime = x.Ime, telefon = x.Telefon }));
});

// ADMIN: postavi klijentu novu (privremenu) lozinku, npr. kad je zaboravi; admin mu je javi, a klijent je promijeni u profilu
app.MapPost("/api/admin/klijenti/lozinka", async (IdDto dto) =>
{
    var nova = NasumicnaLozinka();
    var (sol, hash) = Lozinke.Napravi(nova);
    var uspjeh = await baza.PostaviLozinku(dto.Id ?? "", sol, hash);
    if (!uspjeh) return Results.NotFound("Račun nije pronađen.");
    return Results.Ok(new { lozinka = nova });
});

// ADMIN: obriši račun klijenta (njegove rezervacije ostaju u kalendaru)
app.MapDelete("/api/admin/klijenti", async (string id) =>
{
    await baza.ObrisiKorisnika(id, false);
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

// "2026-10-12" -> "12.10.2026."
static string HrDatum(string iso) =>
    DateOnly.TryParseExact(iso, "yyyy-MM-dd", out var d) ? d.ToString("dd.MM.yyyy.", CultureInfo.InvariantCulture) : iso;

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

// Termini koje klijent smije vidjeti: bez zauzetih i blokiranih te bez onih koji su prošli ili počinju prerano
static List<string> SlobodniTermini(List<string> sviTermini, string datum, DanStanje stanje, DateTime sad, int minNaprijedMin)
{
    var lista = new List<string>();
    if (stanje.CijeliDan) return lista;

    foreach (var t in sviTermini)
    {
        if (stanje.Zauzeto.Contains(t)) continue;
        if (Sat.Pocetak(datum, t, out var pocetak) && pocetak < sad.AddMinutes(minNaprijedMin)) continue;
        lista.Add(t);
    }
    return lista;
}

// Telefon u jedinstveni oblik (samo znamenke, hrvatski pozivni broj): "091 234 5678" i "+385 91 234 5678" su isti račun
static string? NormalizirajTelefon(string? unos)
{
    if (string.IsNullOrWhiteSpace(unos) || !Regex.IsMatch(unos.Trim(), @"^[0-9+\-\s()/]{6,20}$"))
        return null;

    var cifre = new string(unos.Where(char.IsDigit).ToArray());
    if (cifre.StartsWith("00")) cifre = cifre[2..];
    else if (cifre.StartsWith("0")) cifre = "385" + cifre[1..];

    return cifre.Length >= 9 && cifre.Length <= 15 ? cifre : null;
}

// Nasumična privremena lozinka (bez zbunjujućih znakova poput 0/o i 1/l)
static string NasumicnaLozinka()
{
    const string znakovi = "abcdefghjkmnpqrstuvwxyz23456789";
    var sb = new StringBuilder();
    for (int i = 0; i < 8; i++)
        sb.Append(znakovi[RandomNumberGenerator.GetInt32(znakovi.Length)]);
    return sb.ToString();
}

// ===== Prijava admina: potpisani kolačić (vrijedi 60 dana, a promjena lozinke odjavljuje sve) =====

static string Potpis(string podatak, string kljuc)
{
    using var h = new HMACSHA256(Encoding.UTF8.GetBytes(kljuc));
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

// ===== Prijava klijenata: potpisani kolačić (vrijedi 90 dana) =====

static string KlijentToken(string id, string kljuc, DateTimeOffset istek)
{
    var podatak = id + "." + istek.ToUnixTimeSeconds();
    return podatak + "." + Potpis(podatak, kljuc);
}

static string? KlijentIdIzTokena(string? token, string kljuc)
{
    if (string.IsNullOrEmpty(token)) return null;

    var dijelovi = token.Split('.');
    if (dijelovi.Length != 3 || !long.TryParse(dijelovi[1], out var istek)) return null;
    if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > istek) return null;

    var ocekivano = Encoding.UTF8.GetBytes(Potpis(dijelovi[0] + "." + dijelovi[1], kljuc));
    var dobiveno = Encoding.UTF8.GetBytes(dijelovi[2]);
    return CryptographicOperations.FixedTimeEquals(ocekivano, dobiveno) ? dijelovi[0] : null;
}

static void PostaviKlijentKolacic(HttpContext ctx, string id, string kljuc)
{
    var istek = DateTimeOffset.UtcNow.AddDays(90);
    ctx.Response.Cookies.Append("klijent_sesija", KlijentToken(id, kljuc, istek), new CookieOptions
    {
        HttpOnly = true,
        Secure = ctx.Request.IsHttps,
        SameSite = SameSiteMode.Lax,
        Expires = istek,
        Path = "/"
    });
}

// ===== Podaci =====

record RezervacijaDto(string Ime, string Telefon, string Datum, string Vrijeme);
record PrijavaDto(string Lozinka);
record BlokadaDto(string Datum, bool CijeliDan, List<string>? Vremena);
record RasponDto(string OdDatuma, string DoDatuma, int[]? Dani, bool CijeliDan, string? VrijemeOd, string? VrijemeDo, bool Ukloni);
record RucnaRezervacijaDto(string Ime, string? Telefon, string Datum, string Vrijeme);

record RegistracijaDto(string? Ime, string? Telefon, string? Lozinka);
record KlijentPrijavaDto(string? Telefon, string? Lozinka);
record PromjenaLozinkeDto(string? Stara, string? Nova);
record LozinkaDto(string? Lozinka);
record NaruciDto(string Datum, string Vrijeme);
record IdDto(string? Id);

// Rezervacija, blokada i račun u memoriji (Vrijeme "" kod blokade znači cijeli dan; Korisnik je ID računa ili prazno)
record Rez(string Id, string Ime, string Telefon, string Datum, string Vrijeme, string Korisnik);
record Blok(string Id, string Datum, string Vrijeme);
record Korisnik(string Id, string Ime, string Telefon, string Sol, string Hash);

enum Ishod { Ok, Zauzeto, Blokirano, Proslo, Limit }
enum OtkazIshod { Ok, NemaTermina, Prekasno }

// Stanje jednog dana: je li cijeli dan blokiran i koja su vremena zauzeta ili blokirana
class DanStanje
{
    public bool CijeliDan;
    public HashSet<string> Zauzeto = new();
}

// Hrvatsko vrijeme (CET zimi, CEST ljeti), bez ovisnosti o bazi vremenskih zona na serveru
static class Sat
{
    public static DateTime Sad()
    {
        var utc = DateTime.UtcNow;
        return utc.AddHours(Ljeto(utc) ? 2 : 1);
    }

    // Ljetno računanje vremena traje od zadnje nedjelje u ožujku do zadnje nedjelje u listopadu (u 01:00 UTC)
    static bool Ljeto(DateTime utc)
    {
        var pocetak = ZadnjaNedjelja(utc.Year, 3).AddHours(1);
        var kraj = ZadnjaNedjelja(utc.Year, 10).AddHours(1);
        return utc >= pocetak && utc < kraj;
    }

    static DateTime ZadnjaNedjelja(int godina, int mjesec)
    {
        var d = new DateTime(godina, mjesec, DateTime.DaysInMonth(godina, mjesec), 0, 0, 0, DateTimeKind.Utc);
        while (d.DayOfWeek != DayOfWeek.Sunday) d = d.AddDays(-1);
        return d;
    }

    // Početak termina kao datum i vrijeme
    public static bool Pocetak(string datum, string vrijeme, out DateTime pocetak) =>
        DateTime.TryParseExact(datum + " " + vrijeme, "yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out pocetak);
}

// Lozinke se ne spremaju, nego samo "otisak" (PBKDF2 sa solju), pa ih nitko ne može pročitati ni iz baze
static class Lozinke
{
    const int Iteracije = 100_000;
    static readonly byte[] LazniSol = new byte[16];

    public static (string sol, string hash) Napravi(string lozinka)
    {
        var sol = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(lozinka, sol, Iteracije, HashAlgorithmName.SHA256, 32);
        return (Convert.ToBase64String(sol), Convert.ToBase64String(hash));
    }

    // Računa se i kad korisnik ne postoji, da vrijeme odgovora ne otkriva postoji li račun
    public static bool Provjeri(Korisnik? korisnik, string lozinka)
    {
        var sol = korisnik != null ? Convert.FromBase64String(korisnik.Sol) : LazniSol;
        var hash = Rfc2898DeriveBytes.Pbkdf2(lozinka, sol, Iteracije, HashAlgorithmName.SHA256, 32);
        if (korisnik == null) return false;
        return CryptographicOperations.FixedTimeEquals(hash, Convert.FromBase64String(korisnik.Hash));
    }
}

/// <summary>
/// Trajna pohrana u Firebase Firestoreu, uz brzi pregled u memoriji.
/// Firestore čuva podatke (kolekcije "rezervacije", "blokade", "korisnici" i "postavke"), a server pri pokretanju učita
/// posljednjih 60 dana rezervacija i blokada, sve buduće termine i sve račune, pa se čitanja ne troše pri svakom
/// osvježavanju (besplatni plan ima dnevni limit).
/// </summary>
class Baza
{
    readonly FirestoreDb _db;
    readonly CollectionReference _rez;
    readonly CollectionReference _blok;
    readonly CollectionReference _kor;
    readonly SemaphoreSlim _brava = new(1, 1);
    readonly Dictionary<string, Rez> _rezervacije = new();
    readonly Dictionary<string, Blok> _blokade = new();
    readonly Dictionary<string, Korisnik> _korisnici = new();
    string? _tajna;
    bool _ucitano;

    public Baza(FirestoreDb db)
    {
        _db = db;
        _rez = db.Collection("rezervacije");
        _blok = db.Collection("blokade");
        _kor = db.Collection("korisnici");
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

        var od = Sat.Sad().AddDays(-60).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

        _rezervacije.Clear();
        var rez = await _rez.WhereGreaterThanOrEqualTo("datum", od).GetSnapshotAsync();
        foreach (var dok in rez.Documents)
            _rezervacije[dok.Id] = new Rez(dok.Id, Tekst(dok, "ime"), Tekst(dok, "telefon"),
                Tekst(dok, "datum"), Tekst(dok, "vrijeme"), Tekst(dok, "korisnik"));

        _blokade.Clear();
        var blok = await _blok.WhereGreaterThanOrEqualTo("datum", od).GetSnapshotAsync();
        foreach (var dok in blok.Documents)
            _blokade[dok.Id] = new Blok(dok.Id, Tekst(dok, "datum"), Tekst(dok, "vrijeme"));

        _korisnici.Clear();
        var kor = await _kor.GetSnapshotAsync();
        foreach (var dok in kor.Documents)
            _korisnici[dok.Id] = new Korisnik(dok.Id, Tekst(dok, "ime"), Tekst(dok, "telefon"),
                Tekst(dok, "sol"), Tekst(dok, "hash"));

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

    // Tajni ključ za potpisivanje prijava klijenata: stvori se jednom i spremi u Firestore
    public Task<string> Tajna() => Pod<string>(async () =>
    {
        if (_tajna != null) return _tajna;

        var dokument = _db.Collection("postavke").Document("tajna");
        var snimka = await dokument.GetSnapshotAsync();
        if (snimka.Exists && snimka.TryGetValue("kljuc", out string postojeci) && !string.IsNullOrEmpty(postojeci))
        {
            _tajna = postojeci;
            return postojeci;
        }

        var novi = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        await dokument.SetAsync(new Dictionary<string, object> { ["kljuc"] = novi });
        _tajna = novi;
        return novi;
    });

    // ===== Stanje i popisi =====

    public Task<Dictionary<string, DanStanje>> StanjeDana(IEnumerable<string> datumi) => Pod(() =>
    {
        var rezultat = datumi.Distinct().ToDictionary(x => x, _ => new DanStanje());

        foreach (var r in _rezervacije.Values)
            if (rezultat.TryGetValue(r.Datum, out var sr))
                sr.Zauzeto.Add(r.Vrijeme);

        foreach (var b in _blokade.Values)
            if (rezultat.TryGetValue(b.Datum, out var sb))
            {
                if (b.Vrijeme == "") sb.CijeliDan = true;
                else sb.Zauzeto.Add(b.Vrijeme);
            }

        return Task.FromResult(rezultat);
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

    public Task<List<Rez>> MojeRezervacije(string korisnik) => Pod(() => Task.FromResult(
        _rezervacije.Values
            .Where(r => r.Korisnik == korisnik)
            .OrderByDescending(r => r.Datum, StringComparer.Ordinal)
            .ThenByDescending(r => r.Vrijeme, StringComparer.Ordinal)
            .ToList()));

    // ===== Rezervacije =====

    // sad == null znači ručni upis admina (bez provjere prošlosti i ograničenja broja termina)
    public Task<Ishod> DodajRezervaciju(string ime, string telefon, string datum, string vrijeme,
        string korisnik, DateTime? sad, int minNaprijedMin, int maxAktivnih) => Pod(async () =>
    {
        if (sad != null)
        {
            if (Sat.Pocetak(datum, vrijeme, out var pocetak) && pocetak < sad.Value.AddMinutes(minNaprijedMin))
                return Ishod.Proslo;

            if (korisnik != "" && maxAktivnih > 0)
            {
                var sadTekst = sad.Value.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
                var aktivnih = _rezervacije.Values.Count(r =>
                    r.Korisnik == korisnik && string.CompareOrdinal(r.Datum + " " + r.Vrijeme, sadTekst) >= 0);
                if (aktivnih >= maxAktivnih)
                    return Ishod.Limit;
            }
        }

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
                ["korisnik"] = korisnik,
                ["kreirano"] = Timestamp.GetCurrentTimestamp()
            });
        }
        catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.AlreadyExists)
        {
            return Ishod.Zauzeto;
        }

        _rezervacije[id] = new Rez(id, ime, telefon, datum, vrijeme, korisnik);
        return Ishod.Ok;
    });

    public Task<bool> ObrisiRezervaciju(string id) => Pod(async () =>
    {
        await _rez.Document(id).DeleteAsync();
        _rezervacije.Remove(id);
        return true;
    });

    // Klijent otkazuje svoj termin (najkasnije satiLimit sati prije početka)
    public Task<(OtkazIshod, Rez?)> Otkazi(string id, string korisnik, DateTime sad, double satiLimit) =>
        Pod<(OtkazIshod, Rez?)>(async () =>
    {
        if (!_rezervacije.TryGetValue(id, out var rezervacija) || rezervacija.Korisnik != korisnik)
            return (OtkazIshod.NemaTermina, null);

        if (!Sat.Pocetak(rezervacija.Datum, rezervacija.Vrijeme, out var pocetak) || pocetak <= sad)
            return (OtkazIshod.NemaTermina, null);

        if ((pocetak - sad).TotalHours < satiLimit)
            return (OtkazIshod.Prekasno, null);

        await _rez.Document(id).DeleteAsync();
        _rezervacije.Remove(id);
        return (OtkazIshod.Ok, rezervacija);
    });

    // ===== Blokade =====

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
        if (_blokade.TryGetValue(BlokId(datum, vrijeme), out var postojeca))
            await ObrisiBlokade(new List<Blok> { postojeca });
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
                    makni.AddRange(_blokade.Values.Where(x => x.Datum == d));
                }
                else
                {
                    foreach (var v in vremena)
                        if (_blokade.TryGetValue(BlokId(d, v), out var postojeca)) makni.Add(postojeca);
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
                    ? _rezervacije.Values.Count(x => x.Datum == d)
                    : _rezervacije.Values.Count(x => x.Datum == d
                        && string.CompareOrdinal(x.Vrijeme, vOd) >= 0
                        && string.CompareOrdinal(x.Vrijeme, vDo) < 0);
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

    // ===== Računi klijenata =====

    public Task<Korisnik?> NadiKorisnika(string id) => Pod<Korisnik?>(() =>
        Task.FromResult(_korisnici.TryGetValue(id, out var k) ? k : null));

    public Task<List<Korisnik>> SviKorisnici() => Pod(() => Task.FromResult(
        _korisnici.Values.OrderBy(x => x.Ime, StringComparer.CurrentCultureIgnoreCase).ToList()));

    // Vraća novi račun ili null ako račun s tim brojem već postoji
    public Task<Korisnik?> Registriraj(string id, string ime, string telefon, string sol, string hash) =>
        Pod<Korisnik?>(async () =>
    {
        if (_korisnici.ContainsKey(id)) return null;

        try
        {
            await _kor.Document(id).CreateAsync(new Dictionary<string, object>
            {
                ["ime"] = ime,
                ["telefon"] = telefon,
                ["sol"] = sol,
                ["hash"] = hash,
                ["kreirano"] = Timestamp.GetCurrentTimestamp()
            });
        }
        catch (Grpc.Core.RpcException ex) when (ex.StatusCode == Grpc.Core.StatusCode.AlreadyExists)
        {
            return null;
        }

        var novi = new Korisnik(id, ime, telefon, sol, hash);
        _korisnici[id] = novi;
        return novi;
    });

    public Task<bool> PostaviLozinku(string id, string sol, string hash) => Pod(async () =>
    {
        if (!_korisnici.TryGetValue(id, out var postojeci)) return false;

        await _kor.Document(id).UpdateAsync(new Dictionary<string, object> { ["sol"] = sol, ["hash"] = hash });
        _korisnici[id] = postojeci with { Sol = sol, Hash = hash };
        return true;
    });

    // Briše račun; ako je sveRezervacije true, brišu se i sve njegove rezervacije (i starije od 60 dana)
    public Task<bool> ObrisiKorisnika(string id, bool sveRezervacije) => Pod(async () =>
    {
        if (sveRezervacije)
        {
            var snimka = await _rez.WhereEqualTo("korisnik", id).GetSnapshotAsync();
            foreach (var dio in snimka.Documents.Chunk(400))
            {
                var batch = _db.StartBatch();
                foreach (var dok in dio)
                    batch.Delete(dok.Reference);
                await batch.CommitAsync();
            }

            foreach (var stara in _rezervacije.Values.Where(x => x.Korisnik == id).ToList())
                _rezervacije.Remove(stara.Id);
        }

        await _kor.Document(id).DeleteAsync();
        _korisnici.Remove(id);
        return true;
    });
}
