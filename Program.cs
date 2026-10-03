using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var dbPath = Environment.GetEnvironmentVariable("DB_PATH") ?? "raspored.db";
var connStr = $"Data Source={dbPath}";
var adminLozinka = Environment.GetEnvironmentVariable("ADMIN_PASSWORD");

string[] radnoVrijeme =
{
    "11:00", "11:30", "12:00", "12:30", "13:00", "13:30",
    "14:00", "14:30", "15:00", "15:30", "16:00", "16:30",
    "17:00", "17:30", "18:00", "18:30", "19:00", "19:30", "20:00"
};

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
            Vrijeme TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_termin ON Rezervacije(Datum, Vrijeme);";
    command.ExecuteNonQuery();
}

// JAVNO: samo zauzeta vremena za jedan datum (bez imena)
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
    command.CommandText = "SELECT Id, Ime, Datum, Vrijeme FROM Rezervacije ORDER BY Datum ASC, Vrijeme ASC";
    using var reader = command.ExecuteReader();
    while (reader.Read())
    {
        lista.Add(new
        {
            id = reader.GetInt32(0),
            ime = reader.GetString(1),
            datum = reader.GetString(2),
            vrijeme = reader.GetString(3)
        });
    }
    return Results.Ok(lista);
});

// JAVNO: nova rezervacija
app.MapPost("/api/rezervacije", async (HttpRequest request) =>
{
    var form = await request.ReadFromJsonAsync<RezervacijaDto>();
    if (form == null) return Results.BadRequest();

    var ime = form.Ime?.Trim() ?? "";
    if (ime.Length == 0 || ime.Length > 100)
        return Results.BadRequest("Neispravno ime.");

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
        command.CommandText = "INSERT INTO Rezervacije (Ime, Datum, Vrijeme) VALUES ($ime, $datum, $vrijeme)";
        command.Parameters.AddWithValue("$ime", ime);
        command.Parameters.AddWithValue("$datum", form.Datum);
        command.Parameters.AddWithValue("$vrijeme", form.Vrijeme);
        command.ExecuteNonQuery();
    }
    catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
    {
        return Results.Conflict("Termin je već zauzet.");
    }
    return Results.Ok();
});

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

record RezervacijaDto(string Ime, string Datum, string Vrijeme);
