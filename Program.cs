using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

// Inicijalizacija SQLite baze
using (var connection = new SqliteConnection("Data Source=raspored.db"))
{
    connection.Open();
    var command = connection.CreateCommand();
    command.CommandText = @"
        CREATE TABLE IF NOT EXISTS Rezervacije (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Ime TEXT NOT NULL,
            Datum TEXT NOT NULL,
            Vrijeme TEXT NOT NULL
        );";
    command.ExecuteNonQuery();
}

// GET endpoint: Dohvaćanje svih rezervacija
app.MapGet("/api/rezervacije", () =>
{
    var lista = new List<object>();
    using (var connection = new SqliteConnection("Data Source=raspored.db"))
    {
        connection.Open();
        var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, Ime, Datum, Vrijeme FROM Rezervacije ORDER BY Id DESC";
        using (var reader = command.ExecuteReader())
        {
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
        }
    }
    return Results.Ok(lista);
});

// POST endpoint za spremanje novih rezervacija
app.MapPost("/api/rezervacije", async (HttpRequest request) =>
{
    var form = await request.ReadFromJsonAsync<RezervacijaDto>();
    if (form == null) return Results.BadRequest();

    using (var connection = new SqliteConnection("Data Source=raspored.db"))
    {
        connection.Open();
        var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO Rezervacije (Ime, Datum, Vrijeme) VALUES ($ime, $datum, $vrijeme)";
        command.Parameters.AddWithValue("$ime", form.Ime);
        command.Parameters.AddWithValue("$datum", form.Datum);
        command.Parameters.AddWithValue("$vrijeme", form.Vrijeme);
        command.ExecuteNonQuery();
    }
    return Results.Ok();
});

app.Run();

record RezervacijaDto(string Ime, string Datum, string Vrijeme);
