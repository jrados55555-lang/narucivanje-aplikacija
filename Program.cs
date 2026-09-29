using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

string putanjaBaze = "Data Source=raspored.db";

using (var konekcija = new SqliteConnection(putanjaBaze))
{
    konekcija.Open();
    var naredba = konekcija.CreateCommand();
    naredba.CommandText = @"
        CREATE TABLE IF NOT EXISTS Termini (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            ImeKlijenta TEXT NOT NULL,
            Usluga TEXT NOT NULL,
            DatumVrijeme TEXT NOT NULL
        );";
    naredba.ExecuteNonQuery();
}

app.MapGet("/api/termini", () =>
{
    var lista = new List<object>();
    using (var konekcija = new SqliteConnection(putanjaBaze))
    {
        konekcija.Open();
        var naredba = konekcija.CreateCommand();
        naredba.CommandText = "SELECT Id, ImeKlijenta, Usluga, DatumVrijeme FROM Termini ORDER BY DatumVrijeme ASC;";
        using (var citac = naredba.ExecuteReader())
        {
            while (citac.Read())
            {
                lista.Add(new {
                    id = citac.GetInt32(0),
                    ime = citac.GetString(1),
                    usluga = citac.GetString(2),
                    datum = citac.GetString(3)
                });
            }
        }
    }
    return Results.Ok(lista);
});

app.MapPost("/api/termini", (ZahtjevTermin zahtjev) =>
{
    using (var konekcija = new SqliteConnection(putanjaBaze))
    {
        konekcija.Open();
        
        var provjera = konekcija.CreateCommand();
        provjera.CommandText = "SELECT COUNT(*) FROM Termini WHERE DatumVrijeme = $datum;";
        provjera.Parameters.AddWithValue("$datum", zahtjev.DatumVrijeme);
        long zauzeto = (long)provjera.ExecuteScalar();

        if (zauzeto > 0)
        {
            return Results.BadRequest("Termin je već zauzet!");
        }

        var naredba = konekcija.CreateCommand();
        naredba.CommandText = "INSERT INTO Termini (ImeKlijenta, Usluga, DatumVrijeme) VALUES ($ime, $usluga, $datum);";
        naredba.Parameters.AddWithValue("$ime", zahtjev.ImeKlijenta);
        naredba.Parameters.AddWithValue("$usluga", zahtjev.Usluga);
        naredba.Parameters.AddWithValue("$datum", zahtjev.DatumVrijeme);
        naredba.ExecuteNonQuery();
    }
    return Results.Ok("Termin uspješno rezerviran!");
});

app.Run();

record ZahtjevTermin(string ImeKlijenta, string Usluga, string DatumVrijeme);