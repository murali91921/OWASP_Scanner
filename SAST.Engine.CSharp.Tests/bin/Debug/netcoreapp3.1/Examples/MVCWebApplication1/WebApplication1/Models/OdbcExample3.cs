using System;
using System.Data.Odbc;

class OdbcExample3
{
    static void UnsafeCode(string name, decimal price,string connectionstring)
    {
        string queryString = $"SELECT ProductID, UnitPrice, Name from dbo.products WHERE Name = '{name}' and UnitPrice >= {price}";
        queryString = "SELECT ProductID, UnitPrice, Name from dbo.products WHERE Name = '" + name + "' and UnitPrice >= " + price;
        //queryString = "SELECT ProductID, UnitPrice, Name from dbo.products WHERE Name = @name and UnitPrice >= @price ";
        using (OdbcConnection connection = new OdbcConnection(connectionstring))
        {
            OdbcCommand command = new OdbcCommand(queryString, connection);
            command.CommandText = queryString;
            try
            {
                OdbcDataAdapter dataAdapter = new OdbcDataAdapter();
                connection.Open();
                OdbcDataReader reader = command.ExecuteReader();
                while (reader.Read())
                {
                    Console.WriteLine("\t{0}\t{1}\t{2}",
                        reader[0], reader[1], reader[2]);
                }
                reader.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            Console.ReadLine();
        }
    }
}