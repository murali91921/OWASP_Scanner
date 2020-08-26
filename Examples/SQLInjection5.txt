using System;
using System.Data.OracleClient;

class OracleExample4
{
    static void UnsafeCode(string name, decimal price, string connectionstring)
    {
        string queryString = $"SELECT ProductID, UnitPrice, Name from dbo.products WHERE Name = '{name}' and UnitPrice >= {price}";
        queryString = "SELECT ProductID, UnitPrice, Name from dbo.products WHERE Name = '" + name + "' and UnitPrice >= " + price;
        //queryString = "SELECT ProductID, UnitPrice, Name from dbo.products WHERE Name = @name and UnitPrice >= @price ";
        using (OracleConnection connection = new OracleConnection(connectionstring))
        {
            OracleCommand command = new OracleCommand(queryString, connection);
            command.CommandText = queryString;
            try
            {
                connection.Open();
                OracleDataReader reader = command.ExecuteReader();
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