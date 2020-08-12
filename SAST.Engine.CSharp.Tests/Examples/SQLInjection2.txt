using System;
using System.Data;
using System.Data.OleDb;

class OleDbExample2
{
    static void UnsafeCode(string name, decimal price)
    {
        string connectionString = "Data Source=(local);Initial Catalog=Northwind;Integrated Security=true;";
        string queryString = $"SELECT ProductID, UnitPrice, Name from dbo.products WHERE Name = '{name}' and UnitPrice >= {price}";
        queryString = "SELECT ProductID, UnitPrice, Name from dbo.products WHERE Name = '" + name + "' and UnitPrice >= " + price;
        //queryString = "SELECT ProductID, UnitPrice, Name from dbo.products WHERE Name = @name and UnitPrice >= @price ";
        using (OleDbConnection connection = new OleDbConnection(connectionString))
        {
            OleDbCommand command = new OleDbCommand(queryString, connection);
            command.CommandText = queryString;
            try
            {
                connection.Open();
                OleDbDataReader reader = command.ExecuteReader();
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