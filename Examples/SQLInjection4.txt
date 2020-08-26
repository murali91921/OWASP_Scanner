using System;
using System.Data.SQLite;

class SqliteExample4
{
    static void UnsafeCode(string name, string connectionString)
    {
        string queryString = "SELECT CUSTOMER_ID, NAME FROM DEMO.CUSTOMER WHERE NAME = '" + name + "'";
        using (SQLiteConnection connection = new SQLiteConnection(connectionString))
        {
            SQLiteCommand command = connection.CreateCommand();
            command.CommandText = queryString;

            try
            {
                connection.Open();
                SQLiteCommand.Execute(queryString,SQLiteExecuteType.Reader,connectionString,name);
                SQLiteDataReader reader = command.ExecuteReader();
                while (reader.Read())
                {
                    Console.WriteLine("\t{0}\t{1}",
                        reader[0], reader[1]);
                }
                reader.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}