using System;
using System.Data;
using System.Data.SqlClient;

class SqlServerExample1
{
    public string queryString;
    public DataSet UnsafeCode(string name, decimal price)
    {
        string connectionString = "Data Source=(local);Initial Catalog=Northwind;Integrated Security=true;";
        // queryString = $"{queryString} WHERE Name = '{name}' and UnitPrice >= {price}";
        //queryString = queryString + " WHERE Name = '" + name + "' and UnitPrice >= " + price;
        // queryString = queryString + " WHERE Name = @name and UnitPrice >= @price";
        //queryString = ;
        DataSet products = new DataSet();
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            SqlDataAdapter adapter = new SqlDataAdapter(queryString, connection);
            adapter = new SqlDataAdapter(selectConnectionString: connectionString, selectCommandText: queryString);
            adapter = new SqlDataAdapter(selectConnection: connection, selectCommandText: queryString);
            adapter.SelectCommand.Parameters.AddWithValue("@Name", name);
            adapter.SelectCommand.Parameters.AddWithValue("@Price", price);
            adapter.SelectCommand.CommandText = queryString;
            adapter.UpdateCommand.CommandText = queryString;
            adapter.InsertCommand.CommandText = queryString;
            adapter.DeleteCommand.CommandText = queryString;
            adapter.Fill(products, "Customers");
        }
        return products;
    }
    SqlServerExample1()
    {
        queryString = "SELECT ProductID, UnitPrice, Name from dbo.products";
    }
}