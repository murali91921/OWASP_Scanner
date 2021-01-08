using SAST.Engine.CSharp.Enums;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using SAST.Engine.CSharp.Constants;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;

namespace SAST.Engine.CSharp.Scanners
{
    internal class SqlInjectionScanner : IScanner
    {
        private static string[] CommandClasses = {
            KnownType.System_Web_UI_WebControls_SqlDataSource,
            KnownType.System_Data_Common_DbCommand,
            KnownType.System_Data_IDbCommand,
            KnownType.System_Data_IDbDataAdapter,
            KnownType.System_Data_OleDb_OleDbCommand,
            KnownType.System_Data_OleDb_OleDbDataAdapter,
            KnownType.System_Data_OracleClient_OracleCommand,
            KnownType.System_Data_OracleClient_OracleDataAdapter,
            KnownType.System_Data_SqlClient_SqlCommand,
            KnownType.System_Data_SqlClient_SqlDataAdapter,
            KnownType.System_Data_Odbc_OdbcDataAdapter,
            KnownType.System_Data_Odbc_OdbcCommand,
            KnownType.System_Data_SQLite_SQLiteCommand,
            KnownType.System_Data_SQLite_SQLiteDataAdapter,
            KnownType.Mono_Data_Sqlite_SqliteCommand,
            KnownType.Mono_Data_Sqlite_SqliteDataAdapter,
            KnownType.Microsoft_Data_Sqlite_SqliteCommand,
            KnownType.MySql_Data_MySqlClient_MySqlCommand,
            KnownType.MySql_Data_MySqlClient_MySqlDataAdapter
            };
        private static string[] CommandTextParameters = {
            "CommandText",
            "selectCommandText",
            "cmdText",
            "selectCommand"
            };
        private static string[] CommandExecuteMethods = {
            KnownMethod.System_Data_Linq_DataContext_ExecuteCommand,
            KnownMethod.System_Data_Linq_DataContext_ExecuteQuery,
            KnownMethod.System_Data_SQLite_SQLiteCommand_Execute,
            KnownMethod.System_Data_Entity_Database_ExecuteSqlCommand,
            KnownMethod.System_Data_Entity_Database_ExecuteSqlCommandAsync,
            KnownMethod.System_Data_Entity_Database_SqlQuery,
            KnownMethod.System_Data_Entity_DbSet_TEntity_SqlQuery,
            KnownMethod.Microsoft_EntityFrameworkCore_DbSet_TEntity_FromSqlRaw,
            KnownMethod.Microsoft_EntityFrameworkCore_DbSet_TEntity_FromSql,
            KnownMethod.Microsoft_EntityFrameworkCore_DbSet_TEntity_FromSqlInterpolated,
            KnownMethod.Microsoft_EntityFrameworkCore_Infrastructure_DatabaseFacade_ExecuteSqlCommand,
            KnownMethod.Microsoft_EntityFrameworkCore_Infrastructure_DatabaseFacade_ExecuteSqlCommandAsync,
            KnownMethod.Microsoft_EntityFrameworkCore_Infrastructure_DatabaseFacade_ExecuteSqlRaw,
            KnownMethod.Microsoft_EntityFrameworkCore_Infrastructure_DatabaseFacade_ExecuteSqlRawAsync,
            KnownMethod.Microsoft_EntityFrameworkCore_Infrastructure_DatabaseFacade_ExecuteSqlInterpolated,
            KnownMethod.Microsoft_EntityFrameworkCore_Infrastructure_DatabaseFacade_ExecuteSqlInterpolatedAsync,
            KnownMethod.Microsoft_Practices_EnterpriseLibrary_Data_Database_GetSqlStringCommand,
            KnownMethod.Microsoft_Practices_EnterpriseLibrary_Data_Database_ExecuteScalar,
            KnownMethod.Microsoft_Practices_EnterpriseLibrary_Data_Database_ExecuteReader,
            KnownMethod.Microsoft_Practices_EnterpriseLibrary_Data_Database_ExecuteNonQuery,
            KnownMethod.Microsoft_Practices_EnterpriseLibrary_Data_Database_ExecuteDataSet,
        };
        private static string[] CommandExecuteParameters = {
            "query",
            "command",
            "commandText"
        };
        private static string[] CommandTextProperties = {
            KnownType.System_Data_Common_DbCommand_CommandText,
            KnownType.System_Data_IDbCommand_CommandText,
            KnownType.System_Data_SqlClient_SqlCommand_CommandText,
            KnownType.System_Data_OleDb_OleDbCommand_CommandText,
            KnownType.System_Data_Odbc_OdbcCommand_CommandText,
            KnownType.System_Data_OracleClient_OracleCommand_CommandText,
            KnownType.Mono_Data_Sqlite_SqliteCommand_CommandText,
            KnownType.Microsoft_Data_Sqlite_SqliteCommand_CommandText,
            KnownType.System_Data_SQLite_SQLiteCommand_CommandText,
            KnownType.System_Web_UI_WebControls_SqlDataSource_SelectCommand,
            KnownType.System_Web_UI_WebControls_SqlDataSource_InsertCommand,
            KnownType.System_Web_UI_WebControls_SqlDataSource_UpdateCommand,
            KnownType.System_Web_UI_WebControls_SqlDataSource_DeleteCommand,
            KnownType.System_Web_UI_WebControls_SqlDataSourceView_SelectCommand,
            KnownType.System_Web_UI_WebControls_SqlDataSourceView_InsertCommand,
            KnownType.System_Web_UI_WebControls_SqlDataSourceView_UpdateCommand,
            KnownType.System_Web_UI_WebControls_SqlDataSourceView_DeleteCommand
        };

        /// <summary>
        /// This method will find the SQL Injection Vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            HashSet<SyntaxNode> lstVulnerableCheck = new HashSet<SyntaxNode>();
            var objectCreationExpressions = syntaxNode.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
            foreach (var objectCreation in objectCreationExpressions)
            {
                ITypeSymbol typeSymbol = model.GetTypeSymbol(objectCreation);
                if (typeSymbol == null)
                    continue;

                if (!Utils.DerivesFromAny(typeSymbol, CommandClasses))
                    continue;

                if (objectCreation.ArgumentList != null && objectCreation.ArgumentList.Arguments.Count > 0)
                {
                    var argument = objectCreation.ArgumentList.Arguments.First();
                    if (Utils.DerivesFrom(typeSymbol, KnownType.System_Web_UI_WebControls_SqlDataSource) && argument.NameColon == null)
                        argument = objectCreation.ArgumentList.Arguments.Last();

                    if (argument.NameColon != null)
                        foreach (var item in objectCreation.ArgumentList.Arguments)
                            if (CommandTextParameters.Any(text => text == item.NameColon.Name.ToString()))
                            {
                                argument = item;
                                break;
                            }
                    if (model.GetTypeSymbol(argument.Expression).SpecialType == SpecialType.System_String)
                        lstVulnerableCheck.Add(argument.Expression);
                }
                if (objectCreation.Initializer != null)
                {
                    var commandTextInitializer = objectCreation.Initializer.Expressions.OfType<AssignmentExpressionSyntax>().FirstOrDefault(
                        obj => (obj.Left as IdentifierNameSyntax).Identifier.ValueText == "CommandText");
                    if (commandTextInitializer != null)
                        lstVulnerableCheck.Add(commandTextInitializer.Right);
                }
            }
            var methods = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
            foreach (var method in methods)
            {
                IMethodSymbol symbol = model.GetSymbol(method) as IMethodSymbol;
                if (symbol == null)
                {
                    if (method.Expression is MemberAccessExpressionSyntax memberAccess)
                    {
                        if (memberAccess.Name.ToString() == "FromSql")
                        {
                            ITypeSymbol typeSymbol = model.GetTypeSymbol(memberAccess.Expression);
                            if (typeSymbol == null || typeSymbol.OriginalDefinition.ToString() + "." + memberAccess.Name.ToString() != "Microsoft.EntityFrameworkCore.DbSet<TEntity>.FromSql")
                                continue;
                        }
                        else
                            continue;
                    }
                    else
                        continue;
                }
                else if (!CommandExecuteMethods.Any(obj => obj == symbol.ReceiverType.OriginalDefinition.ToString() + "." + symbol.Name.ToString()))
                    continue;

                foreach (var argument in method.ArgumentList.Arguments)
                {
                    ITypeSymbol typeSymbol = model.GetTypeSymbol(argument.Expression);

                    if (typeSymbol == null || typeSymbol.SpecialType != SpecialType.System_String)
                        continue;

                    if (argument.NameColon == null || CommandExecuteParameters.Any(param => param == argument.NameColon.Name.ToString()))
                        lstVulnerableCheck.Add(argument.Expression);
                }
            }
            var assignments = syntaxNode.DescendantNodes().OfType<AssignmentExpressionSyntax>().Where(
                obj => !obj.Right.IsKind(SyntaxKind.ObjectCreationExpression)).ToList();
            foreach (var item in assignments)
            {
                IPropertySymbol symbol = model.GetSymbol(item.Left) as IPropertySymbol;

                if (symbol == null)
                    continue;

                if (CommandTextProperties.Any(obj => obj == symbol.ToString()))
                    lstVulnerableCheck.Add(item.Right);
            }
            foreach (var item in lstVulnerableCheck)
                if (Utils.IsVulnerable(item, model, solution))
                    lstVulnerableStatements.Add(item.Parent);

            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, ScannerType.SqlInjection);
        }
    }
}