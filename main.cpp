#include <iostream>
#include <windows.h>
#include <sqlext.h>
#include <sqltypes.h>
#include <sql.h>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <fstream>

// Helper function declarations
void displaySQLError(SQLHANDLE handle, SQLSMALLINT type);
bool logAttempt(const std::string& username, bool success, const std::string& errorMsg = "");
void runSecureQuery(SQLHDBC dbc);
void runVulnerableQuery(SQLHDBC dbc);
void showUserData(SQLHSTMT stmt);
void displayMenu();
bool validateInput(const std::string& input);

int main() {
    // Database connection objects
    SQLHENV env;      // Environment handle
    SQLHDBC dbc;      // Connection handle
    SQLHSTMT stmt;    // Statement handle
    SQLRETURN ret;    // Return value from ODBC functions

    // User credentials
    std::string username, password;
    bool isLoggedIn = false;
    int loginAttempts = 0;
    const int MAX_ATTEMPTS = 3;

    std::cout << "=================================================\n";
    std::cout << "DATABASE AUTHENTICATION SYSTEM - DEMONSTRATION\n";
    std::cout << "=================================================\n";
    std::cout << "This program demonstrates SQL injection vulnerabilities\n";
    std::cout << "for educational purposes only.\n\n";

    // 1. Allocate environment handle
    if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &env)) {
        std::cout << "Failed to allocate environment handle.\n";
        return 1;
    }

    // 2. Set ODBC version
    if (SQL_SUCCESS != SQLSetEnvAttr(env, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0)) {
        std::cout << "Failed to set ODBC version.\n";
        SQLFreeHandle(SQL_HANDLE_ENV, env);
        return 1;
    }

    // 3. Allocate connection handle
    if (SQL_SUCCESS != SQLAllocHandle(SQL_HANDLE_DBC, env, &dbc)) {
        std::cout << "Failed to allocate connection handle.\n";
        SQLFreeHandle(SQL_HANDLE_ENV, env);
        return 1;
    }

    // Connection string (in a real app, these credentials should never be hardcoded)
    SQLWCHAR connStr[] = L"DSN=MyMSSQLServer;SERVER=localhost;DATABASE=Alvina;UID=Alvina;PWD=Al456852;";

    // 4. Connect to the database
    std::cout << "Connecting to database...\n";
    ret = SQLDriverConnectW(dbc, NULL, connStr, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_COMPLETE);

    if (!SQL_SUCCEEDED(ret)) {
        std::cout << "WARNING: Database connection failed.\n";
        displaySQLError(dbc, SQL_HANDLE_DBC);
        SQLFreeHandle(SQL_HANDLE_DBC, dbc);
        SQLFreeHandle(SQL_HANDLE_ENV, env);
        return 1;
    }

    std::cout << "CONNECTED: Connected to database successfully.\n\n";

    // Authentication loop
    while (loginAttempts < MAX_ATTEMPTS && !isLoggedIn) {
        std::cout << "LOGIN SCREEN (Attempt " << loginAttempts + 1 << " of " << MAX_ATTEMPTS << ")\n";
        std::cout << "Username: ";
        getline(std::cin, username);
        std::cout << "Password: ";
        getline(std::cin, password);

        // Allocate statement handle
        SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

        // VULNERABLE IMPLEMENTATION FOR DEMONSTRATION
        // This code is intentionally vulnerable to SQL injection
        std::string queryStr = "SELECT user_id, username, role FROM users WHERE username = '"
            + username + "' AND password = '" + password + "'";

        // Display the raw query (for educational purposes)
        std::cout << "\nExecuting query: " << queryStr << std::endl;

        // Convert std::string to SQLWCHAR*
        std::wstring wqueryStr(queryStr.begin(), queryStr.end());
        SQLWCHAR* wquery = const_cast<SQLWCHAR*>(wqueryStr.c_str());

        ret = SQLExecDirectW(stmt, wquery, SQL_NTS);

        if (SQL_SUCCEEDED(ret)) {
            SQLLEN rowCount;
            SQLRowCount(stmt, &rowCount);

            if (rowCount > 0) {
                isLoggedIn = true;

                // Display user information
                SQLWCHAR userId[10], dbUsername[50], role[20];
                SQLLEN lenUserId, lenUsername, lenRole;

                // Bind result columns
                SQLBindCol(stmt, 1, SQL_C_WCHAR, userId, sizeof(userId), &lenUserId);
                SQLBindCol(stmt, 2, SQL_C_WCHAR, dbUsername, sizeof(dbUsername), &lenUsername);
                SQLBindCol(stmt, 3, SQL_C_WCHAR, role, sizeof(role), &lenRole);

                // Fetch and display user data
                if (SQL_SUCCESS == SQLFetch(stmt)) {
                    std::wcout << L"\nSUCCESS: Login successful!\n";
                    std::wcout << L"User ID: " << userId << std::endl;
                    std::wcout << L"Username: " << dbUsername << std::endl;
                    std::wcout << L"Role: " << role << std::endl << std::endl;

                    // Convert wide string to narrow for logging
                    std::string narrowUsername(username.begin(), username.end());

                    // Log the successful login
                    logAttempt(narrowUsername, true);
                }

                // Note the vulnerability here: SQL injection could return multiple rows
                // or could modify/delete data with the right injection string
                if (SQL_SUCCESS == SQLFetch(stmt)) {
                    std::cout << "WARNING: Multiple users match the criteria - possible SQL injection!\n";
                }
            }
            else {
                std::cout << "ERROR: Invalid username or password.\n\n";
                logAttempt(username, false, "Invalid credentials");
            }
        }
        else {
            std::cout << "ERROR: Query execution failed.\n";
            displaySQLError(stmt, SQL_HANDLE_STMT);
            logAttempt(username, false, "Query execution failure");
        }

        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
        loginAttempts++;

        if (!isLoggedIn && loginAttempts < MAX_ATTEMPTS) {
            std::cout << "Please try again.\n\n";
        }
    }

    // After authentication
    if (isLoggedIn) {
        int choice = 0;

        while (choice != 5) {
            displayMenu();
            std::cout << "Enter your choice: ";
            std::cin >> choice;
            std::cin.ignore(); // Clear the newline

            // Common string variables to be used across cases
            std::string searchTerm;
            std::string queryStr;
            std::string param;
            std::wstring wQuery;
            std::wstring wParam;

            // Initialize safeQuery here to ensure it's available in all cases
            // Using a dynamically allocated buffer to avoid the initialization issue
            SQLWCHAR* safeQuery = nullptr;

            // Declare these variables for all cases
            SQLHSTMT localStmt = SQL_NULL_HSTMT;
            char charChoice = 'n';

            switch (choice) {
            case 1: // Vulnerable search
                std::cout << "Enter search term: ";
                getline(std::cin, searchTerm);

                std::cout << "VULNERABLE QUERY - Demonstrating SQL Injection Risk\n";
                std::cout << "-----------------------------------------------\n";

                // Allocate statement handle
                SQLAllocHandle(SQL_HANDLE_STMT, dbc, &localStmt);

                // Create vulnerable query
                queryStr = "SELECT user_id, username, email, role FROM users WHERE username LIKE '%"
                    + searchTerm + "%' OR email LIKE '%" + searchTerm + "%'";

                std::cout << "Executing: " << queryStr << std::endl << std::endl;

                // Convert to wide string
                wQuery = std::wstring(queryStr.begin(), queryStr.end());

                // Execute the query
                ret = SQLExecDirectW(localStmt, const_cast<SQLWCHAR*>(wQuery.c_str()), SQL_NTS);

                if (SQL_SUCCEEDED(ret)) {
                    showUserData(localStmt);
                }
                else {
                    displaySQLError(localStmt, SQL_HANDLE_STMT);
                }

                SQLFreeHandle(SQL_HANDLE_STMT, localStmt);
                break;

            case 2: // Parameterized search (safe)
            {
                std::cout << "Enter search term: ";
                getline(std::cin, searchTerm);

                std::cout << "SAFE QUERY - Using Parameterized Statements\n";
                std::cout << "---------------------------------------\n";

                // Allocate statement handle
                SQLAllocHandle(SQL_HANDLE_STMT, dbc, &localStmt);

                // Create a clean initialized buffer for safeQuery
                std::wstring tempSafeQuery = L"SELECT user_id, username, email, role FROM users WHERE username LIKE ? OR email LIKE ?";
                safeQuery = new SQLWCHAR[tempSafeQuery.length() + 1];
                wcscpy_s(safeQuery, tempSafeQuery.length() + 1, tempSafeQuery.c_str());

                // Prepare parameterized query
                SQLPrepareW(localStmt, safeQuery, SQL_NTS);

                // Create parameter values with wildcards
                param = "%" + searchTerm + "%";
                wParam = std::wstring(param.begin(), param.end());

                // Bind parameters
                SQLBindParameter(localStmt, 1, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
                    wParam.length(), 0, (SQLPOINTER)wParam.c_str(), 0, NULL);
                SQLBindParameter(localStmt, 2, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
                    wParam.length(), 0, (SQLPOINTER)wParam.c_str(), 0, NULL);

                std::cout << "Executing parameterized query with search term: '" << searchTerm << "'\n\n";

                // Execute the query
                ret = SQLExecute(localStmt);

                if (SQL_SUCCEEDED(ret)) {
                    showUserData(localStmt);
                }
                else {
                    displaySQLError(localStmt, SQL_HANDLE_STMT);
                }

                // Clean up
                delete[] safeQuery;
                SQLFreeHandle(SQL_HANDLE_STMT, localStmt);
            }
            break;

            case 3: // Run demonstration of vulnerable queries
                runVulnerableQuery(dbc);
                break;

            case 4: // Run demonstration of secure queries
                runSecureQuery(dbc);
                break;

            case 5: // Exit
                std::cout << "Logging out...\n";
                break;

            default:
                std::cout << "Invalid choice. Please try again.\n";
            }

            if (choice != 5) {
                std::cout << "\nPress Enter to continue...";
                std::cin.get();
            }
        }
    }
    else {
        std::cout << "Maximum login attempts exceeded. Exiting.\n";
    }

    // Clean up resources
    std::cout << "Disconnecting from database...\n";
    SQLDisconnect(dbc);
    SQLFreeHandle(SQL_HANDLE_DBC, dbc);
    SQLFreeHandle(SQL_HANDLE_ENV, env);

    std::cout << "Program terminated.\n";
    return 0;
}

// Display ODBC error messages
void displaySQLError(SQLHANDLE handle, SQLSMALLINT type) {
    SQLWCHAR sqlState[6];
    SQLINTEGER nativeError;
    SQLWCHAR messageText[SQL_MAX_MESSAGE_LENGTH];
    SQLSMALLINT textLength;

    std::cout << "SQL Error Details:\n";

    while (SQLGetDiagRecW(type, handle, 1, sqlState, &nativeError,
        messageText, sizeof(messageText) / sizeof(SQLWCHAR), &textLength) == SQL_SUCCESS) {
        std::wcout << L"  SQLSTATE: " << sqlState << std::endl;
        std::wcout << L"  Native Error: " << nativeError << std::endl;
        std::wcout << L"  Message: " << messageText << std::endl;
    }
}

// Log login attempts
bool logAttempt(const std::string& username, bool success, const std::string& errorMsg) {
    // Get current time
    time_t now = time(0);
    struct tm timeinfo;
    char timestamp[80];

    // Use localtime_s for better safety (avoid C4996 warning)
    localtime_s(&timeinfo, &now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeinfo);

    // Open log file
    std::ofstream logFile("auth_log.txt", std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file.\n";
        return false;
    }

    // Write log entry
    logFile << timestamp << " | User: " << std::setw(15) << std::left << username
        << " | Status: " << (success ? "SUCCESS" : "FAILURE");

    if (!errorMsg.empty()) {
        logFile << " | Error: " << errorMsg;
    }

    logFile << std::endl;
    logFile.close();
    return true;
}

// Display formatted user data from query results
void showUserData(SQLHSTMT stmt) {
    SQLWCHAR userId[10], username[50], email[100], role[20];
    SQLLEN lenUserId, lenUsername, lenEmail, lenRole;

    // Bind result columns
    SQLBindCol(stmt, 1, SQL_C_WCHAR, userId, sizeof(userId), &lenUserId);
    SQLBindCol(stmt, 2, SQL_C_WCHAR, username, sizeof(username), &lenUsername);
    SQLBindCol(stmt, 3, SQL_C_WCHAR, email, sizeof(email), &lenEmail);
    SQLBindCol(stmt, 4, SQL_C_WCHAR, role, sizeof(role), &lenRole);

    // Print table header
    std::cout << std::setw(10) << std::left << "USER ID"
        << std::setw(20) << std::left << "USERNAME"
        << std::setw(30) << std::left << "EMAIL"
        << std::setw(15) << std::left << "ROLE" << std::endl;
    std::cout << std::string(75, '-') << std::endl;

    // Fetch and display rows
    int rowCount = 0;
    while (SQL_SUCCESS == SQLFetch(stmt)) {
        std::wcout << std::setw(10) << std::left << userId
            << std::setw(20) << std::left << username
            << std::setw(30) << std::left << email
            << std::setw(15) << std::left << role << std::endl;
        rowCount++;
    }

    std::cout << std::string(75, '-') << std::endl;
    std::cout << rowCount << " record(s) found.\n";
}

// Display the main menu options
void displayMenu() {
    std::cout << "\n=================================================\n";
    std::cout << "                   MAIN MENU                     \n";
    std::cout << "=================================================\n";
    std::cout << "1. Search users (vulnerable to SQL injection)\n";
    std::cout << "2. Search users (safe parameterized query)\n";
    std::cout << "3. Run SQL injection vulnerability demonstrations\n";
    std::cout << "4. Run secure query examples\n";
    std::cout << "5. Exit\n";
    std::cout << "-------------------------------------------------\n";
}

// Run demonstration of various SQL injection vulnerabilities
void runVulnerableQuery(SQLHDBC dbc) {
    SQLHSTMT stmt;
    SQLRETURN ret;

    std::cout << "\n=================================================\n";
    std::cout << "       SQL INJECTION VULNERABILITY EXAMPLES       \n";
    std::cout << "=================================================\n";

    // Example 1: Authentication bypass
    std::cout << "Example 1: Authentication Bypass\n";
    std::cout << "-------------------------------------------------\n";
    std::cout << "Vulnerable Code:\n";
    std::cout << "   query = \"SELECT * FROM users WHERE username = '\" + username + \"' AND password = '\" + password + \"'\"\n\n";
    std::cout << "Attack Input: username = admin' --\n";
    std::cout << "               password = anything\n\n";
    std::cout << "Resulting Query:\n";
    std::cout << "   SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'\n\n";
    std::cout << "Effect: The -- comments out the password check, allowing login as admin\n";
    std::cout << "-------------------------------------------------\n\n";

    // Example 2: UNION-based attack
    std::cout << "Example 2: UNION-based Attack\n";
    std::cout << "-------------------------------------------------\n";
    std::cout << "Vulnerable Code:\n";
    std::cout << "   query = \"SELECT name, description FROM products WHERE id = \" + productId\n\n";
    std::cout << "Attack Input: productId = 1 UNION SELECT username, password FROM users --\n\n";
    std::cout << "Resulting Query:\n";
    std::cout << "   SELECT name, description FROM products WHERE id = 1 UNION SELECT username, password FROM users --\n\n";
    std::cout << "Effect: Returns product data combined with all usernames and passwords\n";
    std::cout << "-------------------------------------------------\n\n";

    // Live demonstration
    std::cout << "Would you like to run a simulated attack? (y/n): ";
    char choice;
    std::cin >> choice;
    std::cin.ignore();

    if (choice == 'y' || choice == 'Y') {
        SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

        std::string attackInput = "x' OR '1'='1";
        std::string queryStr = "SELECT user_id, username, email, role FROM users WHERE username LIKE '%" + attackInput + "%'";

        std::cout << "\nExecuting attack query: " << queryStr << std::endl << std::endl;

        // Convert to wide string
        std::wstring wAttackQuery(queryStr.begin(), queryStr.end());

        ret = SQLExecDirectW(stmt, const_cast<SQLWCHAR*>(wAttackQuery.c_str()), SQL_NTS);

        if (SQL_SUCCEEDED(ret)) {
            std::cout << "Attack successful! Displaying all users regardless of search term:\n\n";
            showUserData(stmt);
        }
        else {
            std::cout << "Attack simulation failed (database may be protected):\n";
            displaySQLError(stmt, SQL_HANDLE_STMT);
        }

        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    }
}

// Run demonstration of secure queries
void runSecureQuery(SQLHDBC dbc) {
    SQLHSTMT stmt = SQL_NULL_HSTMT;
    SQLRETURN ret;

    std::cout << "\n=================================================\n";
    std::cout << "            SECURE QUERY EXAMPLES                \n";
    std::cout << "=================================================\n";

    // Example 1: Parameterized queries
    std::cout << "Example 1: Parameterized Queries\n";
    std::cout << "-------------------------------------------------\n";
    std::cout << "Secure Code:\n";
    std::cout << "   query = \"SELECT * FROM users WHERE username = ? AND password = ?\"\n";
    std::cout << "   SQLPrepare(stmt, query, SQL_NTS);\n";
    std::cout << "   SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 0, 0, username, 0, NULL);\n";
    std::cout << "   SQLBindParameter(stmt, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 0, 0, password, 0, NULL);\n";
    std::cout << "   SQLExecute(stmt);\n\n";
    std::cout << "Effect: Even if username contains SQL injection attempts like \"admin' --\",\n";
    std::cout << "        it will be treated as a literal string, not as SQL code.\n";
    std::cout << "-------------------------------------------------\n\n";

    // Example 2: Input validation
    std::cout << "Example 2: Input Validation\n";
    std::cout << "-------------------------------------------------\n";
    std::cout << "Secure Code:\n";
    std::cout << "   if(!validateInput(username) || !validateInput(password)) {\n";
    std::cout << "       return ERROR_INVALID_INPUT;\n";
    std::cout << "   }\n\n";
    std::cout << "Effect: Reject inputs containing suspicious characters (', \", --, etc.)\n";
    std::cout << "-------------------------------------------------\n\n";

    // Live demonstration
    std::cout << "Would you like to run a parameterized query demonstration? (y/n): ";
    char choice;
    std::cin >> choice;
    std::cin.ignore();

    if (choice == 'y' || choice == 'Y') {
        // Allocate a new handle
        SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

        std::string searchTerm = "admin' OR '1'='1";
        std::cout << "\nSearching for malicious term: " << searchTerm << std::endl;

        // Use a C++ std::wstring to avoid array initialization issues
        std::wstring tempQuery = L"SELECT user_id, username, email, role FROM users WHERE username LIKE ?";

        // Dynamically allocate memory for the query string
        SQLWCHAR* safeQuery = new SQLWCHAR[tempQuery.length() + 1];
        wcscpy_s(safeQuery, tempQuery.length() + 1, tempQuery.c_str());

        // Prepare parameterized query
        SQLPrepareW(stmt, safeQuery, SQL_NTS);

        // Create parameter value with wildcards
        std::string param = "%" + searchTerm + "%";
        std::wstring wParam(param.begin(), param.end());

        // Bind parameter
        SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_WCHAR, SQL_WVARCHAR,
            wParam.length(), 0, (SQLPOINTER)wParam.c_str(), 0, NULL);

        std::cout << "Executing parameterized query with search term treated as literal string\n\n";

        // Execute the query
        ret = SQLExecute(stmt);

        if (SQL_SUCCEEDED(ret)) {
            std::cout << "Query executed safely. Results:\n\n";
            showUserData(stmt);
            std::cout << "\nNotice how the injection attempt was treated as a literal string,\n";
            std::cout << "not as SQL code, preventing the attack.\n";
        }
        else {
            displaySQLError(stmt, SQL_HANDLE_STMT);
        }

        // Clean up resources
        delete[] safeQuery;
        SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    }
}

// Simple input validation function
bool validateInput(const std::string& input) {
    // Check for common SQL injection characters/strings
    std::vector<std::string> blacklist = {
        "'", "\"", ";", "--", "/*", "*/", "@@", "@",
        "char", "nchar", "varchar", "exec",
        "execute", "sp_", "xp_", "sysobjects", "syscolumns"
    };

    for (const auto& item : blacklist) {
        if (input.find(item) != std::string::npos) {
            return false;
        }
    }

    return true;
}
