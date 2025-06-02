#include <iostream>
 
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <fstream>
#include <algorithm>
#include <map>
using namespace std;

// User structure to simulate database records
struct User {
    int user_id;
    string username;
    string password;
    string email;
    string role;
};

// Global user database (in-memory)
vector<User> users = {
    {1, "admin", "admin123", "admin@example.com", "administrator"},
    {2, "john", "password123", "john@example.com", "user"},
    {3, "alice", "secure456", "alice@example.com", "user"},
    {4, "bob", "bob789", "bob@example.com", "user"},
    {5, "sarah", "sarah123", "sarah@example.com", "manager"}
};

// Helper function declarations
bool logAttempt(const string& username, bool success, const string& errorMsg = "");
void runSecureQuery();
void runVulnerableQuery();
void showUserData(const vector<User>& results);
void displayMenu();
bool validateInput(const string& input);

// Simulated SQL query execution - vulnerable version
vector<User> executeVulnerableQuery(const string& query) {
    vector<User> results;
    cout << "Executing query: " << query << endl;

    // Convert query to lowercase for easier parsing
    string lowerQuery = query;
    transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);

    // Simple SQL parser to simulate SQL injection vulnerabilities

    // Check for login query
    if (lowerQuery.find("select") != string::npos &&
        lowerQuery.find("from users where") != string::npos) {

        // Extract conditions after WHERE
        size_t wherePos = lowerQuery.find("where");
        string conditions = lowerQuery.substr(wherePos + 5);

        // Handle SQL injection like ' or '1'='1
        if (conditions.find("'1'='1") != string::npos ||
            conditions.find("1=1") != string::npos) {
            // SQL injection detected - return all users
            return users;
        }

        // Handle normal username/password check
        for (const auto& user : users) {
            // Very simplified check - in a real parser this would be much more complex
            if (query.find(user.username) != string::npos &&
                query.find(user.password) != string::npos) {
                results.push_back(user);
                return results;
            }

            // Check for comment injection (-- or #)
            if (query.find("--") != string::npos || query.find("#") != string::npos) {
                size_t usernamePos = query.find(user.username);
                if (usernamePos != string::npos) {
                    // Username found and password check commented out
                    results.push_back(user);
                    return results;
                }
            }
        }
    }
    // Handle LIKE queries for search functionality
    else if (lowerQuery.find("select") != string::npos &&
        lowerQuery.find("like") != string::npos) {

        // Extract search term
        size_t likePos = lowerQuery.find("like");
        string searchCondition = lowerQuery.substr(likePos + 4);

        // Handle SQL injection
        if (searchCondition.find("'1'='1") != string::npos ||
            searchCondition.find("1=1") != string::npos) {
            // SQL injection detected - return all users
            return users;
        }

        // Extract actual search term between percentage signs
        size_t firstQuote = searchCondition.find("'%");
        size_t lastQuote = searchCondition.find("%'");

        if (firstQuote != string::npos && lastQuote != string::npos) {
            string searchTerm = searchCondition.substr(firstQuote + 2, lastQuote - firstQuote - 2);

            // Perform the search
            for (const auto& user : users) {
                if (user.username.find(searchTerm) != string::npos ||
                    user.email.find(searchTerm) != string::npos) {
                    results.push_back(user);
                }
            }
        }
    }

    return results;
}

// Simulated SQL query execution - secure parameterized version
vector<User> executeSecureQuery(const string& queryTemplate, const map<int, string>& params) {
    vector<User> results;

    cout << "Executing parameterized query with template: " << queryTemplate << endl;
    cout << "Parameters: ";
    for (const auto& param : params) {
        cout << param.first << " = '" << param.second << "' ";
    }
    cout << endl;

    // Handle login query
    if (queryTemplate.find("SELECT user_id, username, role FROM users WHERE") != string::npos) {
        if (params.find(1) != params.end() && params.find(2) != params.end()) {
            string username = params.at(1);
            string password = params.at(2);

            // Exact match required - no SQL injection possible
            for (const auto& user : users) {
                if (user.username == username && user.password == password) {
                    results.push_back(user);
                    return results;
                }
            }
        }
    }
    // Handle search query
    else if (queryTemplate.find("SELECT user_id, username, email, role FROM users") != string::npos) {
        if (params.find(1) != params.end()) {
            string searchTerm = params.at(1);

            // Remove wildcards from parameter for demonstration
            searchTerm = searchTerm.substr(1, searchTerm.length() - 2); // Remove % %

            // Clean search - no SQL injection possible
            for (const auto& user : users) {
                if (user.username.find(searchTerm) != string::npos ||
                    user.email.find(searchTerm) != string::npos) {
                    results.push_back(user);
                }
            }
        }
    }

    return results;
}

int main() {
    // User credentials
    string username, password;
    bool isLoggedIn = false;
    int loginAttempts = 0;
    const int MAX_ATTEMPTS = 3;

    cout << "=================================================\n";
    cout << "DATABASE AUTHENTICATION SYSTEM - DEMONSTRATION\n";
    cout << "=================================================\n";
    cout << "This program demonstrates SQL injection vulnerabilities\n";
    cout << "for educational purposes only.\n\n";

    cout << "Note: Using in-memory simulated database\n\n";

    // Authentication loop
    while (loginAttempts < MAX_ATTEMPTS && !isLoggedIn) {
        cout << "LOGIN SCREEN (Attempt " << loginAttempts + 1 << " of " << MAX_ATTEMPTS << ")\n";
        cout << "Username: ";
        getline(cin, username);
        cout << "Password: ";
        getline(cin, password);

        // VULNERABLE IMPLEMENTATION FOR DEMONSTRATION
        // This code is intentionally vulnerable to SQL injection
        string queryStr = "SELECT user_id, username, role FROM users WHERE username = '"
            + username + "' AND password = '" + password + "'";

        // Execute the simulated query
        vector<User> results = executeVulnerableQuery(queryStr);

        if (!results.empty()) {
            isLoggedIn = true;
            const User& user = results[0];

            cout << "\nSUCCESS: Login successful!\n";
            cout << "User ID: " << user.user_id << endl;
            cout << "Username: " << user.username << endl;
            cout << "Role: " << user.role << endl << endl;

            // Log the successful login
            logAttempt(username, true);

            // Note the vulnerability here: SQL injection could return multiple rows
            if (results.size() > 1) {
                cout << "WARNING: Multiple users match the criteria - possible SQL injection!\n";
            }
        }
        else {
            cout << "ERROR: Invalid username or password.\n\n";
            logAttempt(username, false, "Invalid credentials");
        }

        loginAttempts++;

        if (!isLoggedIn && loginAttempts < MAX_ATTEMPTS) {
            cout << "Please try again.\n\n";
        }
    }

    // After authentication
    if (isLoggedIn) {
        int choice = 0;

        while (choice != 5) {
            displayMenu();
            cout << "Enter your choice: ";
            cin >> choice;
            cin.ignore(); // Clear the newline

            // Common string variables to be used across cases
            string searchTerm;
            string queryStr;

            switch (choice) {
            case 1: // Vulnerable search
                cout << "Enter search term: ";
                getline(cin, searchTerm);

                cout << "VULNERABLE QUERY - Demonstrating SQL Injection Risk\n";
                cout << "-----------------------------------------------\n";

                // Create vulnerable query
                queryStr = "SELECT user_id, username, email, role FROM users WHERE username LIKE '%"
                    + searchTerm + "%' OR email LIKE '%" + searchTerm + "%'";

                // Execute the query
                showUserData(executeVulnerableQuery(queryStr));
                break;

            case 2: // Parameterized search (safe)
            {
                cout << "Enter search term: ";
                getline(cin, searchTerm);

                cout << "SAFE QUERY - Using Parameterized Statements\n";
                cout << "---------------------------------------\n";

                // Create parameterized query
                string paramQueryStr = "SELECT user_id, username, email, role FROM users WHERE username LIKE ? OR email LIKE ?";

                // Create parameter values with wildcards
                map<int, string> params;
                params[1] = "%" + searchTerm + "%";

                // Execute secure query
                showUserData(executeSecureQuery(paramQueryStr, params));
            }
            break;

            case 3: // Run demonstration of vulnerable queries
                runVulnerableQuery();
                break;

            case 4: // Run demonstration of secure queries
                runSecureQuery();
                break;

            case 5: // Exit
                cout << "Logging out...\n";
                break;

            default:
                cout << "Invalid choice. Please try again.\n";
            }

            if (choice != 5) {
                cout << "\nPress Enter to continue...";
                cin.get();
            }
        }
    }
    else {
        cout << "Maximum login attempts exceeded. Exiting.\n";
    }

    cout << "Program terminated.\n";
    return 0;
}

// Log login attempts
bool logAttempt(const string& username, bool success, const string& errorMsg) {
    // Get current time
    time_t now = time(0);
    struct tm timeinfo;
    char timestamp[80];

    // Use localtime_s for better safety (avoid C4996 warning)
    localtime_s(&timeinfo, &now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeinfo);

    // Open log file
    ofstream logFile("auth_log.txt", ios::app);
    if (!logFile.is_open()) {
        cerr << "Failed to open log file.\n";
        return false;
    }

    // Write log entry
    logFile << timestamp << " | User: " << setw(15) << left << username
        << " | Status: " << (success ? "SUCCESS" : "FAILURE");

    if (!errorMsg.empty()) {
        logFile << " | Error: " << errorMsg;
    }

    logFile << endl;
    logFile.close();
    return true;
}

// Display formatted user data from query results
void showUserData(const vector<User>& results) {
    // Print table header
    cout << setw(10) << left << "USER ID"
        << setw(20) << left << "USERNAME"
        << setw(30) << left << "EMAIL"
        << setw(15) << left << "ROLE" << endl;
    cout << string(75, '-') << endl;

    // Display rows
    for (const auto& user : results) {
        cout << setw(10) << left << user.user_id
            << setw(20) << left << user.username
            << setw(30) << left << user.email
            << setw(15) << left << user.role << endl;
    }

    cout << string(75, '-') << endl;
    cout << results.size() << " record(s) found.\n";
}

// Display the main menu options
void displayMenu() {
    cout << "\n=================================================\n";
    cout << "                   MAIN MENU                     \n";
    cout << "=================================================\n";
    cout << "1. Search users (vulnerable to SQL injection)\n";
    cout << "2. Search users (safe parameterized query)\n";
    cout << "3. Run SQL injection vulnerability demonstrations\n";
    cout << "4. Run secure query examples\n";
    cout << "5. Exit\n";
    cout << "-------------------------------------------------\n";
}

// Run demonstration of various SQL injection vulnerabilities
void runVulnerableQuery() {
    cout << "\n=================================================\n";
    cout << "       SQL INJECTION VULNERABILITY EXAMPLES       \n";
    cout << "=================================================\n";

    // Example 1: Authentication bypass
    cout << "Example 1: Authentication Bypass\n";
    cout << "-------------------------------------------------\n";
    cout << "Vulnerable Code:\n";
    cout << "   query = \"SELECT * FROM users WHERE username = '\" + username + \"' AND password = '\" + password + \"'\"\n\n";
    cout << "Attack Input: username = admin' --\n";
    cout << "               password = anything\n\n";
    cout << "Resulting Query:\n";
    cout << "   SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'\n\n";
    cout << "Effect: The -- comments out the password check, allowing login as admin\n";
    cout << "-------------------------------------------------\n\n";

    // Example 2: UNION-based attack
    cout << "Example 2: UNION-based Attack\n";
    cout << "-------------------------------------------------\n";
    cout << "Vulnerable Code:\n";
    cout << "   query = \"SELECT name, description FROM products WHERE id = \" + productId\n\n";
    cout << "Attack Input: productId = 1 UNION SELECT username, password FROM users --\n\n";
    cout << "Resulting Query:\n";
    cout << "   SELECT name, description FROM products WHERE id = 1 UNION SELECT username, password FROM users --\n\n";
    cout << "Effect: Returns product data combined with all usernames and passwords\n";
    cout << "-------------------------------------------------\n\n";

    // Live demonstration
    cout << "Would you like to run a simulated attack? (y/n): ";
    char choice;
    cin >> choice;
    cin.ignore();

    if (choice == 'y' || choice == 'Y') {
        string attackInput = "x' OR '1'='1";
        string queryStr = "SELECT user_id, username, email, role FROM users WHERE username LIKE '%" + attackInput + "%'";

        cout << "\nExecuting attack query: " << queryStr << endl << endl;

        vector<User> results = executeVulnerableQuery(queryStr);

        if (!results.empty()) {
            cout << "Attack successful! Displaying all users regardless of search term:\n\n";
            showUserData(results);
        }
        else {
            cout << "Attack simulation failed.\n";
        }
    }
}

// Run demonstration of secure queries
void runSecureQuery() {
    cout << "\n=================================================\n";
    cout << "            SECURE QUERY EXAMPLES                \n";
    cout << "=================================================\n";

    // Example 1: Parameterized queries
    cout << "Example 1: Parameterized Queries\n";
    cout << "-------------------------------------------------\n";
    cout << "Secure Code:\n";
    cout << "   query = \"SELECT * FROM users WHERE username = ? AND password = ?\"\n";
    cout << "   SQLPrepare(stmt, query, SQL_NTS);\n";
    cout << "   SQLBindParameter(stmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 0, 0, username, 0, NULL);\n";
    cout << "   SQLBindParameter(stmt, 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR, 0, 0, password, 0, NULL);\n";
    cout << "   SQLExecute(stmt);\n\n";
    cout << "Effect: Even if username contains SQL injection attempts like \"admin' --\",\n";
    cout << "        it will be treated as a literal string, not as SQL code.\n";
    cout << "-------------------------------------------------\n\n";

    // Example 2: Input validation
    cout << "Example 2: Input Validation\n";
    cout << "-------------------------------------------------\n";
    cout << "Secure Code:\n";
    cout << "   if(!validateInput(username) || !validateInput(password)) {\n";
    cout << "       return ERROR_INVALID_INPUT;\n";
    cout << "   }\n\n";
    cout << "Effect: Reject inputs containing suspicious characters (', \", --, etc.)\n";
    cout << "-------------------------------------------------\n\n";

    // Live demonstration
    cout << "Would you like to run a parameterized query demonstration? (y/n): ";
    char choice;
    cin >> choice;
    cin.ignore();

    if (choice == 'y' || choice == 'Y') {
        string searchTerm = "admin' OR '1'='1";
        cout << "\nSearching for malicious term: " << searchTerm << endl;

        // Create parameterized query
        string paramQueryStr = "SELECT user_id, username, email, role FROM users WHERE username LIKE ?";

        // Create parameter map
        map<int, string> params;
        params[1] = "%" + searchTerm + "%";

        cout << "Executing parameterized query with search term treated as literal string\n\n";

        // Execute secure query
        vector<User> results = executeSecureQuery(paramQueryStr, params);

        if (!results.empty()) {
            cout << "Query executed safely. Results:\n\n";
            showUserData(results);
            cout << "\nNotice how the injection attempt was treated as a literal string,\n";
            cout << "not as SQL code, preventing the attack.\n";
        }
        else {
            cout << "No results found for literal search term \"" << searchTerm << "\"\n";
            cout << "This demonstrates how parameterized queries protect against SQL injection.\n";
        }
    }
}

// Simple input validation function
bool validateInput(const string& input) {
    // Check for common SQL injection characters/strings
    vector<string> blacklist = {
        "'", "\"", ";", "--", "/*", "*/", "@@", "@",
        "char", "nchar", "varchar", "exec",
        "execute", "sp_", "xp_", "sysobjects", "syscolumns"
    };

    for (const auto& item : blacklist) {
        if (input.find(item) != string::npos) {
            return false;}    }
    return true;
}
