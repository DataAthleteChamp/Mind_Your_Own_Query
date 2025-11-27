package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilderChaining {
    // VULNERABLE
    public static void vulnerable(String user, String pass) throws SQLException {
        String query = new StringBuilder()
            .append("SELECT * FROM users WHERE username = '")
            .append(user)
            .append("' AND password = '")
            .append(pass)
            .append("'")
            .toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        String query = new StringBuilder()
            .append("SELECT * FROM users WHERE username = '")
            .append("admin")
            .append("' AND password = '")
            .append("hashed_password")
            .append("'")
            .toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
