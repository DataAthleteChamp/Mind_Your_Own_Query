package jpamb.sqli;

import java.sql.Statement;
import java.sql.SQLException;

public class SQLi_StringBuilderNestedLoop {
    // VULNERABLE
    public static void vulnerable(String[][] conditions) throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE ");
        for (int i = 0; i < conditions.length; i++) {
            if (i > 0) sb.append(" OR ");
            sb.append("(");
            for (int j = 0; j < conditions[i].length; j++) {
                if (j > 0) sb.append(" AND ");
                sb.append("field").append(j).append(" = '").append(conditions[i][j]).append("'");
            }
            sb.append(")");
        }
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
    
    // SAFE
    public static void safe() throws SQLException {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE ");
        String[][] conditions = {{"admin", "active"}, {"user", "pending"}};
        for (int i = 0; i < conditions.length; i++) {
            if (i > 0) sb.append(" OR ");
            sb.append("(");
            for (int j = 0; j < conditions[i].length; j++) {
                if (j > 0) sb.append(" AND ");
                sb.append("field").append(j).append(" = '").append(conditions[i][j]).append("'");
            }
            sb.append(")");
        }
        String query = sb.toString();
        Statement stmt = DatabaseHelper.getStatement();

        stmt.executeQuery(query);
    }
}
