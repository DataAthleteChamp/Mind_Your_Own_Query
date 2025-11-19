package jpamb.sqli;

public class SQLi_StringBuilderNestedLoop {
    // VULNERABLE
    public static void vulnerable(String[][] conditions) {
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
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
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
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}