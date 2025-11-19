package jpamb.sqli;

import java.util.Map;
import java.util.HashMap;

public class SQLi_MapBuilder {
    // VULNERABLE
    public static void vulnerable(Map<String, String> filters) {
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE ");
        int count = 0;
        for (Map.Entry<String, String> entry : filters.entrySet()) {
            if (count > 0) sb.append(" AND ");
            sb.append(entry.getKey()).append(" = '").append(entry.getValue()).append("'");
            count++;
        }
        String query = sb.toString();
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        Map<String, String> filters = new HashMap<>();
        filters.put("status", "active");
        filters.put("role", "admin");
        
        StringBuilder sb = new StringBuilder("SELECT * FROM users WHERE ");
        int count = 0;
        for (Map.Entry<String, String> entry : filters.entrySet()) {
            if (count > 0) sb.append(" AND ");
            sb.append(entry.getKey()).append(" = '").append(entry.getValue()).append("'");
            count++;
        }
        String query = sb.toString();
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}