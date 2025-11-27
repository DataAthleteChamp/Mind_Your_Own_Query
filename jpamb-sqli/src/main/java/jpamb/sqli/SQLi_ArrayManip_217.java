package jpamb.sqli;

public class SQLi_ArrayManip_217 {
    public static void vulnerable(String[] inputs) {
        String[] processed = new String[inputs.length];
        for (int i = 0; i < inputs.length; i++) {
            processed[i] = inputs[i].trim();
        }
        String query = "SELECT * FROM users WHERE id IN (";
        for (int i = 0; i < processed.length; i++) {
            query += "'" + processed[i] + "'";
            if (i < processed.length - 1) query += ", ";
        }
        query += ")";
        executeQuery(query);
    }
    
    public static void safe() {
        String[] literals = {"1", "2", "3"};
        String[] processed = new String[literals.length];
        for (int i = 0; i < literals.length; i++) {
            processed[i] = literals[i].trim();
        }
        String query = "SELECT * FROM users WHERE id IN (";
        for (int i = 0; i < processed.length; i++) {
            query += "'" + processed[i] + "'";
            if (i < processed.length - 1) query += ", ";
        }
        query += ")";
        executeQuery(query);
    }
    
    private static void executeQuery(String query) {
        System.out.println("Executing query: " + query);
    }
}