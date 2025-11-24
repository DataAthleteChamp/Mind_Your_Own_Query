package jpamb.sqli;

public class SQLi_Interpolation {
    // VULNERABLE
    public static void vulnerable(String table, String column, String value) {
        String query = "SELECT * FROM ".concat(table).concat(" WHERE ").concat(column).concat(" = '").concat(value).concat("'");
        executeQuery(query);
    }
    
    // SAFE
    public static void safe() {
        String table = "users";
        String column = "id";
        String value = "42";
        String query = "SELECT * FROM ".concat(table).concat(" WHERE ").concat(column).concat(" = ").concat(value);
        executeQuery(query);
    }
    
    private static void executeQuery(String q) {
        System.out.println("Executing: " + q);
    }
}