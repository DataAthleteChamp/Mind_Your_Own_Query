/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_Replace {
    public static void vulnerable(String string) {
        String string2 = string.replace("'", "''");
        String string3 = "SELECT * FROM users WHERE name = '" + string2 + "'";
        SQLi_Replace.executeQuery(string3);
    }

    public static void safe() {
        String string = "SELECT * FROM table_name WHERE x = y";
        String string2 = string.replace("table_name", "users");
        SQLi_Replace.executeQuery(string2);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
