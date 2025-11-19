/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_MultipleSources {
    public static void vulnerable(String string, String string2) {
        String string3 = "SELECT * FROM users WHERE name = '" + string + "' OR email = '" + string2 + "'";
        SQLi_MultipleSources.executeQuery(string3);
    }

    public static void safe() {
        String string = "admin";
        String string2 = "admin@example.com";
        String string3 = "SELECT * FROM users WHERE name = '" + string + "' OR email = '" + string2 + "'";
        SQLi_MultipleSources.executeQuery(string3);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
