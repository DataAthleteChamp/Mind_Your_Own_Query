/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_PartialSanitization {
    public static void vulnerable(String string) {
        String string2 = string.replace("'", "\\'");
        String string3 = "SELECT * FROM users WHERE name = '" + string2 + "'";
        SQLi_PartialSanitization.executeQuery(string3);
    }

    public static void safe(String string) {
        String string2 = string.replaceAll("[^a-zA-Z0-9]", "");
        String string3 = "SELECT * FROM users WHERE name = '" + string2 + "'";
        SQLi_PartialSanitization.executeQuery(string3);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
