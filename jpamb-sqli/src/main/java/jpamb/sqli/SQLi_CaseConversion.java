/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_CaseConversion {
    public static void vulnerable(String string) {
        String string2 = string.toUpperCase();
        String string3 = "SELECT * FROM users WHERE name = '" + string2 + "'";
        SQLi_CaseConversion.executeQuery(string3);
    }

    public static void safe() {
        String string = "admin";
        String string2 = string.toUpperCase();
        String string3 = "SELECT * FROM users WHERE role = '" + string2 + "'";
        SQLi_CaseConversion.executeQuery(string3);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
