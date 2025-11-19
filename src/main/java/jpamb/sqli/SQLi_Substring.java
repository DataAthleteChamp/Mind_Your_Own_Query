/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_Substring {
    public static void vulnerable(String string) {
        String string2 = string.substring(0, Math.min(10, string.length()));
        String string3 = "SELECT * FROM users WHERE name = '" + string2 + "'";
        SQLi_Substring.executeQuery(string3);
    }

    public static void safe() {
        String string = "safe_value_here";
        String string2 = string.substring(0, 4);
        String string3 = "SELECT * FROM users WHERE name = '" + string2 + "'";
        SQLi_Substring.executeQuery(string3);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
