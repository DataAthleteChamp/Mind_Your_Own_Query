/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_TimeBased {
    public static void vulnerable(String string) {
        String string2 = "SELECT * FROM users WHERE id = " + string;
        SQLi_TimeBased.executeQuery(string2);
    }

    public static void safe() {
        String string = "42";
        String string2 = "SELECT * FROM users WHERE id = " + string;
        SQLi_TimeBased.executeQuery(string2);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
