/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_LoginBypass {
    public static void vulnerable(String string, String string2) {
        String string3 = "SELECT * FROM users WHERE username = '" + string + "' AND password = '" + string2 + "'";
        SQLi_LoginBypass.executeQuery(string3);
    }

    public static void safe() {
        String string = "admin";
        String string2 = "secret123";
        String string3 = "SELECT * FROM users WHERE username = '" + string + "' AND password = '" + string2 + "'";
        SQLi_LoginBypass.executeQuery(string3);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
