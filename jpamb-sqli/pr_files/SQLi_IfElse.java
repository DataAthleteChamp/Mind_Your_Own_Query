/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_IfElse {
    public static void vulnerable(String string, boolean bl) {
        String string2 = bl ? "SELECT * FROM users WHERE id = " + string : "SELECT * FROM admins WHERE id = " + string;
        SQLi_IfElse.executeQuery(string2);
    }

    public static void safe(boolean bl) {
        String string = bl ? "SELECT * FROM users WHERE id = 42" : "SELECT * FROM users WHERE id = 43";
        SQLi_IfElse.executeQuery(string);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
