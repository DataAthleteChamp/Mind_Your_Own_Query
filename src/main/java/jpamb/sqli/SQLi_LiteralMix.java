/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_LiteralMix {
    public static void vulnerable(String string) {
        String string2 = "SELECT * FROM ";
        String string3 = "users WHERE name = '" + string + "'";
        String string4 = string2 + string3;
        SQLi_LiteralMix.executeQuery(string4);
    }

    public static void safe() {
        String string = "SELECT * FROM ";
        String string2 = "users WHERE id = 1";
        String string3 = string + string2;
        SQLi_LiteralMix.executeQuery(string3);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
