/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_HTTPSource {
    public static void vulnerable(String string) {
        String string2 = string;
        String string3 = "SELECT * FROM users WHERE id = " + string2;
        SQLi_HTTPSource.executeQuery(string3);
    }

    public static void safe() {
        String string = "42";
        String string2 = "SELECT * FROM users WHERE id = " + string;
        SQLi_HTTPSource.executeQuery(string2);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
