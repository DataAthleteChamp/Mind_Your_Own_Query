/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_Union {
    public static void vulnerable(String string) {
        String string2 = "SELECT name, price FROM products WHERE id = " + string;
        SQLi_Union.executeQuery(string2);
    }

    public static void safe() {
        String string = "42";
        String string2 = "SELECT name, price FROM products WHERE id = " + string;
        SQLi_Union.executeQuery(string2);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
