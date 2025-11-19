/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_OrderBy {
    public static void vulnerable(String string) {
        String string2 = "SELECT * FROM products ORDER BY " + string;
        SQLi_OrderBy.executeQuery(string2);
    }

    public static void safe(String string) {
        String string2 = string.equals("price") ? "price" : "name";
        String string3 = "SELECT * FROM products ORDER BY " + string2;
        SQLi_OrderBy.executeQuery(string3);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
