/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_StringBuilder {
    public static void vulnerable(String string) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("SELECT * FROM users WHERE id = ");
        stringBuilder.append(string);
        String string2 = stringBuilder.toString();
        SQLi_StringBuilder.executeQuery(string2);
    }

    public static void safe() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("SELECT * FROM users WHERE id = ");
        stringBuilder.append("42");
        String string = stringBuilder.toString();
        SQLi_StringBuilder.executeQuery(string);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
