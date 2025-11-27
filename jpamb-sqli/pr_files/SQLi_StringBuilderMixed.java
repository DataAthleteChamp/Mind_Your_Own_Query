/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_StringBuilderMixed {
    public static void vulnerable(String string) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("SELECT * FROM ");
        stringBuilder.append("users");
        stringBuilder.append(" WHERE name = '");
        stringBuilder.append(string);
        stringBuilder.append("'");
        String string2 = stringBuilder.toString();
        SQLi_StringBuilderMixed.executeQuery(string2);
    }

    public static void safe() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("SELECT * FROM ");
        stringBuilder.append("users");
        stringBuilder.append(" WHERE id = ");
        stringBuilder.append("42");
        String string = stringBuilder.toString();
        SQLi_StringBuilderMixed.executeQuery(string);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
