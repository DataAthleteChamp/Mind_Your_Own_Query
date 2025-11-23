/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_ComplexNested {
    public static void vulnerable(String string) {
        String string2 = string.trim();
        String string3 = string2.toUpperCase();
        String[] stringArray = string3.split(" ");
        String string4 = stringArray.length > 0 ? stringArray[0] : "";
        String string5 = string4.replace("'", "''");
        String string6 = "SELECT * FROM users WHERE name = '" + string5 + "'";
        SQLi_ComplexNested.executeQuery(string6);
    }

    public static void safe() {
        String string = "  admin user  ";
        String string2 = string.trim();
        String string3 = string2.toUpperCase();
        String[] stringArray = string3.split(" ");
        String string4 = stringArray[0];
        String string5 = "SELECT * FROM users WHERE name = '" + string4 + "'";
        SQLi_ComplexNested.executeQuery(string5);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
