/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_Switch {
    public static void vulnerable(String string, int n) {
        SQLi_Switch.executeQuery(switch (n) {
            case 1 -> "SELECT * FROM users WHERE id = " + string;
            case 2 -> "SELECT * FROM admins WHERE id = " + string;
            default -> "SELECT * FROM guests WHERE id = " + string;
        });
    }

    public static void safe(int n) {
        SQLi_Switch.executeQuery(switch (n) {
            case 1 -> "SELECT * FROM users WHERE id = 42";
            case 2 -> "SELECT * FROM admins WHERE id = 43";
            default -> "SELECT * FROM guests WHERE id = 1";
        });
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
