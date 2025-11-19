/*
 * Decompiled with CFR 0.152.
 */
package jpamb.sqli;

public class SQLi_StringBuffer {
    public static void vulnerable(String[] stringArray) {
        StringBuffer stringBuffer = new StringBuffer("SELECT * FROM users WHERE id IN (");
        for (String string : stringArray) {
            stringBuffer.append(string).append(", ");
        }
        stringBuffer.append(")");
        String string = stringBuffer.toString();
        SQLi_StringBuffer.executeQuery(string);
    }

    public static void safe() {
        String[] stringArray;
        StringBuffer stringBuffer = new StringBuffer("SELECT * FROM users WHERE id IN (");
        for (String string : stringArray = new String[]{"1", "2", "3"}) {
            stringBuffer.append(string).append(", ");
        }
        stringBuffer.append(")");
        String string = stringBuffer.toString();
        SQLi_StringBuffer.executeQuery(string);
    }

    private static void executeQuery(String string) {
        System.out.println("Executing: " + string);
    }
}
