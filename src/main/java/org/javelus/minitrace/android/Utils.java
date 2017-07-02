package org.javelus.minitrace.android;

import java.util.List;


public class Utils {
    
    public static String getMethodArgumentsString(List<? extends CharSequence> list) {
        if (list.size() == 0) {
            return "";
        }

        if (list.size() == 1) {
            return list.get(0).toString();
        }

        StringBuilder sb = new StringBuilder();
        for (CharSequence cs : list) {
            sb.append(cs);
        }

        return sb.toString();
    }
    
    public static String getDescriptor(List<? extends CharSequence> list, CharSequence returnType) {
        return "(" + getMethodArgumentsString(list) + ")" + returnType;
    }
    
    /**
     * Manage name conversion here.
     * @param binaryName
     * @return Our Name..
     */
    public static String binaryNameToName(String binaryName) {
        if (binaryName.equals("V")) {
            return "void";
        }

        if (binaryName.equals("B")) {
            return "byte";
        }

        if (binaryName.equals("Z")) {
            return "boolean";
        }

        if (binaryName.equals("C")) {
            return "char";
        }

        if (binaryName.equals("S")) {
            return "short";
        }

        if (binaryName.equals("I")) {
            return "int";
        }

        if (binaryName.equals("F")) {
            return "float";
        }

        if (binaryName.equals("J")) {
            return "long";
        }

        if (binaryName.equals("D")) {
            return "double";
        }

        if (binaryName.startsWith("L")) {
            int length = binaryName.length();
            return binaryName.substring(1, length-1).replace('/', '.');
        }

        if (binaryName.startsWith("[")) {
            return binaryNameToName(binaryName.substring(1)) + "[]";
        }

        throw new RuntimeException("Invalid binary name: " + binaryName);
    }
    

    public static String toClassName(String string) {
        if (string.startsWith("L") && string.endsWith(";")) {
            return string.substring(1, string.length() - 1).replace('/', '.');
        }
        return string;
    }
}
