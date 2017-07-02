package org.javelus.minitrace.android.coverage;

import java.util.Map;

import org.javelus.minitrace.android.MemberMeta;

public class Data {

    int pid;
    long timestamp;
    String type;
    Map<MemberMeta, String> data;

}
