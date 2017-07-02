package org.javelus.minitrace.android.coverage;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.javelus.minitrace.android.MemberMeta;
import org.javelus.minitrace.android.Utils;

public class IncrementalDataParser implements DataParser {
    

    private static final boolean includeDuplicatedData = true;

    public List<Data> parse(File file) throws IOException {
        List<Data> allData = new ArrayList<Data>();
        Map<MemberMeta, String> methodMetaToData = new HashMap<MemberMeta, String>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(file)))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] tokens = line.split("\t");
                if (tokens.length == 3) {
                    String type = tokens[0];
                    String pid = tokens[1];
                    String timestamp = tokens[2];
                    Data data = new Data();
                    methodMetaToData = new HashMap<MemberMeta, String>();
                    try {
                        data.data = methodMetaToData;
                        data.pid = Integer.valueOf(pid);
                        data.timestamp = Long.valueOf(timestamp);
                        data.type = type;
                        allData.add(data);
                    } catch (NumberFormatException e) {
                        System.err.println("ERROR: Incorrect format of line [" + line + "]");
                    }
                    continue;
                }
                if (tokens.length != 7) {
                    System.err.println("ERROR: Incorrect format of line [" + line + "]");
                    continue;
                }
                String className = Utils.toClassName(tokens[1]);
                String methodName = tokens[2];
                String methodDesc = tokens[3];
                String data = tokens[6];
                MemberMeta mm = new MemberMeta(className, methodName, methodDesc);
                String oldData = methodMetaToData.put(mm, data);
                if (oldData != null) {
                    // throw new RuntimeException("Duplicate method data");
                    System.err.println("ERROR: Duplicate data for method " + mm);
                    if (includeDuplicatedData) {
                        data = oldData + '_' + data;
                        methodMetaToData.put(mm, data);
                    } else {
                        System.err.println("ERROR: \t" + oldData);
                        System.err.println("ERROR: \t" + data);
                    }
                }
            }
        }
        if (allData.isEmpty() && !methodMetaToData.isEmpty()) {
            throw new RuntimeException("Incorrect format for incremental parser");
        }
        return allData;
    }
}
