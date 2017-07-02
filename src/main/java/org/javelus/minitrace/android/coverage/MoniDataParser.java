package org.javelus.minitrace.android.coverage;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.javelus.minitrace.android.MemberMeta;
import org.javelus.minitrace.android.Utils;

public class MoniDataParser implements DataParser {

    @Override
    public List<Data> parse(File file) throws IOException {
        Map<MemberMeta, String> methodMetaToData = new HashMap<MemberMeta, String>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(file)))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] tokens = line.split("\t");
                if (tokens.length != 7) {
                    throw new RuntimeException("Incorrect format");
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
                    System.err.println("ERROR: \t" + oldData);
                    System.err.println("ERROR: \t" + data);
                }
            }
        }
        Data data = new Data();
        // TODO 
        data.data = methodMetaToData;
        return Collections.singletonList(data);
    }

}
