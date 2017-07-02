package org.javelus.minitrace.android;

import java.io.File;
import java.io.IOException;

public class Main {
    public static void main(String [] args) throws IOException {
        String infoPath = args[0];
        //String dataPath = args[1];
        
        MiniTrace mt = MiniTrace.load(infoPath);
        //mt.dumpData(dataPath);
        
        if (args.length>=3) {
            // mt.dumpCoverageFromDex(new File(args[2]));
        }
    }
}
